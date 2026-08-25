# Archive Ledger Canonical Event Stream Specification

Status: authoritative

Date: 2026-08-19

This document defines the durable event log, its crash and checkpoint invariants,
and its relationship to SQLite. Product semantics are defined in the
[product specification](2026-08-19-product.md); projection tables are defined in
the [schema specification](2026-08-19-schema.md).

## Authority and writer model

The JSONL event stream is canonical archive metadata. SQLite is a rebuildable materialized view.

Each named Archive owns one independent version 2 event tree. Per-user
discovery/default configuration points to Archive directories but is not part
of, and cannot override, canonical Archive identity.

The event tree preserves one authoritative history per Archive while allowing a
small number of enrolled installations to append concurrently. It physically
partitions new history into immutable per-origin journals so Git never merges or
rewrites JSONL lines. Origins are storage shards, not independent ledgers: an
accepted frontier and its canonical Git commit name the complete union, and
every synchronized installation retains that union.

## Multi-origin and batch model

### Archive genesis

Every new Archive starts directly in version 2. `archive init` creates a local
Ed25519 client key, derives its origin ID, and writes one immutable, self-signed
`genesis.json`. Genesis binds the Archive ID and display name, creation time,
event/frontier/item/schema versions, and initial client's ID and public key. Its
deterministic bytes and signature form the Archive trust root. The first frontier
binds the genesis hash and has no parent; the `archive_initialized` batch is the
initial origin range descended from it.

`genesis.json` is `{ "body": ..., "signature": ... }`. The body field order is
genesis version, Archive ID/name, creation time, record/frontier/item/schema
versions, initial client ID, and base64 public key. The Ed25519 signature covers
the exact deterministic body bytes; `genesis_hash` covers the complete signed
genesis bytes. The initial client ID must equal `origin_` plus BLAKE3 of the raw
32-byte public key.

Archive creation is all-or-nothing: private key creation, genesis validation,
initial batch/segment, first frontier, Git commit, and SQLite projection complete
in a temporary catalog directory before no-replace publication. A partial
directory is never registered as an Archive. Pre-v2 catalogs are unsupported
development artifacts and fail with an explicit recreate/import message; there
is no activation, legacy migration, or mixed-format replay path.

### Origins, dots, and journals

An origin identifies one enrolled client installation, not a storage Device.
Its stable ID is `origin_` plus the 64-character lowercase hexadecimal BLAKE3 of
its public signing key. Each origin owns one
append-only hash chain with sequence numbers starting at 1. The pair
`(origin_id, origin_seq)` is its dot and is globally unique within the Archive.
Only that enrolled client may sign new closed segments for the origin.

```text
events/v2/origins/<origin-id>/seg-000000000001.jsonl
manifests/v2/origins/<origin-id>/seg-000000000001.manifest.json
frontiers/v2/frontier-<64 lowercase hash hex>.json
frontiers/v2/HEAD
```

Every version 2 physical record contains `v`, origin ID/sequence, record ID,
record kind, UTC time, batch ID, and the prior exact-line hash in that origin.
Sequence and hash continuity are verified independently for every origin. A
closed segment manifest binds the Archive ID, origin, sequence range, first and
last hashes, file BLAKE3, causal base, and previous segment manifest. The
manifest is signed by the enrolled origin key. Signatures cover manifests rather
than individual lines, retaining readable exact-byte JSONL and bounded signing
overhead. Only signed, closed segments enter a shared accepted frontier.

The local open tail remains append-only canonical work on its originating
installation but is sealed before synchronization. Another installation never
appends to, truncates, repairs, or signs that origin's journal.

The exact version 2 envelope is:

```json
{"v":2,"origin_id":"origin_<64 lowercase hex>","origin_seq":8,"record_id":"rec_<lowercase ULID>","record_kind":"batch_chunk","time_utc_ms":1781042405123,"batch_id":"batch_<lowercase ULID>","previous_record_hash":"blake3:<64 lowercase hex>","payload":{}}
```

Fields serialize in that order. `record_kind` is `batch_start`, `batch_chunk`, or
`batch_complete`; all operation-specific meaning is versioned inside `payload`.
`previous_record_hash` is null only at origin sequence 1. The physical line limit
is 1 MiB without its newline, so the chunk builder must leave room for its
envelope. Unknown fields, versions, kinds, or non-object payloads fail closed.
Record hashing is `blake3:` plus lowercase hexadecimal BLAKE3 of the exact line
bytes without the newline. Writers serialize once; closed bytes are never
normalized or rewritten.

### Frontiers and causal dependencies

A frontier manifest contains:

- format version and Archive ID;
- the immutable Archive genesis hash;
- one entry per accepted origin, sorted by binary origin ID, naming its maximum
  accepted sequence, line hash, and segment manifest;
- the prior accepted frontier hash or hashes used to form a union;
- the canonical item/projection rule versions needed to interpret the prefix.

Its ID is the BLAKE3 of its deterministic UTF-8 JSON bytes. A valid successor
never omits or reduces an origin entry. An unchanged origin entry must retain
the same sequence, hash, and manifest; an advanced entry must verify through
that origin's immutable manifest chain. A union frontier takes the pointwise
maximum only after proving that shared ranges are byte-identical and each
advanced range descends from the prior entry. Same-dot/different-hash history is
damage or origin-key misuse and fails closed.

`frontiers/v2/HEAD` contains the accepted `blake3:<hex>` frontier ID followed by
one newline. It is the only replaced file in this subtree: a writer first makes
the referenced immutable frontier durable, then atomically advances `HEAD`.
The canonical Git commit binds both the pointer and referenced manifest. Git
synchronization constructs a verified successor rather than text-merging this
pointer.

Each batch start records its causal base frontier. Projection may process a
batch only after that base is satisfied. Concurrent batches need no invented
global order: additive rules commute, while contradictions are preserved as
explicit conflict/uncertainty. A later observation resolves a conflict only
when its causal base includes every conflicting dot it supersedes.

### One bounded batch protocol

All new version 2 mutations use one physical protocol, including low-volume
registry changes. A batch consists of:

1. `batch_start`, carrying the operation kind, causal base, actor/origin, job,
   Collection/Location/Device/root/scope context, item schema, and defaults;
2. one or more `batch_chunk` records, each containing a consecutive item range;
3. `batch_complete`, carrying total counts, ordered item digest, error summary,
   and coverage publication data when applicable.

A chunk is one atomic hash-chained record, limited by both exact serialized line
bytes (without the newline) and item count. Initial defaults are at most 1 MiB
and 1,000 items; measurement may lower either bound. Writers build and validate
one chunk in bounded memory, serialize it once, append and synchronize it, then
advance local progress.

Item schema 2 encodes `defaults` as an object keyed by item `kind`; each value is
an object of fields common to that kind in this batch. The writer omits an
explicit item field only when its JSON value exactly equals the corresponding
kind default. During projection, defaults are materialized first and explicit
item fields override them, so failures and other exceptions remain self-
describing. `kind` itself cannot be defaulted. Defaults for one kind never enter
another kind, unknown schemas fail closed, and schema-1 items remain explicit
and rebuildable. This is semantic deduplication inside readable JSONL, not
compression or an external dictionary.

Chunk item indexes are zero-based and consecutive across the batch. The ordered
item digest is BLAKE3 over the ASCII domain
`archive-ledger-batch-items-v1\0`, followed for each chunk in order by its
eight-byte big-endian first-item index, four-byte big-endian item count, and the
32 raw bytes of its already-verified exact-record BLAKE3. This binds every item,
its order, and its chunk boundaries without parsing or reserializing item JSON a
second time. `batch_complete` is invalid when the range is gapped, duplicated,
empty, over either bound, or disagrees with its total count or digest.

Common scan items are composite outcomes. One positive item may establish or
refresh the logical File, Object identity, path observation, Copy claim,
presence, and baseline verification in one record. One missing item names the
path/Copy negative outcome together. The
projector expands an item atomically under versioned rules. Batch context and
deterministic IDs replace repeated envelope/payload fields; UTF-8 paths appear
once, while exceptional platform paths retain an explicit lossless encoding.
Failures and identity conflicts carry their non-default evidence rather than
being compressed into a success form.

Positive items become visible after their durable chunk projects, even if a
scan later stops. Complete-scan negatives remain inert candidates until the
matching `batch_complete` validates their full count/digest and publishes them
atomically. An uncompleted batch can therefore add verified evidence but cannot
mark unseen content missing or advance complete coverage. Resume retains the
same batch ID and reconciles deterministic per-item operation keys; it never
duplicates a logical outcome merely because a chunk was durable before local
progress was updated.

### Enrollment, signatures, and revocation

The genesis client is the initial enrolled client. A new installation creates
an Ed25519 keypair locally and becomes writable only after an already-enrolled,
non-revoked client records approval under the client-registry coordination
scope. Private keys and credentials are local secrets and never enter canonical
history or portable snapshots. Enrollment records the public key, stable client
ID, display name, capabilities, and approval dot.

The enrolling installation writes a self-signed, versioned enrollment request
containing the Archive/genesis binding and public fields. The approving client
verifies that signature before recording `client_enrolled`. The request is a
transfer artifact, not canonical history. The new installation keeps its key in
`local/clients/`, selects that client locally, and cannot append until it has
received the canonical frontier containing the approval.

A client's first segment causally depends on the frontier containing its
approval. Revocation prevents acceptance of segments whose causal base follows
the revocation, but never removes already accepted history. Lost-key recovery is
an explicit enrolled-client registry operation; it never silently reuses the
old origin ID. Signature, enrollment, Archive-ID, and causal checks occur before
a fetched segment can affect SQLite.

### Scoped coordination for non-commutative work

Additive Object/File creation at distinct paths, positive observations,
verification attempts, and Device check-ins may be recorded offline. Registry,
topology, policy, client-registry, complete-scan negative publication, and future
drop/delete changes require a short coordination token. The initial
implementation deliberately uses one Archive-wide scope: this is conservative,
fits the small number of installations expected for a personal Archive, and
avoids a finer lock hierarchy until measurements show useful concurrent
administrative work.

Tokens use compare-and-swap Git refs at the configured coordination remote.
Acquisition and release are retained as a small signed coordination chain;
expiry permits safe takeover after interruption. Renewal and administrative
break are future extensions. A protected event embeds the signed token proof
and accepted base frontier. Publishing its canonical union commit succeeds only
while that token remains current; an expired or replaced holder cannot publish
late work.
Clock uncertainty or unavailable coordination fails closed. This mechanism does
not make the coordination remote a second ledger or independent metadata copy.

### Git union publication

Synchronization seals local tails, verifies both accepted commits/frontiers,
fetches missing immutable objects, and constructs a Git merge commit whose tree
is their validated union plus one successor frontier. JSONL files are never
passed to a textual merge driver. Identical paths must have identical bytes;
distinct origins occupy distinct paths. The canonical ref is updated with
compare-and-swap. A race fetches the new tip and repeats validation/union rather
than force-pushing or choosing one side by arrival order.

SQLite is never merged row-to-row. After a successful union, each installation
incrementally projects only origin ranges beyond its stored applied frontier.

## Physical serialization and hashing

The exact line bytes are canonical. There is no JSON canonicalization step.

```text
record_hash = "blake3:" + lowercase_hex(BLAKE3(exact_line_bytes_without_newline))
```

The hash of origin record N is stored in record N+1 as
`previous_record_hash`. Writers serialize a record once and append those exact
bytes plus one `\n`. Closed record bytes are never reformatted, normalized, or
rewritten. Deterministic genesis, frontier, and manifest JSON uses declared
struct field order plus already-sorted arrays; unknown fields fail closed.

## Directory layout

```text
genesis.json
events/
  v2/origins/<origin-id>/seg-000000000001.jsonl
manifests/
  v2/origins/<origin-id>/seg-000000000001.manifest.json
frontiers/v2/frontier-<64 lowercase hash hex>.json
frontiers/v2/HEAD
checkpoints/
  chk-<lowercase-ulid>.json
```

Segment names contain the first origin sequence, zero-padded to 12 digits.
Manifest, frontier, and checkpoint paths are repository-relative and must not
escape the event repository. Each installation writes only beneath its own
origin path.

The Archive directory also contains `local/clients/<origin-id>.key` outside the
canonical Git repository. On Unix its parent directories are mode `0700` and
the key file is mode `0600`. It is neither canonical history nor portable
snapshot content.

## Segment state machine

At every stable point, all of these invariants hold:

1. Segments within each origin are ordered by first sequence.
2. Each origin's ranges are contiguous from 1 through its tail.
3. Every segment except possibly that origin's highest has a valid manifest.
4. At most one segment per local origin lacks a manifest; it is the append-only
   local tail and is never synchronized or accepted into a frontier.
5. A manifested segment is closed and immutable.
6. A writer never appends to a segment whose manifest exists.
7. A new segment starts only after the previous segment has been closed successfully.

Segments close at a bounded batch publication boundary and before sync or
checkpoint. Rollover also obeys a configured record/byte bound. Resetting an
in-memory pointer without closing and signing the segment is forbidden.

### Append protocol

For each bounded canonical batch:

1. acquire the local origin writer lock;
2. Verify the open tail and recover only an incomplete final write as described below.
3. Assign envelope fields and serialize each record once.
4. When creating a segment, create and open it without replacing any existing
   path.
5. Append complete lines in sequence and `fsync` the file.
6. For the first durable batch in a new segment, `fsync` the event directory
   where supported before reporting the batch durable.
7. close and sign the segment before advancing the local frontier.

SQLite application happens after signed-segment and frontier durability. A
failure between canonical publication and projection is recovered by applying
the unapplied origin ranges.

### Close protocol

Closing a segment:

1. flushes and `fsync`s the segment;
2. streams the segment to validate every record and compute manifest values;
3. writes the manifest to a temporary file in the manifest directory;
4. `fsync`s the temporary manifest;
5. signs the deterministic unsigned manifest, verifies the signature, and
   atomically renames the signed manifest to its final path;
6. `fsync`s the manifest directory where supported;
7. syncs the manifest directory and permits a new segment.

The final manifest contains:

```json
{
  "manifest_v": 2,
  "archive_id": "arc_...",
  "origin_id": "origin_...",
  "segment_file": "events/v2/origins/origin_.../seg-000000000001.jsonl",
  "first_seq": 1,
  "last_seq": 12,
  "first_record_id": "rec_...",
  "last_record_id": "rec_...",
  "first_record_hash": "blake3:...",
  "last_record_hash": "blake3:...",
  "record_count": 12,
  "segment_size_bytes": 41238771,
  "segment_blake3": "blake3:...",
  "causal_base_frontier_hash": "blake3:...",
  "previous_segment_manifest_hash": null,
  "signature": "base64-ed25519-signature"
}
```

The signature covers the deterministic manifest without `signature`. The
manifest hash used by frontiers covers the complete signed manifest bytes.

### Restart and tail recovery

On open, the writer inspects segment and manifest state before appending.

- If the local origin's highest segment is manifested, the next append creates a new segment.
- If more than one segment is unmanifested, opening for write fails and requests repair.
- If a non-tail segment lacks a manifest, opening for write fails.
- If the open tail ends in bytes without a newline and those bytes parse as the
  exact next valid record with the expected origin sequence and previous hash, recovery
  appends and `fsync`s the missing newline; it does not discard the event.
- If a no-newline suffix cannot parse as a complete event, recovery may truncate
  only that incomplete suffix after verifying the preceding chain.
- If a no-newline suffix parses as JSON but violates the envelope, origin chain, or
  hash chain, opening fails closed rather than treating the bytes as an
  incomplete write.
- A complete newline-terminated record is never discarded automatically.
- Any sequence, hash-chain, or parse error before the incomplete suffix fails closed.

Recovery is tested at every step of append, close, checkpoint, and projection.

## Chain verification

`archive events verify` streams all segments and validates:

- directory ordering and filename/`first_seq` agreement;
- exactly zero or one unmanifested segment, which must be the tail;
- record JSON and envelope versions;
- enrolled origin identity and exact per-origin sequence continuity;
- per-line `previous_record_hash` continuity across segment boundaries;
- every manifest field, signature, causal base, previous-manifest link, path,
  IDs, counts, byte size, range, record hashes, and full-file BLAKE3;
- every accepted frontier's genesis binding, sorted complete origin set,
  monotonic ancestry, manifest reachability, and hash;
- immutability expectations for every closed segment;
- checkpoint segment lists and contiguous coverage.

Verification never treats the absence of a non-tail manifest as an acceptable open segment.
Closed segment bytes are hashed with a fixed-size buffer. The verifier then
parses at most one bounded record at a time and retains only rolling chain,
batch-digest, client-registry, and coordination state. A projector may read a
segment again after its full-file hash and batch completion have been validated;
this prevents unauthenticated bytes from reaching SQLite without retaining the
decoded segment in memory.

`archive fsck` composes this verifier with read-only `git fsck --full --strict`
and SQLite structural, foreign-key, identity, and per-origin cursor checks. It
does not call projection apply. With `--full`, it binds a consistent live
projection snapshot to a canonical Git commit/frontier, rebuilds from an
isolated disposable clone, and compares deterministic logical table digests. If
the projection is behind, the selected commit contains its historical applied
frontier; newer canonical events are not mistaken for projection divergence.
The live database and canonical working tree are never replaced or repaired.

## Checkpoints and replication

A checkpoint means an exact accepted frontier and canonical Git tree, not merely
that a command ran.

Checkpoint creation:

1. closes and signs the local tail;
2. validates and advances the local accepted frontier;
3. chooses a collision-safe checkpoint ID and final checkpoint path;
4. writes a checkpoint binding the exact genesis, frontier, and complete origin
   manifest set;
5. commits only immutable canonical files and the checkpoint to Git;
6. verifies the resulting commit and records a later checkpoint-commit
   observation batch;
7. optionally replicates the commit to configured independent destinations and
   records observed results separately.

Checkpoint format:

```json
{
  "checkpoint_v": 2,
  "checkpoint_id": "chk_01...",
  "created_time_utc_ms": 1783500000000,
  "archive_id": "arc_...",
  "genesis_hash": "blake3:...",
  "frontier_hash": "blake3:...",
  "canonical_git_commit": "..."
}
```

A checkpoint ID is unique and collision-safe; it is not derived from date and a truncated sequence alone.

Local commit status and independent replication status are distinct. Protection
names an exact frontier and commit containing its complete origin union; it
never reduces that proof to the sum, maximum, or local apply order of origin
sequences.

The post-commit observation is necessarily outside the commit it names. It is a
canonical, rebuildable fact in a later batch. If a crash occurs after Git commit creation but before that record is
durable, `archive checkpoint reconcile` locates a unique commit containing the
exact checkpoint path and frontier, verifies it, and appends the same
deterministic observation. It never guesses among multiple candidates. This
avoids embedding a commit identity in content that determines that identity.

Metadata destinations are registered canonically and refer to active locations.
Replication observations state the destination, commit, checkpoint/frontier
hash, resolved topology, and independence result at observation time. A matching
commit at a destination with unknown or overlapping topology is a replica but is
not reported as independent protection.

## SQLite projection contract

SQLite stores the accepted and applied frontier hashes, one applied
sequence/hash/manifest cursor per origin, and local projection/policy-input
generations. A scalar sequence never pretends to order concurrent origin
records.

### Incremental apply

`archive db apply` first validates the accepted frontier,
then compares it with SQLite's applied origin cursors. It verifies and streams
only each origin's missing closed ranges. Records whose causal base is not yet
satisfied remain unapplied until their dependencies arrive. Each bounded
transaction advances only the origin cursors it actually projects, and the
accepted-frontier marker advances only after all included ranges and required
batch completions have projected. A failure leaves every affected cursor before
the failing transaction. Neither normal apply nor synchronization reconstructs
the complete database or copies rows from another database.

The projector classifies every supported batch operation/item kind through one
versioned, exhaustive policy-input table. Collection, site, device,
mount/check-in, archive-root, location, risk-domain/assignment, policy,
content/identity/availability, completed scan coverage, and verification
outcomes advance the local policy-input generation. Archive initialization,
job/import summaries, scan starts/inert missing candidates, checkpoints,
catalog-location assignment, metadata-destination registry, and replication
observations do not. A new kind cannot project until this classification is
explicit and tested.

### Rebuild

`archive db rebuild` creates a replacement database beside the current database,
streams canonical history in bounded sequential passes, verifies the final
cursor, and atomically installs the replacement. It does not delete the only
usable database before the replacement succeeds.

Local-operational job progress and caches may be rebuilt or discarded. Derived archive facts must reproduce the same logical state.

### Normal reads

Status, file, copy, location, verification, policy, and risk commands query
SQLite. They remain usable when the event repository is temporarily unavailable,
while clearly reporting the last projected, checkpointed, and independently
replicated frontiers already stored in SQLite.

## Observation and job item rules

High-volume operations use local-operational queues for progress and canonical
batch items for durable outcomes. The logical names below are item/outcome kinds,
not separate physical event envelopes.

### Scans

- `scan_started` records the collection, location, optional logical-path prefix,
  resolved root/device identity, filesystem-boundary rule, traversal version,
  normalized exclusion rules and fingerprint, and mode `add` or `complete`. At
  most one canonical running scan may cover a location/collection/scope tuple.
- Positive changes may emit composite items containing `file_ref_observed`,
  `path_observed`, `copy_observed`, identity, and baseline `copy_verified`
  outcomes for new or changed
  content during the scan. A known unchanged entry refreshes coverage only.
- Ordinary symlinks emit no content or inventory events. Only a registered
  git-annex representation whose target validates inside the annex object store
  enters the annex-aware positive path; ignored-symlink counts are operational
  command summaries rather than canonical content claims.
- All positive items produced by the scan carry its scan ID. A path/copy item
  from another job in the same scope between start and completion forces a
  partial result; it is never silently included in complete coverage.
- After full enumeration, missing comparisons emit composite missing-candidate
  items carrying the scan ID. They are canonical but
  have no effect on current path/copy state while the scan is unfinalized.
- `batch_complete` records `complete` or `partial`, coverage parameters,
  observed counts/digests, and the count and ordered chunk-hash digest of every
  missing candidate. The projector validates this final manifest and, for a
  complete scan, activates all candidates in the same SQLite transaction as the
  completion and affected origin cursor.
- A partial completion declares zero activatable missing candidates. Candidates
  from an interrupted, failed, cancelled, malformed, or unfinalized scan remain
  inert and may later be pruned from SQLite.
- A partial scan never advances complete-coverage freshness.

An `add` scan is deliberately positive-only even when its requested subtree was
fully enumerated: it emits no missing candidates and never advances the larger
Location's complete-coverage freshness. A `complete` scan follows the missing
candidate and atomic publication rules below. Both modes share discovery,
hashing, event, and resume implementations.

Namespace coverage and byte integrity are separate. An enumerated regular file
whose content cannot be read remains a present unknown/non-qualifying fact with
a verification failure; that error alone does not hide names or make coverage
partial. New or metadata-changed content is hashed to establish identity.
Unchanged known content is not rehashed by default; routine rehashing belongs to
`archive verify`. Traversal or directory-stat errors that may hide entries make
the scan partial.

An unchanged complete scan emits coverage completion but no per-file change items.
At complete finalization, the covered observation set is inferred as every
current present, corrupt, or unknown fact that is inside the canonical
scope/exclusion rules, existed in the scan's causal base or was emitted by that scan,
and is not made missing by an effective candidate. Facts already `missing` or
`superseded` before the scan are excluded. The projector recomputes the declared
observation count/digest by streaming that canonical set in stable
encoded-path order. It then updates
`last_complete_scan_id` for the covered set in the same finalization transaction.
No local job row or per-file unchanged item is needed for replay. Causal
comparison ensures an effective missing candidate never overwrites a concurrent
or descendant positive/replacement fact for the same target.

### Verification

Every attempt emits a `copy_verified` item, including failures. Routine
successful verification uses bounded batches.

### Jobs

Batch start/completion carry canonical job summaries. Per-item queue state and
retry counters are local-operational. Durable per-item archive outcomes are
canonical items.

Before resuming a job, the writer applies the canonical tail, then reconciles
each local item against the canonical operation-key index. An already-recorded
outcome marks the item complete without another append. Before emitting a new
outcome, the writer holds the exclusive stream lock and rejects any existing
operation key. A crash can therefore leave local progress behind canonical
history, but cannot duplicate a canonical outcome.

The opt-in background stale-presence runner uses `job_started` and
`job_finished` only when a recognized connected Device has eligible work or an
existing job must be finished. Each successful targeted read emits the ordinary
content-observation/verification outcome, while mismatch and read failures emit
the ordinary verification-failure outcome. Deterministic operation keys make a
bounded run resumable. A disabled, paused, or idle scheduler invocation emits no
canonical event, and no background-specific content-event vocabulary exists.

### External staging

`archive stage` emits no canonical event, including no job event. Its checksum
manifest and last archive comparison are explicitly outside ledger state. A
stage audit cannot create or refresh inventory, presence, integrity, coverage,
topology, or policy evidence.

`archive stage import` has a durable local job and canonical `job_started` /
`job_finished` summaries, but no parallel `stage_*` content events. After it
copies and independently verifies a complete new destination subtree, the
existing positive-only add workflow emits the normal `device_checked_in`,
`scan_started`, content-observation, `copy_verified`, `scan_completed`, and scan
job-summary events. A failure before the destination tree is published or before
add begins emits no content observation for the staging source. Resume after
publication re-verifies the frozen imported selection before invoking add.

### Verified Location copy

`archive copy` uses the existing vocabulary rather than introducing a physical
`file_copied` event. The job emits `job_started`; a successfully validated mount
may emit `device_checked_in`; and each newly published destination Object emits
the normal `path_observed`, `copy_observed`, and `copy_verified` facts before
projection advances. A completed job emits `job_finished`. No destination
presence or verification event is emitted before the bytes have been published
without replacement and the final file has been read back successfully.

Each per-Object outcome has a deterministic operation key. Resume applies the
canonical tail and reconciles those keys before copying. If a crash occurred
after destination placement but before the canonical observation, resume accepts
that file only after hashing it to the expected identity, then records the
missing facts. A mismatching or unrelated existing path remains a hard collision.

## Event catalog

Registry events carry full current snapshots. Observation events carry the changed fact and enough identifiers to project without parsing unrelated state.

### Lifecycle and metadata

- `archive_initialized`
- `archive_updated`
- `client_enrolled`, `client_revoked`
- `catalog_location_set`
- `checkpoint_created`
- `checkpoint_commit_observed`
- `checkpoint_replication_observed`

### Registry

- `collection_registered`, `collection_updated`, `collection_retired`
- `site_registered`, `site_updated`, `site_retired`
- `device_registered`, `device_updated`, `device_moved`, `device_checked_in`, `device_retired`
- `device_mount_observed`
- `archive_root_registered`, `archive_root_updated`, `archive_root_retired`
- `location_registered`, `location_updated`, `location_retired`
- `metadata_destination_registered`, `metadata_destination_updated`, `metadata_destination_retired`
- `risk_domain_registered`, `risk_domain_updated`, `risk_domain_retired`
- `risk_assigned`, `risk_unassigned`
- `policy_registered`, `policy_updated`, `policy_retired`

### Content identity and inventory

- `external_identity_observed`
- `external_identity_resolved`
- `external_availability_observed`
- `annex_remote_mapped`, `annex_remote_unmapped`
- `object_observed`
- `object_hash_added`
- `file_ref_observed`, `file_ref_updated`, `file_ref_removed`
- `path_observed`, `path_missing_candidate`
- `copy_observed`, `copy_missing_candidate`

### Coverage, integrity, and jobs

- `scan_started`, `scan_completed`
- `copy_verified`
- `job_started`, `job_finished`
- `annex_import_started`, `annex_import_completed`

Repair, quarantine, and destructive-operation items are not yet part of the
vocabulary. Verified Location copy and stage import reuse existing job,
observation, and verification outcomes after safe placement rather than
reserving parallel speculative kinds. Stage audit remains non-canonical.

## Payload requirements

Detailed structs belong in code schemas generated or checked against fixtures, but these rules are normative:

- `archive_initialized` and `archive_updated` contain the stable Archive ID and
  current human display name; updates never change the ID;
- registry snapshots contain all user-controlled and identity fields, including
  Archive Root filesystem/partition identity evidence separately from Device
  hardware evidence;
- external identities contain namespace, key, expected size/hash when known, and source;
- paths use a versioned lossless value: `{encoding: "utf8", text: ...}` when
  possible, `{encoding: "unix_bytes", base64: ...}` for non-UTF-8 Unix names,
  and `{encoding: "windows_utf16le", base64: ...}` for otherwise
  non-representable Windows names. Unknown encodings fail closed; display
  strings are never used as identity;
- scan completion contains completeness, scope and exclusions fingerprints,
  scan mode, source-adapter/traversal version, observed counts/digests,
  missing-candidate count/digest, and structured error counts; `add` completion
  always declares zero activatable missing candidates;
- after a completed annex import, ordinary scan items may refresh the imported
  path representation, external availability, identity resolution, object,
  copy, and verification facts from direct filesystem observation; these events
  do not require or imply another source import;
- an annex scan records a locked copy at its lossless Location-relative
  `.git/annex/objects/...` path. If an earlier projection used the object-root-
  relative form, the first verified direct scan supersedes that old claim rather
  than counting both paths as independent copies;
- verification contains result, expected and observed hashes, bytes read, duration, path, device fingerprint result, and error detail;
- job completion distinguishes `complete`, `partial`, `failed`, and `cancelled`;
- annex import completion reports every category, including present, absent, unsupported, unresolved, mismatched, and ignored-by-explicit-rule counts;
- errors are structured values with stable codes; free text is supplemental.
- every resumable per-item outcome contains its deterministic `operation_key`;
  the projector rejects a key already associated with a different canonical
  outcome.

## Restore procedure

Without a usable portable snapshot, a clean machine:

1. obtain the event repository from an independent destination;
2. select the latest checkpoint whose commit, frontier, and origin set are available;
3. verify genesis, checkpoint/frontier coverage, signatures, and every origin chain;
4. stream-rebuild SQLite into a new file;
5. verify the applied per-origin cursors and frontier against the canonical tree;
6. reconcile checkpoint commit observations deterministically from repository
   history when the restored checkpoint predates those observations;
7. run metadata status and report any unreplicated tail known from other records;
8. leave archive content untouched.

The acceptance suite performs this procedure without relying on the original
SQLite database or catalog host. Clone may first validate and atomically install
a portable SQLite snapshot bound to the Archive ID,
canonical Git commit, accepted frontier, schema version, projector version, and
database BLAKE3. It then applies only later origin ranges. The snapshot contains
no private keys, credentials, local discovery configuration, live mount-
availability caches, or unfinished jobs; canonical mount evidence remains
projected. It is never canonical history. Any binding or integrity
failure rejects it before it can replace a usable database; full streaming
rebuild remains the recovery path.
