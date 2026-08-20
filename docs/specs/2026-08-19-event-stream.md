# Archive Ledger Canonical Event Stream Specification

Status: authoritative

Date: 2026-08-19

This document defines the durable event log, its crash and checkpoint invariants,
and its relationship to SQLite. Product semantics are defined in the
[product specification](2026-08-19-product.md); projection tables are defined in
the [schema specification](2026-08-19-schema.md).

## Authority and writer model

The JSONL event stream is canonical archive metadata. SQLite is a rebuildable materialized view.

Each named Archive owns one independent stream. Per-user discovery/default
configuration points to Archive directories but is not part of, and cannot
override, canonical Archive identity.

The MVP has exactly one stream and one writer at a time:

- `stream_id` is `stream_primary`;
- `seq` starts at 1 and increases by exactly 1;
- an exclusive archive lock serializes writers;
- multi-writer merge is out of scope.

Single-writer describes catalog mutation, not the number of devices or locations being tracked.

## Envelope

Each event is one UTF-8 JSON object on one line:

```json
{
  "v": 1,
  "stream_id": "stream_primary",
  "seq": 184220,
  "event_id": "evt_01jz8p1kh9x6s4v8q0k1",
  "event_type": "copy_verified",
  "time_utc_ms": 1781042405123,
  "actor_id": "alice",
  "host_id": "dev_primary_pc",
  "job_id": "job_01jz8p...",
  "object_id": "blake3:2c7f...",
  "file_ref_id": null,
  "copy_claim_id": "copy_01jz8n...",
  "location_id": "loc_usb8tb_a_photos",
  "device_id": "dev_usb8tb_a",
  "site_id": null,
  "previous_event_hash": "blake3:a91e...",
  "payload": {}
}
```

Rules:

- `v` is the envelope version.
- `event_id` is `evt_` plus a lowercase ULID.
- entity-reference fields are populated when relevant and `null` otherwise.
- `previous_event_hash` is `null` only for sequence 1.
- an event never embeds its own hash.
- payloads contain structured JSON, never JSON encoded inside strings.
- canonical outcome events produced by resumable work contain an
  `operation_key`; keys are deterministic for the job ID, input version, item,
  and outcome kind and are unique within the stream.
- unknown envelope versions or event types fail projection; they are not silently skipped.

## Physical serialization and hashing

The exact line bytes are canonical. There is no JSON canonicalization step.

```text
event_hash = "blake3:" + lowercase_hex(BLAKE3(exact_line_bytes_without_newline))
```

The hash of event N is stored in event N+1 as `previous_event_hash`. Writers serialize an event once and append those exact bytes plus one `\n`. Closed event bytes are never reformatted, normalized, or rewritten.

## Directory layout

```text
events/
  stream_primary/
    seg-000000000001.jsonl
    seg-000000100001.jsonl
manifests/
  stream_primary/
    seg-000000000001.manifest.json
checkpoints/
  chk-000000184220.json
```

Segment names contain the first sequence number, zero-padded to 12 digits. Manifest and checkpoint paths are repository-relative and must not escape the event repository.

## Segment state machine

At every stable point, all of these invariants hold:

1. Segments are ordered by their first sequence.
2. Sequence ranges are contiguous from 1 through the stream tail.
3. Every segment except possibly the highest-numbered segment has a valid manifest.
4. At most one segment lacks a manifest. It is the append-only open tail.
5. A manifested segment is closed and immutable.
6. A writer never appends to a segment whose manifest exists.
7. A new segment starts only after the previous segment has been closed successfully.

The default rollover threshold is 100,000 events. Reaching the threshold invokes the same authoritative close operation as an explicit checkpoint. Resetting an in-memory segment pointer without closing the file is forbidden.

### Append protocol

For each bounded event batch:

1. Acquire the exclusive writer lock.
2. Verify the open tail and recover only an incomplete final write as described below.
3. Assign envelope fields and serialize each event once.
4. When creating a segment, create and open it without replacing any existing
   path.
5. Append complete lines in sequence and `fsync` the file.
6. For the first durable batch in a new segment, `fsync` the event directory
   where supported before reporting the batch durable.
7. If the threshold is reached, close the segment before opening the next one.

SQLite application happens after event durability. A failure between append and projection is recovered by applying the unapplied tail.

### Close protocol

Closing a segment:

1. flushes and `fsync`s the segment;
2. streams the segment to validate every event and compute manifest values;
3. writes the manifest to a temporary file in the manifest directory;
4. `fsync`s the temporary manifest;
5. atomically renames it to the final manifest path;
6. `fsync`s the manifest directory where supported;
7. marks the in-memory segment closed and permits a new segment.

The final manifest contains:

```json
{
  "manifest_v": 1,
  "stream_id": "stream_primary",
  "segment_file": "events/stream_primary/seg-000000000001.jsonl",
  "first_seq": 1,
  "last_seq": 100000,
  "first_event_id": "evt_...",
  "last_event_id": "evt_...",
  "last_event_hash": "blake3:...",
  "event_count": 100000,
  "segment_size_bytes": 41238771,
  "segment_blake3": "blake3:..."
}
```

### Restart and tail recovery

On open, the writer inspects segment and manifest state before appending.

- If the highest segment is manifested, the next append creates a new segment.
- If more than one segment is unmanifested, opening for write fails and requests repair.
- If a non-tail segment lacks a manifest, opening for write fails.
- If the open tail ends in bytes without a newline and those bytes parse as the
  exact next valid event with the expected sequence and previous hash, recovery
  appends and `fsync`s the missing newline; it does not discard the event.
- If a no-newline suffix cannot parse as a complete event, recovery may truncate
  only that incomplete suffix after verifying the preceding chain.
- If a no-newline suffix parses as JSON but violates the envelope, sequence, or
  hash chain, opening fails closed rather than treating the bytes as an
  incomplete write.
- A complete newline-terminated event is never discarded automatically.
- Any sequence, hash-chain, or parse error before the incomplete suffix fails closed.

Recovery is tested at every step of append, close, checkpoint, and projection.

## Chain verification

`archive events verify` streams all segments and validates:

- directory ordering and filename/`first_seq` agreement;
- exactly zero or one unmanifested segment, which must be the tail;
- event JSON and envelope versions;
- `stream_id` and exact sequence continuity;
- per-line `previous_event_hash` continuity across segment boundaries;
- every manifest field, including paths, IDs, counts, byte size, ranges, last hash, and full-file BLAKE3;
- immutability expectations for every closed segment;
- checkpoint segment lists and contiguous coverage.

Verification never treats the absence of a non-tail manifest as an acceptable open segment.

## Checkpoints and replication

A checkpoint means a contiguous closed prefix of canonical history, not merely that a command ran.

Checkpoint creation:

1. chooses a collision-safe checkpoint ID and final checkpoint path;
2. closes the current open segment, even below the threshold;
3. appends `checkpoint_created` in a new segment with the checkpoint ID, path, and
   its assigned sequence as `event_last_seq`;
4. immediately closes that segment, making the checkpoint event part of the
   checkpointed prefix;
5. verifies contiguous manifested coverage from sequence 1 through that event;
6. writes a checkpoint file listing every covered segment and manifest, using the
   checkpoint event's physical event hash as `event_last_hash`;
7. commits only closed segments, manifests, and the checkpoint file to Git;
8. verifies the resulting commit and appends `checkpoint_commit_observed` with
   the checkpoint ID and commit identity;
9. optionally replicates the commit to configured independent destinations and
   records observed results separately.

The checkpoint event does not embed its own hash. During projection, its envelope
sequence and computed physical event hash supply the checkpoint's covered tail.
After a successful checkpoint there may be no open segment; the next mutation
creates one. A restart that finds a closed checkpoint-event segment without its
checkpoint file either completes that exact pending checkpoint deterministically
or fails closed; it never invents a different checkpoint ID.

Checkpoint format:

```json
{
  "checkpoint_v": 1,
  "checkpoint_id": "chk-000000184220",
  "created_time_utc_ms": 1783500000000,
  "stream_id": "stream_primary",
  "event_first_seq": 1,
  "event_last_seq": 184220,
  "event_last_hash": "blake3:...",
  "segments": [
    {
      "file": "events/stream_primary/seg-000000000001.jsonl",
      "manifest": "manifests/stream_primary/seg-000000000001.manifest.json",
      "segment_blake3": "blake3:..."
    }
  ]
}
```

A checkpoint ID is unique and collision-safe; it is not derived from date and a truncated sequence alone.

Local commit status and independent replication status are distinct. “Protected through N” requires successful observation of a matching checkpoint/commit at an independent destination.

The post-commit observation is necessarily outside the commit it names. It is a
canonical, rebuildable fact in the open tail and will be included by a later
checkpoint. If a crash occurs after Git commit creation but before that event is
durable, `archive checkpoint reconcile` locates a unique commit containing the
exact checkpoint path and covered segment set, verifies it, and appends the same
deterministic observation. It never guesses among multiple candidates. This
avoids embedding a commit identity in content that determines that identity.

Metadata destinations are registered canonically and refer to active locations.
Replication observations state the destination, commit, checkpoint sequence and
hash, resolved topology, and independence result at observation time. A matching
commit at a destination with unknown or overlapping topology is a replica but is
not reported as independent protection.

## SQLite projection contract

SQLite stores `applied_event_seq`, `applied_event_hash`, and the greatest
policy-relevant event sequence as `policy_input_event_seq` in `archive_meta`.

### Incremental apply

`archive db apply`:

1. reads applied sequence N from SQLite;
2. locates the first segment whose range can contain N+1 using filenames/manifests;
3. streams only events N+1 through the current tail;
4. verifies sequence and previous hash against SQLite's applied hash;
5. applies bounded transactions, updating projection rows and the applied cursor atomically;
6. stops without advancing the cursor if any event in a transaction fails.

It must not allocate all historical events or scan segments wholly below N.

The projector classifies every supported event type through one versioned,
exhaustive policy-input table. Collection, site, device, mount/check-in,
archive-root, location, risk-domain/assignment, and policy events advance the
sequence, as do content/identity/availability facts, scan completion, and
verification outcomes. Archive initialization, job/import summaries, scan
starts/provisional missing candidates, checkpoints, catalog-location assignment,
metadata-destination registry, and replication observations do not. A new event
type cannot project until this classification is explicit and tested.

### Rebuild

`archive db rebuild` creates a replacement database beside the current database, streams canonical history once, verifies the final cursor, and atomically installs the replacement. It does not delete the only usable database before the replacement succeeds.

Local-operational job progress and caches may be rebuilt or discarded. Derived archive facts must reproduce the same logical state.

### Normal reads

Status, file, copy, location, verification, policy, and risk commands query SQLite. They remain usable when the event repository is temporarily unavailable, while clearly reporting the last projected and checkpointed sequences already stored in SQLite.

## Observation and job event rules

High-volume operations use local-operational queues for progress and canonical events for durable outcomes.

### Scans

- `scan_started` records the collection, location, optional logical-path prefix,
  resolved root/device identity, filesystem-boundary rule, traversal version,
  normalized exclusion rules and fingerprint, and mode `add` or `complete`. At
  most one canonical running scan may cover a location/collection/scope tuple.
- Positive changes may emit `file_ref_observed`, `path_observed`, `copy_observed`,
  identity events, and baseline `copy_verified` outcomes for new or changed
  content during the scan. A known unchanged entry refreshes coverage only.
- All positive events produced by the scan carry its scan ID. A path/copy event
  from another job in the same scope between start and completion forces a
  partial result; it is never silently included in complete coverage.
- After full enumeration, missing comparisons emit `path_missing_candidate` and
  `copy_missing_candidate` events carrying the scan ID. They are canonical but
  have no effect on current path/copy state while the scan is unfinalized.
- `scan_completed` records `complete` or `partial`, coverage parameters, observed
  counts/digests, and the count and ordered event-hash digest of every missing
  candidate. The projector validates this final manifest and, for a complete
  scan, activates all candidates in the same SQLite transaction as the event and
  applied cursor.
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

An unchanged complete scan emits a coverage event but no per-file change events.
At complete finalization, the covered observation set is inferred as every
current present, corrupt, or unknown fact that is inside the canonical
scope/exclusion rules, existed when the scan started or was emitted by that scan,
and is not made missing by an effective candidate. Facts already `missing` or
`superseded` before the scan are excluded. The projector recomputes the declared
observation count/digest by streaming that event-derived set in stable
encoded-path order. It then updates
`last_complete_scan_id` for the covered set in the same finalization transaction.
No local job row or per-file unchanged event is needed for replay.
Activation preserves canonical event order: an effective missing candidate can
never overwrite a newer positive or replacement fact for the same target.

### Verification

Every attempt emits `copy_verified`, including failures. Routine successful verification volume is accepted as canonical until measurements justify a hashed-manifest representation; no alternate representation is implemented speculatively.

### Jobs

`job_started` and `job_finished` are canonical summaries. Per-item queue state and retry counters are local-operational. Durable per-item archive outcomes have their own canonical events.

Before resuming a job, the writer applies the canonical tail, then reconciles
each local item against the event-derived operation-key index. An already-recorded
outcome marks the item complete without another append. Before emitting a new
outcome, the writer holds the exclusive stream lock and rejects any existing
operation key. A crash can therefore leave local progress behind canonical
history, but cannot duplicate a canonical outcome.

## Event catalog

Registry events carry full current snapshots. Observation events carry the changed fact and enough identifiers to project without parsing unrelated state.

### Lifecycle and metadata

- `archive_initialized`
- `archive_updated`
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

Copy, repair, quarantine, and destructive-operation events are not part of the MVP vocabulary. They will be specified with those operations rather than reserved prematurely.

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
  scan mode, observed counts/digests, missing-candidate count/digest, and
  structured error counts; `add` completion always declares zero activatable
  missing candidates;
- verification contains result, expected and observed hashes, bytes read, duration, path, device fingerprint result, and error detail;
- job completion distinguishes `complete`, `partial`, `failed`, and `cancelled`;
- annex import completion reports every category, including present, absent, unsupported, unresolved, mismatched, and ignored-by-explicit-rule counts;
- errors are structured values with stable codes; free text is supplemental.
- every resumable per-item outcome contains its deterministic `operation_key`;
  the projector rejects a key already associated with a different event.

Schema upgrades do not rewrite old event lines. When replaying version 1 history
created before named Archives, an `archive_initialized` payload without a
display name deterministically uses its Archive ID as the initial display name
until an `archive_updated` event supplies one. Legacy annex imports that named
separate worktree and CAS Locations retain those topology facts; new imports use
one repository Location and never synthesize a history rewrite.

## Restore procedure

On a clean machine:

1. obtain the event repository from an independent destination;
2. select the latest checkpoint whose commit and segment set are available;
3. verify checkpoint coverage and the full available chain;
4. stream-rebuild SQLite into a new file;
5. verify `applied_event_seq` and `applied_event_hash` against the stream tail;
6. reconcile checkpoint commit observations deterministically from repository
   history when the restored checkpoint predates those observations;
7. run metadata status and report any unreplicated tail known from other records;
8. leave archive content untouched.

The acceptance suite performs this procedure without relying on the original SQLite database or catalog host.
