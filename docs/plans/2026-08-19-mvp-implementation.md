# Archive Ledger MVP Implementation Plan

Status: active

Date: 2026-08-19

This plan implements the authoritative
[product](../specs/2026-08-19-product.md),
[event-stream](../specs/2026-08-19-event-stream.md), and
[schema](../specs/2026-08-19-schema.md) specifications. Beads is the durable task
tracker; this document defines sequencing, boundaries, and release gates rather
than duplicating issue status with checkboxes.

## Goal

Deliver a single-user Rust CLI that can safely inventory at least 500,000 files across multiple storage devices and sites, provide fast SQLite-backed review, verify copy integrity, identify actionable permanent-loss risks, and restore its canonical metadata after loss of the catalog host—without mutating archive content.

## Traceability

The initial specification revision is tracked by `al-g18`; the independent
review corrections are tracked by `al-yyb` and gate foundation implementation.
The resulting implementation work is:

| Beads issue | Required outcome |
| --- | --- |
| `al-8zk` | Loss-safe segment rollover, verification, and checkpoints |
| `al-e2s` | Streaming event application and filesystem discovery with bounded memory |
| `al-77q` | Complete inventory, including unavailable and supported non-symlink annex content |
| `al-wim` | Safe scan coverage, device check-in, and catalog freshness |
| `al-9nm` | Trustworthy verification, policies, and device/site/shared-domain loss analysis |
| `al-cgn` | Independent metadata replication status and clean-machine restore proof |
| `al-950` | Human-friendly and structured review/management CLI |
| `al-skp` | Centralized named catalogs and ergonomic Collection/Location workflows |

Implementation work must update the matching issue with observed evidence and discovered constraints. New durable work is recorded in Beads, not appended as checkboxes here.

## Non-negotiable constraints

- Existing archives and git-annex repositories are read-only.
- Tests use disposable fixtures; no real archive is scanned or verified without explicit user selection.
- Canonical events are appended before SQLite projection.
- Normal review commands query SQLite only.
- Incremental projection reads only unapplied events.
- Full event operations stream in bounded memory.
- Closed event segments are immutable, and every non-tail segment is manifested.
- No unverified or stale claim silently satisfies a policy.
- No MVP command copies, repairs, quarantines, or deletes archive content.
- Human defaults and `--json` share the same authoritative query/service path.

## Deliberate economy

Reliability comes from a few explicit invariants, not extra infrastructure:

- one process holds the canonical writer lock; there is no service or distributed transaction;
- scan negatives stage in SQLite and activate with one set-based finalization transaction;
- each collection has one policy, with no selector precedence engine;
- a policy cache is wholly stale when its global policy-input sequence, policy
  version, or time envelope changes; there is no per-file dependency graph;
- continuation tokens fail as stale when SQLite advances instead of retaining cross-command snapshots;
- git-annex remote claims remain hints until ordinary observed and verified copy facts exist;
- performance work follows the 500,000-file measurements rather than speculative parallelism.

## Technology direction

Use Rust 2021 or newer stable Rust with the repository's established toolchain once scaffolded. Expected components include:

- `clap` for the CLI;
- `serde`/`serde_json` for versioned event and output schemas;
- `rusqlite` with bundled SQLite;
- `blake3` and source-hash implementations;
- file locking and explicit sync primitives;
- a bounded traversal/worker pipeline rather than an archive-sized `Vec`;
- `tempfile`, CLI assertions, and generated disposable fixtures for tests.

Dependency versions are selected during scaffold work and locked. The plan does not embed a large speculative implementation listing.

## Phase 1: Safety and streaming foundation

Phases 1A and 1B are the first implementation work after `al-yyb`. They may proceed in parallel only if file ownership is isolated and integration tests are agreed first.

### 1A. Canonical event store (`al-8zk`)

Implement:

- versioned event envelope and exact-line hashing;
- exclusive writer lock;
- bounded batch append and `fsync`;
- parent-directory `fsync`, where supported, before a new segment's first batch
  is reported durable;
- one authoritative close-on-threshold/close-on-checkpoint path;
- atomic manifest publication;
- restart recovery that never appends to a manifested segment;
- streaming chain and checkpoint verification;
- stable damaged-history errors.

Primary tests:

- append and reopen continuity;
- automatic rollover across at least three segments;
- exactly one optional unmanifested tail;
- missing non-tail manifest rejection;
- manifest field, byte, sequence, and cross-segment hash tampering;
- incomplete final-line recovery;
- a valid complete tail event missing only its newline is completed and retained,
  while malformed or chain-invalid tails follow the fail-closed recovery rules;
- crash injection at every append and close transition;
- crash injection between new-segment creation, file sync, and event-directory sync;
- checkpoint coverage from sequence 1 through N.

Exit gate: no later phase may generate high-volume events until multi-segment and crash-boundary tests pass.

### 1B. SQLite schema and streaming projector (`al-e2s`)

Implement schema version 4 and:

- event-derived versus local-operational migrations;
- streaming segment iterator starting at a requested sequence;
- manifest-assisted segment selection;
- bounded projection transactions with prepared statements;
- atomic applied sequence/hash cursor;
- event-derived operation-key uniqueness used by resumable job reconciliation;
- an exhaustive event-type classification that advances the global
  policy-input sequence only for file policy/risk inputs;
- replacement-file rebuild rather than deleting the current database first;
- deterministic logical-state comparison between incremental apply and rebuild.

Primary tests:

- a one-event mutation reads only the tail after a large history;
- a rebuild streams every event exactly once;
- failures leave the cursor before the failing event;
- restart resumes without duplicate derived rows;
- duplicate operation keys fail projection without advancing the cursor;
- every supported event type is covered by the policy-input classification test;
- normal status queries succeed with the event directory temporarily unavailable;
- peak memory is independent of event count within configured batch bounds.

Exit gate: demonstrate linear event application on a generated multi-segment stream.

## Phase 2: Registry and storage topology

Implement the shared registry service and CLI for collections, sites, devices, roots, locations, risk domains, and policies.

Required behavior:

- full-snapshot canonical events for register/update/retire transitions;
- stable display names and IDs;
- Device and Archive Root discovery where supported;
- separate Device hardware and Archive Root filesystem/partition fingerprint
  evidence with explicit “unavailable” confidence;
- fingerprint mismatch fail-closed behavior;
- validated root-to-device and location-to-root relationships;
- partial uniqueness for active confirmed device fingerprints and explicit
  conflict handling rather than duplicate device independence;
- current device placement plus history;
- automatic structural device/site loss domains;
- validated polymorphic custom risk assignments;
- versioned policy input validation before append;
- exactly one policy and home-site assignment per collection, with unconfigured
  collections reported uncertain;
- canonical assignment of the catalog repository to an already registered
  device-backed location;
- registry correction without history rewrite.

Primary tests use two same-model removable drives, a filesystem UUID observed at
changed mount paths, a fingerprint mismatch, a duplicate/cloned filesystem
fingerprint, an offline drive, device
movement between sites, invalid all-null and mismatched root/device locations,
and duplicate inherited risk assignments.

Exit gate: the catalog can distinguish devices independently of mount path and explain all unknown topology.

## Phase 3: Complete git-annex inventory (`al-77q`, built on `al-e2s`)

Implement a read-only importer with a bounded discovery-to-hash-to-event pipeline.

### Discovery

Support source representations proven by fixtures, including locked symlinks and selected unlocked/adjusted forms. Use read-only git/git-annex metadata interfaces when necessary; never mutate annex state.

Every encountered entry ends in a documented category:

- locally present and readable;
- locally absent/dropped;
- supported but unresolved;
- unsupported external identity;
- hash/size mismatch;
- read error;
- excluded by an explicit user rule.

There is no silent “other file” bucket.

### Identity and facts

- Create external identities before bytes are required.
- Preserve file references for dropped/unavailable content.
- Record source-reported remote UUID/key availability in the dedicated
  non-qualifying availability table; optional UUID-to-location mapping still
  does not create a copy claim.
- Expose remote UUID mapping through `archive annex-remote list|map|unmap`.
- When bytes are available, compute BLAKE3 and the expected source hash in one streaming read where practical.
- Emit resolution and successful import-time verification facts.
- Emit durable mismatch/read-error verification outcomes.
- Deduplicate facts across a bounded batch and against indexed SQLite state.
- Use one user-facing Location per annex repository; worktree and annex
  object-store representations are paths inside it.
- Derive collision-safe location/import IDs and validate repository path, root, and device agreement.

### Resume

The local job queue checkpoints discovery progress. Each canonical per-item fact
has a deterministic operation key derived from the immutable import input, job
ID, and item/outcome identity. Resume applies the event tail and reconciles those keys
before queue work, so a crash after event durability cannot duplicate facts.
Source changes during import produce an explicit partial/conflict result.

Primary fixtures cover present and dropped content, duplicate paths, identical bytes under different keys, multiple repositories/devices, supported representations, unsupported keys, mismatches, unreadable content, interruption, and a repository that changes during import.

Exit gate: every known logical file is reviewable even when no local bytes exist, and the importer proves no writes occurred inside source repositories.

## Phase 4: Safe scanning and freshness (`al-wim`)

Implement bounded, resumable location scans.

Required behavior:

- require one location, collection, and optional logical prefix; record lossless
  scope paths, traversal version, exclusion fingerprint, filesystem-boundary
  rule, device fingerprint, and start state;
- inventory regular files while hashing in a streaming pipeline; do not follow
  symlinks, cross the selected filesystem, or admit path escapes, and count
  symlinks/special files/exclusions explicitly;
- record baseline successful verification from the discovery read; a read/hash
  failure records a present unknown/non-qualifying entry and integrity failure
  without invalidating otherwise complete namespace coverage;
- refresh observation only for known entries with unchanged stable metadata;
  use `archive verify` for routine rehashing and identity establishment retries;
- stream positive observations;
- compare unseen prior facts only after successful full enumeration;
- emit inert missing candidates only after successful full enumeration;
- use deterministic job/item/outcome keys so resuming cannot duplicate positive
  observations or missing candidates;
- finalize candidate count/digest and activate all negative outcomes with the
  complete scan event in one SQLite transaction;
- infer unchanged coverage canonically from start sequence, normalized scope and
  exclusions, scan-tagged positives, and effective missing candidates; rebuild
  must reproduce its digest and `last_complete_scan_id` values without job rows;
- reject a second running scan for the same scope and make an interleaved
  same-scope inventory writer force partial completion;
- classify interruption, permissions, I/O errors, device removal, and concurrent changes as partial;
- never refresh complete-coverage age after a partial scan;
- track device check-in and expected/offline availability separately;
- surface observation horizon and uncertainty in every relevant query.
- expose the same engine as positive-only `archive location add [path]` and
  complete-reconciliation `archive location scan [location]`; add mode never
  activates missing candidates or refreshes complete Location coverage.

Primary tests:

- permission-denied subtree;
- unplugged device during scan;
- cancellation and resume;
- exclusion change;
- file creation/removal during traversal;
- stable-snapshot source versus ordinary live filesystem;
- complete scan correctly marking a prior path missing;
- partial scan never doing so;
- crash after zero, some, or all candidate events but before completion;
- completion count/digest mismatch and activation-transaction rollback;
- unchanged complete scan followed by clean rebuild with identical coverage freshness;
- one unreadable/corrupt file alongside a large otherwise complete namespace;
- non-UTF-8 paths, symlinks, special files, filesystem boundaries, and path escapes.

Exit gate: no tested incomplete traversal can create a false missing fact or a false fresh-coverage claim.

## Phase 5: Verification, policy, and risk (`al-9nm`)

### Verification jobs

Implement bounded, resumable verification by exact copy claim. Outcomes are canonical and update hot current-state fields.

Tests cover success, mismatch, read error, identity mismatch, device mismatch,
path content replacement, stale success followed by failure, later recovery,
retired topology, interruption after event append but before queue completion,
and retry without duplicate outcomes.

### Qualifying-copy evaluator

Implement the product specification's qualifying-copy predicate once. Status, policy, and risk reports all call the same implementation.

Tests prove:

- present but never verified does not qualify;
- stale or later-invalidated success does not qualify;
- expected offline media respects explicit freshness limits;
- two paths or locations on one device do not count as two devices;
- unknown encryption or topology cannot satisfy a requirement;
- inactive collection/location/root/device/site state cannot qualify a copy.

### Policy and disaster simulation

Assign exactly one active policy and home site per collection, then evaluate:

- minimum qualifying copies, devices, and sites;
- offsite, offline, encryption, verification-age, observation-age, and check-in requirements;
- loss of each device;
- loss of each device-less service location;
- loss of each site;
- loss of each custom shared domain with distinct inherited mappings.

Results store violations/uncertainty only beneath a complete evaluation envelope
that records the event cursor and binds policy-input sequence, policy version,
full file count, and earliest
freshness expiry. Validity compares a global, exhaustive policy-input event
sequence, so checkpoint/job/replication events do not cause reevaluation. Any
relevant-sequence mismatch is stale/unknown. Rollups separate known bytes
from unknown-size files. Explanations include logical paths, failing facts, and
non-destructive next actions.

Primary scenario: at least three devices at two sites with shared power/account domains, one stale offline drive, one corrupt copy, one unresolved file, and one unclassified service location.

Additional tests advance time past the first freshness deadline, append a
relevant fact, and update a policy. Each invalidates the cache without displaying
false compliance. A checkpoint, job summary, and metadata replication event do
not invalidate it. The collection home site defines offsite; absent home/policy
configuration is uncertain. Tests cover every allowed/unknown service-location
classification value.

Exit gate: manually calculated expected outcomes match human and JSON reports for every scenario.

## Phase 6: Metadata checkpoints and restore (`al-cgn`, built on `al-8zk`)

Implement:

- checkpoint creation over a verified contiguous closed prefix;
- a closed checkpoint-event segment included in that same checkpoint;
- explicit staging that excludes any later open tail;
- local commit identity;
- post-commit canonical observation and deterministic reconciliation after a
  crash between commit creation and event append;
- configuration of independent metadata destinations without embedding credentials;
- destination registry and topology validation against the catalog location,
  rejecting same-device, same-site, shared-domain, and unknown cases as
  independent protection;
- replication attempt and observed destination state;
- status distinction among appended, projected, checkpointed, committed, and independently protected sequences;
- `archive restore check` and documented clean-machine restore.

Primary tests:

- local checkpoint is not labeled protected;
- matching independent destination is protected through exactly N;
- a same-disk Git remote is visible as a replica but is not independent;
- missing/diverged destination is visible;
- uncheckpointed/open tail is visible;
- primary catalog directory is destroyed only in a disposable fixture, then restored from the independent destination;
- restored chain verifies and rebuilds logically identical SQLite state.

Exit gate: the acceptance fixture survives loss of the catalog host without using its SQLite database.

## Phase 7: Review and management CLI (`al-950`)

Implement one query/service layer used by both human and structured output after
the underlying facts and policy semantics are trustworthy:

- concise status with urgent findings first;
- centralized Archive discovery/default selection with an explicit-path escape
  hatch for existing catalogs;
- Archive, Collection, Device, Location, and Site display-name rename helpers;
- Device move and cwd-aware Collection/Location initialization helpers;
- collection/device/location listing, detail, update, and retirement;
- SQLite-backed Collection and Location status rollups;
- a concise stale-presence report grouped by Device, optionally expanded to
  Locations, that displays applicable observation-age thresholds;
- archive-root and metadata-destination listing, detail, update, checking, and retirement;
- policy and risk-domain update/retirement;
- file find/show/history;
- object show/history;
- copy list/show;
- job list/show/resume;
- file/copy detail explaining evidence and freshness;
- risk reports grouped by actionable cause, collection, logical path, file count, and bytes;
- filters for collection, device, site, location, policy, result, and age;
- explicit “show all” or continuation behavior rather than hidden sample caps;
- safe registry update/retire flows;
- shell-friendly exit statuses and versioned JSON.

Human output leads with logical paths and display names. It includes object and
external IDs as supporting detail. Structured output has a version field, stable
error codes, deterministic ordering, limits, and continuation tokens bound to
query shape and applied sequence; changed projections return
`stale_continuation`.

Primary tests verify exact and prefix path search, multiple logical paths to one
object, unresolved content, large paginated result sets including an intervening
projection change, lossless Unicode/non-UTF-8 round trips, stable JSON snapshots,
and error exit statuses.

Run usability walkthroughs from an empty archive and from the full disaster
fixture. `archive init` creates only a centrally stored named Archive. The user
then runs `archive collection init` in the initial content directory; it infers
the mounted root and known Device when safe and prompts only for missing Device
and Site facts. Additional ordinary and annex repositories use Location-scoped
commands. Avoid requiring users to invent internal IDs where discovery or
generated defaults are safe.

## Phase 7A: Ergonomic workflow revision (`al-skp`)

Implement the accepted revision in dependency order:

1. update the authoritative product, event, schema, and this implementation
   contract, removing superseded command descriptions;
2. add a dependency-checking `Makefile` whose default `make install` builds a
   release binary and installs under `${PREFIX:-$HOME/.local}` without `sudo`;
3. add canonical Archive display names, centralized per-user catalog discovery,
   default selection, and safe explicit-path access to existing catalogs;
4. add Archive Root filesystem identity and cwd/mount inference, then guided
   Collection/Location initialization and one-Location annex import;
5. add stable-ID-preserving rename helpers, Device Site movement, and cached
   Collection/Location status;
6. expose positive-only Location add and complete Location scan through the
   existing scan engine;
7. add the concise stale-presence report and verify its grouped queries at the
   established 500,000-file scale.

Background scanning of connected Devices and file-copy mutation did not expand
this read-only phase. Both were subsequently implemented as narrow post-MVP
features: verified copy is no-replace, and background work is an opt-in bounded
one-shot command for external schedulers rather than a custom daemon.

## Phase 8: Scale and release gate

Generate a deterministic fixture with at least:

- 500,000 active logical file references;
- present and dropped external identities;
- duplicate objects;
- at least three copy claims for a substantial subset;
- multiple devices/sites/risk domains;
- enough events to cross at least three segment boundaries.

Measure and record outside product source:

- elapsed import, incremental apply, rebuild, verification, checkpoint, and representative report times;
- peak resident memory;
- event, SQLite, and manifest sizes;
- events and SQL work per file;
- interruption/resume behavior;
- one complete scan with at least 500,000 covered facts and 500,000 missing
  candidates to exercise free-space preflight, set-based activation, rollback,
  WAL/disk growth, and bounded memory;
- actual filesystem discovery and git-annex import at fixture scale, rather than
  only pre-generated event replay;
- query plans for the hot report paths.
- concise Device/Location stale-presence rollups under mixed Collection policy
  thresholds.

Release requirements:

- memory remains within configured bounded pipelines rather than growing with total events/files;
- incremental apply does not read historical segments below its cursor;
- work is observably linear for the tested scale;
- report latency is suitable for interactive CLI use or clearly reports a durable background job;
- all product acceptance scenarios pass on disposable fixtures;
- policy evaluation at scale reports cache validity and unknown-size rollups correctly;
- event-chain and clean-machine restore gates pass;
- source repositories have unchanged content and metadata relevant to the read-only promise.

If a threshold cannot be met, optimize the measured bottleneck. Do not add speculative parallelism or alternate canonical formats without evidence.

## Verification matrix

Each important rule has one primary owner:

| Rule | Primary verification |
| --- | --- |
| Segment and checkpoint invariants | event-store integration tests with crash injection |
| Incremental tail-only apply | iterator/projection instrumentation test |
| Logical replay determinism | incremental-versus-rebuild state comparison |
| Complete annex inventory | multi-layout disposable annex fixtures |
| Partial-scan safety | scanner integration tests |
| Scan-negative atomicity | crash-injected candidate/finalization integration tests |
| Durable job idempotency | event-append/queue-completion crash tests |
| Import and ongoing integrity | per-copy verification tests |
| Qualifying-copy semantics | policy evaluator unit/property cases |
| Policy cache validity | event/version/time invalidation tests |
| Device/site/shared-risk loss | disaster-scenario integration fixture |
| Human/JSON agreement | shared query result and CLI snapshot tests |
| Cwd/root inference and removable remount | disposable mount-discovery adapter tests |
| Stale-presence grouping and thresholds | projection query and CLI fixture tests |
| Metadata restorability | destructive clean-machine fixture restore |
| Metadata destination independence | topology and same-disk rejection tests |
| Lossless paths and pagination | platform path round-trip and stale-token CLI tests |
| Scale | reproducible 500,000-file benchmark fixture |

Tests should not repeat the same assertion at every layer unless the added layer detects a distinct failure.

## Documentation and completion

Implementation updates user-facing command documentation alongside behavior. Before closing each Beads issue:

1. run its focused tests and relevant full-suite gates;
2. inspect current output and the final diff;
3. update durable acceptance evidence in the issue;
4. record any genuine follow-up in Beads;
5. close the issue only when no required work remains.

Commit, sync, and push remain subject to the active repository/user profile; this plan does not grant that authority.
