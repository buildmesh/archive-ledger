Archive Ledger Canonical Event Stream Specification

Date: 2026-07-06

Purpose

This document specifies the canonical JSONL event stream: the envelope format, serialization and hash-chaining rules, mutation and observation semantics, the event type catalog with payload shapes, and the on-disk segment/checkpoint layout.

Companion documents:

- docs/specs/2026-06-09-preliminary-spec.md (system design canvas)
- docs/specs/2026-07-06-schema.md (SQLite schema canvas)
- docs/specs/2026-07-06-schema-design-decisions.md (stress-test decisions)

The event stream is canonical truth. SQLite is a derived materialized view.

MVP is single-writer: only the primary catalog host mints events, into exactly one stream. Events carry host_id and seq is scoped to stream_id so per-host streams can be added later without a format break.

---

Envelope

Every event is one JSON object on one line (JSONL). Envelope fields:

{
  "v": 1,
  "stream_id": "stream_primary",
  "seq": 184220,
  "event_id": "evt_01jz8p1kh9x6s4v8q0k1",
  "event_type": "object_verified",
  "time_utc_ms": 1781042405123,
  "actor_id": "alice",
  "host_id": "dev_primary_pc",
  "job_id": null,
  "object_id": "blake3:2c7f...",
  "location_id": "loc_usb8tb_a_photos",
  "device_id": null,
  "site_id": null,
  "previous_event_hash": "blake3:a91e...",
  "payload": { ... }
}

Rules:

- "v" is the envelope format version. This document specifies v=1.
- "event_id" is a prefixed ULID ("evt_" + ULID). ULIDs are sortable and collision-free.
- "seq" starts at 1 per stream and increments by exactly 1.
- Entity-reference fields (object_id, location_id, device_id, site_id, job_id) are
  set when relevant and null otherwise. They exist so the SQLite events mirror can
  index without parsing payloads. "payload" holds everything type-specific.
- "previous_event_hash" is null only for the genesis event (seq 1, archive_initialized).
- An event never embeds its own hash (see hashing rule).
- The human-readable event_time_text column in SQLite is derived from time_utc_ms
  during apply; it is not stored in the JSONL line.

---

Serialization and Hashing

The physical line bytes are the canonical form. There is no JSON canonicalization anywhere in the system.

- An event's hash is: "blake3:" + lowercase hex of BLAKE3 over the exact UTF-8 bytes
  of its line, excluding the trailing newline.
- The hash of event N is embedded in event N+1 as previous_event_hash.
- The hash of the last event in a closed segment is recorded in the segment manifest.
- Segment files are append-only and never reformatted, rewritten, or re-encoded.

Chain verification procedure:

1. For each segment in manifest order, BLAKE3 the file bytes and compare to the
   manifest's segment_blake3.
2. Rehash each line; compare to the next line's previous_event_hash. Across a
   segment boundary, the first line of the next segment must chain to the last
   hash of the prior segment. The final line's hash must equal the manifest's
   last_event_hash.
3. Verify seq continuity (no gaps, no duplicates) and that seq ranges match
   manifests.

The SQLite events mirror's event_hash column is computed during apply, not read from the line.

---

Mutation Semantics (registry entities)

Registry events carry full entity snapshots. The projector upserts the complete row; there are no field-level deltas. Events are self-contained and readable without replaying priors, and git diffs of the stream show whole entities. Registry entities are small and change rarely, so redundancy is negligible.

Semantically-named transition events (e.g. device_moved) still carry the full entity snapshot, plus explicit transition detail (from_site_id/to_site_id) so history tables get their audit rows from the same event.

In event payloads, structured values (policy selectors, requirements) are JSON objects, not embedded JSON strings. SQLite stores them serialized.

---

Observation Semantics (scans)

Scans are change-only:

- Per-file events are minted only when the observed state differs from the catalog:
  new path, path resolving to a different object, path gone, size/mtime drift.
- A fully known, unchanged file mints zero events.
- Every scan mints one location_scanned coverage event (the canonical fact that a
  location was fully enumerated at a time, with counts).
- "When was this path last seen" resolves to the most recent covering
  location_scanned event, not per-file events.

Verification is separate and always per-object: each verification attempt mints object_verified. This is the budgeted event volume (~3M/year at 1M objects x 3 locations, yearly).

Consequence: the initial import is inherently the expensive pass (every file is a change; up to ~4-5 events per file, one time). Routine re-scans of an unchanged archive mint one event per location.

A typical newly-seen file mints up to four events: object_observed, file_ref_added, path_observed, copy_observed.

---

Event Catalog (MVP 1-2)

Payload field lists below omit envelope fields. Entity snapshots ("device": {...}) carry the full column set of the corresponding SQLite table (minus derived bookkeeping like last_*_event_id, which the projector fills from the event itself).

Archive lifecycle

archive_initialized
  Genesis event, seq 1, previous_event_hash null.
  payload: { archive_id, display_name }

checkpoint_created
  payload: { checkpoint_id, event_first_seq, event_last_seq, event_last_hash,
             manifest_path, git_commit (nullable) }
  Note: the git commit binding the checkpoint cannot be known before the commit
  exists; git_commit is typically null in the event and authoritative in git itself.

snapshot_created
  payload: { snapshot_id, snapshot_path, includes_event_seq, includes_event_hash,
             snapshot_hash_algo, snapshot_hash_hex, storage_location_id }

Registry (full-snapshot payloads; X_updated variants share the X_registered shape)

collection_registered / collection_updated
  payload: { collection: {...} }

device_registered / device_updated
  payload: { device: {...} }               (envelope device_id set)

device_moved
  payload: { device: {...}, from_site_id, to_site_id }
  Projector: upsert device (current_site_id = to_site_id), close the open
  device_site_history row, insert the new one.

device_checked_in
  payload: {}                              (envelope device_id, host_id, time carry the fact)

device_mount_observed
  payload: { mount: { mount_id, device_id, host_id, mount_root_uri, status } }

site_registered / site_updated
  payload: { site: {...} }                 (envelope site_id set)

risk_domain_registered / risk_domain_updated
  payload: { risk_domain: {...} }

risk_assigned / risk_unassigned
  payload: { entity_type, entity_id, risk_domain_id }

archive_root_registered / archive_root_updated
  payload: { archive_root: {...} }         (envelope device_id set)

location_registered / location_updated
  payload: { location: {...} }             (envelope location_id, device_id set)

policy_registered / policy_updated
  payload: { policy: { policy_id, display_name, selector, requirements, enabled } }
  selector/requirements are JSON objects in the event.

external_index_registered
  payload: { external_index: {...} }

Content facts (change-only)

object_observed
  First sighting ever of a byte sequence.
  payload: { object: { object_id, size_bytes, media_type, extension_hint } }
  (envelope object_id set)

object_hash_added
  Alternate hash attached to an object.
  payload: { hash_algo, hash_hex, source }

file_ref_added
  New logical path in a collection.
  payload: { file_ref: { file_ref_id, collection_id, object_id, logical_path,
             original_name, created_time_utc_ms, modified_time_utc_ms,
             observed_size_bytes } }

file_ref_updated
  Logical path now resolves to a different object (content replaced).
  payload: same shape as file_ref_added, plus previous_object_id

file_ref_removed
  payload: { file_ref_id, collection_id, logical_path }

path_observed
  New or changed physical sighting of a logical path at a location.
  payload: { file_ref_id, observed_path, observed_size_bytes,
             modified_time_utc_ms }     (envelope object_id, location_id set)

path_missing
  Previously present path no longer found at a location.
  payload: { file_ref_id, observed_path }

copy_observed
  Object bytes present at a location (the CAS-side fact).
  payload: { path }                     (envelope object_id, location_id set)

copy_missing
  payload: { last_known_path }

object_verified
  Always per-object. One event type for all outcomes.
  payload: { result, expected_hash_algo, expected_hash_hex, observed_hash_hex,
             size_bytes, bytes_read, duration_ms, path_observed, error_message }
  result: ok | hash_mismatch | read_error
  Projector: insert verification_results; update object_locations
  (last_verified_* on ok; state=corrupt on hash_mismatch). There is no separate
  copy_corrupt event; corruption is a verification outcome.

Coverage and jobs

location_scanned
  The canonical coverage fact: this location was fully enumerated.
  payload: { scan_started_time_utc_ms, scan_finished_time_utc_ms, files_seen,
             bytes_seen, new_paths, changed_paths, missing_paths, unchanged_paths }
  (envelope location_id, job_id set)

job_started
  payload: { job_id, job_type, params }

job_finished
  payload: { job_id, status, summary }
  Per the two-tier decision, these are the only canonical job events; job_items
  churn is local-operational only.

git-annex import

annex_import_started
  payload: { import: { import_id, repo_path, collection_id, worktree_location_id,
             cas_location_id, annex_objects_path, git_head_commit, annex_uuid } }

annex_key_mapped
  Per-key mapping; one-time import cost.
  payload: { annex_key, backend, annex_size_bytes, annex_extension,
             parsed_hash_algo, parsed_hash_hex, content_path, import_id }
  (envelope object_id set)

annex_import_completed
  payload: { import_id, keys_mapped, objects_new, objects_existing, errors }

Reserved for MVP 3-4 (named now, payloads designed with those MVPs)

copy_completed, copy_removed (safe drop), repair_started, repair_completed,
quarantine_added

---

Segment and Checkpoint Layout

Directory layout (inside the event repo):

events/
  stream_primary/
    seg-000000000001.jsonl
    seg-000000100001.jsonl          (open: being appended locally)
manifests/
  stream_primary/
    seg-000000000001.manifest.json
checkpoints/
  chk_20260706_000001.json

Segment rules:

- Segments are named by the seq of their first event, zero-padded to 12 digits.
- The open segment is appended locally with fsync'd batches. It is NOT committed
  to git while open.
- A segment closes when it reaches the event-count threshold (default 100,000
  events, roughly 30-50 MB) or when a checkpoint forces an early close.
- On close, the sidecar manifest is written and both files are committed to git.
- Closed segments and manifests are immutable forever.

Segment manifest format:

{
  "manifest_v": 1,
  "stream_id": "stream_primary",
  "segment_file": "events/stream_primary/seg-000000000001.jsonl",
  "first_seq": 1,
  "last_seq": 100000,
  "first_event_id": "evt_01jz70...",
  "last_event_id": "evt_01jz8p...",
  "last_event_hash": "blake3:7bd9...",
  "event_count": 100000,
  "segment_size_bytes": 41238771,
  "segment_blake3": "blake3:90ac..."
}

Checkpoint file format:

{
  "checkpoint_v": 1,
  "checkpoint_id": "chk_20260706_000001",
  "created_time_utc_ms": 1783500000000,
  "stream_id": "stream_primary",
  "event_first_seq": 1,
  "event_last_seq": 184220,
  "event_last_hash": "blake3:7bd9...",
  "segments": [
    { "file": "events/stream_primary/seg-000000000001.jsonl",
      "manifest": "manifests/stream_primary/seg-000000000001.manifest.json",
      "segment_blake3": "blake3:90ac..." }
  ]
}

A checkpoint closes the open segment (even if small), writes the checkpoint file listing every closed segment, mints checkpoint_created as the first event of the next segment, commits, and optionally pushes. "Safe through seq N" means: all segments through N are closed, manifested, committed, and the chain verifies.

Restore flow (unchanged from the design canvas):

1. Clone/pull the event repo.
2. Optionally restore the latest SQLite snapshot and verify its hash.
3. Verify the segment chain (procedure above) from the snapshot's seq forward.
4. Replay events in seq order into SQLite.
5. Confirm applied_event_seq/applied_event_hash match the stream tail.

---

Volume Expectations

- Initial import of 1M files: ~4-5M events, one time (~1-2 GB raw JSONL,
  substantially less after git packing).
- Routine re-scan of an unchanged archive: one location_scanned event per location.
- Yearly full verification at 1M objects x 3 locations: ~3M object_verified events
  per year (~100-300 MB/year packed). Mitigation path if it ever hurts: a
  verification_run_completed event referencing a hashed per-run manifest, applied
  by the projector (future option, not MVP machinery).

---

Open Items

- Payload shapes for the reserved MVP 3-4 events (copy, repair, quarantine, safe drop).
- Per-host stream merge algorithm (deterministic ordering across streams) — deferred
  until a second writer actually exists; the format reserves stream_id and per-stream
  seq for it.
- Segment archiving (moving ancient segments out of git, keeping manifests) — future
  lever, not needed at current volume.
