Archive Ledger Schema Design Decisions

Date: 2026-07-06

Purpose

This document records the design decisions produced by an adversarial stress test of the preliminary schema (docs/specs/2026-06-09-preliminary-schema.md) against the core workflows in the preliminary spec (docs/specs/2026-06-09-preliminary-spec.md): git-annex import, large verification runs, offsite drive rotation, restore-from-scratch, policy evaluation, and safe copy/repair.

The review lens was: a single developer maintaining files on their own machine, plus external backup drives, plus optional cloud, at a scale of hundreds of thousands to millions of files across collections (photos, videos, scanned documents, email).

The revised schema canvas incorporating these decisions is docs/specs/2026-07-06-schema.md.

---

Decision 1: Single-writer event stream, with per-host streams reserved for later

Problem

The event stream is hash-chained with a monotonic seq, which assumes one linear chain. The multi-device model implies events could originate on multiple hosts (an offsite machine verifying a drive), which would fork the chain and produce unmergeable seq collisions.

Decision

- MVP is strictly single-writer: only the primary catalog host mints events.
- Every event carries host_id, and seq is scoped to a stream_id. MVP has exactly one stream.
- Per-host streams with deterministic merge can be added later without a format break.

---

Decision 2: Two-tier table taxonomy — derived vs local-operational

Problem

The principle "every SQLite row traces to an event" collides with job progress tracking: a verify pass over a million objects would mint millions of job_item status-flip events, bloating the canonical stream. If job tables are not event-derived, the replay invariant is violated unless the invariant is scoped.

Decision

Tables are formally classified into two tiers:

Derived (rebuilt exactly by replaying canonical events):

- events (mirror), objects, object_hashes, collections, file_refs, path_observations,
  devices, device_mounts, device_site_history, archive_roots, sites, risk_domains,
  entity_risk_domains, locations, object_locations, verification_results,
  quarantine_items, policies, checkpoints, sqlite_snapshots,
  git_annex_imports, git_annex_keys, external_indexes

Local-operational (excluded from the replay invariant; free to churn):

- archive_meta, jobs, job_items, policy_status, policy_rollup

Only job_started and job_finished (with summary counts) are canonical events. Per-item durable outcomes (object_verified, copy_completed, etc.) were already canonical, so no archive fact is lost. policy_status/policy_rollup are recomputable caches.

---

Decision 3: Physical site placement lives on the device

Problem

site_id lived on locations. Moving a drive offsite (home -> safe deposit box) required updating every location row on that device, and a missed row silently corrupted risk-domain evaluation.

Decision

- devices.current_site_id holds present placement.
- device_site_history records the audit trail, fed by device_moved events.
- locations.site_id remains only for device-less locations (e.g. cloud buckets).
- Risk evaluation resolves location -> device -> site -> risk domains. A device's
  effective risk domains are the union of its own mappings and its current site's.
- Rotating a drive offsite is one event.

---

Decision 4: object_locations stores facts only; freshness is computed

Problem

The stored state enum included verified_fresh / verified_stale, which decay with wall-clock time with no event occurring. Replaying the same events at different times would need to produce different materialized states, breaking replay determinism.

Decision

- object_locations.state holds only event-driven facts:
  present / missing / corrupt / quarantined / removed / unknown_offline.
- Verification freshness is computed at query time from last_verified_time_utc_ms
  against the governing policy's max_verification_age_days.
- Replay is time-independent.

---

Decision 5: A git-annex repo registers two locations

Problem

file_refs pointed at the CAS location (.git/annex/objects) while carrying worktree paths that do not resolve under the CAS URI. The worktree and the CAS are different places on the same device.

Decision

Each git-annex repo registers:

- a git_annex_worktree location (repo root) — where path observations live;
- a git_annex_cas location (.git/annex/objects) — where object bytes live, and what
  object_locations and verification results point at.

Both share the device and archive root. Every stored path resolves under its location's URI.

---

Decision 6: Logical file_refs plus a path_observations table

Problem

file_refs had no uniqueness on (collection_id, logical_path) and carried a source_location_id, so it was ambiguous whether two clones of the same repo produce one file_ref or two.

Decision

- file_refs are purely logical: unique on (collection_id, logical_path) among active
  rows (partial unique index); source_location_id is removed.
- A new path_observations table records where a logical path was actually seen:
  (file_ref_id, location_id, observed object, path, times, state).
- Two repo clones = one file_ref, two observations.
- This resolves the preliminary canvas's open question 5 with "yes, separate table".

---

Decision 7: Scale valves for a million-object archive

policy_status stores violations only

- policy_status holds only objects currently failing a policy, with reasons_json.
- A small policy_rollup table holds per-policy aggregates
  (total / satisfied / violated, last evaluated time) for dashboards.
- One million compliant objects cost approximately zero rows.

events mirror is complete but prunable

- The SQLite events table mirrors the full stream by default.
- It is explicitly prunable: payload_json (or whole rows) older than the last
  checkpoint may be dropped via config/CLI, since JSONL remains canonical.

verification_results is prunable with a retention rule

- Yearly full verification of 1M objects at 3 locations adds ~3M rows per year,
  nearly all "ok". Since JSONL is canonical, the derived table carries retention:
  keep all failures forever; keep the most recent success per (object, location);
  prune older successes behind the last checkpoint.
- object_locations.last_verified_* already serves the hot query.

---

Decision 8: Identity simplifications

- No hosts table: a host is a device that runs the software; host_id columns
  reference devices.device_id. (Preliminary open question 2.)
- No actors table: actor_id stays a free-text convention (user name or tool name)
  until something needs to join on it. (Preliminary open question 3.)
- external_indexes stays in the MVP schema as drafted. (Preliminary open question 9.)
- locations.uri is renamed last_resolved_uri and is explicitly a cache; resolution is
  always computed from device_mounts + archive_roots + relative_path.
  (Preliminary open question 1.)
- Snapshot records stay in both the canonical stream and SQLite as drafted.
  (Preliminary open question 7.)

---

Event-volume budget

Stated expectation, not a surprise:

- A full verify pass of 1M objects x 3 locations mints ~3M object_verified events
  per year into JSONL-in-git.
- JSONL is highly repetitive; compressed and git-packed this is expected to be
  roughly 100-300 MB per year, which is acceptable for a single-developer archive.
- Mitigation path if it ever hurts (future option, not MVP machinery):
  a verification_run_completed event pointing to a hashed per-run manifest file in
  git, with the projector applying the manifest.

Watch items (no change now)

- The event repo grows monotonically for life. With closed segments and git packing
  this is fine for years at this volume. Future lever: segment archiving (move
  ancient segments to plain storage, keep manifests in git).
- Copy-destination layout convention is an MVP 3 concern. Default direction:
  filesystem_tree destinations mirror logical_path. Detail it when MVP 3 is designed.
