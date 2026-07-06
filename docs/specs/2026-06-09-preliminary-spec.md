Archive Ledger Design Canvas

Purpose

Archive Ledger is a local-first digital preservation system for large personal archives such as photos, videos, scanned documents, and email exports.

The system is intended to replace or complement large git-annex repositories when Git and git-annex metadata operations become too slow at hundreds of thousands or millions of files.

The core goals are:

- Verify file integrity using cryptographic checksums.
- Track where every object exists.
- Track the physical devices and locations where copies reside.
- Detect single points of failure such as house fire, power surge, theft, cloud account loss, or too few verified copies.
- Support safe copy, repair, and deletion semantics.
- Maintain a durable, auditable canonical history.
- Keep normal file organization workflows possible.
- Allow higher-level photo, document, and email apps to layer on top.

Locked Foundation

The system uses a layered model:

Canonical truth:
  Append-only JSONL event stream

Fast current state:
  SQLite materialized view

Recovery:
  Replay JSONL events into SQLite
  Optionally start from SQLite snapshots and replay later events

Propagation:
  Git repository containing canonical text artifacts

Convenience restore:
  SQLite snapshots copied by filesystem/object storage

The database is not the source of truth. It is a fast, rebuildable index.

Canonical Event Stream

The canonical event stream records every meaningful archive fact or operation.

Examples of canonical events:

- Object observed.
- Object hashed.
- File reference observed.
- Object verified.
- Object copied.
- Copy verified.
- Copy missing.
- Copy corrupt.
- Copy quarantined.
- Safe repair completed.
- Device checked in.
- Device mounted.
- Device moved.
- Location added.
- Policy added or updated.
- Checkpoint created.

The event stream is:

- Append-only.
- Hash-chained.
- Stored as JSONL.
- Segmented into closed event files.
- Committed to Git once closed.
- Replayable into SQLite.

Replay should rebuild the database logically exactly: same objects, file references, locations, verification states, policies, checkpoints, and risk evaluations.

SQLite byte-for-byte identity is not required.

Git Role

Git is used for what Git is good at: text, history, diffing, push/pull, and durable checkpoints.

Git stores:

- JSONL event segments.
- Event manifests.
- Policy files.
- Schema migration files.
- Checkpoint metadata.
- Human-readable reports if useful.

Git does not need to store:

- Raw media files.
- Large live SQLite databases.
- Large binary SQLite snapshots, unless explicitly desired.
- Constantly rewritten status files.

The Git equivalent of "safe through this point" is an Archive Ledger checkpoint:

checkpoint:
  events through seq N
  last event hash H
  event segment manifest committed
  Git commit pushed

SQLite Role

SQLite is the fast local materialized view of the canonical JSONL event stream.

Each device may have its own SQLite database. A device's SQLite database is current only through the latest event sequence and event hash it has applied.

A stale device can catch up by:

git pull
archive db apply-new-events

The database should support fast answers to questions such as:

- Where is this object?
- Which objects have too few verified copies?
- Which copies are overdue for verification?
- Which devices are overdue for check-in?
- What objects are vulnerable to home fire?
- What happened to this object?
- What did a verification job do?
- What needs repair?

Hashing Decision

Canonical object identity is BLAKE3.

object_id = blake3:<hex>

Rationale:

- Faster than SHA-512 for large-scale hashing.
- Parallelizable.
- Better aligned with the goal that operations should be constrained mainly by raw I/O and CPU hashing speed.

When importing from git-annex, existing SHA-512 or SHA-256 hashes from git-annex keys are preserved as alternate hashes.

Git-annex import flow:

1. Read git-annex file/key metadata.
2. Locate content in .git/annex/objects.
3. Compute legacy hash if available from the annex key.
4. Verify legacy hash matches actual content.
5. Compute BLAKE3.
6. Store BLAKE3 as canonical object ID.
7. Store SHA-512/SHA-256 as alternate hashes.

Object Model

The system separates:

Object:
  Unique byte sequence identified by BLAKE3.

File reference:
  Logical path/name pointing to an object.

Location:
  Place where object bytes may exist.

Device:
  Physical or virtual storage-bearing thing.

Site:
  Physical or logical place.

Risk domain:
  Shared failure mode or dependency.

A path is not identity. A path is a reference to an object.

Multiple paths can point to the same object.

The same object can exist at many locations.

Storage Decision

MVP uses existing storage in place.

Because most existing data is already in git-annex, the MVP supports git-annex CAS in place.

MVP:
  Read git-annex CAS in place.
  Do not mutate .git/annex/objects.
  Import git-annex keys and content paths.
  Compute BLAKE3 canonical IDs.
  Verify legacy hashes where available.

Future:
  Add managed BLAKE3-native CAS.
  Provide clean migration from git-annex CAS to managed CAS.

git-annex CAS Role

git-annex CAS is treated as a read-only location type during MVP.

Benefits:

- No massive migration.
- No duplicate storage.
- Existing annex repositories remain usable.
- Transition is low risk.

Future managed CAS may provide:

- BLAKE3-native layout.
- Cleaner writes.
- Cleaner repair semantics.
- Cleaner garbage collection.
- Better mobile/cloud ingest target.
- Independence from git-annex internals.

Archive Scope

Use one global archive catalog.

Collections are logical buckets inside the archive:

- photos
- videos
- scanned-docs
- email
- mobile-imports
- cloud-imports

Rationale:

- Devices are global.
- Sites are global.
- Risk domains are global.
- Policies are global.
- Deduplication can cross collections.
- Higher-level apps can share the same object substrate.

Physical storage can still remain separated, such as existing photos, documents, and email folders or repos.

Path Handling Model

The system separates device identity, mount observations, archive roots, and locations.

Device

Stable identity of a storage device or virtual storage system.

Examples:

- primary computer
- external USB drive
- NAS
- phone
- cloud account

Device Mount

Host-specific current mount point.

Examples:

external drive mounted at /mnt
external drive mounted at /media/exthd

Archive Root

Path inside a device/filesystem where the archive begins.

Example for external drive:

device: external-8tb-a
archive root path on device: /archive

If mounted at "/mnt", resolved archive root is:

/mnt/archive

If mounted at "/media/exthd", resolved archive root is:

/media/exthd/archive

Location

Path inside the archive root where specific content lives.

Example:

archive root path on device:
  /archive

location relative path:
  photos

resolved location:
  /media/exthd/archive/photos

For git-annex:

location relative path:
  photos/.git/annex/objects

This keeps archive identity stable even when mount points change.

Device, Location, Site, Risk Domain

These are first-class entities.

Device

A storage-bearing object.

Examples:

- WD 8TB USB A
- NAS main
- Primary PC
- Pixel phone
- Backblaze account

Location

A logical place where archive object bytes may exist.

Examples:

- "/home/alice/data/photos/.git/annex/objects"
- "/mnt/archive/photos"
- "b2://bucket/archive/photos"
- mobile ingest staging folder

Site

Physical or logical place.

Examples:

- home
- safe deposit box
- relative's house
- cloud provider

Risk Domain

A shared failure mode or dependency.

Examples:

- home fire
- home burglary
- home power surge
- same USB hub
- same NAS chassis
- same cloud account
- same cloud provider
- same city earthquake
- same password manager

Policies can reason about risk domains, not just copy count.

Verification Model

Verification means reading object bytes at a location and computing the expected hash.

Important distinction:

Location claim:
  "The catalog believes object X exists at location Y."

Verification claim:
  "Object X was actually read at location Y and matched its expected hash at time T."

Verification can expire because storage may silently corrupt over time.

Verification expiry is not caused by another device deleting something without reporting it. That is a separate catalog freshness problem.

The system distinguishes:

- verification freshness
- catalog freshness
- device check-in freshness
- location online/offline state

Object Location States

Typical current states:

- present_unverified
- verified_fresh
- verified_stale
- missing
- corrupt
- quarantined
- removed
- unknown_offline

A copy should only be used for repair or safe deletion if it is freshly verified or re-verified immediately before use.

Safe Operations

Safe Copy

A safe copy operation should:

1. Verify source if needed.
2. Copy source to destination temp path.
3. Flush/sync destination where possible.
4. Move temp file into place atomically where possible.
5. Read destination.
6. Verify destination hash.
7. Record events.

Safe Drop

A safe drop operation should:

1. Find alternate copy.
2. Re-verify alternate copy or confirm it is fresh enough under policy.
3. Simulate policy after removal.
4. Refuse if policy would be violated.
5. Remove local copy.
6. Record events.

Automatic delete is not allowed in MVP.

Safe Repair

Safe repair is allowed if configured.

A safe repair should:

1. Detect corrupt or missing copy.
2. Find candidate source.
3. Re-verify source.
4. Copy good source to temp destination.
5. Verify destination.
6. Quarantine corrupt copy instead of deleting.
7. Put repaired copy in place.
8. Record events.

Automatic repair is acceptable because it preserves the corrupt copy in quarantine and only uses freshly verified source data.

Automation Decisions

Locked automation stance:

Automatic verification:
  yes

Automatic copy to satisfy policy:
  yes, if configured

Automatic repair:
  yes, if source is freshly verified and corrupt file is quarantined

Automatic delete:
  no

Scheduler/Daemon Direction

MVP may start CLI-only, but the database and job model should be designed so that a daemon can be added without a major refactor.

Future daemon:

archive-ledgerd

Responsibilities:

- Run background verification.
- Run policy-driven copy jobs.
- Run safe repair jobs.
- Detect mounted devices.
- Resume interrupted jobs.
- Rate-limit I/O.
- Avoid heavy verification during configured hours.
- Track progress.

Policy Direction

Policy language starts simple.

Example:

collections:
  photos:
    min_verified_copies: 3
    min_sites: 2
    require_offline_copy: true
    max_verification_age_days: 365

  scanned-docs:
    min_verified_copies: 4
    min_sites: 2
    require_offsite_copy: true
    require_encryption: true
    max_verification_age_days: 180

Future policies may support selectors such as:

collection == "scanned-docs" and tag == "critical"

But MVP should avoid overbuilding a complex policy language.

Encryption Decision

Current archive data is plaintext, with full-disk encryption for external drives stored offsite.

MVP should:

- Record encryption state.
- Allow policies to require encrypted locations.
- Not implement per-file encryption.

Per-file encryption may be useful later for untrusted cloud storage, but it adds:

- key-management complexity
- possible deduplication complications
- more difficult mobile/cloud ingest
- more complicated repair/copy logic

For now:

FDE/LUKS/VeraCrypt-style encrypted storage is sufficient for offsite drives.
Cloud encryption can be added later as an encrypted location type.

Multi-Device Model

Each participating device can have:

archive-event-repo/
catalog.sqlite
snapshots/

The event repo is canonical.

The SQLite database is local and current only through its applied event sequence/hash.

A cold/offsite device may be stale. That is acceptable. When it reconnects:

git pull
archive db apply-new-events

Then it catches up.

The system should show:

local DB current through event seq N
event repo has event seq M
device is M-N events behind

Checkpoints and Snapshots

Checkpoints

Checkpoints refer to canonical event-stream safety.

A checkpoint records:

- event range
- last event sequence
- last event hash
- manifest path
- Git commit if committed
- push/copy status if tracked

SQLite Snapshots

SQLite snapshots are restore accelerators.

They are not canonical.

They can be copied by filesystem/object copy to backup locations.

A snapshot records:

- included event sequence
- included event hash
- snapshot hash
- storage location

Restore flow:

1. Restore latest SQLite snapshot.
2. Verify snapshot hash.
3. Apply canonical events after snapshot sequence.
4. Verify final event hash/state hash.

Higher-Level App Layering

Archive Ledger is Layer 0.

Layer 0:
  archive-core

Layer 1:
  domain indexes

Layer 2:
  user apps

Archive Core Owns

- objects
- hashes
- file references
- locations
- devices
- sites
- risk domains
- events
- verification
- copy
- repair
- policy

Photo Gallery Owns

- albums
- people/faces
- places
- events
- ratings
- AI captions
- thumbnails
- search embeddings

The photo gallery references archive objects by "object_id".

Document App Owns

- OCR text
- document type
- document tags
- viewer annotations
- case/folder organization
- full-text index

The document app references archive objects by "object_id".

Email App Owns

- message IDs
- threads
- mailboxes/folders
- parsed headers
- attachments
- search index

Email attachments can deduplicate against photos/documents by "object_id".

Mobile and Cloud Ingest Direction

Many photos/videos are born on mobile devices. The archive should eventually support mobile-friendly ingest.

Early practical option:

phone -> Syncthing/SMB/WebDAV/SFTP/Tailscale drop folder
archive watches ingest folder
archive hashes, dedupes, imports

Longer-term option:

mobile app computes BLAKE3
uploads file plus manifest
archive verifies received bytes
archive records canonical events

Cloud imports such as Amazon Photos should be treated as ingest sources.

Cloud import should:

- download/export files
- compute BLAKE3
- dedupe against existing objects
- record source metadata
- copy into protected archive storage if new

Cloud source metadata may include:

- provider
- provider asset ID
- source filename
- source capture time
- import time

MVP Direction

MVP 1: Read-only archive ledger over existing git-annex repos.

MVP features:

- Initialize global archive.
- Register collections.
- Register devices.
- Register sites.
- Register risk domains.
- Register archive roots.
- Register git-annex CAS locations.
- Import git-annex worktree paths and annex keys.
- Read git-annex CAS content in place.
- Verify SHA-512/SHA-256 from git-annex keys where possible.
- Compute BLAKE3 canonical object IDs.
- Write canonical JSONL events.
- Materialize SQLite database.
- Commit closed event segments to Git.
- Produce basic status/risk/verification reports.

MVP 2:

- Background verification over imported locations.
- Job queue/resume support.

MVP 3:

- Policy-driven copy to another filesystem location.
- Destination verification.

MVP 4:

- Safe repair with quarantine.

MVP 5:

- Mobile/cloud ingest staging.

Explicit Non-Goals for MVP

MVP does not include:

- photo gallery UI
- face recognition
- OCR
- document viewer
- email browser
- cloud backup implementation
- per-file encryption implementation
- complex distributed sync
- automatic destructive cleanup
- mobile app
- managed BLAKE3-native CAS writes

These should be layered later.
