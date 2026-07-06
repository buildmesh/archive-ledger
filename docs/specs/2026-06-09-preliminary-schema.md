Archive Ledger Schema Canvas

Purpose

This canvas tracks the evolving SQLite schema for Archive Ledger.

The SQLite database is a materialized view of the canonical JSONL event stream. It must be rebuildable by replaying canonical events.

The schema should support:

- BLAKE3 canonical objects.
- Alternate hashes such as SHA-512 from git-annex.
- File references and logical paths.
- Collections such as photos, scanned documents, videos, and email.
- Device, mount, archive root, location, site, and risk-domain modeling.
- git-annex CAS import.
- Verification history.
- Object-location current state.
- Policy evaluation.
- Job scheduling and resumability.
- Checkpoints and SQLite snapshots.

Schema Principles

1. JSONL events are canonical.
2. SQLite tables are derived/materialized.
3. Every SQLite row that represents archive facts should trace back to an event where practical.
4. Object identity is BLAKE3.
5. SHA-512/SHA-256 hashes from git-annex are stored as alternate hashes.
6. Paths are references, not identity.
7. Locations are logical storage places.
8. Devices, sites, and risk domains are first-class.
9. Archive roots are path-on-device concepts, not host mount points.
10. Device mounts are host-specific observations.
11. Verification freshness and catalog freshness are separate concepts.
12. The schema should support CLI-first MVP and daemon later.

Current Table List

A. Archive/catalog metadata

- "archive_meta"
- "events"

B. Core content identity

- "objects"
- "object_hashes"

C. Logical organization

- "collections"
- "file_refs"

D. Roots, devices, locations, sites, risks

- "devices"
- "device_mounts"
- "archive_roots"
- "sites"
- "risk_domains"
- "entity_risk_domains"
- "locations"

E. Presence, verification, and repair state

- "object_locations"
- "verification_results"
- "quarantine_items"

F. Policies and derived health

- "policies"
- "policy_status"

G. Jobs and scheduling-ready design

- "jobs"
- "job_items"

H. git-annex import support

- "git_annex_imports"
- "git_annex_keys"

I. Checkpoints and snapshots

- "checkpoints"
- "sqlite_snapshots"

J. Higher-level app integration

- "external_indexes"

Tables

---

"archive_meta"

Description

Small key-value table for database-local metadata.

This table tells the SQLite database what archive it belongs to, which schema version it uses, and how far it has replayed the canonical event stream.

This table is local database bookkeeping, not archive content.

Proposed columns

CREATE TABLE archive_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

Example records

key                  value
-------------------  ------------------------------------
archive_id           arch_01jz_photo_doc_email
schema_version       1
applied_event_seq    184220
applied_event_hash   blake3:7bd9...
event_repo_commit    9f4a1c2...

---

"events"

Description

Queryable SQLite copy of the canonical JSONL event stream.

This table is not the source of truth. It is rebuilt from JSONL and used for fast audit queries, dashboards, debugging, and object timelines.

Proposed columns

CREATE TABLE events (
  seq INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  event_time_utc_ms INTEGER NOT NULL,
  event_time_text TEXT NOT NULL,
  actor_id TEXT,
  host_id TEXT,
  job_id TEXT,
  object_id TEXT,
  location_id TEXT,
  device_id TEXT,
  site_id TEXT,
  payload_json TEXT NOT NULL,
  previous_event_hash TEXT,
  event_hash TEXT NOT NULL
);

CREATE INDEX idx_events_type_time ON events(event_type, event_time_utc_ms);
CREATE INDEX idx_events_object_time ON events(object_id, event_time_utc_ms);
CREATE INDEX idx_events_location_time ON events(location_id, event_time_utc_ms);
CREATE INDEX idx_events_device_time ON events(device_id, event_time_utc_ms);
CREATE INDEX idx_events_job ON events(job_id);

Example record

{
  "seq": 184220,
  "event_id": "evt_01jz8p1kh9x6s4v8q0k1",
  "event_type": "object_verified",
  "event_time_utc_ms": 1781042405123,
  "event_time_text": "2026-06-09T18:00:05.123Z",
  "actor_id": "archive-daemon",
  "host_id": "mini-pc",
  "job_id": "job_verify_usb8tb_a_20260609",
  "object_id": "blake3:2c7f...",
  "location_id": "loc_usb8tb_a_photos",
  "payload_json": "{\"result\":\"ok\",\"bytes_read\":42391551}",
  "previous_event_hash": "blake3:a91e...",
  "event_hash": "blake3:7bd9..."
}

---

"objects"

Description

One row per unique byte sequence.

Object identity is independent of filename, path, device, collection, or location.

Canonical object identity is BLAKE3.

Proposed columns

CREATE TABLE objects (
  object_id TEXT PRIMARY KEY,
  canonical_hash_algo TEXT NOT NULL,
  canonical_hash_hex TEXT NOT NULL UNIQUE,
  size_bytes INTEGER NOT NULL,
  first_seen_event_id TEXT NOT NULL,
  first_seen_time_utc_ms INTEGER NOT NULL,
  media_type TEXT,
  extension_hint TEXT
);

CREATE INDEX idx_objects_size ON objects(size_bytes);
CREATE INDEX idx_objects_media_type ON objects(media_type);

Example record

{
  "object_id": "blake3:2c7f9f9a...",
  "canonical_hash_algo": "blake3",
  "canonical_hash_hex": "2c7f9f9a...",
  "size_bytes": 42391551,
  "first_seen_event_id": "evt_01jz8n...",
  "first_seen_time_utc_ms": 1781039200000,
  "media_type": "image/jpeg",
  "extension_hint": "jpg"
}

---

"object_hashes"

Description

Alternate hashes for an object.

This table preserves SHA-512 or SHA-256 hashes from git-annex keys and any other external manifests.

Proposed columns

CREATE TABLE object_hashes (
  object_id TEXT NOT NULL,
  hash_algo TEXT NOT NULL,
  hash_hex TEXT NOT NULL,
  source TEXT,
  verified_event_id TEXT,
  PRIMARY KEY (object_id, hash_algo, hash_hex),
  FOREIGN KEY (object_id) REFERENCES objects(object_id)
);

CREATE INDEX idx_object_hash_lookup ON object_hashes(hash_algo, hash_hex);

Example records

[
  {
    "object_id": "blake3:2c7f9f9a...",
    "hash_algo": "blake3",
    "hash_hex": "2c7f9f9a...",
    "source": "computed",
    "verified_event_id": "evt_01jz8n..."
  },
  {
    "object_id": "blake3:2c7f9f9a...",
    "hash_algo": "sha512",
    "hash_hex": "a83d2b...",
    "source": "git-annex-key",
    "verified_event_id": "evt_01jz8n..."
  }
]

---

"collections"

Description

Logical top-level categories such as photos, videos, scanned documents, and email.

Policies can target collections.

Proposed columns

CREATE TABLE collections (
  collection_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  description TEXT
);

Example records

[
  {
    "collection_id": "photos",
    "display_name": "Photos",
    "description": "Personal photos and image files"
  },
  {
    "collection_id": "scanned_docs",
    "display_name": "Scanned Documents",
    "description": "Scanned paper records, PDFs, and document images"
  },
  {
    "collection_id": "email",
    "display_name": "Email",
    "description": "Exported email archives and attachments"
  }
]

---

"file_refs"

Description

A logical filename or path pointing to an object.

Paths are labels/references, not identity. Multiple file references can point to the same object.

Proposed columns

CREATE TABLE file_refs (
  file_ref_id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL,
  object_id TEXT NOT NULL,
  logical_path TEXT NOT NULL,
  original_name TEXT,
  path_state TEXT NOT NULL,
  first_seen_event_id TEXT NOT NULL,
  last_seen_event_id TEXT,
  removed_event_id TEXT,
  created_time_utc_ms INTEGER,
  modified_time_utc_ms INTEGER,
  observed_size_bytes INTEGER,
  source_location_id TEXT,
  FOREIGN KEY (collection_id) REFERENCES collections(collection_id),
  FOREIGN KEY (object_id) REFERENCES objects(object_id)
);

CREATE INDEX idx_file_refs_path ON file_refs(collection_id, logical_path);
CREATE INDEX idx_file_refs_object ON file_refs(object_id);
CREATE INDEX idx_file_refs_state ON file_refs(path_state);

Example record

{
  "file_ref_id": "fref_01jz8p...",
  "collection_id": "photos",
  "object_id": "blake3:2c7f9f9a...",
  "logical_path": "photos/2024/05/IMG_1234.JPG",
  "original_name": "IMG_1234.JPG",
  "path_state": "active",
  "first_seen_event_id": "evt_01jz8n...",
  "last_seen_event_id": "evt_01jz8n...",
  "removed_event_id": null,
  "created_time_utc_ms": null,
  "modified_time_utc_ms": 1715531200000,
  "observed_size_bytes": 42391551,
  "source_location_id": "loc_annex_photos_main"
}

---

"devices"

Description

A physical or virtual storage-bearing entity.

Examples include primary PC, external USB drive, NAS, phone, server, or cloud account.

Proposed columns

CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  device_kind TEXT NOT NULL,
  serial_hint TEXT,
  hardware_fingerprint TEXT,
  owner TEXT,
  status TEXT NOT NULL,
  last_checkin_event_id TEXT,
  last_checkin_time_utc_ms INTEGER
);

Example record

{
  "device_id": "dev_usb8tb_a",
  "display_name": "WD 8TB USB A",
  "device_kind": "usb_hdd",
  "serial_hint": "WD-XXXX-1234",
  "hardware_fingerprint": "disk-uuid:abcd-1234",
  "owner": "alice",
  "status": "active",
  "last_checkin_event_id": "evt_01jz8p...",
  "last_checkin_time_utc_ms": 1781042400000
}

---

"device_mounts"

Description

Host-specific observations of where a device is mounted.

This table separates a device's stable identity from its temporary path on a specific host.

Proposed columns

CREATE TABLE device_mounts (
  mount_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  mount_root_uri TEXT NOT NULL,
  observed_time_utc_ms INTEGER NOT NULL,
  observed_event_id TEXT NOT NULL,
  status TEXT NOT NULL,
  FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE INDEX idx_device_mounts_device ON device_mounts(device_id, observed_time_utc_ms);
CREATE INDEX idx_device_mounts_host ON device_mounts(host_id, observed_time_utc_ms);

Example record

{
  "mount_id": "mnt_01jz8p...",
  "device_id": "dev_usb8tb_a",
  "host_id": "primary-pc",
  "mount_root_uri": "file:///media/exthd",
  "observed_time_utc_ms": 1781042400000,
  "observed_event_id": "evt_01jz8p...",
  "status": "mounted"
}

---

"archive_roots"

Description

A path inside a device/filesystem where an archive begins.

This is not the host mount point. It is the archive's path relative to the device filesystem root.

Example: an external drive may have archive root "/archive", which resolves to "/mnt/archive" or "/media/exthd/archive" depending on where the drive is mounted.

Proposed columns

CREATE TABLE archive_roots (
  archive_root_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  root_path_on_device TEXT NOT NULL,
  last_resolved_root_uri TEXT,
  status TEXT NOT NULL,
  created_event_id TEXT NOT NULL,
  last_seen_event_id TEXT,
  last_seen_time_utc_ms INTEGER,
  FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE INDEX idx_archive_roots_device ON archive_roots(device_id);

Example records

[
  {
    "archive_root_id": "root_primary_home_data",
    "device_id": "dev_primary_pc",
    "display_name": "Primary PC data root",
    "root_path_on_device": "/home/alice/data",
    "last_resolved_root_uri": "file:///home/alice/data",
    "status": "active",
    "created_event_id": "evt_01jz70...",
    "last_seen_event_id": "evt_01jz8p...",
    "last_seen_time_utc_ms": 1781042400000
  },
  {
    "archive_root_id": "root_usb8tb_a_archive",
    "device_id": "dev_usb8tb_a",
    "display_name": "USB 8TB A archive root",
    "root_path_on_device": "/archive",
    "last_resolved_root_uri": "file:///media/exthd/archive",
    "status": "active",
    "created_event_id": "evt_01jz71...",
    "last_seen_event_id": "evt_01jz8p...",
    "last_seen_time_utc_ms": 1781042400000
  }
]

---

"sites"

Description

Physical or logical places where devices or locations reside.

Used for offsite and disaster-risk policy.

Proposed columns

CREATE TABLE sites (
  site_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  site_kind TEXT NOT NULL,
  description TEXT
);

Example records

[
  {
    "site_id": "site_home",
    "display_name": "Home",
    "site_kind": "home",
    "description": "Main residence"
  },
  {
    "site_id": "site_safe_deposit_box",
    "display_name": "Safe Deposit Box",
    "site_kind": "safe_deposit_box",
    "description": "Bank safe deposit box"
  }
]

---

"risk_domains"

Description

A shared failure mode or shared dependency.

Examples include home fire, home burglary, power surge, cloud account loss, same NAS chassis, or same cloud provider.

Proposed columns

CREATE TABLE risk_domains (
  risk_domain_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  risk_kind TEXT NOT NULL,
  description TEXT
);

Example records

[
  {
    "risk_domain_id": "risk_home_fire",
    "display_name": "Home fire",
    "risk_kind": "fire",
    "description": "Anything physically located at home could be lost in a house fire"
  },
  {
    "risk_domain_id": "risk_home_power_surge",
    "display_name": "Home power surge",
    "risk_kind": "surge",
    "description": "Powered devices on home electrical circuits"
  }
]

---

"entity_risk_domains"

Description

Many-to-many mapping between entities and risk domains.

Entities may be devices, sites, locations, or archive roots.

Proposed columns

CREATE TABLE entity_risk_domains (
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  risk_domain_id TEXT NOT NULL,
  PRIMARY KEY (entity_type, entity_id, risk_domain_id),
  FOREIGN KEY (risk_domain_id) REFERENCES risk_domains(risk_domain_id)
);

CREATE INDEX idx_entity_risk_domain ON entity_risk_domains(risk_domain_id);

Example records

[
  {
    "entity_type": "site",
    "entity_id": "site_home",
    "risk_domain_id": "risk_home_fire"
  },
  {
    "entity_type": "device",
    "entity_id": "dev_nas_main",
    "risk_domain_id": "risk_home_power_surge"
  }
]

---

"locations"

Description

A logical storage place where object bytes may exist.

A location may be a normal filesystem tree, git-annex CAS, future managed CAS, cloud location, or mobile ingest staging area.

Proposed columns

CREATE TABLE locations (
  location_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  uri TEXT NOT NULL,
  archive_root_id TEXT,
  relative_path TEXT,
  device_id TEXT,
  site_id TEXT,
  encryption_state TEXT,
  trust_level TEXT,
  is_writable INTEGER NOT NULL DEFAULT 0,
  is_online INTEGER NOT NULL DEFAULT 0,
  created_event_id TEXT NOT NULL,
  FOREIGN KEY (archive_root_id) REFERENCES archive_roots(archive_root_id),
  FOREIGN KEY (device_id) REFERENCES devices(device_id),
  FOREIGN KEY (site_id) REFERENCES sites(site_id)
);

CREATE INDEX idx_locations_device ON locations(device_id);
CREATE INDEX idx_locations_site ON locations(site_id);
CREATE INDEX idx_locations_kind ON locations(kind);

Example records

[
  {
    "location_id": "loc_annex_photos_main",
    "display_name": "Main photos git-annex CAS",
    "kind": "git_annex_cas",
    "uri": "file:///home/alice/data/photos/.git/annex/objects",
    "archive_root_id": "root_primary_home_data",
    "relative_path": "photos/.git/annex/objects",
    "device_id": "dev_primary_pc",
    "site_id": "site_home",
    "encryption_state": "none",
    "trust_level": "primary",
    "is_writable": 0,
    "is_online": 1,
    "created_event_id": "evt_01jz7a..."
  },
  {
    "location_id": "loc_usb8tb_a_photos",
    "display_name": "USB 8TB A photos",
    "kind": "filesystem_tree",
    "uri": "file:///media/exthd/archive/photos",
    "archive_root_id": "root_usb8tb_a_archive",
    "relative_path": "photos",
    "device_id": "dev_usb8tb_a",
    "site_id": "site_home",
    "encryption_state": "fde",
    "trust_level": "backup",
    "is_writable": 1,
    "is_online": 1,
    "created_event_id": "evt_01jz7b..."
  }
]

---

"object_locations"

Description

Current materialized belief about whether a given object exists at a given location and whether that copy has been verified.

Proposed columns

CREATE TABLE object_locations (
  object_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  state TEXT NOT NULL,
  first_seen_event_id TEXT,
  last_seen_event_id TEXT,
  last_verified_event_id TEXT,
  last_verified_time_utc_ms INTEGER,
  last_observed_path TEXT,
  last_error TEXT,
  quarantine_ref TEXT,
  PRIMARY KEY (object_id, location_id),
  FOREIGN KEY (object_id) REFERENCES objects(object_id),
  FOREIGN KEY (location_id) REFERENCES locations(location_id)
);

CREATE INDEX idx_object_locations_location ON object_locations(location_id, state);
CREATE INDEX idx_object_locations_state ON object_locations(state);
CREATE INDEX idx_object_locations_verified ON object_locations(last_verified_time_utc_ms);

Example record

{
  "object_id": "blake3:2c7f9f9a...",
  "location_id": "loc_usb8tb_a_photos",
  "state": "verified_fresh",
  "first_seen_event_id": "evt_01jz8a...",
  "last_seen_event_id": "evt_01jz8p...",
  "last_verified_event_id": "evt_01jz8p...",
  "last_verified_time_utc_ms": 1781042405123,
  "last_observed_path": "photos/2024/05/IMG_1234.JPG",
  "last_error": null,
  "quarantine_ref": null
}

---

"verification_results"

Description

Historical checksum verification attempts.

Unlike "object_locations", this table is historical, not just current state.

Proposed columns

CREATE TABLE verification_results (
  verification_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  object_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  result TEXT NOT NULL,
  expected_hash_algo TEXT NOT NULL,
  expected_hash_hex TEXT NOT NULL,
  observed_hash_hex TEXT,
  size_bytes INTEGER,
  bytes_read INTEGER,
  duration_ms INTEGER,
  verified_time_utc_ms INTEGER NOT NULL,
  path_observed TEXT,
  error_message TEXT,
  FOREIGN KEY (object_id) REFERENCES objects(object_id),
  FOREIGN KEY (location_id) REFERENCES locations(location_id)
);

CREATE INDEX idx_verification_object ON verification_results(object_id, verified_time_utc_ms);
CREATE INDEX idx_verification_location ON verification_results(location_id, verified_time_utc_ms);
CREATE INDEX idx_verification_result ON verification_results(result);

Example record

{
  "verification_id": "ver_01jz8p...",
  "event_id": "evt_01jz8p...",
  "object_id": "blake3:2c7f9f9a...",
  "location_id": "loc_usb8tb_a_photos",
  "result": "ok",
  "expected_hash_algo": "blake3",
  "expected_hash_hex": "2c7f9f9a...",
  "observed_hash_hex": "2c7f9f9a...",
  "size_bytes": 42391551,
  "bytes_read": 42391551,
  "duration_ms": 812,
  "verified_time_utc_ms": 1781042405123,
  "path_observed": "photos/2024/05/IMG_1234.JPG",
  "error_message": null
}

---

"quarantine_items"

Description

Tracks corrupt or suspicious files preserved during repair.

The system should not silently delete corrupt files during automatic repair.

Proposed columns

CREATE TABLE quarantine_items (
  quarantine_id TEXT PRIMARY KEY,
  object_id TEXT,
  location_id TEXT NOT NULL,
  original_path TEXT NOT NULL,
  quarantine_path TEXT NOT NULL,
  reason TEXT NOT NULL,
  detected_event_id TEXT NOT NULL,
  quarantined_event_id TEXT NOT NULL,
  created_time_utc_ms INTEGER NOT NULL,
  notes TEXT,
  FOREIGN KEY (object_id) REFERENCES objects(object_id),
  FOREIGN KEY (location_id) REFERENCES locations(location_id)
);

CREATE INDEX idx_quarantine_location ON quarantine_items(location_id);
CREATE INDEX idx_quarantine_object ON quarantine_items(object_id);

Example record

{
  "quarantine_id": "qnt_01jz9a...",
  "object_id": "blake3:2c7f9f9a...",
  "location_id": "loc_usb8tb_a_photos",
  "original_path": "photos/2024/05/IMG_1234.JPG",
  "quarantine_path": ".archive-quarantine/2026-06-09/IMG_1234.JPG.corrupt",
  "reason": "hash_mismatch",
  "detected_event_id": "evt_01jz99...",
  "quarantined_event_id": "evt_01jz9a...",
  "created_time_utc_ms": 1781045000000,
  "notes": "Observed BLAKE3 did not match expected object hash"
}

---

"policies"

Description

Current materialized policy definitions.

Canonical policy changes come from events and policy files in Git.

Proposed columns

CREATE TABLE policies (
  policy_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  selector_json TEXT NOT NULL,
  requirements_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_updated_event_id TEXT NOT NULL
);

Example record

{
  "policy_id": "pol_photos_default",
  "display_name": "Photos default preservation policy",
  "selector_json": "{\"collection_id\":\"photos\"}",
  "requirements_json": "{\"min_verified_copies\":3,\"min_sites\":2,\"require_offline_copy\":true,\"max_verification_age_days\":365}",
  "enabled": 1,
  "last_updated_event_id": "evt_01jz80..."
}

---

"policy_status"

Description

Derived cache showing whether an object satisfies a policy.

This can be recomputed from objects, locations, verification freshness, sites, devices, and risk domains.

Proposed columns

CREATE TABLE policy_status (
  object_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  status TEXT NOT NULL,
  evaluated_time_utc_ms INTEGER NOT NULL,
  reasons_json TEXT NOT NULL,
  PRIMARY KEY (object_id, policy_id),
  FOREIGN KEY (object_id) REFERENCES objects(object_id),
  FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
);

CREATE INDEX idx_policy_status_status ON policy_status(policy_id, status);

Example record

{
  "object_id": "blake3:2c7f9f9a...",
  "policy_id": "pol_photos_default",
  "status": "violated",
  "evaluated_time_utc_ms": 1781046000000,
  "reasons_json": "{\"verified_copies\":2,\"required_verified_copies\":3,\"sites\":[\"site_home\"],\"missing\":\"offsite copy\"}"
}

---

"jobs"

Description

Long-running work units.

Designed so CLI-initiated work can later become daemon-scheduled work without major schema changes.

Proposed columns

CREATE TABLE jobs (
  job_id TEXT PRIMARY KEY,
  job_type TEXT NOT NULL,
  status TEXT NOT NULL,
  created_time_utc_ms INTEGER NOT NULL,
  started_time_utc_ms INTEGER,
  finished_time_utc_ms INTEGER,
  actor_id TEXT,
  host_id TEXT,
  params_json TEXT NOT NULL,
  progress_json TEXT
);

CREATE INDEX idx_jobs_status ON jobs(status, job_type);
CREATE INDEX idx_jobs_host ON jobs(host_id, status);

Example record

{
  "job_id": "job_import_annex_photos_20260609",
  "job_type": "import_git_annex",
  "status": "running",
  "created_time_utc_ms": 1781039000000,
  "started_time_utc_ms": 1781039010000,
  "finished_time_utc_ms": null,
  "actor_id": "alice",
  "host_id": "primary-pc",
  "params_json": "{\"repo_path\":\"/home/alice/data/photos\",\"collection_id\":\"photos\"}",
  "progress_json": "{\"files_seen\":120400,\"objects_imported\":120399,\"errors\":0}"
}

---

"job_items"

Description

Fine-grained resumable job queue.

Useful for huge verification, copy, import, and repair jobs.

Proposed columns

CREATE TABLE job_items (
  job_item_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  item_type TEXT NOT NULL,
  object_id TEXT,
  file_ref_id TEXT,
  location_id TEXT,
  path TEXT,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  updated_time_utc_ms INTEGER NOT NULL,
  FOREIGN KEY (job_id) REFERENCES jobs(job_id)
);

CREATE INDEX idx_job_items_job_status ON job_items(job_id, status);
CREATE INDEX idx_job_items_object ON job_items(object_id);

Example record

{
  "job_item_id": "jitem_01jz8q...",
  "job_id": "job_verify_usb8tb_a_20260609",
  "item_type": "object",
  "object_id": "blake3:2c7f9f9a...",
  "file_ref_id": null,
  "location_id": "loc_usb8tb_a_photos",
  "path": "photos/2024/05/IMG_1234.JPG",
  "status": "complete",
  "attempts": 1,
  "last_error": null,
  "updated_time_utc_ms": 1781042405123
}

---

"git_annex_imports"

Description

Records one-time or repeated imports from existing git-annex repositories.

Proposed columns

CREATE TABLE git_annex_imports (
  import_id TEXT PRIMARY KEY,
  repo_path TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  annex_objects_path TEXT NOT NULL,
  git_head_commit TEXT,
  annex_uuid TEXT,
  import_started_event_id TEXT NOT NULL,
  import_completed_event_id TEXT,
  imported_time_utc_ms INTEGER,
  notes TEXT,
  FOREIGN KEY (collection_id) REFERENCES collections(collection_id),
  FOREIGN KEY (location_id) REFERENCES locations(location_id)
);

Example record

{
  "import_id": "anneximp_photos_20260609",
  "repo_path": "/home/alice/data/photos",
  "collection_id": "photos",
  "location_id": "loc_annex_photos_main",
  "annex_objects_path": "/home/alice/data/photos/.git/annex/objects",
  "git_head_commit": "a1b2c3d4...",
  "annex_uuid": "2f7c...-annex-uuid",
  "import_started_event_id": "evt_01jz80...",
  "import_completed_event_id": "evt_01jz88...",
  "imported_time_utc_ms": 1781039500000,
  "notes": "Read-only import; no git-annex mutation"
}

---

"git_annex_keys"

Description

Maps git-annex keys to Archive Ledger BLAKE3 objects.

Proposed columns

CREATE TABLE git_annex_keys (
  annex_key TEXT PRIMARY KEY,
  object_id TEXT NOT NULL,
  backend TEXT,
  annex_size_bytes INTEGER,
  annex_extension TEXT,
  parsed_hash_algo TEXT,
  parsed_hash_hex TEXT,
  import_id TEXT NOT NULL,
  content_path TEXT,
  verified_event_id TEXT,
  FOREIGN KEY (object_id) REFERENCES objects(object_id),
  FOREIGN KEY (import_id) REFERENCES git_annex_imports(import_id)
);

CREATE INDEX idx_git_annex_keys_object ON git_annex_keys(object_id);
CREATE INDEX idx_git_annex_keys_hash ON git_annex_keys(parsed_hash_algo, parsed_hash_hex);

Example record

{
  "annex_key": "SHA512E-s42391551--a83d2b....jpg",
  "object_id": "blake3:2c7f9f9a...",
  "backend": "SHA512E",
  "annex_size_bytes": 42391551,
  "annex_extension": "jpg",
  "parsed_hash_algo": "sha512",
  "parsed_hash_hex": "a83d2b...",
  "import_id": "anneximp_photos_20260609",
  "content_path": ".git/annex/objects/ab/cd/SHA512E-s42391551--a83d2b....jpg/SHA512E-s42391551--a83d2b....jpg",
  "verified_event_id": "evt_01jz83..."
}

---

"checkpoints"

Description

Records closed canonical event-stream checkpoints.

A checkpoint says the archive is safe through a particular event sequence/hash and, optionally, Git commit.

Proposed columns

CREATE TABLE checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  created_time_utc_ms INTEGER NOT NULL,
  event_first_seq INTEGER,
  event_last_seq INTEGER NOT NULL,
  event_last_hash TEXT NOT NULL,
  git_commit TEXT,
  manifest_path TEXT NOT NULL,
  created_event_id TEXT NOT NULL
);

CREATE INDEX idx_checkpoints_seq ON checkpoints(event_last_seq);

Example record

{
  "checkpoint_id": "chk_20260609_000001_184220",
  "created_time_utc_ms": 1781049600000,
  "event_first_seq": 180001,
  "event_last_seq": 184220,
  "event_last_hash": "blake3:7bd9...",
  "git_commit": "9f4a1c2...",
  "manifest_path": "manifests/2026/06/chk_20260609_000001_184220.json",
  "created_event_id": "evt_01jz9f..."
}

---

"sqlite_snapshots"

Description

Tracks SQLite backup/snapshot files.

Snapshots are restore accelerators, not canonical truth.

Proposed columns

CREATE TABLE sqlite_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  created_time_utc_ms INTEGER NOT NULL,
  snapshot_path TEXT NOT NULL,
  includes_event_seq INTEGER NOT NULL,
  includes_event_hash TEXT NOT NULL,
  snapshot_hash_algo TEXT NOT NULL,
  snapshot_hash_hex TEXT NOT NULL,
  storage_location_id TEXT,
  created_event_id TEXT NOT NULL
);

CREATE INDEX idx_sqlite_snapshots_seq ON sqlite_snapshots(includes_event_seq);

Example record

{
  "snapshot_id": "sqlsnap_20260609_184220",
  "created_time_utc_ms": 1781049700000,
  "snapshot_path": "snapshots/catalog-20260609-184220.sqlite.zst",
  "includes_event_seq": 184220,
  "includes_event_hash": "blake3:7bd9...",
  "snapshot_hash_algo": "blake3",
  "snapshot_hash_hex": "51ea...",
  "storage_location_id": "loc_usb8tb_a_catalog_snapshots",
  "created_event_id": "evt_01jz9g..."
}

---

"external_indexes"

Description

Optional registry of higher-level app indexes layered on archive-core.

Examples:

- photo gallery index
- document index
- email index

These tools should reference archive objects by "object_id".

Proposed columns

CREATE TABLE external_indexes (
  external_index_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  index_kind TEXT NOT NULL,
  database_uri TEXT,
  owner_app TEXT,
  created_event_id TEXT NOT NULL,
  last_seen_event_id TEXT
);

Example record

{
  "external_index_id": "idx_photo_gallery_main",
  "display_name": "Photo gallery index",
  "index_kind": "photo_gallery",
  "database_uri": "file:///home/alice/data/indexes/photo-gallery.sqlite",
  "owner_app": "photo-gallery",
  "created_event_id": "evt_01jza0...",
  "last_seen_event_id": "evt_01jza1..."
}

Open Schema Questions

- Should "locations.uri" be stored as last-resolved convenience only, with resolution always based on "device_mounts + archive_roots + relative_path"?
- Should "hosts" be its own table, separate from "devices"?
- Should "actors" be its own table, separate from free-text "actor_id"?
- Should "object_locations.state" include "verified_fresh", or should freshness always be computed from "last_verified_time_utc_ms + policy"?
- Should "file_refs" track per-location path observations separately from logical paths?
- Should git-annex worktree path and CAS content path be separated more explicitly?
- Should SQLite snapshot records live in the canonical event stream only, or also in SQLite?
- Should policy evaluation be stored per object, per collection, or aggregated first?
- Should external indexes be in MVP, or only a documented integration convention?
