-- Authoritative current-state catalog, schema version 1.
-- Stable IDs are identities; BLAKE3 is an expected property of a Collection/path.
CREATE TABLE catalog_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    archive_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0)
) STRICT;
CREATE TABLE sites (
    site_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    site_kind TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired'))
) STRICT;
CREATE INDEX sites_status_name ON sites(status, display_name, site_id);
CREATE TABLE policies (
    policy_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    requirements_json TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('active', 'retired'))
) STRICT;
CREATE INDEX policies_status_name ON policies(status, display_name, policy_id);
CREATE TABLE collections (
    collection_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT,
    home_site_id TEXT REFERENCES sites(site_id),
    policy_id TEXT REFERENCES policies(policy_id),
    status TEXT NOT NULL CHECK (status IN ('active', 'retired'))
) STRICT;
CREATE INDEX collections_status_name ON collections(status, display_name, collection_id);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    device_kind TEXT NOT NULL,
    serial_hint TEXT,
    hardware_fingerprint TEXT,
    fingerprint_kind TEXT,
    identity_state TEXT NOT NULL CHECK (identity_state IN ('confirmed', 'unavailable', 'conflict')),
    owner TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    current_site_id TEXT REFERENCES sites(site_id),
    expected_availability TEXT NOT NULL CHECK (expected_availability IN ('online', 'offline', 'intermittent')),
    last_checkin_time_utc_ms INTEGER,
    last_fingerprint_match_time_utc_ms INTEGER,
    last_fingerprint_status TEXT
) STRICT;
CREATE INDEX devices_status_name ON devices(status, display_name, device_id);
CREATE UNIQUE INDEX devices_confirmed_fingerprint
    ON devices(fingerprint_kind, hardware_fingerprint)
    WHERE status = 'active' AND identity_state = 'confirmed' AND hardware_fingerprint IS NOT NULL;
CREATE TABLE device_site_history (
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    arrived_time_utc_ms INTEGER NOT NULL,
    departed_time_utc_ms INTEGER,
    PRIMARY KEY (device_id, arrived_time_utc_ms)
) STRICT;
CREATE UNIQUE INDEX device_site_one_open ON device_site_history(device_id) WHERE departed_time_utc_ms IS NULL;
CREATE TABLE archive_roots (
    archive_root_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    display_name TEXT NOT NULL,
    filesystem_fingerprint TEXT,
    fingerprint_kind TEXT,
    identity_state TEXT NOT NULL CHECK (identity_state IN ('confirmed', 'unavailable', 'conflict')),
    root_path_on_device_bytes BLOB NOT NULL,
    root_path_encoding TEXT NOT NULL,
    root_path_display TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    last_seen_time_utc_ms INTEGER
) STRICT;
CREATE UNIQUE INDEX archive_roots_active_path
    ON archive_roots(device_id, root_path_encoding, root_path_on_device_bytes)
    WHERE status = 'active';
CREATE UNIQUE INDEX archive_roots_confirmed_fingerprint
    ON archive_roots(fingerprint_kind, filesystem_fingerprint)
    WHERE status = 'active' AND identity_state = 'confirmed' AND filesystem_fingerprint IS NOT NULL;
CREATE INDEX archive_roots_status_name ON archive_roots(status, display_name, archive_root_id);
CREATE TABLE locations (
    location_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('filesystem', 'service')),
    archive_root_id TEXT REFERENCES archive_roots(archive_root_id),
    relative_path_bytes BLOB,
    relative_path_encoding TEXT,
    relative_path_display TEXT,
    device_id TEXT REFERENCES devices(device_id),
    site_id TEXT REFERENCES sites(site_id),
    encryption_state TEXT CHECK (encryption_state IN ('encrypted', 'unencrypted', 'unknown')),
    trust_level TEXT CHECK (trust_level IN ('trusted', 'untrusted', 'unknown')),
    expected_availability TEXT NOT NULL CHECK (expected_availability IN ('online', 'offline', 'intermittent')),
    is_writable INTEGER NOT NULL DEFAULT 0 CHECK (is_writable IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    CHECK (
      (archive_root_id IS NOT NULL AND device_id IS NOT NULL AND site_id IS NULL AND relative_path_bytes IS NOT NULL)
      OR
      (archive_root_id IS NULL AND device_id IS NULL AND site_id IS NOT NULL AND relative_path_bytes IS NULL)
    )
) STRICT;
CREATE INDEX locations_status_name ON locations(status, display_name, location_id);
CREATE INDEX locations_device ON locations(device_id, status);
CREATE INDEX locations_site ON locations(site_id, status);
CREATE INDEX locations_root ON locations(archive_root_id, status);
CREATE TABLE device_mounts (
    mount_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    archive_root_id TEXT REFERENCES archive_roots(archive_root_id),
    host_id TEXT NOT NULL,
    mount_root_uri TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('mounted', 'unmounted', 'mismatch')),
    fingerprint_status TEXT NOT NULL,
    observed_time_utc_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX device_mounts_root_time ON device_mounts(archive_root_id, observed_time_utc_ms);
CREATE INDEX device_mounts_device_time ON device_mounts(device_id, observed_time_utc_ms);
CREATE TABLE risk_domains (
    risk_domain_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    risk_kind TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired'))
) STRICT;
CREATE INDEX risk_domains_status_name ON risk_domains(status, display_name, risk_domain_id);
CREATE TABLE entity_risk_domains (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('location', 'archive_root', 'device', 'site')),
    entity_id TEXT NOT NULL,
    risk_domain_id TEXT NOT NULL REFERENCES risk_domains(risk_domain_id),
    PRIMARY KEY (entity_type, entity_id, risk_domain_id)
) STRICT;

CREATE TABLE objects (
    object_id TEXT PRIMARY KEY,
    collection_id TEXT NOT NULL REFERENCES collections(collection_id),
    relative_path_encoding TEXT NOT NULL,
    relative_path_bytes BLOB NOT NULL,
    relative_path_display TEXT NOT NULL,
    expected_blake3 BLOB CHECK (expected_blake3 IS NULL OR length(expected_blake3) = 32),
    expected_size_bytes INTEGER CHECK (expected_size_bytes IS NULL OR expected_size_bytes >= 0),
    UNIQUE (collection_id, relative_path_encoding, relative_path_bytes)
) STRICT;
CREATE INDEX objects_expected_blake3 ON objects(expected_blake3) WHERE expected_blake3 IS NOT NULL;

CREATE TABLE files (
    object_id TEXT NOT NULL REFERENCES objects(object_id),
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    presence TEXT NOT NULL CHECK (presence IN ('present', 'missing', 'unknown')),
    integrity TEXT NOT NULL CHECK (integrity IN ('unverified', 'verified', 'damaged')),
    last_check_time_utc_ms INTEGER,
    last_check_result TEXT CHECK (last_check_result IN ('ok', 'mismatch', 'missing', 'read_error')),
    observed_blake3 BLOB CHECK (observed_blake3 IS NULL OR length(observed_blake3) = 32),
    last_success_time_utc_ms INTEGER,
    PRIMARY KEY (object_id, location_id),
    CHECK ((last_check_time_utc_ms IS NULL) = (last_check_result IS NULL)),
    CHECK (integrity != 'verified' OR last_success_time_utc_ms IS NOT NULL)
) STRICT;
CREATE INDEX files_location_object ON files(location_id, object_id);

-- Historical rows explain changes; current queries never replay or join this table.
CREATE TABLE history (
    history_id INTEGER PRIMARY KEY,
    object_id TEXT REFERENCES objects(object_id),
    location_id TEXT REFERENCES locations(location_id),
    time_utc_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    check_result TEXT CHECK (check_result IN ('ok', 'mismatch', 'missing', 'read_error')),
    expected_blake3 BLOB CHECK (expected_blake3 IS NULL OR length(expected_blake3) = 32),
    observed_blake3 BLOB CHECK (observed_blake3 IS NULL OR length(observed_blake3) = 32),
    details_json TEXT
) STRICT;
CREATE INDEX history_object_time ON history(object_id, time_utc_ms, history_id);
CREATE INDEX history_location_time ON history(location_id, time_utc_ms, history_id);
CREATE TRIGGER history_no_update BEFORE UPDATE ON history
BEGIN SELECT RAISE(ABORT, 'catalog history is append-only'); END;
CREATE TRIGGER history_no_delete BEFORE DELETE ON history
BEGIN SELECT RAISE(ABORT, 'catalog history is append-only'); END;

-- Resumable local work and its coverage, committed with the observations it produced.
CREATE TABLE catalog_jobs (
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    params_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running','complete','partial','cancelled')),
    started_time_utc_ms INTEGER NOT NULL,
    finished_time_utc_ms INTEGER,
    progress_json TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE TABLE catalog_scan_seen (
    job_id TEXT NOT NULL REFERENCES catalog_jobs(job_id),
    object_id TEXT NOT NULL REFERENCES objects(object_id),
    PRIMARY KEY(job_id,object_id)
) STRICT;
CREATE TABLE catalog_write_operations (
    operation_key TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    outcome_json TEXT NOT NULL
) STRICT;
-- Completed work survives a restarted enumeration; seen coverage is per pass.
CREATE TABLE catalog_job_items (
    job_id TEXT NOT NULL REFERENCES catalog_jobs(job_id),
    object_id TEXT NOT NULL REFERENCES objects(object_id),
    PRIMARY KEY(job_id,object_id)
) STRICT;
