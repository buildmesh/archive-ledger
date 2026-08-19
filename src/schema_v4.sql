CREATE TABLE archive_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE events (
    stream_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    event_time_utc_ms INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    job_id TEXT,
    object_id TEXT,
    file_ref_id TEXT,
    copy_claim_id TEXT,
    location_id TEXT,
    device_id TEXT,
    site_id TEXT,
    payload_json TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL,
    PRIMARY KEY (stream_id, seq)
);
CREATE INDEX events_type_time ON events(event_type, event_time_utc_ms);
CREATE INDEX events_job ON events(job_id, event_time_utc_ms) WHERE job_id IS NOT NULL;
CREATE INDEX events_object ON events(object_id, event_time_utc_ms) WHERE object_id IS NOT NULL;
CREATE INDEX events_file_ref ON events(file_ref_id, event_time_utc_ms) WHERE file_ref_id IS NOT NULL;
CREATE INDEX events_copy_claim ON events(copy_claim_id, event_time_utc_ms) WHERE copy_claim_id IS NOT NULL;
CREATE INDEX events_location ON events(location_id, event_time_utc_ms) WHERE location_id IS NOT NULL;
CREATE INDEX events_device ON events(device_id, event_time_utc_ms) WHERE device_id IS NOT NULL;
CREATE INDEX events_site ON events(site_id, event_time_utc_ms) WHERE site_id IS NOT NULL;

CREATE TABLE objects (
    object_id TEXT PRIMARY KEY,
    canonical_hash_algo TEXT NOT NULL,
    canonical_hash_hex TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    media_type TEXT,
    extension_hint TEXT,
    first_seen_event_id TEXT NOT NULL,
    first_seen_time_utc_ms INTEGER NOT NULL
);

CREATE TABLE object_hashes (
    object_id TEXT NOT NULL REFERENCES objects(object_id),
    hash_algo TEXT NOT NULL,
    hash_hex TEXT NOT NULL,
    source TEXT NOT NULL,
    verified_event_id TEXT,
    PRIMARY KEY (object_id, hash_algo, hash_hex)
);
CREATE INDEX object_hashes_lookup ON object_hashes(hash_algo, hash_hex);

CREATE TABLE external_identities (
    external_identity_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    external_key TEXT NOT NULL,
    expected_hash_algo TEXT,
    expected_hash_hex TEXT,
    expected_size_bytes INTEGER,
    object_id TEXT REFERENCES objects(object_id),
    resolution_state TEXT NOT NULL CHECK (resolution_state IN ('unresolved', 'resolved', 'conflict', 'unsupported')),
    source_detail_json TEXT,
    first_seen_event_id TEXT NOT NULL,
    resolved_event_id TEXT,
    UNIQUE (namespace, external_key)
);

CREATE TABLE sites (
    site_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    site_kind TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,
    last_event_id TEXT NOT NULL
);

CREATE TABLE policies (
    policy_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    requirements_json TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_event_id TEXT NOT NULL
);

CREATE TABLE collections (
    collection_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT,
    home_site_id TEXT REFERENCES sites(site_id),
    policy_id TEXT REFERENCES policies(policy_id),
    status TEXT NOT NULL,
    last_event_id TEXT NOT NULL
);

CREATE TABLE file_refs (
    file_ref_id TEXT PRIMARY KEY,
    collection_id TEXT NOT NULL REFERENCES collections(collection_id),
    logical_path_bytes BLOB NOT NULL,
    logical_path_encoding TEXT NOT NULL CHECK (logical_path_encoding IN ('utf8', 'unix_bytes', 'windows_utf16le')),
    logical_path_display TEXT NOT NULL,
    object_id TEXT REFERENCES objects(object_id),
    external_identity_id TEXT REFERENCES external_identities(external_identity_id),
    identity_state TEXT NOT NULL CHECK (identity_state IN ('resolved', 'unresolved', 'conflict', 'unknown')),
    path_state TEXT NOT NULL CHECK (path_state IN ('active', 'removed')),
    created_time_utc_ms INTEGER,
    modified_time_utc_ms INTEGER,
    observed_size_bytes INTEGER,
    first_seen_event_id TEXT NOT NULL,
    last_seen_event_id TEXT,
    removed_event_id TEXT,
    CHECK (object_id IS NOT NULL OR external_identity_id IS NOT NULL OR identity_state = 'unknown')
);
CREATE UNIQUE INDEX file_refs_active_path ON file_refs(collection_id, logical_path_encoding, logical_path_bytes) WHERE path_state = 'active';
CREATE INDEX file_refs_object ON file_refs(object_id) WHERE object_id IS NOT NULL;
CREATE INDEX file_refs_external_identity ON file_refs(external_identity_id) WHERE external_identity_id IS NOT NULL;

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    device_kind TEXT NOT NULL,
    serial_hint TEXT,
    hardware_fingerprint TEXT,
    fingerprint_kind TEXT,
    identity_state TEXT NOT NULL CHECK (identity_state IN ('confirmed', 'unavailable', 'conflict')),
    owner TEXT,
    status TEXT NOT NULL,
    current_site_id TEXT REFERENCES sites(site_id),
    expected_availability TEXT NOT NULL CHECK (expected_availability IN ('online', 'offline', 'intermittent')),
    last_checkin_event_id TEXT,
    last_checkin_time_utc_ms INTEGER,
    last_fingerprint_match_time_utc_ms INTEGER,
    last_fingerprint_status TEXT,
    last_event_id TEXT NOT NULL
);
CREATE UNIQUE INDEX devices_confirmed_fingerprint ON devices(fingerprint_kind, hardware_fingerprint)
    WHERE status = 'active' AND identity_state = 'confirmed' AND hardware_fingerprint IS NOT NULL;

CREATE TABLE device_mounts (
    mount_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    host_id TEXT NOT NULL,
    mount_root_uri TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('mounted', 'unmounted', 'mismatch')),
    fingerprint_status TEXT NOT NULL,
    observed_time_utc_ms INTEGER NOT NULL,
    observed_event_id TEXT NOT NULL
);
CREATE INDEX device_mounts_device_time ON device_mounts(device_id, observed_time_utc_ms);
CREATE INDEX device_mounts_host_time ON device_mounts(host_id, observed_time_utc_ms);

CREATE TABLE device_site_history (
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    arrived_time_utc_ms INTEGER NOT NULL,
    departed_time_utc_ms INTEGER,
    moved_event_id TEXT NOT NULL,
    PRIMARY KEY (device_id, arrived_time_utc_ms)
);
CREATE UNIQUE INDEX device_site_one_open ON device_site_history(device_id) WHERE departed_time_utc_ms IS NULL;

CREATE TABLE archive_roots (
    archive_root_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    display_name TEXT NOT NULL,
    root_path_on_device_bytes BLOB NOT NULL,
    root_path_encoding TEXT NOT NULL,
    root_path_display TEXT NOT NULL,
    status TEXT NOT NULL,
    created_event_id TEXT NOT NULL,
    last_seen_event_id TEXT,
    last_seen_time_utc_ms INTEGER
);
CREATE UNIQUE INDEX archive_roots_active_path ON archive_roots(device_id, root_path_encoding, root_path_on_device_bytes) WHERE status = 'active';

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
    status TEXT NOT NULL,
    created_event_id TEXT NOT NULL,
    last_event_id TEXT NOT NULL,
    CHECK (
        (kind = 'filesystem' AND archive_root_id IS NOT NULL AND device_id IS NOT NULL AND site_id IS NULL AND relative_path_bytes IS NOT NULL)
        OR
        (kind = 'service' AND archive_root_id IS NULL AND device_id IS NULL AND site_id IS NOT NULL AND relative_path_bytes IS NULL)
    )
);
CREATE INDEX locations_device ON locations(device_id, status);
CREATE INDEX locations_site ON locations(site_id, status);
CREATE INDEX locations_root ON locations(archive_root_id, status);
CREATE INDEX locations_kind ON locations(kind, status);

CREATE TABLE external_availability (
    external_identity_id TEXT NOT NULL REFERENCES external_identities(external_identity_id),
    source_repo_id TEXT NOT NULL,
    source_remote_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('present', 'missing', 'unknown')),
    location_id TEXT REFERENCES locations(location_id),
    observed_time_utc_ms INTEGER NOT NULL,
    observed_event_id TEXT NOT NULL,
    PRIMARY KEY (external_identity_id, source_repo_id, source_remote_id)
);

CREATE TABLE path_observations (
    file_ref_id TEXT NOT NULL REFERENCES file_refs(file_ref_id),
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    observed_path_bytes BLOB NOT NULL,
    observed_path_encoding TEXT NOT NULL,
    observed_path_display TEXT NOT NULL,
    representation TEXT NOT NULL,
    object_id TEXT REFERENCES objects(object_id),
    external_identity_id TEXT REFERENCES external_identities(external_identity_id),
    state TEXT NOT NULL CHECK (state IN ('present', 'missing')),
    first_seen_event_id TEXT NOT NULL,
    last_seen_event_id TEXT,
    last_seen_time_utc_ms INTEGER NOT NULL,
    last_complete_scan_id TEXT,
    observed_size_bytes INTEGER,
    modified_time_utc_ms INTEGER,
    PRIMARY KEY (file_ref_id, location_id, observed_path_encoding, observed_path_bytes)
);

CREATE TABLE copy_claims (
    copy_claim_id TEXT PRIMARY KEY,
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    relative_path_bytes BLOB NOT NULL,
    relative_path_encoding TEXT NOT NULL,
    relative_path_display TEXT NOT NULL,
    object_id TEXT REFERENCES objects(object_id),
    external_identity_id TEXT REFERENCES external_identities(external_identity_id),
    claim_basis TEXT NOT NULL CHECK (claim_basis IN ('observed_bytes', 'observed_metadata', 'source_metadata')),
    state TEXT NOT NULL CHECK (state IN ('present', 'missing', 'corrupt', 'unknown', 'superseded')),
    state_event_seq INTEGER NOT NULL,
    first_seen_event_id TEXT NOT NULL,
    last_seen_event_id TEXT,
    last_seen_time_utc_ms INTEGER,
    last_complete_scan_id TEXT,
    last_verified_event_id TEXT,
    last_verified_time_utc_ms INTEGER,
    last_verification_result TEXT,
    last_error_code TEXT,
    last_error_detail TEXT,
    CHECK (object_id IS NOT NULL OR external_identity_id IS NOT NULL OR state = 'unknown')
);
CREATE UNIQUE INDEX copy_claims_active_path ON copy_claims(location_id, relative_path_encoding, relative_path_bytes) WHERE state != 'superseded';
CREATE INDEX copy_claims_object_state ON copy_claims(object_id, state);
CREATE INDEX copy_claims_external_state ON copy_claims(external_identity_id, state);
CREATE INDEX copy_claims_location_state ON copy_claims(location_id, state);
CREATE INDEX copy_claims_verification_age ON copy_claims(last_verified_time_utc_ms, last_verification_result);

CREATE TABLE verification_results (
    verification_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    job_id TEXT,
    copy_claim_id TEXT NOT NULL REFERENCES copy_claims(copy_claim_id),
    object_id TEXT REFERENCES objects(object_id),
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    result TEXT NOT NULL CHECK (result IN ('ok', 'hash_mismatch', 'read_error', 'identity_mismatch')),
    expected_hash_algo TEXT,
    expected_hash_hex TEXT,
    observed_hash_hex TEXT,
    size_bytes INTEGER,
    bytes_read INTEGER,
    duration_ms INTEGER,
    verified_time_utc_ms INTEGER NOT NULL,
    path_observed_bytes BLOB NOT NULL,
    path_observed_encoding TEXT NOT NULL,
    path_observed_display TEXT NOT NULL,
    device_fingerprint_status TEXT NOT NULL,
    error_code TEXT,
    error_detail TEXT
);

CREATE TABLE scan_runs (
    scan_id TEXT PRIMARY KEY,
    job_id TEXT,
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    collection_id TEXT NOT NULL REFERENCES collections(collection_id),
    logical_prefix_bytes BLOB,
    logical_prefix_encoding TEXT,
    logical_prefix_display TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed', 'cancelled')),
    started_time_utc_ms INTEGER NOT NULL,
    started_event_seq INTEGER NOT NULL,
    finished_time_utc_ms INTEGER,
    coverage_version INTEGER NOT NULL,
    scope_json TEXT NOT NULL,
    exclusions_json TEXT NOT NULL,
    exclusions_hash TEXT NOT NULL,
    observations_count INTEGER NOT NULL DEFAULT 0,
    observations_digest TEXT,
    missing_candidate_count INTEGER NOT NULL DEFAULT 0,
    missing_candidate_digest TEXT,
    files_seen INTEGER NOT NULL DEFAULT 0,
    bytes_seen INTEGER NOT NULL DEFAULT 0,
    new_paths INTEGER NOT NULL DEFAULT 0,
    changed_paths INTEGER NOT NULL DEFAULT 0,
    missing_paths INTEGER NOT NULL DEFAULT 0,
    unchanged_paths INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    error_summary_json TEXT NOT NULL,
    started_event_id TEXT NOT NULL,
    finished_event_id TEXT
);
CREATE INDEX scan_runs_location_finished ON scan_runs(location_id, finished_time_utc_ms);
CREATE INDEX scan_runs_status ON scan_runs(status);
CREATE UNIQUE INDEX scan_runs_one_running_scope ON scan_runs(location_id, collection_id, scope_json) WHERE status = 'running';

CREATE TABLE scan_missing_candidates (
    candidate_event_id TEXT PRIMARY KEY,
    candidate_event_seq INTEGER NOT NULL UNIQUE,
    candidate_event_hash TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
    candidate_kind TEXT NOT NULL CHECK (candidate_kind IN ('path', 'copy')),
    file_ref_id TEXT REFERENCES file_refs(file_ref_id),
    copy_claim_id TEXT REFERENCES copy_claims(copy_claim_id),
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    path_bytes BLOB NOT NULL,
    path_encoding TEXT NOT NULL,
    activated INTEGER NOT NULL DEFAULT 0 CHECK (activated IN (0, 1))
);
CREATE INDEX scan_candidates_scan_seq ON scan_missing_candidates(scan_id, candidate_event_seq);
CREATE INDEX scan_candidates_file_ref ON scan_missing_candidates(file_ref_id) WHERE file_ref_id IS NOT NULL;
CREATE INDEX scan_candidates_copy_claim ON scan_missing_candidates(copy_claim_id) WHERE copy_claim_id IS NOT NULL;
CREATE INDEX scan_candidates_scan_file ON scan_missing_candidates(scan_id, candidate_kind, file_ref_id) WHERE file_ref_id IS NOT NULL;
CREATE INDEX scan_candidates_scan_copy ON scan_missing_candidates(scan_id, candidate_kind, copy_claim_id) WHERE copy_claim_id IS NOT NULL;

CREATE TABLE risk_domains (
    risk_domain_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    risk_kind TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,
    last_event_id TEXT NOT NULL
);

CREATE TABLE entity_risk_domains (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('location', 'archive_root', 'device', 'site')),
    entity_id TEXT NOT NULL,
    risk_domain_id TEXT NOT NULL REFERENCES risk_domains(risk_domain_id),
    assigned_event_id TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_id, risk_domain_id)
);

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
    progress_json TEXT,
    input_version TEXT NOT NULL
);

CREATE TABLE job_items (
    job_item_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    item_type TEXT NOT NULL,
    item_key TEXT NOT NULL,
    object_id TEXT,
    file_ref_id TEXT,
    copy_claim_id TEXT,
    location_id TEXT,
    path_bytes BLOB,
    path_encoding TEXT,
    path_display TEXT,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    last_error_detail TEXT,
    updated_time_utc_ms INTEGER NOT NULL,
    UNIQUE (job_id, item_type, item_key)
);
CREATE INDEX job_items_job_status ON job_items(job_id, status);
CREATE INDEX job_items_object ON job_items(object_id) WHERE object_id IS NOT NULL;
CREATE INDEX job_items_file_ref ON job_items(file_ref_id) WHERE file_ref_id IS NOT NULL;
CREATE INDEX job_items_copy_claim ON job_items(copy_claim_id) WHERE copy_claim_id IS NOT NULL;
CREATE INDEX job_items_location ON job_items(location_id) WHERE location_id IS NOT NULL;
CREATE INDEX job_items_scan_path ON job_items(job_id, item_type, path_encoding, path_bytes) WHERE item_type = 'scan_seen';

CREATE TABLE operation_outcomes (
    operation_key TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_seq INTEGER NOT NULL UNIQUE,
    job_id TEXT,
    job_type TEXT NOT NULL,
    item_type TEXT NOT NULL,
    item_key TEXT NOT NULL,
    outcome_kind TEXT NOT NULL
);

CREATE TABLE policy_evaluations (
    evaluation_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
    policy_version INTEGER NOT NULL,
    evaluated_event_seq INTEGER NOT NULL,
    evaluated_event_hash TEXT NOT NULL,
    evaluated_policy_input_seq INTEGER NOT NULL,
    rules_version INTEGER NOT NULL,
    started_time_utc_ms INTEGER NOT NULL,
    completed_time_utc_ms INTEGER,
    valid_until_utc_ms INTEGER,
    status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
    files_expected INTEGER NOT NULL,
    files_evaluated INTEGER NOT NULL
);

CREATE TABLE policy_status (
    evaluation_id TEXT NOT NULL REFERENCES policy_evaluations(evaluation_id),
    file_ref_id TEXT NOT NULL REFERENCES file_refs(file_ref_id),
    object_id TEXT REFERENCES objects(object_id),
    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
    policy_version INTEGER NOT NULL,
    evaluated_event_seq INTEGER NOT NULL,
    evaluated_policy_input_seq INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('violated', 'uncertain')),
    evaluated_time_utc_ms INTEGER NOT NULL,
    reasons_json TEXT NOT NULL,
    recommended_actions_json TEXT NOT NULL,
    PRIMARY KEY (evaluation_id, file_ref_id)
);
CREATE INDEX policy_status_policy ON policy_status(policy_id, status, file_ref_id);

CREATE TABLE policy_rollup (
    evaluation_id TEXT NOT NULL REFERENCES policy_evaluations(evaluation_id),
    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
    policy_version INTEGER NOT NULL,
    evaluated_event_seq INTEGER NOT NULL,
    evaluated_policy_input_seq INTEGER NOT NULL,
    evaluated_time_utc_ms INTEGER NOT NULL,
    files_total INTEGER NOT NULL,
    files_satisfied INTEGER NOT NULL,
    files_violated INTEGER NOT NULL,
    files_uncertain INTEGER NOT NULL,
    files_size_unknown INTEGER NOT NULL,
    bytes_known_total INTEGER NOT NULL,
    bytes_known_at_risk INTEGER NOT NULL,
    PRIMARY KEY (evaluation_id, policy_id)
);

CREATE TABLE checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    created_time_utc_ms INTEGER NOT NULL,
    stream_id TEXT NOT NULL,
    event_first_seq INTEGER NOT NULL,
    event_last_seq INTEGER NOT NULL,
    event_last_hash TEXT NOT NULL,
    local_git_commit TEXT,
    manifest_path TEXT NOT NULL,
    created_event_id TEXT NOT NULL,
    commit_observed_event_id TEXT,
    commit_observed_time_utc_ms INTEGER,
    verification_status TEXT NOT NULL,
    last_verified_time_utc_ms INTEGER
);

CREATE TABLE metadata_destinations (
    destination_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    git_remote_name TEXT NOT NULL,
    remote_locator TEXT NOT NULL,
    remote_ref TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    last_event_id TEXT NOT NULL
);

CREATE TABLE checkpoint_replications (
    checkpoint_id TEXT NOT NULL REFERENCES checkpoints(checkpoint_id),
    destination_id TEXT NOT NULL REFERENCES metadata_destinations(destination_id),
    status TEXT NOT NULL CHECK (status IN ('present', 'missing', 'diverged', 'error')),
    observed_git_commit TEXT,
    observed_event_last_seq INTEGER,
    observed_event_last_hash TEXT,
    observed_time_utc_ms INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    independence_status TEXT NOT NULL CHECK (independence_status IN ('independent', 'overlapping', 'unknown')),
    independence_reason_json TEXT NOT NULL,
    error_code TEXT,
    error_detail TEXT,
    PRIMARY KEY (checkpoint_id, destination_id)
);

CREATE TABLE annex_imports (
    import_id TEXT PRIMARY KEY,
    job_id TEXT,
    repo_path_bytes BLOB NOT NULL,
    repo_path_encoding TEXT NOT NULL,
    repo_path_display TEXT NOT NULL,
    collection_id TEXT NOT NULL REFERENCES collections(collection_id),
    worktree_location_id TEXT NOT NULL REFERENCES locations(location_id),
    cas_location_id TEXT NOT NULL REFERENCES locations(location_id),
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    archive_root_id TEXT NOT NULL REFERENCES archive_roots(archive_root_id),
    annex_uuid TEXT,
    git_head_commit TEXT,
    status TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    started_event_id TEXT NOT NULL,
    completed_event_id TEXT
);

CREATE TABLE annex_remotes (
    source_annex_uuid TEXT NOT NULL,
    remote_annex_uuid TEXT NOT NULL,
    display_name TEXT,
    location_id TEXT REFERENCES locations(location_id),
    last_observed_event_id TEXT NOT NULL,
    PRIMARY KEY (source_annex_uuid, remote_annex_uuid)
);
