//! Compact SQLite projection rebuilt from the unchanged version 2 event tree.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;

use crate::genesis::V2_SQLITE_SCHEMA_VERSION;
use crate::registry::{
    registry_path_bytes, ArchiveRootSnapshot, CollectionSnapshot, DeviceCheckIn, DeviceMount,
    DeviceSnapshot, LocationSnapshot, PolicySnapshot, RiskAssignment, RiskDomainSnapshot,
    SiteSnapshot,
};
use crate::v2_event::V2RecordKind;
use crate::v2_store::{
    V2OriginCursor, V2OriginStore, V2StoreError, V2VerificationContext, VerifiedV2Archive,
    VerifiedV2Client, VerifiedV2Record,
};

#[path = "compact_projection.rs"]
mod compact;

// Physical domain storage and logical read models are classified separately by fsck.
pub(crate) const COMPACT_TABLES: &[&str] = &[
    "content_objects",
    "checksums",
    "content_checksums",
    "source_identities",
    "annex_sources",
    "source_availability",
    "file_objects",
    "file_locations",
    "copy_bindings",
    "checks",
    "check_errors",
];
pub(crate) const COMPACT_VIEWS: &[&str] = &[
    "objects",
    "object_hashes",
    "external_identities",
    "external_availability",
    "file_refs",
    "path_observations",
    "copy_claims",
    "file_checks",
];

const CONTROL_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE archive_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE records (
    id INTEGER PRIMARY KEY,
    origin_id TEXT NOT NULL,
    origin_seq INTEGER NOT NULL CHECK (origin_seq > 0),
    record_id TEXT NOT NULL UNIQUE,
    record_kind TEXT NOT NULL,
    record_time_utc_ms INTEGER NOT NULL CHECK (record_time_utc_ms >= 0),
    batch_id TEXT NOT NULL,
    causal_frontier_hash TEXT NOT NULL,
    segment_manifest_hash TEXT NOT NULL,
    previous_record_hash TEXT,
    record_hash TEXT NOT NULL,
    payload_json TEXT,
    UNIQUE (origin_id, origin_seq)
) STRICT;
CREATE INDEX records_kind_time ON records(record_kind, record_time_utc_ms);
CREATE INDEX records_batch_dot ON records(batch_id, origin_id, origin_seq);
CREATE TABLE projection_origins (
    origin_id TEXT PRIMARY KEY,
    applied_seq INTEGER NOT NULL CHECK (applied_seq >= 0),
    applied_record_hash TEXT,
    applied_segment_manifest_hash TEXT,
    updated_time_utc_ms INTEGER NOT NULL CHECK (updated_time_utc_ms >= 0)
) STRICT;
CREATE TABLE clients (
    client_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key BLOB NOT NULL UNIQUE,
    capabilities_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('enrolled', 'revoked')),
    approved_record_id TEXT NOT NULL,
    approved_origin_id TEXT NOT NULL,
    approved_origin_seq INTEGER NOT NULL CHECK (approved_origin_seq > 0),
    revoked_record_id TEXT
) STRICT;
CREATE TABLE batch_runs (
    batch_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL REFERENCES clients(client_id),
    operation_kind TEXT NOT NULL,
    item_schema_version INTEGER NOT NULL CHECK (item_schema_version > 0),
    causal_frontier_hash TEXT NOT NULL,
    context_json TEXT NOT NULL,
    defaults_json TEXT NOT NULL,
    start_seq INTEGER NOT NULL CHECK (start_seq > 0),
    last_chunk_seq INTEGER,
    complete_seq INTEGER,
    item_count INTEGER NOT NULL DEFAULT 0 CHECK (item_count >= 0),
    item_digest TEXT,
    state TEXT NOT NULL CHECK (state IN ('running', 'complete', 'invalid')),
    negative_publication_state TEXT NOT NULL CHECK (negative_publication_state IN ('none', 'pending', 'published'))
) STRICT;
CREATE TABLE coordination_tokens (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    token_id TEXT NOT NULL,
    holder_client_id TEXT NOT NULL REFERENCES clients(client_id),
    base_frontier_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('acquired', 'renewed', 'released', 'broken')),
    not_before_utc_ms INTEGER NOT NULL,
    not_after_utc_ms INTEGER NOT NULL,
    last_record_id TEXT NOT NULL,
    PRIMARY KEY (scope_kind, scope_id)
) STRICT;
CREATE TABLE fact_conflicts (
    conflict_id TEXT PRIMARY KEY,
    fact_kind TEXT NOT NULL,
    entity_key BLOB NOT NULL,
    left_origin_id TEXT NOT NULL,
    left_origin_seq INTEGER NOT NULL CHECK (left_origin_seq > 0),
    left_record_id TEXT NOT NULL,
    right_origin_id TEXT NOT NULL,
    right_origin_seq INTEGER NOT NULL CHECK (right_origin_seq > 0),
    right_record_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('unresolved', 'resolved')),
    resolved_record_id TEXT,
    UNIQUE (fact_kind, entity_key, left_origin_id, left_origin_seq, right_origin_id, right_origin_seq)
) STRICT;
CREATE TABLE sites (
    site_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    site_kind TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    last_record_id TEXT NOT NULL
) STRICT;
CREATE INDEX sites_status_name ON sites(status, display_name, site_id);
CREATE TABLE policies (
    policy_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    requirements_json TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    last_record_id TEXT NOT NULL
) STRICT;
CREATE INDEX policies_status_name ON policies(status, display_name, policy_id);
CREATE TABLE collections (
    id INTEGER PRIMARY KEY,
    collection_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    home_site_id TEXT REFERENCES sites(site_id),
    policy_id TEXT REFERENCES policies(policy_id),
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    last_record_id TEXT NOT NULL
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
    last_checkin_record_id TEXT,
    last_checkin_time_utc_ms INTEGER,
    last_fingerprint_match_time_utc_ms INTEGER,
    last_fingerprint_status TEXT,
    last_record_id TEXT NOT NULL
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
    moved_record_id TEXT NOT NULL,
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
    created_record_id TEXT NOT NULL,
    last_seen_record_id TEXT,
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
    id INTEGER PRIMARY KEY,
    location_id TEXT NOT NULL UNIQUE,
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
    created_record_id TEXT NOT NULL,
    last_record_id TEXT NOT NULL,
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
    observed_time_utc_ms INTEGER NOT NULL,
    observed_record_id TEXT NOT NULL
) STRICT;
CREATE INDEX device_mounts_root_time ON device_mounts(archive_root_id, observed_time_utc_ms);
CREATE INDEX device_mounts_device_time ON device_mounts(device_id, observed_time_utc_ms);
CREATE TABLE risk_domains (
    risk_domain_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    risk_kind TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    last_record_id TEXT NOT NULL
) STRICT;
CREATE INDEX risk_domains_status_name ON risk_domains(status, display_name, risk_domain_id);
CREATE TABLE entity_risk_domains (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('location', 'archive_root', 'device', 'site')),
    entity_id TEXT NOT NULL,
    risk_domain_id TEXT NOT NULL REFERENCES risk_domains(risk_domain_id),
    assigned_record_id TEXT NOT NULL,
    PRIMARY KEY (entity_type, entity_id, risk_domain_id)
) STRICT;
CREATE TABLE scan_runs (
    scan_id TEXT PRIMARY KEY,
    job_id TEXT,
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    collection_id TEXT NOT NULL REFERENCES collections(collection_id),
    logical_prefix_bytes BLOB,
    logical_prefix_encoding TEXT,
    logical_prefix_display TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed', 'cancelled')),
    scan_mode TEXT NOT NULL CHECK (scan_mode IN ('add', 'complete')),
    started_time_utc_ms INTEGER NOT NULL,
    causal_frontier_hash TEXT NOT NULL,
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
    started_record_id TEXT NOT NULL,
    finished_record_id TEXT
) STRICT;
CREATE INDEX scan_runs_location_finished ON scan_runs(location_id, finished_time_utc_ms);
CREATE INDEX scan_runs_status ON scan_runs(status);
CREATE UNIQUE INDEX scan_runs_one_running_scope ON scan_runs(location_id, collection_id, scope_json) WHERE status = 'running';
CREATE TABLE scan_missing_candidates (
    candidate_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    origin_seq INTEGER NOT NULL,
    record_id TEXT NOT NULL,
    item_index INTEGER NOT NULL,
    record_hash TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
    candidate_kind TEXT NOT NULL CHECK (candidate_kind IN ('path', 'copy')),
    file_ref_id TEXT REFERENCES file_objects(canonical_id),
    copy_claim_id TEXT REFERENCES copy_bindings(canonical_id),
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    path_bytes BLOB NOT NULL,
    path_encoding TEXT NOT NULL,
    activated INTEGER NOT NULL DEFAULT 0 CHECK (activated IN (0, 1)),
    UNIQUE (origin_id, origin_seq, item_index)
) STRICT;
CREATE INDEX scan_candidates_scan_dot ON scan_missing_candidates(scan_id, origin_id, origin_seq, item_index);
CREATE INDEX scan_candidates_file_ref ON scan_missing_candidates(file_ref_id) WHERE file_ref_id IS NOT NULL;
CREATE INDEX scan_candidates_copy_claim ON scan_missing_candidates(copy_claim_id) WHERE copy_claim_id IS NOT NULL;
CREATE TABLE scan_pending_completions (
    scan_id TEXT PRIMARY KEY REFERENCES scan_runs(scan_id),
    batch_id TEXT NOT NULL,
    desired_status TEXT NOT NULL CHECK (desired_status IN ('complete', 'partial', 'failed', 'cancelled')),
    finished_time_utc_ms INTEGER NOT NULL,
    summary_json TEXT NOT NULL,
    finished_record_id TEXT NOT NULL
) STRICT;
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
) STRICT;
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
) STRICT;
CREATE INDEX job_items_job_status ON job_items(job_id, status);
CREATE TABLE operation_outcomes (
    operation_key TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    item_index INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
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
    status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed')),
    summary_json TEXT NOT NULL,
    started_record_id TEXT NOT NULL,
    completed_record_id TEXT
) STRICT;
CREATE INDEX annex_imports_location ON annex_imports(worktree_location_id, collection_id, status);
CREATE TABLE annex_remotes (
    source_annex_uuid TEXT NOT NULL,
    remote_annex_uuid TEXT NOT NULL,
    display_name TEXT,
    location_id TEXT REFERENCES locations(location_id),
    last_observed_record_id TEXT NOT NULL,
    PRIMARY KEY (source_annex_uuid, remote_annex_uuid)
) STRICT;
"#;

pub type Result<T> = std::result::Result<T, V2ProjectionError>;

#[derive(Debug, Error)]
pub enum V2ProjectionError {
    #[error("{source}; {context}")]
    Context {
        context: String,
        #[source]
        source: Box<V2ProjectionError>,
    },
    #[error("version 2 event verification failed: {0}")]
    Store(#[from] V2StoreError),
    #[error("SQLite projection is invalid: {0}")]
    Invalid(String),
    #[error("SQLite operation failed for {path}: {source}{}", sqlite_error_details(.source))]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("projection filesystem operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("projection JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl V2ProjectionError {
    fn context(self, context: impl Into<String>) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(self),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Context { source, .. } => source.code(),
            Self::Store(error) => error.code(),
            Self::Sqlite { .. } => "v2_projection_sqlite",
            Self::Io { .. } => "v2_projection_io",
            Self::Json(_) | Self::Invalid(_) => "v2_projection_invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2ProjectionStatus {
    pub version: u32,
    pub archive_id: String,
    pub archive_name: String,
    pub schema_version: u32,
    pub event_tree_version: u32,
    pub genesis_hash: String,
    pub accepted_frontier_hash: String,
    pub applied_frontier_hash: String,
    pub item_projection_version: u32,
    pub projection_generation: u64,
    pub policy_input_generation: u64,
    pub records: u64,
    pub origins: u64,
    pub collections: u64,
    pub unresolved_conflicts: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2RebuildStats {
    pub version: u32,
    pub archive_id: String,
    pub records_applied: u64,
    pub origins_applied: u64,
    pub applied_frontier_hash: String,
    /// Previous projection retained when upgrading its physical schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_database: Option<PathBuf>,
}

/// Ephemeral replay progress. Record counts advance only after a transaction commits.
/// Scan-finalization row counts explicitly describe work inside that transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2ApplyProgress {
    Verifying,
    Applying {
        records_applied: u64,
        total_records: u64,
    },
    /// Work within the current transaction; these rows are not committed yet.
    ScanFinalization {
        phase: &'static str,
        processed: u64,
    },
    Finalizing,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2ApplyStats {
    pub version: u32,
    pub archive_id: String,
    pub records_applied: u64,
    pub origins_advanced: u64,
    pub caught_up: bool,
    pub applied_frontier_hash: String,
}

// Stream records into bounded durable groups; do not buffer canonical input.
const REPLAY_RECORDS_PER_TRANSACTION: usize = 256;

fn configure_replay(connection: &Connection, path: &Path) -> Result<()> {
    // Bound SQLite's page-cache target rather than retaining event rows.
    connection
        .execute_batch("PRAGMA cache_size = -131072;")
        .map_err(|source| sqlite_error(path, source))?;
    connection.set_prepared_statement_cache_capacity(32);
    Ok(())
}

// Retain uniqueness constraints and the complete-scan replay lookups.
// These report indexes are rebuilt in bulk before the replacement is validated.
const DEFERRED_REBUILD_INDEXES: &[&str] = &[
    "records_kind_time",
    "records_batch_dot",
    "sites_status_name",
    "policies_status_name",
    "collections_status_name",
    "devices_status_name",
    "archive_roots_status_name",
    "locations_status_name",
    "locations_device",
    "locations_site",
    "locations_root",
    "device_mounts_root_time",
    "device_mounts_device_time",
    "risk_domains_status_name",
    "scan_runs_location_finished",
    "scan_runs_status",
    "scan_candidates_copy_claim",
    "job_items_job_status",
    "annex_imports_location",
];

fn defer_rebuild_indexes(connection: &Connection, path: &Path) -> Result<Vec<String>> {
    let mut definitions = Vec::with_capacity(DEFERRED_REBUILD_INDEXES.len());
    for name in DEFERRED_REBUILD_INDEXES
        .iter()
        .chain(compact::DEFERRED_INDEXES)
    {
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?1 AND sql LIKE 'CREATE INDEX %'",
            [name], |row| row.get(0),
        ).map_err(|source| sqlite_error(path, source))?;
        connection
            .execute_batch(&format!("DROP INDEX {name};"))
            .map_err(|source| sqlite_error(path, source))?;
        definitions.push(sql);
    }
    Ok(definitions)
}

#[derive(Debug)]
pub struct V2ProjectionDb {
    path: PathBuf,
}

impl V2ProjectionDb {
    pub fn create_from_store(
        store: &V2OriginStore,
        path: impl AsRef<Path>,
    ) -> Result<V2RebuildStats> {
        let path = path.as_ref();
        let verified = store.verify_compact()?;
        if path.exists() {
            return Err(V2ProjectionError::Invalid(format!(
                "projection target already exists: {}",
                path.display()
            )));
        }
        let parent = path.parent().ok_or_else(|| {
            V2ProjectionError::Invalid(format!("{} has no parent directory", path.display()))
        })?;
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        let mut connection = Connection::open(path).map_err(|source| sqlite_error(path, source))?;
        configure_replay(&connection, path)?;
        connection
            .execute_batch(&format!("{CONTROL_SCHEMA}\n{}", compact::SCHEMA))
            .map_err(|source| sqlite_error(path, source))?;
        let deferred_indexes = defer_rebuild_indexes(&connection, path)?;
        let bootstrap_hash = verified
            .frontiers
            .iter()
            .find_map(|(hash, frontier)| frontier.previous_frontiers.is_empty().then_some(hash))
            .ok_or_else(|| {
                V2ProjectionError::Invalid("canonical frontier graph lacks bootstrap".to_owned())
            })?
            .clone();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(path, source))?;
        let init_chunk = verified
            .records
            .iter()
            .find(|record| {
                record.record.envelope.record_kind == V2RecordKind::BatchChunk
                    && record
                        .record
                        .envelope
                        .payload
                        .get("items")
                        .and_then(Value::as_array)
                        .is_some_and(|items| {
                            items.iter().any(|item| {
                                item.get("kind").and_then(Value::as_str)
                                    == Some("archive_initialized")
                            })
                        })
            })
            .ok_or_else(|| {
                V2ProjectionError::Invalid(
                    "canonical initialization batch is missing archive_initialized".to_owned(),
                )
            })?;
        let public_key = STANDARD_NO_PAD
            .decode(&verified.genesis.body.initial_public_key)
            .map_err(|_| V2ProjectionError::Invalid("genesis public key is invalid".to_owned()))?;
        transaction
            .execute(
                "INSERT INTO clients(client_id, display_name, public_key, capabilities_json, status, approved_record_id, approved_origin_id, approved_origin_seq, revoked_record_id)
                 VALUES (?1, ?2, ?3, ?4, 'enrolled', ?5, ?6, ?7, NULL)",
                params![
                    verified.genesis.body.initial_client_id,
                    "Initial client",
                    public_key,
                    "[\"additive_observation\",\"coordination\"]",
                    init_chunk.record.envelope.record_id,
                    init_chunk.record.envelope.origin_id,
                    sql_i64(
                        init_chunk.record.envelope.origin_seq,
                        "approval origin sequence",
                    )?,
                ],
            )
            .map_err(|source| sqlite_error(path, source))?;
        for (key, value) in [
            ("archive_id", verified.genesis.body.archive_id.clone()),
            (
                "archive_display_name",
                verified.genesis.body.archive_display_name.clone(),
            ),
            ("schema_version", V2_SQLITE_SCHEMA_VERSION.to_string()),
            ("event_tree_version", "2".to_owned()),
            ("genesis_hash", verified.genesis_hash.clone()),
            ("accepted_frontier_hash", bootstrap_hash.clone()),
            ("applied_frontier_hash", bootstrap_hash),
            (
                "item_projection_version",
                verified
                    .accepted_frontier
                    .item_projection_version
                    .to_string(),
            ),
            ("projection_generation", "0".to_owned()),
            ("policy_input_generation", "0".to_owned()),
            ("last_verified_checkpoint_id", String::new()),
            ("last_verified_checkpoint_frontier_hash", String::new()),
            ("catalog_location_id", String::new()),
        ] {
            transaction
                .execute(
                    "INSERT INTO archive_meta(key, value) VALUES (?1, ?2)",
                    params![key, value],
                )
                .map_err(|source| sqlite_error(path, source))?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(path, source))?;
        drop(connection);
        // The unpublished database keeps user_version = 0 until every index
        // and validation is complete. Public open_existing must reject partial
        // constructor output, including a file left behind by an error/crash.
        let database = Self {
            path: path.to_path_buf(),
        };
        let applied = database
            .apply(store)
            .map_err(|error| error.context("rebuild phase=replay"))?;
        let mut connection = database.open()?;
        configure_replay(&connection, path)?;
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(path, source))?;
        for definition in deferred_indexes {
            transaction.execute_batch(&definition).map_err(|source| {
                sqlite_operation_error(&transaction, path, &definition, source)
                    .context("rebuild phase=indexes")
            })?;
        }
        transaction.commit().map_err(|source| {
            sqlite_operation_error(&connection, path, "COMMIT", source)
                .context("rebuild phase=index commit")
        })?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;")
            .map_err(|source| {
                sqlite_operation_error(
                    &connection,
                    path,
                    "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;",
                    source,
                )
                .context("rebuild phase=optimize")
            })?;
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|source| {
                sqlite_operation_error(&connection, path, "PRAGMA integrity_check", source)
                    .context("rebuild phase=integrity check")
            })?;
        if integrity != "ok" {
            return Err(V2ProjectionError::Invalid(format!(
                "SQLite integrity_check failed: {integrity}"
            )));
        }
        let foreign_key_violation = connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(|source| sqlite_error(path, source))?
            .query_row([], |_| Ok(()))
            .optional()
            .map_err(|source| sqlite_error(path, source))?;
        if foreign_key_violation.is_some() {
            return Err(V2ProjectionError::Invalid(
                "SQLite foreign_key_check failed".to_owned(),
            ));
        }
        drop(connection);
        database.validate_against_verified(&verified)?;
        let stats = V2RebuildStats {
            version: 2,
            archive_id: verified.genesis.body.archive_id,
            records_applied: applied.records_applied,
            origins_applied: u64::try_from(verified.accepted_frontier.origins.len())
                .map_err(|_| V2ProjectionError::Invalid("origin count overflow".to_owned()))?,
            applied_frontier_hash: verified.accepted_frontier_hash,
            previous_database: None,
        };
        // Set the completion marker with the ordinary durable connection only
        // after successful replay, index creation, and integrity verification.
        database
            .open()?
            .pragma_update(None, "user_version", V2_SQLITE_SCHEMA_VERSION)
            .map_err(|source| sqlite_error(path, source))?;
        Ok(stats)
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(V2ProjectionError::Invalid(format!(
                "SQLite projection not found at {}",
                path.display()
            )));
        }
        let database = Self { path };
        database.validate_schema()?;
        Ok(database)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn status(&self) -> Result<V2ProjectionStatus> {
        let connection = self.open()?;
        let schema_version = u32_meta(&connection, &self.path, "schema_version")?;
        let event_tree_version = u32_meta(&connection, &self.path, "event_tree_version")?;
        let status = V2ProjectionStatus {
            version: 2,
            archive_id: meta(&connection, &self.path, "archive_id")?,
            archive_name: meta(&connection, &self.path, "archive_display_name")?,
            schema_version,
            event_tree_version,
            genesis_hash: meta(&connection, &self.path, "genesis_hash")?,
            accepted_frontier_hash: meta(&connection, &self.path, "accepted_frontier_hash")?,
            applied_frontier_hash: meta(&connection, &self.path, "applied_frontier_hash")?,
            item_projection_version: u32_meta(&connection, &self.path, "item_projection_version")?,
            projection_generation: u64_meta(&connection, &self.path, "projection_generation")?,
            policy_input_generation: u64_meta(&connection, &self.path, "policy_input_generation")?,
            records: count(&connection, &self.path, "records", None)?,
            origins: count(&connection, &self.path, "projection_origins", None)?,
            collections: count(
                &connection,
                &self.path,
                "collections",
                Some("status = 'active'"),
            )?,
            unresolved_conflicts: count(
                &connection,
                &self.path,
                "fact_conflicts",
                Some("state = 'unresolved'"),
            )?,
        };
        if status.schema_version != V2_SQLITE_SCHEMA_VERSION || status.event_tree_version != 2 {
            return Err(V2ProjectionError::Invalid(format!(
                "unsupported SQLite projection format {}/{}; expected event tree 2 and schema {V2_SQLITE_SCHEMA_VERSION}",
                status.event_tree_version, status.schema_version
            )));
        }
        if status.accepted_frontier_hash != status.applied_frontier_hash {
            return Err(V2ProjectionError::Invalid(
                "SQLite projection has an unapplied accepted frontier".to_owned(),
            ));
        }
        Ok(status)
    }

    /// Applies only canonical records beyond each persisted origin cursor.
    /// Transactions stream up to 256 records; a crash rolls back only the current
    /// group. Already committed records, including old per-record imports, are
    /// recognized when revisiting an incomplete batch.
    pub fn apply(&self, store: &V2OriginStore) -> Result<V2ApplyStats> {
        self.apply_with_progress(store, None)
    }

    /// Applies canonical records with notifications after durable replay commits.
    /// Counts include records revisited when resuming a partially applied batch.
    pub fn apply_with_progress(
        &self,
        store: &V2OriginStore,
        mut progress: Option<&mut dyn FnMut(V2ApplyProgress)>,
    ) -> Result<V2ApplyStats> {
        if let Some(report) = progress.as_mut() {
            report(V2ApplyProgress::Verifying);
        }
        let mut connection = self.open()?;
        configure_replay(&connection, &self.path)?;
        let applied_frontier_hash = meta(&connection, &self.path, "applied_frontier_hash")?;
        let stored_cursors = connection
            .prepare("SELECT origin_id, applied_seq, applied_record_hash, applied_segment_manifest_hash FROM projection_origins ORDER BY origin_id")
            .map_err(|source| sqlite_error(&self.path, source))?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(|source| sqlite_error(&self.path, source))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let mut verification_cursors = BTreeMap::new();
        let mut cursors = BTreeMap::new();
        for (origin_id, applied_seq, record_hash, manifest_hash) in stored_cursors {
            let sequence = sql_u64(applied_seq, "projection origin sequence")?;
            verification_cursors.insert(
                origin_id.clone(),
                V2OriginCursor {
                    applied_seq: sequence,
                    applied_record_hash: record_hash,
                    applied_segment_manifest_hash: manifest_hash,
                },
            );
            cursors.insert(origin_id, applied_seq);
        }
        let stored_clients = connection
            .prepare(
                "SELECT c.client_id, c.display_name, c.public_key, c.capabilities_json, c.status,
                        c.approved_origin_id, c.approved_origin_seq, c.revoked_record_id,
                        r.origin_id, r.origin_seq
                 FROM clients c
                 LEFT JOIN records r ON r.record_id = c.revoked_record_id
                 ORDER BY c.client_id",
            )
            .map_err(|source| sqlite_error(&self.path, source))?
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                ))
            })
            .map_err(|source| sqlite_error(&self.path, source))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, source))?;
        let mut trusted_clients = BTreeMap::new();
        for row in stored_clients {
            let public_key: [u8; 32] = row.2.try_into().map_err(|_| {
                V2ProjectionError::Invalid(format!(
                    "stored client {} public key has the wrong length",
                    row.0
                ))
            })?;
            let revoked = row.4 == "revoked" || row.7.is_some();
            let revoked_origin_seq = row
                .9
                .map(|sequence| sql_u64(sequence, "client revocation sequence"))
                .transpose()?;
            if revoked && (row.8.is_none() || revoked_origin_seq.is_none()) {
                return Err(V2ProjectionError::Invalid(format!(
                    "stored client {} revocation record is missing",
                    row.0
                )));
            }
            trusted_clients.insert(
                row.0.clone(),
                VerifiedV2Client {
                    client_id: row.0,
                    display_name: row.1,
                    public_key,
                    capabilities: serde_json::from_str(&row.3)?,
                    approved_origin_id: row.5,
                    approved_origin_seq: sql_u64(row.6, "client approval sequence")?,
                    revoked_origin_id: row.8,
                    revoked_origin_seq,
                },
            );
        }
        let mut next_sequences = cursors.clone();
        let mut records_applied = 0_u64;
        let mut total_records = 0_u64;
        let mut advanced_origins = BTreeMap::<String, ()>::new();
        let mut validated_context = false;
        let mut pending_transaction: Option<Transaction<'_>> = None;
        let mut pending_records = 0;
        let verified = store.visit_verified_since_with_clients::<V2ProjectionError, _>(
            &applied_frontier_hash,
            &verification_cursors,
            &trusted_clients,
            |record, context| {
            let result = (|| -> Result<()> {
            if !validated_context {
                if meta(&connection, &self.path, "archive_id")?
                    != context.genesis.body.archive_id
                    || meta(&connection, &self.path, "genesis_hash")? != context.genesis_hash
                {
                    return Err(V2ProjectionError::Invalid(
                        "SQLite projection belongs to another Archive".to_owned(),
                    ));
                }
                for origin in &context.accepted_frontier.origins {
                    let applied = cursors.get(&origin.origin_id).copied().unwrap_or(0);
                    if applied < 0
                        || u64::try_from(applied)
                            .ok()
                            .is_none_or(|seq| seq > origin.seq)
                    {
                        return Err(V2ProjectionError::Invalid(format!(
                            "SQLite cursor is outside canonical origin {}",
                            origin.origin_id
                        )));
                    }
                }
                total_records = context.accepted_frontier.origins.iter().try_fold(
                    0_u64,
                    |total, origin| {
                        let applied = cursors.get(&origin.origin_id).copied().unwrap_or(0) as u64;
                        total.checked_add(origin.seq - applied).ok_or_else(|| {
                            V2ProjectionError::Invalid("replay record count overflow".to_owned())
                        })
                    },
                )?;
                connection
                    .execute(
                        "UPDATE archive_meta SET value = ?1 WHERE key = 'accepted_frontier_hash'",
                        [&context.accepted_frontier_hash],
                    )
                    .map_err(|source| sqlite_error(&self.path, source))?;
                validated_context = true;
            }
            let origin_id = &record.record.envelope.origin_id;
            let cursor = next_sequences.get(origin_id).copied().unwrap_or(0);
            let sequence = sql_i64(record.record.envelope.origin_seq, "record origin sequence")?;
            if sequence <= cursor {
                return Ok(());
            }
            if sequence != cursor + 1 {
                return Err(V2ProjectionError::Invalid(format!(
                    "canonical origin {origin_id} has a gap after SQLite sequence {cursor}"
                )));
            }
            if pending_transaction.is_none() {
                pending_transaction = Some(connection
                    .unchecked_transaction()
                    .map_err(|source| sqlite_error(&self.path, source))?);
            }
            let transaction = pending_transaction.as_ref().expect("started transaction");
            let inserted = insert_record(transaction, record, &self.path)?;
            if inserted {
                match record.record.envelope.record_kind {
                    V2RecordKind::BatchStart => {
                        project_batch_start(transaction, record, &self.path)?
                    }
                    V2RecordKind::BatchChunk => {
                        project_batch_chunk(transaction, record, context, &self.path)?
                    }
                    V2RecordKind::BatchComplete => {
                        project_batch_complete(transaction, record, &self.path, &mut |event| {
                            if let Some(report) = progress.as_mut() { report(event); }
                        })?
                    }
                }
            }
            if record.record.envelope.record_kind == V2RecordKind::BatchComplete {
                transaction.execute(
                    "INSERT INTO projection_origins(origin_id, applied_seq, applied_record_hash, applied_segment_manifest_hash, updated_time_utc_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(origin_id) DO UPDATE SET applied_seq = excluded.applied_seq, applied_record_hash = excluded.applied_record_hash, applied_segment_manifest_hash = excluded.applied_segment_manifest_hash, updated_time_utc_ms = excluded.updated_time_utc_ms",
                    params![
                        origin_id,
                        sequence,
                        record.record.record_hash,
                        record.segment_manifest_hash,
                        sql_i64(record.record.envelope.time_utc_ms, "projection update time")?,
                    ],
                ).map_err(|source| sqlite_error(&self.path, source))?;
                cursors.insert(origin_id.clone(), sequence);
                advanced_origins.insert(origin_id.clone(), ());
            }
            pending_records += 1;
            if pending_records == REPLAY_RECORDS_PER_TRANSACTION {
                pending_transaction.take().expect("pending transaction")
                    .commit()
                    .map_err(|source| sqlite_error(&self.path, source))?;
                pending_records = 0;
            }
            next_sequences.insert(origin_id.clone(), sequence);
            records_applied = records_applied.checked_add(1).ok_or_else(|| {
                V2ProjectionError::Invalid("applied record count overflow".to_owned())
            })?;
            if pending_records == 0 {
                if let Some(report) = progress.as_mut() {
                    report(V2ApplyProgress::Applying { records_applied, total_records });
                }
            }
            Ok(())
            })();
            result.map_err(|error| {
                error.context(format!(
                    "replay origin={:?} sequence={} batch={:?} kind={:?}; {}",
                    record.record.envelope.origin_id,
                    record.record.envelope.origin_seq,
                    record.record.envelope.batch_id,
                    record.record.envelope.record_kind,
                    sqlite_storage_diagnostics(&connection),
                ))
            })
        },
        )?;
        // Records remain streamed; on error RAII rolls back the pending group.
        if let Some(transaction) = pending_transaction.take() {
            transaction.commit().map_err(|source| {
                sqlite_operation_error(&connection, &self.path, "COMMIT", source)
                    .context("replay phase=final group commit")
            })?;
            if let Some(report) = progress.as_mut() {
                report(V2ApplyProgress::Applying {
                    records_applied,
                    total_records,
                });
            }
        }
        drop(pending_transaction);
        if !validated_context {
            if meta(&connection, &self.path, "archive_id")? != verified.genesis.body.archive_id
                || meta(&connection, &self.path, "genesis_hash")? != verified.genesis_hash
            {
                return Err(V2ProjectionError::Invalid(
                    "SQLite projection belongs to another Archive".to_owned(),
                ));
            }
            connection
                .execute(
                    "UPDATE archive_meta SET value = ?1 WHERE key = 'accepted_frontier_hash'",
                    [&verified.accepted_frontier_hash],
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
        }

        if let Some(report) = progress.as_mut() {
            if records_applied == 0 {
                report(V2ApplyProgress::Applying {
                    records_applied: 0,
                    total_records: 0,
                });
            }
            report(V2ApplyProgress::Finalizing);
        }
        let final_transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, source))?;
        final_transaction
            .execute(
                "UPDATE archive_meta SET value = ?1 WHERE key = 'applied_frontier_hash'",
                [&verified.accepted_frontier_hash],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if records_applied > 0 {
            final_transaction
                .execute(
                    "UPDATE archive_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'projection_generation'",
                    [],
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
        }
        final_transaction.commit().map_err(|source| {
            sqlite_operation_error(&connection, &self.path, "COMMIT", source)
                .context("replay phase=frontier commit")
        })?;
        let status = self.status()?;
        if status.accepted_frontier_hash != verified.accepted_frontier_hash {
            return Err(V2ProjectionError::Invalid(
                "SQLite did not advance to the verified accepted frontier".to_owned(),
            ));
        }
        let final_connection = self.open()?;
        for origin in &verified.accepted_frontier.origins {
            let cursor: Option<(i64, String, String)> = final_connection
                .query_row(
                    "SELECT applied_seq, applied_record_hash, applied_segment_manifest_hash FROM projection_origins WHERE origin_id = ?1",
                    [&origin.origin_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|source| sqlite_error(&self.path, source))?;
            if cursor
                != Some((
                    sql_i64(origin.seq, "origin sequence")?,
                    origin.event_hash.clone(),
                    origin.segment_manifest_hash.clone(),
                ))
            {
                return Err(V2ProjectionError::Invalid(format!(
                    "SQLite cursor did not reach canonical origin {}",
                    origin.origin_id
                )));
            }
        }
        Ok(V2ApplyStats {
            version: 2,
            archive_id: verified.genesis.body.archive_id,
            records_applied,
            origins_advanced: u64::try_from(advanced_origins.len())
                .map_err(|_| V2ProjectionError::Invalid("origin count overflow".to_owned()))?,
            caught_up: true,
            applied_frontier_hash: verified.accepted_frontier_hash,
        })
    }

    pub fn validate_against_store(&self, store: &V2OriginStore) -> Result<V2ProjectionStatus> {
        let verified = store.verify_compact()?;
        let status = self.status()?;
        if status.archive_id != verified.genesis.body.archive_id
            || status.genesis_hash != verified.genesis_hash
            || status.accepted_frontier_hash != verified.accepted_frontier_hash
            || status.records != verified.record_count
            || status.origins
                != u64::try_from(verified.accepted_frontier.origins.len())
                    .map_err(|_| V2ProjectionError::Invalid("origin count overflow".to_owned()))?
        {
            return Err(V2ProjectionError::Invalid(
                "SQLite projection does not match the verified canonical frontier".to_owned(),
            ));
        }
        let connection = self.open()?;
        for origin in &verified.accepted_frontier.origins {
            let cursor: Option<(i64, String, String)> = connection
                .query_row(
                    "SELECT applied_seq, applied_record_hash, applied_segment_manifest_hash FROM projection_origins WHERE origin_id = ?1",
                    [&origin.origin_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|source| sqlite_error(&self.path, source))?;
            if cursor
                != Some((
                    sql_i64(origin.seq, "origin sequence")?,
                    origin.event_hash.clone(),
                    origin.segment_manifest_hash.clone(),
                ))
            {
                return Err(V2ProjectionError::Invalid(format!(
                    "SQLite cursor does not match canonical origin {}",
                    origin.origin_id
                )));
            }
        }
        Ok(status)
    }

    pub fn rebuild(store: &V2OriginStore, target: impl AsRef<Path>) -> Result<V2RebuildStats> {
        let target = target.as_ref();
        let parent = target.parent().ok_or_else(|| {
            V2ProjectionError::Invalid(format!("{} has no parent directory", target.display()))
        })?;
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        let temp = parent.join(format!(".archive-ledger-rebuild-{}.db", lower_ulid()));
        let mut stats = match Self::create_from_store(store, &temp) {
            Ok(stats) => stats,
            Err(error) => {
                let _ = fs::remove_file(&temp);
                return Err(error.context(
                    "rebuild replacement creation failed; original database was not replaced",
                ));
            }
        };
        File::open(&temp)
            .and_then(|file| file.sync_all())
            .map_err(|source| io_error(&temp, source))?;

        let backup = parent.join(format!(".archive-ledger-previous-{}.db", lower_ulid()));
        let had_target = target.exists();
        let mut backup_sidecars = Vec::new();
        let mut retain_previous = false;
        if had_target {
            let existing =
                Connection::open(target).map_err(|source| sqlite_error(target, source))?;
            let old_version: u32 = existing
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(|source| sqlite_error(target, source))?;
            retain_previous = old_version != V2_SQLITE_SCHEMA_VERSION;
            existing
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|source| sqlite_error(target, source))?;
            drop(existing);
            fs::rename(target, &backup).map_err(|source| io_error(target, source))?;
            for suffix in ["-wal", "-shm"] {
                let sidecar = sqlite_sidecar(target, suffix);
                if sidecar.exists() {
                    let backup_sidecar = sqlite_sidecar(&backup, suffix);
                    if let Err(source) = fs::rename(&sidecar, &backup_sidecar) {
                        let _ = fs::rename(&backup, target);
                        for (original, moved) in &backup_sidecars {
                            let _ = fs::rename(moved, original);
                        }
                        return Err(io_error(&sidecar, source));
                    }
                    backup_sidecars.push((sidecar, backup_sidecar));
                }
            }
        }
        if let Err(source) = fs::rename(&temp, target) {
            if had_target {
                let _ = fs::rename(&backup, target);
                for (sidecar, backup_sidecar) in &backup_sidecars {
                    let _ = fs::rename(backup_sidecar, sidecar);
                }
            }
            return Err(io_error(target, source));
        }
        let installed =
            Self::open_existing(target).and_then(|database| database.validate_against_store(store));
        if let Err(error) = installed {
            let failed = parent.join(format!(".archive-ledger-failed-{}.db", lower_ulid()));
            let _ = fs::rename(target, failed);
            if had_target {
                fs::rename(&backup, target).map_err(|source| io_error(target, source))?;
                for (sidecar, backup_sidecar) in &backup_sidecars {
                    fs::rename(backup_sidecar, sidecar)
                        .map_err(|source| io_error(sidecar, source))?;
                }
            }
            return Err(error);
        }
        if had_target && retain_previous {
            stats.previous_database = Some(backup.clone());
        }
        if had_target && !retain_previous {
            fs::remove_file(&backup).map_err(|source| io_error(&backup, source))?;
            for (_, backup_sidecar) in &backup_sidecars {
                fs::remove_file(backup_sidecar)
                    .map_err(|source| io_error(backup_sidecar, source))?;
            }
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))?;
        Ok(stats)
    }

    fn validate_against_verified(&self, verified: &VerifiedV2Archive) -> Result<()> {
        let status = self.status()?;
        if status.archive_id != verified.genesis.body.archive_id
            || status.genesis_hash != verified.genesis_hash
            || status.applied_frontier_hash != verified.accepted_frontier_hash
            || status.records != verified.record_count
        {
            return Err(V2ProjectionError::Invalid(
                "newly built SQLite projection does not match canonical records".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_schema(&self) -> Result<()> {
        let connection = self.open()?;
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|source| sqlite_error(&self.path, source))?;
        if version != V2_SQLITE_SCHEMA_VERSION {
            return Err(V2ProjectionError::Invalid(format!(
                "unsupported SQLite schema {version}; expected schema {V2_SQLITE_SCHEMA_VERSION}. Run archive db rebuild to rebuild from the existing canonical records"
            )));
        }
        Ok(())
    }

    fn open(&self) -> Result<Connection> {
        let connection =
            Connection::open(&self.path).map_err(|source| sqlite_error(&self.path, source))?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok(connection)
    }
}

fn insert_record(
    transaction: &Transaction<'_>,
    record: &VerifiedV2Record,
    path: &Path,
) -> Result<bool> {
    let envelope = &record.record.envelope;
    let record_kind = match envelope.record_kind {
        V2RecordKind::BatchStart => "batch_start",
        V2RecordKind::BatchChunk => "batch_chunk",
        V2RecordKind::BatchComplete => "batch_complete",
    };
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO records(origin_id, origin_seq, record_id, record_kind, record_time_utc_ms, batch_id, causal_frontier_hash, segment_manifest_hash, previous_record_hash, record_hash, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
        params![
            envelope.origin_id,
            sql_i64(envelope.origin_seq, "record origin sequence")?,
            envelope.record_id,
            record_kind,
            sql_i64(envelope.time_utc_ms, "record time")?,
            envelope.batch_id,
            record.causal_frontier_hash,
            record.segment_manifest_hash,
            envelope.previous_record_hash,
            record.record.record_hash,
        ],
    ).map_err(|source| sqlite_error(path, source))?;
    Ok(inserted == 1)
}

fn project_batch_start(
    transaction: &Transaction<'_>,
    record: &VerifiedV2Record,
    path: &Path,
) -> Result<()> {
    let payload = object(&record.record.envelope.payload, "batch_start payload")?;
    let context = required(payload, "context")?;
    let item_schema_version = number(payload, "item_schema_version")?;
    let defaults = required(payload, "defaults")?;
    validate_projected_item_defaults(item_schema_version, defaults)?;
    project_coordination_context(transaction, context, record, path)?;
    transaction.execute(
        "INSERT INTO batch_runs(batch_id, origin_id, operation_kind, item_schema_version, causal_frontier_hash, context_json, defaults_json, start_seq, last_chunk_seq, complete_seq, item_count, item_digest, state, negative_publication_state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, 0, NULL, 'running', 'none')",
        params![
            record.record.envelope.batch_id,
            record.record.envelope.origin_id,
            string(payload, "operation_kind")?,
            sql_i64(item_schema_version, "item schema version")?,
            string(payload, "causal_frontier_hash")?,
            serde_json::to_string(context)?,
            serde_json::to_string(defaults)?,
            sql_i64(
                record.record.envelope.origin_seq,
                "batch start sequence",
            )?,
        ],
    ).map_err(|source| sqlite_error(path, source))?;
    Ok(())
}

fn project_batch_chunk(
    transaction: &Transaction<'_>,
    record: &VerifiedV2Record,
    verified: &V2VerificationContext,
    path: &Path,
) -> Result<()> {
    let payload = object(&record.record.envelope.payload, "batch_chunk payload")?;
    let first = number(payload, "first_item_index")?;
    let items = required(payload, "items")?.as_array().ok_or_else(|| {
        V2ProjectionError::Invalid("batch chunk items must be an array".to_owned())
    })?;
    let (current, item_schema_version, defaults_json): (i64, i64, String) = transaction
        .query_row(
            "SELECT item_count, item_schema_version, defaults_json
             FROM batch_runs WHERE batch_id = ?1 AND state = 'running'",
            [&record.record.envelope.batch_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|source| sqlite_error(path, source))?;
    let item_schema_version = sql_u64(item_schema_version, "batch item schema version")?;
    let defaults: Value = serde_json::from_str(&defaults_json)?;
    validate_projected_item_defaults(item_schema_version, &defaults)?;
    if sql_u64(current, "batch item count")? != first {
        return Err(V2ProjectionError::Invalid(format!(
            "batch {} chunk range is not consecutive",
            record.record.envelope.batch_id
        )));
    }
    for (offset, raw_item) in items.iter().enumerate() {
        let materialized;
        let item = if item_schema_version == 1 {
            object(raw_item, "batch item")?
        } else {
            materialized = materialize_batch_item(raw_item, &defaults)?;
            &materialized
        };
        let offset = u64::try_from(offset)
            .map_err(|_| V2ProjectionError::Invalid("batch item index overflow".to_owned()))?;
        let item_index = first
            .checked_add(offset)
            .ok_or_else(|| V2ProjectionError::Invalid("batch item index overflow".to_owned()))?;
        let kind = string(item, "kind")?;
        let result = (|| -> Result<()> {
            if item_requires_coordination(transaction, item, kind, path)? {
                require_batch_coordination(transaction, &record.record.envelope.batch_id, path)?;
            }
            match kind {
                "archive_initialized" => {
                    if string(item, "archive_id")? != verified.genesis.body.archive_id
                        || string(item, "archive_display_name")?
                            != verified.genesis.body.archive_display_name
                        || string(item, "client_id")? != verified.genesis.body.initial_client_id
                        || string(item, "public_key")? != verified.genesis.body.initial_public_key
                    {
                        return Err(V2ProjectionError::Invalid(
                            "archive_initialized item does not match genesis".to_owned(),
                        ));
                    }
                    let public_key = STANDARD_NO_PAD
                        .decode(&verified.genesis.body.initial_public_key)
                        .map_err(|_| {
                            V2ProjectionError::Invalid("genesis public key is invalid".to_owned())
                        })?;
                    transaction
                    .execute(
                        "INSERT OR IGNORE INTO clients(client_id, display_name, public_key, capabilities_json, status, approved_record_id, approved_origin_id, approved_origin_seq, revoked_record_id)
                         VALUES (?1, ?2, ?3, ?4, 'enrolled', ?5, ?6, ?7, NULL)",
                        params![
                            verified.genesis.body.initial_client_id,
                            "Initial client",
                            public_key,
                            "[\"additive_observation\",\"coordination\"]",
                            record.record.envelope.record_id,
                            record.record.envelope.origin_id,
                            sql_i64(
                                record.record.envelope.origin_seq,
                                "approval origin sequence",
                            )?,
                        ],
                    )
                    .map_err(|source| sqlite_error(path, source))?;
                }
                "archive_updated" => {
                    if string(item, "archive_id")? != verified.genesis.body.archive_id {
                        return Err(V2ProjectionError::Invalid(
                            "archive_updated item belongs to another Archive".to_owned(),
                        ));
                    }
                    let display_name = string(item, "archive_display_name")?;
                    if display_name.trim().is_empty() {
                        return Err(V2ProjectionError::Invalid(
                            "Archive display name must not be empty".to_owned(),
                        ));
                    }
                    transaction
                        .execute(
                            "UPDATE archive_meta SET value = ?1 WHERE key = 'archive_display_name'",
                            [display_name],
                        )
                        .map_err(|source| sqlite_error(path, source))?;
                }
                "client_enrolled" => {
                    project_client_enrolled(transaction, item, record, path)?;
                }
                "client_revoked" => {
                    project_client_revoked(transaction, item, record, path)?;
                }
                kind if is_registry_item(kind) => {
                    project_registry_item(transaction, item, record, path)?;
                }
                "content_observed" => {
                    compact::project_content_observed(
                        transaction,
                        item,
                        record,
                        item_index,
                        verified,
                        path,
                    )?;
                }
                "copy_verification_failed" => {
                    compact::project_copy_verification_failed(
                        transaction,
                        item,
                        record,
                        item_index,
                        path,
                    )?;
                }
                "scan_started" => project_scan_started(transaction, item, record, path)?,
                "scan_missing_candidate" => {
                    project_scan_missing_candidate(transaction, item, record, item_index, path)?;
                }
                "scan_completed" => project_scan_completed(transaction, item, record, path)?,
                "annex_import_started" => {
                    project_annex_import_started(transaction, item, record, path)?
                }
                "annex_entry_observed" => {
                    compact::project_annex_entry(transaction, item, record, item_index, path)?;
                }
                "annex_import_completed" => {
                    project_annex_import_completed(transaction, item, record, path)?
                }
                "job_started" => project_job_started(transaction, item, record, path)?,
                "job_finished" => project_job_finished(transaction, item, record, path)?,
                kind => {
                    return Err(V2ProjectionError::Invalid(format!(
                        "unsupported projection item kind {kind:?}"
                    )))
                }
            }
            project_operation_outcome(transaction, item, record, item_index, path)?;
            Ok(())
        })();
        result.map_err(|error| error.context(format!("batch item index={item_index}")))?;
    }
    let next = sql_u64(current, "batch item count")?
        .checked_add(
            u64::try_from(items.len())
                .map_err(|_| V2ProjectionError::Invalid("batch item count overflow".to_owned()))?,
        )
        .ok_or_else(|| V2ProjectionError::Invalid("batch item count overflow".to_owned()))?;
    transaction
        .execute(
            "UPDATE batch_runs SET last_chunk_seq = ?2, item_count = ?3 WHERE batch_id = ?1",
            params![
                record.record.envelope.batch_id,
                sql_i64(record.record.envelope.origin_seq, "batch chunk sequence",)?,
                sql_i64(next, "batch item count")?
            ],
        )
        .map_err(|source| sqlite_error(path, source))?;
    Ok(())
}

fn project_coordination_context(
    transaction: &Transaction<'_>,
    context: &Value,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let Some(coordination) = context
        .as_object()
        .and_then(|context| context.get("coordination"))
    else {
        return Ok(());
    };
    let coordination = object(coordination, "coordination context")?;
    let scope_kind = string(coordination, "scope_kind")?;
    let scope_id = string(coordination, "scope_id")?;
    let token_id = string(coordination, "token_id")?;
    let holder = string(coordination, "holder_client_id")?;
    let base = string(coordination, "base_frontier_hash")?;
    let not_before = number(coordination, "not_before_utc_ms")?;
    let not_after = number(coordination, "not_after_utc_ms")?;
    if scope_kind != "archive"
        || holder != record.record.envelope.origin_id
        || base != record.causal_frontier_hash
        || not_before > not_after
        || record.record.envelope.time_utc_ms < not_before
        || record.record.envelope.time_utc_ms > not_after
        || coordination.get("lease_proof").is_none()
    {
        return Err(V2ProjectionError::Invalid(
            "batch coordination context is inconsistent".to_owned(),
        ));
    }
    transaction
        .execute(
            "INSERT INTO coordination_tokens(scope_kind, scope_id, token_id, holder_client_id,
                 base_frontier_hash, state, not_before_utc_ms, not_after_utc_ms, last_record_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'acquired', ?6, ?7, ?8)
             ON CONFLICT(scope_kind, scope_id) DO UPDATE SET
                 token_id = excluded.token_id,
                 holder_client_id = excluded.holder_client_id,
                 base_frontier_hash = excluded.base_frontier_hash,
                 state = excluded.state,
                 not_before_utc_ms = excluded.not_before_utc_ms,
                 not_after_utc_ms = excluded.not_after_utc_ms,
                 last_record_id = excluded.last_record_id",
            params![
                scope_kind,
                scope_id,
                token_id,
                holder,
                base,
                sql_i64(not_before, "coordination not-before time")?,
                sql_i64(not_after, "coordination not-after time")?,
                record.record.envelope.record_id,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn item_requires_coordination(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    kind: &str,
    database_path: &Path,
) -> Result<bool> {
    let complete_scan = if kind == "scan_completed" {
        let scan_id = string(item, "scan_id")?;
        transaction
            .query_row(
                "SELECT scan_mode = 'complete' FROM scan_runs WHERE scan_id = ?1",
                [scan_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|source| sqlite_error(database_path, source))?
    } else {
        false
    };
    let protected = kind == "archive_updated"
        || kind == "client_revoked"
        || complete_scan
        || (is_registry_item(kind)
            && !matches!(kind, "device_checked_in" | "device_mount_observed"));
    if !protected && kind != "client_enrolled" {
        return Ok(false);
    }
    let client_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM clients", [], |row| row.get(0))
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(client_count > 1)
}

fn require_batch_coordination(
    transaction: &Transaction<'_>,
    batch_id: &str,
    database_path: &Path,
) -> Result<()> {
    let context_json: String = transaction
        .query_row(
            "SELECT context_json FROM batch_runs WHERE batch_id = ?1",
            [batch_id],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    let context: Value = serde_json::from_str(&context_json)?;
    if context
        .as_object()
        .and_then(|context| context.get("coordination"))
        .is_none()
    {
        return Err(V2ProjectionError::Invalid(
            "this multi-client coordination change lacks a scoped remote lease".to_owned(),
        ));
    }
    Ok(())
}

fn project_job_started(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let job_id = string(item, "job_id")?;
    let job_type = string(item, "job_type")?;
    let input_version = string(item, "input_version")?;
    let params_json = serde_json::to_string(required(item, "params")?)?;
    let started = sql_i64(record.record.envelope.time_utc_ms, "job start time")?;
    transaction
        .execute(
            "INSERT INTO jobs(job_id, job_type, status, created_time_utc_ms, started_time_utc_ms, finished_time_utc_ms, actor_id, host_id, params_json, progress_json, input_version)
             VALUES (?1, ?2, 'running', ?3, ?3, NULL, ?4, ?5, ?6, NULL, ?7)
             ON CONFLICT(job_id) DO UPDATE SET
                 status = CASE WHEN jobs.status = 'complete' THEN jobs.status ELSE 'running' END,
                 started_time_utc_ms = COALESCE(jobs.started_time_utc_ms, excluded.started_time_utc_ms)",
            params![
                job_id,
                job_type,
                started,
                item.get("actor_id").and_then(Value::as_str),
                item.get("host_id").and_then(Value::as_str),
                params_json,
                input_version,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    let actual: (String, String) = transaction
        .query_row(
            "SELECT job_type, input_version FROM jobs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    if actual != (job_type.to_owned(), input_version.to_owned()) {
        return Err(V2ProjectionError::Invalid(format!(
            "job {job_id} was reused with different immutable inputs"
        )));
    }
    Ok(())
}

fn project_client_enrolled(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let approver_status: Option<String> = transaction
        .query_row(
            "SELECT status FROM clients WHERE client_id = ?1",
            [&record.record.envelope.origin_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(database_path, source))?;
    if approver_status.as_deref() != Some("enrolled") {
        return Err(V2ProjectionError::Invalid(format!(
            "client enrollment was not approved by an enrolled origin {}",
            record.record.envelope.origin_id
        )));
    }
    let client_id = string(item, "client_id")?;
    let display_name = string(item, "display_name")?;
    if display_name.trim().is_empty() {
        return Err(V2ProjectionError::Invalid(
            "client display name is empty".to_owned(),
        ));
    }
    let public_key = STANDARD_NO_PAD
        .decode(string(item, "public_key")?)
        .map_err(|_| V2ProjectionError::Invalid("client public key is not base64".to_owned()))?;
    let public_key_array: [u8; 32] = public_key.clone().try_into().map_err(|_| {
        V2ProjectionError::Invalid("client public key has the wrong length".to_owned())
    })?;
    VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| V2ProjectionError::Invalid("client public key is invalid".to_owned()))?;
    if crate::genesis::client_id(&public_key_array) != client_id {
        return Err(V2ProjectionError::Invalid(
            "client ID does not match its public key".to_owned(),
        ));
    }
    let capabilities = required(item, "capabilities")?.as_array().ok_or_else(|| {
        V2ProjectionError::Invalid("client capabilities are not an array".to_owned())
    })?;
    if capabilities.is_empty() || capabilities.iter().any(|value| !value.is_string()) {
        return Err(V2ProjectionError::Invalid(
            "client capabilities must contain strings".to_owned(),
        ));
    }
    transaction
        .execute(
            "INSERT INTO clients(client_id, display_name, public_key, capabilities_json, status, approved_record_id, approved_origin_id, approved_origin_seq, revoked_record_id)
             VALUES (?1, ?2, ?3, ?4, 'enrolled', ?5, ?6, ?7, NULL)",
            params![
                client_id,
                display_name,
                public_key,
                serde_json::to_string(capabilities)?,
                record.record.envelope.record_id,
                record.record.envelope.origin_id,
                sql_i64(record.record.envelope.origin_seq, "client approval sequence")?,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn project_client_revoked(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let client_id = string(item, "client_id")?;
    if client_id == record.record.envelope.origin_id {
        return Err(V2ProjectionError::Invalid(
            "a client cannot revoke itself".to_owned(),
        ));
    }
    let changed = transaction
        .execute(
            "UPDATE clients SET status = 'revoked', revoked_record_id = ?2
             WHERE client_id = ?1 AND status = 'enrolled'
               AND EXISTS (
                 SELECT 1 FROM clients approver
                 WHERE approver.client_id = ?3 AND approver.status = 'enrolled'
               )",
            params![
                client_id,
                record.record.envelope.record_id,
                record.record.envelope.origin_id,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    if changed != 1 {
        return Err(V2ProjectionError::Invalid(format!(
            "client {client_id} is not currently enrolled or the revoker is not trusted"
        )));
    }
    Ok(())
}

fn project_job_finished(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let job_id = string(item, "job_id")?;
    let status = string(item, "status")?;
    if !matches!(status, "complete" | "partial" | "failed" | "cancelled") {
        return Err(V2ProjectionError::Invalid(format!(
            "unsupported terminal job status {status:?}"
        )));
    }
    let changed = transaction
        .execute(
            "UPDATE jobs SET status = ?2, finished_time_utc_ms = ?3, progress_json = ?4
             WHERE job_id = ?1 AND job_type = ?5 AND input_version = ?6",
            params![
                job_id,
                status,
                sql_i64(record.record.envelope.time_utc_ms, "job finish time")?,
                serde_json::to_string(required(item, "summary")?)?,
                string(item, "job_type")?,
                string(item, "input_version")?,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    if changed != 1 {
        return Err(V2ProjectionError::Invalid(format!(
            "job_finished has no matching job_started for {job_id}"
        )));
    }
    Ok(())
}

fn execute_projected<P: rusqlite::Params>(
    transaction: &Transaction<'_>,
    sql: &str,
    parameters: P,
) -> rusqlite::Result<usize> {
    transaction.prepare_cached(sql)?.execute(parameters)
}

fn project_operation_outcome(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    item_index: u64,
    database_path: &Path,
) -> Result<()> {
    let Some(operation_key) = item.get("operation_key").and_then(Value::as_str) else {
        return Ok(());
    };
    execute_projected(
        transaction,
        "INSERT INTO operation_outcomes(operation_key, record_id, item_index)
             VALUES (?1, ?2, ?3)",
        params![
            operation_key,
            record.record.envelope.record_id,
            sql_i64(item_index, "operation item index")?,
        ],
    )
    .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn project_annex_import_started(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let repo: crate::registry::RegistryPath =
        serde_json::from_value(required(item, "repo_path")?.clone()).map_err(|error| {
            V2ProjectionError::Invalid(format!("annex repository path is invalid: {error}"))
        })?;
    let bytes = registry_path_bytes(&repo)
        .map_err(|error| V2ProjectionError::Invalid(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO annex_imports(import_id, job_id, repo_path_bytes, repo_path_encoding, repo_path_display, collection_id, worktree_location_id, cas_location_id, device_id, archive_root_id, annex_uuid, git_head_commit, status, summary_json, started_record_id, completed_record_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'running', '{}', ?13, NULL)",
            params![
                string(item, "import_id")?,
                string(item, "job_id")?,
                bytes,
                repo.encoding,
                repo.display,
                string(item, "collection_id")?,
                string(item, "worktree_location_id")?,
                string(item, "cas_location_id")?,
                string(item, "device_id")?,
                string(item, "archive_root_id")?,
                string(item, "annex_uuid")?,
                string(item, "git_head_commit")?,
                record.record.envelope.record_id,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn project_annex_import_completed(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let status = string(item, "status")?;
    if !matches!(status, "complete" | "partial" | "failed") {
        return Err(V2ProjectionError::Invalid(
            "annex import completion status is invalid".to_owned(),
        ));
    }
    let changed = transaction
        .execute(
            "UPDATE annex_imports SET status = ?2, annex_uuid = ?3, git_head_commit = ?4, summary_json = ?5, completed_record_id = ?6 WHERE import_id = ?1 AND status = 'running'",
            params![string(item, "import_id")?, status, string(item, "annex_uuid")?, string(item, "git_head_commit")?, serde_json::to_string(required(item, "summary")?)?, record.record.envelope.record_id],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    if changed != 1 {
        return Err(V2ProjectionError::Invalid(
            "annex import completion does not match one running import".to_owned(),
        ));
    }
    Ok(())
}

fn project_scan_started(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let scan_mode = string(item, "scan_mode")?;
    if !matches!(scan_mode, "add" | "complete") {
        return Err(V2ProjectionError::Invalid(
            "scan mode must be add or complete".to_owned(),
        ));
    }
    let scope = required(item, "scope")?;
    let exclusions = required(item, "exclusions")?;
    let scope_json = serde_json::to_string(scope)?;
    let exclusions_json = serde_json::to_string(exclusions)?;
    let exclusions_hash = format!(
        "blake3:{}",
        blake3::hash(exclusions_json.as_bytes()).to_hex()
    );
    transaction
        .execute(
            "INSERT INTO scan_runs(scan_id, job_id, location_id, collection_id, logical_prefix_bytes, logical_prefix_encoding, logical_prefix_display, status, scan_mode, started_time_utc_ms, causal_frontier_hash, finished_time_utc_ms, coverage_version, scope_json, exclusions_json, exclusions_hash, observations_count, observations_digest, missing_candidate_count, missing_candidate_digest, files_seen, bytes_seen, new_paths, changed_paths, missing_paths, unchanged_paths, error_count, error_summary_json, started_record_id, finished_record_id)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, 'running', ?5, ?6, ?7, NULL, 1, ?8, ?9, ?10, 0, NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, '{}', ?11, NULL)",
            params![
                string(item, "scan_id")?,
                string(item, "job_id")?,
                string(item, "location_id")?,
                string(item, "collection_id")?,
                scan_mode,
                sql_i64(number(item, "started_time_utc_ms")?, "scan start time")?,
                record.causal_frontier_hash,
                scope_json,
                exclusions_json,
                exclusions_hash,
                record.record.envelope.record_id,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn project_scan_missing_candidate(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    item_index: u64,
    database_path: &Path,
) -> Result<()> {
    let candidate_kind = string(item, "candidate_kind")?;
    if !matches!(candidate_kind, "path" | "copy") {
        return Err(V2ProjectionError::Invalid(
            "scan candidate kind must be path or copy".to_owned(),
        ));
    }
    let scan_id = string(item, "scan_id")?;
    let scan_mode: String = transaction
        .query_row(
            "SELECT scan_mode FROM scan_runs WHERE scan_id = ?1 AND status = 'running'",
            [scan_id],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    if scan_mode != "complete" {
        return Err(V2ProjectionError::Invalid(
            "only a complete scan may emit missing candidates".to_owned(),
        ));
    }
    let path_value: crate::registry::RegistryPath =
        serde_json::from_value(required(item, "path")?.clone()).map_err(|error| {
            V2ProjectionError::Invalid(format!("missing-candidate path is invalid: {error}"))
        })?;
    let path_bytes = registry_path_bytes(&path_value)
        .map_err(|error| V2ProjectionError::Invalid(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO scan_missing_candidates(candidate_id, origin_id, origin_seq, record_id, item_index, record_hash, scan_id, candidate_kind, file_ref_id, copy_claim_id, location_id, path_bytes, path_encoding, activated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0)",
            params![
                string(item, "candidate_id")?,
                record.record.envelope.origin_id,
                sql_i64(record.record.envelope.origin_seq, "candidate origin sequence")?,
                record.record.envelope.record_id,
                sql_i64(item_index, "candidate item index")?,
                record.record.record_hash,
                scan_id,
                candidate_kind,
                item.get("file_ref_id").and_then(Value::as_str),
                item.get("copy_claim_id").and_then(Value::as_str),
                string(item, "location_id")?,
                path_bytes,
                path_value.encoding,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn project_scan_completed(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    database_path: &Path,
) -> Result<()> {
    let status = string(item, "status")?;
    if !matches!(status, "complete" | "partial" | "failed" | "cancelled") {
        return Err(V2ProjectionError::Invalid(
            "scan completion status is invalid".to_owned(),
        ));
    }
    let scan_id = string(item, "scan_id")?;
    let running: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE scan_id = ?1 AND status = 'running'",
            [scan_id],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    if running != 1 {
        return Err(V2ProjectionError::Invalid(
            "scan completion does not match one running scan".to_owned(),
        ));
    }
    transaction
        .execute(
            "INSERT INTO scan_pending_completions(scan_id, batch_id, desired_status, finished_time_utc_ms, summary_json, finished_record_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                scan_id,
                record.record.envelope.batch_id,
                status,
                sql_i64(number(item, "finished_time_utc_ms")?, "scan finish time")?,
                serde_json::to_string(required(item, "summary")?)?,
                record.record.envelope.record_id,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_file_identity_conflict(
    transaction: &Transaction<'_>,
    collection_id: &str,
    path_encoding: &str,
    path_bytes: &[u8],
    existing_origin: &str,
    existing_sequence: u64,
    existing_record_id: &str,
    observed_origin: &str,
    observed_sequence: u64,
    observed_record_id: &str,
    database_path: &Path,
) -> Result<()> {
    let mut entity_key = Vec::new();
    for part in [
        collection_id.as_bytes(),
        path_encoding.as_bytes(),
        path_bytes,
    ] {
        entity_key.extend_from_slice(
            &u64::try_from(part.len())
                .map_err(|_| V2ProjectionError::Invalid("conflict key is too large".to_owned()))?
                .to_be_bytes(),
        );
        entity_key.extend_from_slice(part);
    }
    let existing = (existing_origin, existing_sequence, existing_record_id);
    let observed = (observed_origin, observed_sequence, observed_record_id);
    let (left, right) = if (existing.0, existing.1) <= (observed.0, observed.1) {
        (existing, observed)
    } else {
        (observed, existing)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"file_identity_conflict\0");
    hasher.update(&entity_key);
    hasher.update(left.0.as_bytes());
    hasher.update(&left.1.to_be_bytes());
    hasher.update(right.0.as_bytes());
    hasher.update(&right.1.to_be_bytes());
    let conflict_id = format!("conflict_{}", hasher.finalize().to_hex());
    transaction
        .execute(
            "INSERT OR IGNORE INTO fact_conflicts(
                 conflict_id, fact_kind, entity_key,
                 left_origin_id, left_origin_seq, left_record_id,
                 right_origin_id, right_origin_seq, right_record_id,
                 state, resolved_record_id)
             VALUES (?1, 'file_identity', ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'unresolved', NULL)",
            params![
                conflict_id,
                entity_key,
                left.0,
                sql_i64(left.1, "left conflict sequence")?,
                left.2,
                right.0,
                sql_i64(right.1, "right conflict sequence")?,
                right.2,
            ],
        )
        .map_err(|source| sqlite_error(database_path, source))?;
    Ok(())
}

fn is_registry_item(kind: &str) -> bool {
    matches!(
        kind,
        "site_registered"
            | "site_updated"
            | "site_retired"
            | "policy_registered"
            | "policy_updated"
            | "policy_retired"
            | "collection_registered"
            | "collection_updated"
            | "collection_retired"
            | "device_registered"
            | "device_updated"
            | "device_moved"
            | "device_retired"
            | "archive_root_registered"
            | "archive_root_updated"
            | "archive_root_retired"
            | "location_registered"
            | "location_updated"
            | "location_retired"
            | "risk_domain_registered"
            | "risk_domain_updated"
            | "risk_domain_retired"
            | "risk_assigned"
            | "risk_unassigned"
            | "device_checked_in"
            | "device_mount_observed"
    )
}

fn project_registry_item(
    transaction: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    path: &Path,
) -> Result<()> {
    let kind = string(item, "kind")?;
    let record_id = &record.record.envelope.record_id;
    let record_time = sql_i64(record.record.envelope.time_utc_ms, "registry record time")?;
    match kind {
        "site_registered" | "site_updated" | "site_retired" => {
            let value: SiteSnapshot = registry_snapshot(item, &[])?;
            transaction.execute(
                "INSERT INTO sites(site_id, display_name, site_kind, description, status, last_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(site_id) DO UPDATE SET display_name = excluded.display_name, site_kind = excluded.site_kind, description = excluded.description, status = excluded.status, last_record_id = excluded.last_record_id",
                params![value.site_id, value.display_name, value.site_kind, value.description, value.status, record_id],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "policy_registered" | "policy_updated" | "policy_retired" => {
            let value: PolicySnapshot = registry_snapshot(item, &[])?;
            transaction.execute(
                "INSERT INTO policies(policy_id, display_name, policy_version, requirements_json, enabled, status, last_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(policy_id) DO UPDATE SET display_name = excluded.display_name, policy_version = excluded.policy_version, requirements_json = excluded.requirements_json, enabled = excluded.enabled, status = excluded.status, last_record_id = excluded.last_record_id",
                params![
                    value.policy_id,
                    value.display_name,
                    sql_i64(value.policy_version, "policy version")?,
                    serde_json::to_string(&value.requirements)?,
                    value.enabled,
                    value.status,
                    record_id,
                ],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "collection_registered" | "collection_updated" | "collection_retired" => {
            let value: CollectionSnapshot = registry_snapshot(item, &[])?;
            transaction.execute(
                "INSERT INTO collections(collection_id, display_name, description, home_site_id, policy_id, status, last_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(collection_id) DO UPDATE SET display_name = excluded.display_name, description = excluded.description, home_site_id = excluded.home_site_id, policy_id = excluded.policy_id, status = excluded.status, last_record_id = excluded.last_record_id",
                params![value.collection_id, value.display_name, value.description, value.home_site_id, value.policy_id, value.status, record_id],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "device_registered" | "device_updated" | "device_moved" | "device_retired" => {
            let value: DeviceSnapshot = registry_snapshot(item, &[])?;
            transaction.execute(
                "INSERT INTO devices(device_id, display_name, device_kind, serial_hint, hardware_fingerprint, fingerprint_kind, identity_state, owner, status, current_site_id, expected_availability, last_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(device_id) DO UPDATE SET display_name = excluded.display_name, device_kind = excluded.device_kind, serial_hint = excluded.serial_hint, hardware_fingerprint = excluded.hardware_fingerprint, fingerprint_kind = excluded.fingerprint_kind, identity_state = excluded.identity_state, owner = excluded.owner, status = excluded.status, current_site_id = excluded.current_site_id, expected_availability = excluded.expected_availability, last_record_id = excluded.last_record_id",
                params![value.device_id, value.display_name, value.device_kind, value.serial_hint, value.hardware_fingerprint, value.fingerprint_kind, value.identity_state, value.owner, value.status, value.current_site_id, value.expected_availability, record_id],
            ).map_err(|source| sqlite_error(path, source))?;
            if kind == "device_moved" {
                transaction.execute(
                    "UPDATE device_site_history SET departed_time_utc_ms = ?2 WHERE device_id = ?1 AND departed_time_utc_ms IS NULL",
                    params![value.device_id, record_time],
                ).map_err(|source| sqlite_error(path, source))?;
            }
            if (kind == "device_registered" || kind == "device_moved")
                && value.current_site_id.is_some()
            {
                transaction.execute(
                    "INSERT INTO device_site_history(device_id, site_id, arrived_time_utc_ms, departed_time_utc_ms, moved_record_id) VALUES (?1, ?2, ?3, NULL, ?4)",
                    params![value.device_id, value.current_site_id, record_time, record_id],
                ).map_err(|source| sqlite_error(path, source))?;
            }
        }
        "archive_root_registered" | "archive_root_updated" | "archive_root_retired" => {
            let value: ArchiveRootSnapshot = registry_snapshot(item, &[])?;
            let root_bytes = registry_path_bytes(&value.root_path_on_device)
                .map_err(|error| V2ProjectionError::Invalid(error.to_string()))?;
            transaction.execute(
                "INSERT INTO archive_roots(archive_root_id, device_id, display_name, filesystem_fingerprint, fingerprint_kind, identity_state, root_path_on_device_bytes, root_path_encoding, root_path_display, status, created_record_id, last_seen_record_id, last_seen_time_utc_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?12)
                 ON CONFLICT(archive_root_id) DO UPDATE SET display_name = excluded.display_name, status = excluded.status, last_seen_record_id = excluded.last_seen_record_id, last_seen_time_utc_ms = excluded.last_seen_time_utc_ms",
                params![value.archive_root_id, value.device_id, value.display_name, value.filesystem_fingerprint, value.fingerprint_kind, value.identity_state, root_bytes, value.root_path_on_device.encoding, value.root_path_on_device.display, value.status, record_id, record_time],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "location_registered" | "location_updated" | "location_retired" => {
            let value: LocationSnapshot = registry_snapshot(item, &[])?;
            let relative_bytes = value
                .relative_path
                .as_ref()
                .map(registry_path_bytes)
                .transpose()
                .map_err(|error| V2ProjectionError::Invalid(error.to_string()))?;
            let relative_encoding = value
                .relative_path
                .as_ref()
                .map(|item| item.encoding.clone());
            let relative_display = value
                .relative_path
                .as_ref()
                .map(|item| item.display.clone());
            transaction.execute(
                "INSERT INTO locations(location_id, display_name, kind, archive_root_id, relative_path_bytes, relative_path_encoding, relative_path_display, device_id, site_id, encryption_state, trust_level, expected_availability, is_writable, status, created_record_id, last_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)
                 ON CONFLICT(location_id) DO UPDATE SET display_name = excluded.display_name, kind = excluded.kind, archive_root_id = excluded.archive_root_id, relative_path_bytes = excluded.relative_path_bytes, relative_path_encoding = excluded.relative_path_encoding, relative_path_display = excluded.relative_path_display, device_id = excluded.device_id, site_id = excluded.site_id, encryption_state = excluded.encryption_state, trust_level = excluded.trust_level, expected_availability = excluded.expected_availability, is_writable = excluded.is_writable, status = excluded.status, last_record_id = excluded.last_record_id",
                params![value.location_id, value.display_name, value.kind, value.archive_root_id, relative_bytes, relative_encoding, relative_display, value.device_id, value.site_id, value.encryption_state, value.trust_level, value.expected_availability, value.is_writable, value.status, record_id],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "risk_domain_registered" | "risk_domain_updated" | "risk_domain_retired" => {
            let value: RiskDomainSnapshot = registry_snapshot(item, &[])?;
            transaction.execute(
                "INSERT INTO risk_domains(risk_domain_id, display_name, risk_kind, description, status, last_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(risk_domain_id) DO UPDATE SET display_name = excluded.display_name, risk_kind = excluded.risk_kind, description = excluded.description, status = excluded.status, last_record_id = excluded.last_record_id",
                params![value.risk_domain_id, value.display_name, value.risk_kind, value.description, value.status, record_id],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "risk_assigned" | "risk_unassigned" => {
            let value: RiskAssignment = registry_snapshot(item, &[])?;
            if kind == "risk_assigned" {
                transaction.execute(
                    "INSERT INTO entity_risk_domains(entity_type, entity_id, risk_domain_id, assigned_record_id) VALUES (?1, ?2, ?3, ?4)",
                    params![value.entity_type, value.entity_id, value.risk_domain_id, record_id],
                ).map_err(|source| sqlite_error(path, source))?;
            } else {
                transaction.execute(
                    "DELETE FROM entity_risk_domains WHERE entity_type = ?1 AND entity_id = ?2 AND risk_domain_id = ?3",
                    params![value.entity_type, value.entity_id, value.risk_domain_id],
                ).map_err(|source| sqlite_error(path, source))?;
            }
        }
        "device_checked_in" => {
            let value: DeviceCheckIn = registry_snapshot(item, &[])?;
            transaction.execute(
                "UPDATE devices SET last_checkin_record_id = ?2, last_checkin_time_utc_ms = ?3, last_fingerprint_match_time_utc_ms = CASE WHEN ?4 = 'match' THEN ?3 ELSE last_fingerprint_match_time_utc_ms END, last_fingerprint_status = ?4 WHERE device_id = ?1",
                params![value.device_id, record_id, record_time, value.fingerprint_status],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        "device_mount_observed" => {
            let value: DeviceMount = registry_snapshot(item, &["host_id"])?;
            transaction.execute(
                "INSERT INTO device_mounts(mount_id, device_id, archive_root_id, host_id, mount_root_uri, status, fingerprint_status, observed_time_utc_ms, observed_record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![value.mount_id, value.device_id, value.archive_root_id, string(item, "host_id")?, value.mount_root_uri, value.status, value.fingerprint_status, record_time, record_id],
            ).map_err(|source| sqlite_error(path, source))?;
        }
        _ => unreachable!("registry item kind was checked"),
    }
    Ok(())
}

fn registry_snapshot<T: DeserializeOwned>(
    item: &serde_json::Map<String, Value>,
    _extra_fields: &[&str],
) -> Result<T> {
    let snapshot = required(item, "snapshot")?.clone();
    serde_json::from_value(snapshot).map_err(|error| {
        V2ProjectionError::Invalid(format!("registry snapshot is invalid: {error}"))
    })
}

fn project_batch_complete(
    transaction: &Transaction<'_>,
    record: &VerifiedV2Record,
    path: &Path,
    report: &mut dyn FnMut(V2ApplyProgress),
) -> Result<()> {
    let payload = object(&record.record.envelope.payload, "batch_complete payload")?;
    let declared = number(payload, "total_items")?;
    let observed: i64 = transaction
        .query_row(
            "SELECT item_count FROM batch_runs WHERE batch_id = ?1 AND state = 'running'",
            [&record.record.envelope.batch_id],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, source))?;
    if declared != sql_u64(observed, "batch item count")?
        || string(payload, "status")? != "complete"
    {
        return Err(V2ProjectionError::Invalid(format!(
            "batch {} completion does not match projected chunks",
            record.record.envelope.batch_id
        )));
    }
    compact::finalize_scans_for_batch(transaction, record, path, report)?;
    transaction.execute(
        "UPDATE batch_runs SET complete_seq = ?2, item_digest = ?3, state = 'complete' WHERE batch_id = ?1",
        params![
            record.record.envelope.batch_id,
            sql_i64(
                record.record.envelope.origin_seq,
                "batch complete sequence",
            )?,
            string(payload, "ordered_item_digest")?
        ],
    ).map_err(|source| sqlite_error(path, source))?;
    Ok(())
}

fn meta(connection: &Connection, path: &Path, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM archive_meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(path, source))?
        .ok_or_else(|| V2ProjectionError::Invalid(format!("archive_meta is missing {key}")))
}

fn u32_meta(connection: &Connection, path: &Path, key: &str) -> Result<u32> {
    meta(connection, path, key)?
        .parse()
        .map_err(|_| V2ProjectionError::Invalid(format!("archive_meta {key} is not a u32")))
}

fn u64_meta(connection: &Connection, path: &Path, key: &str) -> Result<u64> {
    meta(connection, path, key)?
        .parse()
        .map_err(|_| V2ProjectionError::Invalid(format!("archive_meta {key} is not a u64")))
}

fn count(
    connection: &Connection,
    path: &Path,
    table: &str,
    predicate: Option<&str>,
) -> Result<u64> {
    let sql = match predicate {
        Some(predicate) => format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
        None => format!("SELECT COUNT(*) FROM {table}"),
    };
    let value: i64 = connection
        .query_row(&sql, [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, source))?;
    sql_u64(value, "row count")
}

fn sql_i64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| V2ProjectionError::Invalid(format!("{field} exceeds SQLite integer range")))
}

fn sql_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| V2ProjectionError::Invalid(format!("{field} is negative")))
}

fn object<'a>(value: &'a Value, description: &str) -> Result<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| V2ProjectionError::Invalid(format!("{description} must be an object")))
}

fn validate_projected_item_defaults(item_schema_version: u64, defaults: &Value) -> Result<()> {
    let defaults = object(defaults, "batch defaults")?;
    match item_schema_version {
        1 => Ok(()),
        2 => {
            for (kind, values) in defaults {
                let values = object(values, &format!("defaults for item kind {kind:?}"))?;
                if values.contains_key("kind") {
                    return Err(V2ProjectionError::Invalid(format!(
                        "defaults for item kind {kind:?} cannot default kind"
                    )));
                }
            }
            Ok(())
        }
        version => Err(V2ProjectionError::Invalid(format!(
            "unsupported batch item schema version {version}"
        ))),
    }
}

fn materialize_batch_item(
    item: &Value,
    defaults: &Value,
) -> Result<serde_json::Map<String, Value>> {
    let item = object(item, "batch item")?;
    let kind = string(item, "kind")?;
    let mut materialized = defaults
        .as_object()
        .and_then(|defaults| defaults.get(kind))
        .map(|values| object(values, &format!("defaults for item kind {kind:?}")))
        .transpose()?
        .cloned()
        .unwrap_or_default();
    for (key, value) in item {
        materialized.insert(key.clone(), value.clone());
    }
    Ok(materialized)
}

fn required<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| V2ProjectionError::Invalid(format!("batch payload is missing {key}")))
}

fn string<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str> {
    required(object, key)?
        .as_str()
        .ok_or_else(|| V2ProjectionError::Invalid(format!("batch payload {key} must be a string")))
}

fn number(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64> {
    required(object, key)?.as_u64().ok_or_else(|| {
        V2ProjectionError::Invalid(format!("batch payload {key} must be a nonnegative integer"))
    })
}

fn lower_ulid() -> String {
    Ulid::new().to_string().to_ascii_lowercase()
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

// Failure-only observations: never replace the original error if a diagnostic query fails.
// Values may reflect SQLite's automatic rollback, not the exact instant of failure.
fn sqlite_storage_diagnostics(connection: &Connection) -> String {
    let mut values = serde_json::Map::new();
    values.insert("sqlite_version".into(), Value::from(rusqlite::version()));
    values.insert("autocommit".into(), Value::from(connection.is_autocommit()));
    for schema in ["main", "temp"] {
        for pragma in ["page_size", "page_count", "max_page_count"] {
            let value = connection
                .query_row(&format!("PRAGMA {schema}.{pragma}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .ok();
            values.insert(
                format!("{schema}.{pragma}"),
                value.map_or(Value::Null, Value::from),
            );
        }
    }
    format!("SQLite state after error={}", Value::Object(values))
}

fn sqlite_operation_error(
    connection: &Connection,
    path: &Path,
    sql: &str,
    source: rusqlite::Error,
) -> V2ProjectionError {
    // A digest identifies the exact source statement without exporting SQL or bound values.
    let statement = blake3::hash(sql.as_bytes()).to_hex();
    sqlite_error(path, source).context(format!(
        "statement_blake3={statement}; {}",
        sqlite_storage_diagnostics(connection)
    ))
}

#[track_caller]
fn sqlite_error(path: impl Into<PathBuf>, source: rusqlite::Error) -> V2ProjectionError {
    let caller = std::panic::Location::caller();
    V2ProjectionError::Sqlite {
        path: path.into(),
        source,
    }
    .context(format!(
        "projection callsite={}:{}",
        caller.file(),
        caller.line()
    ))
}

fn sqlite_error_details(source: &rusqlite::Error) -> String {
    let error = match source {
        rusqlite::Error::SqliteFailure(error, _) | rusqlite::Error::SqlInputError { error, .. } => {
            error
        }
        _ => return String::new(),
    };
    let mut details = format!(
        " (SQLite primary code {}, extended code {})",
        error.extended_code & 0xff,
        error.extended_code
    );
    if error.extended_code == rusqlite::ffi::SQLITE_IOERR_GETTEMPPATH {
        details.push_str(
            "; SQLite could not find a usable temporary directory; check temporary-storage permissions and free space (SQLITE_TMPDIR on Unix)",
        );
    }
    details
}

fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> V2ProjectionError {
    V2ProjectionError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{
        ArchiveRootSnapshot, CollectionSnapshot, DeviceSnapshot, LocationSnapshot, RegistryAction,
        RegistryChange, RegistryPath, SiteSnapshot, V2Registry,
    };
    use crate::v2_store::initialize_v2_archive;
    use serde_json::json;
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn sqlite_diagnostics_distinguish_temp_path_failure_from_other_sqlite_errors() {
        for code in [
            rusqlite::ffi::SQLITE_IOERR_GETTEMPPATH,
            rusqlite::ffi::SQLITE_IOERR_FSYNC,
            rusqlite::ffi::SQLITE_IOERR,
            rusqlite::ffi::SQLITE_FULL,
            rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
        ] {
            let source = rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                Some("original SQLite detail".to_owned()),
            );
            let error = sqlite_error("fixture.db", source);
            let message = error.to_string();
            assert_eq!(error.code(), "v2_projection_sqlite");
            assert!(message
                .starts_with("SQLite operation failed for fixture.db: original SQLite detail"));
            assert!(message.contains(&format!(
                "SQLite primary code {}, extended code {code}",
                code & 0xff
            )));
            assert_eq!(
                message.contains("SQLITE_TMPDIR"),
                code == rusqlite::ffi::SQLITE_IOERR_GETTEMPPATH
            );
        }
    }

    #[test]
    fn sqlite_diagnostics_preserve_errors_without_sqlite_result_codes() {
        let error = sqlite_error("fixture.db", rusqlite::Error::QueryReturnedNoRows);
        assert_eq!(error.code(), "v2_projection_sqlite");
        assert!(error.to_string().starts_with(&format!(
            "SQLite operation failed for fixture.db: {}; projection callsite=",
            rusqlite::Error::QueryReturnedNoRows
        )));
        let invalid = V2ProjectionError::Invalid("original validation detail".to_owned());
        assert_eq!(invalid.code(), "v2_projection_invalid");
        assert_eq!(
            invalid.to_string(),
            "SQLite projection is invalid: original validation detail"
        );
    }

    #[test]
    fn sqlite_diagnostics_include_codes_from_real_sql_input_errors() {
        let connection = Connection::open_in_memory().unwrap();
        let source = connection.execute_batch("SELEC 1").unwrap_err();
        assert!(matches!(&source, rusqlite::Error::SqlInputError { .. }));
        let original = source.to_string();
        let error = sqlite_error("fixture.db", source);
        assert_eq!(error.code(), "v2_projection_sqlite");
        assert!(error.to_string().starts_with(&format!(
            "SQLite operation failed for fixture.db: {original} (SQLite primary code 1, extended code 1); projection callsite="
        )));
    }

    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&source_path, &target_path);
            } else {
                fs::copy(source_path, target_path).unwrap();
            }
        }
    }

    fn git_success(directory: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn schema_two_materializes_defaults_and_preserves_exceptions() {
        let defaults = json!({
            "content_observed": {
                "collection_id": "collection_files",
                "representation": "ordinary_file",
                "sha256_hex": null,
            }
        });
        let item = json!({
            "kind": "content_observed",
            "representation": "annex_locked_symlink",
            "file_ref_id": "file_one",
        });

        validate_projected_item_defaults(2, &defaults).unwrap();
        let materialized = materialize_batch_item(&item, &defaults).unwrap();
        assert_eq!(
            materialized.get("collection_id").and_then(Value::as_str),
            Some("collection_files")
        );
        assert_eq!(
            materialized.get("representation").and_then(Value::as_str),
            Some("annex_locked_symlink")
        );
        assert_eq!(materialized.get("sha256_hex"), Some(&Value::Null));
    }

    #[test]
    fn creates_compact_schema_and_rebuilds_equivalent_projection() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        V2ProjectionDb::create_from_store(&store, archive.join("archive.db")).unwrap();
        let initial = V2ProjectionDb::open_existing(archive.join("archive.db"))
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(initial.schema_version, V2_SQLITE_SCHEMA_VERSION);
        assert_eq!(initial.records, 3);
        assert_eq!(initial.collections, 0);
        let connection = Connection::open(archive.join("archive.db")).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE payload_json IS NOT NULL",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "canonical batch payload belongs in JSONL, not the interactive projection",
        );
        drop(connection);

        let rebuilt = archive.join("rebuilt.db");
        V2ProjectionDb::rebuild(&store, &rebuilt).unwrap();
        let rebuilt = V2ProjectionDb::open_existing(rebuilt)
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(initial, rebuilt);
    }

    #[test]
    fn schema_upgrade_retains_previous_database_and_rebuild_does_not_retain_current_schema() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let path = archive.join("archive.db");
        // A prior local database is preserved byte-for-byte; its contents are not
        // migration input. Only the signed canonical store supplies the new facts.
        let previous = Connection::open(&path).unwrap();
        previous.execute_batch("PRAGMA user_version=7; CREATE TABLE old_data(value TEXT); INSERT INTO old_data VALUES ('preserve me');").unwrap();
        drop(previous);
        let old_bytes = fs::read(&path).unwrap();
        let canonical_head = fs::read(store.root().join("frontiers/v2/HEAD")).unwrap();
        let stats = V2ProjectionDb::rebuild(&store, &path).unwrap();
        let backup = stats.previous_database.unwrap();
        assert_eq!(fs::read(&backup).unwrap(), old_bytes);
        assert_eq!(
            fs::read(store.root().join("frontiers/v2/HEAD")).unwrap(),
            canonical_head
        );
        assert_eq!(
            V2ProjectionDb::open_existing(&path)
                .unwrap()
                .status()
                .unwrap()
                .schema_version,
            V2_SQLITE_SCHEMA_VERSION
        );
        assert!(V2ProjectionDb::rebuild(&store, &path)
            .unwrap()
            .previous_database
            .is_none());
        assert_eq!(fs::read(&backup).unwrap(), old_bytes);
    }

    fn projection_rows(connection: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let filter = if table == "archive_meta" {
            " WHERE key NOT IN ('projection_generation', 'policy_input_generation')"
        } else {
            ""
        };
        let fields = connection
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .filter(|name| {
                !(name == "id" && matches!(table, "records" | "collections" | "locations"))
            })
            .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(",");
        let query = format!("SELECT {fields} FROM {table}{filter}");
        let columns = connection.prepare(&query).unwrap().column_count();
        let order = (1..=columns)
            .map(|column| column.to_string())
            .collect::<Vec<_>>()
            .join(",");
        connection
            .prepare(&format!("{query} ORDER BY {order}"))
            .unwrap()
            .query_map([], |row| {
                (0..columns).map(|column| row.get(column)).collect()
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    fn append_projection_items(store: &V2OriginStore, items: Vec<Value>) {
        store
            .append_batch("projection_test", 1, json!({}), json!({}), items)
            .unwrap();
    }

    #[test]
    fn rebuild_matches_incremental_annex_reimports_and_complete_scan_across_groups() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let live_path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &live_path).unwrap();
        let live = V2ProjectionDb::open_existing(&live_path).unwrap();
        let registry = V2Registry::new(&store, &live);
        registry
            .record(
                RegistryChange::Site(
                    RegistryAction::Register,
                    SiteSnapshot {
                        site_id: "site_home".to_owned(),
                        display_name: "Home".to_owned(),
                        site_kind: "home".to_owned(),
                        description: None,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::Collection(
                    RegistryAction::Register,
                    CollectionSnapshot {
                        collection_id: "collection_files".to_owned(),
                        display_name: "Files".to_owned(),
                        description: None,
                        home_site_id: Some("site_home".to_owned()),
                        policy_id: None,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::Location(
                    RegistryAction::Register,
                    LocationSnapshot {
                        location_id: "location_main".to_owned(),
                        display_name: "Main".to_owned(),
                        kind: "service".to_owned(),
                        archive_root_id: None,
                        relative_path: None,
                        device_id: None,
                        site_id: Some("site_home".to_owned()),
                        encryption_state: Some("unknown".to_owned()),
                        trust_level: Some("trusted".to_owned()),
                        expected_availability: "online".to_owned(),
                        is_writable: true,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();

        registry
            .record(
                RegistryChange::Location(
                    RegistryAction::Register,
                    LocationSnapshot {
                        location_id: "location_annex_cas".to_owned(),
                        display_name: "Annex objects".to_owned(),
                        kind: "service".to_owned(),
                        archive_root_id: None,
                        relative_path: None,
                        device_id: None,
                        site_id: Some("site_home".to_owned()),
                        encryption_state: Some("unknown".to_owned()),
                        trust_level: Some("trusted".to_owned()),
                        expected_availability: "online".to_owned(),
                        is_writable: true,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();

        let entry = |index: usize, operation: &str| {
            json!({
                "kind": "annex_entry_observed", "operation_key": operation,
                "external_identity_id": format!("external_{index}"), "external_key": format!("key_{index}"),
                "backend": "SHA256E", "expected_hash_algo": "sha256", "expected_hash_hex": "a".repeat(64),
                "expected_size_bytes": 4, "resolution_state": "unresolved", "source_repo_id": "repo_main",
                "file_ref_id": format!("file_{index}"), "collection_id": "collection_files",
                "logical_path": RegistryPath::utf8(format!("file-{index}")),
                "worktree_location_id": "location_main", "cas_location_id": "location_main",
                "representation": "annex_locked_symlink", "path_state": "present",
                "local_availability": "unknown", "observed_size_bytes": 4,
                "copy_claim_id": format!("copy_{index}"), "copy_location_id": "location_main",
                "copy_path": RegistryPath::utf8(format!("file-{index}")), "copy_state": "unknown",
                "claim_basis": "source_metadata", "job_id": "job_import",
            })
        };
        // Cross a replay transaction boundary while keeping the fixture tiny.
        for index in 0..86 {
            append_projection_items(&store, vec![entry(index, &format!("first_{index}"))]);
        }
        let hash = "b".repeat(64);
        let mut resolved = entry(0, "resolved_0");
        resolved["object_id"] = json!(format!("blake3:{hash}"));
        resolved["blake3_hex"] = json!(hash);
        resolved["sha256_hex"] = json!("c".repeat(64));
        resolved["sha512_hex"] = json!("d".repeat(128));
        resolved["resolution_state"] = json!("resolved");
        resolved["claim_basis"] = json!("observed_bytes");
        resolved["copy_state"] = json!("present");
        resolved["local_availability"] = json!("present");
        resolved["verification_result"] = json!("ok");
        let mut distinct_cas = resolved.clone();
        distinct_cas["operation_key"] = json!("resolved_distinct_cas");
        distinct_cas["file_ref_id"] = json!("file_distinct_cas");
        distinct_cas["logical_path"] = json!(RegistryPath::utf8("separate-cas-file"));
        distinct_cas["external_identity_id"] = json!("external_distinct_cas");
        distinct_cas["external_key"] = json!("key_distinct_cas");
        distinct_cas["copy_claim_id"] = json!("copy_distinct_cas");
        distinct_cas["cas_location_id"] = json!("location_annex_cas");
        distinct_cas["copy_location_id"] = json!("location_annex_cas");
        distinct_cas["copy_path"] = json!(RegistryPath::utf8("objects/ab/cd/content"));
        append_projection_items(&store, vec![resolved]);
        // Repeated metadata must retain resolved identity and verification facts.
        append_projection_items(&store, vec![entry(0, "reimport_0")]);
        append_projection_items(
            &store,
            vec![
                json!({"kind":"scan_started", "scan_id":"scan_full", "job_id":"job_scan",
                "location_id":"location_main", "collection_id":"collection_files",
                "scan_mode":"complete", "started_time_utc_ms":1_782_000_000_001_u64,
                "scope":{}, "exclusions":[]}),
                json!({"kind":"scan_missing_candidate", "candidate_id":"candidate_one",
                "scan_id":"scan_full", "candidate_kind":"path", "file_ref_id":"file_1",
                "copy_claim_id":"copy_1", "location_id":"location_main",
                "path":RegistryPath::utf8("file-1")}),
                json!({"kind":"scan_completed", "scan_id":"scan_full", "status":"complete",
                "finished_time_utc_ms":1_782_000_000_002_u64,
                "summary":{"missing_paths":1,"files_observed":85,"bytes_observed":340,"unchanged_files":0,
                    "new_paths":0,"changed_paths":0,"confirmed_good":1,
                    "read_errors":0,"concurrent_changes":0,"traversal_errors":0}}),
            ],
        );
        // Append after the existing complete-scan scenario so its coverage counts
        // remain unchanged. The link and its readable bytes occupy distinct Locations.
        append_projection_items(&store, vec![distinct_cas]);
        let interrupted_path = archive.join("interrupted.db");
        fs::copy(&live_path, &interrupted_path).unwrap();
        let interrupted = V2ProjectionDb::open_existing(&interrupted_path).unwrap();
        let mut reached_finalization = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            interrupted
                .apply_with_progress(
                    &store,
                    Some(&mut |event| {
                        if let V2ApplyProgress::ScanFinalization { phase, processed } = event {
                            if phase == "Refreshing copy presence (uncommitted)" && processed > 0 {
                                reached_finalization = true;
                                panic!("interrupt inside uncommitted scan finalization");
                            }
                        }
                    }),
                )
                .unwrap();
        }));
        assert!(result.is_err() && reached_finalization);
        let rolled_back = interrupted.open().unwrap();
        assert_eq!(rolled_back.query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE scan_id='scan_full' AND status='complete'",
            [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        drop(rolled_back);
        // Reopen and replay the published history, without scanning source bytes.
        let resumed = V2ProjectionDb::open_existing(&interrupted_path).unwrap();
        assert!(resumed.apply(&store).unwrap().caught_up);
        assert_eq!(resumed.apply(&store).unwrap().records_applied, 0);
        assert!(
            live.apply(&store).unwrap().records_applied > REPLAY_RECORDS_PER_TRANSACTION as u64
        );
        let rebuilt_path = archive.join("rebuilt.db");
        V2ProjectionDb::rebuild(&store, &rebuilt_path).unwrap();
        let connection = live.open().unwrap();
        let rebuilt = Connection::open(rebuilt_path).unwrap();
        let schema = |db: &Connection| {
            db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
                .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?)))
                .unwrap().collect::<std::result::Result<Vec<_>, _>>().unwrap()
        };
        let expected_schema = schema(&connection);
        let resumed = resumed.open().unwrap();
        assert_eq!(expected_schema, schema(&resumed));
        for (kind, name, _, _) in &expected_schema {
            if kind == "table" {
                assert_eq!(
                    projection_rows(&connection, name),
                    projection_rows(&resumed, name),
                    "resumed table {name}"
                );
            }
        }
        assert_eq!(expected_schema, schema(&rebuilt));
        for (kind, name, _, _) in expected_schema {
            if (kind == "table" && !COMPACT_TABLES.contains(&name.as_str())) || kind == "view" {
                assert_eq!(
                    projection_rows(&connection, &name),
                    projection_rows(&rebuilt, &name),
                    "table {name}"
                );
            }
        }
        for db in [&connection, &rebuilt] {
            let checks = db
                .prepare(
                    "SELECT location_id, presence, integrity FROM file_checks
                     WHERE file_ref_id='file_distinct_cas' OR copy_claim_id='copy_distinct_cas' ORDER BY location_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                checks,
                vec![
                    ("location_annex_cas".to_owned(), 1, 1),
                    ("location_main".to_owned(), 1, 0),
                ],
                "only the CAS Location receives content-integrity evidence",
            );
            let observation: (String, String) = db
                .query_row(
                    "SELECT location_id, observed_path_display FROM path_observations
                 WHERE file_ref_id='file_distinct_cas'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                observation,
                ("location_main".to_owned(), "separate-cas-file".to_owned())
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM path_observations WHERE file_ref_id='file_distinct_cas'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                1,
                "the CAS binding must not invent another logical-path observation",
            );
            let copy: (String, String, String) = db
                .query_row(
                    "SELECT location_id, relative_path_display, last_verification_result
                 FROM copy_claims WHERE copy_claim_id='copy_distinct_cas'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                copy,
                (
                    "location_annex_cas".to_owned(),
                    "objects/ab/cd/content".to_owned(),
                    "ok".to_owned()
                )
            );
        }
        let state: (String, String, String) = rebuilt.query_row(
            "SELECT p.state, c.state, p.last_complete_scan_id FROM path_observations p JOIN copy_claims c ON c.copy_claim_id = 'copy_1' WHERE p.file_ref_id = 'file_1'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(
            state,
            (
                "missing".to_owned(),
                "missing".to_owned(),
                "scan_full".to_owned()
            )
        );
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT identity_state FROM file_refs WHERE file_ref_id='file_0'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "resolved"
        );
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT last_verification_result FROM copy_claims WHERE copy_claim_id='copy_0'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "ok"
        );
        assert_eq!(
            rebuilt
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "delete"
        );
        assert_eq!(
            rebuilt
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn replay_configuration_bounds_memory_and_preserves_durability() {
        let connection = Connection::open_in_memory().unwrap();
        configure_replay(&connection, Path::new(":memory:")).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA cache_size", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            -131072
        );
        assert_eq!(
            connection
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn replay_candidate_activation_spills_statement_journal_and_remains_atomic() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("projection.db");
        let connection = Connection::open(&path).unwrap();
        configure_replay(&connection, &path).unwrap();
        // A reduced scan-candidate table isolates the replay statement-journal
        // boundary. Enough existing pages must be changed twice in one transaction
        // to exceed the former 1 MiB spill threshold. Changing an unrelated table
        // first does not reproduce the failure.
        connection
            .execute_batch(
                "CREATE TABLE scan_missing_candidates (
                candidate_id INTEGER PRIMARY KEY,
                scan_id TEXT NOT NULL,
                path_bytes BLOB NOT NULL,
                activated INTEGER NOT NULL DEFAULT 0 CHECK(activated IN (0,1))
             ) STRICT;
             BEGIN;",
            )
            .unwrap();
        {
            let mut insert = connection.prepare(
                "INSERT INTO scan_missing_candidates(scan_id,path_bytes) VALUES ('scan_test',?1)",
            ).unwrap();
            for _ in 0..8192 {
                insert.execute([vec![b'a'; 212]]).unwrap();
            }
        }
        connection.execute_batch("COMMIT;").unwrap();
        for finish in ["ROLLBACK", "COMMIT"] {
            connection
                .execute_batch(
                    "BEGIN; UPDATE scan_missing_candidates SET path_bytes=zeroblob(212);",
                )
                .unwrap();
            assert_eq!(
                connection
                    .execute(
                        "UPDATE scan_missing_candidates SET activated=1 WHERE scan_id=?1",
                        ["scan_test"],
                    )
                    .unwrap(),
                8192
            );
            connection.execute_batch(finish).unwrap();
            let activated: i64 = connection
                .query_row(
                    "SELECT count(*) FROM scan_missing_candidates WHERE activated=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(activated, if finish == "COMMIT" { 8192 } else { 0 });
            let changed_paths: i64 = connection
                .query_row(
                    "SELECT count(*) FROM scan_missing_candidates WHERE path_bytes=zeroblob(212)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(changed_paths, activated);
        }
    }

    #[test]
    fn failed_replay_group_rolls_back_and_preserves_installed_database() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let installed = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &installed).unwrap();
        let grouped_path = archive.join("grouped.db");
        fs::copy(&installed, &grouped_path).unwrap();
        for index in 0..87 {
            append_projection_items(
                &store,
                vec![json!({
                    "kind":"archive_updated", "archive_id":"arc_test",
                    "archive_display_name":format!("Batch {index}"),
                    "operation_key":format!("operation_{}", index.min(85)),
                })],
            );
        }
        let grouped = V2ProjectionDb::open_existing(grouped_path).unwrap();
        let mut progress = Vec::new();
        assert!(grouped
            .apply_with_progress(&store, Some(&mut |event| progress.push(event)))
            .unwrap_err()
            .to_string()
            .contains("operation_outcomes.operation_key"));
        assert_eq!(
            progress,
            vec![
                V2ApplyProgress::Verifying,
                V2ApplyProgress::Applying {
                    records_applied: 256,
                    total_records: 261
                },
            ]
        );
        let connection = grouped.open().unwrap();
        // The first group ends with batch 85's start, at origin sequence 259.
        // Its chunk and the failing batch are in the rolled-back second group.
        assert_eq!(
            count(&connection, grouped.path(), "records", None).unwrap(),
            259
        );
        assert_eq!(
            meta(&connection, grouped.path(), "archive_display_name").unwrap(),
            "Batch 84"
        );
        assert_eq!(
            connection
                .query_row("SELECT applied_seq FROM projection_origins", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            258
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM operation_outcomes WHERE operation_key='operation_85'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        drop(connection);
        // Direct construction may retain its failed output, but that file
        // must never become a usable projection with indexes still deferred.
        let unfinished_path = archive.join("unfinished.db");
        assert!(V2ProjectionDb::create_from_store(&store, &unfinished_path).is_err());
        let unfinished = Connection::open(&unfinished_path).unwrap();
        assert_eq!(
            unfinished
                .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .unwrap(),
            0
        );
        drop(unfinished);
        assert!(V2ProjectionDb::open_existing(&unfinished_path)
            .unwrap_err()
            .to_string()
            .contains("unsupported SQLite schema 0"));
        let before = fs::read(&installed).unwrap();
        assert!(V2ProjectionDb::rebuild(&store, &installed).is_err());
        assert_eq!(fs::read(&installed).unwrap(), before);
        assert!(!fs::read_dir(&archive).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".archive-ledger-rebuild-")));
    }

    #[test]
    fn incremental_group_failure_resumes_without_duplicate_effects() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &path).unwrap();
        let expected_path = archive.join("uninterrupted.db");
        fs::copy(&path, &expected_path).unwrap();
        for index in 0..87 {
            append_projection_items(
                &store,
                vec![json!({
                    "kind":"archive_updated", "archive_id":"arc_test",
                    "archive_display_name":format!("Batch {index}"),
                    "operation_key":format!("operation_{index}"),
                })],
            );
        }
        let database = V2ProjectionDb::open_existing(&path).unwrap();
        // Fail partway through the second group, after a complete batch in that
        // group has changed both domain rows and its origin cursor.
        database
            .open()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_replay BEFORE INSERT ON records
             WHEN NEW.origin_seq = 263 BEGIN SELECT RAISE(ABORT, 'test interruption'); END;",
            )
            .unwrap();
        assert!(database
            .apply(&store)
            .unwrap_err()
            .to_string()
            .contains("test interruption"));
        let connection = database.open().unwrap();
        assert_eq!(count(&connection, &path, "records", None).unwrap(), 259);
        assert_eq!(
            meta(&connection, &path, "archive_display_name").unwrap(),
            "Batch 84"
        );
        assert_eq!(
            connection
                .query_row("SELECT applied_seq FROM projection_origins", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            258
        );
        assert_ne!(
            meta(&connection, &path, "applied_frontier_hash").unwrap(),
            meta(&connection, &path, "accepted_frontier_hash").unwrap()
        );
        connection
            .execute_batch("DROP TRIGGER fail_replay;")
            .unwrap();
        drop(connection);

        // Reopen as a new process would. Sequence 259 was already durable but its
        // batch was incomplete; replay must recognize it and finish once.
        let database = V2ProjectionDb::open_existing(&path).unwrap();
        let resumed = database.apply(&store).unwrap();
        assert_eq!(resumed.records_applied, 6);
        assert!(resumed.caught_up);
        assert_eq!(database.apply(&store).unwrap().records_applied, 0);
        let expected = V2ProjectionDb::open_existing(&expected_path).unwrap();
        expected.apply(&store).unwrap();
        let connection = database.open().unwrap();
        let expected = expected.open().unwrap();
        let schema = "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name";
        let read_schema = |db: &Connection| {
            db.prepare(schema)
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        let expected_schema = read_schema(&expected);
        assert_eq!(read_schema(&connection), expected_schema);
        for (kind, name, _, _) in expected_schema {
            if (kind == "table" && !COMPACT_TABLES.contains(&name.as_str())) || kind == "view" {
                assert_eq!(
                    projection_rows(&connection, &name),
                    projection_rows(&expected, &name),
                    "table {name}"
                );
            }
        }
        assert_eq!(
            connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert!(!connection
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap());
    }

    #[test]
    fn rejects_old_schema() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("old.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 5;")
            .unwrap();
        drop(connection);
        let error = V2ProjectionDb::open_existing(path).unwrap_err();
        assert!(error
            .to_string()
            .contains("Run archive db rebuild to rebuild from the existing canonical records"));
    }

    #[test]
    fn replay_failure_reports_record_and_item_and_allows_retry() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &path).unwrap();
        let database = V2ProjectionDb::open_existing(&path).unwrap();
        let before = database.status().unwrap();
        append_projection_items(
            &store,
            vec![json!({
                "kind": "archive_updated", "archive_id": "arc_test",
                "archive_display_name": "private-bound-name"
            })],
        );
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_update BEFORE UPDATE ON archive_meta
            WHEN OLD.key='archive_display_name' BEGIN SELECT RAISE(ABORT,'injected failure'); END;",
            )
            .unwrap();
        let error = database.apply(&store).unwrap_err();
        assert_eq!(error.code(), "v2_projection_sqlite");
        let message = error.to_string();
        assert!(message.contains("sequence=5"), "{message}");
        assert!(message.contains("batch item index=0"), "{message}");
        assert!(message.contains("main.max_page_count"), "{message}");
        assert!(message.contains("projection callsite="), "{message}");
        assert!(!message.contains("private-bound-name"));
        // A failed apply intentionally leaves accepted ahead of applied, so inspect
        // the retained facts directly rather than asking for a caught-up status.
        assert_eq!(
            meta(&connection, &path, "archive_display_name").unwrap(),
            before.archive_name
        );
        assert_eq!(
            meta(&connection, &path, "applied_frontier_hash").unwrap(),
            before.applied_frontier_hash
        );
        connection
            .execute_batch("DROP TRIGGER fail_update")
            .unwrap();
        database.apply(&store).unwrap();
        assert_eq!(
            database.status().unwrap().archive_name,
            "private-bound-name"
        );
    }

    #[test]
    fn incrementally_applies_only_records_after_the_persisted_cursor() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let database_path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &database_path).unwrap();
        store
            .append_batch(
                "archive_update",
                1,
                json!({"archive_id": "arc_test"}),
                json!({}),
                vec![json!({
                    "kind": "archive_updated",
                    "archive_id": "arc_test",
                    "archive_display_name": "Family"
                })],
            )
            .unwrap();
        store
            .append_batch(
                "archive_update",
                1,
                json!({"archive_id": "arc_test"}),
                json!({}),
                vec![json!({
                    "kind": "archive_updated",
                    "archive_id": "arc_test",
                    "archive_display_name": "Family Archive"
                })],
            )
            .unwrap();

        let database = V2ProjectionDb::open_existing(database_path).unwrap();
        let mut progress = Vec::new();
        let first = database
            .apply_with_progress(
                &store,
                Some(&mut |event| {
                    if let V2ApplyProgress::Applying {
                        records_applied,
                        total_records,
                    } = event
                    {
                        assert_eq!(total_records, 6);
                        // A separate connection can see every reported record: callbacks
                        // must never advertise uncommitted progress.
                        let visible: i64 = database
                            .open()
                            .unwrap()
                            .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
                            .unwrap();
                        assert_eq!(visible as u64, 3 + records_applied);
                    }
                    progress.push(event);
                }),
            )
            .unwrap();
        assert_eq!(progress.first(), Some(&V2ApplyProgress::Verifying));
        assert_eq!(progress.last(), Some(&V2ApplyProgress::Finalizing));
        assert_eq!(
            &progress[1..progress.len() - 1],
            &[V2ApplyProgress::Applying {
                records_applied: 6,
                total_records: 6,
            }]
        );
        assert_eq!(first.records_applied, 6);
        assert_eq!(first.origins_advanced, 1);
        let status = database.status().unwrap();
        assert_eq!(status.archive_name, "Family Archive");
        assert_eq!(status.records, 9);
        progress.clear();
        let second = database
            .apply_with_progress(&store, Some(&mut |event| progress.push(event)))
            .unwrap();
        assert_eq!(
            progress,
            vec![
                V2ApplyProgress::Verifying,
                V2ApplyProgress::Applying {
                    records_applied: 0,
                    total_records: 0
                },
                V2ApplyProgress::Finalizing,
            ]
        );
        assert_eq!(second.records_applied, 0);
        assert_eq!(second.origins_advanced, 0);
    }

    #[test]
    fn incremental_apply_resumes_after_durable_chunk_without_advancing_cursor() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let database_path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &database_path).unwrap();
        store
            .append_batch(
                "archive_update",
                1,
                json!({"archive_id": "arc_test"}),
                json!({}),
                vec![json!({
                    "kind": "archive_updated",
                    "archive_id": "arc_test",
                    "archive_display_name": "Resumable"
                })],
            )
            .unwrap();
        let verified = store.verify().unwrap();
        let verification_context = V2VerificationContext::from(&verified);
        let new_records: Vec<_> = verified
            .records
            .iter()
            .filter(|record| record.record.envelope.origin_seq >= 4)
            .take(2)
            .collect();
        let database = V2ProjectionDb::open_existing(&database_path).unwrap();
        let mut connection = database.open().unwrap();
        for record in new_records {
            let transaction = connection.transaction().unwrap();
            assert!(insert_record(&transaction, record, &database_path).unwrap());
            match record.record.envelope.record_kind {
                V2RecordKind::BatchStart => {
                    project_batch_start(&transaction, record, &database_path).unwrap()
                }
                V2RecordKind::BatchChunk => {
                    project_batch_chunk(&transaction, record, &verification_context, &database_path)
                        .unwrap()
                }
                V2RecordKind::BatchComplete => unreachable!(),
            }
            transaction.commit().unwrap();
        }
        drop(connection);

        let mut progress = Vec::new();
        let stats = database
            .apply_with_progress(
                &store,
                Some(&mut |event| {
                    if let V2ApplyProgress::Applying {
                        records_applied,
                        total_records,
                    } = event
                    {
                        assert_eq!(total_records, 3);
                        let visible: i64 = database
                            .open()
                            .unwrap()
                            .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
                            .unwrap();
                        // The first two records were durable before this resume, but
                        // count as revisited work until the batch cursor advances.
                        assert_eq!(visible as u64, 3 + records_applied.max(2));
                    }
                    progress.push(event);
                }),
            )
            .unwrap();
        assert_eq!(
            progress,
            vec![
                V2ApplyProgress::Verifying,
                V2ApplyProgress::Applying {
                    records_applied: 3,
                    total_records: 3
                },
                V2ApplyProgress::Finalizing,
            ]
        );
        assert_eq!(stats.records_applied, 3);
        let status = database.status().unwrap();
        assert_eq!(status.archive_name, "Resumable");
        assert_eq!(status.records, 6);
    }

    #[test]
    fn incrementally_projects_an_enrolled_clients_new_origin() {
        let temp = TempDir::new().unwrap();
        let primary = temp.path().join("primary");
        let replica = temp.path().join("replica");
        initialize_v2_archive(&primary, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let primary_store = V2OriginStore::open(primary.join("canonical")).unwrap();
        V2ProjectionDb::create_from_store(&primary_store, primary.join("archive.db")).unwrap();
        copy_tree(&primary, &replica);

        let request = V2OriginStore::open(replica.join("canonical"))
            .unwrap()
            .prepare_enrollment("Laptop")
            .unwrap();
        primary_store.approve_enrollment(&request).unwrap();
        V2ProjectionDb::open_existing(primary.join("archive.db"))
            .unwrap()
            .apply(&primary_store)
            .unwrap();

        fs::remove_dir_all(replica.join("canonical")).unwrap();
        copy_tree(&primary.join("canonical"), &replica.join("canonical"));
        fs::copy(primary.join("archive.db"), replica.join("archive.db")).unwrap();
        let replica_store = V2OriginStore::open(replica.join("canonical")).unwrap();
        replica_store
            .append_batch(
                "job_start",
                1,
                json!({}),
                json!({}),
                vec![json!({
                    "kind": "job_started",
                    "job_id": "job_laptop",
                    "job_type": "test",
                    "input_version": "v1",
                    "params": {}
                })],
            )
            .unwrap();

        let replica_db = V2ProjectionDb::open_existing(replica.join("archive.db")).unwrap();
        let applied = replica_db.apply(&replica_store).unwrap();
        assert_eq!(applied.origins_advanced, 1);
        assert_eq!(replica_db.status().unwrap().origins, 2);
        let connection = replica_db.open().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM jobs WHERE job_id = 'job_laptop'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "running"
        );
        drop(connection);
        let rebuilt_path = replica.join("rebuilt.db");
        V2ProjectionDb::rebuild(&replica_store, &rebuilt_path).unwrap();
        let rebuilt = V2ProjectionDb::open_existing(rebuilt_path).unwrap();
        let rebuilt_status = rebuilt.validate_against_store(&replica_store).unwrap();
        let incremental_status = replica_db.validate_against_store(&replica_store).unwrap();
        assert_eq!(rebuilt_status.records, incremental_status.records);
        assert_eq!(rebuilt_status.origins, incremental_status.origins);
        assert_eq!(
            rebuilt_status.accepted_frontier_hash,
            incremental_status.accepted_frontier_hash
        );

        replica_store
            .append_batch(
                "archive_update",
                1,
                json!({"archive_id": "arc_test"}),
                json!({}),
                vec![json!({
                    "kind": "archive_updated",
                    "archive_id": "arc_test",
                    "archive_display_name": "Uncoordinated"
                })],
            )
            .unwrap();
        let error = replica_db.apply(&replica_store).unwrap_err();
        assert!(error.to_string().contains("lacks a scoped remote lease"));
    }

    #[test]
    fn concurrent_file_identities_remain_an_explicit_rebuildable_conflict() {
        let temp = TempDir::new().unwrap();
        let primary = temp.path().join("primary");
        let replica = temp.path().join("replica");
        let remote = temp.path().join("central.git");
        fs::create_dir(&remote).unwrap();
        git_success(&remote, &["init", "--bare", "--quiet"]);
        initialize_v2_archive(&primary, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let primary_store = V2OriginStore::open(primary.join("canonical")).unwrap();
        let primary_db_path = primary.join("archive.db");
        V2ProjectionDb::create_from_store(&primary_store, &primary_db_path).unwrap();
        let primary_db = V2ProjectionDb::open_existing(&primary_db_path).unwrap();
        let registry = V2Registry::new(&primary_store, &primary_db);
        registry
            .record(
                RegistryChange::Site(
                    RegistryAction::Register,
                    SiteSnapshot {
                        site_id: "site_home".to_owned(),
                        display_name: "Home".to_owned(),
                        site_kind: "home".to_owned(),
                        description: None,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::Device(
                    RegistryAction::Register,
                    DeviceSnapshot {
                        device_id: "device_main".to_owned(),
                        display_name: "Main".to_owned(),
                        device_kind: "computer".to_owned(),
                        serial_hint: None,
                        hardware_fingerprint: None,
                        fingerprint_kind: None,
                        identity_state: "unavailable".to_owned(),
                        owner: None,
                        status: "active".to_owned(),
                        current_site_id: Some("site_home".to_owned()),
                        expected_availability: "online".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::ArchiveRoot(
                    RegistryAction::Register,
                    ArchiveRootSnapshot {
                        archive_root_id: "root_main".to_owned(),
                        device_id: "device_main".to_owned(),
                        display_name: "Main root".to_owned(),
                        root_path_on_device: RegistryPath::utf8("/"),
                        status: "active".to_owned(),
                        filesystem_fingerprint: None,
                        fingerprint_kind: None,
                        identity_state: "unavailable".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::Location(
                    RegistryAction::Register,
                    LocationSnapshot {
                        location_id: "location_main".to_owned(),
                        display_name: "Files on Main".to_owned(),
                        kind: "filesystem".to_owned(),
                        archive_root_id: Some("root_main".to_owned()),
                        relative_path: Some(RegistryPath::utf8("files")),
                        device_id: Some("device_main".to_owned()),
                        site_id: None,
                        encryption_state: Some("unknown".to_owned()),
                        trust_level: Some("trusted".to_owned()),
                        expected_availability: "online".to_owned(),
                        is_writable: true,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::Collection(
                    RegistryAction::Register,
                    CollectionSnapshot {
                        collection_id: "collection_files".to_owned(),
                        display_name: "Files".to_owned(),
                        description: None,
                        home_site_id: Some("site_home".to_owned()),
                        policy_id: None,
                        status: "active".to_owned(),
                    },
                ),
                "desktop",
            )
            .unwrap();
        primary_store
            .add_sync_remote("central", remote.to_str().unwrap())
            .unwrap();
        primary_store.sync_remote("central").unwrap();

        fs::create_dir(&replica).unwrap();
        let cloned = Command::new("git")
            .args(["clone", "--quiet", "--branch", "archive-ledger"])
            .arg(&remote)
            .arg(replica.join("canonical"))
            .output()
            .unwrap();
        assert!(cloned.status.success());
        fs::copy(&primary_db_path, replica.join("archive.db")).unwrap();
        let replica_store = V2OriginStore::open(replica.join("canonical")).unwrap();
        let request = replica_store.prepare_enrollment("Laptop").unwrap();
        primary_store.approve_enrollment(&request).unwrap();
        primary_db.apply(&primary_store).unwrap();
        primary_store.sync_remote("central").unwrap();
        replica_store.sync_remote("origin").unwrap();
        let replica_db = V2ProjectionDb::open_existing(replica.join("archive.db")).unwrap();
        replica_db.apply(&replica_store).unwrap();

        let content_item = |bytes: &[u8], copy_claim_id: &str| {
            let hash = blake3::hash(bytes).to_hex().to_string();
            json!({
                "kind": "content_observed",
                "collection_id": "collection_files",
                "location_id": "location_main",
                "logical_path": RegistryPath::utf8("same.txt"),
                "copy_path": RegistryPath::utf8("same.txt"),
                "file_ref_id": "file_same",
                "copy_claim_id": copy_claim_id,
                "object_id": format!("blake3:{hash}"),
                "blake3_hex": hash,
                "size_bytes": bytes.len(),
                "observed_time_utc_ms": 1_782_000_001_000_u64,
                "device_fingerprint_status": "unavailable",
                "representation": "ordinary_file"
            })
        };
        primary_store
            .append_batch(
                "inventory_add",
                1,
                json!({}),
                json!({}),
                vec![content_item(b"desktop", "copy_desktop")],
            )
            .unwrap();
        primary_db.apply(&primary_store).unwrap();
        replica_store
            .append_batch(
                "inventory_add",
                1,
                json!({}),
                json!({}),
                vec![content_item(b"laptop", "copy_laptop")],
            )
            .unwrap();
        replica_store.sync_remote("origin").unwrap();
        primary_store.sync_remote("central").unwrap();
        primary_db.apply(&primary_store).unwrap();

        let connection = primary_db.open().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM fact_conflicts WHERE state = 'unresolved'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT identity_state FROM file_refs WHERE file_ref_id = 'file_same'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "conflict"
        );
        drop(connection);
        let rebuilt_path = primary.join("conflict-rebuilt.db");
        V2ProjectionDb::rebuild(&primary_store, &rebuilt_path).unwrap();
        let rebuilt = Connection::open(rebuilt_path).unwrap();
        assert_eq!(
            rebuilt
                .query_row("SELECT COUNT(*) FROM fact_conflicts", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }
}
