use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use fs2::available_space;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;

use crate::discovery::{EncodedPath, PathEncoding};
use crate::event_store::{
    EventCursor, EventReadStats, EventRecord, EventStore, EventStoreError, PositionedEvent,
};
use crate::policy::PolicyRequirements;
use crate::registry::{
    ArchiveRootSnapshot, CollectionSnapshot, DeviceSnapshot, LocationSnapshot, PolicySnapshot,
    RegistryPath, RiskAssignment, RiskDomainSnapshot, SiteSnapshot,
};

const SCHEMA_VERSION: u32 = 4;
const STREAM_ID: &str = "stream_primary";
const SCHEMA_V4: &str = include_str!("schema_v4.sql");

pub type Result<T> = std::result::Result<T, ProjectionError>;

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error(transparent)]
    EventStore(#[from] EventStoreError),

    #[error("SQLite operation failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported SQLite schema version {actual}; expected {expected}")]
    UnsupportedSchema { actual: String, expected: u32 },

    #[error("archive identity mismatch: database has {actual}, requested {expected}")]
    ArchiveIdentityMismatch { actual: String, expected: String },

    #[error("unsupported canonical event type {0}")]
    UnsupportedEventType(String),

    #[error("invalid {event_type} payload at sequence {seq}: {message}")]
    InvalidPayload {
        event_type: String,
        seq: u64,
        message: String,
    },

    #[error("operation key {operation_key} is already associated with event {event_id}")]
    DuplicateOperationKey {
        operation_key: String,
        event_id: String,
    },

    #[error("SQLite projection cursor is invalid: {0}")]
    InvalidCursor(String),

    #[error("invalid annex import topology: {0}")]
    InvalidAnnexTopology(String),

    #[error("invalid scan state: {0}")]
    InvalidScan(String),

    #[error("rebuilt database failed integrity_check: {0}")]
    IntegrityCheck(String),
}

impl ProjectionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EventStore(error) => error.code(),
            Self::Sqlite { .. } => "projection_sqlite",
            Self::Io { .. } => "projection_io",
            Self::UnsupportedSchema { .. } => "unsupported_schema",
            Self::ArchiveIdentityMismatch { .. } => "archive_identity_mismatch",
            Self::UnsupportedEventType(_) => "unsupported_event_type",
            Self::InvalidPayload { .. } => "invalid_event_payload",
            Self::DuplicateOperationKey { .. } => "duplicate_operation_key",
            Self::InvalidCursor(_) => "invalid_projection_cursor",
            Self::InvalidAnnexTopology(_) => "invalid_annex_topology",
            Self::InvalidScan(_) => "invalid_scan_state",
            Self::IntegrityCheck(_) => "sqlite_integrity_failure",
        }
    }
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> ProjectionError {
    ProjectionError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> ProjectionError {
    ProjectionError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[derive(Debug, Clone)]
pub struct ProjectionConfig {
    pub batch_events: usize,
    pub batch_bytes: usize,
    pub busy_timeout: Duration,
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self {
            batch_events: 1_000,
            batch_bytes: 16 * 1024 * 1024,
            busy_timeout: Duration::from_secs(5),
        }
    }
}

impl ProjectionConfig {
    fn validate(&self) -> Result<()> {
        if self.batch_events == 0 || self.batch_bytes == 0 {
            return Err(ProjectionError::InvalidCursor(
                "projection batch limits must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionStatus {
    pub archive_id: String,
    pub schema_version: u32,
    pub stream_id: String,
    pub cursor: EventCursor,
    pub policy_input_event_seq: u64,
    pub last_verified_checkpoint_id: Option<String>,
    pub last_verified_checkpoint_seq: u64,
    pub catalog_location_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyStats {
    pub transactions: u64,
    pub events_applied: u64,
    pub segments_opened: u64,
    pub lines_read: u64,
    pub caught_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationFreshness {
    pub location_id: String,
    pub latest_scan_id: Option<String>,
    pub latest_scan_status: Option<String>,
    pub last_complete_scan_id: Option<String>,
    pub last_complete_scan_time_utc_ms: Option<u64>,
    pub scan_error_count: u64,
    pub device_id: Option<String>,
    pub device_status: Option<String>,
    pub device_identity_state: Option<String>,
    pub expected_availability: String,
    pub latest_mount_status: Option<String>,
    pub availability: String,
    pub last_device_checkin_time_utc_ms: Option<u64>,
    pub last_fingerprint_status: Option<String>,
    pub uncertainty: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanKnownEntry {
    pub file_ref_id: String,
    pub copy_claim_id: Option<String>,
    pub path_state: String,
    pub copy_state: Option<String>,
    pub size_bytes: Option<u64>,
    pub modified_time_utc_ms: Option<u64>,
    pub has_effective_missing_candidate: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanMissingTarget {
    pub kind: String,
    pub target_id: String,
    pub file_ref_id: Option<String>,
    pub copy_claim_id: Option<String>,
    pub path: EncodedPath,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanMissingCursor {
    path_encoding: String,
    path_bytes: Vec<u8>,
    kind: String,
    target_id: String,
}

impl ScanMissingTarget {
    pub(crate) fn cursor(&self) -> ScanMissingCursor {
        ScanMissingCursor {
            path_encoding: self.path.encoding.as_str().to_owned(),
            path_bytes: self.path.bytes.clone(),
            kind: self.kind.clone(),
            target_id: self.target_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ScanSeenPath {
    pub item_key: String,
    pub path: EncodedPath,
    pub file_ref_id: Option<String>,
    pub copy_claim_id: Option<String>,
}

pub(crate) struct ScanProjectionSession {
    connection: Connection,
    path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScanCompletionManifest {
    pub observations_count: u64,
    pub observations_digest: String,
    pub missing_candidate_count: u64,
    pub missing_candidate_digest: String,
    pub missing_path_count: u64,
}

const COMPLETION_MIN_FREE_BYTES: u64 = 8 * 1024 * 1024;
const COMPLETION_ESTIMATED_BYTES_PER_ROW: u64 = 256;

#[derive(Debug, Clone)]
pub struct ProjectionDb {
    path: PathBuf,
    config: ProjectionConfig,
}

macro_rules! event_catalog {
    ($($event_type:literal => $policy_relevant:literal),+ $(,)?) => {
        pub const SUPPORTED_EVENT_TYPES: &[&str] = &[$($event_type),+];

        fn policy_relevance(event_type: &str) -> Option<bool> {
            match event_type {
                $($event_type => Some($policy_relevant),)+
                _ => None,
            }
        }
    };
}

event_catalog! {
    "archive_initialized" => false,
    "catalog_location_set" => false,
    "checkpoint_created" => false,
    "checkpoint_commit_observed" => false,
    "checkpoint_replication_observed" => false,
    "collection_registered" => true,
    "collection_updated" => true,
    "collection_retired" => true,
    "site_registered" => true,
    "site_updated" => true,
    "site_retired" => true,
    "device_registered" => true,
    "device_updated" => true,
    "device_moved" => true,
    "device_checked_in" => true,
    "device_retired" => true,
    "device_mount_observed" => true,
    "archive_root_registered" => true,
    "archive_root_updated" => true,
    "archive_root_retired" => true,
    "location_registered" => true,
    "location_updated" => true,
    "location_retired" => true,
    "metadata_destination_registered" => false,
    "metadata_destination_updated" => false,
    "metadata_destination_retired" => false,
    "risk_domain_registered" => true,
    "risk_domain_updated" => true,
    "risk_domain_retired" => true,
    "risk_assigned" => true,
    "risk_unassigned" => true,
    "policy_registered" => true,
    "policy_updated" => true,
    "policy_retired" => true,
    "external_identity_observed" => true,
    "external_identity_resolved" => true,
    "external_availability_observed" => true,
    "annex_remote_mapped" => true,
    "annex_remote_unmapped" => true,
    "object_observed" => true,
    "object_hash_added" => true,
    "file_ref_observed" => true,
    "file_ref_updated" => true,
    "file_ref_removed" => true,
    "path_observed" => true,
    "path_missing_candidate" => false,
    "copy_observed" => true,
    "copy_missing_candidate" => false,
    "scan_started" => false,
    "scan_completed" => true,
    "copy_verified" => true,
    "job_started" => false,
    "job_finished" => false,
    "annex_import_started" => false,
    "annex_import_completed" => false,
}

impl ProjectionDb {
    pub fn open_existing(path: impl AsRef<Path>, config: ProjectionConfig) -> Result<Self> {
        config.validate()?;
        let path = path.as_ref().to_path_buf();
        fs::metadata(&path).map_err(|source| io_error("open database", &path, source))?;
        let database = Self { path, config };
        let connection = database.open_connection()?;
        let archive_id = meta_required(&connection, "archive_id")
            .map_err(|source| sqlite_error(&database.path, source))?;
        database.validate_identity(&connection, &archive_id)?;
        validate_status(
            &connection,
            &read_status(&connection).map_err(|source| sqlite_error(&database.path, source))?,
            &database.path,
        )?;
        Ok(database)
    }

    pub fn open_or_create(
        path: impl AsRef<Path>,
        archive_id: &str,
        config: ProjectionConfig,
    ) -> Result<Self> {
        config.validate()?;
        if archive_id.is_empty() {
            return Err(ProjectionError::InvalidCursor(
                "archive_id must be non-empty".to_owned(),
            ));
        }
        let path = path.as_ref().to_path_buf();
        let parent = parent_directory(&path);
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create database directory", parent, source))?;
        let database = Self { path, config };
        let connection = database.open_connection()?;
        let initialized: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'archive_meta')",
                [],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&database.path, source))?;
        if !initialized {
            let transaction = connection
                .unchecked_transaction()
                .map_err(|source| sqlite_error(&database.path, source))?;
            transaction
                .execute_batch(SCHEMA_V4)
                .map_err(|source| sqlite_error(&database.path, source))?;
            initialize_meta(&transaction, archive_id)
                .map_err(|source| sqlite_error(&database.path, source))?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(&database.path, source))?;
        }
        database.validate_identity(&connection, archive_id)?;
        Ok(database)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn status(&self) -> Result<ProjectionStatus> {
        let connection = self.open_connection()?;
        let status = read_status(&connection).map_err(|source| sqlite_error(&self.path, source))?;
        validate_status(&connection, &status, &self.path)?;
        Ok(status)
    }

    pub fn has_operation_key(&self, operation_key: &str) -> Result<bool> {
        let connection = self.open_connection()?;
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_outcomes WHERE operation_key = ?1)",
                [operation_key],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub fn validate_annex_topology(
        &self,
        collection_id: &str,
        worktree_location_id: &str,
        cas_location_id: &str,
        device_id: &str,
        archive_root_id: &str,
    ) -> Result<()> {
        let connection = self.open_connection()?;
        let collection_ok: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM collections
                    WHERE collection_id = ?1 AND status = 'active'
                 )",
                [collection_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if !collection_ok {
            return Err(ProjectionError::InvalidAnnexTopology(format!(
                "annex collection {collection_id} is not active"
            )));
        }
        for (kind, location_id) in [("worktree", worktree_location_id), ("CAS", cas_location_id)] {
            let valid: bool = connection
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1
                        FROM locations l
                        JOIN archive_roots r ON r.archive_root_id = l.archive_root_id
                        JOIN devices d ON d.device_id = l.device_id
                        WHERE l.location_id = ?1
                          AND l.kind = 'filesystem'
                          AND l.status = 'active'
                          AND r.status = 'active'
                          AND d.status = 'active'
                          AND l.device_id = ?2
                          AND r.device_id = ?2
                          AND l.archive_root_id = ?3
                    )",
                    params![location_id, device_id, archive_root_id],
                    |row| row.get(0),
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
            if !valid {
                return Err(ProjectionError::InvalidAnnexTopology(format!(
                    "annex {kind} location {location_id} does not match active root {archive_root_id} and device {device_id}"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn external_identity_id(
        &self,
        namespace: &str,
        external_key: &str,
    ) -> Result<Option<String>> {
        let connection = self.open_connection()?;
        connection
            .query_row(
                "SELECT external_identity_id FROM external_identities
                 WHERE namespace = ?1 AND external_key = ?2",
                params![namespace, external_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn annex_remote_location(
        &self,
        source_annex_uuid: &str,
        remote_annex_uuid: &str,
    ) -> Result<Option<String>> {
        let connection = self.open_connection()?;
        connection
            .query_row(
                "SELECT location_id FROM annex_remotes
                 WHERE source_annex_uuid = ?1 AND remote_annex_uuid = ?2",
                params![source_annex_uuid, remote_annex_uuid],
                |row| row.get(0),
            )
            .optional()
            .map(|row| row.flatten())
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn annex_inventory_counts(
        &self,
        collection_id: &str,
        source_repo_id: &str,
    ) -> Result<(u64, u64)> {
        let connection = self.open_connection()?;
        let duplicate_paths: i64 = connection
            .query_row(
                "SELECT COALESCE(SUM(path_count - 1), 0)
                 FROM (
                    SELECT COUNT(*) AS path_count
                    FROM file_refs
                    WHERE collection_id = ?1 AND path_state = 'active'
                      AND external_identity_id IS NOT NULL
                    GROUP BY external_identity_id
                    HAVING COUNT(*) > 1
                 )",
                [collection_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        let availability_facts: i64 = connection
            .query_row(
                "SELECT COUNT(*)
                 FROM external_availability a
                 WHERE a.source_repo_id = ?2
                   AND EXISTS (
                       SELECT 1 FROM file_refs f
                       WHERE f.collection_id = ?1
                         AND f.external_identity_id = a.external_identity_id
                   )",
                params![collection_id, source_repo_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok((
            u64::try_from(duplicate_paths).unwrap_or(0),
            u64::try_from(availability_facts).unwrap_or(0),
        ))
    }

    pub(crate) fn annex_import_source_fingerprint(
        &self,
        import_id: &str,
    ) -> Result<Option<String>> {
        let connection = self.open_connection()?;
        connection
            .query_row(
                "SELECT json_extract(e.payload_json, '$.source_fingerprint')
                 FROM annex_imports i
                 JOIN events e ON e.event_id = i.started_event_id
                 WHERE i.import_id = ?1",
                [import_id],
                |row| row.get(0),
            )
            .optional()
            .map(|row| row.flatten())
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn validate_scan_topology(
        &self,
        collection_id: &str,
        location_id: &str,
        device_id: &str,
        archive_root_id: &str,
    ) -> Result<()> {
        let connection = self.open_connection()?;
        let valid: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM collections c
                    JOIN locations l ON l.location_id = ?2
                    JOIN archive_roots r ON r.archive_root_id = l.archive_root_id
                    JOIN devices d ON d.device_id = l.device_id
                    WHERE c.collection_id = ?1 AND c.status = 'active'
                      AND l.kind = 'filesystem' AND l.status = 'active'
                      AND r.status = 'active' AND d.status = 'active'
                      AND l.device_id = ?3 AND r.device_id = ?3
                      AND l.archive_root_id = ?4
                      AND d.identity_state != 'conflict'
                 )",
                params![collection_id, location_id, device_id, archive_root_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if !valid {
            return Err(ProjectionError::InvalidScan(format!(
                "collection {collection_id} and location {location_id} do not match active root {archive_root_id} and device {device_id}"
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_scan_scope_available(
        &self,
        scan_id: &str,
        job_id: &str,
        location_id: &str,
        collection_id: &str,
        scope_json: &str,
        exclusions_hash: &str,
    ) -> Result<()> {
        let connection = self.open_connection()?;
        let existing: Option<(String, String, String, String, String)> = connection
            .query_row(
                "SELECT COALESCE(job_id, ''), location_id, collection_id, scope_json, exclusions_hash
                 FROM scan_runs WHERE scan_id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        if let Some(existing) = existing {
            if existing
                != (
                    job_id.to_owned(),
                    location_id.to_owned(),
                    collection_id.to_owned(),
                    scope_json.to_owned(),
                    exclusions_hash.to_owned(),
                )
            {
                return Err(ProjectionError::InvalidScan(format!(
                    "scan {scan_id} cannot resume with changed job, source, scope, or exclusions"
                )));
            }
        }
        let conflicting: Option<String> = connection
            .query_row(
                "SELECT scan_id FROM scan_runs
                 WHERE location_id = ?1 AND collection_id = ?2 AND scope_json = ?3
                   AND status = 'running' AND scan_id != ?4",
                params![location_id, collection_id, scope_json, scan_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?;
        if let Some(conflicting) = conflicting {
            return Err(ProjectionError::InvalidScan(format!(
                "scan {conflicting} is already running for this scope"
            )));
        }
        Ok(())
    }

    pub(crate) fn scan_run_status(&self, scan_id: &str) -> Result<Option<String>> {
        let connection = self.open_connection()?;
        connection
            .query_row(
                "SELECT status FROM scan_runs WHERE scan_id = ?1",
                [scan_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn scan_has_interleaved_events(&self, scan_id: &str) -> Result<bool> {
        let connection = self.open_connection()?;
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM scan_runs s
                    JOIN events e ON e.seq > s.started_event_seq
                    JOIN file_refs f ON f.file_ref_id = e.file_ref_id
                    WHERE s.scan_id = ?1
                      AND e.event_type IN ('path_observed', 'copy_observed')
                      AND e.location_id = s.location_id
                      AND f.collection_id = s.collection_id
                      AND COALESCE(json_extract(e.payload_json, '$.scan_id'), '') != s.scan_id
                 )",
                [scan_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn scan_change_counts(&self, scan_id: &str) -> Result<(u64, u64)> {
        let connection = self.open_connection()?;
        let (new_paths, changed_paths): (i64, i64) = connection
            .query_row(
                "SELECT
                    COALESCE(SUM(CASE WHEN p.first_seen_event_id = e.event_id THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN p.first_seen_event_id != e.event_id THEN 1 ELSE 0 END), 0)
                 FROM events e
                 JOIN path_observations p
                   ON p.file_ref_id = e.file_ref_id AND p.location_id = e.location_id
                  AND p.last_seen_event_id = e.event_id
                 WHERE e.event_type = 'path_observed'
                   AND json_extract(e.payload_json, '$.scan_id') = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok((
            u64::try_from(new_paths).unwrap_or(0),
            u64::try_from(changed_paths).unwrap_or(0),
        ))
    }

    pub(crate) fn prepare_scan_job(
        &self,
        job_id: &str,
        scan_id: &str,
        params_json: &str,
        now_utc_ms: u64,
    ) -> Result<()> {
        let connection = self.open_connection()?;
        connection
            .execute(
                "INSERT INTO jobs(
                    job_id, job_type, status, created_time_utc_ms, started_time_utc_ms,
                    params_json, input_version
                 ) VALUES (?1, 'scan', 'running', ?3, ?3, ?4, ?2)
                 ON CONFLICT(job_id) DO UPDATE SET
                    status = CASE WHEN jobs.status = 'running' THEN 'running' ELSE jobs.status END",
                params![
                    job_id,
                    scan_id,
                    i64::try_from(now_utc_ms).map_err(|_| ProjectionError::InvalidScan(
                        "scan time exceeds SQLite integer range".to_owned()
                    ))?,
                    params_json,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        let actual: String = connection
            .query_row(
                "SELECT input_version FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        if actual != scan_id {
            return Err(ProjectionError::InvalidScan(format!(
                "job {job_id} belongs to scan {actual}, not {scan_id}"
            )));
        }
        Ok(())
    }

    pub(crate) fn clear_scan_seen(&self, job_id: &str) -> Result<()> {
        let connection = self.open_connection()?;
        connection
            .execute(
                "DELETE FROM job_items WHERE job_id = ?1 AND item_type = 'scan_seen'",
                [job_id],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok(())
    }

    pub(crate) fn open_scan_session(&self) -> Result<ScanProjectionSession> {
        Ok(ScanProjectionSession {
            connection: self.open_connection()?,
            path: self.path.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_missing_targets_after(
        &self,
        scan_id: &str,
        job_id: &str,
        collection_id: &str,
        location_id: &str,
        exclusions_json: &str,
        after: Option<&ScanMissingCursor>,
        limit: usize,
    ) -> Result<Vec<ScanMissingTarget>> {
        if limit == 0 {
            return Err(ProjectionError::InvalidScan(
                "missing-target batch limit must be greater than zero".to_owned(),
            ));
        }
        let mut connection = self.open_connection()?;
        if after.is_none() {
            let transaction = connection
                .transaction()
                .map_err(|source| sqlite_error(&self.path, source))?;
            transaction
                .execute(
                    "DELETE FROM job_items
                     WHERE job_id = ?1
                       AND item_type IN ('scan_missing_path', 'scan_missing_copy')",
                    [job_id],
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
            transaction
                .execute(
                    "INSERT INTO job_items(
                        job_item_id, job_id, item_type, item_key, file_ref_id,
                        path_bytes, path_encoding, path_display, status, updated_time_utc_ms
                     )
                     SELECT 'scan-missing-path:' || ?2 || ':' || p.file_ref_id,
                            ?2, 'scan_missing_path', p.file_ref_id, p.file_ref_id,
                            p.observed_path_bytes, p.observed_path_encoding,
                            p.observed_path_display, 'pending',
                            (SELECT started_time_utc_ms FROM scan_runs WHERE scan_id = ?1)
                     FROM path_observations p
                     JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                     WHERE f.collection_id = ?3 AND f.path_state = 'active'
                       AND p.location_id = ?4 AND p.state = 'present'
                       AND NOT EXISTS (
                           SELECT 1 FROM job_items seen
                           WHERE seen.job_id = ?2 AND seen.item_type = 'scan_seen'
                             AND seen.path_encoding = p.observed_path_encoding
                             AND seen.path_bytes = p.observed_path_bytes
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM scan_missing_candidates candidate
                           WHERE candidate.scan_id = ?1
                             AND candidate.candidate_kind = 'path'
                             AND candidate.file_ref_id = p.file_ref_id
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM json_each(?5) x
                           WHERE upper(hex(p.observed_path_bytes)) = json_extract(x.value, '$.hex')
                              OR upper(hex(p.observed_path_bytes)) LIKE json_extract(x.value, '$.hex') || '2F%'
                       )",
                    params![scan_id, job_id, collection_id, location_id, exclusions_json],
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
            // Keep copy_claims as the outer loop. With a regular JOIN, SQLite
            // may scan every location path against every copy before applying
            // the path equality, which becomes quadratic on large locations.
            transaction
                .execute(
                    "INSERT INTO job_items(
                        job_item_id, job_id, item_type, item_key, copy_claim_id,
                        path_bytes, path_encoding, path_display, status, updated_time_utc_ms
                     )
                     SELECT DISTINCT 'scan-missing-copy:' || ?2 || ':' || c.copy_claim_id,
                            ?2, 'scan_missing_copy', c.copy_claim_id, c.copy_claim_id,
                            c.relative_path_bytes, c.relative_path_encoding,
                            c.relative_path_display, 'pending',
                            (SELECT started_time_utc_ms FROM scan_runs WHERE scan_id = ?1)
                     FROM copy_claims c
                     CROSS JOIN path_observations p
                       ON p.location_id = c.location_id
                      AND p.observed_path_encoding = c.relative_path_encoding
                      AND p.observed_path_bytes = c.relative_path_bytes
                     JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                     WHERE f.collection_id = ?3 AND f.path_state = 'active'
                       AND c.location_id = ?4 AND c.state IN ('present', 'corrupt', 'unknown')
                       AND NOT EXISTS (
                           SELECT 1 FROM job_items seen
                           WHERE seen.job_id = ?2 AND seen.item_type = 'scan_seen'
                             AND seen.path_encoding = c.relative_path_encoding
                             AND seen.path_bytes = c.relative_path_bytes
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM scan_missing_candidates candidate
                           WHERE candidate.scan_id = ?1
                             AND candidate.candidate_kind = 'copy'
                             AND candidate.copy_claim_id = c.copy_claim_id
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM json_each(?5) x
                           WHERE upper(hex(c.relative_path_bytes)) = json_extract(x.value, '$.hex')
                              OR upper(hex(c.relative_path_bytes)) LIKE json_extract(x.value, '$.hex') || '2F%'
                       )",
                    params![scan_id, job_id, collection_id, location_id, exclusions_json],
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(&self.path, source))?;
        }
        let mut statement = connection
            .prepare(
                "SELECT CASE item_type
                            WHEN 'scan_missing_path' THEN 'path' ELSE 'copy' END AS kind,
                        item_key, file_ref_id, copy_claim_id,
                        path_encoding, path_bytes, path_display
                 FROM job_items
                 WHERE job_id = ?1
                   AND item_type IN ('scan_missing_path', 'scan_missing_copy')
                   AND (?2 IS NULL
                     OR path_encoding > ?2
                     OR (path_encoding = ?2 AND path_bytes > ?3)
                     OR (path_encoding = ?2 AND path_bytes = ?3
                         AND item_type > 'scan_missing_' || ?4)
                     OR (path_encoding = ?2 AND path_bytes = ?3
                         AND item_type = 'scan_missing_' || ?4
                         AND item_key > ?5))
                 ORDER BY path_encoding, path_bytes, item_type, item_key
                 LIMIT ?6",
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        let rows = statement
            .query_map(
                params![
                    job_id,
                    after.map(|cursor| cursor.path_encoding.as_str()),
                    after.map(|cursor| cursor.path_bytes.as_slice()),
                    after.map(|cursor| cursor.kind.as_str()),
                    after.map(|cursor| cursor.target_id.as_str()),
                    i64::try_from(limit).unwrap_or(i64::MAX),
                ],
                |row| {
                    let encoding: String = row.get(4)?;
                    let bytes: Vec<u8> = row.get(5)?;
                    let display: String = row.get(6)?;
                    Ok(ScanMissingTarget {
                        kind: row.get(0)?,
                        target_id: row.get(1)?,
                        file_ref_id: row.get(2)?,
                        copy_claim_id: row.get(3)?,
                        path: EncodedPath {
                            encoding: parse_path_encoding(&encoding)?,
                            bytes,
                            display,
                        },
                    })
                },
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn scan_completion_manifest(&self, scan_id: &str) -> Result<ScanCompletionManifest> {
        let connection = self.open_connection()?;
        scan_completion_manifest(&connection, scan_id)
            .map_err(|error| map_transaction_error(&self.path, error))
    }

    pub(crate) fn preflight_scan_completion(
        &self,
        manifest: &ScanCompletionManifest,
    ) -> Result<()> {
        let connection = self.open_connection()?;
        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(|source| sqlite_error(&self.path, source))?;
        let page_size = u64::try_from(page_size).map_err(|_| {
            ProjectionError::InvalidScan("SQLite reported an invalid page size".to_owned())
        })?;
        let rows = manifest
            .observations_count
            .saturating_add(manifest.missing_candidate_count);
        let row_bytes = rows.saturating_mul(COMPLETION_ESTIMATED_BYTES_PER_ROW);
        let page_margin = page_size.saturating_mul(64);
        let required = COMPLETION_MIN_FREE_BYTES.max(row_bytes.saturating_add(page_margin));
        let parent = parent_directory(&self.path);
        let available = available_space(parent)
            .map_err(|source| io_error("check free space for scan completion", parent, source))?;
        if available < required {
            return Err(ProjectionError::InvalidScan(format!(
                "scan completion needs an estimated {required} bytes free beside the SQLite database, but only {available} bytes are available"
            )));
        }
        Ok(())
    }

    pub(crate) fn finish_scan_job(
        &self,
        job_id: &str,
        status: &str,
        progress_json: &str,
        now_utc_ms: u64,
    ) -> Result<()> {
        let connection = self.open_connection()?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute(
                "UPDATE jobs SET status = ?2, progress_json = ?3, finished_time_utc_ms = ?4
                 WHERE job_id = ?1",
                params![
                    job_id,
                    status,
                    progress_json,
                    i64::try_from(now_utc_ms).map_err(|_| ProjectionError::InvalidScan(
                        "scan time exceeds SQLite integer range".to_owned()
                    ))?,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .execute("DELETE FROM job_items WHERE job_id = ?1", [job_id])
            .map_err(|source| sqlite_error(&self.path, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok(())
    }

    pub fn location_freshness(&self, location_id: &str) -> Result<LocationFreshness> {
        let connection = self.open_connection()?;
        let mut freshness = connection
            .query_row(
                "SELECT l.location_id, l.device_id, d.status, d.identity_state,
                        l.expected_availability, mount.status,
                        d.last_checkin_time_utc_ms, d.last_fingerprint_status,
                        latest.scan_id, latest.status, latest.error_count,
                        complete.scan_id, complete.finished_time_utc_ms
                 FROM locations l
                 LEFT JOIN devices d ON d.device_id = l.device_id
                 LEFT JOIN device_mounts mount ON mount.mount_id = (
                    SELECT m.mount_id FROM device_mounts m WHERE m.device_id = l.device_id
                    ORDER BY m.observed_time_utc_ms DESC, m.mount_id DESC LIMIT 1
                 )
                 LEFT JOIN scan_runs latest ON latest.scan_id = (
                    SELECT s.scan_id FROM scan_runs s WHERE s.location_id = l.location_id
                    ORDER BY COALESCE(s.finished_time_utc_ms, s.started_time_utc_ms) DESC,
                             s.started_event_seq DESC LIMIT 1
                 )
                 LEFT JOIN scan_runs complete ON complete.scan_id = (
                    SELECT s.scan_id FROM scan_runs s
                    WHERE s.location_id = l.location_id AND s.status = 'complete'
                    ORDER BY s.finished_time_utc_ms DESC, s.started_event_seq DESC LIMIT 1
                 )
                 WHERE l.location_id = ?1",
                [location_id],
                |row| {
                    Ok(LocationFreshness {
                        location_id: row.get(0)?,
                        device_id: row.get(1)?,
                        device_status: row.get(2)?,
                        device_identity_state: row.get(3)?,
                        expected_availability: row.get(4)?,
                        latest_mount_status: row.get(5)?,
                        availability: "unknown".to_owned(),
                        last_device_checkin_time_utc_ms: optional_u64(row.get(6)?)?,
                        last_fingerprint_status: row.get(7)?,
                        latest_scan_id: row.get(8)?,
                        latest_scan_status: row.get(9)?,
                        scan_error_count: u64::try_from(
                            row.get::<_, Option<i64>>(10)?.unwrap_or(0).max(0),
                        )
                        .unwrap_or(0),
                        last_complete_scan_id: row.get(11)?,
                        last_complete_scan_time_utc_ms: optional_u64(row.get(12)?)?,
                        uncertainty: Vec::new(),
                    })
                },
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))?
            .ok_or_else(|| {
                ProjectionError::InvalidScan(format!("unknown location {location_id}"))
            })?;
        freshness.availability = match freshness.latest_mount_status.as_deref() {
            Some("mounted") if freshness.last_fingerprint_status.as_deref() == Some("match") => {
                "online"
            }
            Some("unmounted") if freshness.expected_availability == "offline" => "expected_offline",
            Some("unmounted") => "unexpectedly_absent",
            _ => "unknown",
        }
        .to_owned();
        if freshness.last_complete_scan_id.is_none() {
            freshness
                .uncertainty
                .push("never_completely_scanned".to_owned());
        }
        if freshness
            .latest_scan_status
            .as_deref()
            .is_some_and(|status| status != "complete")
        {
            freshness
                .uncertainty
                .push("latest_scan_incomplete".to_owned());
        }
        if freshness.device_id.is_some() && freshness.last_device_checkin_time_utc_ms.is_none() {
            freshness
                .uncertainty
                .push("device_never_checked_in".to_owned());
        }
        if freshness
            .last_fingerprint_status
            .as_deref()
            .is_some_and(|status| status != "match")
        {
            freshness
                .uncertainty
                .push("device_identity_unconfirmed".to_owned());
        }
        Ok(freshness)
    }

    pub fn apply(&self, event_store: &EventStore) -> Result<ApplyStats> {
        self.apply_internal(event_store, None)
    }

    pub fn apply_at_most(
        &self,
        event_store: &EventStore,
        max_transactions: u64,
    ) -> Result<ApplyStats> {
        if max_transactions == 0 {
            return Err(ProjectionError::InvalidCursor(
                "max_transactions must be greater than zero".to_owned(),
            ));
        }
        self.apply_internal(event_store, Some(max_transactions))
    }

    fn apply_internal(
        &self,
        event_store: &EventStore,
        max_transactions: Option<u64>,
    ) -> Result<ApplyStats> {
        let mut connection = self.open_connection()?;
        let mut status =
            read_status(&connection).map_err(|source| sqlite_error(&self.path, source))?;
        validate_status(&connection, &status, &self.path)?;
        let mut stats = ApplyStats::default();
        loop {
            let batch = event_store.read_batch(
                &status.cursor,
                self.config.batch_events,
                self.config.batch_bytes,
            )?;
            add_read_stats(&mut stats, &batch.stats);
            if batch.events.is_empty() {
                stats.caught_up = true;
                return Ok(stats);
            }

            let transaction = connection
                .transaction()
                .map_err(|source| sqlite_error(&self.path, source))?;
            apply_batch(&transaction, &batch.events, status.policy_input_event_seq)
                .map_err(|error| map_transaction_error(&self.path, error))?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(&self.path, source))?;
            stats.transactions += 1;
            stats.events_applied += u64::try_from(batch.events.len()).unwrap_or(u64::MAX);
            status = read_status(&connection).map_err(|source| sqlite_error(&self.path, source))?;
            validate_status(&connection, &status, &self.path)?;
            if batch.eof {
                stats.caught_up = true;
                return Ok(stats);
            }
            if max_transactions.is_some_and(|limit| stats.transactions >= limit) {
                return Ok(stats);
            }
        }
    }

    pub fn rebuild(
        event_store: &EventStore,
        target_path: impl AsRef<Path>,
        archive_id: &str,
        config: ProjectionConfig,
    ) -> Result<ApplyStats> {
        let target_path = target_path.as_ref();
        let parent = parent_directory(target_path);
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create rebuild directory", parent, source))?;
        let file_name = target_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("archive.db");
        let temp_path = parent.join(format!(
            ".{file_name}.rebuild.{}.tmp",
            Ulid::new().to_string().to_ascii_lowercase()
        ));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|source| io_error("create rebuild database", &temp_path, source))?;
        let mut guard = RebuildGuard {
            path: temp_path.clone(),
            keep: false,
        };
        let rebuilt = Self::open_or_create(&temp_path, archive_id, config)?;
        let stats = rebuilt.apply(event_store)?;
        rebuilt.finalize_for_replace()?;

        prepare_existing_target(target_path, rebuilt.config.busy_timeout)?;
        fs::rename(&temp_path, target_path)
            .map_err(|source| io_error("install rebuilt database", target_path, source))?;
        guard.keep = true;
        sync_directory(parent)?;
        Ok(stats)
    }

    fn open_connection(&self) -> Result<Connection> {
        let connection =
            Connection::open(&self.path).map_err(|source| sqlite_error(&self.path, source))?;
        connection
            .busy_timeout(self.config.busy_timeout)
            .map_err(|source| sqlite_error(&self.path, source))?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;",
            )
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok(connection)
    }

    fn validate_identity(&self, connection: &Connection, archive_id: &str) -> Result<()> {
        let schema_version = meta_required(connection, "schema_version")
            .map_err(|source| sqlite_error(&self.path, source))?;
        if schema_version != SCHEMA_VERSION.to_string() {
            return Err(ProjectionError::UnsupportedSchema {
                actual: schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        let actual_archive_id = meta_required(connection, "archive_id")
            .map_err(|source| sqlite_error(&self.path, source))?;
        if actual_archive_id != archive_id {
            return Err(ProjectionError::ArchiveIdentityMismatch {
                actual: actual_archive_id,
                expected: archive_id.to_owned(),
            });
        }
        let stream_id = meta_required(connection, "stream_id")
            .map_err(|source| sqlite_error(&self.path, source))?;
        if stream_id != STREAM_ID {
            return Err(ProjectionError::InvalidCursor(format!(
                "database stream_id is {stream_id}, expected {STREAM_ID}"
            )));
        }
        Ok(())
    }

    fn finalize_for_replace(&self) -> Result<()> {
        let connection = self.open_connection()?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
            .map_err(|source| sqlite_error(&self.path, source))?;
        let result: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|source| sqlite_error(&self.path, source))?;
        if result != "ok" {
            return Err(ProjectionError::IntegrityCheck(result));
        }
        drop(connection);
        File::open(&self.path)
            .map_err(|source| io_error("open rebuilt database for sync", &self.path, source))?
            .sync_all()
            .map_err(|source| io_error("sync rebuilt database", &self.path, source))
    }
}

impl ScanProjectionSession {
    pub(crate) fn known_entry(
        &self,
        scan_id: &str,
        collection_id: &str,
        location_id: &str,
        path: &EncodedPath,
    ) -> Result<Option<ScanKnownEntry>> {
        self.connection
            .prepare_cached(
                "SELECT p.file_ref_id, c.copy_claim_id, p.state, c.state,
                        p.observed_size_bytes, p.modified_time_utc_ms,
                        EXISTS(
                            SELECT 1 FROM scan_missing_candidates m
                            WHERE m.scan_id = ?5 AND m.location_id = p.location_id
                              AND m.path_encoding = p.observed_path_encoding
                              AND m.path_bytes = p.observed_path_bytes
                              AND ((m.candidate_kind = 'path' AND m.file_ref_id = p.file_ref_id
                                    AND m.candidate_event_seq > last_path_event.seq)
                                OR (m.candidate_kind = 'copy' AND m.copy_claim_id = c.copy_claim_id
                                    AND m.candidate_event_seq > c.state_event_seq))
                        )
                 FROM path_observations p
                 JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                 JOIN events last_path_event ON last_path_event.event_id = p.last_seen_event_id
                 LEFT JOIN copy_claims c
                   ON c.location_id = p.location_id
                  AND c.relative_path_encoding = p.observed_path_encoding
                  AND c.relative_path_bytes = p.observed_path_bytes
                  AND c.state != 'superseded'
                 WHERE f.collection_id = ?1 AND f.path_state = 'active'
                   AND p.location_id = ?2 AND p.observed_path_encoding = ?3
                   AND p.observed_path_bytes = ?4",
            )
            .and_then(|mut statement| {
                statement.query_row(
                    params![
                        collection_id,
                        location_id,
                        path.encoding.as_str(),
                        path.bytes,
                        scan_id,
                    ],
                    |row| {
                        Ok(ScanKnownEntry {
                            file_ref_id: row.get(0)?,
                            copy_claim_id: row.get(1)?,
                            path_state: row.get(2)?,
                            copy_state: row.get(3)?,
                            size_bytes: optional_u64(row.get(4)?)?,
                            modified_time_utc_ms: optional_u64(row.get(5)?)?,
                            has_effective_missing_candidate: row.get(6)?,
                        })
                    },
                )
            })
            .optional()
            .map_err(|source| sqlite_error(&self.path, source))
    }

    pub(crate) fn mark_seen(
        &mut self,
        job_id: &str,
        paths: &[ScanSeenPath],
        now_utc_ms: u64,
    ) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let time = i64::try_from(now_utc_ms).map_err(|_| {
            ProjectionError::InvalidScan("scan time exceeds SQLite integer range".to_owned())
        })?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, source))?;
        {
            let mut statement = transaction
                .prepare_cached(
                    "INSERT INTO job_items(
                    job_item_id, job_id, item_type, item_key, file_ref_id, copy_claim_id,
                    path_bytes, path_encoding, path_display, status, updated_time_utc_ms
                 ) VALUES (?2, ?1, 'scan_seen', ?2, ?3, ?4, ?5, ?6, ?7, 'complete', ?8)
                 ON CONFLICT(job_id, item_type, item_key) DO UPDATE SET
                    file_ref_id = excluded.file_ref_id,
                    copy_claim_id = excluded.copy_claim_id,
                    path_bytes = excluded.path_bytes,
                    path_encoding = excluded.path_encoding,
                    path_display = excluded.path_display,
                    status = 'complete',
                    updated_time_utc_ms = excluded.updated_time_utc_ms",
                )
                .map_err(|source| sqlite_error(&self.path, source))?;
            for path in paths {
                statement
                    .execute(params![
                        job_id,
                        path.item_key,
                        path.file_ref_id,
                        path.copy_claim_id,
                        path.path.bytes,
                        path.path.encoding.as_str(),
                        path.path.display,
                        time,
                    ])
                    .map_err(|source| sqlite_error(&self.path, source))?;
            }
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, source))?;
        Ok(())
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn prepare_existing_target(path: &Path, busy_timeout: Duration) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection = Connection::open(path).map_err(|source| sqlite_error(path, source))?;
    connection
        .busy_timeout(busy_timeout)
        .map_err(|source| sqlite_error(path, source))?;
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|source| sqlite_error(path, source))?;
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(ProjectionError::InvalidCursor(format!(
            "existing database WAL could not be fully checkpointed ({checkpointed_frames}/{log_frames} frames, busy={busy})"
        )));
    }
    connection
        .execute_batch("PRAGMA journal_mode = DELETE;")
        .map_err(|source| sqlite_error(path, source))?;
    drop(connection);
    for sidecar in [sqlite_sidecar(path, "-wal"), sqlite_sidecar(path, "-shm")] {
        if sidecar.exists() {
            fs::remove_file(&sidecar).map_err(|source| {
                io_error("remove checkpointed SQLite sidecar", sidecar, source)
            })?;
        }
    }
    File::open(path)
        .map_err(|source| io_error("open existing database for sync", path, source))?
        .sync_all()
        .map_err(|source| io_error("sync existing database", path, source))
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn initialize_meta(transaction: &Transaction<'_>, archive_id: &str) -> rusqlite::Result<()> {
    let values = [
        ("archive_id", archive_id.to_owned()),
        ("schema_version", SCHEMA_VERSION.to_string()),
        ("stream_id", STREAM_ID.to_owned()),
        ("applied_event_seq", "0".to_owned()),
        ("applied_event_hash", String::new()),
        ("applied_segment_first_seq", String::new()),
        ("applied_segment_offset", "0".to_owned()),
        ("policy_input_event_seq", "0".to_owned()),
        ("last_verified_checkpoint_id", String::new()),
        ("last_verified_checkpoint_seq", "0".to_owned()),
        ("catalog_location_id", String::new()),
    ];
    let mut statement =
        transaction.prepare("INSERT INTO archive_meta(key, value) VALUES (?1, ?2)")?;
    for (key, value) in values {
        statement.execute(params![key, value])?;
    }
    Ok(())
}

fn meta_required(connection: &Connection, key: &str) -> rusqlite::Result<String> {
    connection.query_row(
        "SELECT value FROM archive_meta WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
}

fn parse_meta_u64(connection: &Connection, key: &str) -> rusqlite::Result<u64> {
    let value = meta_required(connection, key)?;
    value.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn read_status(connection: &Connection) -> rusqlite::Result<ProjectionStatus> {
    let applied_seq = parse_meta_u64(connection, "applied_event_seq")?;
    let applied_hash = meta_required(connection, "applied_event_hash")?;
    let segment_first = meta_required(connection, "applied_segment_first_seq")?;
    let next_offset = parse_meta_u64(connection, "applied_segment_offset")?;
    let schema_version_text = meta_required(connection, "schema_version")?;
    let schema_version = schema_version_text.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ProjectionStatus {
        archive_id: meta_required(connection, "archive_id")?,
        schema_version,
        stream_id: meta_required(connection, "stream_id")?,
        cursor: EventCursor {
            applied_seq,
            applied_event_hash: (!applied_hash.is_empty()).then_some(applied_hash),
            segment_first_seq: if segment_first.is_empty() {
                None
            } else {
                Some(segment_first.parse().map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?)
            },
            next_offset,
        },
        policy_input_event_seq: parse_meta_u64(connection, "policy_input_event_seq")?,
        last_verified_checkpoint_id: nonempty_meta(connection, "last_verified_checkpoint_id")?,
        last_verified_checkpoint_seq: parse_meta_u64(connection, "last_verified_checkpoint_seq")?,
        catalog_location_id: nonempty_meta(connection, "catalog_location_id")?,
    })
}

fn validate_status(connection: &Connection, status: &ProjectionStatus, path: &Path) -> Result<()> {
    if status.policy_input_event_seq > status.cursor.applied_seq {
        return Err(ProjectionError::InvalidCursor(
            "policy_input_event_seq exceeds applied_event_seq".to_owned(),
        ));
    }
    if status.cursor.applied_seq == 0 {
        if status.cursor.applied_event_hash.is_some()
            || status.cursor.segment_first_seq.is_some()
            || status.cursor.next_offset != 0
        {
            return Err(ProjectionError::InvalidCursor(
                "empty projection cursor contains a hash or file position".to_owned(),
            ));
        }
        return Ok(());
    }
    if status.cursor.segment_first_seq.is_none() || status.cursor.next_offset == 0 {
        return Err(ProjectionError::InvalidCursor(
            "non-empty projection cursor lacks its file position".to_owned(),
        ));
    }
    let mirrored_hash: Option<String> = connection
        .query_row(
            "SELECT event_hash FROM events WHERE stream_id = ?1 AND seq = ?2",
            params![
                status.stream_id,
                i64::try_from(status.cursor.applied_seq).map_err(|_| {
                    ProjectionError::InvalidCursor(
                        "applied_event_seq exceeds SQLite's signed integer range".to_owned(),
                    )
                })?
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(path, source))?;
    if mirrored_hash.as_deref() != status.cursor.applied_event_hash.as_deref() {
        return Err(ProjectionError::InvalidCursor(
            "applied hash does not match the mirrored tail event".to_owned(),
        ));
    }
    Ok(())
}

fn nonempty_meta(connection: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    Ok(meta_required(connection, key)
        .optional()?
        .filter(|value| !value.is_empty()))
}

fn optional_u64(value: Option<i64>) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn parse_path_encoding(value: &str) -> rusqlite::Result<PathEncoding> {
    match value {
        "utf8" => Ok(PathEncoding::Utf8),
        "unix_bytes" => Ok(PathEncoding::UnixBytes),
        "windows_utf16le" => Ok(PathEncoding::WindowsUtf16Le),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("unknown path encoding {value}").into(),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct OperationOutcomePayload {
    operation_key: String,
    job_type: String,
    item_type: String,
    item_key: String,
    outcome_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointCreatedPayload {
    checkpoint_id: String,
    checkpoint_path: String,
    event_last_seq: u64,
}

#[derive(Debug, Deserialize)]
struct LosslessPathPayload {
    encoding: String,
    text: Option<String>,
    base64: Option<String>,
    display: String,
}

impl LosslessPathPayload {
    fn bytes(&self, record: &EventRecord) -> std::result::Result<Vec<u8>, BatchError> {
        match self.encoding.as_str() {
            "utf8" => self
                .text
                .as_ref()
                .map(|text| text.as_bytes().to_vec())
                .ok_or_else(|| invalid_payload(record, "UTF-8 path lacks text")),
            "unix_bytes" | "windows_utf16le" => self
                .base64
                .as_ref()
                .ok_or_else(|| invalid_payload(record, "binary path lacks base64"))
                .and_then(|value| {
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|error| {
                            invalid_payload(record, &format!("invalid path base64: {error}"))
                        })
                }),
            _ => Err(invalid_payload(record, "unknown path encoding")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExternalIdentityObservedPayload {
    external_identity_id: String,
    namespace: String,
    external_key: String,
    expected_hash_algo: Option<String>,
    expected_hash_hex: Option<String>,
    expected_size_bytes: Option<u64>,
    resolution_state: String,
    source_detail_json: Value,
}

#[derive(Debug, Deserialize)]
struct ExternalIdentityResolvedPayload {
    external_identity_id: String,
    object_id: String,
}

#[derive(Debug, Deserialize)]
struct ObjectObservedPayload {
    object_id: String,
    canonical_hash_algo: String,
    canonical_hash_hex: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct ObjectHashAddedPayload {
    object_id: String,
    hash_algo: String,
    hash_hex: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct FileRefObservedPayload {
    file_ref_id: String,
    collection_id: String,
    logical_path: LosslessPathPayload,
    object_id: Option<String>,
    external_identity_id: Option<String>,
    identity_state: String,
    path_state: String,
    observed_size_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PathObservedPayload {
    file_ref_id: String,
    location_id: String,
    observed_path: LosslessPathPayload,
    representation: String,
    object_id: Option<String>,
    external_identity_id: Option<String>,
    state: String,
    observed_size_bytes: Option<u64>,
    modified_time_utc_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AvailabilityObservedPayload {
    external_identity_id: String,
    source_repo_id: String,
    source_remote_id: String,
    state: String,
    location_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnnexRemoteMappedPayload {
    source_annex_uuid: String,
    remote_annex_uuid: String,
    display_name: Option<String>,
    location_id: String,
}

#[derive(Debug, Deserialize)]
struct AnnexRemoteUnmappedPayload {
    source_annex_uuid: String,
    remote_annex_uuid: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CopyObservedPayload {
    copy_claim_id: String,
    location_id: String,
    relative_path: LosslessPathPayload,
    object_id: Option<String>,
    external_identity_id: Option<String>,
    claim_basis: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct CopyVerifiedPayload {
    verification_id: String,
    copy_claim_id: String,
    object_id: Option<String>,
    location_id: String,
    result: String,
    expected_hash_algo: Option<String>,
    expected_hash_hex: Option<String>,
    observed_hash_hex: Option<String>,
    size_bytes: Option<u64>,
    bytes_read: Option<u64>,
    duration_ms: Option<u64>,
    path_observed: LosslessPathPayload,
    device_fingerprint_status: String,
    error_code: Option<String>,
    error_detail: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceCheckedInPayload {
    device_id: String,
    fingerprint_status: String,
}

#[derive(Debug, Deserialize)]
struct DeviceMountObservedPayload {
    mount_id: String,
    device_id: String,
    mount_root_uri: String,
    status: String,
    fingerprint_status: String,
}

#[derive(Debug, Deserialize)]
struct ScanStartedPayload {
    scan_id: String,
    location_id: String,
    collection_id: String,
    device_id: String,
    archive_root_id: String,
    fingerprint_status: String,
    logical_prefix: Option<LosslessPathPayload>,
    coverage_version: u64,
    scope_json: Value,
    exclusions_json: Value,
    exclusions_hash: String,
}

#[derive(Debug, Deserialize)]
struct ScanMissingCandidatePayload {
    scan_id: String,
    file_ref_id: Option<String>,
    copy_claim_id: Option<String>,
    location_id: String,
    path: LosslessPathPayload,
}

#[derive(Debug, Deserialize)]
struct ScanCompletedPayload {
    scan_id: String,
    status: String,
    coverage_version: u64,
    scope_json: Value,
    exclusions_hash: String,
    observations_count: u64,
    observations_digest: Option<String>,
    missing_candidate_count: u64,
    missing_candidate_digest: Option<String>,
    files_seen: u64,
    bytes_seen: u64,
    new_paths: u64,
    changed_paths: u64,
    unchanged_paths: u64,
    error_count: u64,
    error_summary: Value,
}

#[derive(Debug, Deserialize)]
struct AnnexImportStartedPayload {
    import_id: String,
    repo_path: LosslessPathPayload,
    collection_id: String,
    worktree_location_id: String,
    cas_location_id: String,
    device_id: String,
    archive_root_id: String,
    annex_uuid: Option<String>,
    git_head_commit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnnexImportCompletedPayload {
    import_id: String,
    status: String,
    summary: Value,
}

enum BatchError {
    Sqlite(rusqlite::Error),
    Projection(ProjectionError),
}

impl From<rusqlite::Error> for BatchError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

fn map_transaction_error(path: &Path, error: BatchError) -> ProjectionError {
    match error {
        BatchError::Sqlite(source) => sqlite_error(path, source),
        BatchError::Projection(error) => error,
    }
}

fn apply_batch(
    transaction: &Transaction<'_>,
    events: &[PositionedEvent],
    initial_policy_input_seq: u64,
) -> std::result::Result<(), BatchError> {
    let mut policy_input_seq = initial_policy_input_seq;
    let mut insert_event = transaction.prepare_cached(
        "INSERT INTO events(
            stream_id, seq, event_id, event_type, event_time_utc_ms, actor_id, host_id, job_id,
            object_id, file_ref_id, copy_claim_id, location_id, device_id, site_id, payload_json,
            previous_event_hash, event_hash
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
         )",
    )?;

    for positioned in events {
        let record = &positioned.record;
        let relevance = policy_relevance(&record.envelope.event_type).ok_or_else(|| {
            BatchError::Projection(ProjectionError::UnsupportedEventType(
                record.envelope.event_type.clone(),
            ))
        })?;
        let payload_json = serde_json::to_string(&record.envelope.payload).map_err(|source| {
            BatchError::Projection(ProjectionError::InvalidPayload {
                event_type: record.envelope.event_type.clone(),
                seq: record.envelope.seq,
                message: source.to_string(),
            })
        })?;
        let event_seq = sql_integer(record.envelope.seq, "seq", record)?;
        let event_time = sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?;
        insert_event.execute(params![
            record.envelope.stream_id,
            event_seq,
            record.envelope.event_id,
            record.envelope.event_type,
            event_time,
            record.envelope.actor_id,
            record.envelope.host_id,
            record.envelope.job_id,
            record.envelope.object_id,
            record.envelope.file_ref_id,
            record.envelope.copy_claim_id,
            record.envelope.location_id,
            record.envelope.device_id,
            record.envelope.site_id,
            payload_json,
            record.envelope.previous_event_hash,
            record.event_hash,
        ])?;

        project_operation_outcome(transaction, record)?;
        project_semantic_event(transaction, record)?;
        if record.envelope.event_type == "checkpoint_created" {
            project_checkpoint_created(transaction, record)?;
        }
        if relevance {
            policy_input_seq = record.envelope.seq;
        }
    }
    drop(insert_event);

    let last = events.last().expect("apply_batch requires events");
    let cursor = &last.record;
    let meta_values = [
        ("applied_event_seq", cursor.envelope.seq.to_string()),
        ("applied_event_hash", cursor.event_hash.clone()),
        (
            "applied_segment_first_seq",
            last.segment_first_seq.to_string(),
        ),
        ("applied_segment_offset", last.next_offset.to_string()),
        ("policy_input_event_seq", policy_input_seq.to_string()),
    ];
    let mut update_meta =
        transaction.prepare_cached("UPDATE archive_meta SET value = ?2 WHERE key = ?1")?;
    for (key, value) in meta_values {
        if update_meta.execute(params![key, value])? != 1 {
            return Err(BatchError::Projection(ProjectionError::InvalidCursor(
                format!("archive_meta is missing {key}"),
            )));
        }
    }
    Ok(())
}

fn project_semantic_event(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    match record.envelope.event_type.as_str() {
        "site_registered" | "site_updated" | "site_retired" => {
            project_site_snapshot(transaction, record)
        }
        "policy_registered" | "policy_updated" | "policy_retired" => {
            project_policy_snapshot(transaction, record)
        }
        "collection_registered" | "collection_updated" | "collection_retired" => {
            project_collection_snapshot(transaction, record)
        }
        "device_registered" | "device_updated" | "device_moved" | "device_retired" => {
            project_device_snapshot(transaction, record)
        }
        "archive_root_registered" | "archive_root_updated" | "archive_root_retired" => {
            project_archive_root_snapshot(transaction, record)
        }
        "location_registered" | "location_updated" | "location_retired" => {
            project_location_snapshot(transaction, record)
        }
        "risk_domain_registered" | "risk_domain_updated" | "risk_domain_retired" => {
            project_risk_domain_snapshot(transaction, record)
        }
        "risk_assigned" => project_risk_assignment(transaction, record, true),
        "risk_unassigned" => project_risk_assignment(transaction, record, false),
        "external_identity_observed" => project_external_identity_observed(transaction, record),
        "external_identity_resolved" => project_external_identity_resolved(transaction, record),
        "external_availability_observed" => project_external_availability(transaction, record),
        "annex_remote_mapped" => project_annex_remote_mapped(transaction, record),
        "annex_remote_unmapped" => project_annex_remote_unmapped(transaction, record),
        "object_observed" => project_object_observed(transaction, record),
        "object_hash_added" => project_object_hash(transaction, record),
        "file_ref_observed" | "file_ref_updated" => project_file_ref(transaction, record),
        "path_observed" => project_path_observation(transaction, record),
        "copy_observed" => project_copy_claim(transaction, record),
        "copy_verified" => project_copy_verification(transaction, record),
        "device_checked_in" => project_device_checked_in(transaction, record),
        "device_mount_observed" => project_device_mount_observed(transaction, record),
        "scan_started" => project_scan_started(transaction, record),
        "path_missing_candidate" => project_scan_missing_candidate(transaction, record, "path"),
        "copy_missing_candidate" => project_scan_missing_candidate(transaction, record, "copy"),
        "scan_completed" => project_scan_completed(transaction, record),
        "annex_import_started" => project_annex_import_started(transaction, record),
        "annex_import_completed" => project_annex_import_completed(transaction, record),
        _ => Ok(()),
    }
}

fn project_site_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: SiteSnapshot = payload(record)?;
    validate_snapshot(record, &value.site_id, &value.display_name, &value.status)?;
    transaction.execute(
        "INSERT INTO sites(site_id, display_name, site_kind, description, status, last_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(site_id) DO UPDATE SET display_name = excluded.display_name,
           site_kind = excluded.site_kind, description = excluded.description,
           status = excluded.status, last_event_id = excluded.last_event_id",
        params![
            value.site_id,
            value.display_name,
            value.site_kind,
            value.description,
            value.status,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_policy_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: PolicySnapshot = payload(record)?;
    validate_snapshot(record, &value.policy_id, &value.display_name, &value.status)?;
    let requirements_json = serde_json::to_string(&value.requirements)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    PolicyRequirements::from_json(&value.policy_id, &requirements_json)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    if value.policy_version == 0 {
        return Err(invalid_payload(record, "policy_version must be positive"));
    }
    let prior_version: Option<i64> = transaction
        .query_row(
            "SELECT policy_version FROM policies WHERE policy_id = ?1",
            [&value.policy_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(prior) = prior_version {
        let prior = u64::try_from(prior)
            .map_err(|_| invalid_payload(record, "stored policy_version is invalid"))?;
        if value.policy_version < prior
            || (record.envelope.event_type == "policy_updated" && value.policy_version <= prior)
        {
            return Err(invalid_payload(
                record,
                "policy updates must increase policy_version",
            ));
        }
    }
    transaction.execute(
        "INSERT INTO policies(policy_id, display_name, policy_version, requirements_json,
                              enabled, status, last_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(policy_id) DO UPDATE SET display_name = excluded.display_name,
           policy_version = excluded.policy_version, requirements_json = excluded.requirements_json,
           enabled = excluded.enabled, status = excluded.status,
           last_event_id = excluded.last_event_id",
        params![
            value.policy_id,
            value.display_name,
            sql_integer(value.policy_version, "policy_version", record)?,
            requirements_json,
            value.enabled,
            value.status,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_collection_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: CollectionSnapshot = payload(record)?;
    validate_snapshot(
        record,
        &value.collection_id,
        &value.display_name,
        &value.status,
    )?;
    transaction.execute(
        "INSERT INTO collections(collection_id, display_name, description, home_site_id,
                                 policy_id, status, last_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(collection_id) DO UPDATE SET display_name = excluded.display_name,
           description = excluded.description, home_site_id = excluded.home_site_id,
           policy_id = excluded.policy_id, status = excluded.status,
           last_event_id = excluded.last_event_id",
        params![
            value.collection_id,
            value.display_name,
            value.description,
            value.home_site_id,
            value.policy_id,
            value.status,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_device_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: DeviceSnapshot = payload(record)?;
    validate_snapshot(record, &value.device_id, &value.display_name, &value.status)?;
    let previous_site: Option<Option<String>> = transaction
        .query_row(
            "SELECT current_site_id FROM devices WHERE device_id = ?1",
            [&value.device_id],
            |row| row.get(0),
        )
        .optional()?;
    transaction.execute(
        "INSERT INTO devices(device_id, display_name, device_kind, serial_hint,
          hardware_fingerprint, fingerprint_kind, identity_state, owner, status,
          current_site_id, expected_availability, last_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(device_id) DO UPDATE SET display_name = excluded.display_name,
          device_kind = excluded.device_kind, serial_hint = excluded.serial_hint,
          hardware_fingerprint = excluded.hardware_fingerprint,
          fingerprint_kind = excluded.fingerprint_kind,
          identity_state = excluded.identity_state, owner = excluded.owner,
          status = excluded.status, current_site_id = excluded.current_site_id,
          expected_availability = excluded.expected_availability,
          last_event_id = excluded.last_event_id",
        params![
            value.device_id,
            value.display_name,
            value.device_kind,
            value.serial_hint,
            value.hardware_fingerprint,
            value.fingerprint_kind,
            value.identity_state,
            value.owner,
            value.status,
            value.current_site_id,
            value.expected_availability,
            record.envelope.event_id,
        ],
    )?;
    if previous_site.flatten() != value.current_site_id {
        transaction.execute(
            "UPDATE device_site_history SET departed_time_utc_ms = ?2
             WHERE device_id = ?1 AND departed_time_utc_ms IS NULL",
            params![
                value.device_id,
                sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            ],
        )?;
        if let Some(site_id) = value.current_site_id {
            transaction.execute(
                "INSERT INTO device_site_history(device_id, site_id, arrived_time_utc_ms,
                                                 moved_event_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    value.device_id,
                    site_id,
                    sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
                    record.envelope.event_id,
                ],
            )?;
        }
    }
    Ok(())
}

fn project_archive_root_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ArchiveRootSnapshot = payload(record)?;
    validate_snapshot(
        record,
        &value.archive_root_id,
        &value.display_name,
        &value.status,
    )?;
    let bytes = registry_path_bytes(&value.root_path_on_device, record)?;
    transaction.execute(
        "INSERT INTO archive_roots(archive_root_id, device_id, display_name,
          root_path_on_device_bytes, root_path_encoding, root_path_display,
          status, created_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(archive_root_id) DO UPDATE SET device_id = excluded.device_id,
          display_name = excluded.display_name,
          root_path_on_device_bytes = excluded.root_path_on_device_bytes,
          root_path_encoding = excluded.root_path_encoding,
          root_path_display = excluded.root_path_display, status = excluded.status",
        params![
            value.archive_root_id,
            value.device_id,
            value.display_name,
            bytes,
            value.root_path_on_device.encoding,
            value.root_path_on_device.display,
            value.status,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_location_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: LocationSnapshot = payload(record)?;
    validate_snapshot(
        record,
        &value.location_id,
        &value.display_name,
        &value.status,
    )?;
    let relative_bytes = value
        .relative_path
        .as_ref()
        .map(|path| registry_path_bytes(path, record))
        .transpose()?;
    if value.kind == "filesystem" {
        let consistent: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM archive_roots r
             WHERE r.archive_root_id = ?1 AND r.device_id = ?2)",
            params![value.archive_root_id, value.device_id],
            |row| row.get(0),
        )?;
        if !consistent || value.site_id.is_some() || relative_bytes.is_none() {
            return Err(invalid_payload(
                record,
                "filesystem location must have a matching root/device, relative path, and no site",
            ));
        }
    } else if value.kind == "service" {
        if value.site_id.is_none()
            || value.archive_root_id.is_some()
            || value.device_id.is_some()
            || relative_bytes.is_some()
        {
            return Err(invalid_payload(
                record,
                "service location must have only a site topology",
            ));
        }
    } else {
        return Err(invalid_payload(record, "location kind is unsupported"));
    }
    transaction.execute(
        "INSERT INTO locations(location_id, display_name, kind, archive_root_id,
          relative_path_bytes, relative_path_encoding, relative_path_display,
          device_id, site_id, encryption_state, trust_level, expected_availability,
          is_writable, status, created_event_id, last_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)
         ON CONFLICT(location_id) DO UPDATE SET display_name = excluded.display_name,
          kind = excluded.kind, archive_root_id = excluded.archive_root_id,
          relative_path_bytes = excluded.relative_path_bytes,
          relative_path_encoding = excluded.relative_path_encoding,
          relative_path_display = excluded.relative_path_display,
          device_id = excluded.device_id, site_id = excluded.site_id,
          encryption_state = excluded.encryption_state, trust_level = excluded.trust_level,
          expected_availability = excluded.expected_availability,
          is_writable = excluded.is_writable, status = excluded.status,
          last_event_id = excluded.last_event_id",
        params![
            value.location_id,
            value.display_name,
            value.kind,
            value.archive_root_id,
            relative_bytes,
            value
                .relative_path
                .as_ref()
                .map(|path| path.encoding.as_str()),
            value
                .relative_path
                .as_ref()
                .map(|path| path.display.as_str()),
            value.device_id,
            value.site_id,
            value.encryption_state,
            value.trust_level,
            value.expected_availability,
            value.is_writable,
            value.status,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_risk_domain_snapshot(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: RiskDomainSnapshot = payload(record)?;
    validate_snapshot(
        record,
        &value.risk_domain_id,
        &value.display_name,
        &value.status,
    )?;
    transaction.execute(
        "INSERT INTO risk_domains(risk_domain_id, display_name, risk_kind,
                                  description, status, last_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(risk_domain_id) DO UPDATE SET display_name = excluded.display_name,
          risk_kind = excluded.risk_kind, description = excluded.description,
          status = excluded.status, last_event_id = excluded.last_event_id",
        params![
            value.risk_domain_id,
            value.display_name,
            value.risk_kind,
            value.description,
            value.status,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_risk_assignment(
    transaction: &Transaction<'_>,
    record: &EventRecord,
    assign: bool,
) -> std::result::Result<(), BatchError> {
    let value: RiskAssignment = payload(record)?;
    let exists: bool = transaction.query_row(
        "SELECT CASE ?1
           WHEN 'location' THEN EXISTS(SELECT 1 FROM locations WHERE location_id = ?2)
           WHEN 'archive_root' THEN EXISTS(SELECT 1 FROM archive_roots WHERE archive_root_id = ?2)
           WHEN 'device' THEN EXISTS(SELECT 1 FROM devices WHERE device_id = ?2)
           WHEN 'site' THEN EXISTS(SELECT 1 FROM sites WHERE site_id = ?2)
           ELSE 0 END",
        params![value.entity_type, value.entity_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(invalid_payload(record, "risk assignment entity is unknown"));
    }
    if assign {
        transaction.execute(
            "INSERT INTO entity_risk_domains(entity_type, entity_id, risk_domain_id,
                                             assigned_event_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(entity_type, entity_id, risk_domain_id) DO UPDATE SET
               assigned_event_id = excluded.assigned_event_id",
            params![
                value.entity_type,
                value.entity_id,
                value.risk_domain_id,
                record.envelope.event_id,
            ],
        )?;
    } else {
        transaction.execute(
            "DELETE FROM entity_risk_domains
             WHERE entity_type = ?1 AND entity_id = ?2 AND risk_domain_id = ?3",
            params![value.entity_type, value.entity_id, value.risk_domain_id],
        )?;
    }
    Ok(())
}

fn validate_snapshot(
    record: &EventRecord,
    id: &str,
    display_name: &str,
    status: &str,
) -> std::result::Result<(), BatchError> {
    if id.trim().is_empty() || display_name.trim().is_empty() {
        return Err(invalid_payload(
            record,
            "registry ID and display name are required",
        ));
    }
    let retired_event = record.envelope.event_type.ends_with("_retired");
    if (retired_event && status != "retired") || (!retired_event && status != "active") {
        return Err(invalid_payload(
            record,
            "registry event type and snapshot status disagree",
        ));
    }
    Ok(())
}

fn registry_path_bytes(
    path: &RegistryPath,
    record: &EventRecord,
) -> std::result::Result<Vec<u8>, BatchError> {
    match path.encoding.as_str() {
        "utf8" => path
            .text
            .as_ref()
            .map(|text| text.as_bytes().to_vec())
            .ok_or_else(|| invalid_payload(record, "UTF-8 registry path lacks text")),
        "unix_bytes" | "windows_utf16le" => path
            .base64
            .as_ref()
            .ok_or_else(|| invalid_payload(record, "binary registry path lacks base64"))
            .and_then(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|error| {
                        invalid_payload(record, &format!("invalid path base64: {error}"))
                    })
            }),
        _ => Err(invalid_payload(
            record,
            "registry path encoding is unsupported",
        )),
    }
}

fn project_annex_remote_mapped(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: AnnexRemoteMappedPayload = payload(record)?;
    transaction.execute(
        "INSERT INTO annex_remotes(
            source_annex_uuid, remote_annex_uuid, display_name, location_id,
            last_observed_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(source_annex_uuid, remote_annex_uuid) DO UPDATE SET
            display_name = excluded.display_name,
            location_id = excluded.location_id,
            last_observed_event_id = excluded.last_observed_event_id",
        params![
            value.source_annex_uuid,
            value.remote_annex_uuid,
            value.display_name,
            value.location_id,
            record.envelope.event_id,
        ],
    )?;
    transaction.execute(
        "UPDATE external_availability
         SET location_id = ?3
         WHERE source_repo_id = ?1 AND source_remote_id = ?2",
        params![
            value.source_annex_uuid,
            value.remote_annex_uuid,
            value.location_id,
        ],
    )?;
    Ok(())
}

fn project_annex_remote_unmapped(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: AnnexRemoteUnmappedPayload = payload(record)?;
    transaction.execute(
        "INSERT INTO annex_remotes(
            source_annex_uuid, remote_annex_uuid, display_name, location_id,
            last_observed_event_id
         ) VALUES (?1, ?2, ?3, NULL, ?4)
         ON CONFLICT(source_annex_uuid, remote_annex_uuid) DO UPDATE SET
            display_name = COALESCE(excluded.display_name, annex_remotes.display_name),
            location_id = NULL,
            last_observed_event_id = excluded.last_observed_event_id",
        params![
            value.source_annex_uuid,
            value.remote_annex_uuid,
            value.display_name,
            record.envelope.event_id,
        ],
    )?;
    transaction.execute(
        "UPDATE external_availability
         SET location_id = NULL
         WHERE source_repo_id = ?1 AND source_remote_id = ?2",
        params![value.source_annex_uuid, value.remote_annex_uuid],
    )?;
    Ok(())
}

fn payload<T: serde::de::DeserializeOwned>(
    record: &EventRecord,
) -> std::result::Result<T, BatchError> {
    serde_json::from_value(record.envelope.payload.clone())
        .map_err(|source| invalid_payload(record, &source.to_string()))
}

fn invalid_payload(record: &EventRecord, message: &str) -> BatchError {
    BatchError::Projection(ProjectionError::InvalidPayload {
        event_type: record.envelope.event_type.clone(),
        seq: record.envelope.seq,
        message: message.to_owned(),
    })
}

fn project_external_identity_observed(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ExternalIdentityObservedPayload = payload(record)?;
    let detail = serde_json::to_string(&value.source_detail_json)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    transaction.execute(
        "INSERT INTO external_identities(
            external_identity_id, namespace, external_key, expected_hash_algo,
            expected_hash_hex, expected_size_bytes, resolution_state,
            source_detail_json, first_seen_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(external_identity_id) DO UPDATE SET
            expected_hash_algo = COALESCE(excluded.expected_hash_algo, expected_hash_algo),
            expected_hash_hex = COALESCE(excluded.expected_hash_hex, expected_hash_hex),
            expected_size_bytes = COALESCE(excluded.expected_size_bytes, expected_size_bytes),
            source_detail_json = excluded.source_detail_json,
            resolution_state = CASE
                WHEN external_identities.resolution_state IN ('resolved', 'conflict')
                    THEN external_identities.resolution_state
                ELSE excluded.resolution_state
            END",
        params![
            value.external_identity_id,
            value.namespace,
            value.external_key,
            value.expected_hash_algo,
            value.expected_hash_hex,
            optional_sql_integer(value.expected_size_bytes, "expected_size_bytes", record)?,
            value.resolution_state,
            detail,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_external_identity_resolved(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ExternalIdentityResolvedPayload = payload(record)?;
    let changed = transaction.execute(
        "UPDATE external_identities
         SET object_id = ?2, resolution_state = 'resolved', resolved_event_id = ?3
         WHERE external_identity_id = ?1
           AND (object_id IS NULL OR object_id = ?2)",
        params![
            value.external_identity_id,
            value.object_id,
            record.envelope.event_id
        ],
    )?;
    if changed != 1 {
        return Err(invalid_payload(
            record,
            "external identity is missing or resolves to conflicting content",
        ));
    }
    Ok(())
}

fn project_external_availability(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: AvailabilityObservedPayload = payload(record)?;
    transaction.execute(
        "INSERT INTO external_availability(
            external_identity_id, source_repo_id, source_remote_id, state,
            location_id, observed_time_utc_ms, observed_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(external_identity_id, source_repo_id, source_remote_id) DO UPDATE SET
            state = excluded.state,
            location_id = excluded.location_id,
            observed_time_utc_ms = excluded.observed_time_utc_ms,
            observed_event_id = excluded.observed_event_id",
        params![
            value.external_identity_id,
            value.source_repo_id,
            value.source_remote_id,
            value.state,
            value.location_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_object_observed(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ObjectObservedPayload = payload(record)?;
    transaction.execute(
        "INSERT INTO objects(
            object_id, canonical_hash_algo, canonical_hash_hex, size_bytes,
            first_seen_event_id, first_seen_time_utc_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(object_id) DO NOTHING",
        params![
            value.object_id,
            value.canonical_hash_algo,
            value.canonical_hash_hex,
            sql_integer(value.size_bytes, "size_bytes", record)?,
            record.envelope.event_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
        ],
    )?;
    let consistent: bool = transaction.query_row(
        "SELECT canonical_hash_algo = ?2 AND canonical_hash_hex = ?3 AND size_bytes = ?4
         FROM objects WHERE object_id = ?1",
        params![
            value.object_id,
            value.canonical_hash_algo,
            value.canonical_hash_hex,
            sql_integer(value.size_bytes, "size_bytes", record)?,
        ],
        |row| row.get(0),
    )?;
    if !consistent {
        return Err(invalid_payload(
            record,
            "object identity conflicts with prior state",
        ));
    }
    Ok(())
}

fn project_object_hash(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ObjectHashAddedPayload = payload(record)?;
    transaction.execute(
        "INSERT INTO object_hashes(object_id, hash_algo, hash_hex, source, verified_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(object_id, hash_algo, hash_hex) DO UPDATE SET
            verified_event_id = excluded.verified_event_id",
        params![
            value.object_id,
            value.hash_algo,
            value.hash_hex,
            value.source,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_file_ref(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: FileRefObservedPayload = payload(record)?;
    let path_bytes = value.logical_path.bytes(record)?;
    transaction.execute(
        "INSERT INTO file_refs(
            file_ref_id, collection_id, logical_path_bytes, logical_path_encoding,
            logical_path_display, object_id, external_identity_id, identity_state,
            path_state, observed_size_bytes, first_seen_event_id, last_seen_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
         ON CONFLICT(file_ref_id) DO UPDATE SET
            object_id = excluded.object_id,
            external_identity_id = excluded.external_identity_id,
            identity_state = excluded.identity_state,
            path_state = excluded.path_state,
            observed_size_bytes = excluded.observed_size_bytes,
            last_seen_event_id = excluded.last_seen_event_id",
        params![
            value.file_ref_id,
            value.collection_id,
            path_bytes,
            value.logical_path.encoding,
            value.logical_path.display,
            value.object_id,
            value.external_identity_id,
            value.identity_state,
            value.path_state,
            optional_sql_integer(value.observed_size_bytes, "observed_size_bytes", record)?,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_path_observation(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: PathObservedPayload = payload(record)?;
    let path_bytes = value.observed_path.bytes(record)?;
    transaction.execute(
        "INSERT INTO path_observations(
            file_ref_id, location_id, observed_path_bytes, observed_path_encoding,
            observed_path_display, representation, object_id, external_identity_id,
            state, first_seen_event_id, last_seen_event_id, last_seen_time_utc_ms,
            observed_size_bytes, modified_time_utc_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13)
         ON CONFLICT(file_ref_id, location_id, observed_path_encoding, observed_path_bytes)
         DO UPDATE SET
            representation = excluded.representation,
            object_id = excluded.object_id,
            external_identity_id = excluded.external_identity_id,
            state = excluded.state,
            last_seen_event_id = excluded.last_seen_event_id,
            last_seen_time_utc_ms = excluded.last_seen_time_utc_ms,
            observed_size_bytes = excluded.observed_size_bytes,
            modified_time_utc_ms = excluded.modified_time_utc_ms",
        params![
            value.file_ref_id,
            value.location_id,
            path_bytes,
            value.observed_path.encoding,
            value.observed_path.display,
            value.representation,
            value.object_id,
            value.external_identity_id,
            value.state,
            record.envelope.event_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            optional_sql_integer(value.observed_size_bytes, "observed_size_bytes", record)?,
            optional_sql_integer(value.modified_time_utc_ms, "modified_time_utc_ms", record)?,
        ],
    )?;
    Ok(())
}

fn project_copy_claim(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: CopyObservedPayload = payload(record)?;
    let path_bytes = value.relative_path.bytes(record)?;
    transaction.execute(
        "INSERT INTO copy_claims(
            copy_claim_id, location_id, relative_path_bytes, relative_path_encoding,
            relative_path_display, object_id, external_identity_id, claim_basis,
            state, state_event_seq, first_seen_event_id, last_seen_event_id,
            last_seen_time_utc_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?12)
         ON CONFLICT(copy_claim_id) DO UPDATE SET
            object_id = excluded.object_id,
            external_identity_id = excluded.external_identity_id,
            claim_basis = excluded.claim_basis,
            state = excluded.state,
            state_event_seq = excluded.state_event_seq,
            last_seen_event_id = excluded.last_seen_event_id,
            last_seen_time_utc_ms = excluded.last_seen_time_utc_ms",
        params![
            value.copy_claim_id,
            value.location_id,
            path_bytes,
            value.relative_path.encoding,
            value.relative_path.display,
            value.object_id,
            value.external_identity_id,
            value.claim_basis,
            value.state,
            sql_integer(record.envelope.seq, "seq", record)?,
            record.envelope.event_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
        ],
    )?;
    Ok(())
}

fn project_copy_verification(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: CopyVerifiedPayload = payload(record)?;
    let path_bytes = value.path_observed.bytes(record)?;
    transaction.execute(
        "INSERT INTO verification_results(
            verification_id, event_id, job_id, copy_claim_id, object_id, location_id,
            result, expected_hash_algo, expected_hash_hex, observed_hash_hex,
            size_bytes, bytes_read, duration_ms, verified_time_utc_ms,
            path_observed_bytes, path_observed_encoding, path_observed_display,
            device_fingerprint_status, error_code, error_detail
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            value.verification_id,
            record.envelope.event_id,
            record.envelope.job_id,
            value.copy_claim_id,
            value.object_id,
            value.location_id,
            value.result,
            value.expected_hash_algo,
            value.expected_hash_hex,
            value.observed_hash_hex,
            optional_sql_integer(value.size_bytes, "size_bytes", record)?,
            optional_sql_integer(value.bytes_read, "bytes_read", record)?,
            optional_sql_integer(value.duration_ms, "duration_ms", record)?,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            path_bytes,
            value.path_observed.encoding,
            value.path_observed.display,
            value.device_fingerprint_status,
            value.error_code,
            value.error_detail,
        ],
    )?;
    transaction.execute(
        "UPDATE copy_claims SET
            state = CASE
                WHEN ?2 = 'ok' THEN 'present'
                WHEN ?2 = 'hash_mismatch' THEN 'corrupt'
                ELSE 'unknown'
            END,
            state_event_seq = ?3,
            last_verified_event_id = ?4,
            last_verified_time_utc_ms = ?5,
            last_verification_result = ?2,
            last_error_code = ?6,
            last_error_detail = ?7
         WHERE copy_claim_id = ?1",
        params![
            value.copy_claim_id,
            value.result,
            sql_integer(record.envelope.seq, "seq", record)?,
            record.envelope.event_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            value.error_code,
            value.error_detail,
        ],
    )?;
    Ok(())
}

fn project_device_checked_in(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: DeviceCheckedInPayload = payload(record)?;
    if !matches!(
        value.fingerprint_status.as_str(),
        "match" | "unavailable" | "mismatch"
    ) {
        return Err(invalid_payload(record, "invalid fingerprint_status"));
    }
    let changed = transaction.execute(
        "UPDATE devices SET
            identity_state = CASE
                WHEN ?4 = 'mismatch' THEN 'conflict' ELSE identity_state END,
            last_checkin_event_id = ?2,
            last_checkin_time_utc_ms = ?3,
            last_fingerprint_match_time_utc_ms = CASE
                WHEN ?4 = 'match' THEN ?3 ELSE last_fingerprint_match_time_utc_ms END,
            last_fingerprint_status = ?4
         WHERE device_id = ?1 AND status = 'active'",
        params![
            value.device_id,
            record.envelope.event_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            value.fingerprint_status,
        ],
    )?;
    if changed != 1 {
        return Err(invalid_payload(
            record,
            "device check-in names no active device",
        ));
    }
    Ok(())
}

fn project_device_mount_observed(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: DeviceMountObservedPayload = payload(record)?;
    if !matches!(value.status.as_str(), "mounted" | "unmounted" | "mismatch")
        || !matches!(
            value.fingerprint_status.as_str(),
            "match" | "unavailable" | "mismatch"
        )
    {
        return Err(invalid_payload(record, "invalid device mount state"));
    }
    let device_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1)",
        [&value.device_id],
        |row| row.get(0),
    )?;
    if !device_exists {
        return Err(invalid_payload(record, "device mount names no device"));
    }
    transaction.execute(
        "INSERT INTO device_mounts(
            mount_id, device_id, host_id, mount_root_uri, status,
            fingerprint_status, observed_time_utc_ms, observed_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            value.mount_id,
            value.device_id,
            record.envelope.host_id,
            value.mount_root_uri,
            value.status,
            value.fingerprint_status,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            record.envelope.event_id,
        ],
    )?;
    transaction.execute(
        "UPDATE devices SET
            identity_state = CASE
                WHEN ?2 = 'mismatch' THEN 'conflict' ELSE identity_state END,
            last_fingerprint_match_time_utc_ms = CASE
                WHEN ?2 = 'match' THEN ?3 ELSE last_fingerprint_match_time_utc_ms END,
            last_fingerprint_status = ?2
         WHERE device_id = ?1",
        params![
            value.device_id,
            value.fingerprint_status,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
        ],
    )?;
    Ok(())
}

fn project_scan_started(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ScanStartedPayload = payload(record)?;
    let logical_prefix = value
        .logical_prefix
        .as_ref()
        .map(|path| path.bytes(record))
        .transpose()?;
    let scope_json = serde_json::to_string(&value.scope_json)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    let exclusions_json = serde_json::to_string(&value.exclusions_json)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    if !matches!(value.fingerprint_status.as_str(), "match" | "unavailable") {
        return Err(invalid_payload(
            record,
            "scan start requires a non-conflicting device fingerprint",
        ));
    }
    if record.envelope.location_id.as_deref() != Some(value.location_id.as_str())
        || record.envelope.device_id.as_deref() != Some(value.device_id.as_str())
    {
        return Err(invalid_payload(
            record,
            "scan start envelope does not match its location and device",
        ));
    }
    let topology_valid: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM collections c
            JOIN locations l ON l.location_id = ?2
            JOIN archive_roots r ON r.archive_root_id = l.archive_root_id
            JOIN devices d ON d.device_id = l.device_id
            WHERE c.collection_id = ?1 AND c.status = 'active'
              AND l.kind = 'filesystem' AND l.status = 'active'
              AND r.status = 'active' AND d.status = 'active'
              AND l.device_id = ?3 AND r.device_id = ?3
              AND l.archive_root_id = ?4
              AND d.identity_state != 'conflict'
         )",
        params![
            value.collection_id,
            value.location_id,
            value.device_id,
            value.archive_root_id,
        ],
        |row| row.get(0),
    )?;
    if !topology_valid {
        return Err(invalid_payload(
            record,
            "scan start does not name an active, consistent scan topology",
        ));
    }
    transaction.execute(
        "INSERT INTO scan_runs(
            scan_id, job_id, location_id, collection_id,
            logical_prefix_bytes, logical_prefix_encoding, logical_prefix_display,
            status, started_time_utc_ms, started_event_seq, coverage_version,
            scope_json, exclusions_json, exclusions_hash, error_summary_json,
            started_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'running', ?8, ?9, ?10,
                   ?11, ?12, ?13, '{}', ?14)",
        params![
            value.scan_id,
            record.envelope.job_id,
            value.location_id,
            value.collection_id,
            logical_prefix,
            value
                .logical_prefix
                .as_ref()
                .map(|path| path.encoding.as_str()),
            value
                .logical_prefix
                .as_ref()
                .map(|path| path.display.as_str()),
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            sql_integer(record.envelope.seq, "seq", record)?,
            sql_integer(value.coverage_version, "coverage_version", record)?,
            scope_json,
            exclusions_json,
            value.exclusions_hash,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_scan_missing_candidate(
    transaction: &Transaction<'_>,
    record: &EventRecord,
    kind: &str,
) -> std::result::Result<(), BatchError> {
    let value: ScanMissingCandidatePayload = payload(record)?;
    if (kind == "path" && value.file_ref_id.is_none())
        || (kind == "copy" && value.copy_claim_id.is_none())
    {
        return Err(invalid_payload(
            record,
            "missing candidate lacks its target ID",
        ));
    }
    let running: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM scan_runs
            WHERE scan_id = ?1 AND location_id = ?2 AND status = 'running'
         )",
        params![value.scan_id, value.location_id],
        |row| row.get(0),
    )?;
    if !running {
        return Err(invalid_payload(
            record,
            "missing candidate has no running scan",
        ));
    }
    transaction.execute(
        "INSERT INTO scan_missing_candidates(
            candidate_event_id, candidate_event_seq, candidate_event_hash, scan_id,
            candidate_kind, file_ref_id, copy_claim_id, location_id,
            path_bytes, path_encoding
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            record.envelope.event_id,
            sql_integer(record.envelope.seq, "seq", record)?,
            record.event_hash,
            value.scan_id,
            kind,
            value.file_ref_id,
            value.copy_claim_id,
            value.location_id,
            value.path.bytes(record)?,
            value.path.encoding,
        ],
    )?;
    Ok(())
}

fn project_scan_completed(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: ScanCompletedPayload = payload(record)?;
    if !matches!(
        value.status.as_str(),
        "complete" | "partial" | "failed" | "cancelled"
    ) {
        return Err(invalid_payload(record, "invalid scan completion status"));
    }
    let (
        location_id,
        collection_id,
        started_event_seq,
        coverage_version,
        scope_json,
        exclusions_json,
        exclusions_hash,
    ): (String, String, i64, i64, String, String, String) = transaction
        .query_row(
            "SELECT location_id, collection_id, started_event_seq, coverage_version,
                    scope_json, exclusions_json, exclusions_hash
             FROM scan_runs WHERE scan_id = ?1 AND status = 'running'",
            [&value.scan_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| invalid_payload(record, "scan completion has no running start"))?;
    let declared_scope = serde_json::to_string(&value.scope_json)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    if coverage_version != sql_integer(value.coverage_version, "coverage_version", record)?
        || scope_json != declared_scope
        || exclusions_hash != value.exclusions_hash
    {
        return Err(invalid_payload(
            record,
            "scan completion coverage does not match its start",
        ));
    }
    let interleaved = if value.status == "complete" {
        transaction.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM events e
                JOIN file_refs f ON f.file_ref_id = e.file_ref_id
                WHERE e.seq > ?1 AND e.seq < ?2
                  AND e.event_type IN ('path_observed', 'copy_observed')
                  AND e.location_id = ?3 AND f.collection_id = ?4
                  AND COALESCE(json_extract(e.payload_json, '$.scan_id'), '') != ?5
             )",
            params![
                started_event_seq,
                sql_integer(record.envelope.seq, "seq", record)?,
                location_id,
                collection_id,
                value.scan_id,
            ],
            |row| row.get(0),
        )?
    } else {
        false
    };
    if interleaved {
        let mut error_summary = value.error_summary.clone();
        if let Value::Object(summary) = &mut error_summary {
            let count = summary
                .get("concurrent_changes")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_add(1);
            summary.insert("concurrent_changes".to_owned(), Value::from(count));
            summary.insert("completion_downgraded".to_owned(), Value::from(true));
        }
        return project_incomplete_scan(
            transaction,
            record,
            &value,
            "partial",
            value.error_count.saturating_add(1),
            &error_summary,
        );
    }

    if value.status != "complete" {
        if value.observations_count != 0
            || value.observations_digest.is_some()
            || value.missing_candidate_count != 0
            || value.missing_candidate_digest.is_some()
        {
            return Err(invalid_payload(
                record,
                "an incomplete scan cannot activate missing candidates",
            ));
        }
        return project_incomplete_scan(
            transaction,
            record,
            &value,
            &value.status,
            value.error_count,
            &value.error_summary,
        );
    }

    let error_summary = serde_json::to_string(&value.error_summary)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;

    let actual = scan_completion_manifest(transaction, &value.scan_id)?;
    if actual.observations_count != value.observations_count
        || digest_option(&actual.observations_digest, actual.observations_count)
            != value.observations_digest.as_deref()
        || actual.missing_candidate_count != value.missing_candidate_count
        || digest_option(
            &actual.missing_candidate_digest,
            actual.missing_candidate_count,
        ) != value.missing_candidate_digest.as_deref()
    {
        return Err(invalid_payload(record, "scan completion manifest mismatch"));
    }

    let missing_paths = transaction.execute(
        "UPDATE path_observations AS p SET
            state = 'missing',
            last_seen_event_id = (
                SELECT c.candidate_event_id FROM scan_missing_candidates c
                WHERE c.scan_id = ?1 AND c.candidate_kind = 'path'
                  AND c.file_ref_id = p.file_ref_id
                  AND c.location_id = p.location_id
                  AND c.path_encoding = p.observed_path_encoding
                  AND c.path_bytes = p.observed_path_bytes
                  AND c.candidate_event_seq > COALESCE((
                      SELECT e.seq FROM events e WHERE e.event_id = p.last_seen_event_id
                  ), 0)
                ORDER BY c.candidate_event_seq DESC LIMIT 1
            ),
            last_seen_time_utc_ms = ?2
         WHERE EXISTS (
            SELECT 1 FROM scan_missing_candidates c
            WHERE c.scan_id = ?1 AND c.candidate_kind = 'path'
              AND c.file_ref_id = p.file_ref_id AND c.location_id = p.location_id
              AND c.path_encoding = p.observed_path_encoding
              AND c.path_bytes = p.observed_path_bytes
              AND c.candidate_event_seq > COALESCE((
                  SELECT e.seq FROM events e WHERE e.event_id = p.last_seen_event_id
              ), 0)
         )",
        params![
            value.scan_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
        ],
    )?;
    transaction.execute(
        "UPDATE copy_claims AS c SET
            state = 'missing',
            state_event_seq = (
                SELECT MAX(m.candidate_event_seq) FROM scan_missing_candidates m
                WHERE m.scan_id = ?1 AND m.candidate_kind = 'copy'
                  AND m.copy_claim_id = c.copy_claim_id
                  AND m.candidate_event_seq > c.state_event_seq
            ),
            last_seen_event_id = (
                SELECT m.candidate_event_id FROM scan_missing_candidates m
                WHERE m.scan_id = ?1 AND m.candidate_kind = 'copy'
                  AND m.copy_claim_id = c.copy_claim_id
                  AND m.candidate_event_seq > c.state_event_seq
                ORDER BY m.candidate_event_seq DESC LIMIT 1
            ),
            last_seen_time_utc_ms = ?2
         WHERE EXISTS (
            SELECT 1 FROM scan_missing_candidates m
            WHERE m.scan_id = ?1 AND m.candidate_kind = 'copy'
              AND m.copy_claim_id = c.copy_claim_id
              AND m.candidate_event_seq > c.state_event_seq
         )",
        params![
            value.scan_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
        ],
    )?;
    transaction.execute(
        "UPDATE scan_missing_candidates SET activated = 1 WHERE scan_id = ?1",
        [&value.scan_id],
    )?;
    transaction.execute(
        "UPDATE path_observations AS p SET last_complete_scan_id = ?1
         WHERE p.location_id = ?2 AND p.state = 'present'
           AND EXISTS (
             SELECT 1 FROM file_refs f
             WHERE f.file_ref_id = p.file_ref_id AND f.collection_id = ?3
               AND f.path_state = 'active'
           )
           AND NOT EXISTS (
             SELECT 1 FROM json_each(?4) x
             WHERE upper(hex(p.observed_path_bytes)) = json_extract(x.value, '$.hex')
                OR upper(hex(p.observed_path_bytes)) LIKE json_extract(x.value, '$.hex') || '2F%'
           )",
        params![value.scan_id, location_id, collection_id, exclusions_json],
    )?;
    transaction.execute(
        "UPDATE copy_claims AS c SET last_complete_scan_id = ?1
         WHERE c.location_id = ?2 AND c.state IN ('present', 'corrupt', 'unknown')
           AND EXISTS (
             SELECT 1 FROM path_observations p
             JOIN file_refs f ON f.file_ref_id = p.file_ref_id
             WHERE p.location_id = c.location_id
               AND p.observed_path_encoding = c.relative_path_encoding
               AND p.observed_path_bytes = c.relative_path_bytes
               AND f.collection_id = ?3 AND f.path_state = 'active'
           )
           AND NOT EXISTS (
             SELECT 1 FROM json_each(?4) x
             WHERE upper(hex(c.relative_path_bytes)) = json_extract(x.value, '$.hex')
                OR upper(hex(c.relative_path_bytes)) LIKE json_extract(x.value, '$.hex') || '2F%'
           )",
        params![value.scan_id, location_id, collection_id, exclusions_json],
    )?;

    transaction.execute(
        "UPDATE scan_runs SET
            status = 'complete', finished_time_utc_ms = ?2,
            observations_count = ?3, observations_digest = ?4,
            missing_candidate_count = ?5, missing_candidate_digest = ?6,
            files_seen = ?7, bytes_seen = ?8, new_paths = ?9,
            changed_paths = ?10, missing_paths = ?11, unchanged_paths = ?12,
            error_count = ?13, error_summary_json = ?14, finished_event_id = ?15
         WHERE scan_id = ?1",
        params![
            value.scan_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            sql_integer(value.observations_count, "observations_count", record)?,
            value.observations_digest,
            sql_integer(
                value.missing_candidate_count,
                "missing_candidate_count",
                record
            )?,
            value.missing_candidate_digest,
            sql_integer(value.files_seen, "files_seen", record)?,
            sql_integer(value.bytes_seen, "bytes_seen", record)?,
            sql_integer(value.new_paths, "new_paths", record)?,
            sql_integer(value.changed_paths, "changed_paths", record)?,
            i64::try_from(missing_paths).unwrap_or(i64::MAX),
            sql_integer(value.unchanged_paths, "unchanged_paths", record)?,
            sql_integer(value.error_count, "error_count", record)?,
            error_summary,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_incomplete_scan(
    transaction: &Transaction<'_>,
    record: &EventRecord,
    value: &ScanCompletedPayload,
    status: &str,
    error_count: u64,
    error_summary: &Value,
) -> std::result::Result<(), BatchError> {
    let error_summary = serde_json::to_string(error_summary)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    transaction.execute(
        "UPDATE scan_runs SET
            status = ?2, finished_time_utc_ms = ?3,
            observations_count = 0, observations_digest = NULL,
            missing_candidate_count = 0, missing_candidate_digest = NULL,
            files_seen = ?4, bytes_seen = ?5, new_paths = ?6,
            changed_paths = ?7, missing_paths = 0, unchanged_paths = ?8,
            error_count = ?9, error_summary_json = ?10, finished_event_id = ?11
         WHERE scan_id = ?1",
        params![
            value.scan_id,
            status,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            sql_integer(value.files_seen, "files_seen", record)?,
            sql_integer(value.bytes_seen, "bytes_seen", record)?,
            sql_integer(value.new_paths, "new_paths", record)?,
            sql_integer(value.changed_paths, "changed_paths", record)?,
            sql_integer(value.unchanged_paths, "unchanged_paths", record)?,
            sql_integer(error_count, "error_count", record)?,
            error_summary,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn digest_option(digest: &str, count: u64) -> Option<&str> {
    (count != 0).then_some(digest)
}

fn scan_completion_manifest(
    connection: &Connection,
    scan_id: &str,
) -> std::result::Result<ScanCompletionManifest, BatchError> {
    let (location_id, collection_id, started_event_seq, exclusions_json): (
        String,
        String,
        i64,
        String,
    ) = connection
        .query_row(
            "SELECT location_id, collection_id, started_event_seq, exclusions_json
             FROM scan_runs WHERE scan_id = ?1 AND status = 'running'",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or_else(|| {
            BatchError::Projection(ProjectionError::InvalidScan(format!(
                "scan {scan_id} is not running"
            )))
        })?;

    let mut candidate_count = 0_u64;
    let mut missing_path_count = 0_u64;
    let mut candidate_hasher = blake3::Hasher::new();
    {
        let mut statement = connection.prepare(
            "SELECT m.candidate_event_hash, m.candidate_kind,
                    CASE WHEN m.candidate_kind = 'path' THEN EXISTS (
                        SELECT 1 FROM path_observations p
                        JOIN events last_event ON last_event.event_id = p.last_seen_event_id
                        WHERE p.file_ref_id = m.file_ref_id
                          AND p.location_id = m.location_id
                          AND p.observed_path_encoding = m.path_encoding
                          AND p.observed_path_bytes = m.path_bytes
                          AND m.candidate_event_seq > last_event.seq
                    ) ELSE 0 END
             FROM scan_missing_candidates m
             WHERE m.scan_id = ?1 ORDER BY m.candidate_event_seq",
        )?;
        let rows = statement.query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?;
        for row in rows {
            let (hash, kind, effective) = row?;
            hash_piece(&mut candidate_hasher, hash.as_bytes());
            candidate_count += 1;
            if kind == "path" && effective {
                missing_path_count += 1;
            }
        }
    }

    let mut observation_count = 0_u64;
    let mut observation_hasher = blake3::Hasher::new();
    {
        let mut statement = connection.prepare(
            "WITH covered(kind, target_id, path_encoding, path_bytes) AS (
                SELECT 'path', p.file_ref_id, p.observed_path_encoding, p.observed_path_bytes
                FROM path_observations p
                JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                JOIN events first_event ON first_event.event_id = p.first_seen_event_id
                JOIN events last_event ON last_event.event_id = p.last_seen_event_id
                WHERE p.location_id = ?1 AND f.collection_id = ?2
                  AND f.path_state = 'active' AND p.state = 'present'
                  AND (first_event.seq <= ?3 OR json_extract(last_event.payload_json, '$.scan_id') = ?4)
                  AND NOT EXISTS (
                    SELECT 1 FROM scan_missing_candidates m
                    WHERE m.scan_id = ?4 AND m.candidate_kind = 'path'
                      AND m.file_ref_id = p.file_ref_id AND m.location_id = p.location_id
                      AND m.path_encoding = p.observed_path_encoding
                      AND m.path_bytes = p.observed_path_bytes
                      AND m.candidate_event_seq > last_event.seq
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM json_each(?5) x
                    WHERE upper(hex(p.observed_path_bytes)) = json_extract(x.value, '$.hex')
                       OR upper(hex(p.observed_path_bytes)) LIKE json_extract(x.value, '$.hex') || '2F%'
                  )
                UNION ALL
                SELECT DISTINCT 'copy', c.copy_claim_id, c.relative_path_encoding, c.relative_path_bytes
                FROM copy_claims c
                JOIN path_observations p
                  ON p.location_id = c.location_id
                 AND p.observed_path_encoding = c.relative_path_encoding
                 AND p.observed_path_bytes = c.relative_path_bytes
                JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                JOIN events first_event ON first_event.event_id = c.first_seen_event_id
                JOIN events last_event ON last_event.event_id = c.last_seen_event_id
                WHERE c.location_id = ?1 AND f.collection_id = ?2
                  AND f.path_state = 'active' AND c.state IN ('present', 'corrupt', 'unknown')
                  AND (first_event.seq <= ?3 OR json_extract(last_event.payload_json, '$.scan_id') = ?4)
                  AND NOT EXISTS (
                    SELECT 1 FROM scan_missing_candidates m
                    WHERE m.scan_id = ?4 AND m.candidate_kind = 'copy'
                      AND m.copy_claim_id = c.copy_claim_id
                      AND m.candidate_event_seq > c.state_event_seq
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM json_each(?5) x
                    WHERE upper(hex(c.relative_path_bytes)) = json_extract(x.value, '$.hex')
                       OR upper(hex(c.relative_path_bytes)) LIKE json_extract(x.value, '$.hex') || '2F%'
                  )
             )
             SELECT kind, target_id, path_encoding, path_bytes FROM covered
             ORDER BY path_encoding, path_bytes, kind, target_id",
        )?;
        let rows = statement.query_map(
            params![
                location_id,
                collection_id,
                started_event_seq,
                scan_id,
                exclusions_json
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        for row in rows {
            let (kind, target_id, encoding, path) = row?;
            hash_piece(&mut observation_hasher, kind.as_bytes());
            hash_piece(&mut observation_hasher, target_id.as_bytes());
            hash_piece(&mut observation_hasher, encoding.as_bytes());
            hash_piece(&mut observation_hasher, &path);
            observation_count += 1;
        }
    }
    Ok(ScanCompletionManifest {
        observations_count: observation_count,
        observations_digest: observation_hasher.finalize().to_hex().to_string(),
        missing_candidate_count: candidate_count,
        missing_candidate_digest: candidate_hasher.finalize().to_hex().to_string(),
        missing_path_count,
    })
}

fn hash_piece(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn project_annex_import_started(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: AnnexImportStartedPayload = payload(record)?;
    let repo_path = value.repo_path.bytes(record)?;
    transaction.execute(
        "INSERT INTO annex_imports(
            import_id, job_id, repo_path_bytes, repo_path_encoding, repo_path_display,
            collection_id, worktree_location_id, cas_location_id, device_id,
            archive_root_id, annex_uuid, git_head_commit, status, summary_json,
            started_event_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   'running', '{}', ?13)",
        params![
            value.import_id,
            record.envelope.job_id,
            repo_path,
            value.repo_path.encoding,
            value.repo_path.display,
            value.collection_id,
            value.worktree_location_id,
            value.cas_location_id,
            value.device_id,
            value.archive_root_id,
            value.annex_uuid,
            value.git_head_commit,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn project_annex_import_completed(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let value: AnnexImportCompletedPayload = payload(record)?;
    let summary = serde_json::to_string(&value.summary)
        .map_err(|error| invalid_payload(record, &error.to_string()))?;
    let changed = transaction.execute(
        "UPDATE annex_imports
         SET status = ?2, summary_json = ?3, completed_event_id = ?4
         WHERE import_id = ?1",
        params![
            value.import_id,
            value.status,
            summary,
            record.envelope.event_id,
        ],
    )?;
    if changed != 1 {
        return Err(invalid_payload(
            record,
            "annex import completion has no start",
        ));
    }
    Ok(())
}

fn optional_sql_integer(
    value: Option<u64>,
    field: &str,
    record: &EventRecord,
) -> std::result::Result<Option<i64>, BatchError> {
    value
        .map(|value| sql_integer(value, field, record))
        .transpose()
}

fn project_operation_outcome(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let Some(operation_key) = record
        .envelope
        .payload
        .get("operation_key")
        .and_then(|value| value.as_str())
    else {
        return Ok(());
    };
    let existing: Option<String> = transaction
        .query_row(
            "SELECT event_id FROM operation_outcomes WHERE operation_key = ?1",
            [operation_key],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(event_id) = existing {
        return Err(BatchError::Projection(
            ProjectionError::DuplicateOperationKey {
                operation_key: operation_key.to_owned(),
                event_id,
            },
        ));
    }
    let payload: OperationOutcomePayload = serde_json::from_value(record.envelope.payload.clone())
        .map_err(|source| {
            BatchError::Projection(ProjectionError::InvalidPayload {
                event_type: record.envelope.event_type.clone(),
                seq: record.envelope.seq,
                message: format!("operation outcome: {source}"),
            })
        })?;
    transaction.execute(
        "INSERT INTO operation_outcomes(
            operation_key, event_id, event_seq, job_id, job_type, item_type, item_key, outcome_kind
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            payload.operation_key,
            record.envelope.event_id,
            sql_integer(record.envelope.seq, "seq", record)?,
            record.envelope.job_id,
            payload.job_type,
            payload.item_type,
            payload.item_key,
            payload.outcome_kind,
        ],
    )?;
    Ok(())
}

fn project_checkpoint_created(
    transaction: &Transaction<'_>,
    record: &EventRecord,
) -> std::result::Result<(), BatchError> {
    let payload: CheckpointCreatedPayload = serde_json::from_value(record.envelope.payload.clone())
        .map_err(|source| {
            BatchError::Projection(ProjectionError::InvalidPayload {
                event_type: record.envelope.event_type.clone(),
                seq: record.envelope.seq,
                message: source.to_string(),
            })
        })?;
    if payload.event_last_seq != record.envelope.seq {
        return Err(BatchError::Projection(ProjectionError::InvalidPayload {
            event_type: record.envelope.event_type.clone(),
            seq: record.envelope.seq,
            message: "event_last_seq does not match the envelope".to_owned(),
        }));
    }
    transaction.execute(
        "INSERT INTO checkpoints(
            checkpoint_id, created_time_utc_ms, stream_id, event_first_seq, event_last_seq,
            event_last_hash, manifest_path, created_event_id, verification_status
         ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, 'unverified')",
        params![
            payload.checkpoint_id,
            sql_integer(record.envelope.time_utc_ms, "time_utc_ms", record)?,
            record.envelope.stream_id,
            sql_integer(record.envelope.seq, "seq", record)?,
            record.event_hash,
            payload.checkpoint_path,
            record.envelope.event_id,
        ],
    )?;
    Ok(())
}

fn sql_integer(
    value: u64,
    field: &str,
    record: &EventRecord,
) -> std::result::Result<i64, BatchError> {
    i64::try_from(value).map_err(|_| {
        BatchError::Projection(ProjectionError::InvalidPayload {
            event_type: record.envelope.event_type.clone(),
            seq: record.envelope.seq,
            message: format!("{field} exceeds SQLite's signed integer range"),
        })
    })
}

fn add_read_stats(target: &mut ApplyStats, read: &EventReadStats) {
    target.segments_opened += read.segments_opened;
    target.lines_read += read.lines_read;
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(|source| io_error("open database directory for sync", path, source))?
            .sync_all()
            .map_err(|source| io_error("sync database directory", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

struct RebuildGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for RebuildGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_file(sqlite_sidecar(&self.path, "-wal"));
            let _ = fs::remove_file(sqlite_sidecar(&self.path, "-shm"));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::event_store::{EventRequest, EventStoreConfig};

    fn event_store(temp: &TempDir, rollover_events: u64) -> EventStore {
        EventStore::open_or_create(
            temp.path().join("canonical"),
            EventStoreConfig {
                rollover_events,
                max_event_bytes: 1024 * 1024,
                actor_id: "test-user".to_owned(),
                host_id: "test-host".to_owned(),
            },
        )
        .unwrap()
    }

    fn database(temp: &TempDir, config: ProjectionConfig) -> ProjectionDb {
        ProjectionDb::open_or_create(temp.path().join("archive.db"), "arc_test", config).unwrap()
    }

    fn summary_event(number: u64) -> EventRequest {
        EventRequest::new("job_started", json!({ "number": number }))
    }

    #[test]
    fn schema_v4_contains_every_specified_table_tier() {
        assert_eq!(parent_directory(Path::new("archive.db")), Path::new("."));
        let temp = TempDir::new().unwrap();
        let database = database(&temp, ProjectionConfig::default());
        let connection = database.open_connection().unwrap();
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let actual: BTreeSet<String> = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let expected: BTreeSet<String> = [
            "archive_meta",
            "events",
            "objects",
            "object_hashes",
            "external_identities",
            "external_availability",
            "collections",
            "file_refs",
            "path_observations",
            "devices",
            "device_mounts",
            "device_site_history",
            "archive_roots",
            "sites",
            "locations",
            "risk_domains",
            "entity_risk_domains",
            "copy_claims",
            "scan_runs",
            "scan_missing_candidates",
            "verification_results",
            "policies",
            "checkpoints",
            "metadata_destinations",
            "checkpoint_replications",
            "annex_imports",
            "annex_remotes",
            "operation_outcomes",
            "jobs",
            "job_items",
            "policy_evaluations",
            "policy_status",
            "policy_rollup",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(actual, expected);
        assert_eq!(database.status().unwrap().schema_version, 4);
    }

    #[test]
    fn incremental_apply_reads_only_the_unapplied_tail() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 1_000);
        store
            .append_batch((0..100).map(summary_event).collect())
            .unwrap();
        let database = database(
            &temp,
            ProjectionConfig {
                batch_events: 10,
                ..ProjectionConfig::default()
            },
        );
        let interrupted = database.apply_at_most(&store, 1).unwrap();
        assert_eq!(interrupted.events_applied, 10);
        assert!(!interrupted.caught_up);
        assert_eq!(database.status().unwrap().cursor.applied_seq, 10);
        let initial = database.apply(&store).unwrap();
        assert_eq!(initial.events_applied, 90);
        assert_eq!(initial.lines_read, 90);
        assert!(initial.caught_up);

        store.append(summary_event(100)).unwrap();
        let tail = database.apply(&store).unwrap();
        assert_eq!(tail.events_applied, 1);
        assert_eq!(tail.lines_read, 1);
        assert_eq!(tail.segments_opened, 1);
        assert_eq!(database.status().unwrap().cursor.applied_seq, 101);
    }

    #[test]
    fn projection_failure_leaves_cursor_before_the_failing_event() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 1_000);
        store
            .append_batch(vec![
                EventRequest::new(
                    "job_started",
                    json!({
                        "operation_key": "op_same",
                        "job_type": "import",
                        "item_type": "path",
                        "item_key": "one",
                        "outcome_kind": "observed"
                    }),
                ),
                EventRequest::new(
                    "job_started",
                    json!({
                        "operation_key": "op_same",
                        "job_type": "import",
                        "item_type": "path",
                        "item_key": "two",
                        "outcome_kind": "observed"
                    }),
                ),
            ])
            .unwrap();
        let database = database(
            &temp,
            ProjectionConfig {
                batch_events: 1,
                ..ProjectionConfig::default()
            },
        );
        let error = database.apply(&store).unwrap_err();
        assert_eq!(error.code(), "duplicate_operation_key");
        assert_eq!(database.status().unwrap().cursor.applied_seq, 1);
        let connection = database.open_connection().unwrap();
        let outcomes: i64 = connection
            .query_row("SELECT count(*) FROM operation_outcomes", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(outcomes, 1);
    }

    #[test]
    fn unknown_event_rolls_back_its_entire_bounded_transaction() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 1_000);
        store
            .append_batch(vec![
                summary_event(1),
                EventRequest::new("future_event", json!({})),
            ])
            .unwrap();
        let database = database(&temp, ProjectionConfig::default());
        assert_eq!(
            database.apply(&store).unwrap_err().code(),
            "unsupported_event_type"
        );
        assert_eq!(database.status().unwrap().cursor.applied_seq, 0);
        let connection = database.open_connection().unwrap();
        let events: i64 = connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events, 0);
    }

    #[test]
    fn rebuild_replaces_the_database_with_equivalent_event_derived_state() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 2);
        store
            .append_batch((0..5).map(summary_event).collect())
            .unwrap();
        store.create_checkpoint().unwrap();
        let database = database(&temp, ProjectionConfig::default());
        database.apply(&store).unwrap();

        let target = temp.path().join("rebuilt.db");
        let existing =
            ProjectionDb::open_or_create(&target, "arc_test", ProjectionConfig::default()).unwrap();
        assert_eq!(existing.status().unwrap().cursor.applied_seq, 0);
        let rebuild_stats =
            ProjectionDb::rebuild(&store, &target, "arc_test", ProjectionConfig::default())
                .unwrap();
        assert_eq!(rebuild_stats.events_applied, 6);
        assert_eq!(rebuild_stats.lines_read, 6);
        assert!(rebuild_stats.caught_up);
        let rebuilt =
            ProjectionDb::open_or_create(&target, "arc_test", ProjectionConfig::default()).unwrap();
        assert_eq!(database.status().unwrap(), rebuilt.status().unwrap());

        let state = |database: &ProjectionDb| {
            let connection = database.open_connection().unwrap();
            let events = connection
                .prepare(
                    "SELECT seq, event_id, event_type, payload_json, event_hash
                     FROM events ORDER BY seq",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let checkpoints = connection
                .prepare(
                    "SELECT checkpoint_id, event_last_seq, event_last_hash, manifest_path,
                            created_event_id, verification_status
                     FROM checkpoints ORDER BY event_last_seq",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (events, checkpoints)
        };
        assert_eq!(state(&database), state(&rebuilt));
        assert_eq!(state(&rebuilt).0.len(), 6);
        assert_eq!(state(&rebuilt).1.len(), 1);
    }

    #[test]
    fn status_fails_closed_when_its_cursor_disagrees_with_the_event_mirror() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 100);
        store.append(summary_event(1)).unwrap();
        let database = database(&temp, ProjectionConfig::default());
        database.apply(&store).unwrap();
        let connection = database.open_connection().unwrap();
        connection
            .execute(
                "UPDATE archive_meta SET value = ?1 WHERE key = 'applied_event_hash'",
                [format!("blake3:{}", "0".repeat(64))],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            database.status().unwrap_err().code(),
            "invalid_projection_cursor"
        );
    }

    #[test]
    fn failed_rebuild_preserves_the_existing_database() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("archive.db");
        let existing =
            ProjectionDb::open_or_create(&target, "arc_test", ProjectionConfig::default()).unwrap();
        assert_eq!(existing.status().unwrap().cursor.applied_seq, 0);

        let store = event_store(&temp, 100);
        store
            .append(EventRequest::new("future_event", json!({})))
            .unwrap();
        assert_eq!(
            ProjectionDb::rebuild(&store, &target, "arc_test", ProjectionConfig::default(),)
                .unwrap_err()
                .code(),
            "unsupported_event_type"
        );
        assert_eq!(
            ProjectionDb::open_or_create(&target, "arc_test", ProjectionConfig::default(),)
                .unwrap()
                .status()
                .unwrap()
                .cursor
                .applied_seq,
            0
        );
    }

    #[test]
    fn status_does_not_require_the_canonical_event_directory() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 100);
        store.append(summary_event(1)).unwrap();
        let database = database(&temp, ProjectionConfig::default());
        database.apply(&store).unwrap();

        let canonical = temp.path().join("canonical");
        let unavailable = temp.path().join("canonical-unavailable");
        fs::rename(&canonical, &unavailable).unwrap();
        assert_eq!(database.status().unwrap().cursor.applied_seq, 1);
        fs::rename(&unavailable, &canonical).unwrap();
    }

    #[test]
    fn registry_snapshots_project_and_rebuild_with_validated_topology() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 100);
        let requirements = json!({
            "min_qualifying_copies": 2,
            "min_devices": 2,
            "min_sites": 2,
            "require_offsite_copy": true,
            "require_offline_copy": false,
            "require_encrypted_offsite": false,
            "max_verification_age_days": 365,
            "max_observation_age_days": 365,
            "max_device_checkin_age_days": 365
        });
        store
            .append_batch(vec![
                EventRequest::new(
                    "site_registered",
                    json!({"site_id":"site_1","display_name":"Home","site_kind":"home",
                           "description":null,"status":"active"}),
                ),
                EventRequest::new(
                    "policy_registered",
                    json!({"policy_id":"policy_1","display_name":"Starter","policy_version":1,
                           "requirements":requirements,"enabled":true,"status":"active"}),
                ),
                EventRequest::new(
                    "collection_registered",
                    json!({"collection_id":"collection_1","display_name":"Photos",
                           "description":null,"home_site_id":"site_1","policy_id":"policy_1",
                           "status":"active"}),
                ),
                EventRequest::new(
                    "device_registered",
                    json!({"device_id":"device_1","display_name":"Disk","device_kind":"disk",
                           "serial_hint":null,"hardware_fingerprint":"fp1","fingerprint_kind":"serial",
                           "identity_state":"confirmed","owner":null,"status":"active",
                           "current_site_id":"site_1","expected_availability":"online"}),
                ),
                EventRequest::new(
                    "archive_root_registered",
                    json!({"archive_root_id":"root_1","device_id":"device_1",
                           "display_name":"Archive root","root_path_on_device":{
                             "encoding":"utf8","text":"/archive","base64":null,"display":"/archive"},
                           "status":"active"}),
                ),
                EventRequest::new(
                    "location_registered",
                    json!({"location_id":"location_1","display_name":"Main archive",
                           "kind":"filesystem","archive_root_id":"root_1","relative_path":{
                             "encoding":"utf8","text":"photos","base64":null,"display":"photos"},
                           "device_id":"device_1","site_id":null,"encryption_state":"encrypted",
                           "trust_level":"trusted","expected_availability":"online",
                           "is_writable":false,"status":"active"}),
                ),
                EventRequest::new(
                    "risk_domain_registered",
                    json!({"risk_domain_id":"risk_1","display_name":"Flood zone",
                           "risk_kind":"environment","description":null,"status":"active"}),
                ),
                EventRequest::new(
                    "risk_assigned",
                    json!({"entity_type":"archive_root","entity_id":"root_1",
                           "risk_domain_id":"risk_1"}),
                ),
            ])
            .unwrap();
        let database = database(&temp, ProjectionConfig::default());
        database.apply(&store).unwrap();
        let connection = database.open_connection().unwrap();
        let count = |table: &str| -> i64 {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        assert_eq!(count("sites"), 1);
        assert_eq!(count("policies"), 1);
        assert_eq!(count("collections"), 1);
        assert_eq!(count("devices"), 1);
        assert_eq!(count("device_site_history"), 1);
        assert_eq!(count("archive_roots"), 1);
        assert_eq!(count("locations"), 1);
        assert_eq!(count("risk_domains"), 1);
        assert_eq!(count("entity_risk_domains"), 1);
        drop(connection);

        let rebuilt_path = temp.path().join("rebuilt.db");
        let rebuilt = ProjectionDb::rebuild(
            &store,
            &rebuilt_path,
            "arc_test",
            ProjectionConfig::default(),
        )
        .unwrap();
        assert_eq!(rebuilt.events_applied, 8);
        let rebuilt =
            ProjectionDb::open_existing(rebuilt_path, ProjectionConfig::default()).unwrap();
        assert_eq!(rebuilt.status().unwrap().cursor.applied_seq, 8);
        assert_eq!(
            rebuilt
                .open_connection()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM entity_risk_domains", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn invalid_registry_topology_fails_before_projection_cursor_advances() {
        let temp = TempDir::new().unwrap();
        let store = event_store(&temp, 100);
        store
            .append_batch(vec![
                EventRequest::new(
                    "site_registered",
                    json!({"site_id":"site_1","display_name":"Home","site_kind":"home",
                           "description":null,"status":"active"}),
                ),
                EventRequest::new(
                    "device_registered",
                    json!({"device_id":"device_1","display_name":"Disk","device_kind":"disk",
                           "serial_hint":null,"hardware_fingerprint":"fp1","fingerprint_kind":"serial",
                           "identity_state":"confirmed","owner":null,"status":"active",
                           "current_site_id":"site_1","expected_availability":"online"}),
                ),
                EventRequest::new(
                    "location_registered",
                    json!({"location_id":"bad","display_name":"Bad location","kind":"filesystem",
                           "archive_root_id":"missing","relative_path":{"encoding":"utf8",
                             "text":"","base64":null,"display":""},"device_id":"device_1",
                           "site_id":null,"encryption_state":"unknown","trust_level":"unknown",
                           "expected_availability":"online","is_writable":false,"status":"active"}),
                ),
            ])
            .unwrap();
        let database = database(&temp, ProjectionConfig::default());
        let error = database.apply(&store).unwrap_err();
        assert_eq!(error.code(), "invalid_event_payload");
        assert_eq!(database.status().unwrap().cursor.applied_seq, 0);
    }

    #[test]
    fn policy_input_classification_is_exhaustive_and_distinguishes_bookkeeping() {
        let expected: BTreeSet<&str> = [
            "archive_initialized",
            "catalog_location_set",
            "checkpoint_created",
            "checkpoint_commit_observed",
            "checkpoint_replication_observed",
            "collection_registered",
            "collection_updated",
            "collection_retired",
            "site_registered",
            "site_updated",
            "site_retired",
            "device_registered",
            "device_updated",
            "device_moved",
            "device_checked_in",
            "device_retired",
            "device_mount_observed",
            "archive_root_registered",
            "archive_root_updated",
            "archive_root_retired",
            "location_registered",
            "location_updated",
            "location_retired",
            "metadata_destination_registered",
            "metadata_destination_updated",
            "metadata_destination_retired",
            "risk_domain_registered",
            "risk_domain_updated",
            "risk_domain_retired",
            "risk_assigned",
            "risk_unassigned",
            "policy_registered",
            "policy_updated",
            "policy_retired",
            "external_identity_observed",
            "external_identity_resolved",
            "external_availability_observed",
            "annex_remote_mapped",
            "annex_remote_unmapped",
            "object_observed",
            "object_hash_added",
            "file_ref_observed",
            "file_ref_updated",
            "file_ref_removed",
            "path_observed",
            "path_missing_candidate",
            "copy_observed",
            "copy_missing_candidate",
            "scan_started",
            "scan_completed",
            "copy_verified",
            "job_started",
            "job_finished",
            "annex_import_started",
            "annex_import_completed",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            SUPPORTED_EVENT_TYPES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert!(SUPPORTED_EVENT_TYPES
            .iter()
            .all(|event_type| policy_relevance(event_type).is_some()));
        assert_eq!(policy_relevance("copy_verified"), Some(true));
        assert_eq!(policy_relevance("checkpoint_created"), Some(false));
        assert_eq!(policy_relevance("future_event"), None);
    }
}
