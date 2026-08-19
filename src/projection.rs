use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Deserialize;
use thiserror::Error;
use ulid::Ulid;

use crate::event_store::{
    EventCursor, EventReadStats, EventRecord, EventStore, EventStoreError, PositionedEvent,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
                    "file_ref_observed",
                    json!({
                        "operation_key": "op_same",
                        "job_type": "import",
                        "item_type": "path",
                        "item_key": "one",
                        "outcome_kind": "observed"
                    }),
                ),
                EventRequest::new(
                    "file_ref_observed",
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
