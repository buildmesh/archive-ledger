//! Read-only external-directory audits backed by a non-canonical checksum manifest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::discovery::{
    modified_time_ms, DiscoveryError, DiscoveryItem, EncodedPath, FileDiscovery,
};
use crate::policy::{PolicyError, PolicyRequirements};
use crate::projection::{ProjectionDb, ProjectionError};
use crate::v2_projection::{V2ProjectionDb, V2ProjectionError};

pub const DEFAULT_STAGE_DIRECTORY: &str = ".archive-ledger-stage";
pub const DEFAULT_STAGE_MANIFEST: &str = "manifest.sqlite3";
const STAGE_SCHEMA_VERSION: i64 = 2;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const DEFAULT_BATCH_FILES: u64 = 1_000;

pub type Result<T> = std::result::Result<T, StageError>;

#[derive(Debug, Error)]
pub enum StageError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),

    #[error(transparent)]
    Projection(#[from] ProjectionError),

    #[error(transparent)]
    V2Projection(#[from] V2ProjectionError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error("stage manifest SQLite error at {path}: {source}")]
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

    #[error("invalid stage manifest: {0}")]
    InvalidManifest(String),

    #[error("invalid stage path: {0}")]
    InvalidPath(String),

    #[error("stage manifest has no complete or partial audit to import")]
    NotAudited,

    #[error("lossless staged paths are unavailable on this platform")]
    UnsupportedPlatform,
}

impl StageError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Discovery(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::V2Projection(error) => error.code(),
            Self::Policy(error) => error.code(),
            Self::Sqlite { .. } => "stage_sqlite",
            Self::Io { .. } => "stage_io",
            Self::InvalidManifest(_) => "stage_invalid_manifest",
            Self::InvalidPath(_) => "stage_invalid_path",
            Self::NotAudited => "stage_not_audited",
            Self::UnsupportedPlatform => "stage_platform_unsupported",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StageAuditOptions {
    pub source: PathBuf,
    pub manifest: Option<PathBuf>,
    pub collection_id: Option<String>,
    pub list_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageFileReview {
    pub path_encoding: String,
    pub path_display: String,
    pub path_text: Option<String>,
    pub path_base64: Option<String>,
    pub size_bytes: u64,
    pub blake3_hex: String,
    pub archive_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageReport {
    pub version: u32,
    pub source: PathBuf,
    pub manifest: PathBuf,
    pub manifest_is_source_local: bool,
    pub audit_status: String,
    pub archive_id: String,
    pub applied_event_seq: u64,
    pub selected_collection_id: Option<String>,
    pub files_seen: u64,
    pub bytes_seen: u64,
    pub checksums_computed: u64,
    pub checksums_reused: u64,
    pub new_to_archive_files: u64,
    pub new_to_archive_objects: u64,
    pub known_in_selected_collection: u64,
    pub known_only_in_other_collections: u64,
    pub known_policy_satisfied_files: u64,
    pub known_at_risk_files: u64,
    pub known_policy_unknown_files: u64,
    pub policy_evidence_stale_policies: u64,
    pub policy_unconfigured_collections: u64,
    pub source_removal_ready: bool,
    pub duplicate_files: u64,
    pub ignored_symlinks: u64,
    pub special_files: u64,
    pub excluded_subtrees: u64,
    pub filesystem_boundaries: u64,
    pub traversal_errors: u64,
    pub content_read_errors: u64,
    pub concurrent_changes: u64,
    pub listed_files: Vec<StageFileReview>,
    pub listed_files_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageImportCandidate {
    pub relative_path: PathBuf,
    pub path_display: String,
    pub size_bytes: u64,
    pub modified_time_utc_ms: Option<u64>,
    pub blake3_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageImportCursor {
    path_encoding: String,
    path_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageImportPage {
    pub items: Vec<StageImportCandidate>,
    pub next: Option<StageImportCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageImportPlan {
    pub source: PathBuf,
    pub manifest: PathBuf,
    pub eligible_files: u64,
    pub eligible_bytes: u64,
    generation: String,
    selection_job_id: Option<String>,
}

impl StageImportPlan {
    pub fn input_version(&self) -> &str {
        &self.generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    size_bytes: u64,
    modified_time_utc_ms: Option<u64>,
    inode: Option<u64>,
    ctime_seconds: Option<i64>,
    ctime_nanoseconds: Option<i64>,
}

#[derive(Debug, Default)]
struct AuditCounts {
    files_seen: u64,
    bytes_seen: u64,
    checksums_computed: u64,
    checksums_reused: u64,
    ignored_symlinks: u64,
    special_files: u64,
    excluded_subtrees: u64,
    filesystem_boundaries: u64,
    traversal_errors: u64,
    content_read_errors: u64,
    concurrent_changes: u64,
}

enum HashOutcome {
    Stable { blake3_hex: String },
    ReadError,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectionState {
    Satisfied,
    AtRisk,
    Unknown,
}

#[derive(Debug)]
struct ObjectArchiveReview {
    collections: Vec<String>,
    protection: ProtectionState,
}

pub fn audit_stage(database: &ProjectionDb, options: &StageAuditOptions) -> Result<StageReport> {
    let source = fs::canonicalize(&options.source)
        .map_err(|error| io_error("resolve stage source", &options.source, error))?;
    if !fs::metadata(&source)
        .map_err(|error| io_error("inspect stage source", &source, error))?
        .is_dir()
    {
        return Err(StageError::InvalidPath(format!(
            "stage source must be a directory: {}",
            source.display()
        )));
    }
    let (manifest, manifest_is_source_local) =
        resolve_audit_manifest(&source, options.manifest.as_deref())?;
    let mut connection = open_manifest(&manifest)?;
    initialize_manifest(&connection, &manifest)?;
    let generation = format!("stage_{}", Ulid::new().to_string().to_ascii_lowercase());
    set_meta(
        &connection,
        &manifest,
        "source_path",
        &source.to_string_lossy(),
    )?;
    set_meta(&connection, &manifest, "generation", &generation)?;
    set_meta(&connection, &manifest, "audit_status", "running")?;

    let mut exclusions = vec![PathBuf::from(DEFAULT_STAGE_DIRECTORY)];
    if let Ok(relative_manifest) = manifest.strip_prefix(&source) {
        if !relative_manifest.as_os_str().is_empty() {
            exclusions.extend(manifest_sidecar_exclusions(relative_manifest));
        }
    }
    exclusions.sort();
    exclusions.dedup();
    let mut discovery = FileDiscovery::with_exclusions(&source, exclusions)?;
    let mut counts = AuditCounts::default();
    let mut batch_count = 0_u64;
    begin_manifest_batch(&connection, &manifest)?;
    for item in discovery.by_ref() {
        match item {
            DiscoveryItem::File(file) => {
                counts.files_seen = counts.files_seen.saturating_add(1);
                counts.bytes_seen = counts.bytes_seen.saturating_add(file.size_bytes);
                let relative = raw_relative_path(&file.relative_path)?;
                let absolute = source.join(&relative);
                let fingerprint = fingerprint(&absolute)?;
                let existing =
                    cached_checksum(&connection, &manifest, &file.relative_path, &fingerprint)?;
                let (state, checksum) = if let Some(checksum) = existing {
                    counts.checksums_reused = counts.checksums_reused.saturating_add(1);
                    ("stable", Some(checksum))
                } else {
                    match hash_stable(&absolute, &fingerprint) {
                        HashOutcome::Stable { blake3_hex } => {
                            counts.checksums_computed = counts.checksums_computed.saturating_add(1);
                            ("stable", Some(blake3_hex))
                        }
                        HashOutcome::ReadError => {
                            counts.content_read_errors =
                                counts.content_read_errors.saturating_add(1);
                            ("read_error", None)
                        }
                        HashOutcome::Changed => {
                            counts.concurrent_changes = counts.concurrent_changes.saturating_add(1);
                            ("unstable", None)
                        }
                    }
                };
                upsert_staged_file(
                    &connection,
                    &manifest,
                    &generation,
                    &file.relative_path,
                    &fingerprint,
                    state,
                    checksum.as_deref(),
                )?;
                batch_count += 1;
                if batch_count >= DEFAULT_BATCH_FILES {
                    commit_manifest_batch(&connection, &manifest)?;
                    begin_manifest_batch(&connection, &manifest)?;
                    batch_count = 0;
                }
            }
            DiscoveryItem::Symlink(_) => {
                counts.ignored_symlinks = counts.ignored_symlinks.saturating_add(1)
            }
            DiscoveryItem::Special(_) => {
                counts.special_files = counts.special_files.saturating_add(1)
            }
            DiscoveryItem::Excluded(_) => {
                counts.excluded_subtrees = counts.excluded_subtrees.saturating_add(1)
            }
            DiscoveryItem::FilesystemBoundary(_) => {
                counts.filesystem_boundaries = counts.filesystem_boundaries.saturating_add(1)
            }
            DiscoveryItem::ConcurrentChange(_) => {
                counts.concurrent_changes = counts.concurrent_changes.saturating_add(1)
            }
            DiscoveryItem::Error { .. } => {
                counts.traversal_errors = counts.traversal_errors.saturating_add(1)
            }
        }
    }
    commit_manifest_batch(&connection, &manifest)?;
    let audit_status = if counts.traversal_errors == 0
        && counts.content_read_errors == 0
        && counts.concurrent_changes == 0
    {
        connection
            .execute(
                "DELETE FROM staged_files WHERE generation != ?1",
                [&generation],
            )
            .map_err(|source| sqlite_error(&manifest, source))?;
        "complete"
    } else {
        "partial"
    };
    set_meta(&connection, &manifest, "audit_status", audit_status)?;
    set_meta(
        &connection,
        &manifest,
        "completed_time_utc_ms",
        &now_utc_ms()?.to_string(),
    )?;

    classify_manifest(
        database,
        &mut connection,
        &manifest,
        &source,
        manifest_is_source_local,
        &generation,
        audit_status,
        &counts,
        options.collection_id.as_deref(),
        options.list_limit,
    )
}

pub fn audit_stage_v2(
    database: &V2ProjectionDb,
    options: &StageAuditOptions,
) -> Result<StageReport> {
    let source = fs::canonicalize(&options.source)
        .map_err(|error| io_error("resolve stage source", &options.source, error))?;
    if !fs::metadata(&source)
        .map_err(|error| io_error("inspect stage source", &source, error))?
        .is_dir()
    {
        return Err(StageError::InvalidPath(format!(
            "stage source must be a directory: {}",
            source.display()
        )));
    }
    let (manifest, manifest_is_source_local) =
        resolve_audit_manifest(&source, options.manifest.as_deref())?;
    let mut connection = open_manifest(&manifest)?;
    initialize_manifest(&connection, &manifest)?;
    let generation = format!("stage_{}", Ulid::new().to_string().to_ascii_lowercase());
    set_meta(
        &connection,
        &manifest,
        "source_path",
        &source.to_string_lossy(),
    )?;
    set_meta(&connection, &manifest, "generation", &generation)?;
    set_meta(&connection, &manifest, "audit_status", "running")?;
    let mut exclusions = vec![PathBuf::from(DEFAULT_STAGE_DIRECTORY)];
    if let Ok(relative_manifest) = manifest.strip_prefix(&source) {
        if !relative_manifest.as_os_str().is_empty() {
            exclusions.extend(manifest_sidecar_exclusions(relative_manifest));
        }
    }
    exclusions.sort();
    exclusions.dedup();
    let mut discovery = FileDiscovery::with_exclusions(&source, exclusions)?;
    let mut counts = AuditCounts::default();
    let mut batch_count = 0_u64;
    begin_manifest_batch(&connection, &manifest)?;
    for item in discovery.by_ref() {
        match item {
            DiscoveryItem::File(file) => {
                counts.files_seen = counts.files_seen.saturating_add(1);
                counts.bytes_seen = counts.bytes_seen.saturating_add(file.size_bytes);
                let relative = raw_relative_path(&file.relative_path)?;
                let absolute = source.join(&relative);
                let fingerprint = fingerprint(&absolute)?;
                let existing =
                    cached_checksum(&connection, &manifest, &file.relative_path, &fingerprint)?;
                let (state, checksum) = if let Some(checksum) = existing {
                    counts.checksums_reused = counts.checksums_reused.saturating_add(1);
                    ("stable", Some(checksum))
                } else {
                    match hash_stable(&absolute, &fingerprint) {
                        HashOutcome::Stable { blake3_hex } => {
                            counts.checksums_computed = counts.checksums_computed.saturating_add(1);
                            ("stable", Some(blake3_hex))
                        }
                        HashOutcome::ReadError => {
                            counts.content_read_errors =
                                counts.content_read_errors.saturating_add(1);
                            ("read_error", None)
                        }
                        HashOutcome::Changed => {
                            counts.concurrent_changes = counts.concurrent_changes.saturating_add(1);
                            ("unstable", None)
                        }
                    }
                };
                upsert_staged_file(
                    &connection,
                    &manifest,
                    &generation,
                    &file.relative_path,
                    &fingerprint,
                    state,
                    checksum.as_deref(),
                )?;
                batch_count += 1;
                if batch_count >= DEFAULT_BATCH_FILES {
                    commit_manifest_batch(&connection, &manifest)?;
                    begin_manifest_batch(&connection, &manifest)?;
                    batch_count = 0;
                }
            }
            DiscoveryItem::Symlink(_) => {
                counts.ignored_symlinks = counts.ignored_symlinks.saturating_add(1)
            }
            DiscoveryItem::Special(_) => {
                counts.special_files = counts.special_files.saturating_add(1)
            }
            DiscoveryItem::Excluded(_) => {
                counts.excluded_subtrees = counts.excluded_subtrees.saturating_add(1)
            }
            DiscoveryItem::FilesystemBoundary(_) => {
                counts.filesystem_boundaries = counts.filesystem_boundaries.saturating_add(1)
            }
            DiscoveryItem::ConcurrentChange(_) => {
                counts.concurrent_changes = counts.concurrent_changes.saturating_add(1)
            }
            DiscoveryItem::Error { .. } => {
                counts.traversal_errors = counts.traversal_errors.saturating_add(1)
            }
        }
    }
    commit_manifest_batch(&connection, &manifest)?;
    let audit_status = if counts.traversal_errors == 0
        && counts.content_read_errors == 0
        && counts.concurrent_changes == 0
    {
        connection
            .execute(
                "DELETE FROM staged_files WHERE generation != ?1",
                [&generation],
            )
            .map_err(|source| sqlite_error(&manifest, source))?;
        "complete"
    } else {
        "partial"
    };
    set_meta(&connection, &manifest, "audit_status", audit_status)?;
    set_meta(
        &connection,
        &manifest,
        "completed_time_utc_ms",
        &now_utc_ms()?.to_string(),
    )?;
    classify_manifest_v2(
        database,
        &mut connection,
        &manifest,
        &source,
        manifest_is_source_local,
        &generation,
        audit_status,
        &counts,
        options.collection_id.as_deref(),
        options.list_limit,
    )
}

pub fn prepare_stage_import(
    database: &ProjectionDb,
    source: &Path,
    manifest_override: Option<&Path>,
) -> Result<StageImportPlan> {
    let archive = database.status()?;
    prepare_stage_import_at(
        database.path(),
        &archive.archive_id,
        source,
        manifest_override,
    )
}

pub fn prepare_stage_import_v2(
    database: &V2ProjectionDb,
    source: &Path,
    manifest_override: Option<&Path>,
) -> Result<StageImportPlan> {
    let archive = database.status()?;
    prepare_stage_import_at(
        database.path(),
        &archive.archive_id,
        source,
        manifest_override,
    )
}

fn prepare_stage_import_at(
    database_path: &Path,
    archive_id: &str,
    source: &Path,
    manifest_override: Option<&Path>,
) -> Result<StageImportPlan> {
    let source = fs::canonicalize(source)
        .map_err(|error| io_error("resolve stage import source", source, error))?;
    let manifest = resolve_existing_manifest(&source, manifest_override)?;
    let connection = open_manifest(&manifest)?;
    initialize_manifest(&connection, &manifest)?;
    let generation =
        get_meta(&connection, &manifest, "generation")?.ok_or(StageError::NotAudited)?;
    let status = get_meta(&connection, &manifest, "audit_status")?.ok_or(StageError::NotAudited)?;
    if !matches!(status.as_str(), "complete" | "partial") {
        return Err(StageError::NotAudited);
    }
    let catalog = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| sqlite_error(database_path, source))?;
    let mut rows = connection
        .prepare(
            "SELECT size_bytes, blake3_hex
             FROM staged_files
             WHERE generation = ?1 AND content_state = 'stable'
             ORDER BY path_encoding, path_bytes",
        )
        .map_err(|source| sqlite_error(&manifest, source))?;
    let rows = rows
        .query_map([&generation], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(&manifest, source))?;
    let mut eligible_files = 0_u64;
    let mut eligible_bytes = 0_u64;
    for row in rows {
        let (size, hash) = row.map_err(|source| sqlite_error(&manifest, source))?;
        if object_is_cataloged(&catalog, database_path, &hash)? {
            continue;
        }
        let size = u64::try_from(size)
            .map_err(|_| StageError::InvalidManifest("negative staged file size".to_owned()))?;
        eligible_files = eligible_files.saturating_add(1);
        eligible_bytes = eligible_bytes.checked_add(size).ok_or_else(|| {
            StageError::InvalidManifest("staged import byte total exceeds u64".to_owned())
        })?;
    }
    set_meta(&connection, &manifest, "last_import_archive_id", archive_id)?;
    Ok(StageImportPlan {
        source,
        manifest,
        eligible_files,
        eligible_bytes,
        generation,
        selection_job_id: None,
    })
}

/// Freezes the archive-unknown paths selected by a mutating stage import.
///
/// The selection lives only in the non-canonical stage manifest. A resumed
/// job therefore processes exactly the paths reviewed when that job started,
/// even if another Archive operation catalogs the same content meanwhile.
pub fn select_stage_import(
    database: &ProjectionDb,
    plan: StageImportPlan,
    job_id: &str,
) -> Result<StageImportPlan> {
    select_stage_import_at(database.path(), plan, job_id)
}

pub fn select_stage_import_v2(
    database: &V2ProjectionDb,
    plan: StageImportPlan,
    job_id: &str,
) -> Result<StageImportPlan> {
    select_stage_import_at(database.path(), plan, job_id)
}

fn select_stage_import_at(
    database_path: &Path,
    mut plan: StageImportPlan,
    job_id: &str,
) -> Result<StageImportPlan> {
    let mut manifest = open_manifest(&plan.manifest)?;
    initialize_manifest(&manifest, &plan.manifest)?;
    let catalog = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| sqlite_error(database_path, source))?;
    let transaction = manifest
        .transaction()
        .map_err(|source| sqlite_error(&plan.manifest, source))?;
    let existing: Option<(String, String)> = transaction
        .query_row(
            "SELECT generation, source_path FROM stage_import_jobs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|source| sqlite_error(&plan.manifest, source))?;
    if let Some((generation, source_path)) = existing {
        if generation != plan.generation || source_path != plan.source.to_string_lossy() {
            return Err(StageError::InvalidManifest(format!(
                "stage import job {job_id} belongs to a different audit or source"
            )));
        }
    } else {
        transaction
            .execute(
                "INSERT INTO stage_import_jobs(job_id, generation, source_path)
                 VALUES (?1, ?2, ?3)",
                params![job_id, plan.generation, plan.source.to_string_lossy()],
            )
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        let mut statement = transaction
            .prepare(
                "SELECT path_encoding, path_bytes, blake3_hex
                 FROM staged_files
                 WHERE generation = ?1 AND content_state = 'stable'
                 ORDER BY path_encoding, path_bytes",
            )
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        let mut rows = statement
            .query([&plan.generation])
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        while let Some(row) = rows
            .next()
            .map_err(|source| sqlite_error(&plan.manifest, source))?
        {
            let hash: String = row
                .get(2)
                .map_err(|source| sqlite_error(&plan.manifest, source))?;
            if object_is_cataloged(&catalog, database_path, &hash)? {
                continue;
            }
            transaction
                .execute(
                    "INSERT INTO stage_import_files(job_id, path_encoding, path_bytes)
                     VALUES (?1, ?2, ?3)",
                    params![
                        job_id,
                        row.get::<_, String>(0)
                            .map_err(|source| sqlite_error(&plan.manifest, source))?,
                        row.get::<_, Vec<u8>>(1)
                            .map_err(|source| sqlite_error(&plan.manifest, source))?
                    ],
                )
                .map_err(|source| sqlite_error(&plan.manifest, source))?;
        }
        drop(rows);
        drop(statement);
    }
    let (files, bytes): (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(staged.size_bytes), 0)
             FROM stage_import_files selected
             JOIN staged_files staged
               ON staged.path_encoding = selected.path_encoding
              AND staged.path_bytes = selected.path_bytes
             WHERE selected.job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|source| sqlite_error(&plan.manifest, source))?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(&plan.manifest, source))?;
    plan.eligible_files = u64::try_from(files)
        .map_err(|_| StageError::InvalidManifest("negative import file count".to_owned()))?;
    plan.eligible_bytes = u64::try_from(bytes)
        .map_err(|_| StageError::InvalidManifest("negative import byte count".to_owned()))?;
    plan.selection_job_id = Some(job_id.to_owned());
    Ok(plan)
}

pub fn stage_import_candidates(
    database: &ProjectionDb,
    plan: &StageImportPlan,
    after: Option<&StageImportCursor>,
    limit: usize,
) -> Result<StageImportPage> {
    stage_import_candidates_at(database.path(), plan, after, limit)
}

pub fn stage_import_candidates_v2(
    database: &V2ProjectionDb,
    plan: &StageImportPlan,
    after: Option<&StageImportCursor>,
    limit: usize,
) -> Result<StageImportPage> {
    stage_import_candidates_at(database.path(), plan, after, limit)
}

fn stage_import_candidates_at(
    database_path: &Path,
    plan: &StageImportPlan,
    after: Option<&StageImportCursor>,
    limit: usize,
) -> Result<StageImportPage> {
    if limit == 0 {
        return Err(StageError::InvalidManifest(
            "stage import page limit must be greater than zero".to_owned(),
        ));
    }
    let connection = open_manifest(&plan.manifest)?;
    validate_manifest(&connection, &plan.manifest)?;
    let catalog = plan
        .selection_job_id
        .is_none()
        .then(|| {
            Connection::open_with_flags(
                database_path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|source| sqlite_error(database_path, source))
        })
        .transpose()?;
    let selection_filter = "AND (?4 IS NULL OR EXISTS(
             SELECT 1 FROM stage_import_files selected
             WHERE selected.job_id = ?4
               AND selected.path_encoding = staged_files.path_encoding
               AND selected.path_bytes = staged_files.path_bytes
         ))";
    let sql = format!(
        "SELECT path_encoding, path_bytes, path_display, size_bytes,
                    modified_time_utc_ms, blake3_hex
             FROM staged_files
             WHERE generation = ?1 AND content_state = 'stable'
               AND (?2 IS NULL OR path_encoding > ?2
                    OR (path_encoding = ?2 AND path_bytes > ?3))
               {selection_filter}
             ORDER BY path_encoding, path_bytes"
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|source| sqlite_error(&plan.manifest, source))?;
    let after_encoding = after.map(|cursor| cursor.path_encoding.as_str());
    let after_bytes = after.map(|cursor| cursor.path_bytes.as_slice());
    let mut rows = statement
        .query(params![
            plan.generation,
            after_encoding,
            after_bytes,
            plan.selection_job_id
        ])
        .map_err(|source| sqlite_error(&plan.manifest, source))?;
    let mut items = Vec::with_capacity(limit.min(1_000));
    let mut last_cursor = None;
    let mut has_more = false;
    while let Some(row) = rows
        .next()
        .map_err(|source| sqlite_error(&plan.manifest, source))?
    {
        let encoding: String = row
            .get(0)
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        let bytes: Vec<u8> = row
            .get(1)
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        let hash: String = row
            .get(5)
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        let cursor = StageImportCursor {
            path_encoding: encoding.clone(),
            path_bytes: bytes.clone(),
        };
        if let Some(catalog) = &catalog {
            if object_is_cataloged(catalog, database_path, &hash)? {
                last_cursor = Some(cursor);
                continue;
            }
        }
        if items.len() == limit {
            has_more = true;
            break;
        }
        let size: i64 = row
            .get(3)
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        let modified: Option<i64> = row
            .get(4)
            .map_err(|source| sqlite_error(&plan.manifest, source))?;
        items.push(StageImportCandidate {
            relative_path: decoded_path(&encoding, &bytes)?,
            path_display: row
                .get(2)
                .map_err(|source| sqlite_error(&plan.manifest, source))?,
            size_bytes: u64::try_from(size)
                .map_err(|_| StageError::InvalidManifest("negative staged file size".to_owned()))?,
            modified_time_utc_ms: modified.and_then(|value| u64::try_from(value).ok()),
            blake3_hex: hash,
        });
        last_cursor = Some(cursor);
    }
    Ok(StageImportPage {
        items,
        next: has_more.then_some(last_cursor).flatten(),
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_manifest(
    database: &ProjectionDb,
    manifest_connection: &mut Connection,
    manifest: &Path,
    source: &Path,
    manifest_is_source_local: bool,
    generation: &str,
    audit_status: &str,
    counts: &AuditCounts,
    selected_collection: Option<&str>,
    list_limit: usize,
) -> Result<StageReport> {
    let archive = database.status()?;
    let policy_status = database.cached_policy_status(now_utc_ms()?)?;
    let catalog = Connection::open_with_flags(
        database.path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| sqlite_error(database.path(), source))?;
    catalog
        .execute_batch(
            "CREATE TEMP TABLE stage_usable_policy_evaluations (
                 policy_id TEXT PRIMARY KEY,
                 evaluation_id TEXT NOT NULL
             ) WITHOUT ROWID;",
        )
        .map_err(|source| sqlite_error(database.path(), source))?;
    for evaluation in &policy_status.evaluations {
        catalog
            .execute(
                "INSERT INTO temp.stage_usable_policy_evaluations(policy_id, evaluation_id)
                 VALUES (?1, ?2)",
                params![evaluation.policy_id, evaluation.evaluation_id],
            )
            .map_err(|source| sqlite_error(database.path(), source))?;
    }
    let transaction = manifest_connection
        .transaction()
        .map_err(|source| sqlite_error(manifest, source))?;
    let mut query = transaction
        .prepare(
            "SELECT path_encoding, path_bytes, path_display, size_bytes, blake3_hex
             FROM staged_files
             WHERE generation = ?1 AND content_state = 'stable'
             ORDER BY path_encoding, path_bytes",
        )
        .map_err(|source| sqlite_error(manifest, source))?;
    let rows = query
        .query_map([generation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|source| sqlite_error(manifest, source))?;
    let mut new_files = 0_u64;
    let mut known_selected = 0_u64;
    let mut known_other = 0_u64;
    let mut policy_satisfied = 0_u64;
    let mut policy_at_risk = 0_u64;
    let mut policy_unknown = 0_u64;
    let mut listed_files = Vec::new();
    for row in rows {
        let (encoding, bytes, display, size, hash) =
            row.map_err(|source| sqlite_error(manifest, source))?;
        let review = object_archive_review(&catalog, database.path(), &hash)?;
        let state = if review.collections.is_empty() {
            new_files = new_files.saturating_add(1);
            "new_to_archive"
        } else if selected_collection
            .is_some_and(|selected| review.collections.iter().any(|value| value == selected))
        {
            known_selected = known_selected.saturating_add(1);
            "known_in_selected_collection"
        } else {
            known_other = known_other.saturating_add(1);
            "known_in_other_collection"
        };
        if !review.collections.is_empty() {
            match review.protection {
                ProtectionState::Satisfied => policy_satisfied = policy_satisfied.saturating_add(1),
                ProtectionState::AtRisk => policy_at_risk = policy_at_risk.saturating_add(1),
                ProtectionState::Unknown => policy_unknown = policy_unknown.saturating_add(1),
            }
        }
        transaction
            .execute(
                "UPDATE staged_files
                 SET archive_id = ?1, archive_event_seq = ?2, archive_state = ?3
                 WHERE path_encoding = ?4 AND path_bytes = ?5",
                params![
                    archive.archive_id,
                    i64::try_from(archive.cursor.applied_seq).unwrap_or(i64::MAX),
                    state,
                    encoding,
                    bytes
                ],
            )
            .map_err(|source| sqlite_error(manifest, source))?;
        if state == "new_to_archive" && listed_files.len() < list_limit {
            let (text, base64) = path_json_parts(&encoding, &bytes);
            listed_files.push(StageFileReview {
                path_encoding: encoding,
                path_display: display,
                path_text: text,
                path_base64: base64,
                size_bytes: u64::try_from(size).unwrap_or(0),
                blake3_hex: hash,
                archive_state: state.to_owned(),
            });
        }
    }
    drop(query);
    transaction
        .commit()
        .map_err(|source| sqlite_error(manifest, source))?;
    let new_objects = scalar_u64(
        manifest_connection,
        manifest,
        "SELECT COUNT(DISTINCT blake3_hex) FROM staged_files
         WHERE generation = ?1 AND content_state = 'stable' AND archive_state = 'new_to_archive'",
        generation,
    )?;
    let duplicate_files = scalar_u64(
        manifest_connection,
        manifest,
        "SELECT COALESCE(SUM(copies - 1), 0) FROM (
             SELECT COUNT(*) AS copies FROM staged_files
             WHERE generation = ?1 AND content_state = 'stable'
             GROUP BY blake3_hex HAVING COUNT(*) > 1
         )",
        generation,
    )?;
    set_meta(
        manifest_connection,
        manifest,
        "last_archive_id",
        &archive.archive_id,
    )?;
    set_meta(
        manifest_connection,
        manifest,
        "last_archive_event_seq",
        &archive.cursor.applied_seq.to_string(),
    )?;
    Ok(StageReport {
        version: 2,
        source: source.to_path_buf(),
        manifest: manifest.to_path_buf(),
        manifest_is_source_local,
        audit_status: audit_status.to_owned(),
        archive_id: archive.archive_id,
        applied_event_seq: archive.cursor.applied_seq,
        selected_collection_id: selected_collection.map(ToOwned::to_owned),
        files_seen: counts.files_seen,
        bytes_seen: counts.bytes_seen,
        checksums_computed: counts.checksums_computed,
        checksums_reused: counts.checksums_reused,
        new_to_archive_files: new_files,
        new_to_archive_objects: new_objects,
        known_in_selected_collection: known_selected,
        known_only_in_other_collections: known_other,
        known_policy_satisfied_files: policy_satisfied,
        known_at_risk_files: policy_at_risk,
        known_policy_unknown_files: policy_unknown,
        policy_evidence_stale_policies: policy_status.stale_policies.len() as u64,
        policy_unconfigured_collections: policy_status.unconfigured_collections.len() as u64,
        source_removal_ready: audit_status == "complete"
            && new_files == 0
            && policy_at_risk == 0
            && policy_unknown == 0,
        duplicate_files,
        ignored_symlinks: counts.ignored_symlinks,
        special_files: counts.special_files,
        excluded_subtrees: counts.excluded_subtrees,
        filesystem_boundaries: counts.filesystem_boundaries,
        traversal_errors: counts.traversal_errors,
        content_read_errors: counts.content_read_errors,
        concurrent_changes: counts.concurrent_changes,
        listed_files,
        listed_files_truncated: usize::try_from(new_files).unwrap_or(usize::MAX) > list_limit,
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_manifest_v2(
    database: &V2ProjectionDb,
    manifest_connection: &mut Connection,
    manifest: &Path,
    source: &Path,
    manifest_is_source_local: bool,
    generation: &str,
    audit_status: &str,
    counts: &AuditCounts,
    selected_collection: Option<&str>,
    list_limit: usize,
) -> Result<StageReport> {
    let archive = database.status()?;
    let catalog = Connection::open_with_flags(
        database.path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| sqlite_error(database.path(), source))?;
    let transaction = manifest_connection
        .transaction()
        .map_err(|source| sqlite_error(manifest, source))?;
    let mut query = transaction
        .prepare(
            "SELECT path_encoding, path_bytes, path_display, size_bytes, blake3_hex
             FROM staged_files
             WHERE generation = ?1 AND content_state = 'stable'
             ORDER BY path_encoding, path_bytes",
        )
        .map_err(|source| sqlite_error(manifest, source))?;
    let rows = query
        .query_map([generation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|source| sqlite_error(manifest, source))?;
    let mut new_files = 0_u64;
    let mut known_selected = 0_u64;
    let mut known_other = 0_u64;
    let mut policy_satisfied = 0_u64;
    let mut policy_at_risk = 0_u64;
    let mut policy_unknown = 0_u64;
    let mut review_cache = BTreeMap::new();
    let mut listed_files = Vec::new();
    for row in rows {
        let (encoding, bytes, display, size, hash) =
            row.map_err(|source| sqlite_error(manifest, source))?;
        let review = if let Some(review) = review_cache.get(&hash) {
            review
        } else {
            let review = v2_object_archive_review(&catalog, database.path(), &hash)?;
            review_cache.insert(hash.clone(), review);
            review_cache.get(&hash).expect("review was inserted")
        };
        let collections = &review.collections;
        let state = if collections.is_empty() {
            new_files = new_files.saturating_add(1);
            "new_to_archive"
        } else if selected_collection
            .is_some_and(|selected| collections.iter().any(|value| value == selected))
        {
            known_selected = known_selected.saturating_add(1);
            "known_in_selected_collection"
        } else {
            known_other = known_other.saturating_add(1);
            "known_in_other_collection"
        };
        if !collections.is_empty() {
            match review.protection {
                ProtectionState::Satisfied => policy_satisfied = policy_satisfied.saturating_add(1),
                ProtectionState::AtRisk => policy_at_risk = policy_at_risk.saturating_add(1),
                ProtectionState::Unknown => policy_unknown = policy_unknown.saturating_add(1),
            }
        }
        transaction
            .execute(
                "UPDATE staged_files SET archive_id = ?1, archive_event_seq = ?2, archive_state = ?3
                 WHERE path_encoding = ?4 AND path_bytes = ?5",
                params![
                    archive.archive_id,
                    i64::try_from(archive.records).unwrap_or(i64::MAX),
                    state,
                    encoding,
                    bytes,
                ],
            )
            .map_err(|source| sqlite_error(manifest, source))?;
        if state == "new_to_archive" && listed_files.len() < list_limit {
            let (text, base64) = path_json_parts(&encoding, &bytes);
            listed_files.push(StageFileReview {
                path_encoding: encoding,
                path_display: display,
                path_text: text,
                path_base64: base64,
                size_bytes: u64::try_from(size).unwrap_or(0),
                blake3_hex: hash,
                archive_state: state.to_owned(),
            });
        }
    }
    drop(query);
    transaction
        .commit()
        .map_err(|source| sqlite_error(manifest, source))?;
    let new_objects = scalar_u64(
        manifest_connection,
        manifest,
        "SELECT COUNT(DISTINCT blake3_hex) FROM staged_files
         WHERE generation = ?1 AND content_state = 'stable' AND archive_state = 'new_to_archive'",
        generation,
    )?;
    let duplicate_files = scalar_u64(
        manifest_connection,
        manifest,
        "SELECT COALESCE(SUM(copies - 1), 0) FROM (
             SELECT COUNT(*) AS copies FROM staged_files
             WHERE generation = ?1 AND content_state = 'stable'
             GROUP BY blake3_hex HAVING COUNT(*) > 1
         )",
        generation,
    )?;
    set_meta(
        manifest_connection,
        manifest,
        "last_archive_id",
        &archive.archive_id,
    )?;
    set_meta(
        manifest_connection,
        manifest,
        "last_archive_event_seq",
        &archive.records.to_string(),
    )?;
    Ok(StageReport {
        version: 2,
        source: source.to_path_buf(),
        manifest: manifest.to_path_buf(),
        manifest_is_source_local,
        audit_status: audit_status.to_owned(),
        archive_id: archive.archive_id,
        applied_event_seq: archive.records,
        selected_collection_id: selected_collection.map(ToOwned::to_owned),
        files_seen: counts.files_seen,
        bytes_seen: counts.bytes_seen,
        checksums_computed: counts.checksums_computed,
        checksums_reused: counts.checksums_reused,
        new_to_archive_files: new_files,
        new_to_archive_objects: new_objects,
        known_in_selected_collection: known_selected,
        known_only_in_other_collections: known_other,
        known_policy_satisfied_files: policy_satisfied,
        known_at_risk_files: policy_at_risk,
        known_policy_unknown_files: policy_unknown,
        policy_evidence_stale_policies: 0,
        policy_unconfigured_collections: 0,
        source_removal_ready: audit_status == "complete"
            && new_files == 0
            && policy_at_risk == 0
            && policy_unknown == 0,
        duplicate_files,
        ignored_symlinks: counts.ignored_symlinks,
        special_files: counts.special_files,
        excluded_subtrees: counts.excluded_subtrees,
        filesystem_boundaries: counts.filesystem_boundaries,
        traversal_errors: counts.traversal_errors,
        content_read_errors: counts.content_read_errors,
        concurrent_changes: counts.concurrent_changes,
        listed_files,
        listed_files_truncated: usize::try_from(new_files).unwrap_or(usize::MAX) > list_limit,
    })
}

fn object_collections(connection: &Connection, path: &Path, hash: &str) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare_cached(
            "SELECT DISTINCT f.collection_id
             FROM objects o JOIN file_refs f ON f.object_id = o.object_id
             WHERE o.canonical_hash_algo = 'blake3' AND o.canonical_hash_hex = ?1
               AND f.path_state = 'active'
             ORDER BY f.collection_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let collections = statement
        .query_map([hash], |row| row.get(0))
        .map_err(|source| sqlite_error(path, source))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, source))?;
    Ok(collections)
}

fn v2_object_archive_review(
    connection: &Connection,
    path: &Path,
    hash: &str,
) -> Result<ObjectArchiveReview> {
    let collections = object_collections(connection, path, hash)?;
    if collections.is_empty() {
        return Ok(ObjectArchiveReview {
            collections,
            protection: ProtectionState::Unknown,
        });
    }
    let now = i64::try_from(now_utc_ms()?)
        .map_err(|_| StageError::InvalidManifest("system time exceeds SQLite range".to_owned()))?;
    let mut protection = ProtectionState::Satisfied;
    for collection_id in &collections {
        let policy: Option<(String, String, Option<String>)> = connection
            .query_row(
                "SELECT p.policy_id, p.requirements_json, c.home_site_id
                 FROM collections c
                 JOIN policies p ON p.policy_id = c.policy_id
                    AND p.enabled = 1 AND p.status = 'active'
                 WHERE c.collection_id = ?1 AND c.status = 'active'",
                [collection_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|source| sqlite_error(path, source))?;
        let Some((policy_id, requirements_json, home_site_id)) = policy else {
            protection = ProtectionState::Unknown;
            continue;
        };
        let requirements = PolicyRequirements::from_json(&policy_id, &requirements_json)?;
        let mut statement = connection
            .prepare_cached(
                "SELECT c.copy_claim_id, l.device_id,
                        COALESCE(d.current_site_id, l.site_id),
                        l.expected_availability, l.encryption_state,
                        c.last_seen_time_utc_ms, c.last_verified_time_utc_ms,
                        c.last_verification_result, d.last_checkin_time_utc_ms
                 FROM objects o
                 JOIN copy_claims c ON c.object_id = o.object_id AND c.state = 'present'
                 JOIN locations l ON l.location_id = c.location_id AND l.status = 'active'
                 LEFT JOIN devices d ON d.device_id = l.device_id AND d.status = 'active'
                 WHERE o.canonical_hash_algo = 'blake3' AND o.canonical_hash_hex = ?1
                 ORDER BY c.copy_claim_id",
            )
            .map_err(|source| sqlite_error(path, source))?;
        let mut rows = statement
            .query([hash])
            .map_err(|source| sqlite_error(path, source))?;
        let mut copies = BTreeSet::new();
        let mut devices = BTreeSet::new();
        let mut sites = BTreeSet::new();
        let mut has_offsite = false;
        let mut has_offline = false;
        let mut has_encrypted_offsite = false;
        while let Some(row) = rows.next().map_err(|source| sqlite_error(path, source))? {
            let device_id: Option<String> =
                row.get(1).map_err(|source| sqlite_error(path, source))?;
            let site_id: Option<String> =
                row.get(2).map_err(|source| sqlite_error(path, source))?;
            let last_seen: Option<i64> = row.get(5).map_err(|source| sqlite_error(path, source))?;
            let last_verified: Option<i64> =
                row.get(6).map_err(|source| sqlite_error(path, source))?;
            let result: Option<String> = row.get(7).map_err(|source| sqlite_error(path, source))?;
            let last_checkin: Option<i64> =
                row.get(8).map_err(|source| sqlite_error(path, source))?;
            if result.as_deref() != Some("ok")
                || !stage_age_is_fresh(now, last_seen, requirements.max_observation_age_days)
                || !stage_age_is_fresh(now, last_verified, requirements.max_verification_age_days)
                || (device_id.is_some()
                    && !stage_age_is_fresh(
                        now,
                        last_checkin,
                        requirements.max_device_checkin_age_days,
                    ))
            {
                continue;
            }
            copies.insert(
                row.get::<_, String>(0)
                    .map_err(|source| sqlite_error(path, source))?,
            );
            if let Some(device_id) = device_id {
                devices.insert(device_id);
            }
            if let Some(site_id) = &site_id {
                sites.insert(site_id.clone());
            }
            let offsite = home_site_id
                .as_deref()
                .is_some_and(|home| site_id.as_deref().is_some_and(|site| site != home));
            has_offsite |= offsite;
            has_offline |= row
                .get::<_, String>(3)
                .map_err(|source| sqlite_error(path, source))?
                == "offline";
            has_encrypted_offsite |= offsite
                && row
                    .get::<_, Option<String>>(4)
                    .map_err(|source| sqlite_error(path, source))?
                    .as_deref()
                    == Some("encrypted");
        }
        let violated = u64::try_from(copies.len()).unwrap_or(u64::MAX)
            < requirements.min_qualifying_copies
            || u64::try_from(devices.len()).unwrap_or(u64::MAX) < requirements.min_devices
            || u64::try_from(sites.len()).unwrap_or(u64::MAX) < requirements.min_sites
            || (requirements.require_offsite_copy && !has_offsite)
            || (requirements.require_offline_copy && !has_offline)
            || (requirements.require_encrypted_offsite && !has_encrypted_offsite);
        if violated {
            protection = ProtectionState::AtRisk;
        }
    }
    Ok(ObjectArchiveReview {
        collections,
        protection,
    })
}

fn stage_age_is_fresh(now: i64, timestamp: Option<i64>, max_days: u64) -> bool {
    let Some(timestamp) = timestamp else {
        return false;
    };
    let max_age = i64::try_from(max_days.saturating_mul(86_400_000)).unwrap_or(i64::MAX);
    timestamp >= now.saturating_sub(max_age)
}

fn initialize_manifest(connection: &Connection, path: &Path) -> Result<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, source))?;
    if version == 0 {
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE stage_meta (
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE staged_files (
                     path_encoding TEXT NOT NULL,
                     path_bytes BLOB NOT NULL,
                     path_display TEXT NOT NULL,
                     size_bytes INTEGER NOT NULL,
                     modified_time_utc_ms INTEGER,
                     inode INTEGER,
                     ctime_seconds INTEGER,
                     ctime_nanoseconds INTEGER,
                     blake3_hex TEXT,
                     content_state TEXT NOT NULL,
                     generation TEXT NOT NULL,
                     archive_id TEXT,
                     archive_event_seq INTEGER,
                     archive_state TEXT,
                     PRIMARY KEY (path_encoding, path_bytes)
                 ) WITHOUT ROWID;
                 CREATE INDEX staged_files_generation ON staged_files(generation, content_state);
                 CREATE INDEX staged_files_hash ON staged_files(blake3_hex) WHERE blake3_hex IS NOT NULL;
                 CREATE TABLE stage_import_jobs (
                     job_id TEXT PRIMARY KEY,
                     generation TEXT NOT NULL,
                     source_path TEXT NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE stage_import_files (
                     job_id TEXT NOT NULL REFERENCES stage_import_jobs(job_id),
                     path_encoding TEXT NOT NULL,
                     path_bytes BLOB NOT NULL,
                     PRIMARY KEY (job_id, path_encoding, path_bytes)
                 ) WITHOUT ROWID;
                 PRAGMA user_version=2;",
            )
            .map_err(|source| sqlite_error(path, source))?;
    } else if version == 1 {
        connection
            .execute_batch(
                "CREATE TABLE stage_import_jobs (
                     job_id TEXT PRIMARY KEY,
                     generation TEXT NOT NULL,
                     source_path TEXT NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE stage_import_files (
                     job_id TEXT NOT NULL REFERENCES stage_import_jobs(job_id),
                     path_encoding TEXT NOT NULL,
                     path_bytes BLOB NOT NULL,
                     PRIMARY KEY (job_id, path_encoding, path_bytes)
                 ) WITHOUT ROWID;
                 PRAGMA user_version=2;",
            )
            .map_err(|source| sqlite_error(path, source))?;
    } else if version != STAGE_SCHEMA_VERSION {
        return Err(StageError::InvalidManifest(format!(
            "unsupported stage schema version {version}; expected {STAGE_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn validate_manifest(connection: &Connection, path: &Path) -> Result<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, source))?;
    if version != STAGE_SCHEMA_VERSION {
        return Err(StageError::InvalidManifest(format!(
            "unsupported stage schema version {version}; expected {STAGE_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn resolve_audit_manifest(source: &Path, override_path: Option<&Path>) -> Result<(PathBuf, bool)> {
    if let Some(path) = override_path {
        let path = absolute_path(path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| io_error("create stage manifest directory", parent, error))?;
        }
        return Ok((path.clone(), path.starts_with(source)));
    }
    let directory = source.join(DEFAULT_STAGE_DIRECTORY);
    match create_private_directory(&directory) {
        Ok(()) => return Ok((directory.join(DEFAULT_STAGE_MANIFEST), true)),
        Err(StageError::Io { source: error, .. })
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) => {}
        Err(error) => return Err(error),
    }
    let directory = std::env::temp_dir().join(format!(
        "archive-ledger-stage-{}",
        Ulid::new().to_string().to_ascii_lowercase()
    ));
    create_private_directory(&directory)?;
    Ok((directory.join(DEFAULT_STAGE_MANIFEST), false))
}

fn resolve_existing_manifest(source: &Path, override_path: Option<&Path>) -> Result<PathBuf> {
    let manifest = if let Some(path) = override_path {
        absolute_path(path)?
    } else {
        source
            .join(DEFAULT_STAGE_DIRECTORY)
            .join(DEFAULT_STAGE_MANIFEST)
    };
    if !manifest.is_file() {
        return Err(StageError::InvalidManifest(format!(
            "stage manifest not found at {}; rerun archive stage or provide --manifest",
            manifest.display()
        )));
    }
    Ok(manifest)
}

fn open_manifest(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| sqlite_error(path, source))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|source| sqlite_error(path, source))?;
    Ok(connection)
}

fn cached_checksum(
    connection: &Connection,
    manifest: &Path,
    path: &EncodedPath,
    fingerprint: &FileFingerprint,
) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT blake3_hex FROM staged_files
             WHERE path_encoding = ?1 AND path_bytes = ?2
               AND content_state = 'stable' AND size_bytes = ?3
               AND modified_time_utc_ms IS ?4 AND inode IS ?5
               AND ctime_seconds IS ?6 AND ctime_nanoseconds IS ?7",
            params![
                path.encoding.as_str(),
                path.bytes,
                sql_i64(fingerprint.size_bytes, "staged file size")?,
                optional_sql_i64(fingerprint.modified_time_utc_ms),
                fingerprint
                    .inode
                    .and_then(|value| i64::try_from(value).ok()),
                fingerprint.ctime_seconds,
                fingerprint.ctime_nanoseconds,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(manifest, source))
}

#[allow(clippy::too_many_arguments)]
fn upsert_staged_file(
    connection: &Connection,
    manifest: &Path,
    generation: &str,
    path: &EncodedPath,
    fingerprint: &FileFingerprint,
    state: &str,
    checksum: Option<&str>,
) -> Result<()> {
    connection
        .execute(
            "INSERT INTO staged_files(
                 path_encoding, path_bytes, path_display, size_bytes,
                 modified_time_utc_ms, inode, ctime_seconds, ctime_nanoseconds,
                 blake3_hex, content_state, generation, archive_id,
                 archive_event_seq, archive_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, NULL)
             ON CONFLICT(path_encoding, path_bytes) DO UPDATE SET
                 path_display=excluded.path_display, size_bytes=excluded.size_bytes,
                 modified_time_utc_ms=excluded.modified_time_utc_ms, inode=excluded.inode,
                 ctime_seconds=excluded.ctime_seconds,
                 ctime_nanoseconds=excluded.ctime_nanoseconds,
                 blake3_hex=excluded.blake3_hex, content_state=excluded.content_state,
                 generation=excluded.generation, archive_id=NULL,
                 archive_event_seq=NULL, archive_state=NULL",
            params![
                path.encoding.as_str(),
                path.bytes,
                path.display,
                sql_i64(fingerprint.size_bytes, "staged file size")?,
                optional_sql_i64(fingerprint.modified_time_utc_ms),
                fingerprint
                    .inode
                    .and_then(|value| i64::try_from(value).ok()),
                fingerprint.ctime_seconds,
                fingerprint.ctime_nanoseconds,
                checksum,
                state,
                generation,
            ],
        )
        .map_err(|source| sqlite_error(manifest, source))?;
    Ok(())
}

fn fingerprint(path: &Path) -> Result<FileFingerprint> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect staged file", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(StageError::InvalidPath(format!(
            "staged path is no longer a regular file: {}",
            path.display()
        )));
    }
    Ok(fingerprint_from_metadata(&metadata))
}

fn fingerprint_from_metadata(metadata: &fs::Metadata) -> FileFingerprint {
    FileFingerprint {
        size_bytes: metadata.len(),
        modified_time_utc_ms: modified_time_ms(metadata),
        #[cfg(unix)]
        inode: Some(metadata.ino()),
        #[cfg(not(unix))]
        inode: None,
        #[cfg(unix)]
        ctime_seconds: Some(metadata.ctime()),
        #[cfg(not(unix))]
        ctime_seconds: None,
        #[cfg(unix)]
        ctime_nanoseconds: Some(metadata.ctime_nsec()),
        #[cfg(not(unix))]
        ctime_nanoseconds: None,
    }
}

fn hash_stable(path: &Path, before: &FileFingerprint) -> HashOutcome {
    let input = match File::open(path) {
        Ok(input) => input,
        Err(_) => return HashOutcome::ReadError,
    };
    let mut reader = BufReader::with_capacity(HASH_BUFFER_BYTES, input);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => return HashOutcome::ReadError,
        };
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => fingerprint_from_metadata(&metadata),
        _ => return HashOutcome::Changed,
    };
    if &after != before {
        return HashOutcome::Changed;
    }
    HashOutcome::Stable {
        blake3_hex: hasher.finalize().to_hex().to_string(),
    }
}

fn object_archive_review(
    connection: &Connection,
    path: &Path,
    hash: &str,
) -> Result<ObjectArchiveReview> {
    let mut statement = connection
        .prepare_cached(
            "SELECT f.collection_id, c.status,
                    CASE
                        WHEN c.status != 'active' THEN 'inactive'
                        WHEN c.policy_id IS NULL THEN 'unknown'
                        WHEN usable.evaluation_id IS NULL THEN 'unknown'
                        WHEN finding.status = 'violated' THEN 'at_risk'
                        WHEN finding.status = 'uncertain' THEN 'unknown'
                        ELSE 'satisfied'
                    END
             FROM objects o
             JOIN file_refs f ON f.object_id = o.object_id AND f.path_state = 'active'
             JOIN collections c ON c.collection_id = f.collection_id
             LEFT JOIN temp.stage_usable_policy_evaluations usable
               ON usable.policy_id = c.policy_id
             LEFT JOIN policy_status finding
               ON finding.evaluation_id = usable.evaluation_id
              AND finding.file_ref_id = f.file_ref_id
             WHERE o.canonical_hash_algo = 'blake3' AND o.canonical_hash_hex = ?1
             ORDER BY f.collection_id, f.file_ref_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let rows = statement
        .query_map([hash], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|source| sqlite_error(path, source))?;
    let mut collections = Vec::new();
    let mut has_active_owner = false;
    let mut protection = ProtectionState::Satisfied;
    for row in rows {
        let (collection_id, collection_status, file_status) =
            row.map_err(|source| sqlite_error(path, source))?;
        if collections.last() != Some(&collection_id) {
            collections.push(collection_id);
        }
        if collection_status != "active" {
            continue;
        }
        has_active_owner = true;
        protection = match (protection, file_status.as_str()) {
            (_, "at_risk") => ProtectionState::AtRisk,
            (ProtectionState::AtRisk, _) => ProtectionState::AtRisk,
            (_, "unknown") => ProtectionState::Unknown,
            (state, "satisfied") => state,
            (_, _) => ProtectionState::Unknown,
        };
    }
    if !has_active_owner {
        protection = ProtectionState::Unknown;
    }
    Ok(ObjectArchiveReview {
        collections,
        protection,
    })
}

fn object_is_cataloged(connection: &Connection, path: &Path, hash: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM objects o JOIN file_refs f ON f.object_id = o.object_id
                 WHERE o.canonical_hash_algo = 'blake3' AND o.canonical_hash_hex = ?1
                   AND f.path_state = 'active'
             )",
            [hash],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, source))
}

fn scalar_u64(connection: &Connection, path: &Path, sql: &str, value: &str) -> Result<u64> {
    let result: i64 = connection
        .query_row(sql, [value], |row| row.get(0))
        .map_err(|source| sqlite_error(path, source))?;
    u64::try_from(result)
        .map_err(|_| StageError::InvalidManifest("negative manifest count".to_owned()))
}

fn set_meta(connection: &Connection, path: &Path, key: &str, value: &str) -> Result<()> {
    connection
        .execute(
            "INSERT INTO stage_meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [key, value],
        )
        .map_err(|source| sqlite_error(path, source))?;
    Ok(())
}

fn get_meta(connection: &Connection, path: &Path, key: &str) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT value FROM stage_meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(path, source))
}

fn begin_manifest_batch(connection: &Connection, path: &Path) -> Result<()> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|source| sqlite_error(path, source))
}

fn commit_manifest_batch(connection: &Connection, path: &Path) -> Result<()> {
    connection
        .execute_batch("COMMIT")
        .map_err(|source| sqlite_error(path, source))
}

fn manifest_sidecar_exclusions(relative: &Path) -> Vec<PathBuf> {
    let mut values = vec![relative.to_path_buf()];
    let name = relative.as_os_str().to_string_lossy();
    values.push(PathBuf::from(format!("{name}-journal")));
    values.push(PathBuf::from(format!("{name}-wal")));
    values.push(PathBuf::from(format!("{name}-shm")));
    values
}

fn create_private_directory(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|error| io_error("create stage manifest directory", path, error))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .map_err(|error| io_error("read current directory", Path::new("."), error))?
            .join(path))
    }
}

fn decoded_path(encoding: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = match encoding {
        "utf8" => PathBuf::from(String::from_utf8(bytes.to_vec()).map_err(|_| {
            StageError::InvalidManifest("UTF-8 staged path contains invalid bytes".to_owned())
        })?),
        #[cfg(unix)]
        "unix_bytes" => PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())),
        #[cfg(not(unix))]
        "unix_bytes" => return Err(StageError::UnsupportedPlatform),
        _ => return Err(StageError::UnsupportedPlatform),
    };
    validate_relative_path(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn raw_relative_path(path: &EncodedPath) -> Result<PathBuf> {
    decoded_path(path.encoding.as_str(), &path.bytes)
}

#[cfg(not(unix))]
fn raw_relative_path(path: &EncodedPath) -> Result<PathBuf> {
    decoded_path(path.encoding.as_str(), &path.bytes)
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(StageError::InvalidPath(format!(
            "path must be non-empty, relative, and contained: {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_json_parts(encoding: &str, bytes: &[u8]) -> (Option<String>, Option<String>) {
    if encoding == "utf8" {
        (String::from_utf8(bytes.to_vec()).ok(), None)
    } else {
        (None, Some(URL_SAFE_NO_PAD.encode(bytes)))
    }
}

fn sql_i64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| StageError::InvalidManifest(format!("{field} exceeds SQLite INTEGER")))
}

fn optional_sql_i64(value: Option<u64>) -> Option<i64> {
    value.and_then(|value| i64::try_from(value).ok())
}

fn now_utc_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StageError::InvalidManifest("system clock is before Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .map_err(|_| StageError::InvalidManifest("system time exceeds u64".to_owned()))
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> StageError {
    StageError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> StageError {
    StageError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_manifest_schema_is_versioned_and_excluded_from_source_data() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("incoming");
        fs::create_dir(&source).unwrap();
        let manifest_dir = source.join(DEFAULT_STAGE_DIRECTORY);
        create_private_directory(&manifest_dir).unwrap();
        let manifest = manifest_dir.join(DEFAULT_STAGE_MANIFEST);
        let connection = open_manifest(&manifest).unwrap();
        initialize_manifest(&connection, &manifest).unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, STAGE_SCHEMA_VERSION);
        let mut discovery =
            FileDiscovery::with_exclusions(&source, vec![DEFAULT_STAGE_DIRECTORY.into()]).unwrap();
        assert!(discovery.next().is_some());
        assert!(discovery.all(|item| !matches!(item, DiscoveryItem::File(_))));
    }
}
