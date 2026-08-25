//! Read-only git-annex inventory import.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::discovery::{encode_relative_path, modified_time_ms, EncodedPath};
use crate::event_store::{EventReferences, EventRequest, EventStore, EventStoreError};
use crate::projection::{ProjectionDb, ProjectionError};
use crate::v2_projection::{V2ProjectionDb, V2ProjectionError};
use crate::v2_store::{V2OriginStore, V2StoreError};

const MAX_POINTER_BYTES: u64 = 32 * 1024;

pub type Result<T> = std::result::Result<T, AnnexImportError>;

#[derive(Debug, Error)]
pub enum AnnexImportError {
    #[error(transparent)]
    EventStore(#[from] EventStoreError),

    #[error(transparent)]
    Projection(#[from] ProjectionError),

    #[error(transparent)]
    V2Store(#[from] V2StoreError),

    #[error(transparent)]
    V2Projection(#[from] V2ProjectionError),

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("git command failed ({operation}): {detail}")]
    Git {
        operation: &'static str,
        detail: String,
    },

    #[error("invalid git output from {operation}: {detail}")]
    InvalidGitOutput {
        operation: &'static str,
        detail: String,
    },

    #[error("invalid annex import configuration: {0}")]
    InvalidConfig(String),

    #[error("git-annex repository changed during import")]
    SourceChanged,

    #[error("lossless git path handling is unavailable on this platform")]
    UnsupportedPlatform,
}

impl AnnexImportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EventStore(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::V2Store(error) => error.code(),
            Self::V2Projection(error) => error.code(),
            Self::Io { .. } => "annex_import_io",
            Self::Git { .. } => "annex_git_failed",
            Self::InvalidGitOutput { .. } => "annex_invalid_git_output",
            Self::InvalidConfig(_) => "annex_invalid_config",
            Self::SourceChanged => "annex_source_changed",
            Self::UnsupportedPlatform => "annex_platform_unsupported",
        }
    }
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> AnnexImportError {
    AnnexImportError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[derive(Debug, Clone)]
pub struct AnnexImportConfig {
    pub repo_path: PathBuf,
    pub import_id: String,
    pub job_id: String,
    pub collection_id: String,
    pub worktree_location_id: String,
    pub cas_location_id: String,
    pub device_id: String,
    pub archive_root_id: String,
    pub batch_entries: usize,
}

impl AnnexImportConfig {
    fn validate(&self) -> Result<()> {
        if self.batch_entries == 0 {
            return Err(AnnexImportError::InvalidConfig(
                "batch_entries must be greater than zero".to_owned(),
            ));
        }
        for (name, value) in [
            ("import_id", &self.import_id),
            ("job_id", &self.job_id),
            ("collection_id", &self.collection_id),
            ("worktree_location_id", &self.worktree_location_id),
            ("cas_location_id", &self.cas_location_id),
            ("device_id", &self.device_id),
            ("archive_root_id", &self.archive_root_id),
        ] {
            if value.is_empty() {
                return Err(AnnexImportError::InvalidConfig(format!(
                    "{name} must be non-empty"
                )));
            }
        }
        if !self.repo_path.is_dir() {
            return Err(AnnexImportError::InvalidConfig(format!(
                "repository is not a directory: {}",
                self.repo_path.display()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnexImportStatus {
    Complete,
    Interrupted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnexSummary {
    pub entries_seen: u64,
    pub present: u64,
    pub absent: u64,
    pub supported_unresolved: u64,
    pub unsupported: u64,
    pub mismatched: u64,
    pub read_errors: u64,
    pub ignored_non_annex: u64,
    /// Git-tracked symlinks that are not validated git-annex CAS links.
    #[serde(default)]
    pub ignored_symlinks: u64,
    pub duplicate_paths: u64,
    pub availability_facts: u64,
    pub source_changed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnnexLocalCheckpoint {
    summary: AnnexSummary,
    spool_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnexImportResult {
    pub status: AnnexImportStatus,
    pub annex_uuid: String,
    pub git_head_commit: String,
    pub summary: AnnexSummary,
}

pub struct AnnexImporter<'a> {
    store: &'a EventStore,
    projection: &'a ProjectionDb,
    config: AnnexImportConfig,
}

pub struct V2AnnexImporter<'a> {
    store: &'a V2OriginStore,
    projection: &'a V2ProjectionDb,
    config: AnnexImportConfig,
}

/// Detects a git-annex worktree from its local Git configuration without
/// changing the repository. Paths inside the worktree are accepted.
pub fn is_git_annex_repository(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    let canonical = fs::canonicalize(path)
        .map_err(|source| io_error("canonicalize possible annex repository", path, source))?;
    if !canonical.is_dir() {
        return Err(AnnexImportError::InvalidConfig(format!(
            "repository path is not a directory: {}",
            canonical.display()
        )));
    }
    let mut has_worktree_marker = false;
    for ancestor in canonical.ancestors() {
        let marker = ancestor.join(".git");
        match fs::symlink_metadata(&marker) {
            Ok(_) => {
                has_worktree_marker = true;
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(io_error("inspect Git worktree marker", &marker, source));
            }
        }
    }
    if !has_worktree_marker {
        return Ok(false);
    }
    let worktree = git_command(&canonical)
        .args([
            "-c",
            "safe.directory=*",
            "rev-parse",
            "--is-inside-work-tree",
        ])
        .output()
        .map_err(|source| io_error("run git command", &canonical, source))?;
    if !worktree.status.success() {
        if worktree.status.code() == Some(128) {
            return Ok(false);
        }
        return Err(AnnexImportError::Git {
            operation: "detect Git worktree",
            detail: String::from_utf8_lossy(&worktree.stderr).trim().to_owned(),
        });
    }
    if String::from_utf8_lossy(&worktree.stdout).trim() != "true" {
        return Ok(false);
    }
    let output = git_command(&canonical)
        .args([
            "-c",
            "safe.directory=*",
            "config",
            "--local",
            "--get",
            "annex.uuid",
        ])
        .output()
        .map_err(|source| io_error("run git command", &canonical, source))?;
    if output.status.success() {
        return Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err(AnnexImportError::Git {
        operation: "detect annex repository",
        detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

/// Confirms that a path is a readable git-annex repository without changing it.
pub fn validate_annex_repository(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let canonical = fs::canonicalize(path)
        .map_err(|source| io_error("canonicalize annex repository", path, source))?;
    if !canonical.is_dir() {
        return Err(AnnexImportError::InvalidConfig(format!(
            "repository is not a directory: {}",
            canonical.display()
        )));
    }
    let annex_uuid = git_text(
        &canonical,
        "read annex UUID",
        &["config", "--local", "--get", "annex.uuid"],
    )?;
    if annex_uuid.is_empty() {
        return Err(AnnexImportError::InvalidConfig(
            "repository has no annex.uuid".to_owned(),
        ));
    }
    Ok(canonical)
}

impl<'a> V2AnnexImporter<'a> {
    pub fn new(
        store: &'a V2OriginStore,
        projection: &'a V2ProjectionDb,
        mut config: AnnexImportConfig,
    ) -> Result<Self> {
        config.validate()?;
        config.repo_path = fs::canonicalize(&config.repo_path).map_err(|source| {
            io_error("canonicalize annex repository", &config.repo_path, source)
        })?;
        let connection = rusqlite::Connection::open(projection.path()).map_err(|source| {
            AnnexImportError::V2Projection(V2ProjectionError::Sqlite {
                path: projection.path().to_path_buf(),
                source,
            })
        })?;
        let valid: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM collections WHERE collection_id = ?1 AND status = 'active')
                   AND EXISTS(SELECT 1 FROM locations WHERE location_id = ?2 AND status = 'active')
                   AND EXISTS(SELECT 1 FROM locations WHERE location_id = ?3 AND status = 'active')
                   AND EXISTS(SELECT 1 FROM devices WHERE device_id = ?4 AND status = 'active')
                   AND EXISTS(SELECT 1 FROM archive_roots WHERE archive_root_id = ?5 AND status = 'active')",
                rusqlite::params![
                    config.collection_id,
                    config.worktree_location_id,
                    config.cas_location_id,
                    config.device_id,
                    config.archive_root_id,
                ],
                |row| row.get(0),
            )
            .map_err(|source| {
                AnnexImportError::V2Projection(V2ProjectionError::Sqlite {
                    path: projection.path().to_path_buf(),
                    source,
                })
            })?;
        if valid != 1 {
            return Err(AnnexImportError::InvalidConfig(
                "annex import topology is not active in this Archive".to_owned(),
            ));
        }
        Ok(Self {
            store,
            projection,
            config,
        })
    }

    pub fn run(&self) -> Result<AnnexImportResult> {
        self.run_at_most(None)
    }

    pub fn run_at_most(&self, limit: Option<usize>) -> Result<AnnexImportResult> {
        self.projection.apply(self.store)?;
        let initial = SourceSnapshot::capture(&self.config.repo_path)?;
        let annex_uuid = git_text(
            &self.config.repo_path,
            "read annex UUID",
            &["config", "--local", "--get", "annex.uuid"],
        )?;
        if annex_uuid.is_empty() {
            return Err(AnnexImportError::InvalidConfig(
                "repository has no annex.uuid".to_owned(),
            ));
        }
        let job_root = self
            .projection
            .path()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("local/jobs")
            .join(&self.config.job_id);
        let spool_path = job_root.join("annex-items.jsonl");
        let summary_path = job_root.join("annex-summary.json");
        let config_path = job_root.join("annex-config.json");
        let config_value = json!({
            "repo_path": path_json(&encode_absolute_path(&self.config.repo_path)),
            "import_id": self.config.import_id,
            "job_id": self.config.job_id,
            "collection_id": self.config.collection_id,
            "worktree_location_id": self.config.worktree_location_id,
            "cas_location_id": self.config.cas_location_id,
            "device_id": self.config.device_id,
            "archive_root_id": self.config.archive_root_id,
            "batch_entries": self.config.batch_entries,
            "annex_uuid": annex_uuid,
            "git_head_commit": initial.head,
            "source_fingerprint": initial.fingerprint(),
        });
        fs::create_dir_all(&job_root)
            .map_err(|source| io_error("create annex import job directory", &job_root, source))?;
        let new_job = !config_path.exists();
        if new_job {
            fs::write(
                &config_path,
                serde_json::to_vec(&config_value)
                    .map_err(|error| AnnexImportError::InvalidConfig(error.to_string()))?,
            )
            .map_err(|source| {
                io_error("write annex import job configuration", &config_path, source)
            })?;
        } else {
            let existing: Value =
                serde_json::from_slice(&fs::read(&config_path).map_err(|source| {
                    io_error("read annex import job configuration", &config_path, source)
                })?)
                .map_err(|error| {
                    AnnexImportError::InvalidConfig(format!(
                        "annex job configuration is invalid: {error}"
                    ))
                })?;
            if existing != config_value {
                return Err(AnnexImportError::InvalidConfig(format!(
                    "job {} belongs to a different repository snapshot or import",
                    self.config.job_id
                )));
            }
        }
        let connection = rusqlite::Connection::open(self.projection.path()).map_err(|source| {
            AnnexImportError::V2Projection(V2ProjectionError::Sqlite {
                path: self.projection.path().to_path_buf(),
                source,
            })
        })?;
        let now = annex_now_utc_ms()?;
        let params_text = serde_json::to_string(&config_value)
            .map_err(|error| AnnexImportError::InvalidConfig(error.to_string()))?;
        connection
            .execute(
                "INSERT INTO jobs(job_id, job_type, status, created_time_utc_ms, started_time_utc_ms, params_json, input_version)
                 VALUES (?1, 'annex_import', 'running', ?2, ?2, ?3, ?4)
                 ON CONFLICT(job_id) DO NOTHING",
                rusqlite::params![
                    self.config.job_id,
                    i64::try_from(now).unwrap_or(i64::MAX),
                    params_text,
                    self.config.import_id,
                ],
            )
            .map_err(|source| AnnexImportError::V2Projection(V2ProjectionError::Sqlite {
                path: self.projection.path().to_path_buf(),
                source,
            }))?;
        let actual: (String, String, String, String, Option<String>) = connection
            .query_row(
                "SELECT job_type, status, input_version, params_json, progress_json FROM jobs WHERE job_id = ?1",
                [&self.config.job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(|source| AnnexImportError::V2Projection(V2ProjectionError::Sqlite {
                path: self.projection.path().to_path_buf(),
                source,
            }))?;
        if actual.0 != "annex_import"
            || actual.2 != self.config.import_id
            || actual.3 != params_text
        {
            return Err(AnnexImportError::InvalidConfig(format!(
                "job {} belongs to different immutable inputs",
                self.config.job_id
            )));
        }
        if matches!(actual.1.as_str(), "complete" | "partial") {
            let summary = actual
                .4
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|error| {
                    AnnexImportError::InvalidConfig(format!(
                        "completed annex job summary is invalid: {error}"
                    ))
                })?
                .unwrap_or_default();
            if job_root.is_dir() {
                fs::remove_dir_all(&job_root).map_err(|source| {
                    io_error("remove completed annex import job files", &job_root, source)
                })?;
            }
            return Ok(AnnexImportResult {
                status: AnnexImportStatus::Complete,
                annex_uuid,
                git_head_commit: initial.head,
                summary,
            });
        }

        let checkpoint: Option<AnnexLocalCheckpoint> = if summary_path.exists() {
            Some(
                serde_json::from_slice(&fs::read(&summary_path).map_err(|source| {
                    io_error("read annex import job summary", &summary_path, source)
                })?)
                .map_err(|error| {
                    AnnexImportError::InvalidConfig(format!(
                        "annex job summary is invalid: {error}"
                    ))
                })?,
            )
        } else {
            None
        };
        let fresh_progress = checkpoint.is_none();
        let checkpoint_len = checkpoint.as_ref().map_or(0, |value| value.spool_len);
        let spool_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&spool_path)
            .map_err(|source| io_error("open annex import spool", &spool_path, source))?;
        spool_file
            .set_len(checkpoint_len)
            .map_err(|source| io_error("truncate annex import spool", &spool_path, source))?;
        let mut spool = BufWriter::new(spool_file);
        spool
            .seek(std::io::SeekFrom::End(0))
            .map_err(|source| io_error("seek annex import spool", &spool_path, source))?;
        if fresh_progress {
            write_v2_item(
                &mut spool,
                &json!({
                    "kind": "job_started",
                    "job_id": self.config.job_id,
                    "job_type": "annex_import",
                    "input_version": self.config.import_id,
                    "params": config_value,
                    "item_type": "job",
                    "item_key": self.config.job_id,
                    "outcome_kind": "started",
                    "operation_key": stable_id("op", &[self.config.job_id.as_bytes(), self.config.import_id.as_bytes(), b"job", b"started"]),
                }),
                &spool_path,
            )?;
            write_v2_item(
                &mut spool,
                &json!({
                "kind": "annex_import_started",
                "import_id": self.config.import_id,
                "job_id": self.config.job_id,
                "repo_path": path_json(&encode_absolute_path(&self.config.repo_path)),
                "collection_id": self.config.collection_id,
                "worktree_location_id": self.config.worktree_location_id,
                "cas_location_id": self.config.cas_location_id,
                "device_id": self.config.device_id,
                "archive_root_id": self.config.archive_root_id,
                "annex_uuid": annex_uuid,
                "git_head_commit": initial.head,
                "source_fingerprint": initial.fingerprint(),
                }),
                &spool_path,
            )?;
        }
        let mut summary = checkpoint.map_or_else(AnnexSummary::default, |value| value.summary);
        if fresh_progress {
            save_annex_checkpoint(&mut spool, &spool_path, &summary_path, &summary)?;
        }
        let mut index = IndexStream::open(&self.config.repo_path)?;
        let mut cat_file = CatFile::open(&self.config.repo_path)?;
        let mut skip_entries = summary.entries_seen;
        let mut processed_this_run = 0_usize;
        let mut interrupted = false;
        while let Some(entry) = index.next_entry()? {
            if entry.stage != 0 {
                continue;
            }
            if skip_entries > 0 {
                skip_entries -= 1;
                continue;
            }
            if limit.is_some_and(|limit| processed_this_run >= limit) {
                interrupted = true;
                break;
            }
            processed_this_run = processed_this_run.saturating_add(1);
            summary.entries_seen = summary.entries_seen.saturating_add(1);
            let blob_size = cat_file.check(&entry.oid)?;
            if entry.mode != "120000" && blob_size > MAX_POINTER_BYTES {
                summary.ignored_non_annex = summary.ignored_non_annex.saturating_add(1);
                if summary
                    .entries_seen
                    .is_multiple_of(self.config.batch_entries as u64)
                {
                    save_annex_checkpoint(&mut spool, &spool_path, &summary_path, &summary)?;
                }
                continue;
            }
            let blob = cat_file.read_blob(&entry.oid, blob_size)?;
            let Some(key_text) = annex_key_from_blob(&entry.mode, &blob) else {
                summary.ignored_non_annex = summary.ignored_non_annex.saturating_add(1);
                if entry.mode == "120000" {
                    summary.ignored_symlinks = summary.ignored_symlinks.saturating_add(1);
                }
                if summary
                    .entries_seen
                    .is_multiple_of(self.config.batch_entries as u64)
                {
                    save_annex_checkpoint(&mut spool, &spool_path, &summary_path, &summary)?;
                }
                continue;
            };
            let logical = encode_relative_path(&raw_path(&entry.path)?);
            let key = AnnexKey::parse(&key_text);
            let outcome = inspect_entry_v2(&self.config, &entry, &blob, &key)?;
            summary.add(&outcome.category);
            write_v2_item(
                &mut spool,
                &v2_annex_entry_item(&self.config, &annex_uuid, &logical, &key, &outcome),
                &spool_path,
            )?;
            if summary
                .entries_seen
                .is_multiple_of(self.config.batch_entries as u64)
            {
                save_annex_checkpoint(&mut spool, &spool_path, &summary_path, &summary)?;
            }
        }
        if interrupted {
            while index.next_entry()?.is_some() {}
        }
        index.finish()?;
        cat_file.finish()?;
        let final_snapshot = SourceSnapshot::capture(&self.config.repo_path)?;
        if initial != final_snapshot {
            return Err(AnnexImportError::SourceChanged);
        }
        if interrupted {
            save_annex_checkpoint(&mut spool, &spool_path, &summary_path, &summary)?;
            connection
                .execute(
                    "UPDATE jobs SET progress_json = ?2 WHERE job_id = ?1",
                    rusqlite::params![
                        self.config.job_id,
                        serde_json::to_string(&json!({
                            "phase": "reading_index",
                            "entries_seen": summary.entries_seen,
                        }))
                        .map_err(|error| AnnexImportError::InvalidConfig(error.to_string()))?
                    ],
                )
                .map_err(|source| {
                    AnnexImportError::V2Projection(V2ProjectionError::Sqlite {
                        path: self.projection.path().to_path_buf(),
                        source,
                    })
                })?;
            return Ok(AnnexImportResult {
                status: AnnexImportStatus::Interrupted,
                annex_uuid,
                git_head_commit: initial.head,
                summary,
            });
        }
        write_v2_item(
            &mut spool,
            &json!({
                "kind": "annex_import_completed",
                "import_id": self.config.import_id,
                "annex_uuid": annex_uuid,
                "git_head_commit": initial.head,
                "status": "complete",
                "summary": summary,
            }),
            &spool_path,
        )?;
        write_v2_item(
            &mut spool,
            &json!({
                "kind": "job_finished",
                "job_id": self.config.job_id,
                "job_type": "annex_import",
                "input_version": self.config.import_id,
                "status": "complete",
                "summary": summary,
                "item_type": "job",
                "item_key": self.config.job_id,
                "outcome_kind": "complete",
                "operation_key": stable_id("op", &[self.config.job_id.as_bytes(), self.config.import_id.as_bytes(), b"job", b"complete"]),
            }),
            &spool_path,
        )?;
        spool
            .flush()
            .and_then(|()| spool.get_ref().sync_all())
            .map_err(|source| io_error("sync annex import spool", &spool_path, source))?;
        drop(spool);
        self.store.append_jsonl_batch(
            "annex_import",
            1,
            json!({
                "import_id": self.config.import_id,
                "collection_id": self.config.collection_id,
                "location_id": self.config.worktree_location_id,
            }),
            json!({}),
            &spool_path,
        )?;
        self.projection.apply(self.store)?;
        drop(connection);
        fs::remove_dir_all(&job_root).map_err(|source| {
            io_error("remove completed annex import job files", &job_root, source)
        })?;
        Ok(AnnexImportResult {
            status: AnnexImportStatus::Complete,
            annex_uuid,
            git_head_commit: initial.head,
            summary,
        })
    }
}

impl<'a> AnnexImporter<'a> {
    pub fn new(
        store: &'a EventStore,
        projection: &'a ProjectionDb,
        mut config: AnnexImportConfig,
    ) -> Result<Self> {
        config.validate()?;
        config.repo_path = fs::canonicalize(&config.repo_path).map_err(|source| {
            io_error("canonicalize annex repository", &config.repo_path, source)
        })?;
        projection.validate_annex_topology(
            &config.collection_id,
            &config.worktree_location_id,
            &config.cas_location_id,
            &config.device_id,
            &config.archive_root_id,
        )?;
        Ok(Self {
            store,
            projection,
            config,
        })
    }

    pub fn run(&self) -> Result<AnnexImportResult> {
        self.run_at_most(None)
    }

    /// Stops cleanly after `limit` index entries. Re-running with the same job
    /// and import IDs resumes by reconciling deterministic operation keys.
    pub fn run_at_most(&self, limit: Option<usize>) -> Result<AnnexImportResult> {
        self.projection.apply(self.store)?;
        let initial = SourceSnapshot::capture(&self.config.repo_path)?;
        let annex_uuid = git_text(
            &self.config.repo_path,
            "read annex UUID",
            &["config", "--local", "--get", "annex.uuid"],
        )?;
        if annex_uuid.is_empty() {
            return Err(AnnexImportError::InvalidConfig(
                "repository has no annex.uuid".to_owned(),
            ));
        }

        let started = import_started_event(&self.config, &annex_uuid, &initial);
        let started_key = event_operation_key(&started)?;
        if self.projection.has_operation_key(started_key)? {
            if self
                .projection
                .annex_import_source_fingerprint(&self.config.import_id)?
                .as_deref()
                != Some(initial.fingerprint().as_str())
            {
                self.record_source_changed(&annex_uuid, &initial)?;
                return Err(AnnexImportError::SourceChanged);
            }
        } else {
            self.store.append(started)?;
        }
        self.projection.apply(self.store)?;

        let mut summary = AnnexSummary::default();
        let mut pending = Vec::new();
        let mut pending_entries = 0usize;
        let mut index = IndexStream::open(&self.config.repo_path)?;
        let mut cat_file = CatFile::open(&self.config.repo_path)?;

        while let Some(entry) = index.next_entry()? {
            if entry.stage != 0 {
                continue;
            }
            if limit.is_some_and(|limit| summary.entries_seen as usize >= limit) {
                self.flush(&mut pending)?;
                return Ok(AnnexImportResult {
                    status: AnnexImportStatus::Interrupted,
                    annex_uuid,
                    git_head_commit: initial.head,
                    summary,
                });
            }
            summary.entries_seen += 1;
            let blob_size = cat_file.check(&entry.oid)?;
            if entry.mode != "120000" && blob_size > MAX_POINTER_BYTES {
                summary.ignored_non_annex += 1;
                continue;
            }
            let blob = cat_file.read_blob(&entry.oid, blob_size)?;
            let Some(key_text) = annex_key_from_blob(&entry.mode, &blob) else {
                summary.ignored_non_annex += 1;
                if entry.mode == "120000" {
                    summary.ignored_symlinks += 1;
                }
                continue;
            };
            let path = raw_path(&entry.path)?;
            let encoded = encode_relative_path(&path);
            let key = AnnexKey::parse(&key_text);
            let outcome = self.inspect_entry(&entry, &blob, &key)?;
            summary.add(&outcome.category);
            let events = self.events_for_entry(&annex_uuid, &entry, &encoded, &key, outcome);
            for event in events {
                if !self
                    .projection
                    .has_operation_key(event_operation_key(&event)?)?
                {
                    pending.push(event);
                }
            }
            pending_entries += 1;
            if pending_entries >= self.config.batch_entries {
                self.flush(&mut pending)?;
                pending_entries = 0;
            }
        }
        index.finish()?;
        cat_file.finish()?;
        self.flush(&mut pending)?;

        self.import_location_logs(&annex_uuid, &mut summary)?;
        let (duplicate_paths, availability_facts) = self
            .projection
            .annex_inventory_counts(&self.config.collection_id, &annex_uuid)?;
        summary.duplicate_paths = duplicate_paths;
        summary.availability_facts = availability_facts;
        let final_snapshot = SourceSnapshot::capture(&self.config.repo_path)?;
        if initial != final_snapshot {
            self.record_source_changed(&annex_uuid, &initial)?;
            return Err(AnnexImportError::SourceChanged);
        }

        self.append_if_new(import_completed_event(
            &self.config,
            &annex_uuid,
            &initial.head,
            &summary,
            "complete",
        ))?;
        self.projection.apply(self.store)?;
        Ok(AnnexImportResult {
            status: AnnexImportStatus::Complete,
            annex_uuid,
            git_head_commit: initial.head,
            summary,
        })
    }

    fn append_if_new(&self, event: EventRequest) -> Result<()> {
        let operation_key = event_operation_key(&event)?;
        if !self.projection.has_operation_key(operation_key)? {
            self.store.append(event)?;
        }
        Ok(())
    }

    fn record_source_changed(&self, annex_uuid: &str, initial: &SourceSnapshot) -> Result<()> {
        let summary = AnnexSummary {
            source_changed: 1,
            ..AnnexSummary::default()
        };
        self.append_if_new(import_completed_event(
            &self.config,
            annex_uuid,
            &initial.head,
            &summary,
            "partial",
        ))?;
        self.projection.apply(self.store)?;
        Ok(())
    }

    fn flush(&self, pending: &mut Vec<EventRequest>) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        self.store.append_batch(std::mem::take(pending))?;
        self.projection.apply(self.store)?;
        Ok(())
    }

    fn inspect_entry(
        &self,
        entry: &IndexEntry,
        index_blob: &[u8],
        key: &AnnexKey,
    ) -> Result<EntryOutcome> {
        let worktree_path = self.config.repo_path.join(raw_path(&entry.path)?);
        let metadata = match fs::symlink_metadata(&worktree_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if key.state == KeyState::Unsupported {
                    return Ok(EntryOutcome {
                        category: EntryCategory::Unsupported,
                        representation: "missing_worktree_entry",
                        content: None,
                        error: None,
                        path_present: false,
                        local_bytes_present: false,
                        copy_path: None,
                    });
                }
                return Ok(EntryOutcome::absent("missing_worktree_entry", false));
            }
            Err(error) => return Ok(EntryOutcome::read_error(error.to_string())),
        };
        let (representation, content_metadata, path_present, copy_path) = if entry.mode == "120000"
        {
            if !metadata.file_type().is_symlink() {
                return Ok(EntryOutcome::read_error(
                    "worktree representation changed from annex symlink".to_owned(),
                ));
            }
            let target = fs::read_link(&worktree_path)
                .map_err(|source| io_error("read annex symlink", &worktree_path, source))?;
            if path_bytes(&target)? != index_blob {
                return Ok(EntryOutcome::read_error(
                    "worktree symlink target differs from the Git index".to_owned(),
                ));
            }
            let target_metadata = match fs::metadata(&worktree_path) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Ok(EntryOutcome::read_error(error.to_string())),
            };
            let copy_path = annex_object_relative(index_blob)
                .and_then(|bytes| raw_path(bytes).ok())
                .map(|path| {
                    if self.config.cas_location_id == self.config.worktree_location_id {
                        encode_relative_path(&Path::new(".git/annex/objects").join(path))
                    } else {
                        encode_relative_path(&path)
                    }
                });
            ("annex_locked_symlink", target_metadata, true, copy_path)
        } else if metadata.file_type().is_file() {
            if metadata.len() <= MAX_POINTER_BYTES {
                match fs::read(&worktree_path) {
                    Ok(bytes)
                        if annex_key_from_blob("100644", &bytes).as_deref() == Some(&key.raw) =>
                    {
                        ("annex_pointer_file", None, true, None)
                    }
                    Ok(_) => (
                        "annex_unlocked_file",
                        Some(metadata),
                        true,
                        Some(encoded_worktree_path(entry)?),
                    ),
                    Err(error) => return Ok(EntryOutcome::read_error(error.to_string())),
                }
            } else {
                (
                    "annex_unlocked_file",
                    Some(metadata),
                    true,
                    Some(encoded_worktree_path(entry)?),
                )
            }
        } else {
            return Ok(EntryOutcome::read_error(
                "worktree entry is neither the indexed symlink nor a regular file".to_owned(),
            ));
        };

        if key.state == KeyState::Unsupported {
            return Ok(EntryOutcome {
                category: EntryCategory::Unsupported,
                representation,
                content: None,
                error: None,
                path_present,
                local_bytes_present: content_metadata.is_some(),
                copy_path,
            });
        }
        let Some(content_metadata) = content_metadata else {
            return Ok(EntryOutcome::absent(representation, path_present));
        };
        if key.expected_sha256.is_none() {
            return Ok(EntryOutcome {
                category: EntryCategory::SupportedUnresolved,
                representation,
                content: None,
                error: None,
                path_present,
                local_bytes_present: true,
                copy_path,
            });
        }

        match hash_file(&worktree_path, &content_metadata) {
            Ok(content) => {
                let size_matches = key.expected_size.is_none_or(|size| size == content.size);
                let hash_matches = key.expected_sha256.as_deref() == Some(&content.sha256_hex);
                let category = if size_matches && hash_matches {
                    EntryCategory::Present
                } else {
                    EntryCategory::Mismatch
                };
                Ok(EntryOutcome {
                    category,
                    representation,
                    content: Some(content),
                    error: None,
                    path_present,
                    local_bytes_present: true,
                    copy_path,
                })
            }
            Err(error) => Ok(EntryOutcome {
                category: EntryCategory::ReadError,
                representation,
                content: None,
                error: Some(error.to_string()),
                path_present,
                local_bytes_present: true,
                copy_path,
            }),
        }
    }

    fn events_for_entry(
        &self,
        annex_uuid: &str,
        entry: &IndexEntry,
        path: &EncodedPath,
        key: &AnnexKey,
        outcome: EntryOutcome,
    ) -> Vec<EventRequest> {
        let external_identity_id = stable_id("ext", &[b"git-annex", key.raw.as_bytes()]);
        let file_ref_id = stable_id(
            "file",
            &[
                self.config.collection_id.as_bytes(),
                path.encoding.as_str().as_bytes(),
                &path.bytes,
            ],
        );
        let path_value = path_json(path);
        let common = OutcomeFields::new(&self.config, path, "inventory", outcome.category.as_str());
        let source_detail = json!({
            "backend": key.backend,
            "source_repo_id": annex_uuid,
        });
        let resolution_state = match outcome.category {
            EntryCategory::Unsupported => "unsupported",
            _ => "unresolved",
        };
        let mut events = vec![event(
            "external_identity_observed",
            json!({
                "external_identity_id": external_identity_id,
                "namespace": "git-annex",
                "external_key": key.raw,
                "expected_hash_algo": key.expected_sha256.as_ref().map(|_| "sha256"),
                "expected_hash_hex": key.expected_sha256,
                "expected_size_bytes": key.expected_size,
                "resolution_state": resolution_state,
                "source_detail_json": source_detail,
                "operation_key": common.operation_key("external_identity"),
                "job_type": "annex_import",
                "item_type": "external_identity",
                "item_key": key.raw,
                "outcome_kind": outcome.category.as_str(),
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                ..EventReferences::default()
            },
        )];

        let resolved = outcome.category == EntryCategory::Present;
        let object_id = outcome
            .content
            .as_ref()
            .filter(|_| resolved)
            .map(|content| format!("obj_blake3_{}", content.blake3_hex));
        if let (Some(content), Some(object_id)) = (&outcome.content, &object_id) {
            events.push(event(
                "object_observed",
                json!({
                    "object_id": object_id,
                    "canonical_hash_algo": "blake3",
                    "canonical_hash_hex": content.blake3_hex,
                    "size_bytes": content.size,
                    "operation_key": common.operation_key("object"),
                    "job_type": "annex_import",
                    "item_type": "object",
                    "item_key": object_id,
                    "outcome_kind": "observed",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.clone()),
                    ..EventReferences::default()
                },
            ));
            events.push(event(
                "object_hash_added",
                json!({
                    "object_id": object_id,
                    "hash_algo": "sha256",
                    "hash_hex": content.sha256_hex,
                    "source": "annex_import",
                    "operation_key": common.operation_key("object_hash"),
                    "job_type": "annex_import",
                    "item_type": "object_hash",
                    "item_key": key.raw,
                    "outcome_kind": "verified",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.clone()),
                    ..EventReferences::default()
                },
            ));
            events.push(event(
                "external_identity_resolved",
                json!({
                    "external_identity_id": external_identity_id,
                    "object_id": object_id,
                    "operation_key": common.operation_key("resolve"),
                    "job_type": "annex_import",
                    "item_type": "external_identity",
                    "item_key": key.raw,
                    "outcome_kind": "resolved",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.clone()),
                    ..EventReferences::default()
                },
            ));
        }

        let identity_state = if resolved { "resolved" } else { "unresolved" };
        events.push(event(
            "file_ref_observed",
            json!({
                "file_ref_id": file_ref_id,
                "collection_id": self.config.collection_id,
                "logical_path": path_value,
                "object_id": object_id,
                "external_identity_id": external_identity_id,
                "identity_state": identity_state,
                "path_state": "active",
                "observed_size_bytes": outcome.content.as_ref().map(|content| content.size).or(key.expected_size),
                "operation_key": common.operation_key("file_ref"),
                "job_type": "annex_import",
                "item_type": "file_ref",
                "item_key": file_ref_id,
                "outcome_kind": outcome.category.as_str(),
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.clone(),
                file_ref_id: Some(file_ref_id.clone()),
                ..EventReferences::default()
            },
        ));
        let path_state = if outcome.path_present {
            "present"
        } else {
            "missing"
        };
        events.push(event(
            "path_observed",
            json!({
                "file_ref_id": file_ref_id,
                "location_id": self.config.worktree_location_id,
                "observed_path": path_value,
                "representation": outcome.representation,
                "object_id": object_id,
                "external_identity_id": external_identity_id,
                "state": path_state,
                "observed_size_bytes": outcome.content.as_ref().map(|content| content.size),
                "modified_time_utc_ms": outcome.content.as_ref().and_then(|content| content.modified_time_utc_ms),
                "operation_key": common.operation_key("path"),
                "job_type": "annex_import",
                "item_type": "path",
                "item_key": file_ref_id,
                "outcome_kind": path_state,
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.clone(),
                file_ref_id: Some(file_ref_id.clone()),
                location_id: Some(self.config.worktree_location_id.clone()),
                ..EventReferences::default()
            },
        ));
        events.push(event(
            "external_availability_observed",
            json!({
                "external_identity_id": external_identity_id,
                "source_repo_id": annex_uuid,
                "source_remote_id": annex_uuid,
                "state": if outcome.local_bytes_present { "present" } else { "missing" },
                "location_id": self.config.cas_location_id,
                "operation_key": common.operation_key("availability_local"),
                "job_type": "annex_import",
                "item_type": "external_availability",
                "item_key": key.raw,
                "outcome_kind": outcome.category.as_str(),
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                location_id: Some(self.config.cas_location_id.clone()),
                ..EventReferences::default()
            },
        ));

        if outcome.content.is_some() || outcome.category == EntryCategory::ReadError {
            let copy_location = if entry.mode == "120000" {
                &self.config.cas_location_id
            } else {
                &self.config.worktree_location_id
            };
            let copy_path = outcome.copy_path.as_ref().unwrap_or(path);
            let copy_claim_id = stable_id(
                "copy",
                &[
                    copy_location.as_bytes(),
                    copy_path.encoding.as_str().as_bytes(),
                    &copy_path.bytes,
                ],
            );
            let state = match outcome.category {
                EntryCategory::Mismatch => "corrupt",
                EntryCategory::ReadError => "unknown",
                _ => "present",
            };
            let content = outcome.content.as_ref();
            events.push(event(
                "copy_observed",
                json!({
                    "copy_claim_id": copy_claim_id,
                    "location_id": copy_location,
                    "relative_path": path_json(copy_path),
                    "object_id": object_id,
                    "external_identity_id": external_identity_id,
                    "claim_basis": "observed_bytes",
                    "state": state,
                    "operation_key": common.operation_key("copy"),
                    "job_type": "annex_import",
                    "item_type": "copy",
                    "item_key": copy_claim_id,
                    "outcome_kind": state,
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: object_id.clone(),
                    file_ref_id: Some(file_ref_id.clone()),
                    copy_claim_id: Some(copy_claim_id.clone()),
                    location_id: Some(copy_location.clone()),
                    ..EventReferences::default()
                },
            ));
            events.push(event(
                "copy_verified",
                json!({
                    "verification_id": stable_id("verify", &[self.config.job_id.as_bytes(), &path.bytes]),
                    "copy_claim_id": copy_claim_id,
                    "object_id": object_id,
                    "location_id": copy_location,
                    "result": match outcome.category {
                        EntryCategory::Mismatch => "hash_mismatch",
                        EntryCategory::ReadError => "read_error",
                        _ => "ok",
                    },
                    "expected_hash_algo": "sha256",
                    "expected_hash_hex": key.expected_sha256,
                    "observed_hash_hex": content.map(|content| &content.sha256_hex),
                    "size_bytes": key.expected_size,
                    "bytes_read": content.map(|content| content.size).unwrap_or(0),
                    "duration_ms": content.map(|content| content.duration_ms).unwrap_or(0),
                    "path_observed": path_json(copy_path),
                    "device_fingerprint_status": "not_checked",
                    "error_code": match outcome.category {
                        EntryCategory::Mismatch => Some("annex_content_mismatch"),
                        EntryCategory::ReadError => Some("annex_content_read_error"),
                        _ => None,
                    },
                    "error_detail": outcome.error,
                    "operation_key": common.operation_key("verification"),
                    "job_type": "annex_import",
                    "item_type": "verification",
                    "item_key": copy_claim_id,
                    "outcome_kind": outcome.category.as_str(),
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: object_id.clone(),
                    file_ref_id: Some(file_ref_id),
                    copy_claim_id: Some(copy_claim_id),
                    location_id: Some(copy_location.clone()),
                    ..EventReferences::default()
                },
            ));
        }
        events
    }

    fn import_location_logs(&self, annex_uuid: &str, _summary: &mut AnnexSummary) -> Result<()> {
        let mut tree = TreeStream::open(&self.config.repo_path)?;
        let mut cat_file = CatFile::open(&self.config.repo_path)?;
        let mut pending = Vec::new();
        while let Some(entry) = tree.next_entry()? {
            let Some(key) = entry
                .path
                .rsplit(|byte| *byte == b'/')
                .next()
                .and_then(|name| name.strip_suffix(b".log"))
                .and_then(|name| std::str::from_utf8(name).ok())
            else {
                continue;
            };
            if key == "uuid" {
                continue;
            }
            let Some(external_identity_id) =
                self.projection.external_identity_id("git-annex", key)?
            else {
                continue;
            };
            let size = cat_file.check(&entry.oid)?;
            if size > MAX_LOCATION_LOG_BYTES {
                return Err(AnnexImportError::InvalidGitOutput {
                    operation: "read git-annex location log",
                    detail: format!(
                        "location log for {key} exceeds {MAX_LOCATION_LOG_BYTES} bytes"
                    ),
                });
            }
            let blob = cat_file.read_blob_bounded(&entry.oid, size, MAX_LOCATION_LOG_BYTES)?;
            for (remote_uuid, state) in parse_location_log(key, &blob)? {
                let location_id = self
                    .projection
                    .annex_remote_location(annex_uuid, &remote_uuid)?;
                let operation_key = stable_id(
                    "op",
                    &[
                        self.config.import_id.as_bytes(),
                        self.config.job_id.as_bytes(),
                        b"availability",
                        key.as_bytes(),
                        remote_uuid.as_bytes(),
                        state.as_bytes(),
                    ],
                );
                if self.projection.has_operation_key(&operation_key)? {
                    continue;
                }
                pending.push(event(
                    "external_availability_observed",
                    json!({
                        "external_identity_id": external_identity_id,
                        "source_repo_id": annex_uuid,
                        "source_remote_id": remote_uuid,
                        "state": state,
                        "location_id": location_id,
                        "operation_key": operation_key,
                        "job_type": "annex_import",
                        "item_type": "external_availability",
                        "item_key": key,
                        "outcome_kind": state,
                    }),
                    &self.config,
                    EventReferences {
                        job_id: Some(self.config.job_id.clone()),
                        location_id,
                        ..EventReferences::default()
                    },
                ));
                if pending.len() >= self.config.batch_entries {
                    self.flush(&mut pending)?;
                }
            }
        }
        tree.finish()?;
        cat_file.finish()?;
        self.flush(&mut pending)?;
        Ok(())
    }
}

const MAX_LOCATION_LOG_BYTES: u64 = 4 * 1024 * 1024;

fn write_v2_item(writer: &mut BufWriter<File>, item: &Value, path: &Path) -> Result<()> {
    serde_json::to_writer(&mut *writer, item)
        .map_err(|error| AnnexImportError::InvalidConfig(error.to_string()))?;
    writer
        .write_all(b"\n")
        .map_err(|source| io_error("write annex import spool", path, source))
}

fn save_annex_checkpoint(
    spool: &mut BufWriter<File>,
    spool_path: &Path,
    checkpoint_path: &Path,
    summary: &AnnexSummary,
) -> Result<()> {
    spool
        .flush()
        .and_then(|()| spool.get_ref().sync_all())
        .map_err(|source| io_error("sync annex import spool", spool_path, source))?;
    let spool_len = spool
        .stream_position()
        .map_err(|source| io_error("measure annex import spool", spool_path, source))?;
    let checkpoint = AnnexLocalCheckpoint {
        summary: summary.clone(),
        spool_len,
    };
    let temporary = checkpoint_path.with_extension("json.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|source| io_error("create annex import checkpoint", &temporary, source))?;
    serde_json::to_writer(&mut file, &checkpoint)
        .map_err(|error| AnnexImportError::InvalidConfig(error.to_string()))?;
    file.sync_all()
        .map_err(|source| io_error("sync annex import checkpoint", &temporary, source))?;
    fs::rename(&temporary, checkpoint_path)
        .map_err(|source| io_error("publish annex import checkpoint", checkpoint_path, source))
}

fn v2_annex_entry_item(
    config: &AnnexImportConfig,
    annex_uuid: &str,
    logical: &EncodedPath,
    key: &AnnexKey,
    outcome: &EntryOutcome,
) -> Value {
    let external_identity_id = stable_id("ext", &[b"git-annex", key.raw.as_bytes()]);
    let file_ref_id = stable_id(
        "file",
        &[
            config.collection_id.as_bytes(),
            logical.encoding.as_str().as_bytes(),
            &logical.bytes,
        ],
    );
    let resolved = outcome.category == EntryCategory::Present;
    let object_id = outcome
        .content
        .as_ref()
        .filter(|_| resolved)
        .map(|content| format!("blake3:{}", content.blake3_hex));
    let copy_location_id =
        (outcome.content.is_some() || outcome.category == EntryCategory::ReadError).then(|| {
            if outcome.representation == "annex_locked_symlink" {
                config.cas_location_id.clone()
            } else {
                config.worktree_location_id.clone()
            }
        });
    let copy_path = copy_location_id
        .as_ref()
        .map(|_| outcome.copy_path.as_ref().unwrap_or(logical));
    let copy_claim_id = copy_path
        .zip(copy_location_id.as_ref())
        .map(|(path, location)| {
            stable_id(
                "copy",
                &[
                    location.as_bytes(),
                    path.encoding.as_str().as_bytes(),
                    &path.bytes,
                ],
            )
        });
    let operation_key = stable_id(
        "op",
        &[
            config.job_id.as_bytes(),
            config.import_id.as_bytes(),
            logical.encoding.as_str().as_bytes(),
            &logical.bytes,
            b"annex_entry_observed",
        ],
    );
    json!({
        "kind": "annex_entry_observed",
        "import_id": config.import_id,
        "job_id": config.job_id,
        "collection_id": config.collection_id,
        "worktree_location_id": config.worktree_location_id,
        "cas_location_id": config.cas_location_id,
        "source_repo_id": annex_uuid,
        "external_identity_id": external_identity_id,
        "external_key": key.raw,
        "backend": key.backend,
        "expected_hash_algo": key.expected_sha256.as_ref().map(|_| "sha256"),
        "expected_hash_hex": key.expected_sha256,
        "expected_size_bytes": key.expected_size,
        "resolution_state": if resolved { "resolved" } else if key.state == KeyState::Unsupported { "unsupported" } else { "unresolved" },
        "file_ref_id": file_ref_id,
        "logical_path": path_json(logical),
        "path_state": if outcome.path_present { "present" } else { "missing" },
        "representation": outcome.representation,
        "local_availability": if outcome.local_bytes_present { "present" } else { "missing" },
        "object_id": object_id,
        "blake3_hex": outcome.content.as_ref().filter(|_| resolved).map(|content| &content.blake3_hex),
        "sha256_hex": outcome.content.as_ref().map(|content| &content.sha256_hex),
        "observed_size_bytes": outcome.content.as_ref().map(|content| content.size).or(key.expected_size),
        "modified_time_utc_ms": outcome.content.as_ref().and_then(|content| content.modified_time_utc_ms),
        "duration_ms": outcome.content.as_ref().map(|content| content.duration_ms),
        "copy_location_id": copy_location_id,
        "copy_path": copy_path.map(path_json),
        "copy_claim_id": copy_claim_id,
        "copy_state": match outcome.category {
            EntryCategory::Present | EntryCategory::SupportedUnresolved => "present",
            EntryCategory::Mismatch => "corrupt",
            EntryCategory::ReadError => "unknown",
            EntryCategory::Absent | EntryCategory::Unsupported => "missing",
        },
        "verification_result": match outcome.category {
            EntryCategory::Present => Some("ok"),
            EntryCategory::Mismatch => Some("hash_mismatch"),
            EntryCategory::ReadError => Some("read_error"),
            _ => None,
        },
        "error_detail": outcome.error,
        "job_type": "annex_import",
        "item_type": "file_ref",
        "item_key": file_ref_id,
        "outcome_kind": "annex_entry_observed",
        "operation_key": operation_key,
    })
}

fn inspect_entry_v2(
    config: &AnnexImportConfig,
    entry: &IndexEntry,
    index_blob: &[u8],
    key: &AnnexKey,
) -> Result<EntryOutcome> {
    let worktree_path = config.repo_path.join(raw_path(&entry.path)?);
    let metadata = match fs::symlink_metadata(&worktree_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if key.state == KeyState::Unsupported {
                return Ok(EntryOutcome {
                    category: EntryCategory::Unsupported,
                    representation: "missing_worktree_entry",
                    content: None,
                    error: None,
                    path_present: false,
                    local_bytes_present: false,
                    copy_path: None,
                });
            }
            return Ok(EntryOutcome::absent("missing_worktree_entry", false));
        }
        Err(error) => return Ok(EntryOutcome::read_error(error.to_string())),
    };
    let (representation, content_metadata, path_present, copy_path) = if entry.mode == "120000" {
        if !metadata.file_type().is_symlink() {
            return Ok(EntryOutcome::read_error(
                "worktree representation changed from annex symlink".to_owned(),
            ));
        }
        let target = fs::read_link(&worktree_path)
            .map_err(|source| io_error("read annex symlink", &worktree_path, source))?;
        if path_bytes(&target)? != index_blob {
            return Ok(EntryOutcome::read_error(
                "worktree symlink target differs from the Git index".to_owned(),
            ));
        }
        let target_metadata = match fs::metadata(&worktree_path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Ok(EntryOutcome::read_error(error.to_string())),
        };
        let copy_path = annex_object_relative(index_blob)
            .and_then(|bytes| raw_path(bytes).ok())
            .map(|path| {
                if config.cas_location_id == config.worktree_location_id {
                    encode_relative_path(&Path::new(".git/annex/objects").join(path))
                } else {
                    encode_relative_path(&path)
                }
            });
        ("annex_locked_symlink", target_metadata, true, copy_path)
    } else if metadata.file_type().is_file() {
        if metadata.len() <= MAX_POINTER_BYTES {
            match fs::read(&worktree_path) {
                Ok(bytes) if annex_key_from_blob("100644", &bytes).as_deref() == Some(&key.raw) => {
                    ("annex_pointer_file", None, true, None)
                }
                Ok(_) => (
                    "annex_unlocked_file",
                    Some(metadata),
                    true,
                    Some(encoded_worktree_path(entry)?),
                ),
                Err(error) => return Ok(EntryOutcome::read_error(error.to_string())),
            }
        } else {
            (
                "annex_unlocked_file",
                Some(metadata),
                true,
                Some(encoded_worktree_path(entry)?),
            )
        }
    } else {
        return Ok(EntryOutcome::read_error(
            "worktree entry is neither the indexed symlink nor a regular file".to_owned(),
        ));
    };
    if key.state == KeyState::Unsupported {
        return Ok(EntryOutcome {
            category: EntryCategory::Unsupported,
            representation,
            content: None,
            error: None,
            path_present,
            local_bytes_present: content_metadata.is_some(),
            copy_path,
        });
    }
    let Some(content_metadata) = content_metadata else {
        return Ok(EntryOutcome::absent(representation, path_present));
    };
    if key.expected_sha256.is_none() {
        return Ok(EntryOutcome {
            category: EntryCategory::SupportedUnresolved,
            representation,
            content: None,
            error: None,
            path_present,
            local_bytes_present: true,
            copy_path,
        });
    }
    match hash_file(&worktree_path, &content_metadata) {
        Ok(content) => {
            let matches = key.expected_size.is_none_or(|size| size == content.size)
                && key.expected_sha256.as_deref() == Some(&content.sha256_hex);
            Ok(EntryOutcome {
                category: if matches {
                    EntryCategory::Present
                } else {
                    EntryCategory::Mismatch
                },
                representation,
                content: Some(content),
                error: None,
                path_present,
                local_bytes_present: true,
                copy_path,
            })
        }
        Err(error) => Ok(EntryOutcome {
            category: EntryCategory::ReadError,
            representation,
            content: None,
            error: Some(error.to_string()),
            path_present,
            local_bytes_present: true,
            copy_path,
        }),
    }
}

fn parse_location_log(key: &str, blob: &[u8]) -> Result<BTreeMap<String, &'static str>> {
    let mut states = BTreeMap::new();
    for line in blob.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let line =
            std::str::from_utf8(line).map_err(|error| AnnexImportError::InvalidGitOutput {
                operation: "parse git-annex location log",
                detail: format!("location log for {key} is not UTF-8: {error}"),
            })?;
        let mut fields = line.split_whitespace();
        let timestamp = fields.next();
        let present = fields.next();
        let uuid = fields.next();
        if timestamp.is_none() || present.is_none() || uuid.is_none() || fields.next().is_some() {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "parse git-annex location log",
                detail: format!("location log for {key} contains a malformed line"),
            });
        }
        let uuid = uuid.expect("checked above");
        if uuid.is_empty() {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "parse git-annex location log",
                detail: format!("location log for {key} contains an empty UUID"),
            });
        }
        let state = match present.expect("checked above") {
            "1" => "present",
            "0" => "missing",
            _ => "unknown",
        };
        states.insert(uuid.to_owned(), state);
    }
    Ok(states)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryCategory {
    Present,
    Absent,
    SupportedUnresolved,
    Unsupported,
    Mismatch,
    ReadError,
}

impl EntryCategory {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::SupportedUnresolved => "supported_unresolved",
            Self::Unsupported => "unsupported",
            Self::Mismatch => "mismatched",
            Self::ReadError => "read_error",
        }
    }
}

impl AnnexSummary {
    fn add(&mut self, category: &EntryCategory) {
        match category {
            EntryCategory::Present => self.present += 1,
            EntryCategory::Absent => self.absent += 1,
            EntryCategory::SupportedUnresolved => self.supported_unresolved += 1,
            EntryCategory::Unsupported => self.unsupported += 1,
            EntryCategory::Mismatch => self.mismatched += 1,
            EntryCategory::ReadError => self.read_errors += 1,
        }
    }
}

struct EntryOutcome {
    category: EntryCategory,
    representation: &'static str,
    content: Option<ContentHashes>,
    error: Option<String>,
    path_present: bool,
    local_bytes_present: bool,
    copy_path: Option<EncodedPath>,
}

impl EntryOutcome {
    fn absent(representation: &'static str, path_present: bool) -> Self {
        Self {
            category: EntryCategory::Absent,
            representation,
            content: None,
            error: None,
            path_present,
            local_bytes_present: false,
            copy_path: None,
        }
    }

    fn read_error(error: String) -> Self {
        Self {
            category: EntryCategory::ReadError,
            representation: "annex_unreadable",
            content: None,
            error: Some(error),
            path_present: true,
            local_bytes_present: false,
            copy_path: None,
        }
    }
}

struct ContentHashes {
    blake3_hex: String,
    sha256_hex: String,
    size: u64,
    duration_ms: u64,
    modified_time_utc_ms: Option<u64>,
}

fn hash_file(path: &Path, initial_metadata: &Metadata) -> Result<ContentHashes> {
    let start = std::time::Instant::now();
    let mut file =
        File::open(path).map_err(|source| io_error("open annex content", path, source))?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut size = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("read annex content", path, source))?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or_else(|| {
            AnnexImportError::InvalidConfig("content size exceeds u64".to_owned())
        })?;
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    let final_metadata = file
        .metadata()
        .map_err(|source| io_error("reinspect annex content", path, source))?;
    if initial_metadata.len() != final_metadata.len()
        || modified_time_ms(initial_metadata) != modified_time_ms(&final_metadata)
        || size != final_metadata.len()
    {
        return Err(AnnexImportError::SourceChanged);
    }
    Ok(ContentHashes {
        blake3_hex: blake3.finalize().to_hex().to_string(),
        sha256_hex: format!("{:x}", sha256.finalize()),
        size,
        duration_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        modified_time_utc_ms: modified_time_ms(&final_metadata),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyState {
    Supported,
    Unsupported,
}

struct AnnexKey {
    raw: String,
    backend: String,
    expected_size: Option<u64>,
    expected_sha256: Option<String>,
    state: KeyState,
}

impl AnnexKey {
    fn parse(raw: &str) -> Self {
        let (metadata, name) = raw.split_once("--").unwrap_or((raw, ""));
        let mut fields = metadata.split('-');
        let backend = fields.next().unwrap_or("").to_owned();
        let expected_size = fields
            .find_map(|field| field.strip_prefix('s'))
            .and_then(|digits| digits.parse().ok());
        let expected_sha256 = match backend.as_str() {
            "SHA256" if is_lower_hex(name, 64) => Some(name.to_owned()),
            "SHA256E" if name.len() >= 64 && is_lower_hex(&name[..64], 64) => {
                Some(name[..64].to_owned())
            }
            _ => None,
        };
        let recognized = matches!(
            backend.as_str(),
            "SHA256"
                | "SHA256E"
                | "SHA512"
                | "SHA512E"
                | "SHA1"
                | "SHA1E"
                | "MD5"
                | "MD5E"
                | "BLAKE2B"
                | "BLAKE2BP"
        );
        let state = if raw.contains("--") && recognized {
            KeyState::Supported
        } else {
            KeyState::Unsupported
        };
        Self {
            raw: raw.to_owned(),
            backend,
            expected_size,
            expected_sha256,
            state,
        }
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn annex_key_from_blob(mode: &str, blob: &[u8]) -> Option<String> {
    if mode == "120000" {
        annex_object_relative(blob)?;
        let last = blob.rsplit(|byte| *byte == b'/').next()?;
        let previous = blob.rsplit(|byte| *byte == b'/').nth(1)?;
        if last != previous {
            return None;
        }
        return std::str::from_utf8(last).ok().map(str::to_owned);
    }
    let line = blob.split(|byte| *byte == b'\n').next()?;
    let key = line.strip_prefix(b"/annex/objects/")?;
    (!key.is_empty())
        .then(|| std::str::from_utf8(key).ok().map(str::to_owned))
        .flatten()
}

fn annex_object_relative(blob: &[u8]) -> Option<&[u8]> {
    const MARKER: &[u8] = b".git/annex/objects/";
    blob.windows(MARKER.len())
        .position(|window| window == MARKER)
        .map(|offset| &blob[offset + MARKER.len()..])
        .filter(|relative| !relative.is_empty())
}

fn encoded_worktree_path(entry: &IndexEntry) -> Result<EncodedPath> {
    raw_path(&entry.path).map(|path| encode_relative_path(&path))
}

struct IndexEntry {
    mode: String,
    oid: String,
    stage: u8,
    path: Vec<u8>,
}

struct IndexStream {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

struct TreeEntry {
    oid: String,
    path: Vec<u8>,
}

struct TreeStream {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl TreeStream {
    fn open(repo: &Path) -> Result<Self> {
        let mut child = git_command(repo)
            .args(["ls-tree", "-r", "-z", "refs/heads/git-annex"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| io_error("start git ls-tree", repo, source))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AnnexImportError::InvalidGitOutput {
                operation: "git ls-tree",
                detail: "stdout pipe was unavailable".to_owned(),
            })?;
        Ok(Self {
            child,
            stdout: BufReader::new(stdout),
        })
    }

    fn next_entry(&mut self) -> Result<Option<TreeEntry>> {
        let mut record = Vec::new();
        let read = self
            .stdout
            .read_until(0, &mut record)
            .map_err(|source| io_error("read git ls-tree", "git stdout", source))?;
        if read == 0 {
            return Ok(None);
        }
        record.pop();
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| AnnexImportError::InvalidGitOutput {
                operation: "git ls-tree",
                detail: "record lacks path separator".to_owned(),
            })?;
        let header = std::str::from_utf8(&record[..tab]).map_err(|error| {
            AnnexImportError::InvalidGitOutput {
                operation: "git ls-tree",
                detail: error.to_string(),
            }
        })?;
        let mut fields = header.split(' ');
        let _mode = fields.next();
        let kind = fields.next();
        let oid = fields.next();
        if kind != Some("blob") || oid.is_none() || fields.next().is_some() {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "git ls-tree",
                detail: format!("invalid tree header {header:?}"),
            });
        }
        Ok(Some(TreeEntry {
            oid: oid.expect("checked above").to_owned(),
            path: record[tab + 1..].to_vec(),
        }))
    }

    fn finish(self) -> Result<()> {
        let output = self
            .child
            .wait_with_output()
            .map_err(|source| io_error("wait for git ls-tree", "git process", source))?;
        if !output.status.success() {
            return Err(AnnexImportError::Git {
                operation: "git ls-tree",
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(())
    }
}

impl IndexStream {
    fn open(repo: &Path) -> Result<Self> {
        let mut child = git_command(repo)
            .args(["ls-files", "--stage", "-z"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| io_error("start git ls-files", repo, source))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AnnexImportError::InvalidGitOutput {
                operation: "git ls-files",
                detail: "stdout pipe was unavailable".to_owned(),
            })?;
        Ok(Self {
            child,
            stdout: BufReader::new(stdout),
        })
    }

    fn next_entry(&mut self) -> Result<Option<IndexEntry>> {
        let mut record = Vec::new();
        let read = self
            .stdout
            .read_until(0, &mut record)
            .map_err(|source| io_error("read git ls-files", "git stdout", source))?;
        if read == 0 {
            return Ok(None);
        }
        record.pop();
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| AnnexImportError::InvalidGitOutput {
                operation: "git ls-files",
                detail: "record lacks path separator".to_owned(),
            })?;
        let header = std::str::from_utf8(&record[..tab]).map_err(|error| {
            AnnexImportError::InvalidGitOutput {
                operation: "git ls-files",
                detail: error.to_string(),
            }
        })?;
        let mut fields = header.split(' ');
        let mode = fields.next().unwrap_or("");
        let oid = fields.next().unwrap_or("");
        let stage = fields.next().unwrap_or("");
        if mode.is_empty() || oid.is_empty() || fields.next().is_some() {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "git ls-files",
                detail: format!("invalid index header {header:?}"),
            });
        }
        Ok(Some(IndexEntry {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
            stage: stage
                .parse()
                .map_err(|_| AnnexImportError::InvalidGitOutput {
                    operation: "git ls-files",
                    detail: format!("invalid index stage {stage:?}"),
                })?,
            path: record[tab + 1..].to_vec(),
        }))
    }

    fn finish(self) -> Result<()> {
        let output = self
            .child
            .wait_with_output()
            .map_err(|source| io_error("wait for git ls-files", "git process", source))?;
        if !output.status.success() {
            return Err(AnnexImportError::Git {
                operation: "git ls-files",
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(())
    }
}

struct BatchProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    operation: &'static str,
}

impl BatchProcess {
    fn open(repo: &Path, args: &[&str], operation: &'static str) -> Result<Self> {
        let mut child = git_command(repo)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| io_error("start git cat-file", repo, source))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AnnexImportError::InvalidGitOutput {
                operation,
                detail: "stdin pipe was unavailable".to_owned(),
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AnnexImportError::InvalidGitOutput {
                operation,
                detail: "stdout pipe was unavailable".to_owned(),
            })?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            operation,
        })
    }

    fn request_header(&mut self, oid: &str) -> Result<(String, String, u64)> {
        writeln!(self.stdin, "{oid}")
            .and_then(|_| self.stdin.flush())
            .map_err(|source| io_error("write git cat-file request", "git stdin", source))?;
        let mut header = String::new();
        self.stdout
            .read_line(&mut header)
            .map_err(|source| io_error("read git cat-file header", "git stdout", source))?;
        let mut fields = header.trim_end().split(' ');
        let actual_oid = fields.next().unwrap_or("");
        let kind = fields.next().unwrap_or("");
        let size = fields.next().unwrap_or("");
        if actual_oid.is_empty() || kind.is_empty() || size.is_empty() || fields.next().is_some() {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: self.operation,
                detail: format!("invalid cat-file header {header:?}"),
            });
        }
        let size = size
            .parse()
            .map_err(|_| AnnexImportError::InvalidGitOutput {
                operation: self.operation,
                detail: format!("invalid object size {size:?}"),
            })?;
        Ok((actual_oid.to_owned(), kind.to_owned(), size))
    }

    fn finish(self) -> Result<()> {
        drop(self.stdin);
        let output = self
            .child
            .wait_with_output()
            .map_err(|source| io_error("wait for git cat-file", "git process", source))?;
        if !output.status.success() {
            return Err(AnnexImportError::Git {
                operation: self.operation,
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(())
    }
}

struct CatFile {
    check: BatchProcess,
    content: BatchProcess,
}

impl CatFile {
    fn open(repo: &Path) -> Result<Self> {
        Ok(Self {
            check: BatchProcess::open(repo, &["cat-file", "--batch-check"], "git cat-file check")?,
            content: BatchProcess::open(repo, &["cat-file", "--batch"], "git cat-file content")?,
        })
    }

    fn check(&mut self, oid: &str) -> Result<u64> {
        let (actual, kind, size) = self.check.request_header(oid)?;
        if actual != oid || kind != "blob" {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "git cat-file check",
                detail: format!("expected blob {oid}, received {kind} {actual}"),
            });
        }
        Ok(size)
    }

    fn read_blob(&mut self, oid: &str, expected_size: u64) -> Result<Vec<u8>> {
        self.read_blob_bounded(oid, expected_size, MAX_POINTER_BYTES)
    }

    fn read_blob_bounded(
        &mut self,
        oid: &str,
        expected_size: u64,
        max_size: u64,
    ) -> Result<Vec<u8>> {
        let (actual, kind, size) = self.content.request_header(oid)?;
        if actual != oid || kind != "blob" || size != expected_size || size > max_size {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "git cat-file content",
                detail: format!("unexpected blob response for {oid}"),
            });
        }
        let mut blob = vec![0u8; size as usize];
        self.content
            .stdout
            .read_exact(&mut blob)
            .map_err(|source| io_error("read git blob", "git stdout", source))?;
        let mut newline = [0u8; 1];
        self.content
            .stdout
            .read_exact(&mut newline)
            .map_err(|source| io_error("read git blob terminator", "git stdout", source))?;
        if newline != *b"\n" {
            return Err(AnnexImportError::InvalidGitOutput {
                operation: "git cat-file content",
                detail: "blob was not followed by a newline".to_owned(),
            });
        }
        Ok(blob)
    }

    fn finish(self) -> Result<()> {
        self.check.finish()?;
        self.content.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceSnapshot {
    head: String,
    annex_branch: String,
    index_status_digest: String,
    worktree_metadata_digest: String,
}

impl SourceSnapshot {
    fn capture(repo: &Path) -> Result<Self> {
        Ok(Self {
            head: git_text(repo, "read HEAD", &["rev-parse", "--verify", "HEAD"])?,
            annex_branch: git_text_optional(
                repo,
                "read git-annex branch",
                &["rev-parse", "--verify", "refs/heads/git-annex"],
            )?,
            index_status_digest: git_output_digest(
                repo,
                "inspect tracked worktree state",
                &["status", "--porcelain=v1", "-z", "--untracked-files=no"],
            )?,
            worktree_metadata_digest: worktree_metadata_digest(repo)?,
        })
    }

    fn fingerprint(&self) -> String {
        stable_id(
            "source",
            &[
                self.head.as_bytes(),
                self.annex_branch.as_bytes(),
                self.index_status_digest.as_bytes(),
                self.worktree_metadata_digest.as_bytes(),
            ],
        )
    }
}

#[cfg(unix)]
fn worktree_metadata_digest(repo: &Path) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let mut hasher = blake3::Hasher::new();
    let mut index = IndexStream::open(repo)?;
    while let Some(entry) = index.next_entry()? {
        if entry.stage != 0 {
            continue;
        }
        hasher.update(&(entry.path.len() as u64).to_le_bytes());
        hasher.update(&entry.path);
        let path = repo.join(raw_path(&entry.path)?);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                hasher.update(b"present");
                hasher.update(&metadata.mode().to_le_bytes());
                hasher.update(&metadata.len().to_le_bytes());
                hasher.update(&metadata.mtime().to_le_bytes());
                hasher.update(&metadata.mtime_nsec().to_le_bytes());
                hasher.update(&metadata.ctime().to_le_bytes());
                hasher.update(&metadata.ctime_nsec().to_le_bytes());
                if metadata.file_type().is_symlink() {
                    hasher.update(
                        fs::read_link(&path)
                            .map_err(|source| io_error("read worktree symlink", &path, source))?
                            .as_os_str()
                            .as_bytes(),
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                hasher.update(b"missing");
            }
            Err(source) => return Err(io_error("inspect tracked worktree entry", path, source)),
        }
    }
    index.finish()?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(not(unix))]
fn worktree_metadata_digest(_repo: &Path) -> Result<String> {
    Err(AnnexImportError::UnsupportedPlatform)
}

fn git_command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C");
    command
}

fn git_text(repo: &Path, operation: &'static str, args: &[&str]) -> Result<String> {
    let output = git_command(repo)
        .args(args)
        .output()
        .map_err(|source| io_error("run git command", repo, source))?;
    if !output.status.success() {
        return Err(AnnexImportError::Git {
            operation,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_text_optional(repo: &Path, operation: &'static str, args: &[&str]) -> Result<String> {
    let output = git_command(repo)
        .args(args)
        .output()
        .map_err(|source| io_error("run git command", repo, source))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    if output.status.code() == Some(128) {
        return Ok(String::new());
    }
    Err(AnnexImportError::Git {
        operation,
        detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

fn git_output_digest(repo: &Path, operation: &'static str, args: &[&str]) -> Result<String> {
    let mut child = git_command(repo)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| io_error("run git command", repo, source))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AnnexImportError::InvalidGitOutput {
            operation,
            detail: "stdout pipe was unavailable".to_owned(),
        })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = stdout
            .read(&mut buffer)
            .map_err(|source| io_error("read git command output", "git stdout", source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    drop(stdout);
    let output = child
        .wait_with_output()
        .map_err(|source| io_error("wait for git command", repo, source))?;
    if !output.status.success() {
        return Err(AnnexImportError::Git {
            operation,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn event_operation_key(event: &EventRequest) -> Result<&str> {
    event
        .payload
        .get("operation_key")
        .and_then(Value::as_str)
        .ok_or_else(|| AnnexImportError::InvalidConfig("event lacks operation_key".to_owned()))
}

struct OutcomeFields<'a> {
    config: &'a AnnexImportConfig,
    item: Vec<u8>,
    outcome: &'a str,
}

impl<'a> OutcomeFields<'a> {
    fn new(
        config: &'a AnnexImportConfig,
        path: &EncodedPath,
        item_kind: &'a str,
        outcome: &'a str,
    ) -> Self {
        let mut item = item_kind.as_bytes().to_vec();
        item.push(0);
        item.extend_from_slice(path.encoding.as_str().as_bytes());
        item.push(0);
        item.extend_from_slice(&path.bytes);
        Self {
            config,
            item,
            outcome,
        }
    }

    fn operation_key(&self, fact: &str) -> String {
        stable_id(
            "op",
            &[
                self.config.import_id.as_bytes(),
                self.config.job_id.as_bytes(),
                &self.item,
                fact.as_bytes(),
                self.outcome.as_bytes(),
            ],
        )
    }
}

fn stable_id(prefix: &str, pieces: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for piece in pieces {
        hasher.update(&(piece.len() as u64).to_le_bytes());
        hasher.update(piece);
    }
    format!("{prefix}_{}", &hasher.finalize().to_hex()[..32])
}

fn annex_now_utc_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            AnnexImportError::InvalidConfig(format!("system clock is before epoch: {error}"))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| AnnexImportError::InvalidConfig("system time exceeds u64".to_owned()))
}

fn path_json(path: &EncodedPath) -> Value {
    match path.encoding.as_str() {
        "utf8" => json!({
            "encoding": "utf8",
            "text": std::str::from_utf8(&path.bytes).expect("UTF-8 path encoding invariant"),
            "display": path.display,
        }),
        encoding => json!({
            "encoding": encoding,
            "base64": base64::engine::general_purpose::STANDARD.encode(&path.bytes),
            "display": path.display,
        }),
    }
}

fn event(
    event_type: &str,
    payload: Value,
    _config: &AnnexImportConfig,
    references: EventReferences,
) -> EventRequest {
    EventRequest::new(event_type, payload).with_references(references)
}

fn import_started_event(
    config: &AnnexImportConfig,
    annex_uuid: &str,
    snapshot: &SourceSnapshot,
) -> EventRequest {
    event(
        "annex_import_started",
        json!({
            "import_id": config.import_id,
            "repo_path": path_json(&encode_absolute_path(&config.repo_path)),
            "collection_id": config.collection_id,
            "location_id": (config.worktree_location_id == config.cas_location_id)
                .then_some(&config.worktree_location_id),
            "worktree_location_id": config.worktree_location_id,
            "cas_location_id": config.cas_location_id,
            "device_id": config.device_id,
            "archive_root_id": config.archive_root_id,
            "annex_uuid": annex_uuid,
            "git_head_commit": snapshot.head,
            "source_fingerprint": snapshot.fingerprint(),
            "operation_key": stable_id("op", &[config.import_id.as_bytes(), b"started"]),
            "job_type": "annex_import",
            "item_type": "import",
            "item_key": config.import_id,
            "outcome_kind": "started",
        }),
        config,
        EventReferences {
            job_id: Some(config.job_id.clone()),
            device_id: Some(config.device_id.clone()),
            ..EventReferences::default()
        },
    )
}

fn import_completed_event(
    config: &AnnexImportConfig,
    annex_uuid: &str,
    head: &str,
    summary: &AnnexSummary,
    status: &str,
) -> EventRequest {
    event(
        "annex_import_completed",
        json!({
            "import_id": config.import_id,
            "annex_uuid": annex_uuid,
            "git_head_commit": head,
            "status": status,
            "summary": summary,
            "operation_key": stable_id("op", &[config.import_id.as_bytes(), b"completed"]),
            "job_type": "annex_import",
            "item_type": "import",
            "item_key": config.import_id,
            "outcome_kind": "complete",
        }),
        config,
        EventReferences {
            job_id: Some(config.job_id.clone()),
            device_id: Some(config.device_id.clone()),
            ..EventReferences::default()
        },
    )
}

#[cfg(unix)]
fn raw_path(bytes: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn raw_path(_bytes: &[u8]) -> Result<PathBuf> {
    Err(AnnexImportError::UnsupportedPlatform)
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn path_bytes(_path: &Path) -> Result<Vec<u8>> {
    Err(AnnexImportError::UnsupportedPlatform)
}

fn encode_absolute_path(path: &Path) -> EncodedPath {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes().to_vec();
        let encoding = if path.to_str().is_some() {
            crate::discovery::PathEncoding::Utf8
        } else {
            crate::discovery::PathEncoding::UnixBytes
        };
        EncodedPath {
            encoding,
            display: path.to_string_lossy().into_owned(),
            bytes,
        }
    }
    #[cfg(not(unix))]
    {
        encode_relative_path(path)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Command;

    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;
    use crate::event_store::EventStoreConfig;
    use crate::projection::ProjectionConfig;

    #[test]
    fn parses_locked_and_pointer_representations() {
        let key =
            "SHA256E-s3--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt";
        let link = format!(".git/annex/objects/aa/bb/{key}/{key}");
        assert_eq!(
            annex_key_from_blob("120000", link.as_bytes()).as_deref(),
            Some(key)
        );
        assert_eq!(
            annex_key_from_blob("100644", format!("/annex/objects/{key}\n").as_bytes()).as_deref(),
            Some(key)
        );
        assert!(annex_key_from_blob("120000", format!("../src/{key}/{key}").as_bytes()).is_none());
        assert!(annex_key_from_blob(
            "120000",
            format!("../not-git/annex/objects/{key}/{key}").as_bytes()
        )
        .is_none());
        assert!(annex_key_from_blob("100644", b"ordinary content").is_none());
    }

    #[test]
    fn key_parser_separates_supported_unverifiable_and_unsupported() {
        let sha = AnnexKey::parse(
            "SHA256E-s3--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt",
        );
        assert_eq!(sha.state, KeyState::Supported);
        assert_eq!(sha.expected_size, Some(3));
        assert_eq!(
            sha.expected_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );

        let sha512 = AnnexKey::parse("SHA512E-s3--abc.txt");
        assert_eq!(sha512.state, KeyState::Supported);
        assert!(sha512.expected_sha256.is_none());

        let worm = AnnexKey::parse("WORM-s3--file.txt");
        assert_eq!(worm.state, KeyState::Unsupported);
    }

    #[test]
    fn stable_ids_are_framed_and_do_not_conflate_piece_boundaries() {
        assert_ne!(
            stable_id("id", &[b"ab", b"c"]),
            stable_id("id", &[b"a", b"bc"])
        );
    }

    #[test]
    fn location_logs_keep_latest_state_and_reject_malformed_lines() {
        let states =
            parse_location_log("key", b"1s 1 remote-a\n2s 0 remote-a\n3s x remote-b\n").unwrap();
        assert_eq!(states.get("remote-a"), Some(&"missing"));
        assert_eq!(states.get("remote-b"), Some(&"unknown"));
        assert_eq!(
            parse_location_log("key", b"malformed\n")
                .unwrap_err()
                .code(),
            "annex_invalid_git_output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn imports_complete_annex_inventory_read_only_and_resumes() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let temp = TempDir::new().unwrap();
        let fixture = build_annex_fixture(&temp);
        let before = tree_fingerprint(&fixture.repo);

        let store = EventStore::open_or_create(
            temp.path().join("canonical"),
            EventStoreConfig {
                rollover_events: 100,
                max_event_bytes: 1024 * 1024,
                actor_id: "test-user".to_owned(),
                host_id: "test-host".to_owned(),
            },
        )
        .unwrap();
        let projection = ProjectionDb::open_or_create(
            temp.path().join("archive.db"),
            "arc_test",
            ProjectionConfig {
                batch_events: 50,
                ..ProjectionConfig::default()
            },
        )
        .unwrap();
        seed_topology(projection.path());
        store
            .append(EventRequest::new(
                "annex_remote_mapped",
                json!({
                    "source_annex_uuid": "source-fixture",
                    "remote_annex_uuid": "remote-fixture",
                    "display_name": "Fixture remote",
                    "location_id": "location_worktree",
                }),
            ))
            .unwrap();
        projection.apply(&store).unwrap();
        let config = AnnexImportConfig {
            repo_path: fixture.repo.clone(),
            import_id: "import_fixture".to_owned(),
            job_id: "job_fixture".to_owned(),
            collection_id: "collection_fixture".to_owned(),
            worktree_location_id: "location_worktree".to_owned(),
            cas_location_id: "location_cas".to_owned(),
            device_id: "device_fixture".to_owned(),
            archive_root_id: "root_fixture".to_owned(),
            batch_entries: 2,
        };
        let importer = AnnexImporter::new(&store, &projection, config.clone()).unwrap();
        let interrupted = importer.run_at_most(Some(2)).unwrap();
        assert_eq!(interrupted.status, AnnexImportStatus::Interrupted);

        let result = AnnexImporter::new(&store, &projection, config.clone())
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(result.status, AnnexImportStatus::Complete);
        assert_eq!(result.summary.entries_seen, 13);
        assert_eq!(result.summary.present, 4);
        assert_eq!(result.summary.absent, 2);
        assert_eq!(result.summary.unsupported, 1);
        assert_eq!(result.summary.mismatched, 1);
        assert_eq!(result.summary.read_errors, 1);
        assert_eq!(result.summary.ignored_non_annex, 4);
        assert_eq!(result.summary.ignored_symlinks, 3);
        assert_eq!(result.summary.duplicate_paths, 1);
        assert_eq!(result.summary.availability_facts, 9);
        assert_eq!(before, tree_fingerprint(&fixture.repo));

        let connection = Connection::open(projection.path()).unwrap();
        let count = |sql: &str| -> i64 { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM external_identities"), 8);
        assert_eq!(count("SELECT count(*) FROM file_refs"), 9);
        assert_eq!(count("SELECT count(*) FROM objects"), 3);
        assert_eq!(count("SELECT count(*) FROM copy_claims"), 5);
        assert_eq!(count("SELECT count(*) FROM verification_results"), 6);
        assert_eq!(
            count(
                "SELECT count(*) FROM verification_results
                 WHERE result = 'ok' AND expected_hash_algo = 'sha256'
                   AND expected_hash_hex = observed_hash_hex"
            ),
            4
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM copy_claims
                 WHERE state = 'present' AND last_verification_result = 'ok'
                   AND last_verified_time_utc_ms IS NOT NULL"
            ),
            3
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM external_identities WHERE resolution_state = 'unsupported'"
            ),
            1
        );
        assert_eq!(
            count("SELECT count(*) FROM file_refs WHERE identity_state = 'unresolved'"),
            5
        );
        assert_eq!(
            count("SELECT count(*) FROM external_availability WHERE source_remote_id = 'remote-fixture' AND state = 'present' AND location_id = 'location_worktree'"),
            1
        );
        assert_eq!(
            count(
                "SELECT count(*)
                 FROM external_availability a
                 WHERE a.source_remote_id = 'remote-fixture'
                   AND EXISTS (
                       SELECT 1 FROM copy_claims c
                       WHERE c.external_identity_id = a.external_identity_id
                         AND c.location_id = a.location_id
                   )"
            ),
            0
        );
        assert_eq!(
            count("SELECT count(*) FROM copy_claims WHERE state = 'corrupt'"),
            1
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM copy_claims
                 WHERE state = 'corrupt' AND last_verification_result = 'hash_mismatch'"
            ),
            1
        );
        assert_eq!(
            count("SELECT count(*) FROM verification_results WHERE result = 'read_error'"),
            1
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM copy_claims
                 WHERE state = 'unknown' AND last_verification_result = 'read_error'"
            ),
            1
        );
        drop(connection);

        let event_count = projection.status().unwrap().cursor.applied_seq;
        let repeated = AnnexImporter::new(&store, &projection, config)
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(repeated.summary, result.summary);
        assert_eq!(projection.status().unwrap().cursor.applied_seq, event_count);
        assert_eq!(before, tree_fingerprint(&fixture.repo));

        let second = build_annex_fixture_at(&temp, "annex-source-two", "source-fixture-two");
        let second_before = tree_fingerprint(&second.repo);
        seed_second_topology(projection.path());
        let second_result = AnnexImporter::new(
            &store,
            &projection,
            AnnexImportConfig {
                repo_path: second.repo.clone(),
                import_id: "import_fixture_two".to_owned(),
                job_id: "job_fixture_two".to_owned(),
                collection_id: "collection_fixture_two".to_owned(),
                worktree_location_id: "location_worktree_two".to_owned(),
                cas_location_id: "location_cas_two".to_owned(),
                device_id: "device_fixture_two".to_owned(),
                archive_root_id: "root_fixture_two".to_owned(),
                batch_entries: 3,
            },
        )
        .unwrap()
        .run()
        .unwrap();
        assert_eq!(second_result.status, AnnexImportStatus::Complete);
        assert_eq!(second_before, tree_fingerprint(&second.repo));
        let connection = Connection::open(projection.path()).unwrap();
        let devices: i64 = connection
            .query_row(
                "SELECT count(DISTINCT l.device_id)
                 FROM copy_claims c JOIN locations l ON l.location_id = c.location_id",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(devices, 2);
        drop(connection);

        let changing = build_annex_fixture_at(&temp, "annex-source-changing", "source-changing");
        let changing_config = AnnexImportConfig {
            repo_path: changing.repo.clone(),
            import_id: "import_changing".to_owned(),
            job_id: "job_changing".to_owned(),
            collection_id: "collection_fixture".to_owned(),
            worktree_location_id: "location_worktree".to_owned(),
            cas_location_id: "location_cas".to_owned(),
            device_id: "device_fixture".to_owned(),
            archive_root_id: "root_fixture".to_owned(),
            batch_entries: 2,
        };
        AnnexImporter::new(&store, &projection, changing_config.clone())
            .unwrap()
            .run_at_most(Some(1))
            .unwrap();
        fs::write(
            changing.repo.join("ordinary.txt"),
            b"changed during import\n",
        )
        .unwrap();
        assert_eq!(
            AnnexImporter::new(&store, &projection, changing_config)
                .unwrap()
                .run()
                .unwrap_err()
                .code(),
            "annex_source_changed"
        );
        let connection = Connection::open(projection.path()).unwrap();
        let changing_status: String = connection
            .query_row(
                "SELECT status FROM annex_imports WHERE import_id = 'import_changing'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(changing_status, "partial");
    }

    #[cfg(unix)]
    struct AnnexFixture {
        repo: PathBuf,
    }

    #[cfg(unix)]
    fn build_annex_fixture(temp: &TempDir) -> AnnexFixture {
        build_annex_fixture_at(temp, "annex-source", "source-fixture")
    }

    #[cfg(unix)]
    fn build_annex_fixture_at(temp: &TempDir, directory: &str, annex_uuid: &str) -> AnnexFixture {
        let repo = temp.path().join(directory);
        fs::create_dir(&repo).unwrap();
        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.name", "Archive Ledger Test"]);
        run_git(&repo, &["config", "user.email", "test@example.invalid"]);
        run_git(&repo, &["config", "annex.uuid", annex_uuid]);

        let present_key = sha256_key(b"present content\n", "present.txt");
        let dropped_key = sha256_key(b"dropped content\n", "drop.txt");
        let duplicate_key = sha256_key(b"duplicate content\n", "duplicate.txt");
        let unlocked_key = sha256_key(b"unlocked content\n", "unlocked.txt");
        let mismatch_key = sha256_key(b"expected content\n", "mismatch.txt");
        let unreadable_key = sha256_key(b"unreadable content\n", "unreadable.txt");
        let pointer_key = sha256_key(b"pointer content\n", "pointer.txt");
        let unsupported_key = "WORM-s20--unsupported.txt".to_owned();

        make_locked(
            &repo,
            "present.txt",
            &present_key,
            Some(b"present content\n"),
        );
        make_locked(&repo, "drop.txt", &dropped_key, None);
        make_locked(
            &repo,
            "duplicate-a.txt",
            &duplicate_key,
            Some(b"duplicate content\n"),
        );
        make_locked(&repo, "duplicate-b.txt", &duplicate_key, None);
        make_locked(
            &repo,
            "mismatch.txt",
            &mismatch_key,
            Some(b"wrong content\n"),
        );
        make_locked(
            &repo,
            "unsupported.txt",
            &unsupported_key,
            Some(b"unsupported content\n"),
        );
        make_locked_directory(&repo, "unreadable.txt", &unreadable_key);
        fs::write(
            repo.join("unlocked.txt"),
            format!("/annex/objects/{unlocked_key}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("pointer.txt"),
            format!("/annex/objects/{pointer_key}\n"),
        )
        .unwrap();
        fs::write(repo.join("ordinary.txt"), b"ordinary file\n").unwrap();
        fs::create_dir(repo.join("organized")).unwrap();
        std::os::unix::fs::symlink("../present.txt", repo.join("organized/present-alias.txt"))
            .unwrap();
        std::os::unix::fs::symlink("../missing-target", repo.join("organized/dangling-alias"))
            .unwrap();
        std::os::unix::fs::symlink(
            format!("../src/{present_key}/{present_key}"),
            repo.join("organized/repeated-name-alias"),
        )
        .unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "fixture"]);

        run_git(&repo, &["checkout", "--orphan", "git-annex"]);
        run_git(&repo, &["rm", "-rf", "."]);
        let log_path = repo.join(format!("aa/bb/{present_key}.log"));
        fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        fs::write(&log_path, b"1s 1 remote-fixture\n").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "annex location log"]);
        run_git(&repo, &["checkout", "main"]);
        fs::write(repo.join("unlocked.txt"), b"unlocked content\n").unwrap();

        AnnexFixture { repo }
    }

    #[cfg(unix)]
    fn sha256_key(content: &[u8], name: &str) -> String {
        let digest = Sha256::digest(content);
        format!("SHA256E-s{}--{:x}.{name}", content.len(), digest)
    }

    #[cfg(unix)]
    fn make_locked(repo: &Path, name: &str, key: &str, content: Option<&[u8]>) {
        use std::os::unix::fs::symlink;

        let relative = PathBuf::from(format!(".git/annex/objects/aa/bb/{key}/{key}"));
        if let Some(content) = content {
            let object = repo.join(&relative);
            fs::create_dir_all(object.parent().unwrap()).unwrap();
            if !object.exists() {
                fs::write(object, content).unwrap();
            }
        }
        symlink(relative, repo.join(name)).unwrap();
    }

    #[cfg(unix)]
    fn make_locked_directory(repo: &Path, name: &str, key: &str) {
        use std::os::unix::fs::symlink;

        let relative = PathBuf::from(format!(".git/annex/objects/aa/bb/{key}/{key}"));
        fs::create_dir_all(repo.join(&relative)).unwrap();
        symlink(relative, repo.join(name)).unwrap();
    }

    #[cfg(unix)]
    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    fn seed_topology(database: &Path) {
        let connection = Connection::open(database).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
             INSERT INTO collections(
                collection_id, display_name, status, last_event_id
             ) VALUES ('collection_fixture', 'Fixture', 'active', 'seed');
             INSERT INTO devices(
                device_id, display_name, device_kind, identity_state, status,
                expected_availability, last_event_id
             ) VALUES (
                'device_fixture', 'Fixture device', 'disk', 'confirmed', 'active',
                'online', 'seed'
             );
             INSERT INTO archive_roots(
                archive_root_id, device_id, display_name, root_path_on_device_bytes,
                root_path_encoding, root_path_display, status, created_event_id
             ) VALUES (
                'root_fixture', 'device_fixture', 'Fixture root', x'2f',
                'utf8', '/', 'active', 'seed'
             );
             INSERT INTO locations(
                location_id, display_name, kind, archive_root_id,
                relative_path_bytes, relative_path_encoding, relative_path_display,
                device_id, encryption_state, trust_level, expected_availability,
                is_writable, status, created_event_id, last_event_id
             ) VALUES
                ('location_worktree', 'Worktree', 'filesystem', 'root_fixture',
                 x'2e', 'utf8', '.', 'device_fixture', 'unknown', 'trusted',
                 'online', 0, 'active', 'seed', 'seed'),
                ('location_cas', 'CAS', 'filesystem', 'root_fixture',
                 x'2e6769742f616e6e65782f6f626a65637473', 'utf8', '.git/annex/objects',
                 'device_fixture', 'unknown', 'trusted', 'online', 0, 'active',
                 'seed', 'seed');",
            )
            .unwrap();
    }

    #[cfg(unix)]
    fn seed_second_topology(database: &Path) {
        let connection = Connection::open(database).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 INSERT INTO collections(
                    collection_id, display_name, status, last_event_id
                 ) VALUES ('collection_fixture_two', 'Fixture two', 'active', 'seed');
                 INSERT INTO devices(
                    device_id, display_name, device_kind, identity_state, status,
                    expected_availability, last_event_id
                 ) VALUES (
                    'device_fixture_two', 'Fixture device two', 'disk', 'confirmed',
                    'active', 'online', 'seed'
                 );
                 INSERT INTO archive_roots(
                    archive_root_id, device_id, display_name, root_path_on_device_bytes,
                    root_path_encoding, root_path_display, status, created_event_id
                 ) VALUES (
                    'root_fixture_two', 'device_fixture_two', 'Fixture root two', x'2f',
                    'utf8', '/', 'active', 'seed'
                 );
                 INSERT INTO locations(
                    location_id, display_name, kind, archive_root_id,
                    relative_path_bytes, relative_path_encoding, relative_path_display,
                    device_id, encryption_state, trust_level, expected_availability,
                    is_writable, status, created_event_id, last_event_id
                 ) VALUES
                    ('location_worktree_two', 'Worktree two', 'filesystem', 'root_fixture_two',
                     x'2e', 'utf8', '.', 'device_fixture_two', 'unknown', 'trusted',
                     'online', 0, 'active', 'seed', 'seed'),
                    ('location_cas_two', 'CAS two', 'filesystem', 'root_fixture_two',
                     x'2e6769742f616e6e65782f6f626a65637473', 'utf8', '.git/annex/objects',
                     'device_fixture_two', 'unknown', 'trusted', 'online', 0, 'active',
                     'seed', 'seed');",
            )
            .unwrap();
    }

    #[cfg(unix)]
    fn tree_fingerprint(root: &Path) -> String {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fn visit(root: &Path, current: &Path, rows: &mut BTreeMap<Vec<u8>, Vec<u8>>) {
            let mut entries: Vec<_> = fs::read_dir(current)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let mut value = Vec::new();
                value.extend_from_slice(&metadata.permissions().mode().to_le_bytes());
                if metadata.file_type().is_symlink() {
                    value.extend_from_slice(b"link\0");
                    value.extend_from_slice(fs::read_link(&path).unwrap().as_os_str().as_bytes());
                } else if metadata.is_file() {
                    value.extend_from_slice(b"file\0");
                    value.extend_from_slice(&fs::read(&path).unwrap());
                } else if metadata.is_dir() {
                    value.extend_from_slice(b"dir\0");
                } else {
                    value.extend_from_slice(b"special\0");
                    value.extend_from_slice(&metadata.rdev().to_le_bytes());
                }
                rows.insert(relative.as_os_str().as_bytes().to_vec(), value);
                if metadata.is_dir() {
                    visit(root, &path, rows);
                }
            }
        }

        let mut rows = BTreeMap::new();
        visit(root, root, &mut rows);
        let mut hasher = blake3::Hasher::new();
        for (path, value) in rows {
            hasher.update(&(path.len() as u64).to_le_bytes());
            hasher.update(&path);
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(&value);
        }
        hasher.finalize().to_hex().to_string()
    }
}
