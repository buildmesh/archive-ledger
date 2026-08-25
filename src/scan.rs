//! Bounded, read-only filesystem scans with fail-closed coverage semantics.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use ulid::Ulid;

use crate::discovery::{
    encode_relative_path, modified_time_ms, DiscoveredFile, DiscoveryError, DiscoveryItem,
    EncodedPath, FileDiscovery, PathEncoding,
};
use crate::event_store::{EventReferences, EventRequest, EventStore, EventStoreError};
use crate::projection::{
    ProjectionDb, ProjectionError, ScanKnownEntry, ScanProjectionSession, ScanSeenPath,
};

const COVERAGE_VERSION: u64 = 1;
const TRAVERSAL_VERSION: u64 = 3;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

pub type Result<T> = std::result::Result<T, ScanError>;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error(transparent)]
    EventStore(#[from] EventStoreError),

    #[error(transparent)]
    Projection(#[from] ProjectionError),

    #[error(transparent)]
    Discovery(#[from] DiscoveryError),

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid scan configuration: {0}")]
    InvalidConfig(String),

    #[error("device fingerprint mismatch; scan refused")]
    DeviceMismatch,

    #[error("lossless scan paths are unavailable on this platform")]
    UnsupportedPlatform,
}

impl ScanError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EventStore(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Discovery(error) => error.code(),
            Self::Io { .. } => "scan_io",
            Self::InvalidConfig(_) => "scan_invalid_config",
            Self::DeviceMismatch => "scan_device_mismatch",
            Self::UnsupportedPlatform => "scan_platform_unsupported",
        }
    }
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> ScanError {
    ScanError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub root_path: PathBuf,
    pub scan_id: String,
    pub job_id: String,
    pub collection_id: String,
    pub location_id: String,
    pub device_id: String,
    pub archive_root_id: String,
    /// Location-relative prefix of `root_path`, used by positive-only add runs.
    pub location_prefix: Option<PathBuf>,
    pub logical_prefix: Option<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub fingerprint_status: String,
    pub batch_entries: usize,
    pub scan_mode: ScanMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Record only files that are present. Never infer that an unseen file is missing.
    Add,
    /// Reconcile the complete declared scope, including safe missing-file detection.
    Complete,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Complete => "complete",
        }
    }
}

impl ScanConfig {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("scan_id", &self.scan_id),
            ("job_id", &self.job_id),
            ("collection_id", &self.collection_id),
            ("location_id", &self.location_id),
            ("device_id", &self.device_id),
            ("archive_root_id", &self.archive_root_id),
        ] {
            if value.is_empty() {
                return Err(ScanError::InvalidConfig(format!(
                    "{name} must be non-empty"
                )));
            }
        }
        if self.batch_entries == 0 {
            return Err(ScanError::InvalidConfig(
                "batch_entries must be greater than zero".to_owned(),
            ));
        }
        if !matches!(
            self.fingerprint_status.as_str(),
            "match" | "unavailable" | "mismatch"
        ) {
            return Err(ScanError::InvalidConfig(
                "fingerprint_status must be match, unavailable, or mismatch".to_owned(),
            ));
        }
        if let Some(prefix) = &self.logical_prefix {
            validate_relative_path("logical_prefix", prefix)?;
        }
        if let Some(prefix) = &self.location_prefix {
            validate_relative_path("location_prefix", prefix)?;
            if self.scan_mode != ScanMode::Add {
                return Err(ScanError::InvalidConfig(
                    "location_prefix is supported only for positive-only add runs".to_owned(),
                ));
            }
        }
        for exclusion in &self.exclusions {
            validate_relative_path("exclusion", exclusion)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Complete,
    Partial,
    Interrupted,
    Cancelled,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSummary {
    pub files_seen: u64,
    pub bytes_seen: u64,
    pub new_paths: u64,
    pub changed_paths: u64,
    pub unchanged_paths: u64,
    /// Logical files whose content was successfully hashed during this scan.
    #[serde(default)]
    pub integrity_verified_paths: u64,
    pub missing_paths: u64,
    pub symlinks: u64,
    pub special_files: u64,
    pub excluded_subtrees: u64,
    /// Symlinks ignored because they are not registered git-annex representations.
    #[serde(default)]
    pub ignored_symlinks: u64,
    pub filesystem_boundaries: u64,
    pub traversal_errors: u64,
    pub content_read_errors: u64,
    pub concurrent_changes: u64,
}

impl ScanSummary {
    fn error_count(&self) -> u64 {
        self.traversal_errors
            .saturating_add(self.content_read_errors)
            .saturating_add(self.concurrent_changes)
    }

    fn error_summary(&self) -> Value {
        json!({
            "traversal_errors": self.traversal_errors,
            "content_read_errors": self.content_read_errors,
            "concurrent_changes": self.concurrent_changes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub status: ScanStatus,
    pub summary: ScanSummary,
}

pub struct LocationScanner<'a> {
    store: &'a EventStore,
    projection: &'a ProjectionDb,
    config: ScanConfig,
    logical_prefix: Option<EncodedPath>,
    location_prefix: Option<EncodedPath>,
    scope_json: Value,
    exclusions_json: Value,
    exclusions_json_text: String,
    exclusions_hash: String,
    imported_annex: bool,
}

struct ScanEventSpool {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    batches: u64,
}

impl ScanEventSpool {
    fn create(database_path: &Path) -> Result<Self> {
        let parent = database_path.parent().unwrap_or_else(|| Path::new("."));
        let path = parent.join(format!(
            ".archive-ledger-scan-{}.jsonl.tmp",
            Ulid::new().to_string().to_ascii_lowercase()
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .map_err(|source| io_error("create scan event spool", &path, source))?;
        Ok(Self {
            path,
            writer: Some(BufWriter::new(file)),
            batches: 0,
        })
    }

    fn write_batch(&mut self, events: &[EventRequest]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let writer = self.writer.as_mut().ok_or_else(|| {
            ScanError::InvalidConfig("scan event spool is already finalized".to_owned())
        })?;
        serde_json::to_writer(&mut *writer, events).map_err(|error| {
            ScanError::InvalidConfig(format!("serialize scan event spool: {error}"))
        })?;
        writer
            .write_all(b"\n")
            .map_err(|source| io_error("write scan event spool", &self.path, source))?;
        self.batches += 1;
        Ok(())
    }

    fn publish(&mut self, store: &EventStore) -> Result<()> {
        let Some(mut writer) = self.writer.take() else {
            return Err(ScanError::InvalidConfig(
                "scan event spool was already published".to_owned(),
            ));
        };
        writer
            .flush()
            .map_err(|source| io_error("flush scan event spool", &self.path, source))?;
        drop(writer);
        if self.batches == 0 {
            return Ok(());
        }

        self.validate()?;
        let reader = File::open(&self.path)
            .map(BufReader::new)
            .map_err(|source| io_error("open scan event spool", &self.path, source))?;
        let mut lines = reader.lines();
        let mut spool_error = None;
        let batches = std::iter::from_fn(|| match lines.next() {
            Some(Ok(line)) => match serde_json::from_str::<Vec<EventRequest>>(&line) {
                Ok(events) => Some(events),
                Err(error) => {
                    spool_error = Some(ScanError::InvalidConfig(format!(
                        "parse scan event spool: {error}"
                    )));
                    None
                }
            },
            Some(Err(source)) => {
                spool_error = Some(io_error("read scan event spool", &self.path, source));
                None
            }
            None => None,
        });
        store.append_batches(batches)?;
        if let Some(error) = spool_error {
            return Err(error);
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let reader = File::open(&self.path)
            .map(BufReader::new)
            .map_err(|source| io_error("open scan event spool", &self.path, source))?;
        let mut batches = 0_u64;
        for line in reader.lines() {
            let line =
                line.map_err(|source| io_error("read scan event spool", &self.path, source))?;
            let events = serde_json::from_str::<Vec<EventRequest>>(&line).map_err(|error| {
                ScanError::InvalidConfig(format!("parse scan event spool: {error}"))
            })?;
            if events.is_empty() {
                return Err(ScanError::InvalidConfig(
                    "scan event spool contains an empty batch".to_owned(),
                ));
            }
            batches += 1;
        }
        if batches != self.batches {
            return Err(ScanError::InvalidConfig(format!(
                "scan event spool contains {batches} batches, expected {}",
                self.batches
            )));
        }
        Ok(())
    }
}

impl Drop for ScanEventSpool {
    fn drop(&mut self) {
        drop(self.writer.take());
        let _ = fs::remove_file(&self.path);
    }
}

impl<'a> LocationScanner<'a> {
    pub fn new(
        store: &'a EventStore,
        projection: &'a ProjectionDb,
        mut config: ScanConfig,
    ) -> Result<Self> {
        config.validate()?;
        config.root_path = fs::canonicalize(&config.root_path)
            .map_err(|source| io_error("canonicalize scan root", &config.root_path, source))?;
        projection.validate_scan_topology(
            &config.collection_id,
            &config.location_id,
            &config.device_id,
            &config.archive_root_id,
        )?;
        let imported_annex = projection
            .location_has_completed_annex_import(&config.collection_id, &config.location_id)?;

        config.exclusions.sort();
        config.exclusions.dedup();
        let logical_prefix = config
            .logical_prefix
            .as_ref()
            .map(|path| encode_relative_path(path));
        let location_prefix = config
            .location_prefix
            .as_ref()
            .map(|path| encode_relative_path(path));
        let exclusions: Vec<_> = config
            .exclusions
            .iter()
            .map(|path| encode_relative_path(path))
            .collect();
        let scope_json = json!({
            "version": COVERAGE_VERSION,
            "scan_mode": config.scan_mode.as_str(),
            "resolved_root_path": path_json(&encode_absolute_path(&config.root_path)),
            "root_filesystem_identity": root_filesystem_identity(&config.root_path)?,
            "logical_prefix": logical_prefix.as_ref().map(path_json),
            "location_prefix": location_prefix.as_ref().map(path_json),
            "filesystem_boundary": "same_device",
            "traversal_version": TRAVERSAL_VERSION,
            "source_mode": if imported_annex {
                "imported_annex_direct_filesystem"
            } else {
                "ordinary_filesystem"
            },
            "source_stability": if config.scan_mode == ScanMode::Complete {
                if imported_annex {
                    "double_metadata_enumeration_with_validated_annex_targets"
                } else {
                    "double_metadata_enumeration"
                }
            } else {
                "positive_observations_only"
            },
        });
        let exclusions_json = Value::Array(
            exclusions
                .iter()
                .map(|path| {
                    json!({
                        "encoding": path.encoding.as_str(),
                        "hex": uppercase_hex(&path.bytes),
                        "display": path.display,
                    })
                })
                .collect(),
        );
        let exclusions_json_text = serde_json::to_string(&exclusions_json)
            .map_err(|error| ScanError::InvalidConfig(error.to_string()))?;
        let exclusions_hash = blake3::hash(exclusions_json_text.as_bytes())
            .to_hex()
            .to_string();
        Ok(Self {
            store,
            projection,
            config,
            logical_prefix,
            location_prefix,
            scope_json,
            exclusions_json,
            exclusions_json_text,
            exclusions_hash,
            imported_annex,
        })
    }

    pub fn run(&self) -> Result<ScanResult> {
        self.run_at_most(None)
    }

    /// Finalizes an already-started scan without activating negative findings
    /// or refreshing complete coverage.
    pub fn cancel(&self) -> Result<ScanResult> {
        self.projection.apply(self.store)?;
        let scope_text = serde_json::to_string(&self.scope_json)
            .map_err(|error| ScanError::InvalidConfig(error.to_string()))?;
        self.projection.ensure_scan_scope_available(
            &self.config.scan_id,
            &self.config.job_id,
            &self.config.location_id,
            &self.config.collection_id,
            &scope_text,
            &self.exclusions_hash,
        )?;
        if self
            .projection
            .scan_run_status(&self.config.scan_id)?
            .as_deref()
            != Some("running")
        {
            return Err(ScanError::InvalidConfig(format!(
                "scan {} is not running",
                self.config.scan_id
            )));
        }
        let summary = ScanSummary::default();
        self.complete_scan("cancelled", &summary, None)?;
        Ok(ScanResult {
            status: ScanStatus::Cancelled,
            summary,
        })
    }

    /// Stops cleanly after `limit` regular files. Re-running the same scan/job
    /// safely resumes through deterministic outcomes and local seen-path state.
    pub fn run_at_most(&self, limit: Option<usize>) -> Result<ScanResult> {
        self.projection.apply(self.store)?;
        if self.config.fingerprint_status == "mismatch" {
            let event = self.device_checked_in_event();
            if !self.projection.has_operation_key(operation_key(&event)?)? {
                self.store.append(event)?;
            }
            self.projection.apply(self.store)?;
            return Err(ScanError::DeviceMismatch);
        }
        let scope_text = serde_json::to_string(&self.scope_json)
            .map_err(|error| ScanError::InvalidConfig(error.to_string()))?;
        self.projection.ensure_scan_scope_available(
            &self.config.scan_id,
            &self.config.job_id,
            &self.config.location_id,
            &self.config.collection_id,
            &scope_text,
            &self.exclusions_hash,
        )?;

        let beginnings = [self.device_checked_in_event(), self.scan_started_event()];
        let mut pending_beginnings = Vec::new();
        for event in beginnings {
            if !self.projection.has_operation_key(operation_key(&event)?)? {
                pending_beginnings.push(event);
            }
        }
        if !pending_beginnings.is_empty() {
            self.store.append_batch(pending_beginnings)?;
        }
        self.projection.apply(self.store)?;
        if self
            .projection
            .scan_run_status(&self.config.scan_id)?
            .as_deref()
            != Some("running")
        {
            return Err(ScanError::InvalidConfig(format!(
                "scan {} is already finalized",
                self.config.scan_id
            )));
        }
        let now = now_utc_ms()?;
        let params_json = serde_json::to_string(&json!({
            "scan_id": self.config.scan_id,
            "scan_mode": self.config.scan_mode.as_str(),
            "root_path": self.config.root_path.to_string_lossy(),
            "collection_id": self.config.collection_id,
            "location_id": self.config.location_id,
            "device_id": self.config.device_id,
            "archive_root_id": self.config.archive_root_id,
            "location_prefix": self.config.location_prefix.as_ref().map(|path| path.to_string_lossy()),
            "logical_prefix": self.config.logical_prefix.as_ref().map(|path| path.to_string_lossy()),
            "exclusion_paths": self.config.exclusions.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
            "fingerprint_status": self.config.fingerprint_status,
            "batch_entries": self.config.batch_entries,
            "scope": self.scope_json,
            "exclusions": self.exclusions_json,
        }))
        .map_err(|error| ScanError::InvalidConfig(error.to_string()))?;
        self.projection.prepare_scan_job(
            &self.config.job_id,
            &self.config.scan_id,
            &params_json,
            now,
        )?;
        self.projection.clear_scan_seen(&self.config.job_id)?;

        let mut discovery = match FileDiscovery::with_exclusions(
            &self.config.root_path,
            self.config.exclusions.clone(),
        ) {
            Ok(discovery) => discovery,
            Err(_) => {
                let summary = ScanSummary {
                    traversal_errors: 1,
                    ..ScanSummary::default()
                };
                self.complete_scan("partial", &summary, None)?;
                return Ok(ScanResult {
                    status: ScanStatus::Partial,
                    summary,
                });
            }
        };
        let mut spool = ScanEventSpool::create(self.projection.path())?;
        let mut session = self.projection.open_scan_session()?;
        let mut summary = ScanSummary::default();
        let mut pending_events = Vec::new();
        let mut pending_seen = Vec::new();
        let mut processed_files = 0_usize;
        let mut coverage_partial = false;
        let mut annex_namespace = AnnexNamespaceAccumulator::default();

        for item in discovery.by_ref() {
            match item {
                DiscoveryItem::File(file) => {
                    if limit.is_some_and(|limit| processed_files >= limit) {
                        self.flush_to_spool(
                            &mut spool,
                            &mut session,
                            &mut pending_events,
                            &mut pending_seen,
                        )?;
                        drop(session);
                        spool.publish(self.store)?;
                        self.projection.apply(self.store)?;
                        let (new_paths, changed_paths, integrity_verified_paths) = self
                            .projection
                            .scan_observation_counts(&self.config.scan_id)?;
                        summary.new_paths = new_paths;
                        summary.changed_paths = changed_paths;
                        summary.integrity_verified_paths = integrity_verified_paths;
                        return Ok(ScanResult {
                            status: ScanStatus::Interrupted,
                            summary,
                        });
                    }
                    processed_files += 1;
                    summary.files_seen += 1;
                    let location_path = self.location_path(&file.relative_path)?;
                    let known = session.known_entry(
                        &self.config.scan_id,
                        &self.config.collection_id,
                        &self.config.location_id,
                        &location_path,
                    )?;
                    if known
                        .as_ref()
                        .is_some_and(|known| self.is_imported_annex_entry(known))
                    {
                        let known = known.as_ref().expect("checked above");
                        let result =
                            self.events_for_imported_annex_regular(&session, &file, known)?;
                        coverage_partial |= apply_imported_annex_events(
                            result,
                            known.observed_by_current_scan,
                            &mut summary,
                            &mut pending_events,
                            &mut pending_seen,
                        );
                    } else {
                        summary.bytes_seen = summary.bytes_seen.saturating_add(file.size_bytes);
                        let unchanged = known.as_ref().is_some_and(|known| {
                            !known.has_effective_missing_candidate
                                && known.path_state == "present"
                                && known.copy_state.as_deref().is_some_and(|state| {
                                    matches!(state, "present" | "corrupt" | "unknown")
                                })
                                && known.size_bytes == Some(file.size_bytes)
                                && known.modified_time_utc_ms == file.modified_time_utc_ms
                        });
                        if unchanged {
                            let known = known.expect("checked above");
                            if !known.observed_by_current_scan {
                                summary.unchanged_paths += 1;
                            }
                            pending_seen.push(seen_path(&location_path, &known));
                        } else {
                            match self.events_for_file(&file, known.as_ref())? {
                                FileEvents::Stable {
                                    events,
                                    seen,
                                    changed,
                                } => {
                                    if changed {
                                        summary.changed_paths += 1;
                                    } else {
                                        summary.new_paths += 1;
                                    }
                                    pending_events.extend(events);
                                    pending_seen.push(seen);
                                }
                                FileEvents::ReadError { events, seen } => {
                                    summary.content_read_errors += 1;
                                    if known.is_some() {
                                        summary.changed_paths += 1;
                                    } else {
                                        summary.new_paths += 1;
                                    }
                                    pending_events.extend(events);
                                    pending_seen.push(seen);
                                }
                                FileEvents::ChangedDuringRead => {
                                    summary.concurrent_changes += 1;
                                    coverage_partial = true;
                                }
                            }
                        }
                    }
                }
                DiscoveryItem::Symlink(relative_path) => {
                    summary.symlinks += 1;
                    let mut handled_as_annex = false;
                    if self.imported_annex {
                        let location_path = self.location_path(&relative_path)?;
                        let known = session.known_entry(
                            &self.config.scan_id,
                            &self.config.collection_id,
                            &self.config.location_id,
                            &location_path,
                        )?;
                        if let Some(known) = known
                            .as_ref()
                            .filter(|known| self.is_imported_annex_entry(known))
                        {
                            handled_as_annex = true;
                            if limit.is_some_and(|limit| processed_files >= limit) {
                                self.flush_to_spool(
                                    &mut spool,
                                    &mut session,
                                    &mut pending_events,
                                    &mut pending_seen,
                                )?;
                                drop(session);
                                spool.publish(self.store)?;
                                self.projection.apply(self.store)?;
                                return Ok(ScanResult {
                                    status: ScanStatus::Interrupted,
                                    summary,
                                });
                            }
                            processed_files += 1;
                            summary.files_seen += 1;
                            let inspection = self.inspect_imported_annex_symlink(&relative_path)?;
                            let (result, fingerprint) = self.events_for_imported_annex_symlink(
                                &session,
                                &relative_path,
                                known,
                                inspection,
                            )?;
                            annex_namespace.record(&fingerprint);
                            coverage_partial |= apply_imported_annex_events(
                                result,
                                known.observed_by_current_scan,
                                &mut summary,
                                &mut pending_events,
                                &mut pending_seen,
                            );
                        }
                    }
                    if !handled_as_annex {
                        summary.ignored_symlinks += 1;
                    }
                }
                DiscoveryItem::Special(_) => summary.special_files += 1,
                DiscoveryItem::Excluded(_) => summary.excluded_subtrees += 1,
                DiscoveryItem::FilesystemBoundary(_) => summary.filesystem_boundaries += 1,
                DiscoveryItem::ConcurrentChange(_) => {
                    summary.concurrent_changes += 1;
                    coverage_partial = true;
                }
                DiscoveryItem::Error { .. } => {
                    summary.traversal_errors += 1;
                    coverage_partial = true;
                }
            }
            if pending_seen.len() >= self.config.batch_entries {
                self.flush_to_spool(
                    &mut spool,
                    &mut session,
                    &mut pending_events,
                    &mut pending_seen,
                )?;
            }
        }
        let first_namespace = discovery.namespace_fingerprint();
        let first_annex_namespace = annex_namespace.finish();
        self.flush_to_spool(
            &mut spool,
            &mut session,
            &mut pending_events,
            &mut pending_seen,
        )?;
        drop(session);
        spool.publish(self.store)?;
        self.projection.apply(self.store)?;

        let (new_paths, changed_paths, integrity_verified_paths) = self
            .projection
            .scan_observation_counts(&self.config.scan_id)?;
        summary.new_paths = new_paths;
        summary.changed_paths = changed_paths;
        summary.integrity_verified_paths = integrity_verified_paths;

        if coverage_partial {
            self.complete_scan("partial", &summary, None)?;
            return Ok(ScanResult {
                status: ScanStatus::Partial,
                summary,
            });
        }

        // An add run proves only positive observations. Finalize it before
        // candidate generation and complete-coverage confirmation so absence
        // from an add traversal can never become a missing claim.
        if self.config.scan_mode == ScanMode::Add {
            let status = self.complete_scan("complete", &summary, None)?;
            return Ok(ScanResult { status, summary });
        }

        self.generate_missing_candidates()?;
        let manifest = self
            .projection
            .scan_completion_manifest(&self.config.scan_id)?;
        self.projection.preflight_scan_completion(&manifest)?;

        // This confirmation is deliberately after candidate generation. A
        // file that reappears while negatives or their manifest are being
        // staged must make the candidates inert rather than being committed.
        coverage_partial |=
            self.confirm_source_unchanged(first_namespace, first_annex_namespace, &mut summary)?;
        if coverage_partial {
            self.complete_scan("partial", &summary, None)?;
            return Ok(ScanResult {
                status: ScanStatus::Partial,
                summary,
            });
        }

        summary.missing_paths = manifest.missing_path_count;
        let status = self.complete_scan("complete", &summary, Some(&manifest))?;
        if status == ScanStatus::Partial {
            summary.concurrent_changes += 1;
        }
        Ok(ScanResult { status, summary })
    }

    fn generate_missing_candidates(&self) -> Result<()> {
        let first_targets = self.projection.scan_missing_targets_after(
            &self.config.scan_id,
            &self.config.job_id,
            &self.config.collection_id,
            &self.config.location_id,
            &self.exclusions_json_text,
            None,
            self.config.batch_entries,
        )?;
        if first_targets.is_empty() {
            return Ok(());
        }
        let mut cursor = first_targets.last().map(|target| target.cursor());
        let first_events = first_targets
            .into_iter()
            .map(|target| self.missing_candidate_event(&target))
            .collect::<Vec<_>>();
        let mut generation_error = None;
        let following = std::iter::from_fn(|| {
            let targets = match self.projection.scan_missing_targets_after(
                &self.config.scan_id,
                &self.config.job_id,
                &self.config.collection_id,
                &self.config.location_id,
                &self.exclusions_json_text,
                cursor.as_ref(),
                self.config.batch_entries,
            ) {
                Ok(targets) => targets,
                Err(error) => {
                    generation_error = Some(ScanError::Projection(error));
                    return None;
                }
            };
            if targets.is_empty() {
                return None;
            }
            cursor = targets.last().map(|target| target.cursor());
            Some(
                targets
                    .into_iter()
                    .map(|target| self.missing_candidate_event(&target))
                    .collect::<Vec<_>>(),
            )
        });
        self.store
            .append_batches(std::iter::once(first_events).chain(following))?;
        if let Some(error) = generation_error {
            return Err(error);
        }
        self.projection.apply(self.store)?;
        Ok(())
    }

    fn confirm_source_unchanged(
        &self,
        first_namespace: crate::discovery::NamespaceFingerprint,
        first_annex_namespace: AnnexNamespaceFingerprint,
        summary: &mut ScanSummary,
    ) -> Result<bool> {
        let mut coverage_partial = false;
        if self
            .projection
            .scan_has_interleaved_events(&self.config.scan_id)?
        {
            summary.concurrent_changes += 1;
            coverage_partial = true;
        }
        let session = self.projection.open_scan_session()?;
        let mut annex_namespace = AnnexNamespaceAccumulator::default();
        match FileDiscovery::with_exclusions(&self.config.root_path, self.config.exclusions.clone())
        {
            Ok(mut confirmation) => {
                for item in confirmation.by_ref() {
                    match item {
                        DiscoveryItem::Symlink(relative_path) if self.imported_annex => {
                            let location_path = self.location_path(&relative_path)?;
                            let known = session.known_entry(
                                &self.config.scan_id,
                                &self.config.collection_id,
                                &self.config.location_id,
                                &location_path,
                            )?;
                            if known
                                .as_ref()
                                .is_some_and(|known| self.is_imported_annex_entry(known))
                            {
                                let inspection =
                                    self.inspect_imported_annex_symlink(&relative_path)?;
                                annex_namespace.record(&inspection.fingerprint);
                            }
                        }
                        DiscoveryItem::Error { .. } => {
                            summary.traversal_errors += 1;
                            coverage_partial = true;
                        }
                        DiscoveryItem::ConcurrentChange(_) => {
                            summary.concurrent_changes += 1;
                            coverage_partial = true;
                        }
                        _ => {}
                    }
                }
                if confirmation.namespace_fingerprint() != first_namespace {
                    summary.concurrent_changes += 1;
                    coverage_partial = true;
                }
                if annex_namespace.finish() != first_annex_namespace {
                    summary.concurrent_changes += 1;
                    coverage_partial = true;
                }
            }
            Err(_) => {
                summary.traversal_errors += 1;
                coverage_partial = true;
            }
        }
        Ok(coverage_partial)
    }

    fn flush_to_spool(
        &self,
        spool: &mut ScanEventSpool,
        session: &mut ScanProjectionSession,
        events: &mut Vec<EventRequest>,
        seen: &mut Vec<ScanSeenPath>,
    ) -> Result<()> {
        if !events.is_empty() {
            let events = std::mem::take(events);
            spool.write_batch(&events)?;
        }
        session.mark_seen(&self.config.job_id, seen, now_utc_ms()?)?;
        seen.clear();
        Ok(())
    }

    fn events_for_file(
        &self,
        file: &DiscoveredFile,
        known: Option<&ScanKnownEntry>,
    ) -> Result<FileEvents> {
        let absolute = self
            .config
            .root_path
            .join(raw_relative_path(&file.relative_path)?);
        let logical_path = self.logical_path(&file.relative_path)?;
        let location_path = self.location_path(&file.relative_path)?;
        let file_ref_id = known
            .map(|entry| entry.file_ref_id.clone())
            .unwrap_or_else(|| {
                stable_id(
                    "file",
                    &[
                        self.config.collection_id.as_bytes(),
                        logical_path.encoding.as_str().as_bytes(),
                        &logical_path.bytes,
                    ],
                )
            });
        let copy_claim_id = known
            .and_then(|entry| entry.copy_claim_id.clone())
            .unwrap_or_else(|| {
                stable_id(
                    "copy",
                    &[
                        self.config.location_id.as_bytes(),
                        location_path.encoding.as_str().as_bytes(),
                        &location_path.bytes,
                    ],
                )
            });
        let item_key = scan_item_key(&location_path);
        match hash_file_stable(&absolute, file) {
            HashOutcome::Stable(content) => {
                let object_id = format!("obj_blake3_{}", content.blake3_hex);
                let events = self.positive_events(
                    file,
                    &logical_path,
                    &location_path,
                    &file_ref_id,
                    &copy_claim_id,
                    Some(&object_id),
                    Some(&content),
                    None,
                );
                Ok(FileEvents::Stable {
                    events,
                    seen: ScanSeenPath {
                        item_key,
                        path: location_path,
                        file_ref_id: Some(file_ref_id),
                        copy_claim_id: Some(copy_claim_id),
                    },
                    changed: known.is_some(),
                })
            }
            HashOutcome::ReadError { bytes_read, detail } => {
                let events = self.positive_events(
                    file,
                    &logical_path,
                    &location_path,
                    &file_ref_id,
                    &copy_claim_id,
                    None,
                    None,
                    Some((bytes_read, detail)),
                );
                Ok(FileEvents::ReadError {
                    events,
                    seen: ScanSeenPath {
                        item_key,
                        path: location_path,
                        file_ref_id: Some(file_ref_id),
                        copy_claim_id: Some(copy_claim_id),
                    },
                })
            }
            HashOutcome::Changed => Ok(FileEvents::ChangedDuringRead),
        }
    }

    fn is_imported_annex_entry(&self, known: &ScanKnownEntry) -> bool {
        self.imported_annex
            && known.external_identity_id.is_some()
            && (known.representation.starts_with("annex_")
                || known.representation == "missing_worktree_entry")
    }

    fn events_for_imported_annex_regular(
        &self,
        session: &ScanProjectionSession,
        file: &DiscoveredFile,
        known: &ScanKnownEntry,
    ) -> Result<ImportedAnnexEvents> {
        let absolute = self
            .config
            .root_path
            .join(raw_relative_path(&file.relative_path)?);
        let location_path = self.location_path(&file.relative_path)?;
        if file.size_bytes <= 32 * 1024 {
            if let Some(key) = known.external_key.as_deref() {
                match is_annex_pointer_file(&absolute, key) {
                    Ok(true) => {
                        return Ok(self.imported_annex_absent_events(
                            known,
                            &location_path,
                            "annex_pointer_file",
                        ));
                    }
                    Ok(false) => {}
                    Err(error) => {
                        return Ok(self.imported_annex_read_error_events(
                            known,
                            &location_path,
                            "annex_unreadable",
                            None,
                            error.to_string(),
                        ));
                    }
                }
            }
        }
        self.events_for_imported_annex_content(
            session,
            file,
            &absolute,
            &location_path,
            &location_path,
            None,
            "annex_unlocked_file",
            known,
        )
    }

    fn events_for_imported_annex_symlink(
        &self,
        session: &ScanProjectionSession,
        relative_path: &EncodedPath,
        known: &ScanKnownEntry,
        inspection: AnnexSymlinkInspection,
    ) -> Result<(ImportedAnnexEvents, [u8; 32])> {
        let location_path = self.location_path(relative_path)?;
        let events = match inspection.state {
            AnnexSymlinkState::Present {
                content_path,
                copy_path,
                legacy_copy_path,
                file,
            } => self.events_for_imported_annex_content(
                session,
                &file,
                &content_path,
                &location_path,
                &copy_path,
                Some(&legacy_copy_path),
                "annex_locked_symlink",
                known,
            )?,
            AnnexSymlinkState::Absent => {
                self.imported_annex_absent_events(known, &location_path, "annex_locked_symlink")
            }
            AnnexSymlinkState::Unsafe(detail) | AnnexSymlinkState::ReadError(detail) => self
                .imported_annex_read_error_events(
                    known,
                    &location_path,
                    "annex_unreadable",
                    None,
                    detail,
                ),
        };
        Ok((events, inspection.fingerprint))
    }

    #[allow(clippy::too_many_arguments)]
    fn events_for_imported_annex_content(
        &self,
        session: &ScanProjectionSession,
        file: &DiscoveredFile,
        content_path: &Path,
        location_path: &EncodedPath,
        copy_path: &EncodedPath,
        legacy_copy_path: Option<&EncodedPath>,
        representation: &str,
        known: &ScanKnownEntry,
    ) -> Result<ImportedAnnexEvents> {
        if known.expected_hash_algo.as_deref() != Some("sha256")
            || known.expected_hash_hex.is_none()
        {
            let mut events = vec![self.imported_annex_path_event(
                known,
                location_path,
                representation,
                None,
                Some(file),
            )];
            events.extend(self.imported_annex_availability_event(known, location_path, "present"));
            return Ok(ImportedAnnexEvents::Observed {
                events,
                seen: vec![ScanSeenPath {
                    item_key: scan_item_key(location_path),
                    path: location_path.clone(),
                    file_ref_id: Some(known.file_ref_id.clone()),
                    copy_claim_id: None,
                }],
                size_bytes: file.size_bytes,
                changed: false,
            });
        }
        let known_copy =
            session.known_copy(&self.config.scan_id, &self.config.location_id, copy_path)?;
        let legacy_copy = if known_copy.is_none() {
            legacy_copy_path
                .map(|path| {
                    session.known_copy(&self.config.scan_id, &self.config.location_id, path)
                })
                .transpose()?
                .flatten()
        } else {
            None
        };
        let unchanged = known_copy.as_ref().is_some_and(|copy| {
            !known.has_effective_missing_candidate
                && !copy.has_effective_missing_candidate
                && known.path_state == "present"
                && copy.state == "present"
                && known.size_bytes == Some(file.size_bytes)
                && known.modified_time_utc_ms == file.modified_time_utc_ms
                && copy.external_identity_id == known.external_identity_id
                && copy.object_id == known.resolved_object_id
        });
        if unchanged {
            let copy = known_copy.expect("checked above");
            let events = self
                .imported_annex_availability_event(known, location_path, "present")
                .into_iter()
                .collect();
            return Ok(ImportedAnnexEvents::Observed {
                events,
                seen: annex_seen_paths(location_path, known, copy_path, &copy.copy_claim_id),
                size_bytes: file.size_bytes,
                changed: false,
            });
        }

        match hash_annex_file_stable(content_path, file) {
            AnnexHashOutcome::Stable(content) => {
                let expected_matches = known.expected_hash_algo.as_deref() == Some("sha256")
                    && known.expected_hash_hex.as_deref() == Some(content.sha256_hex.as_str())
                    && known
                        .expected_size_bytes
                        .is_none_or(|size| size == content.size_bytes);
                let computed_object_id = format!("obj_blake3_{}", content.blake3_hex);
                let identity_matches = expected_matches
                    && known
                        .resolved_object_id
                        .as_deref()
                        .is_none_or(|object_id| object_id == computed_object_id);
                let copy_claim_id = known_copy
                    .as_ref()
                    .map(|copy| copy.copy_claim_id.clone())
                    .unwrap_or_else(|| {
                        stable_id(
                            "copy",
                            &[
                                self.config.location_id.as_bytes(),
                                copy_path.encoding.as_str().as_bytes(),
                                &copy_path.bytes,
                            ],
                        )
                    });
                let mut events = self.imported_annex_content_events(
                    file,
                    location_path,
                    copy_path,
                    representation,
                    known,
                    &copy_claim_id,
                    &content,
                    identity_matches,
                    &computed_object_id,
                );
                if let (Some(legacy_path), Some(legacy_copy)) =
                    (legacy_copy_path, legacy_copy.as_ref())
                {
                    if legacy_copy.copy_claim_id != copy_claim_id {
                        events.push(self.imported_annex_superseded_copy_event(
                            known,
                            location_path,
                            legacy_path,
                            legacy_copy,
                        ));
                    }
                }
                Ok(ImportedAnnexEvents::Observed {
                    events,
                    seen: annex_seen_paths(location_path, known, copy_path, &copy_claim_id),
                    size_bytes: content.size_bytes,
                    changed: true,
                })
            }
            AnnexHashOutcome::ReadError { bytes_read, detail } => {
                let _ = bytes_read;
                Ok(self.imported_annex_read_error_events(
                    known,
                    location_path,
                    representation,
                    Some(copy_path),
                    detail,
                ))
            }
            AnnexHashOutcome::Changed => Ok(ImportedAnnexEvents::ChangedDuringRead),
        }
    }

    fn imported_annex_absent_events(
        &self,
        known: &ScanKnownEntry,
        location_path: &EncodedPath,
        representation: &str,
    ) -> ImportedAnnexEvents {
        let mut events = if known.path_state == "present" && known.representation == representation
        {
            Vec::new()
        } else {
            vec![self.imported_annex_path_event(known, location_path, representation, None, None)]
        };
        events.extend(self.imported_annex_availability_event(known, location_path, "missing"));
        ImportedAnnexEvents::Observed {
            events,
            seen: vec![ScanSeenPath {
                item_key: scan_item_key(location_path),
                path: location_path.clone(),
                file_ref_id: Some(known.file_ref_id.clone()),
                copy_claim_id: None,
            }],
            size_bytes: 0,
            changed: false,
        }
    }

    fn imported_annex_read_error_events(
        &self,
        known: &ScanKnownEntry,
        location_path: &EncodedPath,
        representation: &str,
        copy_path: Option<&EncodedPath>,
        detail: String,
    ) -> ImportedAnnexEvents {
        let mut events =
            vec![self.imported_annex_path_event(known, location_path, representation, None, None)];
        events.extend(self.imported_annex_availability_event(known, location_path, "unknown"));
        let mut seen = vec![ScanSeenPath {
            item_key: scan_item_key(location_path),
            path: location_path.clone(),
            file_ref_id: Some(known.file_ref_id.clone()),
            copy_claim_id: None,
        }];
        if let Some(copy_path) = copy_path {
            let copy_claim_id = stable_id(
                "copy",
                &[
                    self.config.location_id.as_bytes(),
                    copy_path.encoding.as_str().as_bytes(),
                    &copy_path.bytes,
                ],
            );
            events.extend(self.imported_annex_copy_events(
                known,
                location_path,
                copy_path,
                &copy_claim_id,
                None,
                None,
                "unknown",
                "read_error",
                None,
                Some(&detail),
            ));
            seen = annex_seen_paths(location_path, known, copy_path, &copy_claim_id);
        }
        ImportedAnnexEvents::ReadError { events, seen }
    }

    #[allow(clippy::too_many_arguments)]
    fn imported_annex_content_events(
        &self,
        file: &DiscoveredFile,
        location_path: &EncodedPath,
        copy_path: &EncodedPath,
        representation: &str,
        known: &ScanKnownEntry,
        copy_claim_id: &str,
        content: &AnnexHashedContent,
        identity_matches: bool,
        computed_object_id: &str,
    ) -> Vec<EventRequest> {
        let object_id = identity_matches.then_some(computed_object_id);
        let fields = EventFields::new(&self.config, location_path);
        let external_identity_id = known
            .external_identity_id
            .as_deref()
            .expect("annex scan entry has an external identity");
        let mut events = Vec::new();
        if let Some(object_id) = object_id {
            events.push(scan_event(
                "object_observed",
                json!({
                    "object_id": object_id,
                    "canonical_hash_algo": "blake3",
                    "canonical_hash_hex": content.blake3_hex,
                    "size_bytes": content.size_bytes,
                    "scan_id": self.config.scan_id,
                    "operation_key": fields.operation_key("annex_object"),
                    "job_type": "scan", "item_type": "object",
                    "item_key": object_id, "outcome_kind": "observed",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.to_owned()),
                    ..EventReferences::default()
                },
            ));
            events.push(scan_event(
                "object_hash_added",
                json!({
                    "object_id": object_id,
                    "hash_algo": "sha256",
                    "hash_hex": content.sha256_hex,
                    "source": "imported_annex_scan",
                    "scan_id": self.config.scan_id,
                    "operation_key": fields.operation_key("annex_object_hash"),
                    "job_type": "scan", "item_type": "object_hash",
                    "item_key": external_identity_id, "outcome_kind": "verified",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.to_owned()),
                    ..EventReferences::default()
                },
            ));
            events.push(scan_event(
                "external_identity_resolved",
                json!({
                    "external_identity_id": external_identity_id,
                    "object_id": object_id,
                    "scan_id": self.config.scan_id,
                    "operation_key": fields.operation_key("annex_identity_resolved"),
                    "job_type": "scan", "item_type": "external_identity",
                    "item_key": external_identity_id, "outcome_kind": "resolved",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.to_owned()),
                    file_ref_id: Some(known.file_ref_id.clone()),
                    ..EventReferences::default()
                },
            ));
        }
        events.push(scan_event(
            "file_ref_observed",
            json!({
                "file_ref_id": known.file_ref_id,
                "collection_id": self.config.collection_id,
                "logical_path": path_json(location_path),
                "object_id": object_id,
                "external_identity_id": external_identity_id,
                "identity_state": if identity_matches { "resolved" } else { "unresolved" },
                "path_state": "active",
                "observed_size_bytes": content.size_bytes,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("annex_file_ref"),
                "job_type": "scan", "item_type": "file_ref",
                "item_key": known.file_ref_id, "outcome_kind": "observed",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(known.file_ref_id.clone()),
                ..EventReferences::default()
            },
        ));
        events.push(self.imported_annex_path_event(
            known,
            location_path,
            representation,
            object_id,
            Some(file),
        ));
        events.extend(self.imported_annex_availability_event(known, location_path, "present"));
        events.extend(self.imported_annex_copy_events(
            known,
            location_path,
            copy_path,
            copy_claim_id,
            object_id,
            Some(content),
            if identity_matches {
                "present"
            } else {
                "corrupt"
            },
            if identity_matches {
                "ok"
            } else {
                "hash_mismatch"
            },
            (!identity_matches).then_some("annex_content_mismatch"),
            None,
        ));
        events
    }

    fn imported_annex_availability_event(
        &self,
        known: &ScanKnownEntry,
        location_path: &EncodedPath,
        state: &str,
    ) -> Option<EventRequest> {
        if state == "missing" && self.config.scan_mode == ScanMode::Add {
            return None;
        }
        if known.local_annex_availability_state.as_deref() == Some(state) {
            return None;
        }
        let source_repo_id = known.local_annex_repo_id.as_deref()?;
        let external_identity_id = known.external_identity_id.as_deref()?;
        let fields = EventFields::new(&self.config, location_path);
        Some(scan_event(
            "external_availability_observed",
            json!({
                "external_identity_id": external_identity_id,
                "source_repo_id": source_repo_id,
                "source_remote_id": source_repo_id,
                "state": state,
                "location_id": self.config.location_id,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("annex_availability"),
                "job_type": "scan", "item_type": "external_availability",
                "item_key": external_identity_id, "outcome_kind": state,
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                file_ref_id: Some(known.file_ref_id.clone()),
                location_id: Some(self.config.location_id.clone()),
                ..EventReferences::default()
            },
        ))
    }

    fn imported_annex_superseded_copy_event(
        &self,
        known: &ScanKnownEntry,
        location_path: &EncodedPath,
        legacy_copy_path: &EncodedPath,
        legacy_copy: &crate::projection::ScanKnownCopy,
    ) -> EventRequest {
        let fields = EventFields::new(&self.config, location_path);
        scan_event(
            "copy_observed",
            json!({
                "copy_claim_id": legacy_copy.copy_claim_id,
                "location_id": self.config.location_id,
                "relative_path": path_json(legacy_copy_path),
                "object_id": legacy_copy.object_id,
                "external_identity_id": legacy_copy.external_identity_id,
                "claim_basis": "observed_metadata",
                "state": "superseded",
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("annex_legacy_copy_superseded"),
                "job_type": "scan", "item_type": "copy",
                "item_key": legacy_copy.copy_claim_id, "outcome_kind": "superseded",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: legacy_copy.object_id.clone(),
                file_ref_id: Some(known.file_ref_id.clone()),
                copy_claim_id: Some(legacy_copy.copy_claim_id.clone()),
                location_id: Some(self.config.location_id.clone()),
                ..EventReferences::default()
            },
        )
    }

    fn imported_annex_path_event(
        &self,
        known: &ScanKnownEntry,
        location_path: &EncodedPath,
        representation: &str,
        object_id: Option<&str>,
        file: Option<&DiscoveredFile>,
    ) -> EventRequest {
        let fields = EventFields::new(&self.config, location_path);
        scan_event(
            "path_observed",
            json!({
                "file_ref_id": known.file_ref_id,
                "location_id": self.config.location_id,
                "observed_path": path_json(location_path),
                "representation": representation,
                "object_id": object_id,
                "external_identity_id": known.external_identity_id,
                "state": "present",
                "observed_size_bytes": file.map(|file| file.size_bytes),
                "modified_time_utc_ms": file.and_then(|file| file.modified_time_utc_ms),
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("annex_path"),
                "job_type": "scan", "item_type": "path",
                "item_key": known.file_ref_id, "outcome_kind": "present",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(known.file_ref_id.clone()),
                location_id: Some(self.config.location_id.clone()),
                ..EventReferences::default()
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn imported_annex_copy_events(
        &self,
        known: &ScanKnownEntry,
        location_path: &EncodedPath,
        copy_path: &EncodedPath,
        copy_claim_id: &str,
        object_id: Option<&str>,
        content: Option<&AnnexHashedContent>,
        copy_state: &str,
        verification_result: &str,
        error_code: Option<&str>,
        error_detail: Option<&str>,
    ) -> Vec<EventRequest> {
        let fields = EventFields::new(&self.config, location_path);
        let copy = scan_event(
            "copy_observed",
            json!({
                "copy_claim_id": copy_claim_id,
                "location_id": self.config.location_id,
                "relative_path": path_json(copy_path),
                "object_id": object_id,
                "external_identity_id": known.external_identity_id,
                "claim_basis": if object_id.is_some() { "observed_bytes" } else { "observed_metadata" },
                "state": copy_state,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("annex_copy"),
                "job_type": "scan", "item_type": "copy",
                "item_key": copy_claim_id, "outcome_kind": copy_state,
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(known.file_ref_id.clone()),
                copy_claim_id: Some(copy_claim_id.to_owned()),
                location_id: Some(self.config.location_id.clone()),
                ..EventReferences::default()
            },
        );
        let verification = scan_event(
            "copy_verified",
            json!({
                "verification_id": stable_id("verify", &[
                    self.config.scan_id.as_bytes(), &location_path.bytes, &copy_path.bytes,
                ]),
                "copy_claim_id": copy_claim_id,
                "object_id": object_id,
                "location_id": self.config.location_id,
                "result": verification_result,
                "expected_hash_algo": known.expected_hash_algo,
                "expected_hash_hex": known.expected_hash_hex,
                "observed_hash_hex": content.map(|content| content.sha256_hex.as_str()),
                "size_bytes": known.expected_size_bytes,
                "bytes_read": content.map_or(0, |content| content.size_bytes),
                "duration_ms": content.map_or(0, |content| content.duration_ms),
                "path_observed": path_json(copy_path),
                "device_fingerprint_status": self.config.fingerprint_status,
                "error_code": error_code,
                "error_detail": error_detail,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("annex_verification"),
                "job_type": "scan", "item_type": "verification",
                "item_key": copy_claim_id, "outcome_kind": verification_result,
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(known.file_ref_id.clone()),
                copy_claim_id: Some(copy_claim_id.to_owned()),
                location_id: Some(self.config.location_id.clone()),
                device_id: Some(self.config.device_id.clone()),
                ..EventReferences::default()
            },
        );
        vec![copy, verification]
    }

    fn inspect_imported_annex_symlink(
        &self,
        relative_path: &EncodedPath,
    ) -> Result<AnnexSymlinkInspection> {
        let raw_relative = raw_relative_path(relative_path)?;
        let worktree_path = self.config.root_path.join(&raw_relative);
        let target = match fs::read_link(&worktree_path) {
            Ok(target) => target,
            Err(error) => {
                return Ok(AnnexSymlinkInspection {
                    fingerprint: annex_symlink_fingerprint(relative_path, None, "read_error", None),
                    state: AnnexSymlinkState::ReadError(error.to_string()),
                });
            }
        };
        let location_root = self.location_root_path()?;
        let object_root = location_root.join(".git/annex/objects");
        let Some(candidate) = lexical_relative_target(
            worktree_path.parent().unwrap_or(&self.config.root_path),
            &target,
        ) else {
            return Ok(AnnexSymlinkInspection {
                fingerprint: annex_symlink_fingerprint(
                    relative_path,
                    Some(&target),
                    "unsafe",
                    None,
                ),
                state: AnnexSymlinkState::Unsafe(
                    "annex symlink target is absolute or cannot be normalized safely".to_owned(),
                ),
            });
        };
        if !candidate.starts_with(&object_root) {
            return Ok(AnnexSymlinkInspection {
                fingerprint: annex_symlink_fingerprint(
                    relative_path,
                    Some(&target),
                    "unsafe",
                    None,
                ),
                state: AnnexSymlinkState::Unsafe(
                    "annex symlink target escapes the Location's .git/annex/objects directory"
                        .to_owned(),
                ),
            });
        }
        let copy_relative = candidate.strip_prefix(&location_root).map_err(|_| {
            ScanError::InvalidConfig(
                "validated annex target is outside the Location root".to_owned(),
            )
        })?;
        let copy_path = encode_relative_path(copy_relative);
        let legacy_copy_path =
            encode_relative_path(candidate.strip_prefix(&object_root).map_err(|_| {
                ScanError::InvalidConfig(
                    "validated annex target is outside the annex object root".to_owned(),
                )
            })?);
        let metadata = match fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AnnexSymlinkInspection {
                    fingerprint: annex_symlink_fingerprint(
                        relative_path,
                        Some(&target),
                        "absent",
                        None,
                    ),
                    state: AnnexSymlinkState::Absent,
                });
            }
            Err(error) => {
                return Ok(AnnexSymlinkInspection {
                    fingerprint: annex_symlink_fingerprint(
                        relative_path,
                        Some(&target),
                        "read_error",
                        None,
                    ),
                    state: AnnexSymlinkState::ReadError(error.to_string()),
                });
            }
        };
        if !metadata.file_type().is_file() {
            return Ok(AnnexSymlinkInspection {
                fingerprint: annex_symlink_fingerprint(
                    relative_path,
                    Some(&target),
                    "unsafe",
                    Some(&metadata),
                ),
                state: AnnexSymlinkState::Unsafe(
                    "annex symlink target is not a regular file".to_owned(),
                ),
            });
        }
        let canonical_object_root = match fs::canonicalize(&object_root) {
            Ok(path) => path,
            Err(error) => {
                return Ok(AnnexSymlinkInspection {
                    fingerprint: annex_symlink_fingerprint(
                        relative_path,
                        Some(&target),
                        "read_error",
                        Some(&metadata),
                    ),
                    state: AnnexSymlinkState::ReadError(error.to_string()),
                });
            }
        };
        let canonical_candidate = match fs::canonicalize(&candidate) {
            Ok(path) => path,
            Err(error) => {
                return Ok(AnnexSymlinkInspection {
                    fingerprint: annex_symlink_fingerprint(
                        relative_path,
                        Some(&target),
                        "read_error",
                        Some(&metadata),
                    ),
                    state: AnnexSymlinkState::ReadError(error.to_string()),
                });
            }
        };
        if !canonical_candidate.starts_with(&canonical_object_root) {
            return Ok(AnnexSymlinkInspection {
                fingerprint: annex_symlink_fingerprint(
                    relative_path,
                    Some(&target),
                    "unsafe",
                    Some(&metadata),
                ),
                state: AnnexSymlinkState::Unsafe(
                    "annex symlink resolves outside the Location's .git/annex/objects directory"
                        .to_owned(),
                ),
            });
        }
        let fingerprint =
            annex_symlink_fingerprint(relative_path, Some(&target), "present", Some(&metadata));
        Ok(AnnexSymlinkInspection {
            state: AnnexSymlinkState::Present {
                content_path: canonical_candidate,
                copy_path,
                legacy_copy_path,
                file: DiscoveredFile {
                    relative_path: relative_path.clone(),
                    size_bytes: metadata.len(),
                    modified_time_utc_ms: modified_time_ms(&metadata),
                },
            },
            fingerprint,
        })
    }

    fn location_root_path(&self) -> Result<PathBuf> {
        let mut root = self.config.root_path.clone();
        if let Some(prefix) = &self.config.location_prefix {
            for component in prefix.components() {
                if matches!(component, Component::Normal(_)) && !root.pop() {
                    return Err(ScanError::InvalidConfig(
                        "Location prefix has more components than the scan root".to_owned(),
                    ));
                }
            }
        }
        Ok(root)
    }

    #[allow(clippy::too_many_arguments)]
    fn positive_events(
        &self,
        file: &DiscoveredFile,
        logical_path: &EncodedPath,
        location_path: &EncodedPath,
        file_ref_id: &str,
        copy_claim_id: &str,
        object_id: Option<&str>,
        content: Option<&HashedContent>,
        read_error: Option<(u64, String)>,
    ) -> Vec<EventRequest> {
        let fields = EventFields::new(&self.config, location_path);
        let mut events = Vec::new();
        if let (Some(object_id), Some(content)) = (object_id, content) {
            events.push(scan_event(
                "object_observed",
                json!({
                    "object_id": object_id,
                    "canonical_hash_algo": "blake3",
                    "canonical_hash_hex": content.blake3_hex,
                    "size_bytes": content.size_bytes,
                    "scan_id": self.config.scan_id,
                    "operation_key": fields.operation_key("object"),
                    "job_type": "scan", "item_type": "object",
                    "item_key": object_id, "outcome_kind": "observed",
                }),
                &self.config,
                EventReferences {
                    job_id: Some(self.config.job_id.clone()),
                    object_id: Some(object_id.to_owned()),
                    ..EventReferences::default()
                },
            ));
        }
        events.push(scan_event(
            "file_ref_observed",
            json!({
                "file_ref_id": file_ref_id,
                "collection_id": self.config.collection_id,
                "logical_path": path_json(logical_path),
                "object_id": object_id,
                "external_identity_id": null,
                "identity_state": if object_id.is_some() { "resolved" } else { "unknown" },
                "path_state": "active",
                "observed_size_bytes": file.size_bytes,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("file_ref"),
                "job_type": "scan", "item_type": "file_ref",
                "item_key": file_ref_id, "outcome_kind": "observed",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(file_ref_id.to_owned()),
                ..EventReferences::default()
            },
        ));
        events.push(scan_event(
            "path_observed",
            json!({
                "file_ref_id": file_ref_id,
                "location_id": self.config.location_id,
                "observed_path": path_json(location_path),
                "representation": "ordinary_file",
                "object_id": object_id,
                "external_identity_id": null,
                "state": "present",
                "observed_size_bytes": file.size_bytes,
                "modified_time_utc_ms": file.modified_time_utc_ms,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("path"),
                "job_type": "scan", "item_type": "path",
                "item_key": file_ref_id, "outcome_kind": "present",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(file_ref_id.to_owned()),
                location_id: Some(self.config.location_id.clone()),
                ..EventReferences::default()
            },
        ));
        events.push(scan_event(
            "copy_observed",
            json!({
                "copy_claim_id": copy_claim_id,
                "location_id": self.config.location_id,
                "relative_path": path_json(location_path),
                "object_id": object_id,
                "external_identity_id": null,
                "claim_basis": if object_id.is_some() { "observed_bytes" } else { "observed_metadata" },
                "state": if object_id.is_some() { "present" } else { "unknown" },
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("copy"),
                "job_type": "scan", "item_type": "copy",
                "item_key": copy_claim_id, "outcome_kind": if object_id.is_some() { "present" } else { "read_error" },
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(file_ref_id.to_owned()),
                copy_claim_id: Some(copy_claim_id.to_owned()),
                location_id: Some(self.config.location_id.clone()),
                ..EventReferences::default()
            },
        ));
        let (result, bytes_read, duration_ms, error_code, error_detail) = match read_error {
            Some((bytes_read, detail)) => (
                "read_error",
                bytes_read,
                0,
                Some("scan_content_read_error"),
                Some(detail),
            ),
            None => (
                "ok",
                content.map_or(0, |content| content.size_bytes),
                content.map_or(0, |content| content.duration_ms),
                None,
                None,
            ),
        };
        events.push(scan_event(
            "copy_verified",
            json!({
                "verification_id": stable_id("verify", &[self.config.scan_id.as_bytes(), &location_path.bytes]),
                "copy_claim_id": copy_claim_id,
                "object_id": object_id,
                "location_id": self.config.location_id,
                "result": result,
                "expected_hash_algo": object_id.map(|_| "blake3"),
                "expected_hash_hex": content.map(|content| content.blake3_hex.as_str()),
                "observed_hash_hex": content.map(|content| content.blake3_hex.as_str()),
                "size_bytes": file.size_bytes,
                "bytes_read": bytes_read,
                "duration_ms": duration_ms,
                "path_observed": path_json(location_path),
                "device_fingerprint_status": self.config.fingerprint_status,
                "error_code": error_code,
                "error_detail": error_detail,
                "scan_id": self.config.scan_id,
                "operation_key": fields.operation_key("verification"),
                "job_type": "scan", "item_type": "verification",
                "item_key": copy_claim_id, "outcome_kind": result,
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                object_id: object_id.map(ToOwned::to_owned),
                file_ref_id: Some(file_ref_id.to_owned()),
                copy_claim_id: Some(copy_claim_id.to_owned()),
                location_id: Some(self.config.location_id.clone()),
                device_id: Some(self.config.device_id.clone()),
                ..EventReferences::default()
            },
        ));
        events
    }

    fn logical_path(&self, relative: &EncodedPath) -> Result<EncodedPath> {
        join_encoded_prefix(self.logical_prefix.as_ref(), relative)
    }

    fn location_path(&self, relative: &EncodedPath) -> Result<EncodedPath> {
        join_encoded_prefix(self.location_prefix.as_ref(), relative)
    }
}

fn join_encoded_prefix(
    prefix: Option<&EncodedPath>,
    relative: &EncodedPath,
) -> Result<EncodedPath> {
    let Some(prefix) = prefix else {
        return Ok(relative.clone());
    };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;

        let mut bytes = prefix.bytes.clone();
        bytes.push(b'/');
        bytes.extend_from_slice(&relative.bytes);
        Ok(encode_relative_path(&PathBuf::from(
            std::ffi::OsString::from_vec(bytes),
        )))
    }
    #[cfg(not(unix))]
    {
        let _ = (prefix, relative);
        Err(ScanError::UnsupportedPlatform)
    }
}

impl LocationScanner<'_> {
    fn missing_candidate_event(
        &self,
        target: &crate::projection::ScanMissingTarget,
    ) -> EventRequest {
        let event_type = if target.kind == "path" {
            "path_missing_candidate"
        } else {
            "copy_missing_candidate"
        };
        scan_event(
            event_type,
            json!({
                "scan_id": self.config.scan_id,
                "file_ref_id": target.file_ref_id,
                "copy_claim_id": target.copy_claim_id,
                "location_id": self.config.location_id,
                "path": path_json(&target.path),
                "operation_key": stable_id("op", &[
                    self.config.scan_id.as_bytes(), b"missing", target.kind.as_bytes(),
                    target.target_id.as_bytes(),
                ]),
                "job_type": "scan", "item_type": target.kind,
                "item_key": target.target_id, "outcome_kind": "missing_candidate",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                file_ref_id: target.file_ref_id.clone(),
                copy_claim_id: target.copy_claim_id.clone(),
                location_id: Some(self.config.location_id.clone()),
                device_id: Some(self.config.device_id.clone()),
                ..EventReferences::default()
            },
        )
    }

    fn complete_scan(
        &self,
        status: &str,
        summary: &ScanSummary,
        manifest: Option<&crate::projection::ScanCompletionManifest>,
    ) -> Result<ScanStatus> {
        let completion = scan_event(
            "scan_completed",
            json!({
                "scan_id": self.config.scan_id,
                "scan_mode": self.config.scan_mode.as_str(),
                "status": status,
                "coverage_version": COVERAGE_VERSION,
                "scope_json": self.scope_json,
                "exclusions_hash": self.exclusions_hash,
                "observations_count": manifest.map_or(0, |manifest| manifest.observations_count),
                "observations_digest": manifest.and_then(|manifest| (manifest.observations_count != 0).then_some(&manifest.observations_digest)),
                "missing_candidate_count": manifest.map_or(0, |manifest| manifest.missing_candidate_count),
                "missing_candidate_digest": manifest.and_then(|manifest| (manifest.missing_candidate_count != 0).then_some(&manifest.missing_candidate_digest)),
                "files_seen": summary.files_seen,
                "bytes_seen": summary.bytes_seen,
                "new_paths": summary.new_paths,
                "changed_paths": summary.changed_paths,
                "unchanged_paths": summary.unchanged_paths,
                "error_count": summary.error_count(),
                "error_summary": summary.error_summary(),
                "operation_key": stable_id("op", &[self.config.scan_id.as_bytes(), b"completed"]),
                "job_type": "scan", "item_type": "scan",
                "item_key": self.config.scan_id, "outcome_kind": status,
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                location_id: Some(self.config.location_id.clone()),
                device_id: Some(self.config.device_id.clone()),
                ..EventReferences::default()
            },
        );
        self.store.append(completion)?;
        self.projection.apply(self.store)?;
        let actual_status = self
            .projection
            .scan_run_status(&self.config.scan_id)?
            .ok_or_else(|| {
                ScanError::InvalidConfig(format!(
                    "scan {} vanished during completion",
                    self.config.scan_id
                ))
            })?;
        let mut progress_summary = summary.clone();
        if status == "complete" && actual_status == "partial" {
            progress_summary.concurrent_changes += 1;
        }
        let progress = serde_json::to_string(&progress_summary)
            .map_err(|error| ScanError::InvalidConfig(error.to_string()))?;
        self.projection.finish_scan_job(
            &self.config.job_id,
            &actual_status,
            &progress,
            now_utc_ms()?,
        )?;
        match actual_status.as_str() {
            "complete" => Ok(ScanStatus::Complete),
            "partial" | "failed" => Ok(ScanStatus::Partial),
            "cancelled" => Ok(ScanStatus::Cancelled),
            other => Err(ScanError::InvalidConfig(format!(
                "scan {} finalized with invalid status {other}",
                self.config.scan_id
            ))),
        }
    }

    fn scan_started_event(&self) -> EventRequest {
        scan_event(
            "scan_started",
            json!({
                "scan_id": self.config.scan_id,
                "scan_mode": self.config.scan_mode.as_str(),
                "location_id": self.config.location_id,
                "collection_id": self.config.collection_id,
                "logical_prefix": self.logical_prefix.as_ref().map(path_json),
                "device_id": self.config.device_id,
                "archive_root_id": self.config.archive_root_id,
                "fingerprint_status": self.config.fingerprint_status,
                "coverage_version": COVERAGE_VERSION,
                "scope_json": self.scope_json,
                "exclusions_json": self.exclusions_json,
                "exclusions_hash": self.exclusions_hash,
                "operation_key": stable_id("op", &[self.config.scan_id.as_bytes(), b"started"]),
                "job_type": "scan", "item_type": "scan",
                "item_key": self.config.scan_id, "outcome_kind": "started",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                location_id: Some(self.config.location_id.clone()),
                device_id: Some(self.config.device_id.clone()),
                ..EventReferences::default()
            },
        )
    }

    fn device_checked_in_event(&self) -> EventRequest {
        scan_event(
            "device_checked_in",
            json!({
                "device_id": self.config.device_id,
                "fingerprint_status": self.config.fingerprint_status,
                "operation_key": stable_id("op", &[self.config.scan_id.as_bytes(), b"device_checkin"]),
                "job_type": "scan", "item_type": "device",
                "item_key": self.config.device_id, "outcome_kind": "checked_in",
            }),
            &self.config,
            EventReferences {
                job_id: Some(self.config.job_id.clone()),
                device_id: Some(self.config.device_id.clone()),
                ..EventReferences::default()
            },
        )
    }
}

enum FileEvents {
    Stable {
        events: Vec<EventRequest>,
        seen: ScanSeenPath,
        changed: bool,
    },
    ReadError {
        events: Vec<EventRequest>,
        seen: ScanSeenPath,
    },
    ChangedDuringRead,
}

enum ImportedAnnexEvents {
    Observed {
        events: Vec<EventRequest>,
        seen: Vec<ScanSeenPath>,
        size_bytes: u64,
        changed: bool,
    },
    ReadError {
        events: Vec<EventRequest>,
        seen: Vec<ScanSeenPath>,
    },
    ChangedDuringRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnnexNamespaceFingerprint {
    entries: u64,
    digest: String,
}

#[derive(Default)]
struct AnnexNamespaceAccumulator {
    entries: u64,
    xor: [u8; 32],
}

impl AnnexNamespaceAccumulator {
    fn record(&mut self, digest: &[u8; 32]) {
        for (target, source) in self.xor.iter_mut().zip(digest) {
            *target ^= source;
        }
        self.entries = self.entries.saturating_add(1);
    }

    fn finish(&self) -> AnnexNamespaceFingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.entries.to_le_bytes());
        hasher.update(&self.xor);
        AnnexNamespaceFingerprint {
            entries: self.entries,
            digest: hasher.finalize().to_hex().to_string(),
        }
    }
}

enum AnnexSymlinkState {
    Present {
        content_path: PathBuf,
        copy_path: EncodedPath,
        legacy_copy_path: EncodedPath,
        file: DiscoveredFile,
    },
    Absent,
    Unsafe(String),
    ReadError(String),
}

struct AnnexSymlinkInspection {
    state: AnnexSymlinkState,
    fingerprint: [u8; 32],
}

struct AnnexHashedContent {
    blake3_hex: String,
    sha256_hex: String,
    size_bytes: u64,
    duration_ms: u64,
}

enum AnnexHashOutcome {
    Stable(AnnexHashedContent),
    ReadError { bytes_read: u64, detail: String },
    Changed,
}

struct HashedContent {
    blake3_hex: String,
    size_bytes: u64,
    duration_ms: u64,
}

enum HashOutcome {
    Stable(HashedContent),
    ReadError { bytes_read: u64, detail: String },
    Changed,
}

fn hash_file_stable(path: &Path, discovered: &DiscoveredFile) -> HashOutcome {
    let started = Instant::now();
    let before = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return HashOutcome::ReadError {
                bytes_read: 0,
                detail: error.to_string(),
            }
        }
    };
    if before.len() != discovered.size_bytes
        || modified_time_ms(&before) != discovered.modified_time_utc_ms
    {
        return HashOutcome::Changed;
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            return HashOutcome::ReadError {
                bytes_read: 0,
                detail: error.to_string(),
            }
        }
    };
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                bytes_read = bytes_read.saturating_add(read as u64);
            }
            Err(error) => {
                return HashOutcome::ReadError {
                    bytes_read,
                    detail: error.to_string(),
                }
            }
        }
    }
    let after = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return HashOutcome::Changed,
    };
    if before.len() != after.len()
        || modified_time_ms(&before) != modified_time_ms(&after)
        || bytes_read != after.len()
    {
        return HashOutcome::Changed;
    }
    HashOutcome::Stable(HashedContent {
        blake3_hex: hasher.finalize().to_hex().to_string(),
        size_bytes: bytes_read,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn hash_annex_file_stable(path: &Path, discovered: &DiscoveredFile) -> AnnexHashOutcome {
    let started = Instant::now();
    let before = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return AnnexHashOutcome::ReadError {
                bytes_read: 0,
                detail: error.to_string(),
            };
        }
    };
    if !before.file_type().is_file()
        || before.len() != discovered.size_bytes
        || modified_time_ms(&before) != discovered.modified_time_utc_ms
    {
        return AnnexHashOutcome::Changed;
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            return AnnexHashOutcome::ReadError {
                bytes_read: 0,
                detail: error.to_string(),
            };
        }
    };
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                blake3.update(&buffer[..read]);
                sha256.update(&buffer[..read]);
                bytes_read = bytes_read.saturating_add(read as u64);
            }
            Err(error) => {
                return AnnexHashOutcome::ReadError {
                    bytes_read,
                    detail: error.to_string(),
                };
            }
        }
    }
    let after = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return AnnexHashOutcome::Changed,
    };
    if before.len() != after.len()
        || modified_time_ms(&before) != modified_time_ms(&after)
        || bytes_read != after.len()
    {
        return AnnexHashOutcome::Changed;
    }
    AnnexHashOutcome::Stable(AnnexHashedContent {
        blake3_hex: blake3.finalize().to_hex().to_string(),
        sha256_hex: format!("{:x}", sha256.finalize()),
        size_bytes: bytes_read,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn is_annex_pointer_file(path: &Path, external_key: &str) -> std::io::Result<bool> {
    let bytes = fs::read(path)?;
    let first_line = bytes.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    Ok(first_line
        .strip_prefix(b"/annex/objects/")
        .is_some_and(|key| key == external_key.as_bytes()))
}

fn lexical_relative_target(base: &Path, target: &Path) -> Option<PathBuf> {
    if target.is_absolute() {
        return None;
    }
    let mut resolved = base.to_path_buf();
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    return None;
                }
            }
            Component::Normal(value) => resolved.push(value),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

fn annex_symlink_fingerprint(
    relative_path: &EncodedPath,
    target: Option<&Path>,
    state: &str,
    metadata: Option<&fs::Metadata>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_fingerprint_piece(&mut hasher, relative_path.encoding.as_str().as_bytes());
    hash_fingerprint_piece(&mut hasher, &relative_path.bytes);
    hash_fingerprint_piece(&mut hasher, state.as_bytes());
    if let Some(target) = target {
        hash_fingerprint_piece(&mut hasher, target.as_os_str().as_encoded_bytes());
    }
    if let Some(metadata) = metadata {
        hasher.update(&metadata.len().to_le_bytes());
        if let Some(modified) = modified_time_ms(metadata) {
            hasher.update(&modified.to_le_bytes());
        }
        #[cfg(unix)]
        {
            hasher.update(&metadata.dev().to_le_bytes());
            hasher.update(&metadata.ino().to_le_bytes());
            hasher.update(&metadata.ctime().to_le_bytes());
            hasher.update(&metadata.ctime_nsec().to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn hash_fingerprint_piece(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn annex_seen_paths(
    location_path: &EncodedPath,
    known: &ScanKnownEntry,
    copy_path: &EncodedPath,
    copy_claim_id: &str,
) -> Vec<ScanSeenPath> {
    if location_path.encoding == copy_path.encoding && location_path.bytes == copy_path.bytes {
        return vec![ScanSeenPath {
            item_key: scan_item_key(location_path),
            path: location_path.clone(),
            file_ref_id: Some(known.file_ref_id.clone()),
            copy_claim_id: Some(copy_claim_id.to_owned()),
        }];
    }
    vec![
        ScanSeenPath {
            item_key: scan_item_key(location_path),
            path: location_path.clone(),
            file_ref_id: Some(known.file_ref_id.clone()),
            copy_claim_id: None,
        },
        ScanSeenPath {
            item_key: scan_item_key(copy_path),
            path: copy_path.clone(),
            file_ref_id: None,
            copy_claim_id: Some(copy_claim_id.to_owned()),
        },
    ]
}

fn apply_imported_annex_events(
    result: ImportedAnnexEvents,
    observed_by_current_scan: bool,
    summary: &mut ScanSummary,
    pending_events: &mut Vec<EventRequest>,
    pending_seen: &mut Vec<ScanSeenPath>,
) -> bool {
    match result {
        ImportedAnnexEvents::Observed {
            events,
            seen,
            size_bytes,
            changed,
        } => {
            summary.bytes_seen = summary.bytes_seen.saturating_add(size_bytes);
            if changed {
                summary.changed_paths += 1;
            } else if !observed_by_current_scan {
                summary.unchanged_paths += 1;
            }
            pending_events.extend(events);
            pending_seen.extend(seen);
            false
        }
        ImportedAnnexEvents::ReadError { events, seen } => {
            summary.content_read_errors += 1;
            summary.changed_paths += 1;
            pending_events.extend(events);
            pending_seen.extend(seen);
            false
        }
        ImportedAnnexEvents::ChangedDuringRead => {
            summary.concurrent_changes += 1;
            true
        }
    }
}

struct EventFields<'a> {
    config: &'a ScanConfig,
    item: Vec<u8>,
}

impl<'a> EventFields<'a> {
    fn new(config: &'a ScanConfig, path: &EncodedPath) -> Self {
        let mut item = path.encoding.as_str().as_bytes().to_vec();
        item.push(0);
        item.extend_from_slice(&path.bytes);
        Self { config, item }
    }

    fn operation_key(&self, fact: &str) -> String {
        stable_id(
            "op",
            &[
                self.config.scan_id.as_bytes(),
                self.config.job_id.as_bytes(),
                &self.item,
                fact.as_bytes(),
            ],
        )
    }
}

fn seen_path(path: &EncodedPath, known: &ScanKnownEntry) -> ScanSeenPath {
    ScanSeenPath {
        item_key: scan_item_key(path),
        path: path.clone(),
        file_ref_id: Some(known.file_ref_id.clone()),
        copy_claim_id: known.copy_claim_id.clone(),
    }
}

fn scan_item_key(path: &EncodedPath) -> String {
    stable_id("seen", &[path.encoding.as_str().as_bytes(), &path.bytes])
}

fn scan_event(
    event_type: &str,
    payload: Value,
    _config: &ScanConfig,
    references: EventReferences,
) -> EventRequest {
    EventRequest::new(event_type, payload).with_references(references)
}

fn operation_key(event: &EventRequest) -> Result<&str> {
    event
        .payload
        .get("operation_key")
        .and_then(Value::as_str)
        .ok_or_else(|| ScanError::InvalidConfig("event lacks operation_key".to_owned()))
}

fn stable_id(prefix: &str, pieces: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for piece in pieces {
        hasher.update(&(piece.len() as u64).to_le_bytes());
        hasher.update(piece);
    }
    format!("{prefix}_{}", &hasher.finalize().to_hex()[..32])
}

fn path_json(path: &EncodedPath) -> Value {
    match path.encoding {
        PathEncoding::Utf8 => json!({
            "encoding": "utf8",
            "text": std::str::from_utf8(&path.bytes).expect("UTF-8 path invariant"),
            "display": path.display,
        }),
        encoding => json!({
            "encoding": encoding.as_str(),
            "base64": base64::engine::general_purpose::STANDARD.encode(&path.bytes),
            "display": path.display,
        }),
    }
}

fn uppercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02X}");
    }
    output
}

fn encode_absolute_path(path: &Path) -> EncodedPath {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_os_str().as_bytes().to_vec();
        EncodedPath {
            encoding: if path.to_str().is_some() {
                PathEncoding::Utf8
            } else {
                PathEncoding::UnixBytes
            },
            display: path.to_string_lossy().into_owned(),
            bytes,
        }
    }
    #[cfg(not(unix))]
    {
        encode_relative_path(path)
    }
}

fn root_filesystem_identity(path: &Path) -> Result<Value> {
    let metadata = fs::metadata(path)
        .map_err(|source| io_error("inspect scan root identity", path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok(json!({"kind": "unix_dev_inode", "device": metadata.dev(), "inode": metadata.ino()}))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(ScanError::UnsupportedPlatform)
    }
}

fn validate_relative_path(name: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ScanError::InvalidConfig(format!(
            "{name} must be a non-empty relative path without parent traversal"
        )));
    }
    Ok(())
}

fn now_utc_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            ScanError::InvalidConfig(format!("system clock is before epoch: {error}"))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| ScanError::InvalidConfig("system time exceeds u64 milliseconds".to_owned()))
}

#[cfg(unix)]
fn raw_relative_path(path: &EncodedPath) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(
        path.bytes.clone(),
    )))
}

#[cfg(not(unix))]
fn raw_relative_path(_path: &EncodedPath) -> Result<PathBuf> {
    Err(ScanError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;
    use crate::{EventStoreConfig, ProjectionConfig};

    #[test]
    fn complete_partial_resume_missing_and_rebuild_are_loss_safe() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir_all(fixture.join("excluded/deep")).unwrap();
        fs::write(fixture.join("keep.txt"), b"keep").unwrap();
        fs::write(fixture.join("remove.txt"), b"remove").unwrap();
        fs::write(fixture.join("excluded/deep/ignored.txt"), b"ignore").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("keep.txt", fixture.join("link")).unwrap();

        let (store, database) = setup(&temp);
        let first = scanner(&store, &database, &fixture, "scan_one", "job_one");
        let interrupted = first.run_at_most(Some(1)).unwrap();
        assert_eq!(interrupted.status, ScanStatus::Interrupted);
        assert_eq!(
            database.scan_run_status("scan_one").unwrap().as_deref(),
            Some("running")
        );
        let completed = first.run().unwrap();
        assert_eq!(completed.status, ScanStatus::Complete);
        assert_eq!(completed.summary.files_seen, 2);
        assert_eq!(completed.summary.excluded_subtrees, 1);
        #[cfg(unix)]
        {
            assert_eq!(completed.summary.symlinks, 1);
            assert_eq!(completed.summary.ignored_symlinks, 1);
        }

        fs::remove_file(fixture.join("remove.txt")).unwrap();
        let second = scanner(&store, &database, &fixture, "scan_two", "job_two");
        let second = second.run().unwrap();
        assert_eq!(second.status, ScanStatus::Complete);
        assert_eq!(second.summary.missing_paths, 1);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            ),
            1
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM path_observations WHERE state = 'missing'"
            ),
            1
        );

        fs::write(fixture.join("remove.txt"), b"remove").unwrap();
        let third = scanner(&store, &database, &fixture, "scan_three", "job_three")
            .run()
            .unwrap();
        assert_eq!(third.status, ScanStatus::Complete);
        assert_eq!(third.summary.missing_paths, 0);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            ),
            0
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM path_observations WHERE state = 'missing'"
            ),
            0
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE last_complete_scan_id = 'scan_three'"
            ),
            2
        );

        store
            .append(
                EventRequest::new(
                    "device_mount_observed",
                    json!({
                        "mount_id": "mount_fixture",
                        "device_id": "device_fixture",
                        "mount_root_uri": fixture.to_string_lossy(),
                        "status": "mounted",
                        "fingerprint_status": "match",
                        "operation_key": "op_mount_fixture",
                        "job_type": "device", "item_type": "mount",
                        "item_key": "mount_fixture", "outcome_kind": "mounted",
                    }),
                )
                .with_references(EventReferences {
                    device_id: Some("device_fixture".to_owned()),
                    ..EventReferences::default()
                }),
            )
            .unwrap();
        database.apply(&store).unwrap();

        let rebuilt_path = temp.path().join("rebuilt.db");
        let rebuilt =
            ProjectionDb::open_or_create(&rebuilt_path, "arc_scan", ProjectionConfig::default())
                .unwrap();
        seed_topology(&rebuilt);
        rebuilt.apply(&store).unwrap();
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            ),
            scalar(
                &rebuilt,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            )
        );
        let live_freshness = database.location_freshness("location_fixture").unwrap();
        let rebuilt_freshness = rebuilt.location_freshness("location_fixture").unwrap();
        assert_eq!(
            live_freshness.last_complete_scan_id,
            rebuilt_freshness.last_complete_scan_id
        );
        assert!(live_freshness.last_device_checkin_time_utc_ms.is_some());
        assert_eq!(live_freshness.availability, "online");
    }

    #[test]
    fn partial_scan_never_activates_missing_or_refreshes_complete_coverage() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("known.txt"), b"known").unwrap();
        let (store, database) = setup(&temp);
        scanner(&store, &database, &fixture, "scan_initial", "job_initial")
            .run()
            .unwrap();
        fs::remove_file(fixture.join("known.txt")).unwrap();

        let partial = scanner(&store, &database, &fixture, "scan_partial", "job_partial");
        partial.projection.apply(partial.store).unwrap();
        let started = partial.scan_started_event();
        partial
            .store
            .append_batch(vec![partial.device_checked_in_event(), started])
            .unwrap();
        partial.projection.apply(partial.store).unwrap();
        let summary = ScanSummary {
            traversal_errors: 1,
            ..ScanSummary::default()
        };
        partial.complete_scan("partial", &summary, None).unwrap();

        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'"
            ),
            1
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE activated = 1"
            ),
            0
        );
        assert_eq!(
            text_scalar(
                &database,
                "SELECT last_complete_scan_id FROM copy_claims LIMIT 1"
            ),
            "scan_initial"
        );
        let freshness = database.location_freshness("location_fixture").unwrap();
        assert_eq!(freshness.latest_scan_status.as_deref(), Some("partial"));
        assert!(freshness
            .uncertainty
            .contains(&"latest_scan_incomplete".to_owned()));
    }

    #[test]
    fn add_records_new_files_without_missing_or_complete_coverage() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("kept.txt"), b"kept").unwrap();
        fs::write(fixture.join("later-removed.txt"), b"removed").unwrap();
        let (store, database) = setup(&temp);
        scanner(&store, &database, &fixture, "scan_initial", "job_initial")
            .run()
            .unwrap();
        fs::remove_file(fixture.join("later-removed.txt")).unwrap();
        fs::write(fixture.join("new.txt"), b"new").unwrap();

        let result = scanner_with_mode(
            &store,
            &database,
            &fixture,
            "add_positive",
            "job_add_positive",
            ScanMode::Add,
        )
        .run()
        .unwrap();

        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.summary.new_paths, 1);
        assert_eq!(result.summary.integrity_verified_paths, 1);
        assert_eq!(result.summary.missing_paths, 0);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'add_positive'"
            ),
            0
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            ),
            0
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'"
            ),
            3
        );
        assert_eq!(
            text_scalar(
                &database,
                "SELECT last_complete_scan_id FROM copy_claims WHERE relative_path_display = 'later-removed.txt'"
            ),
            "scan_initial"
        );
        assert_eq!(
            text_scalar(
                &database,
                "SELECT scan_mode FROM scan_runs WHERE scan_id = 'add_positive'"
            ),
            "add"
        );
    }

    #[test]
    fn exclusion_change_creates_a_new_boundary_without_false_missing() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir_all(fixture.join("held")).unwrap();
        fs::write(fixture.join("held/file.txt"), b"held").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::remove_file(fixture.join("held/file.txt")).unwrap();

        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_excluded",
            "job_excluded",
            vec![PathBuf::from("held")],
        )
        .run()
        .unwrap();
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'"
            ),
            1
        );

        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_unexcluded",
            "job_unexcluded",
            Vec::new(),
        )
        .run()
        .unwrap();
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            ),
            1
        );
    }

    #[test]
    fn provisional_candidate_is_inert_and_resume_completes_the_set() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("keep.txt"), b"keep").unwrap();
        fs::write(fixture.join("remove.txt"), b"remove").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::remove_file(fixture.join("remove.txt")).unwrap();

        let resumed = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_resumed",
            "job_resumed",
            Vec::new(),
        );
        store
            .append_batch(vec![
                resumed.device_checked_in_event(),
                resumed.scan_started_event(),
            ])
            .unwrap();
        database.apply(&store).unwrap();
        database
            .prepare_scan_job("job_resumed", "scan_resumed", "{}", now_utc_ms().unwrap())
            .unwrap();
        let keep_path = encode_relative_path(Path::new("keep.txt"));
        let mut session = database.open_scan_session().unwrap();
        let known = session
            .known_entry(
                "scan_resumed",
                "collection_fixture",
                "location_fixture",
                &keep_path,
            )
            .unwrap()
            .unwrap();
        session
            .mark_seen(
                "job_resumed",
                &[seen_path(&keep_path, &known)],
                now_utc_ms().unwrap(),
            )
            .unwrap();
        drop(session);
        let targets = database
            .scan_missing_targets_after(
                "scan_resumed",
                "job_resumed",
                "collection_fixture",
                "location_fixture",
                "[]",
                None,
                10,
            )
            .unwrap();
        assert_eq!(targets.len(), 2);
        store
            .append(resumed.missing_candidate_event(&targets[0]))
            .unwrap();
        database.apply(&store).unwrap();
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_resumed' AND activated = 0"
            ),
            1
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'"
            ),
            2
        );

        let result = resumed.run().unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.summary.missing_paths, 1);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_resumed' AND activated = 1"
            ),
            2
        );
    }

    #[test]
    fn source_change_after_candidate_generation_keeps_negatives_inert() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("returns.txt"), b"returns").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::remove_file(fixture.join("returns.txt")).unwrap();

        let concurrent = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_candidate_race",
            "job_candidate_race",
            Vec::new(),
        );
        store
            .append_batch(vec![
                concurrent.device_checked_in_event(),
                concurrent.scan_started_event(),
            ])
            .unwrap();
        database.apply(&store).unwrap();
        database
            .prepare_scan_job(
                "job_candidate_race",
                "scan_candidate_race",
                "{}",
                now_utc_ms().unwrap(),
            )
            .unwrap();
        database.clear_scan_seen("job_candidate_race").unwrap();
        let mut discovery = FileDiscovery::with_exclusions(&fixture, Vec::new()).unwrap();
        assert!(discovery.next().is_none());
        let first_namespace = discovery.namespace_fingerprint();

        concurrent.generate_missing_candidates().unwrap();
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_candidate_race' AND activated = 0"
            ),
            2
        );
        fs::write(fixture.join("returns.txt"), b"returns").unwrap();
        let mut summary = ScanSummary::default();
        assert!(concurrent
            .confirm_source_unchanged(
                first_namespace,
                AnnexNamespaceAccumulator::default().finish(),
                &mut summary,
            )
            .unwrap());
        concurrent.complete_scan("partial", &summary, None).unwrap();

        assert!(summary.concurrent_changes >= 1);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_candidate_race' AND activated = 1"
            ),
            0
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'"
            ),
            1
        );
    }

    #[test]
    fn resume_supersedes_a_stale_candidate_with_a_later_positive_observation() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("still-here.txt"), b"present").unwrap();
        fs::write(fixture.join("also-here.txt"), b"present too").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();

        let resumed = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_stale_candidate",
            "job_stale_candidate",
            Vec::new(),
        );
        store
            .append_batch(vec![
                resumed.device_checked_in_event(),
                resumed.scan_started_event(),
            ])
            .unwrap();
        database.apply(&store).unwrap();
        database
            .prepare_scan_job(
                "job_stale_candidate",
                "scan_stale_candidate",
                "{}",
                now_utc_ms().unwrap(),
            )
            .unwrap();
        database.clear_scan_seen("job_stale_candidate").unwrap();
        resumed.generate_missing_candidates().unwrap();
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_stale_candidate'"
            ),
            4
        );

        let interrupted = resumed.run_at_most(Some(1)).unwrap();
        assert_eq!(interrupted.status, ScanStatus::Interrupted);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*)
                 FROM scan_missing_candidates m
                 WHERE m.scan_id = 'scan_stale_candidate'
                   AND ((m.candidate_kind = 'path' AND EXISTS (
                        SELECT 1 FROM path_observations p
                        JOIN events e ON e.event_id = p.last_seen_event_id
                        WHERE p.file_ref_id = m.file_ref_id
                          AND m.candidate_event_seq > e.seq
                   )) OR (m.candidate_kind = 'copy' AND EXISTS (
                        SELECT 1 FROM copy_claims c
                        WHERE c.copy_claim_id = m.copy_claim_id
                          AND m.candidate_event_seq > c.state_event_seq
                   )))"
            ),
            2
        );
        let result = resumed.run().unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.summary.missing_paths, 0);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_stale_candidate' AND activated = 1"
            ),
            4
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present' AND last_complete_scan_id = 'scan_stale_candidate'"
            ),
            2
        );
    }

    #[test]
    fn resume_rejects_changed_scan_identity_and_cancellation_is_nonqualifying() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("file.txt"), b"content").unwrap();
        let (store, database) = setup(&temp);
        let interrupted = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_resume_identity",
            "job_resume_identity",
            Vec::new(),
        );
        assert_eq!(
            interrupted.run_at_most(Some(0)).unwrap().status,
            ScanStatus::Interrupted
        );

        let mut changed = interrupted.config.clone();
        changed.exclusions.push(PathBuf::from("new-exclusion"));
        let changed = LocationScanner::new(&store, &database, changed).unwrap();
        let error = changed.run().unwrap_err();
        assert_eq!(error.code(), "invalid_scan_state");
        assert_eq!(
            database
                .scan_run_status("scan_resume_identity")
                .unwrap()
                .as_deref(),
            Some("running")
        );

        let cancelled = interrupted.cancel().unwrap();
        assert_eq!(cancelled.status, ScanStatus::Cancelled);
        let freshness = database.location_freshness("location_fixture").unwrap();
        assert_eq!(freshness.latest_scan_status.as_deref(), Some("cancelled"));
        assert!(freshness.last_complete_scan_id.is_none());
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE activated = 1"
            ),
            0
        );
    }

    #[test]
    fn completion_manifest_mismatch_rolls_back_activation_and_cursor() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("gone.txt"), b"gone").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::remove_file(fixture.join("gone.txt")).unwrap();
        let malformed = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_malformed",
            "job_malformed",
            Vec::new(),
        );
        store
            .append_batch(vec![
                malformed.device_checked_in_event(),
                malformed.scan_started_event(),
            ])
            .unwrap();
        database.apply(&store).unwrap();
        database
            .prepare_scan_job(
                "job_malformed",
                "scan_malformed",
                "{}",
                now_utc_ms().unwrap(),
            )
            .unwrap();
        let target = database
            .scan_missing_targets_after(
                "scan_malformed",
                "job_malformed",
                "collection_fixture",
                "location_fixture",
                "[]",
                None,
                1,
            )
            .unwrap()
            .pop()
            .unwrap();
        store
            .append(malformed.missing_candidate_event(&target))
            .unwrap();
        database.apply(&store).unwrap();
        let cursor_before = database.status().unwrap().cursor.applied_seq;
        let actual = database.scan_completion_manifest("scan_malformed").unwrap();
        store
            .append(scan_event(
                "scan_completed",
                json!({
                    "scan_id": "scan_malformed",
                    "status": "complete",
                    "coverage_version": COVERAGE_VERSION,
                    "scope_json": malformed.scope_json,
                    "exclusions_hash": malformed.exclusions_hash,
                    "observations_count": actual.observations_count,
                    "observations_digest": (actual.observations_count != 0).then_some(actual.observations_digest),
                    "missing_candidate_count": actual.missing_candidate_count + 1,
                    "missing_candidate_digest": actual.missing_candidate_digest,
                    "files_seen": 0, "bytes_seen": 0, "new_paths": 0,
                    "changed_paths": 0, "unchanged_paths": 0, "error_count": 0,
                    "error_summary": {},
                    "operation_key": "op_bad_manifest",
                    "job_type": "scan", "item_type": "scan",
                    "item_key": "scan_malformed", "outcome_kind": "complete",
                }),
                &malformed.config,
                EventReferences {
                    job_id: Some("job_malformed".to_owned()),
                    location_id: Some("location_fixture".to_owned()),
                    device_id: Some("device_fixture".to_owned()),
                    ..EventReferences::default()
                },
            ))
            .unwrap();
        let error = database.apply(&store).unwrap_err();
        assert_eq!(error.code(), "invalid_event_payload");
        assert_eq!(database.status().unwrap().cursor.applied_seq, cursor_before);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id = 'scan_malformed' AND activated = 1"
            ),
            0
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'"
            ),
            1
        );
    }

    #[test]
    fn interleaved_same_scope_writer_forces_partial_completion() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("file.txt"), b"content").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();
        let connection = Connection::open(database.path()).unwrap();
        let (file_ref_id, object_id, size, modified): (String, String, i64, i64) = connection
            .query_row(
                "SELECT p.file_ref_id, p.object_id, p.observed_size_bytes, p.modified_time_utc_ms
                 FROM path_observations p",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        drop(connection);
        let concurrent = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_concurrent",
            "job_concurrent",
            Vec::new(),
        );
        store
            .append_batch(vec![
                concurrent.device_checked_in_event(),
                concurrent.scan_started_event(),
            ])
            .unwrap();
        database.apply(&store).unwrap();
        store
            .append(
                EventRequest::new(
                    "path_observed",
                    json!({
                        "file_ref_id": file_ref_id,
                        "location_id": "location_fixture",
                        "observed_path": {"encoding":"utf8", "text":"file.txt", "display":"file.txt"},
                        "representation": "ordinary_file",
                        "object_id": object_id,
                        "external_identity_id": null,
                        "state": "present",
                        "observed_size_bytes": size,
                        "modified_time_utc_ms": modified,
                        "operation_key": "op_interleaved_writer",
                        "job_type": "external_inventory", "item_type": "path",
                        "item_key": file_ref_id, "outcome_kind": "present",
                    }),
                )
                .with_references(EventReferences {
                    job_id: Some("job_external".to_owned()),
                    object_id: Some(object_id),
                    file_ref_id: Some(file_ref_id),
                    location_id: Some("location_fixture".to_owned()),
                    ..EventReferences::default()
                }),
            )
            .unwrap();
        database.apply(&store).unwrap();

        let result = concurrent.run().unwrap();
        assert_eq!(result.status, ScanStatus::Partial);
        assert!(result.summary.concurrent_changes >= 1);
        assert_eq!(
            text_scalar(
                &database,
                "SELECT last_complete_scan_id FROM copy_claims LIMIT 1"
            ),
            "scan_initial"
        );

        let late = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_late_writer",
            "job_late_writer",
            Vec::new(),
        );
        store
            .append_batch(vec![
                late.device_checked_in_event(),
                late.scan_started_event(),
            ])
            .unwrap();
        database.apply(&store).unwrap();
        let manifest = database
            .scan_completion_manifest("scan_late_writer")
            .unwrap();
        let connection = Connection::open(database.path()).unwrap();
        let (file_ref_id, object_id, size, modified): (String, String, i64, i64) = connection
            .query_row(
                "SELECT p.file_ref_id, p.object_id, p.observed_size_bytes, p.modified_time_utc_ms
                 FROM path_observations p",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        drop(connection);
        store
            .append(
                EventRequest::new(
                    "path_observed",
                    json!({
                        "file_ref_id": file_ref_id,
                        "location_id": "location_fixture",
                        "observed_path": {"encoding":"utf8", "text":"file.txt", "display":"file.txt"},
                        "representation": "ordinary_file",
                        "object_id": object_id,
                        "external_identity_id": null,
                        "state": "present",
                        "observed_size_bytes": size,
                        "modified_time_utc_ms": modified,
                        "operation_key": "op_late_interleaved_writer",
                        "job_type": "external_inventory", "item_type": "path",
                        "item_key": file_ref_id, "outcome_kind": "present",
                    }),
                )
                .with_references(EventReferences {
                    job_id: Some("job_late_external".to_owned()),
                    object_id: Some(object_id),
                    file_ref_id: Some(file_ref_id),
                    location_id: Some("location_fixture".to_owned()),
                    ..EventReferences::default()
                }),
            )
            .unwrap();
        database.apply(&store).unwrap();

        let downgraded = late
            .complete_scan("complete", &ScanSummary::default(), Some(&manifest))
            .unwrap();
        assert_eq!(downgraded, ScanStatus::Partial);
        assert_eq!(
            database
                .scan_run_status("scan_late_writer")
                .unwrap()
                .as_deref(),
            Some("partial")
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT error_count FROM scan_runs WHERE scan_id = 'scan_late_writer'"
            ),
            1
        );
    }

    #[test]
    fn fingerprint_mismatch_is_recorded_and_refuses_the_scan() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        let (store, database) = setup(&temp);
        let base = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_mismatch",
            "job_mismatch",
            Vec::new(),
        );
        let mut config = base.config.clone();
        config.fingerprint_status = "mismatch".to_owned();
        let scanner = LocationScanner::new(&store, &database, config).unwrap();
        let error = scanner.run().unwrap_err();
        assert_eq!(error.code(), "scan_device_mismatch");
        assert_eq!(scalar(&database, "SELECT COUNT(*) FROM scan_runs"), 0);
        assert_eq!(
            text_scalar(
                &database,
                "SELECT last_fingerprint_status FROM devices WHERE device_id = 'device_fixture'"
            ),
            "mismatch"
        );
        assert_eq!(
            text_scalar(
                &database,
                "SELECT identity_state FROM devices WHERE device_id = 'device_fixture'"
            ),
            "conflict"
        );
        let freshness = database.location_freshness("location_fixture").unwrap();
        assert!(freshness
            .uncertainty
            .contains(&"device_identity_unconfirmed".to_owned()));
    }

    #[test]
    fn canonical_scan_start_rejects_inconsistent_topology() {
        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        let (store, database) = setup(&temp);
        let scanner = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_bad_topology",
            "job_bad_topology",
            Vec::new(),
        );
        let mut started = scanner.scan_started_event();
        started.payload["archive_root_id"] = json!("wrong_root");
        store.append(started).unwrap();

        let error = database.apply(&store).unwrap_err();
        assert_eq!(error.code(), "invalid_event_payload");
        assert_eq!(scalar(&database, "SELECT COUNT(*) FROM scan_runs"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_subtree_forces_partial_without_false_missing() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        let guarded = fixture.join("guarded");
        fs::create_dir_all(&guarded).unwrap();
        fs::write(fixture.join("visible.txt"), b"visible").unwrap();
        fs::write(guarded.join("hidden.txt"), b"hidden").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_initial",
            "job_initial",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::remove_file(fixture.join("visible.txt")).unwrap();
        fs::set_permissions(&guarded, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&guarded).is_ok() {
            fs::set_permissions(&guarded, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let result = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_denied",
            "job_denied",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::set_permissions(&guarded, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.status, ScanStatus::Partial);
        assert!(result.summary.traversal_errors >= 1);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'"
            ),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_stays_visible_and_nonqualifying_without_partial_coverage() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("readable.txt"), b"readable").unwrap();
        let unreadable = fixture.join("unreadable.txt");
        fs::write(&unreadable, b"unreadable").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&unreadable).is_ok() {
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
            return;
        }
        let (store, database) = setup(&temp);
        let result = scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_unreadable",
            "job_unreadable",
            Vec::new(),
        )
        .run()
        .unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.summary.content_read_errors, 1);
        assert_eq!(result.summary.integrity_verified_paths, 1);
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE state = 'unknown' AND last_verification_result = 'read_error'"
            ),
            1
        );
        assert_eq!(
            scalar(
                &database,
                "SELECT COUNT(*) FROM copy_claims WHERE last_complete_scan_id = 'scan_unreadable'"
            ),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn scanner_preserves_non_utf8_path_identity() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().unwrap();
        let fixture = temp.path().join("files");
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join(OsString::from_vec(vec![b'f', 0x80])), b"bytes").unwrap();
        let (store, database) = setup(&temp);
        scanner_with_exclusions(
            &store,
            &database,
            &fixture,
            "scan_non_utf8",
            "job_non_utf8",
            Vec::new(),
        )
        .run()
        .unwrap();
        let connection = Connection::open(database.path()).unwrap();
        let (encoding, bytes): (String, Vec<u8>) = connection
            .query_row(
                "SELECT logical_path_encoding, logical_path_bytes FROM file_refs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(encoding, "unix_bytes");
        assert_eq!(bytes, vec![b'f', 0x80]);
    }

    fn setup(temp: &TempDir) -> (EventStore, ProjectionDb) {
        let store =
            EventStore::open_or_create(temp.path().join("canonical"), EventStoreConfig::default())
                .unwrap();
        let database = ProjectionDb::open_or_create(
            temp.path().join("archive.db"),
            "arc_scan",
            ProjectionConfig::default(),
        )
        .unwrap();
        seed_topology(&database);
        (store, database)
    }

    fn seed_topology(database: &ProjectionDb) {
        let connection = Connection::open(database.path()).unwrap();
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             INSERT INTO collections(collection_id, display_name, status, last_event_id)
             VALUES ('collection_fixture', 'Fixture', 'active', 'seed');
             INSERT INTO devices(
                device_id, display_name, device_kind, identity_state, status,
                expected_availability, last_event_id
             ) VALUES ('device_fixture', 'Device', 'disk', 'confirmed', 'active', 'online', 'seed');
             INSERT INTO archive_roots(
                archive_root_id, device_id, display_name, root_path_on_device_bytes,
                root_path_encoding, root_path_display, status, created_event_id
             ) VALUES ('root_fixture', 'device_fixture', 'Root', x'2f', 'utf8', '/', 'active', 'seed');
             INSERT INTO locations(
                location_id, display_name, kind, archive_root_id, relative_path_bytes,
                relative_path_encoding, relative_path_display, device_id,
                encryption_state, trust_level, expected_availability, is_writable,
                status, created_event_id, last_event_id
             ) VALUES (
                'location_fixture', 'Files', 'filesystem', 'root_fixture', x'2e',
                'utf8', '.', 'device_fixture', 'unknown', 'trusted', 'online', 0,
                'active', 'seed', 'seed'
             );",
        ).unwrap();
    }

    fn scanner<'a>(
        store: &'a EventStore,
        database: &'a ProjectionDb,
        root: &Path,
        scan_id: &str,
        job_id: &str,
    ) -> LocationScanner<'a> {
        scanner_with_exclusions(
            store,
            database,
            root,
            scan_id,
            job_id,
            vec![PathBuf::from("excluded")],
        )
    }

    fn scanner_with_exclusions<'a>(
        store: &'a EventStore,
        database: &'a ProjectionDb,
        root: &Path,
        scan_id: &str,
        job_id: &str,
        exclusions: Vec<PathBuf>,
    ) -> LocationScanner<'a> {
        scanner_with_mode_and_exclusions(
            store,
            database,
            root,
            scan_id,
            job_id,
            ScanMode::Complete,
            exclusions,
        )
    }

    fn scanner_with_mode<'a>(
        store: &'a EventStore,
        database: &'a ProjectionDb,
        root: &Path,
        scan_id: &str,
        job_id: &str,
        scan_mode: ScanMode,
    ) -> LocationScanner<'a> {
        scanner_with_mode_and_exclusions(
            store,
            database,
            root,
            scan_id,
            job_id,
            scan_mode,
            Vec::new(),
        )
    }

    fn scanner_with_mode_and_exclusions<'a>(
        store: &'a EventStore,
        database: &'a ProjectionDb,
        root: &Path,
        scan_id: &str,
        job_id: &str,
        scan_mode: ScanMode,
        exclusions: Vec<PathBuf>,
    ) -> LocationScanner<'a> {
        LocationScanner::new(
            store,
            database,
            ScanConfig {
                root_path: root.to_path_buf(),
                scan_id: scan_id.to_owned(),
                job_id: job_id.to_owned(),
                collection_id: "collection_fixture".to_owned(),
                location_id: "location_fixture".to_owned(),
                device_id: "device_fixture".to_owned(),
                archive_root_id: "root_fixture".to_owned(),
                location_prefix: None,
                logical_prefix: None,
                exclusions,
                fingerprint_status: "match".to_owned(),
                batch_entries: 2,
                scan_mode,
            },
        )
        .unwrap()
    }

    fn scalar(database: &ProjectionDb, sql: &str) -> i64 {
        Connection::open(database.path())
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    fn text_scalar(database: &ProjectionDb, sql: &str) -> String {
        Connection::open(database.path())
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }
}
