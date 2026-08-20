use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use ulid::Ulid;

const ENVELOPE_VERSION: u32 = 1;
const MANIFEST_VERSION: u32 = 1;
const CHECKPOINT_VERSION: u32 = 1;
const STREAM_ID: &str = "stream_primary";
const DEFAULT_ROLLOVER_EVENTS: u64 = 100_000;
const DEFAULT_MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

pub type Result<T> = std::result::Result<T, EventStoreError>;

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid event-store layout: {0}")]
    InvalidLayout(String),

    #[error("invalid event at {path}:{line}: {message}")]
    InvalidEvent {
        path: PathBuf,
        line: u64,
        message: String,
    },

    #[error("event hash chain failed at {path}:{line}: {message}")]
    HashChain {
        path: PathBuf,
        line: u64,
        message: String,
    },

    #[error("invalid manifest {path}: {message}")]
    InvalidManifest { path: PathBuf, message: String },

    #[error("invalid checkpoint {path}: {message}")]
    InvalidCheckpoint { path: PathBuf, message: String },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("system clock is before the Unix epoch")]
    Clock,

    #[cfg(test)]
    #[error("injected failure at {0}")]
    InjectedFailure(&'static str),
}

impl EventStoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "event_store_io",
            Self::InvalidLayout(_) => "invalid_event_layout",
            Self::InvalidEvent { .. } => "invalid_event",
            Self::HashChain { .. } => "event_hash_chain_failure",
            Self::InvalidManifest { .. } => "invalid_segment_manifest",
            Self::InvalidCheckpoint { .. } => "invalid_checkpoint",
            Self::InvalidInput(_) => "invalid_input",
            Self::Clock => "invalid_system_clock",
            #[cfg(test)]
            Self::InjectedFailure(_) => "injected_failure",
        }
    }
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> EventStoreError {
    EventStoreError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[derive(Debug, Clone)]
pub struct EventStoreConfig {
    pub rollover_events: u64,
    pub max_event_bytes: usize,
    pub actor_id: String,
    pub host_id: String,
}

impl Default for EventStoreConfig {
    fn default() -> Self {
        Self {
            rollover_events: DEFAULT_ROLLOVER_EVENTS,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            actor_id: "local-user".to_owned(),
            host_id: "local-host".to_owned(),
        }
    }
}

impl EventStoreConfig {
    fn validate(&self) -> Result<()> {
        if self.rollover_events == 0 {
            return Err(EventStoreError::InvalidInput(
                "rollover_events must be greater than zero".to_owned(),
            ));
        }
        if self.max_event_bytes == 0 {
            return Err(EventStoreError::InvalidInput(
                "max_event_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.actor_id.is_empty() || self.host_id.is_empty() {
            return Err(EventStoreError::InvalidInput(
                "actor_id and host_id must be non-empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReferences {
    pub job_id: Option<String>,
    pub object_id: Option<String>,
    pub file_ref_id: Option<String>,
    pub copy_claim_id: Option<String>,
    pub location_id: Option<String>,
    pub device_id: Option<String>,
    pub site_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRequest {
    pub event_type: String,
    pub payload: Value,
    pub references: EventReferences,
}

impl EventRequest {
    pub fn new(event_type: impl Into<String>, payload: Value) -> Self {
        Self {
            event_type: event_type.into(),
            payload,
            references: EventReferences::default(),
        }
    }

    pub fn with_references(mut self, references: EventReferences) -> Self {
        self.references = references;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub v: u32,
    pub stream_id: String,
    pub seq: u64,
    pub event_id: String,
    pub event_type: String,
    pub time_utc_ms: u64,
    pub actor_id: String,
    pub host_id: String,
    pub job_id: Option<String>,
    pub object_id: Option<String>,
    pub file_ref_id: Option<String>,
    pub copy_claim_id: Option<String>,
    pub location_id: Option<String>,
    pub device_id: Option<String>,
    pub site_id: Option<String>,
    pub previous_event_hash: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventRecord {
    pub envelope: EventEnvelope,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SegmentManifest {
    pub manifest_v: u32,
    pub stream_id: String,
    pub segment_file: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub first_event_id: String,
    pub last_event_id: String,
    pub last_event_hash: String,
    pub event_count: u64,
    pub segment_size_bytes: u64,
    pub segment_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSegment {
    pub file: String,
    pub manifest: String,
    pub segment_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub checkpoint_v: u32,
    pub checkpoint_id: String,
    pub created_time_utc_ms: u64,
    pub stream_id: String,
    pub event_first_seq: u64,
    pub event_last_seq: u64,
    pub event_last_hash: String,
    pub segments: Vec<CheckpointSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSegment {
    pub segment_file: String,
    pub first_seq: u64,
    pub last_seq: Option<u64>,
    pub event_count: u64,
    pub manifest: Option<SegmentManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub stream_id: String,
    pub last_seq: u64,
    pub last_event_hash: Option<String>,
    pub segments: Vec<VerifiedSegment>,
    pub checkpoints: Vec<Checkpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    pub applied_seq: u64,
    pub applied_event_hash: Option<String>,
    pub segment_first_seq: Option<u64>,
    pub next_offset: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PositionedEvent {
    pub record: EventRecord,
    pub segment_first_seq: u64,
    pub next_offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventReadStats {
    pub segments_opened: u64,
    pub lines_read: u64,
    pub events_returned: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventBatch {
    pub events: Vec<PositionedEvent>,
    pub next_cursor: EventCursor,
    pub eof: bool,
    pub stats: EventReadStats,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppendStats {
    pub batches: u64,
    pub events_appended: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
}

#[derive(Debug, Clone)]
struct Layout {
    root: PathBuf,
    event_dir: PathBuf,
    manifest_dir: PathBuf,
    checkpoint_dir: PathBuf,
    lock_path: PathBuf,
}

impl Layout {
    fn new(root: PathBuf) -> Self {
        Self {
            event_dir: root.join("events").join(STREAM_ID),
            manifest_dir: root.join("manifests").join(STREAM_ID),
            checkpoint_dir: root.join("checkpoints"),
            lock_path: root.join(".archive-ledger-writer.lock"),
            root,
        }
    }

    fn segment_path(&self, first_seq: u64) -> PathBuf {
        self.event_dir.join(segment_filename(first_seq))
    }

    fn manifest_path(&self, first_seq: u64) -> PathBuf {
        self.manifest_dir.join(manifest_filename(first_seq))
    }

    fn checkpoint_path(&self, checkpoint_id: &str) -> PathBuf {
        self.checkpoint_dir.join(format!("{checkpoint_id}.json"))
    }
}

#[derive(Debug)]
pub struct EventStore {
    layout: Layout,
    config: EventStoreConfig,
    #[cfg(test)]
    fault: std::sync::Mutex<Option<FaultPoint>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    SegmentCreated,
    EventLineWritten,
    SegmentFileSynced,
    SegmentDirectorySynced,
    ClosedSegmentSynced,
    ManifestTempSynced,
    ManifestRenamed,
    ManifestDirectorySynced,
    CheckpointPrefixClosed,
    CheckpointEventClosed,
    CheckpointTempSynced,
    CheckpointRenamed,
    CheckpointDirectorySynced,
}

impl FaultPoint {
    #[cfg(test)]
    fn name(self) -> &'static str {
        match self {
            Self::SegmentCreated => "after_segment_create",
            Self::EventLineWritten => "after_event_line_write",
            Self::SegmentFileSynced => "after_segment_file_sync",
            Self::SegmentDirectorySynced => "after_segment_directory_sync",
            Self::ClosedSegmentSynced => "after_closed_segment_sync",
            Self::ManifestTempSynced => "after_manifest_temp_sync",
            Self::ManifestRenamed => "after_manifest_rename",
            Self::ManifestDirectorySynced => "after_manifest_directory_sync",
            Self::CheckpointPrefixClosed => "after_checkpoint_prefix_closed",
            Self::CheckpointEventClosed => "after_checkpoint_event_closed",
            Self::CheckpointTempSynced => "after_checkpoint_temp_sync",
            Self::CheckpointRenamed => "after_checkpoint_rename",
            Self::CheckpointDirectorySynced => "after_checkpoint_directory_sync",
        }
    }
}

impl EventStore {
    pub fn open_or_create(root: impl AsRef<Path>, config: EventStoreConfig) -> Result<Self> {
        config.validate()?;
        let layout = Layout::new(root.as_ref().to_path_buf());
        create_dir_all(&layout.root)?;
        create_dir_all(&layout.event_dir)?;
        create_dir_all(&layout.manifest_dir)?;
        create_dir_all(&layout.checkpoint_dir)?;
        if let Some(parent) = layout.event_dir.parent() {
            sync_directory(parent)?;
        }
        if let Some(parent) = layout.manifest_dir.parent() {
            sync_directory(parent)?;
        }
        sync_directory(&layout.root)?;
        sync_directory(&layout.event_dir)?;
        sync_directory(&layout.manifest_dir)?;
        sync_directory(&layout.checkpoint_dir)?;

        let store = Self {
            layout,
            config,
            #[cfg(test)]
            fault: std::sync::Mutex::new(None),
        };
        store.with_writer_lock(|| {
            let _ = store.complete_pending_checkpoint_locked()?;
            Ok(())
        })?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.layout.root
    }

    pub fn archive_id(&self) -> Result<String> {
        let batch = self.read_batch(&EventCursor::default(), 1, self.config.max_event_bytes)?;
        let record = batch.events.first().ok_or_else(|| {
            EventStoreError::InvalidLayout(
                "event stream has no archive_initialized event".to_owned(),
            )
        })?;
        if record.record.envelope.event_type != "archive_initialized" {
            return Err(EventStoreError::InvalidLayout(
                "the first event is not archive_initialized".to_owned(),
            ));
        }
        record.record.envelope.payload["archive_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                EventStoreError::InvalidLayout(
                    "archive_initialized lacks a valid archive_id".to_owned(),
                )
            })
    }

    pub fn append(&self, request: EventRequest) -> Result<EventRecord> {
        let mut records = self.append_batch(vec![request])?;
        records.pop().ok_or_else(|| {
            EventStoreError::InvalidLayout("append returned no event record".to_owned())
        })
    }

    pub fn append_batch(&self, requests: Vec<EventRequest>) -> Result<Vec<EventRecord>> {
        validate_public_batch(&requests)?;

        self.with_writer_lock(|| {
            let _ = self.complete_pending_checkpoint_locked()?;
            self.append_batch_locked(requests, false)
        })
    }

    pub fn append_batches<I>(&self, batches: I) -> Result<AppendStats>
    where
        I: IntoIterator<Item = Vec<EventRequest>>,
    {
        self.with_writer_lock(|| {
            let _ = self.complete_pending_checkpoint_locked()?;
            let mut state = self.inspect_writer_state(true)?;
            if state
                .open
                .as_ref()
                .is_some_and(|open| open.event_count >= self.config.rollover_events)
            {
                self.close_open_segment(&mut state)?;
            }
            let mut stats = AppendStats::default();
            for requests in batches {
                validate_public_batch(&requests)?;
                let records = self.append_batch_to_state(&mut state, requests, false)?;
                if let Some(first) = records.first() {
                    stats.first_seq.get_or_insert(first.envelope.seq);
                }
                if let Some(last) = records.last() {
                    stats.last_seq = Some(last.envelope.seq);
                }
                stats.batches += 1;
                stats.events_appended += u64::try_from(records.len()).map_err(|_| {
                    EventStoreError::InvalidLayout("append count exceeds u64".to_owned())
                })?;
            }
            if stats.batches == 0 {
                return Err(EventStoreError::InvalidInput(
                    "append_batches requires at least one batch".to_owned(),
                ));
            }
            Ok(stats)
        })
    }

    pub fn read_batch(
        &self,
        cursor: &EventCursor,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<EventBatch> {
        if max_events == 0 || max_bytes == 0 {
            return Err(EventStoreError::InvalidInput(
                "event and byte batch limits must be greater than zero".to_owned(),
            ));
        }
        if cursor.applied_seq == 0 {
            if cursor.applied_event_hash.is_some()
                || cursor.segment_first_seq.is_some()
                || cursor.next_offset != 0
            {
                return Err(EventStoreError::InvalidInput(
                    "an empty cursor cannot contain a hash or segment position".to_owned(),
                ));
            }
        } else if cursor
            .applied_event_hash
            .as_deref()
            .is_none_or(|hash| !is_blake3_identifier(hash))
        {
            return Err(EventStoreError::InvalidInput(
                "a non-empty cursor requires a valid applied event hash".to_owned(),
            ));
        }

        self.with_reader_lock(|| self.read_batch_locked(cursor, max_events, max_bytes))
    }

    pub fn create_checkpoint(&self) -> Result<Checkpoint> {
        self.with_writer_lock(|| self.create_checkpoint_locked())
    }

    pub fn verify(&self) -> Result<VerificationReport> {
        self.with_writer_lock(|| self.verify_locked(true).map(|verified| verified.report))
    }

    fn with_writer_lock<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.layout.lock_path)
            .map_err(|source| io_error("open writer lock", &self.layout.lock_path, source))?;
        lock_file
            .lock_exclusive()
            .map_err(|source| io_error("acquire writer lock", &self.layout.lock_path, source))?;

        let result = action();
        let unlock_result = FileExt::unlock(&lock_file)
            .map_err(|source| io_error("release writer lock", &self.layout.lock_path, source));

        match (result, unlock_result) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    fn with_reader_lock<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.layout.lock_path)
            .map_err(|source| io_error("open reader lock", &self.layout.lock_path, source))?;
        FileExt::lock_shared(&lock_file)
            .map_err(|source| io_error("acquire reader lock", &self.layout.lock_path, source))?;

        let result = action();
        let unlock_result = FileExt::unlock(&lock_file)
            .map_err(|source| io_error("release reader lock", &self.layout.lock_path, source));

        match (result, unlock_result) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    #[cfg(test)]
    fn inject_once(&self, point: FaultPoint) {
        *self.fault.lock().expect("fault mutex poisoned") = Some(point);
    }

    #[cfg(test)]
    fn maybe_fail(&self, point: FaultPoint) -> Result<()> {
        let mut fault = self.fault.lock().expect("fault mutex poisoned");
        if *fault == Some(point) {
            *fault = None;
            return Err(EventStoreError::InjectedFailure(point.name()));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn maybe_fail(&self, _point: FaultPoint) -> Result<()> {
        Ok(())
    }
}

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| io_error("create directory", path, source))
}

fn validate_public_batch(requests: &[EventRequest]) -> Result<()> {
    if requests.is_empty() {
        return Err(EventStoreError::InvalidInput(
            "an append batch must contain at least one event".to_owned(),
        ));
    }
    if requests
        .iter()
        .any(|request| request.event_type == "checkpoint_created")
    {
        return Err(EventStoreError::InvalidInput(
            "checkpoint_created may only be emitted by create_checkpoint".to_owned(),
        ));
    }
    Ok(())
}

fn segment_filename(first_seq: u64) -> String {
    format!("seg-{first_seq:012}.jsonl")
}

fn manifest_filename(first_seq: u64) -> String {
    format!("seg-{first_seq:012}.manifest.json")
}

fn parse_segment_filename(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("seg-")?.strip_suffix(".jsonl")?;
    if digits.len() != 12 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn parse_manifest_filename(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("seg-")?.strip_suffix(".manifest.json")?;
    if digits.len() != 12 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn event_hash(line_without_newline: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(line_without_newline).to_hex())
}

fn is_blake3_identifier(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_prefixed_lowercase_ulid(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|ulid_text| {
        ulid_text == ulid_text.to_ascii_lowercase() && Ulid::from_string(ulid_text).is_ok()
    })
}

fn file_blake3(hasher: blake3::Hasher) -> String {
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn now_utc_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EventStoreError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| EventStoreError::Clock)
}

fn new_prefixed_ulid(prefix: &str) -> String {
    format!("{prefix}{}", Ulid::new().to_string().to_ascii_lowercase())
}

fn relative_segment_path(first_seq: u64) -> String {
    format!("events/{STREAM_ID}/{}", segment_filename(first_seq))
}

fn relative_manifest_path(first_seq: u64) -> String {
    format!("manifests/{STREAM_ID}/{}", manifest_filename(first_seq))
}

fn relative_checkpoint_path(checkpoint_id: &str) -> String {
    format!("checkpoints/{checkpoint_id}.json")
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let directory =
            File::open(path).map_err(|source| io_error("open directory for sync", path, source))?;
        directory
            .sync_all()
            .map_err(|source| io_error("sync directory", path, source))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, kind: &'static str) -> Result<T> {
    let file = File::open(path).map_err(|source| io_error("open JSON file", path, source))?;
    serde_json::from_reader(BufReader::new(file)).map_err(|source| match kind {
        "manifest" => EventStoreError::InvalidManifest {
            path: path.to_path_buf(),
            message: source.to_string(),
        },
        _ => EventStoreError::InvalidCheckpoint {
            path: path.to_path_buf(),
            message: source.to_string(),
        },
    })
}

fn list_canonical_files(
    directory: &Path,
    parser: fn(&str) -> Option<u64>,
    kind: &'static str,
) -> Result<BTreeMap<u64, PathBuf>> {
    let mut files = BTreeMap::new();
    let entries = fs::read_dir(directory)
        .map_err(|source| io_error("read canonical directory", directory, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read directory entry", directory, source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| io_error("read directory entry type", entry.path(), source))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            EventStoreError::InvalidLayout(format!(
                "{kind} directory contains a non-UTF-8 filename"
            ))
        })?;
        if name.starts_with('.') && name.ends_with(".tmp") {
            continue;
        }
        if !file_type.is_file() {
            return Err(EventStoreError::InvalidLayout(format!(
                "unexpected non-file entry in {kind} directory: {}",
                entry.path().display()
            )));
        }
        let first_seq = parser(name).ok_or_else(|| {
            EventStoreError::InvalidLayout(format!(
                "unexpected file in {kind} directory: {}",
                entry.path().display()
            ))
        })?;
        if files.insert(first_seq, entry.path()).is_some() {
            return Err(EventStoreError::InvalidLayout(format!(
                "duplicate {kind} for first sequence {first_seq}"
            )));
        }
    }
    Ok(files)
}

fn parse_event_line(path: &Path, line_number: u64, line: &[u8]) -> Result<EventEnvelope> {
    serde_json::from_slice(line).map_err(|source| EventStoreError::InvalidEvent {
        path: path.to_path_buf(),
        line: line_number,
        message: source.to_string(),
    })
}

fn validate_event(
    path: &Path,
    line_number: u64,
    envelope: &EventEnvelope,
    expected_seq: u64,
    expected_previous_hash: Option<&str>,
) -> Result<()> {
    if envelope.v != ENVELOPE_VERSION {
        return Err(EventStoreError::InvalidEvent {
            path: path.to_path_buf(),
            line: line_number,
            message: format!("unsupported envelope version {}", envelope.v),
        });
    }
    if envelope.stream_id != STREAM_ID {
        return Err(EventStoreError::InvalidEvent {
            path: path.to_path_buf(),
            line: line_number,
            message: format!("unexpected stream_id {}", envelope.stream_id),
        });
    }
    if envelope.seq != expected_seq {
        return Err(EventStoreError::HashChain {
            path: path.to_path_buf(),
            line: line_number,
            message: format!("expected sequence {expected_seq}, got {}", envelope.seq),
        });
    }
    let actual_previous = envelope.previous_event_hash.as_deref();
    if actual_previous != expected_previous_hash {
        return Err(EventStoreError::HashChain {
            path: path.to_path_buf(),
            line: line_number,
            message: format!(
                "expected previous hash {:?}, got {:?}",
                expected_previous_hash, actual_previous
            ),
        });
    }
    if envelope.event_type.is_empty()
        || envelope.actor_id.is_empty()
        || envelope.host_id.is_empty()
        || !envelope.payload.is_object()
    {
        return Err(EventStoreError::InvalidEvent {
            path: path.to_path_buf(),
            line: line_number,
            message:
                "event_type, actor_id, and host_id must be non-empty and payload must be an object"
                    .to_owned(),
        });
    }
    if !is_prefixed_lowercase_ulid(&envelope.event_id, "evt_") {
        return Err(EventStoreError::InvalidEvent {
            path: path.to_path_buf(),
            line: line_number,
            message: "event_id must be evt_ plus a lowercase ULID".to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct SegmentScan {
    first_seq: u64,
    last_seq: Option<u64>,
    first_event_id: Option<String>,
    last_event_id: Option<String>,
    last_event_hash: Option<String>,
    event_count: u64,
    segment_size_bytes: u64,
    segment_blake3: String,
    checkpoint_events: Vec<EventRecord>,
}

fn scan_segment(
    path: &Path,
    first_seq: u64,
    expected_previous_hash: Option<&str>,
    max_event_bytes: usize,
    allow_empty: bool,
) -> Result<SegmentScan> {
    let file = File::open(path).map_err(|source| io_error("open segment", path, source))?;
    let mut reader = BufReader::new(file);
    let mut raw_line = Vec::new();
    let mut line_number = 0_u64;
    let mut expected_seq = first_seq;
    let mut previous_hash = expected_previous_hash.map(ToOwned::to_owned);
    let mut file_hasher = blake3::Hasher::new();
    let mut size_bytes = 0_u64;
    let mut first_event_id = None;
    let mut last_event_id = None;
    let mut checkpoint_events = Vec::new();

    loop {
        raw_line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut raw_line)
            .map_err(|source| io_error("read segment", path, source))?;
        if bytes_read == 0 {
            break;
        }
        line_number += 1;
        if !raw_line.ends_with(b"\n") {
            return Err(EventStoreError::InvalidEvent {
                path: path.to_path_buf(),
                line: line_number,
                message: "event line is not newline terminated".to_owned(),
            });
        }
        let line = &raw_line[..raw_line.len() - 1];
        if line.len() > max_event_bytes {
            return Err(EventStoreError::InvalidEvent {
                path: path.to_path_buf(),
                line: line_number,
                message: format!("event exceeds {max_event_bytes} bytes"),
            });
        }
        let envelope = parse_event_line(path, line_number, line)?;
        validate_event(
            path,
            line_number,
            &envelope,
            expected_seq,
            previous_hash.as_deref(),
        )?;
        let hash = event_hash(line);
        if first_event_id.is_none() {
            first_event_id = Some(envelope.event_id.clone());
        }
        last_event_id = Some(envelope.event_id.clone());
        if envelope.event_type == "checkpoint_created" {
            checkpoint_events.push(EventRecord {
                envelope: envelope.clone(),
                event_hash: hash.clone(),
            });
        }
        previous_hash = Some(hash);
        expected_seq += 1;
        size_bytes += u64::try_from(raw_line.len())
            .map_err(|_| EventStoreError::InvalidLayout("segment size exceeds u64".to_owned()))?;
        file_hasher.update(&raw_line);
    }

    let event_count = expected_seq - first_seq;
    if event_count == 0 && !allow_empty {
        return Err(EventStoreError::InvalidLayout(format!(
            "closed segment {} is empty",
            path.display()
        )));
    }

    Ok(SegmentScan {
        first_seq,
        last_seq: (event_count > 0).then_some(expected_seq - 1),
        first_event_id,
        last_event_id,
        last_event_hash: if event_count > 0 { previous_hash } else { None },
        event_count,
        segment_size_bytes: size_bytes,
        segment_blake3: file_blake3(file_hasher),
        checkpoint_events,
    })
}

#[derive(Debug)]
struct OpenSegment {
    first_seq: u64,
    path: PathBuf,
    event_count: u64,
    newly_created: bool,
}

#[derive(Debug)]
struct WriterState {
    closed: Vec<SegmentManifest>,
    open: Option<OpenSegment>,
    next_seq: u64,
    previous_event_hash: Option<String>,
}

#[derive(Debug)]
struct StreamSegment {
    first_seq: u64,
    path: PathBuf,
    manifest: Option<SegmentManifest>,
}

impl EventStore {
    fn stream_segments(&self) -> Result<Vec<StreamSegment>> {
        let segments = list_canonical_files(
            &self.layout.event_dir,
            parse_segment_filename,
            "event segment",
        )?;
        let manifest_paths = list_canonical_files(
            &self.layout.manifest_dir,
            parse_manifest_filename,
            "segment manifest",
        )?;
        for first_seq in manifest_paths.keys() {
            if !segments.contains_key(first_seq) {
                return Err(EventStoreError::InvalidLayout(format!(
                    "manifest for sequence {first_seq} has no segment"
                )));
            }
        }

        let mut result = Vec::with_capacity(segments.len());
        let mut expected_first_seq = 1_u64;
        let segment_count = segments.len();
        for (index, (first_seq, segment_path)) in segments.into_iter().enumerate() {
            if first_seq != expected_first_seq {
                return Err(EventStoreError::InvalidLayout(format!(
                    "expected segment starting at {expected_first_seq}, found {first_seq}"
                )));
            }
            let manifest = if let Some(manifest_path) = manifest_paths.get(&first_seq) {
                let manifest: SegmentManifest = read_json(manifest_path, "manifest")?;
                self.validate_manifest_shape(&manifest, manifest_path, &segment_path, first_seq)?;
                expected_first_seq = manifest.last_seq.checked_add(1).ok_or_else(|| {
                    EventStoreError::InvalidLayout("event sequence overflow".to_owned())
                })?;
                Some(manifest)
            } else {
                if index + 1 != segment_count {
                    return Err(EventStoreError::InvalidLayout(format!(
                        "non-tail segment {first_seq} lacks a manifest"
                    )));
                }
                None
            };
            result.push(StreamSegment {
                first_seq,
                path: segment_path,
                manifest,
            });
        }
        Ok(result)
    }

    fn read_batch_locked(
        &self,
        cursor: &EventCursor,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<EventBatch> {
        let segments = self.stream_segments()?;
        let target_seq = cursor
            .applied_seq
            .checked_add(1)
            .ok_or_else(|| EventStoreError::InvalidLayout("event sequence overflow".to_owned()))?;
        let mut first_index = segments.len();
        for (index, segment) in segments.iter().enumerate() {
            let can_contain_target = segment
                .manifest
                .as_ref()
                .map_or(target_seq >= segment.first_seq, |manifest| {
                    target_seq >= segment.first_seq && target_seq <= manifest.last_seq
                });
            if can_contain_target {
                first_index = index;
                break;
            }
            if segment
                .manifest
                .as_ref()
                .is_some_and(|manifest| target_seq == manifest.last_seq.saturating_add(1))
                && index + 1 == segments.len()
            {
                first_index = segments.len();
            }
        }

        let mut batch = EventBatch {
            events: Vec::with_capacity(max_events.min(1024)),
            next_cursor: cursor.clone(),
            eof: true,
            stats: EventReadStats::default(),
        };
        if cursor.applied_seq > 0 && first_index > 0 {
            let previous_segment = &segments[first_index - 1];
            if let Some(manifest) = &previous_segment.manifest {
                if manifest.last_seq == cursor.applied_seq
                    && cursor.applied_event_hash.as_deref()
                        != Some(manifest.last_event_hash.as_str())
                {
                    return Err(EventStoreError::HashChain {
                        path: previous_segment.path.clone(),
                        line: manifest.event_count,
                        message: "stream cursor hash does not match preceding manifest".to_owned(),
                    });
                }
            }
        }
        let mut returned_bytes = 0_usize;
        let mut previous_manifest_hash: Option<&str> = if first_index == 0 {
            None
        } else {
            segments[first_index - 1]
                .manifest
                .as_ref()
                .map(|manifest| manifest.last_event_hash.as_str())
        };

        for segment in segments.iter().skip(first_index) {
            let use_cursor_offset = cursor.segment_first_seq == Some(segment.first_seq)
                && cursor.next_offset > 0
                && target_seq > segment.first_seq;
            let start_offset = if use_cursor_offset {
                cursor.next_offset
            } else {
                0
            };
            let mut expected_seq = if use_cursor_offset {
                target_seq
            } else {
                segment.first_seq
            };
            let mut previous_hash = if use_cursor_offset {
                cursor.applied_event_hash.clone()
            } else {
                previous_manifest_hash.map(ToOwned::to_owned)
            };

            let mut file = File::open(&segment.path)
                .map_err(|source| io_error("open segment for streaming", &segment.path, source))?;
            if start_offset > 0 {
                let length = file
                    .metadata()
                    .map_err(|source| io_error("read segment metadata", &segment.path, source))?
                    .len();
                if start_offset > length {
                    return Err(EventStoreError::InvalidLayout(format!(
                        "stream cursor offset {start_offset} exceeds {} bytes in {}",
                        length,
                        segment.path.display()
                    )));
                }
                file.seek(SeekFrom::Start(start_offset - 1))
                    .map_err(|source| {
                        io_error("seek before stream cursor", &segment.path, source)
                    })?;
                let mut preceding = [0_u8; 1];
                file.read_exact(&mut preceding).map_err(|source| {
                    io_error("read before stream cursor", &segment.path, source)
                })?;
                if preceding[0] != b'\n' {
                    return Err(EventStoreError::InvalidLayout(format!(
                        "stream cursor does not point to an event boundary in {}",
                        segment.path.display()
                    )));
                }
            }
            file.seek(SeekFrom::Start(start_offset))
                .map_err(|source| io_error("seek stream cursor", &segment.path, source))?;
            let mut reader = BufReader::new(file);
            let mut raw_line = Vec::new();
            let mut offset = start_offset;
            batch.stats.segments_opened += 1;

            loop {
                raw_line.clear();
                let bytes_read = reader
                    .read_until(b'\n', &mut raw_line)
                    .map_err(|source| io_error("stream segment", &segment.path, source))?;
                if bytes_read == 0 {
                    break;
                }
                batch.stats.lines_read += 1;
                if !raw_line.ends_with(b"\n") {
                    return Err(EventStoreError::InvalidEvent {
                        path: segment.path.clone(),
                        line: expected_seq.saturating_sub(segment.first_seq) + 1,
                        message: "event line is not newline terminated".to_owned(),
                    });
                }
                let line = &raw_line[..raw_line.len() - 1];
                if line.len() > self.config.max_event_bytes {
                    return Err(EventStoreError::InvalidEvent {
                        path: segment.path.clone(),
                        line: expected_seq.saturating_sub(segment.first_seq) + 1,
                        message: format!("event exceeds {} bytes", self.config.max_event_bytes),
                    });
                }
                let line_number = expected_seq.saturating_sub(segment.first_seq) + 1;
                let envelope = parse_event_line(&segment.path, line_number, line)?;
                validate_event(
                    &segment.path,
                    line_number,
                    &envelope,
                    expected_seq,
                    previous_hash.as_deref(),
                )?;
                let hash = event_hash(line);
                let next_offset = offset
                    .checked_add(u64::try_from(bytes_read).map_err(|_| {
                        EventStoreError::InvalidLayout("stream offset exceeds u64".to_owned())
                    })?)
                    .ok_or_else(|| {
                        EventStoreError::InvalidLayout("stream offset overflow".to_owned())
                    })?;

                if envelope.seq == cursor.applied_seq
                    && cursor.applied_event_hash.as_deref() != Some(hash.as_str())
                {
                    return Err(EventStoreError::HashChain {
                        path: segment.path.clone(),
                        line: line_number,
                        message: "stream cursor hash does not match canonical event".to_owned(),
                    });
                }
                if envelope.seq > cursor.applied_seq {
                    if !batch.events.is_empty()
                        && returned_bytes.saturating_add(raw_line.len()) > max_bytes
                    {
                        batch.eof = false;
                        return Ok(batch);
                    }
                    returned_bytes = returned_bytes.saturating_add(raw_line.len());
                    batch.next_cursor = EventCursor {
                        applied_seq: envelope.seq,
                        applied_event_hash: Some(hash.clone()),
                        segment_first_seq: Some(segment.first_seq),
                        next_offset,
                    };
                    batch.events.push(PositionedEvent {
                        record: EventRecord {
                            envelope,
                            event_hash: hash.clone(),
                        },
                        segment_first_seq: segment.first_seq,
                        next_offset,
                    });
                    batch.stats.events_returned += 1;
                    if batch.events.len() == max_events {
                        batch.eof = false;
                        return Ok(batch);
                    }
                }

                offset = next_offset;
                previous_hash = Some(hash);
                expected_seq = expected_seq.checked_add(1).ok_or_else(|| {
                    EventStoreError::InvalidLayout("event sequence overflow".to_owned())
                })?;
            }

            if let Some(manifest) = &segment.manifest {
                if expected_seq != manifest.last_seq.saturating_add(1) {
                    return Err(EventStoreError::InvalidManifest {
                        path: self.layout.manifest_path(segment.first_seq),
                        message: "streamed event count does not match manifest range".to_owned(),
                    });
                }
                previous_manifest_hash = Some(manifest.last_event_hash.as_str());
            }
        }
        Ok(batch)
    }

    fn inspect_writer_state(&self, recover_tail: bool) -> Result<WriterState> {
        let segments = list_canonical_files(
            &self.layout.event_dir,
            parse_segment_filename,
            "event segment",
        )?;
        let manifest_paths = list_canonical_files(
            &self.layout.manifest_dir,
            parse_manifest_filename,
            "segment manifest",
        )?;
        if recover_tail && !manifest_paths.is_empty() {
            sync_directory(&self.layout.manifest_dir)?;
        }

        for first_seq in manifest_paths.keys() {
            if !segments.contains_key(first_seq) {
                return Err(EventStoreError::InvalidLayout(format!(
                    "manifest for sequence {first_seq} has no segment"
                )));
            }
        }

        let unmanifested: Vec<u64> = segments
            .keys()
            .filter(|first_seq| !manifest_paths.contains_key(first_seq))
            .copied()
            .collect();
        if unmanifested.len() > 1 {
            return Err(EventStoreError::InvalidLayout(format!(
                "more than one unmanifested segment: {unmanifested:?}"
            )));
        }
        if let Some(first_seq) = unmanifested.first() {
            if segments.keys().next_back() != Some(first_seq) {
                return Err(EventStoreError::InvalidLayout(format!(
                    "non-tail segment {first_seq} lacks a manifest"
                )));
            }
        }

        let mut expected_first_seq = 1_u64;
        let mut previous_event_hash = None;
        let mut closed = Vec::new();
        let mut open = None;

        for (first_seq, segment_path) in &segments {
            if *first_seq != expected_first_seq {
                return Err(EventStoreError::InvalidLayout(format!(
                    "expected segment starting at {expected_first_seq}, found {first_seq}"
                )));
            }

            if let Some(manifest_path) = manifest_paths.get(first_seq) {
                let manifest: SegmentManifest = read_json(manifest_path, "manifest")?;
                self.validate_manifest_shape(&manifest, manifest_path, segment_path, *first_seq)?;
                expected_first_seq = manifest.last_seq.checked_add(1).ok_or_else(|| {
                    EventStoreError::InvalidLayout("event sequence overflow".to_owned())
                })?;
                previous_event_hash = Some(manifest.last_event_hash.clone());
                closed.push(manifest);
            } else {
                if recover_tail {
                    self.recover_open_tail(
                        segment_path,
                        *first_seq,
                        previous_event_hash.as_deref(),
                    )?;
                }
                let scan = scan_segment(
                    segment_path,
                    *first_seq,
                    previous_event_hash.as_deref(),
                    self.config.max_event_bytes,
                    true,
                )?;
                let next_seq = scan.last_seq.map_or(*first_seq, |seq| seq + 1);
                if let Some(hash) = scan.last_event_hash {
                    previous_event_hash = Some(hash);
                }
                expected_first_seq = next_seq;
                open = Some(OpenSegment {
                    first_seq: *first_seq,
                    path: segment_path.clone(),
                    event_count: scan.event_count,
                    newly_created: false,
                });
            }
        }

        Ok(WriterState {
            closed,
            open,
            next_seq: expected_first_seq,
            previous_event_hash,
        })
    }

    fn validate_manifest_shape(
        &self,
        manifest: &SegmentManifest,
        manifest_path: &Path,
        segment_path: &Path,
        first_seq: u64,
    ) -> Result<()> {
        let invalid = |message: String| EventStoreError::InvalidManifest {
            path: manifest_path.to_path_buf(),
            message,
        };
        if manifest.manifest_v != MANIFEST_VERSION {
            return Err(invalid(format!(
                "unsupported manifest version {}",
                manifest.manifest_v
            )));
        }
        if manifest.stream_id != STREAM_ID {
            return Err(invalid(format!(
                "unexpected stream_id {}",
                manifest.stream_id
            )));
        }
        if manifest.segment_file != relative_segment_path(first_seq) {
            return Err(invalid(format!(
                "segment_file must be {}",
                relative_segment_path(first_seq)
            )));
        }
        if manifest.first_seq != first_seq || manifest.event_count == 0 {
            return Err(invalid(
                "first sequence/count does not match filename".to_owned(),
            ));
        }
        let expected_last = first_seq
            .checked_add(manifest.event_count - 1)
            .ok_or_else(|| invalid("manifest range overflows u64".to_owned()))?;
        if manifest.last_seq != expected_last {
            return Err(invalid(format!(
                "last_seq {} does not equal computed {}",
                manifest.last_seq, expected_last
            )));
        }
        if !is_prefixed_lowercase_ulid(&manifest.first_event_id, "evt_")
            || !is_prefixed_lowercase_ulid(&manifest.last_event_id, "evt_")
        {
            return Err(invalid(
                "first_event_id and last_event_id must be evt_ plus lowercase ULIDs".to_owned(),
            ));
        }
        if !is_blake3_identifier(&manifest.last_event_hash)
            || !is_blake3_identifier(&manifest.segment_blake3)
        {
            return Err(invalid(
                "last_event_hash and segment_blake3 must be lowercase BLAKE3 identifiers"
                    .to_owned(),
            ));
        }
        let actual_size = fs::metadata(segment_path)
            .map_err(|source| io_error("read segment metadata", segment_path, source))?
            .len();
        if actual_size != manifest.segment_size_bytes {
            return Err(invalid(format!(
                "segment size is {actual_size}, manifest says {}",
                manifest.segment_size_bytes
            )));
        }
        Ok(())
    }

    fn recover_open_tail(
        &self,
        path: &Path,
        first_seq: u64,
        expected_previous_hash: Option<&str>,
    ) -> Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| io_error("open tail for recovery", path, source))?;
        let reader_file = file
            .try_clone()
            .map_err(|source| io_error("clone tail handle", path, source))?;
        let mut reader = BufReader::new(reader_file);
        let mut raw_line = Vec::new();
        let mut line_number = 0_u64;
        let mut expected_seq = first_seq;
        let mut previous_hash = expected_previous_hash.map(ToOwned::to_owned);
        let mut line_start = 0_u64;

        loop {
            raw_line.clear();
            let bytes_read = reader
                .read_until(b'\n', &mut raw_line)
                .map_err(|source| io_error("read tail for recovery", path, source))?;
            if bytes_read == 0 {
                break;
            }
            line_number += 1;
            let terminated = raw_line.ends_with(b"\n");
            let line = if terminated {
                &raw_line[..raw_line.len() - 1]
            } else {
                &raw_line[..]
            };
            if line.len() > self.config.max_event_bytes {
                return Err(EventStoreError::InvalidEvent {
                    path: path.to_path_buf(),
                    line: line_number,
                    message: format!("event exceeds {} bytes", self.config.max_event_bytes),
                });
            }

            if terminated {
                let envelope = parse_event_line(path, line_number, line)?;
                validate_event(
                    path,
                    line_number,
                    &envelope,
                    expected_seq,
                    previous_hash.as_deref(),
                )?;
                previous_hash = Some(event_hash(line));
                expected_seq += 1;
                line_start += u64::try_from(bytes_read).map_err(|_| {
                    EventStoreError::InvalidLayout("tail offset exceeds u64".to_owned())
                })?;
                continue;
            }

            let generic = match serde_json::from_slice::<Value>(line) {
                Ok(value) => value,
                Err(_) => {
                    file.set_len(line_start)
                        .map_err(|source| io_error("truncate incomplete tail", path, source))?;
                    file.sync_all()
                        .map_err(|source| io_error("sync recovered tail", path, source))?;
                    return Ok(());
                }
            };
            let envelope: EventEnvelope = serde_json::from_value(generic).map_err(|source| {
                EventStoreError::InvalidEvent {
                    path: path.to_path_buf(),
                    line: line_number,
                    message: source.to_string(),
                }
            })?;
            validate_event(
                path,
                line_number,
                &envelope,
                expected_seq,
                previous_hash.as_deref(),
            )?;
            file.seek(SeekFrom::End(0))
                .map_err(|source| io_error("seek recovered tail", path, source))?;
            file.write_all(b"\n")
                .map_err(|source| io_error("complete tail newline", path, source))?;
            file.sync_all()
                .map_err(|source| io_error("sync completed tail", path, source))?;
            return Ok(());
        }

        Ok(())
    }

    fn append_batch_locked(
        &self,
        requests: Vec<EventRequest>,
        force_close_after: bool,
    ) -> Result<Vec<EventRecord>> {
        let mut state = self.inspect_writer_state(true)?;
        if state
            .open
            .as_ref()
            .is_some_and(|open| open.event_count >= self.config.rollover_events)
        {
            self.close_open_segment(&mut state)?;
        }
        self.append_batch_to_state(&mut state, requests, force_close_after)
    }

    fn append_batch_to_state(
        &self,
        state: &mut WriterState,
        requests: Vec<EventRequest>,
        force_close_after: bool,
    ) -> Result<Vec<EventRecord>> {
        for request in &requests {
            self.validate_request(request)?;
        }
        let mut prepared = Vec::with_capacity(requests.len());
        let mut prepared_seq = state.next_seq;
        let mut prepared_previous_hash = state.previous_event_hash.clone();
        for request in requests {
            let envelope = EventEnvelope {
                v: ENVELOPE_VERSION,
                stream_id: STREAM_ID.to_owned(),
                seq: prepared_seq,
                event_id: new_prefixed_ulid("evt_"),
                event_type: request.event_type,
                time_utc_ms: now_utc_ms()?,
                actor_id: self.config.actor_id.clone(),
                host_id: self.config.host_id.clone(),
                job_id: request.references.job_id,
                object_id: request.references.object_id,
                file_ref_id: request.references.file_ref_id,
                copy_claim_id: request.references.copy_claim_id,
                location_id: request.references.location_id,
                device_id: request.references.device_id,
                site_id: request.references.site_id,
                previous_event_hash: prepared_previous_hash,
                payload: request.payload,
            };
            let line = serde_json::to_vec(&envelope).map_err(|source| {
                EventStoreError::InvalidInput(format!("event serialization failed: {source}"))
            })?;
            if line.len() > self.config.max_event_bytes {
                return Err(EventStoreError::InvalidInput(format!(
                    "serialized event exceeds {} bytes",
                    self.config.max_event_bytes
                )));
            }
            let hash = event_hash(&line);
            prepared_seq = prepared_seq.checked_add(1).ok_or_else(|| {
                EventStoreError::InvalidLayout("event sequence overflow".to_owned())
            })?;
            prepared_previous_hash = Some(hash.clone());
            prepared.push((envelope, line, hash));
        }

        let mut records = Vec::with_capacity(prepared.len());
        for (envelope, line, hash) in prepared {
            if state.open.is_none() {
                let path = self.layout.segment_path(state.next_seq);
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|source| io_error("create event segment", &path, source))?;
                self.maybe_fail(FaultPoint::SegmentCreated)?;
                state.open = Some(OpenSegment {
                    first_seq: state.next_seq,
                    path,
                    event_count: 0,
                    newly_created: true,
                });
            }

            let open = state.open.as_mut().expect("open segment was created");
            let mut file = OpenOptions::new()
                .append(true)
                .open(&open.path)
                .map_err(|source| io_error("open segment for append", &open.path, source))?;
            file.write_all(&line)
                .and_then(|_| file.write_all(b"\n"))
                .map_err(|source| io_error("append event", &open.path, source))?;
            self.maybe_fail(FaultPoint::EventLineWritten)?;
            open.event_count += 1;
            state.next_seq = state.next_seq.checked_add(1).ok_or_else(|| {
                EventStoreError::InvalidLayout("event sequence overflow".to_owned())
            })?;
            state.previous_event_hash = Some(hash.clone());
            records.push(EventRecord {
                envelope,
                event_hash: hash,
            });

            if open.event_count == self.config.rollover_events {
                self.close_open_segment(state)?;
            }
        }

        if state.open.is_some() {
            if force_close_after {
                self.close_open_segment(state)?;
            } else {
                self.sync_open_segment(state)?;
            }
        }
        Ok(records)
    }

    fn validate_request(&self, request: &EventRequest) -> Result<()> {
        if request.event_type.is_empty() {
            return Err(EventStoreError::InvalidInput(
                "event_type must be non-empty".to_owned(),
            ));
        }
        if !request.payload.is_object() {
            return Err(EventStoreError::InvalidInput(
                "event payload must be a JSON object".to_owned(),
            ));
        }
        Ok(())
    }

    fn sync_open_segment(&self, state: &mut WriterState) -> Result<()> {
        let Some(open) = state.open.as_mut() else {
            return Ok(());
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&open.path)
            .map_err(|source| io_error("open segment for sync", &open.path, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync event segment", &open.path, source))?;
        if open.newly_created {
            self.maybe_fail(FaultPoint::SegmentFileSynced)?;
        }
        sync_directory(&self.layout.event_dir)?;
        if open.newly_created {
            open.newly_created = false;
            self.maybe_fail(FaultPoint::SegmentDirectorySynced)?;
        }
        Ok(())
    }

    fn close_open_segment(&self, state: &mut WriterState) -> Result<()> {
        let Some(open) = state.open.as_ref() else {
            return Ok(());
        };
        if open.event_count == 0 {
            return Err(EventStoreError::InvalidLayout(format!(
                "cannot close empty segment {}",
                open.path.display()
            )));
        }
        self.sync_open_segment(state)?;
        self.maybe_fail(FaultPoint::ClosedSegmentSynced)?;
        let open = state.open.as_ref().expect("open segment was just synced");
        let prior_hash = state
            .closed
            .last()
            .map(|manifest| manifest.last_event_hash.as_str());
        let scan = scan_segment(
            &open.path,
            open.first_seq,
            prior_hash,
            self.config.max_event_bytes,
            false,
        )?;
        if scan.event_count != open.event_count {
            return Err(EventStoreError::InvalidLayout(format!(
                "open segment count changed from {} to {}",
                open.event_count, scan.event_count
            )));
        }
        let manifest = self.publish_manifest(&scan)?;
        state.previous_event_hash = Some(manifest.last_event_hash.clone());
        state.next_seq = manifest.last_seq + 1;
        state.closed.push(manifest);
        state.open = None;
        Ok(())
    }

    fn publish_manifest(&self, scan: &SegmentScan) -> Result<SegmentManifest> {
        let first_event_id = scan.first_event_id.clone().ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?;
        let last_event_id = scan.last_event_id.clone().ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?;
        let last_seq = scan.last_seq.ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?;
        let last_event_hash = scan.last_event_hash.clone().ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?;
        let manifest = SegmentManifest {
            manifest_v: MANIFEST_VERSION,
            stream_id: STREAM_ID.to_owned(),
            segment_file: relative_segment_path(scan.first_seq),
            first_seq: scan.first_seq,
            last_seq,
            first_event_id,
            last_event_id,
            last_event_hash,
            event_count: scan.event_count,
            segment_size_bytes: scan.segment_size_bytes,
            segment_blake3: scan.segment_blake3.clone(),
        };
        let final_path = self.layout.manifest_path(scan.first_seq);
        if final_path.exists() {
            let existing: SegmentManifest = read_json(&final_path, "manifest")?;
            if existing == manifest {
                return Ok(existing);
            }
            return Err(EventStoreError::InvalidManifest {
                path: final_path,
                message: "existing manifest does not match segment".to_owned(),
            });
        }

        let temp_path = self.layout.manifest_dir.join(format!(
            ".{}.{}.tmp",
            manifest_filename(scan.first_seq),
            Ulid::new().to_string().to_ascii_lowercase()
        ));
        write_new_json(&temp_path, &manifest)?;
        self.maybe_fail(FaultPoint::ManifestTempSynced)?;
        fs::rename(&temp_path, &final_path)
            .map_err(|source| io_error("publish segment manifest", &final_path, source))?;
        self.maybe_fail(FaultPoint::ManifestRenamed)?;
        sync_directory(&self.layout.manifest_dir)?;
        self.maybe_fail(FaultPoint::ManifestDirectorySynced)?;
        Ok(manifest)
    }

    fn verify_locked(&self, include_checkpoints: bool) -> Result<VerifiedStream> {
        let segments = list_canonical_files(
            &self.layout.event_dir,
            parse_segment_filename,
            "event segment",
        )?;
        let manifest_paths = list_canonical_files(
            &self.layout.manifest_dir,
            parse_manifest_filename,
            "segment manifest",
        )?;
        for first_seq in manifest_paths.keys() {
            if !segments.contains_key(first_seq) {
                return Err(EventStoreError::InvalidLayout(format!(
                    "manifest for sequence {first_seq} has no segment"
                )));
            }
        }

        let mut previous_hash = None;
        let mut expected_first_seq = 1_u64;
        let mut verified_segments = Vec::new();
        let mut checkpoint_events = Vec::new();
        let segment_count = segments.len();

        for (index, (first_seq, segment_path)) in segments.iter().enumerate() {
            if *first_seq != expected_first_seq {
                return Err(EventStoreError::InvalidLayout(format!(
                    "expected segment starting at {expected_first_seq}, found {first_seq}"
                )));
            }
            let manifest_path = manifest_paths.get(first_seq);
            if manifest_path.is_none() && index + 1 != segment_count {
                return Err(EventStoreError::InvalidLayout(format!(
                    "non-tail segment {first_seq} lacks a manifest"
                )));
            }
            let scan = scan_segment(
                segment_path,
                *first_seq,
                previous_hash.as_deref(),
                self.config.max_event_bytes,
                manifest_path.is_none(),
            )?;
            checkpoint_events.extend(scan.checkpoint_events.clone());

            let manifest = if let Some(manifest_path) = manifest_path {
                let manifest: SegmentManifest = read_json(manifest_path, "manifest")?;
                self.validate_manifest_shape(&manifest, manifest_path, segment_path, *first_seq)?;
                let expected = manifest_from_scan(&scan)?;
                if manifest != expected {
                    return Err(EventStoreError::InvalidManifest {
                        path: manifest_path.clone(),
                        message: manifest_difference(&manifest, &expected),
                    });
                }
                Some(manifest)
            } else {
                None
            };

            if let Some(last_seq) = scan.last_seq {
                expected_first_seq = last_seq.checked_add(1).ok_or_else(|| {
                    EventStoreError::InvalidLayout("event sequence overflow".to_owned())
                })?;
                previous_hash = scan.last_event_hash.clone();
            }
            verified_segments.push(VerifiedSegment {
                segment_file: relative_segment_path(*first_seq),
                first_seq: *first_seq,
                last_seq: scan.last_seq,
                event_count: scan.event_count,
                manifest,
            });
        }

        let mut report = VerificationReport {
            stream_id: STREAM_ID.to_owned(),
            last_seq: expected_first_seq.saturating_sub(1),
            last_event_hash: previous_hash,
            segments: verified_segments,
            checkpoints: Vec::new(),
        };

        if include_checkpoints {
            report.checkpoints = self.verify_checkpoints(&report, &checkpoint_events)?;
        }
        Ok(VerifiedStream {
            report,
            checkpoint_events,
        })
    }

    fn verify_checkpoints(
        &self,
        report: &VerificationReport,
        checkpoint_events: &[EventRecord],
    ) -> Result<Vec<Checkpoint>> {
        let checkpoint_paths = list_checkpoint_files(&self.layout.checkpoint_dir)?;
        let mut events_by_id = HashMap::new();
        for record in checkpoint_events {
            let payload = parse_checkpoint_event(record)?;
            if events_by_id
                .insert(payload.checkpoint_id.clone(), record)
                .is_some()
            {
                return Err(EventStoreError::InvalidCheckpoint {
                    path: self.layout.checkpoint_path(&payload.checkpoint_id),
                    message: "duplicate checkpoint_id in canonical events".to_owned(),
                });
            }
        }

        for checkpoint_id in events_by_id.keys() {
            if !checkpoint_paths.contains_key(checkpoint_id) {
                return Err(EventStoreError::InvalidCheckpoint {
                    path: self.layout.checkpoint_path(checkpoint_id),
                    message: "checkpoint event has no checkpoint file".to_owned(),
                });
            }
        }
        for checkpoint_id in checkpoint_paths.keys() {
            if !events_by_id.contains_key(checkpoint_id) {
                return Err(EventStoreError::InvalidCheckpoint {
                    path: checkpoint_paths[checkpoint_id].clone(),
                    message: "checkpoint file has no checkpoint event".to_owned(),
                });
            }
        }

        let mut checkpoints = Vec::new();
        for (checkpoint_id, path) in checkpoint_paths {
            let checkpoint: Checkpoint = read_json(&path, "checkpoint")?;
            let record = events_by_id[&checkpoint_id];
            self.validate_checkpoint(&checkpoint, &path, record, report)?;
            checkpoints.push(checkpoint);
        }
        checkpoints.sort_by_key(|checkpoint| checkpoint.event_last_seq);
        Ok(checkpoints)
    }

    fn validate_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        path: &Path,
        record: &EventRecord,
        report: &VerificationReport,
    ) -> Result<()> {
        let payload = parse_checkpoint_event(record)?;
        let invalid = |message: String| EventStoreError::InvalidCheckpoint {
            path: path.to_path_buf(),
            message,
        };
        if checkpoint.checkpoint_v != CHECKPOINT_VERSION {
            return Err(invalid(format!(
                "unsupported checkpoint version {}",
                checkpoint.checkpoint_v
            )));
        }
        if checkpoint.checkpoint_id != payload.checkpoint_id
            || payload.checkpoint_path != relative_checkpoint_path(&payload.checkpoint_id)
        {
            return Err(invalid(
                "checkpoint identity/path does not match its event".to_owned(),
            ));
        }
        if checkpoint.stream_id != STREAM_ID || checkpoint.event_first_seq != 1 {
            return Err(invalid(
                "checkpoint must cover stream_primary from sequence 1".to_owned(),
            ));
        }
        if checkpoint.created_time_utc_ms != record.envelope.time_utc_ms
            || checkpoint.event_last_seq != record.envelope.seq
            || checkpoint.event_last_seq != payload.event_last_seq
            || checkpoint.event_last_hash != record.event_hash
        {
            return Err(invalid(
                "checkpoint tail does not match checkpoint_created".to_owned(),
            ));
        }
        let expected_segments = checkpoint_segments_through(report, checkpoint.event_last_seq)?;
        if checkpoint.segments != expected_segments {
            return Err(invalid(
                "checkpoint segment list is not the exact contiguous closed prefix".to_owned(),
            ));
        }
        Ok(())
    }

    fn create_checkpoint_locked(&self) -> Result<Checkpoint> {
        if let Some(checkpoint) = self.complete_pending_checkpoint_locked()? {
            return Ok(checkpoint);
        }

        let mut state = self.inspect_writer_state(true)?;
        if state.next_seq == 1 {
            return Err(EventStoreError::InvalidInput(
                "cannot checkpoint an empty event stream".to_owned(),
            ));
        }
        if state.open.as_ref().is_some_and(|open| open.event_count > 0) {
            self.close_open_segment(&mut state)?;
        }
        self.maybe_fail(FaultPoint::CheckpointPrefixClosed)?;

        let checkpoint_id = new_prefixed_ulid("chk_");
        let event_last_seq = state.next_seq;
        let checkpoint_path = relative_checkpoint_path(&checkpoint_id);
        let request = EventRequest::new(
            "checkpoint_created",
            json!({
                "checkpoint_id": checkpoint_id,
                "checkpoint_path": checkpoint_path,
                "event_last_seq": event_last_seq,
            }),
        );
        let mut records = self.append_batch_locked(vec![request], true)?;
        let record = records.pop().ok_or_else(|| {
            EventStoreError::InvalidLayout("checkpoint append returned no event".to_owned())
        })?;
        self.maybe_fail(FaultPoint::CheckpointEventClosed)?;
        let verified = self.verify_locked(false)?;
        let checkpoint = build_checkpoint(&verified.report, &record)?;
        self.publish_checkpoint(&checkpoint)?;
        let final_report = self.verify_locked(true)?;
        final_report
            .report
            .checkpoints
            .into_iter()
            .find(|item| item.checkpoint_id == checkpoint.checkpoint_id)
            .ok_or_else(|| EventStoreError::InvalidCheckpoint {
                path: self.layout.checkpoint_path(&checkpoint.checkpoint_id),
                message: "published checkpoint was not discoverable".to_owned(),
            })
    }

    fn complete_pending_checkpoint_locked(&self) -> Result<Option<Checkpoint>> {
        let state = self.inspect_writer_state(true)?;
        if state.open.is_some() {
            return Ok(None);
        }
        let Some(last_manifest) = state.closed.last() else {
            return Ok(None);
        };
        let record = read_manifest_last_event(
            &self.layout.segment_path(last_manifest.first_seq),
            last_manifest,
            self.config.max_event_bytes,
        )?;
        if record.envelope.event_type != "checkpoint_created" {
            return Ok(None);
        }
        let payload = parse_checkpoint_event(&record)?;
        let final_path = self.layout.checkpoint_path(&payload.checkpoint_id);
        if final_path.exists() {
            let report = report_from_closed_state(&state);
            let checkpoint = build_checkpoint(&report, &record)?;
            let existing: Checkpoint = read_json(&final_path, "checkpoint")?;
            if existing != checkpoint {
                return Err(EventStoreError::InvalidCheckpoint {
                    path: final_path,
                    message: "checkpoint file differs from its canonical event".to_owned(),
                });
            }
            sync_directory(&self.layout.checkpoint_dir)?;
            return Ok(None);
        }

        let verified = self.verify_locked(false)?;
        let matching_record = verified
            .checkpoint_events
            .iter()
            .find(|candidate| candidate.envelope.event_id == record.envelope.event_id)
            .ok_or_else(|| EventStoreError::InvalidCheckpoint {
                path: final_path.clone(),
                message: "pending checkpoint event was not found during verification".to_owned(),
            })?;
        let checkpoint = build_checkpoint(&verified.report, matching_record)?;
        self.publish_checkpoint(&checkpoint)?;
        Ok(Some(checkpoint))
    }

    fn publish_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        let final_path = self.layout.checkpoint_path(&checkpoint.checkpoint_id);
        if final_path.exists() {
            let existing: Checkpoint = read_json(&final_path, "checkpoint")?;
            if existing == *checkpoint {
                return Ok(());
            }
            return Err(EventStoreError::InvalidCheckpoint {
                path: final_path,
                message: "existing checkpoint file differs".to_owned(),
            });
        }
        let temp_path = self.layout.checkpoint_dir.join(format!(
            ".{}.{}.tmp",
            checkpoint.checkpoint_id,
            Ulid::new().to_string().to_ascii_lowercase()
        ));
        write_new_json(&temp_path, checkpoint)?;
        self.maybe_fail(FaultPoint::CheckpointTempSynced)?;
        fs::rename(&temp_path, &final_path)
            .map_err(|source| io_error("publish checkpoint", &final_path, source))?;
        self.maybe_fail(FaultPoint::CheckpointRenamed)?;
        sync_directory(&self.layout.checkpoint_dir)?;
        self.maybe_fail(FaultPoint::CheckpointDirectorySynced)?;
        Ok(())
    }
}

#[derive(Debug)]
struct VerifiedStream {
    report: VerificationReport,
    checkpoint_events: Vec<EventRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEventPayload {
    checkpoint_id: String,
    checkpoint_path: String,
    event_last_seq: u64,
}

fn parse_checkpoint_event(record: &EventRecord) -> Result<CheckpointEventPayload> {
    let path = PathBuf::from(format!("event:seq-{}", record.envelope.seq));
    let payload: CheckpointEventPayload = serde_json::from_value(record.envelope.payload.clone())
        .map_err(|source| EventStoreError::InvalidCheckpoint {
        path: path.clone(),
        message: format!("invalid checkpoint_created payload: {source}"),
    })?;
    if !is_prefixed_lowercase_ulid(&payload.checkpoint_id, "chk_") {
        return Err(EventStoreError::InvalidCheckpoint {
            path,
            message: "checkpoint_id must be chk_ plus a lowercase ULID".to_owned(),
        });
    }
    if payload.event_last_seq != record.envelope.seq
        || payload.checkpoint_path != relative_checkpoint_path(&payload.checkpoint_id)
    {
        return Err(EventStoreError::InvalidCheckpoint {
            path,
            message: "checkpoint path/sequence does not match its event".to_owned(),
        });
    }
    Ok(payload)
}

fn manifest_from_scan(scan: &SegmentScan) -> Result<SegmentManifest> {
    Ok(SegmentManifest {
        manifest_v: MANIFEST_VERSION,
        stream_id: STREAM_ID.to_owned(),
        segment_file: relative_segment_path(scan.first_seq),
        first_seq: scan.first_seq,
        last_seq: scan.last_seq.ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?,
        first_event_id: scan.first_event_id.clone().ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?,
        last_event_id: scan.last_event_id.clone().ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?,
        last_event_hash: scan.last_event_hash.clone().ok_or_else(|| {
            EventStoreError::InvalidLayout("cannot manifest an empty segment".to_owned())
        })?,
        event_count: scan.event_count,
        segment_size_bytes: scan.segment_size_bytes,
        segment_blake3: scan.segment_blake3.clone(),
    })
}

fn manifest_difference(actual: &SegmentManifest, expected: &SegmentManifest) -> String {
    if actual.first_event_id != expected.first_event_id {
        "first_event_id does not match segment".to_owned()
    } else if actual.last_event_id != expected.last_event_id {
        "last_event_id does not match segment".to_owned()
    } else if actual.last_event_hash != expected.last_event_hash {
        "last_event_hash does not match segment".to_owned()
    } else if actual.segment_blake3 != expected.segment_blake3 {
        "segment_blake3 does not match segment bytes".to_owned()
    } else {
        "manifest fields do not match segment".to_owned()
    }
}

fn checkpoint_segments_through(
    report: &VerificationReport,
    event_last_seq: u64,
) -> Result<Vec<CheckpointSegment>> {
    let mut result = Vec::new();
    let mut expected_first = 1_u64;
    for segment in &report.segments {
        let Some(manifest) = &segment.manifest else {
            if segment.first_seq <= event_last_seq {
                return Err(EventStoreError::InvalidCheckpoint {
                    path: PathBuf::from(relative_segment_path(segment.first_seq)),
                    message: "checkpoint coverage includes an open segment".to_owned(),
                });
            }
            break;
        };
        if manifest.first_seq != expected_first {
            return Err(EventStoreError::InvalidCheckpoint {
                path: PathBuf::from(relative_manifest_path(manifest.first_seq)),
                message: "checkpoint prefix is not contiguous".to_owned(),
            });
        }
        if manifest.last_seq > event_last_seq {
            break;
        }
        result.push(CheckpointSegment {
            file: manifest.segment_file.clone(),
            manifest: relative_manifest_path(manifest.first_seq),
            segment_blake3: manifest.segment_blake3.clone(),
        });
        expected_first = manifest.last_seq + 1;
    }
    if expected_first != event_last_seq + 1 {
        return Err(EventStoreError::InvalidCheckpoint {
            path: PathBuf::from("checkpoints"),
            message: format!(
                "closed prefix ends at {}, checkpoint requires {}",
                expected_first.saturating_sub(1),
                event_last_seq
            ),
        });
    }
    Ok(result)
}

fn report_from_closed_state(state: &WriterState) -> VerificationReport {
    VerificationReport {
        stream_id: STREAM_ID.to_owned(),
        last_seq: state.next_seq.saturating_sub(1),
        last_event_hash: state.previous_event_hash.clone(),
        segments: state
            .closed
            .iter()
            .map(|manifest| VerifiedSegment {
                segment_file: manifest.segment_file.clone(),
                first_seq: manifest.first_seq,
                last_seq: Some(manifest.last_seq),
                event_count: manifest.event_count,
                manifest: Some(manifest.clone()),
            })
            .collect(),
        checkpoints: Vec::new(),
    }
}

fn build_checkpoint(report: &VerificationReport, record: &EventRecord) -> Result<Checkpoint> {
    let payload = parse_checkpoint_event(record)?;
    if report.last_seq != record.envelope.seq
        || report.last_event_hash.as_deref() != Some(record.event_hash.as_str())
    {
        return Err(EventStoreError::InvalidCheckpoint {
            path: PathBuf::from(payload.checkpoint_path),
            message: "checkpoint event is not the verified stream tail".to_owned(),
        });
    }
    let segments = checkpoint_segments_through(report, record.envelope.seq)?;
    Ok(Checkpoint {
        checkpoint_v: CHECKPOINT_VERSION,
        checkpoint_id: payload.checkpoint_id,
        created_time_utc_ms: record.envelope.time_utc_ms,
        stream_id: STREAM_ID.to_owned(),
        event_first_seq: 1,
        event_last_seq: record.envelope.seq,
        event_last_hash: record.event_hash.clone(),
        segments,
    })
}

fn list_checkpoint_files(directory: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut files = BTreeMap::new();
    let entries = fs::read_dir(directory)
        .map_err(|source| io_error("read checkpoint directory", directory, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read checkpoint entry", directory, source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| io_error("read checkpoint entry type", entry.path(), source))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            EventStoreError::InvalidLayout(
                "checkpoint directory contains a non-UTF-8 filename".to_owned(),
            )
        })?;
        if name.starts_with('.') && name.ends_with(".tmp") {
            continue;
        }
        if !file_type.is_file() {
            return Err(EventStoreError::InvalidLayout(format!(
                "unexpected non-file in checkpoint directory: {}",
                entry.path().display()
            )));
        }
        let checkpoint_id = name.strip_suffix(".json").ok_or_else(|| {
            EventStoreError::InvalidLayout(format!(
                "unexpected checkpoint file: {}",
                entry.path().display()
            ))
        })?;
        let Some(ulid_text) = checkpoint_id.strip_prefix("chk_") else {
            return Err(EventStoreError::InvalidLayout(format!(
                "invalid checkpoint filename: {name}"
            )));
        };
        if ulid_text != ulid_text.to_ascii_lowercase() || Ulid::from_string(ulid_text).is_err() {
            return Err(EventStoreError::InvalidLayout(format!(
                "invalid checkpoint filename: {name}"
            )));
        }
        files.insert(checkpoint_id.to_owned(), entry.path());
    }
    Ok(files)
}

fn read_manifest_last_event(
    segment_path: &Path,
    manifest: &SegmentManifest,
    max_event_bytes: usize,
) -> Result<EventRecord> {
    let line = read_last_line(segment_path, max_event_bytes)?;
    let envelope = parse_event_line(segment_path, manifest.event_count, &line)?;
    if envelope.seq != manifest.last_seq || envelope.event_id != manifest.last_event_id {
        return Err(EventStoreError::InvalidManifest {
            path: segment_path.to_path_buf(),
            message: "last event does not match manifest".to_owned(),
        });
    }
    let hash = event_hash(&line);
    if hash != manifest.last_event_hash {
        return Err(EventStoreError::InvalidManifest {
            path: segment_path.to_path_buf(),
            message: "last event hash does not match manifest".to_owned(),
        });
    }
    Ok(EventRecord {
        envelope,
        event_hash: hash,
    })
}

fn read_last_line(path: &Path, max_event_bytes: usize) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).map_err(|source| io_error("open segment tail", path, source))?;
    let length = file
        .metadata()
        .map_err(|source| io_error("read segment tail metadata", path, source))?
        .len();
    if length == 0 {
        return Err(EventStoreError::InvalidLayout(format!(
            "segment {} is empty",
            path.display()
        )));
    }
    file.seek(SeekFrom::End(-1))
        .map_err(|source| io_error("seek segment tail", path, source))?;
    let mut final_byte = [0_u8; 1];
    file.read_exact(&mut final_byte)
        .map_err(|source| io_error("read segment tail", path, source))?;
    if final_byte[0] != b'\n' {
        return Err(EventStoreError::InvalidEvent {
            path: path.to_path_buf(),
            line: 0,
            message: "segment does not end with a newline".to_owned(),
        });
    }

    let line_end = length - 1;
    let lower_bound = line_end
        .saturating_sub(u64::try_from(max_event_bytes.saturating_add(1)).unwrap_or(u64::MAX));
    let mut cursor = line_end;
    let mut buffer = vec![0_u8; 8192];
    let mut line_start = 0_u64;
    while cursor > lower_bound {
        let chunk_start = cursor.saturating_sub(u64::try_from(buffer.len()).unwrap_or(8192));
        let chunk_start = chunk_start.max(lower_bound);
        let chunk_len = usize::try_from(cursor - chunk_start)
            .map_err(|_| EventStoreError::InvalidLayout("tail chunk exceeds usize".to_owned()))?;
        file.seek(SeekFrom::Start(chunk_start))
            .map_err(|source| io_error("seek segment tail chunk", path, source))?;
        file.read_exact(&mut buffer[..chunk_len])
            .map_err(|source| io_error("read segment tail chunk", path, source))?;
        if let Some(index) = buffer[..chunk_len].iter().rposition(|byte| *byte == b'\n') {
            line_start = chunk_start + u64::try_from(index + 1).unwrap_or(0);
            break;
        }
        cursor = chunk_start;
    }
    let line_len = usize::try_from(line_end - line_start).map_err(|_| {
        EventStoreError::InvalidLayout("last event length exceeds usize".to_owned())
    })?;
    if line_len > max_event_bytes {
        return Err(EventStoreError::InvalidEvent {
            path: path.to_path_buf(),
            line: 0,
            message: format!("event exceeds {max_event_bytes} bytes"),
        });
    }
    let mut line = vec![0_u8; line_len];
    file.seek(SeekFrom::Start(line_start))
        .map_err(|source| io_error("seek last event", path, source))?;
    file.read_exact(&mut line)
        .map_err(|source| io_error("read last event", path, source))?;
    Ok(line)
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|source| {
        EventStoreError::InvalidInput(format!("JSON serialization failed: {source}"))
    })?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| io_error("create temporary JSON file", path, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error("write temporary JSON file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync temporary JSON file", path, source))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use tempfile::TempDir;

    use super::*;

    fn config(rollover_events: u64) -> EventStoreConfig {
        EventStoreConfig {
            rollover_events,
            max_event_bytes: 1024 * 1024,
            actor_id: "test-user".to_owned(),
            host_id: "test-host".to_owned(),
        }
    }

    fn open_store(temp: &TempDir, rollover_events: u64) -> EventStore {
        EventStore::open_or_create(temp.path(), config(rollover_events)).unwrap()
    }

    fn request(number: u64) -> EventRequest {
        EventRequest::new("test_event", json!({ "number": number }))
    }

    fn append_range(store: &EventStore, start: u64, end: u64) -> Vec<EventRecord> {
        store
            .append_batch((start..end).map(request).collect())
            .unwrap()
    }

    fn read_value(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn write_value(path: &Path, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn rolls_over_multiple_segments_and_checkpoints_the_closed_prefix() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 2);

        let records = append_range(&store, 1, 6);
        assert_eq!(
            records
                .iter()
                .map(|item| item.envelope.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );

        let before = store.verify().unwrap();
        assert_eq!(before.last_seq, 5);
        assert_eq!(before.segments.len(), 3);
        assert!(before.segments[0].manifest.is_some());
        assert!(before.segments[1].manifest.is_some());
        assert!(before.segments[2].manifest.is_none());

        let checkpoint = store.create_checkpoint().unwrap();
        assert_eq!(checkpoint.event_first_seq, 1);
        assert_eq!(checkpoint.event_last_seq, 6);
        assert_eq!(checkpoint.segments.len(), 4);

        let after = store.verify().unwrap();
        assert_eq!(after.last_seq, 6);
        assert_eq!(after.checkpoints, vec![checkpoint.clone()]);
        assert!(after
            .segments
            .iter()
            .all(|segment| segment.manifest.is_some()));

        let next = store.append(request(6)).unwrap();
        assert_eq!(next.envelope.seq, 7);
        let final_report = store.verify().unwrap();
        assert_eq!(final_report.last_seq, 7);
        assert!(final_report.segments.last().unwrap().manifest.is_none());
    }

    #[test]
    fn recovers_incomplete_suffix_without_discarding_preceding_events() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        store.append(request(1)).unwrap();
        let path = store.layout.segment_path(1);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(br#"{"v":1"#).unwrap();
        file.sync_all().unwrap();

        let reopened = open_store(&temp, 10);
        let second = reopened.append(request(2)).unwrap();
        assert_eq!(second.envelope.seq, 2);
        let report = reopened.verify().unwrap();
        assert_eq!(report.last_seq, 2);
        let text = fs::read_to_string(path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn completes_valid_tail_event_missing_only_its_newline() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        let first = store.append(request(1)).unwrap();
        let path = store.layout.segment_path(1);
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        file.set_len(len - 1).unwrap();
        file.sync_all().unwrap();

        let reopened = open_store(&temp, 10);
        let second = reopened.append(request(2)).unwrap();
        assert_eq!(second.envelope.seq, 2);
        assert_eq!(second.envelope.previous_event_hash, Some(first.event_hash));
        assert_eq!(reopened.verify().unwrap().last_seq, 2);
        assert!(fs::read(path).unwrap().ends_with(b"\n"));
    }

    #[test]
    fn valid_json_with_invalid_sequence_fails_closed_instead_of_truncating() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        store.append(request(1)).unwrap();
        let path = store.layout.segment_path(1);
        let mut value: Value =
            serde_json::from_slice(fs::read(&path).unwrap().strip_suffix(b"\n").unwrap()).unwrap();
        value["seq"] = json!(99);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let error = EventStore::open_or_create(temp.path(), config(10)).unwrap_err();
        assert_eq!(error.code(), "event_hash_chain_failure");
        assert!(!fs::read(path).unwrap().ends_with(b"\n"));
    }

    #[test]
    fn invalid_batch_is_rejected_before_any_event_bytes_are_written() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        let error = store
            .append_batch(vec![
                request(1),
                EventRequest::new("invalid", json!("not an object")),
            ])
            .unwrap_err();
        assert_eq!(error.code(), "invalid_input");
        assert_eq!(store.verify().unwrap().last_seq, 0);

        let oversized = EventRequest::new(
            "oversized",
            json!({ "value": "x".repeat(store.config.max_event_bytes) }),
        );
        let error = store.append_batch(vec![request(2), oversized]).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
        assert_eq!(store.verify().unwrap().last_seq, 0);
    }

    #[test]
    fn rejects_every_manifest_field_when_tampered() {
        let cases: Vec<(&str, Value)> = vec![
            ("manifest_v", json!(2)),
            ("stream_id", json!("other_stream")),
            ("segment_file", json!("events/escape.jsonl")),
            ("first_seq", json!(2)),
            ("last_seq", json!(2)),
            ("first_event_id", json!("evt_00000000000000000000000000")),
            ("last_event_id", json!("evt_00000000000000000000000000")),
            ("last_event_hash", json!("blake3:00")),
            ("event_count", json!(2)),
            ("segment_size_bytes", json!(1)),
            ("segment_blake3", json!("blake3:00")),
        ];

        for (field, replacement) in cases {
            let temp = TempDir::new().unwrap();
            let store = open_store(&temp, 1);
            store.append(request(1)).unwrap();
            let path = store.layout.manifest_path(1);
            let mut manifest = read_value(&path);
            manifest[field] = replacement;
            write_value(&path, &manifest);
            let error = store.verify().unwrap_err();
            assert_eq!(
                error.code(),
                "invalid_segment_manifest",
                "field {field} should fail: {error}"
            );
        }
    }

    #[test]
    fn rejects_segment_bytes_and_cross_segment_hash_tampering() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 1);
        store
            .append(EventRequest::new("event_a", json!({})))
            .unwrap();
        let path = store.layout.segment_path(1);
        let bytes = fs::read(&path).unwrap();
        let text = String::from_utf8(bytes)
            .unwrap()
            .replace("event_a", "event_b");
        fs::write(&path, text).unwrap();
        assert_eq!(
            store.verify().unwrap_err().code(),
            "invalid_segment_manifest"
        );

        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 1);
        store.append(request(1)).unwrap();
        store.append(request(2)).unwrap();
        let second_path = store.layout.segment_path(2);
        let mut second: Value =
            serde_json::from_slice(fs::read(&second_path).unwrap().strip_suffix(b"\n").unwrap())
                .unwrap();
        second["previous_event_hash"] = json!(format!("blake3:{}", "0".repeat(64)));
        write_value(&second_path, &second);
        assert_eq!(
            store.verify().unwrap_err().code(),
            "event_hash_chain_failure"
        );
    }

    #[test]
    fn rejects_missing_non_tail_manifest_and_multiple_open_segments() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 2);
        append_range(&store, 1, 4);
        fs::remove_file(store.layout.manifest_path(1)).unwrap();
        assert_eq!(store.verify().unwrap_err().code(), "invalid_event_layout");

        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        store.append(request(1)).unwrap();
        File::create(store.layout.segment_path(2)).unwrap();
        assert_eq!(store.verify().unwrap_err().code(), "invalid_event_layout");
    }

    #[test]
    fn missing_checkpoint_file_is_reconciled_before_the_next_append() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        store.append(request(1)).unwrap();
        let checkpoint = store.create_checkpoint().unwrap();
        fs::remove_file(store.layout.checkpoint_path(&checkpoint.checkpoint_id)).unwrap();
        assert_eq!(store.verify().unwrap_err().code(), "invalid_checkpoint");

        let next = store.append(request(2)).unwrap();
        assert_eq!(next.envelope.seq, checkpoint.event_last_seq + 1);
        let report = store.verify().unwrap();
        assert_eq!(report.checkpoints, vec![checkpoint]);
    }

    #[test]
    fn checkpoint_segment_list_tampering_is_rejected() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 2);
        append_range(&store, 1, 5);
        let checkpoint = store.create_checkpoint().unwrap();
        let path = store.layout.checkpoint_path(&checkpoint.checkpoint_id);
        let mut value = read_value(&path);
        value["segments"].as_array_mut().unwrap().remove(0);
        write_value(&path, &value);
        assert_eq!(store.verify().unwrap_err().code(), "invalid_checkpoint");
    }

    #[test]
    fn tampered_completed_checkpoint_blocks_the_next_append() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        store.append(request(1)).unwrap();
        let checkpoint = store.create_checkpoint().unwrap();
        let path = store.layout.checkpoint_path(&checkpoint.checkpoint_id);
        let original = fs::read(&path).unwrap();
        let mut value: Value = serde_json::from_slice(&original).unwrap();
        value["created_time_utc_ms"] = json!(0);
        write_value(&path, &value);

        assert_eq!(
            store.append(request(2)).unwrap_err().code(),
            "invalid_checkpoint"
        );
        fs::write(&path, original).unwrap();
        assert_eq!(store.verify().unwrap().last_seq, checkpoint.event_last_seq);
    }

    #[test]
    fn restart_recovers_each_new_segment_durability_boundary() {
        for (point, expected_next_seq) in [
            (FaultPoint::SegmentCreated, 1),
            (FaultPoint::EventLineWritten, 2),
            (FaultPoint::SegmentFileSynced, 2),
            (FaultPoint::SegmentDirectorySynced, 2),
        ] {
            let temp = TempDir::new().unwrap();
            let store = open_store(&temp, 10);
            store.inject_once(point);
            assert_eq!(
                store.append(request(1)).unwrap_err().code(),
                "injected_failure"
            );

            let reopened = open_store(&temp, 10);
            let record = reopened.append(request(2)).unwrap();
            assert_eq!(record.envelope.seq, expected_next_seq, "fault {point:?}");
            assert_eq!(reopened.verify().unwrap().last_seq, expected_next_seq);
        }
    }

    #[test]
    fn restart_recovers_each_manifest_publication_boundary() {
        for point in [
            FaultPoint::ClosedSegmentSynced,
            FaultPoint::ManifestTempSynced,
            FaultPoint::ManifestRenamed,
            FaultPoint::ManifestDirectorySynced,
        ] {
            let temp = TempDir::new().unwrap();
            let store = open_store(&temp, 1);
            store.inject_once(point);
            assert_eq!(
                store.append(request(1)).unwrap_err().code(),
                "injected_failure"
            );

            let reopened = open_store(&temp, 1);
            let second = reopened.append(request(2)).unwrap();
            assert_eq!(second.envelope.seq, 2, "fault {point:?}");
            let report = reopened.verify().unwrap();
            assert_eq!(report.last_seq, 2);
            assert!(report
                .segments
                .iter()
                .all(|segment| segment.manifest.is_some()));
        }
    }

    #[test]
    fn restart_recovers_each_checkpoint_publication_boundary() {
        for point in [
            FaultPoint::CheckpointEventClosed,
            FaultPoint::CheckpointTempSynced,
            FaultPoint::CheckpointRenamed,
            FaultPoint::CheckpointDirectorySynced,
        ] {
            let temp = TempDir::new().unwrap();
            let store = open_store(&temp, 10);
            store.append(request(1)).unwrap();
            store.inject_once(point);
            assert_eq!(
                store.create_checkpoint().unwrap_err().code(),
                "injected_failure"
            );

            let reopened = open_store(&temp, 10);
            reopened.append(request(2)).unwrap();
            let report = reopened.verify().unwrap();
            assert_eq!(report.checkpoints.len(), 1, "fault {point:?}");
        }

        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 10);
        store.append(request(1)).unwrap();
        store.inject_once(FaultPoint::CheckpointPrefixClosed);
        assert_eq!(
            store.create_checkpoint().unwrap_err().code(),
            "injected_failure"
        );
        let reopened = open_store(&temp, 10);
        let checkpoint = reopened.create_checkpoint().unwrap();
        assert_eq!(checkpoint.event_last_seq, 2);
        assert_eq!(reopened.verify().unwrap().checkpoints.len(), 1);
    }

    #[test]
    fn independent_store_handles_serialize_batch_writers() {
        let temp = TempDir::new().unwrap();
        let first = Arc::new(open_store(&temp, 1_000));
        let second = Arc::new(open_store(&temp, 1_000));
        let left = {
            let store = Arc::clone(&first);
            thread::spawn(move || append_range(&store, 0, 50))
        };
        let right = {
            let store = Arc::clone(&second);
            thread::spawn(move || append_range(&store, 50, 100))
        };
        let mut sequences: Vec<u64> = left
            .join()
            .unwrap()
            .into_iter()
            .chain(right.join().unwrap())
            .map(|record| record.envelope.seq)
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=100).collect::<Vec<_>>());
        assert_eq!(first.verify().unwrap().last_seq, 100);
    }

    #[test]
    fn streaming_batches_resume_from_the_exact_file_offset() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 1_000);
        append_range(&store, 0, 100);

        let initial = store
            .read_batch(&EventCursor::default(), 1_000, 4 * 1024 * 1024)
            .unwrap();
        assert_eq!(initial.events.len(), 100);
        assert!(initial.eof);

        store.append(request(100)).unwrap();
        let tail = store
            .read_batch(&initial.next_cursor, 10, 1024 * 1024)
            .unwrap();
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].record.envelope.seq, 101);
        assert_eq!(tail.stats.segments_opened, 1);
        assert_eq!(tail.stats.lines_read, 1);
        assert!(tail.eof);
    }

    #[test]
    fn multi_batch_writer_reuses_state_across_rollovers() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 2);
        let stats = store
            .append_batches([
                vec![request(1)],
                vec![request(2), request(3)],
                vec![request(4), request(5)],
            ])
            .unwrap();
        assert_eq!(stats.batches, 3);
        assert_eq!(stats.events_appended, 5);
        assert_eq!(stats.first_seq, Some(1));
        assert_eq!(stats.last_seq, Some(5));
        let report = store.verify().unwrap();
        assert_eq!(report.last_seq, 5);
        assert_eq!(report.segments.len(), 3);
        assert!(report.segments[0].manifest.is_some());
        assert!(report.segments[1].manifest.is_some());
        assert!(report.segments[2].manifest.is_none());
    }

    #[test]
    fn streaming_uses_manifests_to_skip_wholly_applied_segments() {
        let temp = TempDir::new().unwrap();
        let store = open_store(&temp, 2);
        append_range(&store, 0, 6);

        let prefix = store
            .read_batch(&EventCursor::default(), 4, 1024 * 1024)
            .unwrap();
        assert_eq!(prefix.next_cursor.applied_seq, 4);
        let suffix = store
            .read_batch(&prefix.next_cursor, 10, 1024 * 1024)
            .unwrap();
        assert_eq!(
            suffix
                .events
                .iter()
                .map(|event| event.record.envelope.seq)
                .collect::<Vec<_>>(),
            vec![5, 6]
        );
        assert_eq!(suffix.stats.segments_opened, 1);
        assert_eq!(suffix.stats.lines_read, 2);

        let mut damaged_cursor = prefix.next_cursor;
        damaged_cursor.applied_event_hash = Some(format!("blake3:{}", "0".repeat(64)));
        assert_eq!(
            store
                .read_batch(&damaged_cursor, 10, 1024 * 1024)
                .unwrap_err()
                .code(),
            "event_hash_chain_failure"
        );
    }
}
