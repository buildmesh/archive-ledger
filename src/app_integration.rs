//! Bounded, read-only integration queries for applications above Archive Ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::BufRead;
use std::path::{Component, Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    discover_mounted_filesystem, CausalFrontier, V2CanonicalCursor, V2OriginStore, V2ProjectionDb,
    V2ProjectionError, V2StoreError,
};

const OUTPUT_VERSION: u32 = 1;
const TOKEN_VERSION: u32 = 1;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_REQUEST_LINE_BYTES: usize = 16 * 1024;

pub type Result<T> = std::result::Result<T, AppIntegrationError>;

#[derive(Debug, Error)]
pub enum AppIntegrationError {
    #[error(transparent)]
    Store(#[from] V2StoreError),
    #[error(transparent)]
    Projection(#[from] V2ProjectionError),
    #[error("application integration SQLite query failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("page limit must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidLimit,
    #[error("application continuation token is invalid")]
    InvalidContinuation,
    #[error("application continuation is stale; restart from the first page")]
    StaleContinuation,
    #[error("the SQLite projection is not current at the canonical Archive frontier")]
    ProjectionBehind,
    #[error("application request JSONL line {line} is invalid: {detail}")]
    InvalidRequest { line: u64, detail: String },
    #[error("application request contains no File IDs")]
    EmptyRequest,
    #[error("registered path cannot be represented safely on this platform: {0}")]
    UnsafePath(String),
    #[error("application query found invalid projected data: {0}")]
    InvalidProjectedData(String),
}

impl AppIntegrationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Store(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Sqlite { .. } => "app_query_sqlite",
            Self::InvalidLimit => "invalid_limit",
            Self::InvalidContinuation => "invalid_continuation",
            Self::StaleContinuation => "stale_continuation",
            Self::ProjectionBehind => "projection_behind",
            Self::InvalidRequest { .. } | Self::EmptyRequest => "invalid_app_request",
            Self::UnsafePath(_) => "unsafe_registered_path",
            Self::InvalidProjectedData(_) => "app_projection_invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppPath {
    pub encoding: String,
    pub display: String,
    pub text: Option<String>,
    pub base64: Option<String>,
}

impl AppPath {
    fn from_parts(encoding: String, bytes: Vec<u8>, display: String) -> Self {
        if encoding == "utf8" {
            Self {
                text: String::from_utf8(bytes).ok(),
                base64: None,
                encoding,
                display,
            }
        } else {
            Self {
                text: None,
                base64: Some(URL_SAFE_NO_PAD.encode(bytes)),
                encoding,
                display,
            }
        }
    }

    fn from_path(path: &Path) -> Self {
        if let Some(text) = path.to_str() {
            return Self {
                encoding: "utf8".to_owned(),
                display: text.to_owned(),
                text: Some(text.to_owned()),
                base64: None,
            };
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            return Self {
                encoding: "unix_bytes".to_owned(),
                display: path.to_string_lossy().into_owned(),
                text: None,
                base64: Some(URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())),
            };
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;
            let bytes = path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            return Self {
                encoding: "windows_utf16le".to_owned(),
                display: path.to_string_lossy().into_owned(),
                text: None,
                base64: Some(URL_SAFE_NO_PAD.encode(bytes)),
            };
        }
        #[allow(unreachable_code)]
        Self {
            encoding: "utf8".to_owned(),
            display: path.to_string_lossy().into_owned(),
            text: None,
            base64: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppCheckpoint {
    pub git_commit: String,
    pub accepted_frontier_hash: String,
}

impl From<&V2CanonicalCursor> for AppCheckpoint {
    fn from(value: &V2CanonicalCursor) -> Self {
        Self {
            git_commit: value.git_commit.clone(),
            accepted_frontier_hash: value.accepted_frontier_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IntroducedFile {
    pub file_ref_id: String,
    pub object_id: Option<String>,
    pub external_identity_id: Option<String>,
    pub identity_state: String,
    pub logical_path: AppPath,
    pub first_seen_record_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChangeFeedPage {
    pub version: u32,
    pub collection_id: String,
    pub since: AppCheckpoint,
    pub current: AppCheckpoint,
    pub semantics: &'static str,
    pub items: Vec<IntroducedFile>,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChangeToken {
    v: u32,
    collection_id: String,
    since_commit: String,
    current_frontier: String,
    path_encoding: String,
    path_bytes: String,
    file_ref_id: String,
}

pub fn introduced_files(
    database: &V2ProjectionDb,
    store: &V2OriginStore,
    collection_id: &str,
    since: &str,
    limit: usize,
    continuation: Option<&str>,
) -> Result<ChangeFeedPage> {
    validate_limit(limit)?;
    let current = store.canonical_cursor("HEAD")?;
    let mut connection = open_snapshot(database, &current)?;
    let base = store.canonical_cursor(since)?;
    if !frontier_is_at_or_before(&base.frontier, &current.frontier) {
        return Err(V2StoreError::CursorNotReachable {
            cursor: base.git_commit,
            current: current.git_commit,
        }
        .into());
    }
    let token = continuation.map(decode_token::<ChangeToken>).transpose()?;
    if token.as_ref().is_some_and(|token| {
        token.v != TOKEN_VERSION
            || token.collection_id != collection_id
            || token.since_commit != base.git_commit
            || token.current_frontier != current.accepted_frontier_hash
    }) {
        return Err(AppIntegrationError::StaleContinuation);
    }

    install_frontier(&mut connection, &base.frontier)?;
    let cursor_bytes = token
        .as_ref()
        .map(|token| URL_SAFE_NO_PAD.decode(&token.path_bytes))
        .transpose()
        .map_err(|_| AppIntegrationError::InvalidContinuation)?;
    let mut statement = connection
        .prepare(
            "SELECT f.file_ref_id, f.object_id, f.external_identity_id,
                    f.identity_state, f.logical_path_encoding, f.logical_path_bytes,
                    f.logical_path_display, f.first_seen_record_id
             FROM file_refs f
             JOIN records r ON r.record_id = f.first_seen_record_id
             LEFT JOIN temp.app_base_frontier b ON b.origin_id = r.origin_id
             WHERE f.collection_id = ?1 AND f.path_state = 'active'
               AND r.origin_seq > COALESCE(b.origin_seq, 0)
               AND (?2 IS NULL OR (f.logical_path_encoding, f.logical_path_bytes,
                    f.file_ref_id) > (?2, ?3, ?4))
             ORDER BY f.logical_path_encoding, f.logical_path_bytes, f.file_ref_id
             LIMIT ?5",
        )
        .map_err(|source| sqlite_error(database, source))?;
    let requested =
        i64::try_from(limit.saturating_add(1)).map_err(|_| AppIntegrationError::InvalidLimit)?;
    let rows = statement
        .query_map(
            params![
                collection_id,
                token.as_ref().map(|token| token.path_encoding.as_str()),
                cursor_bytes,
                token.as_ref().map(|token| token.file_ref_id.as_str()),
                requested,
            ],
            |row| {
                Ok(IntroducedFile {
                    file_ref_id: row.get(0)?,
                    object_id: row.get(1)?,
                    external_identity_id: row.get(2)?,
                    identity_state: row.get(3)?,
                    logical_path: AppPath::from_parts(row.get(4)?, row.get(5)?, row.get(6)?),
                    first_seen_record_id: row.get(7)?,
                })
            },
        )
        .map_err(|source| sqlite_error(database, source))?;
    let mut items = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| sqlite_error(database, source))?;
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next = if has_more {
        let last = items.last().expect("a truncated page has a last item");
        Some(encode_token(&ChangeToken {
            v: TOKEN_VERSION,
            collection_id: collection_id.to_owned(),
            since_commit: base.git_commit.clone(),
            current_frontier: current.accepted_frontier_hash.clone(),
            path_encoding: last.logical_path.encoding.clone(),
            path_bytes: URL_SAFE_NO_PAD.encode(path_bytes(&last.logical_path)?),
            file_ref_id: last.file_ref_id.clone(),
        })?)
    } else {
        None
    };
    Ok(ChangeFeedPage {
        version: OUTPUT_VERSION,
        collection_id: collection_id.to_owned(),
        since: AppCheckpoint::from(&base),
        current: AppCheckpoint::from(&current),
        semantics: "currently_active_files_first_introduced_after_cursor",
        items,
        next,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccessCandidate {
    pub copy_claim_id: String,
    pub location_id: String,
    pub location_name: String,
    pub device_id: String,
    pub device_name: String,
    pub site_id: Option<String>,
    pub site_name: Option<String>,
    pub path: AppPath,
    pub mount_identity_status: String,
    pub last_seen_time_utc_ms: Option<u64>,
    pub last_verified_time_utc_ms: Option<u64>,
    pub last_verification_result: Option<String>,
    pub evidence: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileAccess {
    pub ordinal: u64,
    pub requested_file_ref_id: String,
    pub state: String,
    pub object_id: Option<String>,
    pub logical_path: Option<AppPath>,
    pub local_candidate: Option<AccessCandidate>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttachmentLocation {
    pub location_id: String,
    pub location_name: String,
    pub requested_files_covered: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttachmentStep {
    pub device_id: String,
    pub device_name: String,
    pub site_id: Option<String>,
    pub site_name: Option<String>,
    pub newly_covered_files: u64,
    pub locations: Vec<AttachmentLocation>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttachmentPlan {
    pub algorithm: &'static str,
    pub optimality: &'static str,
    pub steps: Vec<AttachmentStep>,
    pub no_attachable_copy_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccessPlanPage {
    pub version: u32,
    pub collection_id: String,
    pub current: AppCheckpoint,
    pub request_hash: String,
    pub requested_file_count: u64,
    pub summary: AccessRequestSummary,
    pub items: Vec<FileAccess>,
    pub attachment_plan: Option<AttachmentPlan>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccessRequestSummary {
    pub accessible: u64,
    pub attachment_required: u64,
    pub no_known_copy: u64,
    pub not_found: u64,
    pub wrong_collection: u64,
    pub removed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessToken {
    v: u32,
    collection_id: String,
    host_id: String,
    request_hash: String,
    current_frontier: String,
    last_ordinal: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RequestLine {
    Id(String),
    Object { file_ref_id: String },
}

pub fn access_plan<R: BufRead>(
    database: &V2ProjectionDb,
    store: &V2OriginStore,
    collection_id: &str,
    host_id: &str,
    mut input: R,
    limit: usize,
    continuation: Option<&str>,
) -> Result<AccessPlanPage> {
    validate_limit(limit)?;
    let current = store.canonical_cursor("HEAD")?;
    let mut connection = open_snapshot(database, &current)?;
    connection
        .execute_batch(
            "CREATE TEMP TABLE app_requested_files(
                 ordinal INTEGER PRIMARY KEY,
                 file_ref_id TEXT NOT NULL UNIQUE
             ) STRICT;",
        )
        .map_err(|source| sqlite_error(database, source))?;
    let (request_hash, requested_file_count) = load_request(database, &mut connection, &mut input)?;
    let token = continuation.map(decode_token::<AccessToken>).transpose()?;
    if token.as_ref().is_some_and(|token| {
        token.v != TOKEN_VERSION
            || token.collection_id != collection_id
            || token.host_id != host_id
            || token.request_hash != request_hash
            || token.current_frontier != current.accepted_frontier_hash
    }) {
        return Err(AppIntegrationError::StaleContinuation);
    }
    install_accessible_roots(database, &mut connection, host_id)?;
    install_content_access(database, &mut connection, collection_id)?;
    let summary = access_summary(database, &connection, collection_id)?;
    let after = token.as_ref().map_or(0, |token| token.last_ordinal);
    let mut items = access_page(database, &connection, collection_id, after, limit)?;
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next = if has_more {
        Some(encode_token(&AccessToken {
            v: TOKEN_VERSION,
            collection_id: collection_id.to_owned(),
            host_id: host_id.to_owned(),
            request_hash: request_hash.clone(),
            current_frontier: current.accepted_frontier_hash.clone(),
            last_ordinal: items
                .last()
                .expect("a truncated page has a last item")
                .ordinal,
        })?)
    } else {
        None
    };
    let attachment_plan = if continuation.is_none() {
        Some(attachment_plan(database, &mut connection)?)
    } else {
        None
    };
    Ok(AccessPlanPage {
        version: OUTPUT_VERSION,
        collection_id: collection_id.to_owned(),
        current: AppCheckpoint::from(&current),
        request_hash,
        requested_file_count,
        summary,
        items,
        attachment_plan,
        next,
    })
}

fn require_current_projection(
    database: &V2ProjectionDb,
    connection: &Connection,
    current: &V2CanonicalCursor,
) -> Result<()> {
    let projected = connection
        .query_row(
            "SELECT
                 (SELECT value FROM archive_meta WHERE key = 'archive_id'),
                 (SELECT value FROM archive_meta WHERE key = 'genesis_hash'),
                 (SELECT value FROM archive_meta WHERE key = 'accepted_frontier_hash'),
                 (SELECT value FROM archive_meta WHERE key = 'applied_frontier_hash')",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|source| sqlite_error(database, source))?;
    if projected.0 != current.archive_id
        || projected.1 != current.genesis_hash
        || projected.2 != current.accepted_frontier_hash
        || projected.3 != current.accepted_frontier_hash
    {
        return Err(AppIntegrationError::ProjectionBehind);
    }
    Ok(())
}

fn install_frontier(connection: &mut Connection, frontier: &CausalFrontier) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TEMP TABLE app_base_frontier(
                 origin_id TEXT PRIMARY KEY,
                 origin_seq INTEGER NOT NULL
             ) STRICT;",
        )
        .map_err(|source| AppIntegrationError::Sqlite {
            path: PathBuf::from("temporary app frontier"),
            source,
        })?;
    for origin in &frontier.origins {
        connection
            .execute(
                "INSERT INTO app_base_frontier(origin_id, origin_seq) VALUES (?1, ?2)",
                params![
                    origin.origin_id,
                    sql_i64(origin.seq, "frontier origin sequence")?
                ],
            )
            .map_err(|source| AppIntegrationError::Sqlite {
                path: PathBuf::from("temporary app frontier"),
                source,
            })?;
    }
    Ok(())
}

fn load_request<R: BufRead>(
    database: &V2ProjectionDb,
    connection: &mut Connection,
    input: &mut R,
) -> Result<(String, u64)> {
    let mut line_number = 0_u64;
    let mut ordinal = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut insert = connection
        .prepare_cached(
            "INSERT OR IGNORE INTO app_requested_files(ordinal, file_ref_id) VALUES (?1, ?2)",
        )
        .map_err(|source| sqlite_error(database, source))?;
    loop {
        let mut bytes = Vec::new();
        let read = input.read_until(b'\n', &mut bytes).map_err(|error| {
            AppIntegrationError::InvalidRequest {
                line: line_number.saturating_add(1),
                detail: error.to_string(),
            }
        })?;
        if read == 0 {
            break;
        }
        line_number = line_number.saturating_add(1);
        if bytes.len() > MAX_REQUEST_LINE_BYTES {
            return Err(AppIntegrationError::InvalidRequest {
                line: line_number,
                detail: format!("line exceeds {MAX_REQUEST_LINE_BYTES} bytes"),
            });
        }
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let request: RequestLine = serde_json::from_slice(&bytes).map_err(|error| {
            AppIntegrationError::InvalidRequest {
                line: line_number,
                detail: error.to_string(),
            }
        })?;
        let id = match request {
            RequestLine::Id(id) | RequestLine::Object { file_ref_id: id } => id,
        };
        if id.trim() != id || id.is_empty() || id.len() > 512 {
            return Err(AppIntegrationError::InvalidRequest {
                line: line_number,
                detail: "file_ref_id must be 1-512 bytes without surrounding whitespace".to_owned(),
            });
        }
        let next_ordinal = ordinal.saturating_add(1);
        let changed = insert
            .execute(params![sql_i64(next_ordinal, "request ordinal")?, id])
            .map_err(|source| sqlite_error(database, source))?;
        if changed == 1 {
            ordinal = next_ordinal;
            hasher.update(id.as_bytes());
            hasher.update(b"\n");
        }
    }
    if ordinal == 0 {
        return Err(AppIntegrationError::EmptyRequest);
    }
    Ok((format!("blake3:{}", hasher.finalize().to_hex()), ordinal))
}

fn install_accessible_roots(
    database: &V2ProjectionDb,
    connection: &mut Connection,
    host_id: &str,
) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TEMP TABLE app_accessible_roots(
                 archive_root_id TEXT PRIMARY KEY,
                 mount_root TEXT NOT NULL,
                 fingerprint_status TEXT NOT NULL
             ) STRICT;",
        )
        .map_err(|source| sqlite_error(database, source))?;
    let rows = {
        let mut statement = connection
            .prepare(
                "SELECT dm.archive_root_id, dm.mount_root_uri, dm.status,
                        ar.identity_state, ar.fingerprint_kind,
                        ar.filesystem_fingerprint
                 FROM device_mounts dm
                 JOIN archive_roots ar ON ar.archive_root_id = dm.archive_root_id
                 WHERE dm.host_id = ?1 AND ar.status = 'active'
                   AND dm.mount_id = (
                       SELECT latest.mount_id FROM device_mounts latest
                       WHERE latest.host_id = dm.host_id
                         AND latest.archive_root_id = dm.archive_root_id
                       ORDER BY latest.observed_time_utc_ms DESC, latest.mount_id DESC
                       LIMIT 1
                   )
                 ORDER BY dm.archive_root_id",
            )
            .map_err(|source| sqlite_error(database, source))?;
        let collected = statement
            .query_map([host_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|source| sqlite_error(database, source))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(database, source))?;
        collected
    };
    for (root_id, mount, status, identity_state, expected_kind, expected_fingerprint) in rows {
        if status != "mounted" {
            continue;
        }
        let Ok(mount_path) = std::fs::canonicalize(&mount) else {
            continue;
        };
        let Ok(discovered) = discover_mounted_filesystem(&mount_path) else {
            continue;
        };
        let fingerprint_status = if identity_state == "confirmed" {
            if discovered.fingerprint_kind != expected_kind
                || discovered.filesystem_fingerprint != expected_fingerprint
            {
                continue;
            }
            "match"
        } else if discovered.mount_root == mount_path {
            "unavailable"
        } else {
            continue;
        };
        connection
            .execute(
                "INSERT INTO app_accessible_roots(archive_root_id, mount_root, fingerprint_status)
                 VALUES (?1, ?2, ?3)",
                params![root_id, mount_path.to_string_lossy(), fingerprint_status],
            )
            .map_err(|source| sqlite_error(database, source))?;
    }
    Ok(())
}

fn install_content_access(
    database: &V2ProjectionDb,
    connection: &mut Connection,
    collection_id: &str,
) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TEMP TABLE app_content_access(
                 content_key TEXT PRIMARY KEY,
                 object_id TEXT,
                 external_identity_id TEXT,
                 requested_file_count INTEGER NOT NULL,
                 accessible_copy_claim_id TEXT,
                 has_attachable_copy INTEGER NOT NULL DEFAULT 0
             ) STRICT;",
        )
        .map_err(|source| sqlite_error(database, source))?;
    connection
        .execute(
            "INSERT INTO app_content_access(
                 content_key, object_id, external_identity_id, requested_file_count
             )
             SELECT CASE
                        WHEN f.object_id IS NOT NULL THEN 'object:' || f.object_id
                        WHEN f.external_identity_id IS NOT NULL
                          THEN 'external:' || f.external_identity_id
                        ELSE 'file:' || f.file_ref_id
                    END,
                    f.object_id, f.external_identity_id, COUNT(*)
             FROM app_requested_files r
             JOIN file_refs f ON f.file_ref_id = r.file_ref_id
             WHERE f.collection_id = ?1 AND f.path_state = 'active'
             GROUP BY 1, f.object_id, f.external_identity_id",
            [collection_id],
        )
        .map_err(|source| sqlite_error(database, source))?;
    connection
        .execute_batch(
            "UPDATE app_content_access AS content
             SET accessible_copy_claim_id = (
                 SELECT cc.copy_claim_id
                 FROM copy_claims cc
                 JOIN locations l ON l.location_id = cc.location_id
                 JOIN app_accessible_roots roots
                   ON roots.archive_root_id = l.archive_root_id
                 JOIN devices d ON d.device_id = l.device_id
                 WHERE cc.state = 'present' AND l.status = 'active'
                   AND d.status = 'active'
                   AND ((content.object_id IS NOT NULL
                         AND cc.object_id = content.object_id)
                     OR (content.object_id IS NULL
                         AND content.external_identity_id IS NOT NULL
                         AND cc.external_identity_id = content.external_identity_id))
                 ORDER BY l.location_id, cc.copy_claim_id
                 LIMIT 1
             );
             UPDATE app_content_access AS content
             SET has_attachable_copy = EXISTS (
                 SELECT 1
                 FROM copy_claims cc
                 JOIN locations l ON l.location_id = cc.location_id
                 JOIN devices d ON d.device_id = l.device_id
                 WHERE cc.state = 'present' AND l.status = 'active'
                   AND d.status = 'active'
                   AND ((content.object_id IS NOT NULL
                         AND cc.object_id = content.object_id)
                     OR (content.object_id IS NULL
                         AND content.external_identity_id IS NOT NULL
                         AND cc.external_identity_id = content.external_identity_id))
             );",
        )
        .map_err(|source| sqlite_error(database, source))?;
    Ok(())
}

fn access_page(
    database: &V2ProjectionDb,
    connection: &Connection,
    collection_id: &str,
    after: u64,
    limit: usize,
) -> Result<Vec<FileAccess>> {
    let requested =
        i64::try_from(limit.saturating_add(1)).map_err(|_| AppIntegrationError::InvalidLimit)?;
    let after = i64::try_from(after).map_err(|_| AppIntegrationError::InvalidContinuation)?;
    let mut statement = connection
        .prepare(
            "SELECT r.ordinal, r.file_ref_id, f.collection_id, f.path_state,
                    f.object_id, f.logical_path_encoding, f.logical_path_bytes,
                    f.logical_path_display
             FROM app_requested_files r
             LEFT JOIN file_refs f ON f.file_ref_id = r.file_ref_id
             WHERE r.ordinal > ?1 ORDER BY r.ordinal LIMIT ?2",
        )
        .map_err(|source| sqlite_error(database, source))?;
    let raw = statement
        .query_map(params![after, requested], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })
        .map_err(|source| sqlite_error(database, source))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| sqlite_error(database, source))?;
    let last_ordinal = raw.last().map_or(after, |row| row.0);
    let candidates = candidate_page(database, connection, collection_id, after, last_ordinal)?;
    let attachable = attachable_page(database, connection, collection_id, after, last_ordinal)?;
    raw.into_iter()
        .map(|row| {
            let ordinal =
                u64::try_from(row.0).map_err(|_| AppIntegrationError::InvalidRequest {
                    line: 0,
                    detail: "negative request ordinal in SQLite".to_owned(),
                })?;
            let state = match (row.2.as_deref(), row.3.as_deref()) {
                (None, _) => "not_found",
                (Some(found), _) if found != collection_id => "wrong_collection",
                (_, Some("removed")) => "removed",
                (_, Some("active")) if candidates.contains_key(&ordinal) => "accessible",
                (_, Some("active")) if attachable.contains(&ordinal) => "attachment_required",
                (_, Some("active")) => "no_known_copy",
                _ => "not_found",
            }
            .to_owned();
            let logical_path = match (row.5, row.6, row.7) {
                (Some(encoding), Some(bytes), Some(display)) => {
                    Some(AppPath::from_parts(encoding, bytes, display))
                }
                _ => None,
            };
            Ok(FileAccess {
                ordinal,
                requested_file_ref_id: row.1,
                state,
                object_id: row.4,
                logical_path,
                local_candidate: candidates.get(&ordinal).cloned(),
            })
        })
        .collect()
}

fn access_summary(
    database: &V2ProjectionDb,
    connection: &Connection,
    collection_id: &str,
) -> Result<AccessRequestSummary> {
    let values = connection
        .query_row(
            "WITH classified AS (
                 SELECT f.collection_id, f.path_state,
                        content.accessible_copy_claim_id IS NOT NULL AS is_accessible,
                        COALESCE(content.has_attachable_copy, 0) AS is_attachable
                 FROM app_requested_files r
                 LEFT JOIN file_refs f ON f.file_ref_id = r.file_ref_id
                 LEFT JOIN app_content_access content ON content.content_key =
                    CASE
                        WHEN f.object_id IS NOT NULL THEN 'object:' || f.object_id
                        WHEN f.external_identity_id IS NOT NULL
                          THEN 'external:' || f.external_identity_id
                        ELSE 'file:' || f.file_ref_id
                    END
             )
             SELECT
                 COALESCE(SUM(collection_id = ?1 AND path_state = 'active'
                              AND is_accessible), 0),
                 COALESCE(SUM(collection_id = ?1 AND path_state = 'active'
                              AND NOT is_accessible AND is_attachable), 0),
                 COALESCE(SUM(collection_id = ?1 AND path_state = 'active'
                              AND NOT is_accessible AND NOT is_attachable), 0),
                 COALESCE(SUM(collection_id IS NULL), 0),
                 COALESCE(SUM(collection_id IS NOT NULL AND collection_id != ?1), 0),
                 COALESCE(SUM(collection_id = ?1 AND path_state = 'removed'), 0)
             FROM classified",
            [collection_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|source| sqlite_error(database, source))?;
    Ok(AccessRequestSummary {
        accessible: sql_u64(values.0, "accessible count")?,
        attachment_required: sql_u64(values.1, "attachment-required count")?,
        no_known_copy: sql_u64(values.2, "no-known-copy count")?,
        not_found: sql_u64(values.3, "not-found count")?,
        wrong_collection: sql_u64(values.4, "wrong-Collection count")?,
        removed: sql_u64(values.5, "removed count")?,
    })
}

fn attachable_page(
    database: &V2ProjectionDb,
    connection: &Connection,
    collection_id: &str,
    after: i64,
    through: i64,
) -> Result<BTreeSet<u64>> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT r.ordinal
             FROM app_requested_files r
             JOIN file_refs f ON f.file_ref_id = r.file_ref_id
             JOIN app_content_access content ON content.content_key =
                CASE
                    WHEN f.object_id IS NOT NULL THEN 'object:' || f.object_id
                    WHEN f.external_identity_id IS NOT NULL
                      THEN 'external:' || f.external_identity_id
                    ELSE 'file:' || f.file_ref_id
                END
             WHERE r.ordinal > ?1 AND r.ordinal <= ?2
               AND f.collection_id = ?3 AND f.path_state = 'active'
               AND content.accessible_copy_claim_id IS NULL
               AND content.has_attachable_copy = 1
             ORDER BY r.ordinal",
        )
        .map_err(|source| sqlite_error(database, source))?;
    let collected = statement
        .query_map(params![after, through, collection_id], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|source| sqlite_error(database, source))?
        .map(|value| {
            let value = value.map_err(|source| sqlite_error(database, source))?;
            u64::try_from(value).map_err(|_| AppIntegrationError::InvalidContinuation)
        })
        .collect();
    collected
}

type CandidateRow = (
    i64,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

fn candidate_page(
    database: &V2ProjectionDb,
    connection: &Connection,
    collection_id: &str,
    after: i64,
    through: i64,
) -> Result<BTreeMap<u64, AccessCandidate>> {
    let mut statement = connection
        .prepare(
            "SELECT r.ordinal, cc.copy_claim_id, l.location_id, l.display_name,
                    d.device_id, d.display_name, d.current_site_id, s.display_name,
                    roots.mount_root, roots.fingerprint_status,
                    l.relative_path_encoding, l.relative_path_bytes,
                    cc.relative_path_encoding, cc.relative_path_bytes,
                    cc.last_seen_time_utc_ms, cc.last_verified_time_utc_ms,
                    cc.last_verification_result
             FROM app_requested_files r
             JOIN file_refs f ON f.file_ref_id = r.file_ref_id
             JOIN app_content_access content ON content.content_key =
                CASE
                    WHEN f.object_id IS NOT NULL THEN 'object:' || f.object_id
                    WHEN f.external_identity_id IS NOT NULL
                      THEN 'external:' || f.external_identity_id
                    ELSE 'file:' || f.file_ref_id
                END
             JOIN copy_claims cc
               ON cc.copy_claim_id = content.accessible_copy_claim_id
             JOIN locations l ON l.location_id = cc.location_id
             JOIN app_accessible_roots roots
               ON roots.archive_root_id = l.archive_root_id
             JOIN devices d ON d.device_id = l.device_id
             LEFT JOIN sites s ON s.site_id = d.current_site_id
             WHERE r.ordinal > ?1 AND r.ordinal <= ?2
               AND f.collection_id = ?3 AND f.path_state = 'active'
             ORDER BY r.ordinal",
        )
        .map_err(|source| sqlite_error(database, source))?;
    let rows = statement
        .query_map(params![after, through, collection_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
                row.get(15)?,
                row.get(16)?,
            ))
        })
        .map_err(|source| sqlite_error(database, source))?
        .collect::<rusqlite::Result<Vec<CandidateRow>>>()
        .map_err(|source| sqlite_error(database, source))?;
    let mut candidates = BTreeMap::new();
    for row in rows {
        let location_relative = db_path(&row.10, row.11)?;
        let copy_relative = db_path(&row.12, row.13)?;
        let location_root = safe_join(Path::new(&row.8), &location_relative)?;
        let path = safe_join(&location_root, &copy_relative)?;
        candidates.insert(
            u64::try_from(row.0).map_err(|_| AppIntegrationError::InvalidContinuation)?,
            AccessCandidate {
                copy_claim_id: row.1,
                location_id: row.2,
                location_name: row.3,
                device_id: row.4,
                device_name: row.5,
                site_id: row.6,
                site_name: row.7,
                path: AppPath::from_path(&path),
                mount_identity_status: row.9,
                last_seen_time_utc_ms: optional_u64(row.14)?,
                last_verified_time_utc_ms: optional_u64(row.15)?,
                last_verification_result: row.16,
                evidence: "present_claim_on_revalidated_mount_not_freshly_verified",
            },
        );
    }
    Ok(candidates)
}

fn attachment_plan(
    database: &V2ProjectionDb,
    connection: &mut Connection,
) -> Result<AttachmentPlan> {
    connection
        .execute_batch(
            "CREATE TEMP TABLE app_uncovered_content(
                 content_key TEXT PRIMARY KEY,
                 object_id TEXT,
                 external_identity_id TEXT,
                 requested_file_count INTEGER NOT NULL
             ) STRICT;
             INSERT INTO app_uncovered_content(
                 content_key, object_id, external_identity_id, requested_file_count
             )
             SELECT content_key, object_id, external_identity_id, requested_file_count
             FROM app_content_access
             WHERE accessible_copy_claim_id IS NULL;",
        )
        .map_err(|source| sqlite_error(database, source))?;

    let mut steps = Vec::new();
    loop {
        let best = connection
            .query_row(
                "WITH device_content AS (
                     SELECT DISTINCT d.device_id, u.content_key
                     FROM app_uncovered_content u
                     JOIN copy_claims cc ON (
                         (u.object_id IS NOT NULL AND cc.object_id = u.object_id)
                         OR (u.object_id IS NULL AND u.external_identity_id IS NOT NULL
                             AND cc.external_identity_id = u.external_identity_id)
                     )
                     JOIN locations l ON l.location_id = cc.location_id
                     JOIN devices d ON d.device_id = l.device_id
                     WHERE cc.state = 'present' AND l.status = 'active'
                       AND d.status = 'active'
                 )
                 SELECT d.device_id, d.display_name, d.current_site_id, s.display_name,
                        SUM(u.requested_file_count) AS covered
                 FROM device_content coverage
                 JOIN app_uncovered_content u ON u.content_key = coverage.content_key
                 JOIN devices d ON d.device_id = coverage.device_id
                 LEFT JOIN sites s ON s.site_id = d.current_site_id
                 GROUP BY d.device_id, d.display_name, d.current_site_id, s.display_name
                 ORDER BY covered DESC, d.device_id LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(database, source))?;
        let Some((device_id, device_name, site_id, site_name, covered)) = best else {
            break;
        };
        let locations = {
            let mut statement = connection
                .prepare(
                    "WITH location_content AS (
                         SELECT DISTINCT l.location_id, u.content_key
                         FROM app_uncovered_content u
                         JOIN copy_claims cc ON (
                             (u.object_id IS NOT NULL AND cc.object_id = u.object_id)
                             OR (u.object_id IS NULL AND u.external_identity_id IS NOT NULL
                                 AND cc.external_identity_id = u.external_identity_id)
                         )
                         JOIN locations l ON l.location_id = cc.location_id
                         WHERE cc.state = 'present' AND l.status = 'active'
                           AND l.device_id = ?1
                     )
                     SELECT l.location_id, l.display_name,
                            SUM(u.requested_file_count) AS covered
                     FROM location_content coverage
                     JOIN app_uncovered_content u ON u.content_key = coverage.content_key
                     JOIN locations l ON l.location_id = coverage.location_id
                     GROUP BY l.location_id, l.display_name
                     ORDER BY covered DESC, l.location_id",
                )
                .map_err(|source| sqlite_error(database, source))?;
            let collected = statement
                .query_map([&device_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|source| sqlite_error(database, source))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|source| sqlite_error(database, source))?;
            collected
                .into_iter()
                .map(|(location_id, location_name, covered)| {
                    Ok(AttachmentLocation {
                        location_id,
                        location_name,
                        requested_files_covered: sql_u64(covered, "Location coverage count")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        connection
            .execute(
                "DELETE FROM app_uncovered_content AS u
                 WHERE EXISTS (
                     SELECT 1 FROM copy_claims cc
                     WHERE (
                         (u.object_id IS NOT NULL AND cc.object_id = u.object_id)
                         OR (u.object_id IS NULL AND u.external_identity_id IS NOT NULL
                             AND cc.external_identity_id = u.external_identity_id)
                     )
                       AND cc.state = 'present'
                       AND EXISTS (
                           SELECT 1 FROM locations l
                           WHERE l.location_id = cc.location_id
                             AND l.status = 'active' AND l.device_id = ?1
                       )
                 )",
                [&device_id],
            )
            .map_err(|source| sqlite_error(database, source))?;
        steps.push(AttachmentStep {
            device_id,
            device_name,
            site_id,
            site_name,
            newly_covered_files: sql_u64(covered, "Device coverage count")?,
            locations,
        });
    }
    let no_attachable_copy_count = connection
        .query_row(
            "SELECT COALESCE(SUM(requested_file_count), 0)
             FROM app_uncovered_content",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|source| sqlite_error(database, source))?;
    Ok(AttachmentPlan {
        algorithm: "deterministic_greedy_device_cover",
        optimality: "not_guaranteed",
        steps,
        no_attachable_copy_count: sql_u64(no_attachable_copy_count, "no-attachable-copy count")?,
    })
}

fn validate_limit(limit: usize) -> Result<()> {
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(AppIntegrationError::InvalidLimit)
    }
}

fn open_snapshot(database: &V2ProjectionDb, current: &V2CanonicalCursor) -> Result<Connection> {
    let connection =
        Connection::open(database.path()).map_err(|source| sqlite_error(database, source))?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; BEGIN;")
        .map_err(|source| sqlite_error(database, source))?;
    require_current_projection(database, &connection, current)?;
    Ok(connection)
}

fn frontier_is_at_or_before(base: &CausalFrontier, current: &CausalFrontier) -> bool {
    base.archive_id == current.archive_id
        && base.genesis_hash == current.genesis_hash
        && base.origins.iter().all(|base_origin| {
            current
                .origins
                .binary_search_by(|origin| origin.origin_id.cmp(&base_origin.origin_id))
                .ok()
                .is_some_and(|index| current.origins[index].seq >= base_origin.seq)
        })
}

fn sqlite_error(database: &V2ProjectionDb, source: rusqlite::Error) -> AppIntegrationError {
    AppIntegrationError::Sqlite {
        path: database.path().to_path_buf(),
        source,
    }
}

fn encode_token<T: Serialize>(token: &T) -> Result<String> {
    serde_json::to_vec(token)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| AppIntegrationError::InvalidContinuation)
}

fn decode_token<T: for<'de> Deserialize<'de>>(token: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| AppIntegrationError::InvalidContinuation)?;
    serde_json::from_slice(&bytes).map_err(|_| AppIntegrationError::InvalidContinuation)
}

fn path_bytes(path: &AppPath) -> Result<Vec<u8>> {
    match path.encoding.as_str() {
        "utf8" => path
            .text
            .as_ref()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| AppIntegrationError::UnsafePath(path.display.clone())),
        _ => path
            .base64
            .as_ref()
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .ok_or_else(|| AppIntegrationError::UnsafePath(path.display.clone())),
    }
}

fn db_path(encoding: &str, bytes: Vec<u8>) -> Result<PathBuf> {
    match encoding {
        "utf8" => String::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| AppIntegrationError::UnsafePath("invalid UTF-8 path".to_owned())),
        #[cfg(unix)]
        "unix_bytes" => {
            use std::os::unix::ffi::OsStringExt as _;
            Ok(PathBuf::from(OsString::from_vec(bytes)))
        }
        #[cfg(windows)]
        "windows_utf16le" => {
            use std::os::windows::ffi::OsStringExt as _;
            if bytes.len() % 2 != 0 {
                return Err(AppIntegrationError::UnsafePath(
                    "odd-length UTF-16 path".to_owned(),
                ));
            }
            let words = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            Ok(PathBuf::from(OsString::from_wide(&words)))
        }
        _ => Err(AppIntegrationError::UnsafePath(format!(
            "unsupported path encoding {encoding:?}"
        ))),
    }
}

fn safe_join(base: &Path, relative: &Path) -> Result<PathBuf> {
    if !base.is_absolute() || relative.is_absolute() {
        return Err(AppIntegrationError::UnsafePath(
            relative.to_string_lossy().into_owned(),
        ));
    }
    for component in relative.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err(AppIntegrationError::UnsafePath(
                relative.to_string_lossy().into_owned(),
            ));
        }
    }
    Ok(base.join(relative))
}

fn optional_u64(value: Option<i64>) -> Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                AppIntegrationError::InvalidProjectedData("negative timestamp in SQLite".to_owned())
            })
        })
        .transpose()
}

fn sql_i64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        AppIntegrationError::InvalidProjectedData(format!("{field} exceeds SQLite range"))
    })
}

fn sql_u64(value: i64, field: &'static str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| AppIntegrationError::InvalidProjectedData(format!("{field} is negative")))
}
