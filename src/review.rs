//! Bounded catalog review queries.
//!
//! Routine summaries use SQLite only. Explicit v2 history reads stream and
//! authenticate canonical records because their payloads are not duplicated
//! in the materialized view.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::discovery::{EncodedPath, PathEncoding};
use crate::projection::{ProjectionDb, ProjectionError};
use crate::v2_event::V2RecordKind;
use crate::v2_projection::{V2ProjectionDb, V2ProjectionError};
use crate::v2_store::{V2OriginStore, V2StoreError, VerifiedV2Record};

const OUTPUT_VERSION: u32 = 1;
const TOKEN_VERSION: u32 = 1;
const MAX_PAGE_SIZE: usize = 1_000;

pub type Result<T> = std::result::Result<T, ReviewError>;

#[derive(Debug, Error)]
pub enum ReviewError {
    #[error(transparent)]
    Projection(#[from] ProjectionError),

    #[error(transparent)]
    V2Projection(#[from] V2ProjectionError),

    #[error(transparent)]
    V2Store(#[from] V2StoreError),

    #[error("SQLite operation failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("page limit must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidLimit,

    #[error("invalid continuation token")]
    InvalidContinuation,

    #[error("invalid review filter: {0}")]
    InvalidFilter(String),

    #[error("continuation token is stale; restart the query")]
    StaleContinuation,

    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },
}

impl ReviewError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Projection(error) => error.code(),
            Self::V2Projection(error) => error.code(),
            Self::V2Store(error) => error.code(),
            Self::Sqlite { .. } => "review_sqlite",
            Self::InvalidLimit => "invalid_limit",
            Self::InvalidContinuation => "invalid_continuation",
            Self::InvalidFilter(_) => "invalid_filter",
            Self::StaleContinuation => "stale_continuation",
            Self::NotFound { .. } => "not_found",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LosslessPath {
    pub encoding: String,
    pub display: String,
    pub text: Option<String>,
    pub base64: Option<String>,
}

impl LosslessPath {
    fn from_parts(encoding: String, bytes: Vec<u8>, display: String) -> Self {
        if encoding == "utf8" {
            Self {
                encoding,
                display,
                text: String::from_utf8(bytes).ok(),
                base64: None,
            }
        } else {
            Self {
                encoding,
                display,
                text: None,
                base64: Some(URL_SAFE_NO_PAD.encode(bytes)),
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FileFilter {
    pub collection_id: Option<String>,
    pub exact_path: Option<EncodedPath>,
    pub path_prefix: Option<EncodedPath>,
    pub identity_state: Option<String>,
    pub object_id: Option<String>,
    pub external_identity_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FilePageRequest {
    pub filter: FileFilter,
    pub limit: usize,
    pub continuation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSummary {
    pub file_ref_id: String,
    pub collection_id: String,
    pub collection_name: String,
    pub logical_path: LosslessPath,
    pub identity_state: String,
    pub object_id: Option<String>,
    pub external_identity_id: Option<String>,
    pub size_bytes: Option<u64>,
    pub current_copy_count: u64,
    pub present_copy_count: u64,
    pub last_seen_time_utc_ms: Option<u64>,
    pub last_verified_time_utc_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilePage {
    pub version: u32,
    pub applied_event_seq: u64,
    pub items: Vec<FileSummary>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopyReview {
    pub copy_claim_id: String,
    pub state: String,
    pub claim_basis: String,
    pub relative_path: LosslessPath,
    pub location_id: String,
    pub location_name: String,
    pub location_kind: String,
    pub location_status: String,
    pub archive_root_id: Option<String>,
    pub archive_root_name: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_identity_state: Option<String>,
    pub site_id: Option<String>,
    pub site_name: Option<String>,
    pub encryption_state: Option<String>,
    pub trust_level: Option<String>,
    pub expected_availability: String,
    pub last_seen_time_utc_ms: Option<u64>,
    pub last_verified_time_utc_ms: Option<u64>,
    pub last_verification_result: Option<String>,
    pub last_error_code: Option<String>,
    pub last_error_detail: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CopyFilter {
    pub copy_claim_id: Option<String>,
    pub object_id: Option<String>,
    pub external_identity_id: Option<String>,
    pub location_id: Option<String>,
    pub device_id: Option<String>,
    pub site_id: Option<String>,
    pub state: Option<String>,
    pub verified_before_utc_ms: Option<u64>,
    pub observed_before_utc_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CopyPageRequest {
    pub filter: CopyFilter,
    pub limit: usize,
    pub continuation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopyPage {
    pub version: u32,
    pub applied_event_seq: u64,
    pub items: Vec<CopyReview>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileReview {
    pub version: u32,
    pub applied_event_seq: u64,
    pub file: FileSummary,
    pub external_namespace: Option<String>,
    pub external_key: Option<String>,
    pub copies: Vec<CopyReview>,
    pub copies_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEntry {
    pub seq: u64,
    pub event_id: String,
    pub event_type: String,
    pub time_utc_ms: u64,
    pub actor_id: String,
    pub host_id: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryPage {
    pub version: u32,
    pub applied_event_seq: u64,
    pub items: Vec<HistoryEntry>,
    pub next_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2HistoryEntry {
    pub origin_id: String,
    pub origin_seq: u64,
    pub record_id: String,
    pub time_utc_ms: u64,
    pub batch_id: String,
    pub operation_kind: String,
    pub item_index: u64,
    pub item_kind: String,
    pub item: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2HistoryPage {
    pub version: u32,
    pub accepted_frontier_hash: String,
    pub items: Vec<V2HistoryEntry>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectHashReview {
    pub hash_algo: String,
    pub hash_hex: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectReview {
    pub version: u32,
    pub applied_event_seq: u64,
    pub object_id: String,
    pub canonical_hash_algo: String,
    pub canonical_hash_hex: String,
    pub size_bytes: u64,
    pub media_type: Option<String>,
    pub extension_hint: Option<String>,
    pub hashes: Vec<ObjectHashReview>,
    pub files: FilePage,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileToken {
    version: u32,
    applied_event_seq: u64,
    query_hash: String,
    collection_id: String,
    path_encoding: String,
    path_bytes: String,
    file_ref_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyToken {
    version: u32,
    applied_event_seq: u64,
    query_hash: String,
    location_id: String,
    path_encoding: String,
    path_bytes: String,
    copy_claim_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2HistoryToken {
    version: u32,
    accepted_frontier_hash: String,
    subject_kind: String,
    subject_id: String,
    offset: u64,
}

#[derive(Debug, Clone)]
struct V2BatchHistoryContext {
    operation_kind: String,
    item_schema_version: u64,
    defaults: serde_json::Value,
}

impl ProjectionDb {
    pub fn find_files(&self, request: FilePageRequest) -> Result<FilePage> {
        validate_limit(request.limit)?;
        validate_filter(&request.filter)?;
        let applied_event_seq = self.status()?.cursor.applied_seq;
        let query_hash = file_query_hash(&request.filter);
        let cursor = request
            .continuation
            .as_deref()
            .map(decode_file_token)
            .transpose()?;
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.applied_event_seq != applied_event_seq || cursor.query_hash != query_hash
        }) {
            return Err(ReviewError::StaleContinuation);
        }

        let connection = open(self.path())?;
        let prefix_upper = request
            .filter
            .path_prefix
            .as_ref()
            .and_then(|path| exclusive_prefix_end(&path.bytes));
        let cursor_bytes = cursor
            .as_ref()
            .map(|cursor| URL_SAFE_NO_PAD.decode(&cursor.path_bytes))
            .transpose()
            .map_err(|_| ReviewError::InvalidContinuation)?;
        let mut statement = connection
            .prepare(
                "WITH object_copy_metrics AS (
                    SELECT object_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NOT NULL
                    GROUP BY object_id
                 ), external_copy_metrics AS (
                    SELECT external_identity_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NULL
                      AND external_identity_id IS NOT NULL
                    GROUP BY external_identity_id
                 )
                 SELECT f.file_ref_id, f.collection_id, c.display_name,
                        f.logical_path_encoding, f.logical_path_bytes,
                        f.logical_path_display, f.identity_state, f.object_id,
                        f.external_identity_id, COALESCE(o.size_bytes, f.observed_size_bytes),
                        COALESCE(om.current_copy_count, em.current_copy_count, 0),
                        COALESCE(om.present_copy_count, em.present_copy_count, 0),
                        COALESCE(om.last_seen_time_utc_ms, em.last_seen_time_utc_ms),
                        COALESCE(om.last_verified_time_utc_ms, em.last_verified_time_utc_ms)
                 FROM file_refs f
                 JOIN collections c ON c.collection_id = f.collection_id
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 LEFT JOIN object_copy_metrics om ON om.object_id = f.object_id
                 LEFT JOIN external_copy_metrics em
                   ON f.object_id IS NULL AND em.external_identity_id = f.external_identity_id
                 WHERE f.path_state = 'active'
                   AND (?1 IS NULL OR f.collection_id = ?1)
                   AND (?2 IS NULL OR (f.logical_path_encoding = ?2 AND f.logical_path_bytes = ?3))
                   AND (?4 IS NULL OR (f.logical_path_encoding = ?4
                        AND f.logical_path_bytes >= ?5
                        AND (?6 IS NULL OR f.logical_path_bytes < ?6)))
                   AND (?7 IS NULL OR f.identity_state = ?7)
                   AND (?8 IS NULL OR f.object_id = ?8)
                   AND (?9 IS NULL OR f.external_identity_id = ?9)
                   AND (?10 IS NULL OR (f.collection_id, f.logical_path_encoding,
                        f.logical_path_bytes, f.file_ref_id) > (?10, ?11, ?12, ?13))
                 ORDER BY f.collection_id, f.logical_path_encoding,
                          f.logical_path_bytes, f.file_ref_id
                 LIMIT ?14",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let exact = request.filter.exact_path.as_ref();
        let prefix = request.filter.path_prefix.as_ref();
        let rows = statement
            .query_map(
                params![
                    request.filter.collection_id,
                    exact.map(|path| path.encoding.as_str()),
                    exact.map(|path| path.bytes.as_slice()),
                    prefix.map(|path| path.encoding.as_str()),
                    prefix.map(|path| path.bytes.as_slice()),
                    prefix_upper,
                    request.filter.identity_state,
                    request.filter.object_id,
                    request.filter.external_identity_id,
                    cursor.as_ref().map(|cursor| cursor.collection_id.as_str()),
                    cursor.as_ref().map(|cursor| cursor.path_encoding.as_str()),
                    cursor_bytes,
                    cursor.as_ref().map(|cursor| cursor.file_ref_id.as_str()),
                    i64::try_from(request.limit + 1).unwrap_or(i64::MAX),
                ],
                file_summary_from_row,
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut items = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let has_more = items.len() > request.limit;
        items.truncate(request.limit);
        let next = if has_more {
            items
                .last()
                .map(|item| encode_file_token(item, applied_event_seq, &query_hash))
                .transpose()?
        } else {
            None
        };
        Ok(FilePage {
            version: OUTPUT_VERSION,
            applied_event_seq,
            items,
            next,
        })
    }

    pub fn review_file(&self, file_ref_id: &str) -> Result<FileReview> {
        let applied_event_seq = self.status()?.cursor.applied_seq;
        let connection = open(self.path())?;
        let file = connection
            .query_row(
                "WITH object_copy_metrics AS (
                    SELECT object_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NOT NULL
                    GROUP BY object_id
                 ), external_copy_metrics AS (
                    SELECT external_identity_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NULL
                      AND external_identity_id IS NOT NULL
                    GROUP BY external_identity_id
                 )
                 SELECT f.file_ref_id, f.collection_id, c.display_name,
                        f.logical_path_encoding, f.logical_path_bytes,
                        f.logical_path_display, f.identity_state, f.object_id,
                        f.external_identity_id, COALESCE(o.size_bytes, f.observed_size_bytes),
                        COALESCE(om.current_copy_count, em.current_copy_count, 0),
                        COALESCE(om.present_copy_count, em.present_copy_count, 0),
                        COALESCE(om.last_seen_time_utc_ms, em.last_seen_time_utc_ms),
                        COALESCE(om.last_verified_time_utc_ms, em.last_verified_time_utc_ms)
                 FROM file_refs f
                 JOIN collections c ON c.collection_id = f.collection_id
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 LEFT JOIN object_copy_metrics om ON om.object_id = f.object_id
                 LEFT JOIN external_copy_metrics em
                   ON f.object_id IS NULL AND em.external_identity_id = f.external_identity_id
                 WHERE f.file_ref_id = ?1",
                [file_ref_id],
                file_summary_from_row,
            )
            .optional()
            .map_err(|source| sqlite_error(self.path(), source))?
            .ok_or_else(|| ReviewError::NotFound {
                kind: "file",
                id: file_ref_id.to_owned(),
            })?;
        let (external_namespace, external_key) = file
            .external_identity_id
            .as_ref()
            .map(|id| {
                connection
                    .query_row(
                        "SELECT namespace, external_key FROM external_identities
                         WHERE external_identity_id = ?1",
                        [id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
            })
            .transpose()
            .map_err(|source| sqlite_error(self.path(), source))?
            .flatten()
            .map_or((None, None), |(namespace, key)| {
                (Some(namespace), Some(key))
            });
        let mut statement = connection
            .prepare(
                "SELECT cc.copy_claim_id, cc.state, cc.claim_basis,
                        cc.relative_path_encoding, cc.relative_path_bytes,
                        cc.relative_path_display, l.location_id, l.display_name,
                        l.kind, l.status, l.archive_root_id, ar.display_name,
                        l.device_id, d.display_name, d.identity_state,
                        COALESCE(l.site_id, d.current_site_id), s.display_name,
                        l.encryption_state, l.trust_level, l.expected_availability,
                        cc.last_seen_time_utc_ms, cc.last_verified_time_utc_ms,
                        cc.last_verification_result, cc.last_error_code, cc.last_error_detail
                 FROM copy_claims cc
                 JOIN locations l ON l.location_id = cc.location_id
                 LEFT JOIN archive_roots ar ON ar.archive_root_id = l.archive_root_id
                 LEFT JOIN devices d ON d.device_id = l.device_id
                 LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
                 WHERE cc.state != 'superseded'
                   AND ((?1 IS NOT NULL AND cc.object_id = ?1)
                     OR (?1 IS NULL AND ?2 IS NOT NULL AND cc.external_identity_id = ?2))
                 ORDER BY l.display_name, cc.relative_path_encoding,
                          cc.relative_path_bytes, cc.copy_claim_id
                 LIMIT ?3",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut copies = statement
            .query_map(
                params![
                    file.object_id,
                    file.external_identity_id,
                    i64::try_from(MAX_PAGE_SIZE + 1).unwrap_or(i64::MAX),
                ],
                copy_review_from_row,
            )
            .map_err(|source| sqlite_error(self.path(), source))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let copies_truncated = copies.len() > MAX_PAGE_SIZE;
        copies.truncate(MAX_PAGE_SIZE);
        Ok(FileReview {
            version: OUTPUT_VERSION,
            applied_event_seq,
            file,
            external_namespace,
            external_key,
            copies,
            copies_truncated,
        })
    }

    pub fn list_copies(&self, request: CopyPageRequest) -> Result<CopyPage> {
        validate_limit(request.limit)?;
        let applied_event_seq = self.status()?.cursor.applied_seq;
        let query_hash = copy_query_hash(&request.filter);
        let cursor = request
            .continuation
            .as_deref()
            .map(decode_copy_token)
            .transpose()?;
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.applied_event_seq != applied_event_seq || cursor.query_hash != query_hash
        }) {
            return Err(ReviewError::StaleContinuation);
        }
        let cursor_bytes = cursor
            .as_ref()
            .map(|cursor| URL_SAFE_NO_PAD.decode(&cursor.path_bytes))
            .transpose()
            .map_err(|_| ReviewError::InvalidContinuation)?;
        let connection = open(self.path())?;
        let verified_before = request
            .filter
            .verified_before_utc_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_| ReviewError::InvalidFilter("verification time is too large".to_owned()))?;
        let observed_before = request
            .filter
            .observed_before_utc_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_| ReviewError::InvalidFilter("observation time is too large".to_owned()))?;
        let mut statement = connection
            .prepare(
                "SELECT cc.copy_claim_id, cc.state, cc.claim_basis,
                        cc.relative_path_encoding, cc.relative_path_bytes,
                        cc.relative_path_display, l.location_id, l.display_name,
                        l.kind, l.status, l.archive_root_id, ar.display_name,
                        l.device_id, d.display_name, d.identity_state,
                        COALESCE(l.site_id, d.current_site_id), s.display_name,
                        l.encryption_state, l.trust_level, l.expected_availability,
                        cc.last_seen_time_utc_ms, cc.last_verified_time_utc_ms,
                        cc.last_verification_result, cc.last_error_code, cc.last_error_detail
                 FROM copy_claims cc
                 JOIN locations l ON l.location_id = cc.location_id
                 LEFT JOIN archive_roots ar ON ar.archive_root_id = l.archive_root_id
                 LEFT JOIN devices d ON d.device_id = l.device_id
                 LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
                 WHERE cc.state != 'superseded'
                   AND (?1 IS NULL OR cc.copy_claim_id = ?1)
                   AND (?2 IS NULL OR cc.object_id = ?2)
                   AND (?3 IS NULL OR cc.external_identity_id = ?3)
                   AND (?4 IS NULL OR cc.location_id = ?4)
                   AND (?5 IS NULL OR l.device_id = ?5)
                   AND (?6 IS NULL OR COALESCE(l.site_id, d.current_site_id) = ?6)
                   AND (?7 IS NULL OR cc.state = ?7)
                   AND (?8 IS NULL OR cc.last_verified_time_utc_ms IS NULL
                        OR cc.last_verified_time_utc_ms < ?8)
                   AND (?9 IS NULL OR cc.last_seen_time_utc_ms IS NULL
                        OR cc.last_seen_time_utc_ms < ?9)
                   AND (?10 IS NULL OR (cc.location_id, cc.relative_path_encoding,
                        cc.relative_path_bytes, cc.copy_claim_id) > (?10, ?11, ?12, ?13))
                 ORDER BY cc.location_id, cc.relative_path_encoding,
                          cc.relative_path_bytes, cc.copy_claim_id
                 LIMIT ?14",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let rows = statement
            .query_map(
                params![
                    request.filter.copy_claim_id,
                    request.filter.object_id,
                    request.filter.external_identity_id,
                    request.filter.location_id,
                    request.filter.device_id,
                    request.filter.site_id,
                    request.filter.state,
                    verified_before,
                    observed_before,
                    cursor.as_ref().map(|cursor| cursor.location_id.as_str()),
                    cursor.as_ref().map(|cursor| cursor.path_encoding.as_str()),
                    cursor_bytes,
                    cursor.as_ref().map(|cursor| cursor.copy_claim_id.as_str()),
                    i64::try_from(request.limit + 1).unwrap_or(i64::MAX),
                ],
                copy_review_from_row,
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut items = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let has_more = items.len() > request.limit;
        items.truncate(request.limit);
        let next = if has_more {
            items
                .last()
                .map(|item| encode_copy_token(item, applied_event_seq, &query_hash))
                .transpose()?
        } else {
            None
        };
        Ok(CopyPage {
            version: OUTPUT_VERSION,
            applied_event_seq,
            items,
            next,
        })
    }

    pub fn review_copy(&self, copy_claim_id: &str) -> Result<CopyReview> {
        let page = self.list_copies(CopyPageRequest {
            filter: CopyFilter {
                copy_claim_id: Some(copy_claim_id.to_owned()),
                ..CopyFilter::default()
            },
            limit: 1,
            continuation: None,
        })?;
        page.items
            .into_iter()
            .find(|copy| copy.copy_claim_id == copy_claim_id)
            .ok_or_else(|| ReviewError::NotFound {
                kind: "copy",
                id: copy_claim_id.to_owned(),
            })
    }

    pub fn file_history(
        &self,
        file_ref_id: &str,
        after_seq: u64,
        limit: usize,
    ) -> Result<HistoryPage> {
        validate_limit(limit)?;
        let applied_event_seq = self.status()?.cursor.applied_seq;
        let connection = open(self.path())?;
        let known: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM file_refs WHERE file_ref_id = ?1)",
                [file_ref_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        if !known {
            return Err(ReviewError::NotFound {
                kind: "file",
                id: file_ref_id.to_owned(),
            });
        }
        let mut statement = connection
            .prepare(
                "SELECT seq, event_id, event_type, event_time_utc_ms,
                        actor_id, host_id, payload_json
                 FROM events WHERE file_ref_id = ?1 AND seq > ?2
                 ORDER BY seq LIMIT ?3",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let rows = statement
            .query_map(
                params![
                    file_ref_id,
                    sql_i64(after_seq)?,
                    i64::try_from(limit + 1).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut items = Vec::new();
        for row in rows {
            let (seq, event_id, event_type, time, actor_id, host_id, payload) =
                row.map_err(|source| sqlite_error(self.path(), source))?;
            items.push(HistoryEntry {
                seq: sql_u64(seq)?,
                event_id,
                event_type,
                time_utc_ms: sql_u64(time)?,
                actor_id,
                host_id,
                payload: serde_json::from_str(&payload).map_err(|_| ReviewError::Sqlite {
                    path: self.path().to_path_buf(),
                    source: rusqlite::Error::InvalidQuery,
                })?,
            });
        }
        let has_more = items.len() > limit;
        items.truncate(limit);
        Ok(HistoryPage {
            version: OUTPUT_VERSION,
            applied_event_seq,
            next_seq: has_more.then(|| items.last().map_or(after_seq, |item| item.seq)),
            items,
        })
    }

    pub fn review_object(
        &self,
        object_id: &str,
        limit: usize,
        continuation: Option<String>,
    ) -> Result<ObjectReview> {
        validate_limit(limit)?;
        let connection = open(self.path())?;
        let object = connection
            .query_row(
                "SELECT canonical_hash_algo, canonical_hash_hex, size_bytes,
                        media_type, extension_hint
                 FROM objects WHERE object_id = ?1",
                [object_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(self.path(), source))?
            .ok_or_else(|| ReviewError::NotFound {
                kind: "object",
                id: object_id.to_owned(),
            })?;
        let mut statement = connection
            .prepare(
                "SELECT hash_algo, hash_hex, source FROM object_hashes
                 WHERE object_id = ?1 ORDER BY hash_algo, hash_hex",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let hashes = statement
            .query_map([object_id], |row| {
                Ok(ObjectHashReview {
                    hash_algo: row.get(0)?,
                    hash_hex: row.get(1)?,
                    source: row.get(2)?,
                })
            })
            .map_err(|source| sqlite_error(self.path(), source))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let files = self.find_files(FilePageRequest {
            filter: FileFilter {
                object_id: Some(object_id.to_owned()),
                ..FileFilter::default()
            },
            limit,
            continuation,
        })?;
        Ok(ObjectReview {
            version: OUTPUT_VERSION,
            applied_event_seq: files.applied_event_seq,
            object_id: object_id.to_owned(),
            canonical_hash_algo: object.0,
            canonical_hash_hex: object.1,
            size_bytes: sql_u64(object.2)?,
            media_type: object.3,
            extension_hint: object.4,
            hashes,
            files,
        })
    }

    pub fn object_history(
        &self,
        object_id: &str,
        after_seq: u64,
        limit: usize,
    ) -> Result<HistoryPage> {
        validate_limit(limit)?;
        let connection = open(self.path())?;
        let known: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM objects WHERE object_id = ?1)",
                [object_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        if !known {
            return Err(ReviewError::NotFound {
                kind: "object",
                id: object_id.to_owned(),
            });
        }
        history_query(self, "object_id", object_id, after_seq, limit)
    }
}

impl V2ProjectionDb {
    pub fn find_files(&self, request: FilePageRequest) -> Result<FilePage> {
        validate_limit(request.limit)?;
        validate_filter(&request.filter)?;
        let status = self.status()?;
        let applied_event_seq = status.records;
        let query_hash = file_query_hash_at(&request.filter, &status.applied_frontier_hash);
        let cursor = request
            .continuation
            .as_deref()
            .map(decode_file_token)
            .transpose()?;
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.applied_event_seq != applied_event_seq || cursor.query_hash != query_hash
        }) {
            return Err(ReviewError::StaleContinuation);
        }

        let connection = open(self.path())?;
        let prefix_upper = request
            .filter
            .path_prefix
            .as_ref()
            .and_then(|path| exclusive_prefix_end(&path.bytes));
        let cursor_bytes = cursor
            .as_ref()
            .map(|cursor| URL_SAFE_NO_PAD.decode(&cursor.path_bytes))
            .transpose()
            .map_err(|_| ReviewError::InvalidContinuation)?;
        let mut statement = connection
            .prepare(
                "WITH object_copy_metrics AS (
                    SELECT object_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NOT NULL
                    GROUP BY object_id
                 ), external_copy_metrics AS (
                    SELECT external_identity_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NULL
                      AND external_identity_id IS NOT NULL
                    GROUP BY external_identity_id
                 )
                 SELECT f.file_ref_id, f.collection_id, c.display_name,
                        f.logical_path_encoding, f.logical_path_bytes,
                        f.logical_path_display, f.identity_state, f.object_id,
                        f.external_identity_id, COALESCE(o.size_bytes, f.observed_size_bytes),
                        COALESCE(om.current_copy_count, em.current_copy_count, 0),
                        COALESCE(om.present_copy_count, em.present_copy_count, 0),
                        COALESCE(om.last_seen_time_utc_ms, em.last_seen_time_utc_ms),
                        COALESCE(om.last_verified_time_utc_ms, em.last_verified_time_utc_ms)
                 FROM file_refs f
                 JOIN collections c ON c.collection_id = f.collection_id
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 LEFT JOIN object_copy_metrics om ON om.object_id = f.object_id
                 LEFT JOIN external_copy_metrics em
                   ON f.object_id IS NULL AND em.external_identity_id = f.external_identity_id
                 WHERE f.path_state = 'active'
                   AND (?1 IS NULL OR f.collection_id = ?1)
                   AND (?2 IS NULL OR (f.logical_path_encoding = ?2 AND f.logical_path_bytes = ?3))
                   AND (?4 IS NULL OR (f.logical_path_encoding = ?4
                        AND f.logical_path_bytes >= ?5
                        AND (?6 IS NULL OR f.logical_path_bytes < ?6)))
                   AND (?7 IS NULL OR f.identity_state = ?7)
                   AND (?8 IS NULL OR f.object_id = ?8)
                   AND (?9 IS NULL OR f.external_identity_id = ?9)
                   AND (?10 IS NULL OR (f.collection_id, f.logical_path_encoding,
                        f.logical_path_bytes, f.file_ref_id) > (?10, ?11, ?12, ?13))
                 ORDER BY f.collection_id, f.logical_path_encoding,
                          f.logical_path_bytes, f.file_ref_id
                 LIMIT ?14",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let exact = request.filter.exact_path.as_ref();
        let prefix = request.filter.path_prefix.as_ref();
        let rows = statement
            .query_map(
                params![
                    request.filter.collection_id,
                    exact.map(|path| path.encoding.as_str()),
                    exact.map(|path| path.bytes.as_slice()),
                    prefix.map(|path| path.encoding.as_str()),
                    prefix.map(|path| path.bytes.as_slice()),
                    prefix_upper,
                    request.filter.identity_state,
                    request.filter.object_id,
                    request.filter.external_identity_id,
                    cursor.as_ref().map(|cursor| cursor.collection_id.as_str()),
                    cursor.as_ref().map(|cursor| cursor.path_encoding.as_str()),
                    cursor_bytes,
                    cursor.as_ref().map(|cursor| cursor.file_ref_id.as_str()),
                    i64::try_from(request.limit + 1).unwrap_or(i64::MAX),
                ],
                file_summary_from_row,
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut items = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let has_more = items.len() > request.limit;
        items.truncate(request.limit);
        let next = if has_more {
            items
                .last()
                .map(|item| encode_file_token(item, applied_event_seq, &query_hash))
                .transpose()?
        } else {
            None
        };
        Ok(FilePage {
            version: 2,
            applied_event_seq,
            items,
            next,
        })
    }

    pub fn review_file(&self, file_ref_id: &str) -> Result<FileReview> {
        let status = self.status()?;
        let applied_event_seq = status.records;
        let connection = open(self.path())?;
        let file = connection
            .query_row(
                "WITH object_copy_metrics AS (
                    SELECT object_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NOT NULL
                    GROUP BY object_id
                 ), external_copy_metrics AS (
                    SELECT external_identity_id,
                           COUNT(*) AS current_copy_count,
                           SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END) AS present_copy_count,
                           MAX(last_seen_time_utc_ms) AS last_seen_time_utc_ms,
                           MAX(last_verified_time_utc_ms) AS last_verified_time_utc_ms
                    FROM copy_claims
                    WHERE state != 'superseded' AND object_id IS NULL
                      AND external_identity_id IS NOT NULL
                    GROUP BY external_identity_id
                 )
                 SELECT f.file_ref_id, f.collection_id, c.display_name,
                        f.logical_path_encoding, f.logical_path_bytes,
                        f.logical_path_display, f.identity_state, f.object_id,
                        f.external_identity_id, COALESCE(o.size_bytes, f.observed_size_bytes),
                        COALESCE(om.current_copy_count, em.current_copy_count, 0),
                        COALESCE(om.present_copy_count, em.present_copy_count, 0),
                        COALESCE(om.last_seen_time_utc_ms, em.last_seen_time_utc_ms),
                        COALESCE(om.last_verified_time_utc_ms, em.last_verified_time_utc_ms)
                 FROM file_refs f
                 JOIN collections c ON c.collection_id = f.collection_id
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 LEFT JOIN object_copy_metrics om ON om.object_id = f.object_id
                 LEFT JOIN external_copy_metrics em
                   ON f.object_id IS NULL AND em.external_identity_id = f.external_identity_id
                 WHERE f.file_ref_id = ?1",
                [file_ref_id],
                file_summary_from_row,
            )
            .optional()
            .map_err(|source| sqlite_error(self.path(), source))?
            .ok_or_else(|| ReviewError::NotFound {
                kind: "file",
                id: file_ref_id.to_owned(),
            })?;
        let (external_namespace, external_key) = file
            .external_identity_id
            .as_ref()
            .map(|id| {
                connection
                    .query_row(
                        "SELECT namespace, external_key FROM external_identities
                         WHERE external_identity_id = ?1",
                        [id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
            })
            .transpose()
            .map_err(|source| sqlite_error(self.path(), source))?
            .flatten()
            .map_or((None, None), |(namespace, key)| {
                (Some(namespace), Some(key))
            });
        let mut statement = connection
            .prepare(
                "SELECT cc.copy_claim_id, cc.state, cc.claim_basis,
                        cc.relative_path_encoding, cc.relative_path_bytes,
                        cc.relative_path_display, l.location_id, l.display_name,
                        l.kind, l.status, l.archive_root_id, ar.display_name,
                        l.device_id, d.display_name, d.identity_state,
                        COALESCE(l.site_id, d.current_site_id), s.display_name,
                        l.encryption_state, l.trust_level, l.expected_availability,
                        cc.last_seen_time_utc_ms, cc.last_verified_time_utc_ms,
                        cc.last_verification_result, cc.last_error_code, cc.last_error_detail
                 FROM copy_claims cc
                 JOIN locations l ON l.location_id = cc.location_id
                 LEFT JOIN archive_roots ar ON ar.archive_root_id = l.archive_root_id
                 LEFT JOIN devices d ON d.device_id = l.device_id
                 LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
                 WHERE cc.state != 'superseded'
                   AND ((?1 IS NOT NULL AND cc.object_id = ?1)
                     OR (?1 IS NULL AND ?2 IS NOT NULL AND cc.external_identity_id = ?2))
                 ORDER BY l.display_name, cc.relative_path_encoding,
                          cc.relative_path_bytes, cc.copy_claim_id
                 LIMIT ?3",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut copies = statement
            .query_map(
                params![
                    file.object_id,
                    file.external_identity_id,
                    i64::try_from(MAX_PAGE_SIZE + 1).unwrap_or(i64::MAX),
                ],
                copy_review_from_row,
            )
            .map_err(|source| sqlite_error(self.path(), source))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let copies_truncated = copies.len() > MAX_PAGE_SIZE;
        copies.truncate(MAX_PAGE_SIZE);
        Ok(FileReview {
            version: 2,
            applied_event_seq,
            file,
            external_namespace,
            external_key,
            copies,
            copies_truncated,
        })
    }

    pub fn review_object(
        &self,
        object_id: &str,
        limit: usize,
        continuation: Option<String>,
    ) -> Result<ObjectReview> {
        validate_limit(limit)?;
        let connection = open(self.path())?;
        let object = connection
            .query_row(
                "SELECT canonical_hash_algo, canonical_hash_hex, size_bytes,
                        media_type, extension_hint
                 FROM objects WHERE object_id = ?1",
                [object_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(self.path(), source))?
            .ok_or_else(|| ReviewError::NotFound {
                kind: "object",
                id: object_id.to_owned(),
            })?;
        let mut statement = connection
            .prepare(
                "SELECT hash_algo, hash_hex, source FROM object_hashes
                 WHERE object_id = ?1 ORDER BY hash_algo, hash_hex",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let hashes = statement
            .query_map([object_id], |row| {
                Ok(ObjectHashReview {
                    hash_algo: row.get(0)?,
                    hash_hex: row.get(1)?,
                    source: row.get(2)?,
                })
            })
            .map_err(|source| sqlite_error(self.path(), source))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let files = self.find_files(FilePageRequest {
            filter: FileFilter {
                object_id: Some(object_id.to_owned()),
                ..FileFilter::default()
            },
            limit,
            continuation,
        })?;
        Ok(ObjectReview {
            version: 2,
            applied_event_seq: files.applied_event_seq,
            object_id: object_id.to_owned(),
            canonical_hash_algo: object.0,
            canonical_hash_hex: object.1,
            size_bytes: sql_u64(object.2)?,
            media_type: object.3,
            extension_hint: object.4,
            hashes,
            files,
        })
    }

    pub fn file_history(
        &self,
        store: &V2OriginStore,
        file_ref_id: &str,
        limit: usize,
        continuation: Option<String>,
    ) -> Result<V2HistoryPage> {
        self.require_v2_subject("file", "file_refs", "file_ref_id", file_ref_id)?;
        v2_history(
            store,
            "file",
            "file_ref_id",
            file_ref_id,
            limit,
            continuation,
        )
    }

    pub fn object_history(
        &self,
        store: &V2OriginStore,
        object_id: &str,
        limit: usize,
        continuation: Option<String>,
    ) -> Result<V2HistoryPage> {
        self.require_v2_subject("object", "objects", "object_id", object_id)?;
        v2_history(store, "object", "object_id", object_id, limit, continuation)
    }

    fn require_v2_subject(
        &self,
        kind: &'static str,
        table: &'static str,
        column: &'static str,
        id: &str,
    ) -> Result<()> {
        let connection = open(self.path())?;
        let known: bool = connection
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {column} = ?1)"),
                [id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        if known {
            Ok(())
        } else {
            Err(ReviewError::NotFound {
                kind,
                id: id.to_owned(),
            })
        }
    }
}

fn v2_history(
    store: &V2OriginStore,
    subject_kind: &'static str,
    subject_field: &'static str,
    subject_id: &str,
    limit: usize,
    continuation: Option<String>,
) -> Result<V2HistoryPage> {
    validate_limit(limit)?;
    let cursor = continuation
        .as_deref()
        .map(decode_v2_history_token)
        .transpose()?;
    if cursor.as_ref().is_some_and(|cursor| {
        cursor.subject_kind != subject_kind || cursor.subject_id != subject_id
    }) {
        return Err(ReviewError::InvalidContinuation);
    }
    let offset = cursor.as_ref().map_or(0, |cursor| cursor.offset);
    let end = offset
        .checked_add(u64::try_from(limit).map_err(|_| ReviewError::InvalidLimit)?)
        .and_then(|value| value.checked_add(1))
        .ok_or(ReviewError::InvalidContinuation)?;
    let mut batches = BTreeMap::<String, V2BatchHistoryContext>::new();
    let mut matched = 0_u64;
    let mut items = Vec::with_capacity(limit.saturating_add(1));
    let verified = store.visit_verified(|record| {
        collect_v2_history_record(
            record,
            subject_field,
            subject_id,
            offset,
            end,
            &mut matched,
            &mut items,
            &mut batches,
        )
    })?;
    if cursor
        .as_ref()
        .is_some_and(|cursor| cursor.accepted_frontier_hash != verified.accepted_frontier_hash)
    {
        return Err(ReviewError::StaleContinuation);
    }
    let has_more = items.len() > limit;
    items.truncate(limit);
    let next = if has_more {
        Some(encode_v2_history_token(&V2HistoryToken {
            version: TOKEN_VERSION,
            accepted_frontier_hash: verified.accepted_frontier_hash.clone(),
            subject_kind: subject_kind.to_owned(),
            subject_id: subject_id.to_owned(),
            offset: offset
                .checked_add(u64::try_from(items.len()).unwrap_or(u64::MAX))
                .ok_or(ReviewError::InvalidContinuation)?,
        })?)
    } else {
        None
    };
    Ok(V2HistoryPage {
        version: 2,
        accepted_frontier_hash: verified.accepted_frontier_hash,
        items,
        next,
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_v2_history_record(
    record: &VerifiedV2Record,
    subject_field: &str,
    subject_id: &str,
    offset: u64,
    end: u64,
    matched: &mut u64,
    entries: &mut Vec<V2HistoryEntry>,
    batches: &mut BTreeMap<String, V2BatchHistoryContext>,
) -> std::result::Result<(), V2StoreError> {
    let envelope = &record.record.envelope;
    match envelope.record_kind {
        V2RecordKind::BatchStart => {
            let payload = history_object(&envelope.payload, "batch_start payload")?;
            let operation_kind = history_string(payload, "operation_kind")?.to_owned();
            let item_schema_version = history_number(payload, "item_schema_version")?;
            if !matches!(item_schema_version, 1 | 2) {
                return Err(V2StoreError::Invalid(format!(
                    "unsupported batch item schema version {item_schema_version}"
                )));
            }
            let defaults = payload
                .get("defaults")
                .filter(|value| value.is_object())
                .cloned()
                .ok_or_else(|| {
                    V2StoreError::Invalid("batch_start defaults must be an object".to_owned())
                })?;
            batches.insert(
                envelope.batch_id.clone(),
                V2BatchHistoryContext {
                    operation_kind,
                    item_schema_version,
                    defaults,
                },
            );
        }
        V2RecordKind::BatchChunk => {
            let batch = batches.get(&envelope.batch_id).ok_or_else(|| {
                V2StoreError::Invalid(format!(
                    "batch {} chunk has no preceding start",
                    envelope.batch_id
                ))
            })?;
            let payload = history_object(&envelope.payload, "batch_chunk payload")?;
            let first = history_number(payload, "first_item_index")?;
            let chunk_items = payload
                .get("items")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    V2StoreError::Invalid("batch_chunk items must be an array".to_owned())
                })?;
            for (position, raw_item) in chunk_items.iter().enumerate() {
                let item = materialize_v2_history_item(
                    raw_item,
                    batch.item_schema_version,
                    &batch.defaults,
                )?;
                if item.get(subject_field).and_then(serde_json::Value::as_str) != Some(subject_id) {
                    continue;
                }
                let item_position = u64::try_from(position)
                    .map_err(|_| V2StoreError::Invalid("item index overflow".to_owned()))?;
                let item_index = first
                    .checked_add(item_position)
                    .ok_or_else(|| V2StoreError::Invalid("item index overflow".to_owned()))?;
                if *matched >= offset && *matched < end {
                    let item_kind = history_string(&item, "kind")?.to_owned();
                    entries.push(V2HistoryEntry {
                        origin_id: envelope.origin_id.clone(),
                        origin_seq: envelope.origin_seq,
                        record_id: envelope.record_id.clone(),
                        time_utc_ms: envelope.time_utc_ms,
                        batch_id: envelope.batch_id.clone(),
                        operation_kind: batch.operation_kind.clone(),
                        item_index,
                        item_kind,
                        item: serde_json::Value::Object(item),
                    });
                }
                *matched = matched
                    .checked_add(1)
                    .ok_or_else(|| V2StoreError::Invalid("history count overflow".to_owned()))?;
            }
        }
        V2RecordKind::BatchComplete => {
            batches.remove(&envelope.batch_id);
        }
    }
    Ok(())
}

fn materialize_v2_history_item(
    item: &serde_json::Value,
    item_schema_version: u64,
    defaults: &serde_json::Value,
) -> std::result::Result<serde_json::Map<String, serde_json::Value>, V2StoreError> {
    let item = history_object(item, "batch item")?;
    if item_schema_version == 1 {
        return Ok(item.clone());
    }
    let kind = history_string(item, "kind")?;
    let mut materialized = defaults
        .as_object()
        .and_then(|defaults| defaults.get(kind))
        .map(|values| history_object(values, "item defaults"))
        .transpose()?
        .cloned()
        .unwrap_or_default();
    for (key, value) in item {
        materialized.insert(key.clone(), value.clone());
    }
    Ok(materialized)
}

fn history_object<'a>(
    value: &'a serde_json::Value,
    description: &str,
) -> std::result::Result<&'a serde_json::Map<String, serde_json::Value>, V2StoreError> {
    value
        .as_object()
        .ok_or_else(|| V2StoreError::Invalid(format!("{description} must be an object")))
}

fn history_string<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<&'a str, V2StoreError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| V2StoreError::Invalid(format!("history item is missing string {key}")))
}

fn history_number(
    value: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> std::result::Result<u64, V2StoreError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| V2StoreError::Invalid(format!("history item is missing integer {key}")))
}

fn encode_v2_history_token(token: &V2HistoryToken) -> Result<String> {
    serde_json::to_vec(token)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ReviewError::InvalidContinuation)
}

fn decode_v2_history_token(token: &str) -> Result<V2HistoryToken> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ReviewError::InvalidContinuation)?;
    let token: V2HistoryToken =
        serde_json::from_slice(&bytes).map_err(|_| ReviewError::InvalidContinuation)?;
    if token.version != TOKEN_VERSION
        || token.subject_kind.is_empty()
        || token.subject_id.is_empty()
    {
        return Err(ReviewError::InvalidContinuation);
    }
    Ok(token)
}

fn history_query(
    database: &ProjectionDb,
    column: &'static str,
    id: &str,
    after_seq: u64,
    limit: usize,
) -> Result<HistoryPage> {
    let applied_event_seq = database.status()?.cursor.applied_seq;
    let connection = open(database.path())?;
    let sql = format!(
        "SELECT seq, event_id, event_type, event_time_utc_ms, actor_id, host_id, payload_json
         FROM events WHERE {column} = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3"
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|source| sqlite_error(database.path(), source))?;
    let rows = statement
        .query_map(
            params![
                id,
                sql_i64(after_seq)?,
                i64::try_from(limit + 1).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|source| sqlite_error(database.path(), source))?;
    let mut items = Vec::new();
    for row in rows {
        let (seq, event_id, event_type, time, actor_id, host_id, payload) =
            row.map_err(|source| sqlite_error(database.path(), source))?;
        items.push(HistoryEntry {
            seq: sql_u64(seq)?,
            event_id,
            event_type,
            time_utc_ms: sql_u64(time)?,
            actor_id,
            host_id,
            payload: serde_json::from_str(&payload).map_err(|_| ReviewError::Sqlite {
                path: database.path().to_path_buf(),
                source: rusqlite::Error::InvalidQuery,
            })?,
        });
    }
    let has_more = items.len() > limit;
    items.truncate(limit);
    Ok(HistoryPage {
        version: OUTPUT_VERSION,
        applied_event_seq,
        next_seq: has_more.then(|| items.last().map_or(after_seq, |item| item.seq)),
        items,
    })
}

fn file_summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileSummary> {
    Ok(FileSummary {
        file_ref_id: row.get(0)?,
        collection_id: row.get(1)?,
        collection_name: row.get(2)?,
        logical_path: LosslessPath::from_parts(row.get(3)?, row.get(4)?, row.get(5)?),
        identity_state: row.get(6)?,
        object_id: row.get(7)?,
        external_identity_id: row.get(8)?,
        size_bytes: optional_u64(row.get(9)?)?,
        current_copy_count: sql_u64_sql(row.get(10)?)?,
        present_copy_count: sql_u64_sql(row.get(11)?)?,
        last_seen_time_utc_ms: optional_u64(row.get(12)?)?,
        last_verified_time_utc_ms: optional_u64(row.get(13)?)?,
    })
}

fn copy_review_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CopyReview> {
    Ok(CopyReview {
        copy_claim_id: row.get(0)?,
        state: row.get(1)?,
        claim_basis: row.get(2)?,
        relative_path: LosslessPath::from_parts(row.get(3)?, row.get(4)?, row.get(5)?),
        location_id: row.get(6)?,
        location_name: row.get(7)?,
        location_kind: row.get(8)?,
        location_status: row.get(9)?,
        archive_root_id: row.get(10)?,
        archive_root_name: row.get(11)?,
        device_id: row.get(12)?,
        device_name: row.get(13)?,
        device_identity_state: row.get(14)?,
        site_id: row.get(15)?,
        site_name: row.get(16)?,
        encryption_state: row.get(17)?,
        trust_level: row.get(18)?,
        expected_availability: row.get(19)?,
        last_seen_time_utc_ms: optional_u64(row.get(20)?)?,
        last_verified_time_utc_ms: optional_u64(row.get(21)?)?,
        last_verification_result: row.get(22)?,
        last_error_code: row.get(23)?,
        last_error_detail: row.get(24)?,
    })
}

fn validate_limit(limit: usize) -> Result<()> {
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(ReviewError::InvalidLimit);
    }
    Ok(())
}

fn validate_filter(filter: &FileFilter) -> Result<()> {
    if filter.exact_path.is_some() && filter.path_prefix.is_some() {
        return Err(ReviewError::InvalidContinuation);
    }
    Ok(())
}

fn file_query_hash(filter: &FileFilter) -> String {
    file_query_hash_at(filter, "")
}

fn file_query_hash_at(filter: &FileFilter, projection_snapshot: &str) -> String {
    let path = |path: &Option<EncodedPath>| {
        path.as_ref().map(|path| {
            json!({
                "encoding": path.encoding.as_str(),
                "bytes": URL_SAFE_NO_PAD.encode(&path.bytes),
            })
        })
    };
    blake3::hash(
        serde_json::to_string(&json!({
            "collection_id": filter.collection_id,
            "exact_path": path(&filter.exact_path),
            "path_prefix": path(&filter.path_prefix),
            "identity_state": filter.identity_state,
            "object_id": filter.object_id,
            "external_identity_id": filter.external_identity_id,
            "projection_snapshot": projection_snapshot,
        }))
        .expect("file query shape is serializable")
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

fn encode_file_token(item: &FileSummary, applied_seq: u64, query_hash: &str) -> Result<String> {
    let bytes = item
        .logical_path
        .text
        .as_ref()
        .map(|text| text.as_bytes().to_vec())
        .or_else(|| {
            item.logical_path
                .base64
                .as_ref()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        })
        .ok_or(ReviewError::InvalidContinuation)?;
    let token = FileToken {
        version: TOKEN_VERSION,
        applied_event_seq: applied_seq,
        query_hash: query_hash.to_owned(),
        collection_id: item.collection_id.clone(),
        path_encoding: item.logical_path.encoding.clone(),
        path_bytes: URL_SAFE_NO_PAD.encode(bytes),
        file_ref_id: item.file_ref_id.clone(),
    };
    serde_json::to_vec(&token)
        .map(|value| URL_SAFE_NO_PAD.encode(value))
        .map_err(|_| ReviewError::InvalidContinuation)
}

fn decode_file_token(value: &str) -> Result<FileToken> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ReviewError::InvalidContinuation)?;
    let token: FileToken =
        serde_json::from_slice(&bytes).map_err(|_| ReviewError::InvalidContinuation)?;
    if token.version != TOKEN_VERSION {
        return Err(ReviewError::InvalidContinuation);
    }
    Ok(token)
}

fn copy_query_hash(filter: &CopyFilter) -> String {
    blake3::hash(
        serde_json::to_string(&json!({
            "copy_claim_id": filter.copy_claim_id,
            "object_id": filter.object_id,
            "external_identity_id": filter.external_identity_id,
            "location_id": filter.location_id,
            "device_id": filter.device_id,
            "site_id": filter.site_id,
            "state": filter.state,
            "verified_before_utc_ms": filter.verified_before_utc_ms,
            "observed_before_utc_ms": filter.observed_before_utc_ms,
        }))
        .expect("copy query shape is serializable")
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

fn encode_copy_token(item: &CopyReview, applied_seq: u64, query_hash: &str) -> Result<String> {
    let bytes = item
        .relative_path
        .text
        .as_ref()
        .map(|text| text.as_bytes().to_vec())
        .or_else(|| {
            item.relative_path
                .base64
                .as_ref()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        })
        .ok_or(ReviewError::InvalidContinuation)?;
    let token = CopyToken {
        version: TOKEN_VERSION,
        applied_event_seq: applied_seq,
        query_hash: query_hash.to_owned(),
        location_id: item.location_id.clone(),
        path_encoding: item.relative_path.encoding.clone(),
        path_bytes: URL_SAFE_NO_PAD.encode(bytes),
        copy_claim_id: item.copy_claim_id.clone(),
    };
    serde_json::to_vec(&token)
        .map(|value| URL_SAFE_NO_PAD.encode(value))
        .map_err(|_| ReviewError::InvalidContinuation)
}

fn decode_copy_token(value: &str) -> Result<CopyToken> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ReviewError::InvalidContinuation)?;
    let token: CopyToken =
        serde_json::from_slice(&bytes).map_err(|_| ReviewError::InvalidContinuation)?;
    if token.version != TOKEN_VERSION {
        return Err(ReviewError::InvalidContinuation);
    }
    Ok(token)
}

fn exclusive_prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    for index in (0..end.len()).rev() {
        if end[index] != u8::MAX {
            end[index] += 1;
            end.truncate(index + 1);
            return Some(end);
        }
    }
    None
}

fn open(path: &Path) -> Result<Connection> {
    Connection::open(path).map_err(|source| sqlite_error(path, source))
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> ReviewError {
    ReviewError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

fn sql_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| ReviewError::InvalidContinuation)
}

fn sql_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| ReviewError::Sqlite {
        path: PathBuf::new(),
        source: rusqlite::Error::IntegralValueOutOfRange(0, value),
    })
}

fn sql_u64_sql(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn optional_u64(value: Option<i64>) -> rusqlite::Result<Option<u64>> {
    value.map(sql_u64_sql).transpose()
}

pub fn utf8_path(value: impl Into<String>) -> EncodedPath {
    let value = value.into();
    EncodedPath {
        encoding: PathEncoding::Utf8,
        bytes: value.as_bytes().to_vec(),
        display: value,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::projection::ProjectionConfig;
    use crate::v2_store::initialize_v2_archive;
    use serde_json::json;
    use tempfile::TempDir;

    fn seeded_database(temp: &TempDir) -> ProjectionDb {
        let database = ProjectionDb::open_or_create(
            temp.path().join("archive.db"),
            "arc_review",
            ProjectionConfig::default(),
        )
        .unwrap();
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                r#"
                PRAGMA foreign_keys = ON;
                INSERT INTO events(
                  stream_id, seq, event_id, event_type, event_time_utc_ms,
                  actor_id, host_id, file_ref_id, object_id, payload_json, previous_event_hash, event_hash
                ) VALUES
                  ('stream_primary', 1, 'event_1', 'file_ref_observed', 100,
                   'user', 'host', 'file_a', 'object_1', '{"change":"created"}', NULL, 'hash_1'),
                  ('stream_primary', 2, 'event_2', 'file_ref_updated', 200,
                   'user', 'host', 'file_a', 'object_1', '{"change":"renamed"}', 'hash_1', 'hash_2'),
                  ('stream_primary', 3, 'event_3', 'job_finished', 300,
                   'user', 'host', NULL, NULL, '{}', 'hash_2', 'hash_3');
                UPDATE archive_meta SET value = '3' WHERE key = 'applied_event_seq';
                UPDATE archive_meta SET value = 'hash_3' WHERE key = 'applied_event_hash';
                UPDATE archive_meta SET value = '1' WHERE key = 'applied_segment_first_seq';
                UPDATE archive_meta SET value = '3' WHERE key = 'applied_segment_offset';
                UPDATE archive_meta SET value = '2' WHERE key = 'policy_input_event_seq';

                INSERT INTO sites VALUES ('site_1', 'Home', 'home', NULL, 'active', 'event_1');
                INSERT INTO collections VALUES
                  ('collection_1', 'Photos', NULL, 'site_1', NULL, 'active', 'event_1');
                INSERT INTO objects VALUES
                  ('object_1', 'blake3', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                   42, 'image/jpeg', 'jpg', 'event_1', 100);
                INSERT INTO object_hashes VALUES
                  ('object_1', 'sha256', 'bbbb', 'import', 'event_1');
                INSERT INTO external_identities VALUES
                  ('external_1', 'git-annex', 'SHA256E-s10--abc', 'sha256', 'abc', 10,
                   NULL, 'unresolved', '{}', 'event_1', NULL);
                INSERT INTO file_refs VALUES
                  ('file_a', 'collection_1', X'70686f746f732f612e6a7067', 'utf8', 'photos/a.jpg',
                   'object_1', NULL, 'resolved', 'active', 100, 100, 42, 'event_1', 'event_2', NULL),
                  ('file_b', 'collection_1', X'70686f746f732f622e6a7067', 'utf8', 'photos/b.jpg',
                   'object_1', NULL, 'resolved', 'active', 100, 100, 42, 'event_1', 'event_1', NULL),
                  ('file_external', 'collection_1', X'64726f707065642e62696e', 'utf8', 'dropped.bin',
                   NULL, 'external_1', 'unresolved', 'active', 100, 100, 10, 'event_1', 'event_1', NULL),
                  ('file_non_utf8', 'collection_1', X'ff61', 'unix_bytes', '\xffa',
                   'object_1', NULL, 'resolved', 'active', 100, 100, 42, 'event_1', 'event_1', NULL);
                INSERT INTO devices VALUES
                  ('device_1', 'Archive disk', 'disk', NULL, 'fp', 'serial', 'confirmed', NULL,
                   'active', 'site_1', 'online', 'event_1', 250, 250, 'match', 'event_1');
                INSERT INTO archive_roots(
                  archive_root_id, device_id, display_name, root_path_on_device_bytes,
                  root_path_encoding, root_path_display, status, created_event_id,
                  last_seen_event_id, last_seen_time_utc_ms
                ) VALUES
                  ('root_1', 'device_1', 'Archive root', X'2f61726368697665', 'utf8', '/archive',
                   'active', 'event_1', 'event_1', 250);
                INSERT INTO locations VALUES
                  ('location_1', 'Primary archive', 'filesystem', 'root_1', X'', 'utf8', '',
                   'device_1', NULL, 'encrypted', 'trusted', 'online', 0, 'active', 'event_1', 'event_1');
                INSERT INTO copy_claims(
                  copy_claim_id, location_id, relative_path_bytes, relative_path_encoding,
                  relative_path_display, object_id, claim_basis, state, state_event_seq,
                  first_seen_event_id, last_seen_event_id, last_seen_time_utc_ms,
                  last_verified_event_id, last_verified_time_utc_ms, last_verification_result
                ) VALUES
                  ('copy_1', 'location_1', X'612e6a7067', 'utf8', 'a.jpg', 'object_1',
                   'observed_bytes', 'present', 2, 'event_1', 'event_2', 250, 'event_2', 240, 'ok'),
                  ('copy_2', 'location_1', X'622e6a7067', 'utf8', 'b.jpg', 'object_1',
                   'observed_bytes', 'missing', 2, 'event_1', 'event_2', 230, NULL, NULL, NULL);
                "#,
            )
            .unwrap();
        database
    }

    fn seeded_v2_database(temp: &TempDir) -> (V2OriginStore, V2ProjectionDb, String) {
        let archive = temp.path().join("v2-archive");
        initialize_v2_archive(&archive, "arc_review_v2", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let database_path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &database_path).unwrap();
        let hash = "a".repeat(64);
        let object_id = format!("blake3:{hash}");
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(&format!(
                r#"
                INSERT INTO collections(
                  collection_id, display_name, description, home_site_id, policy_id,
                  status, last_record_id
                ) VALUES ('collection_1', 'Photos', NULL, NULL, NULL, 'active', 'seed');
                INSERT INTO objects(
                  object_id, canonical_hash_algo, canonical_hash_hex, size_bytes,
                  media_type, extension_hint, first_seen_record_id, first_seen_time_utc_ms
                ) VALUES ('{object_id}', 'blake3', '{hash}', 42,
                          'image/jpeg', 'jpg', 'seed', 100);
                INSERT INTO object_hashes(
                  object_id, hash_algo, hash_hex, source, verified_record_id
                ) VALUES ('{object_id}', 'sha256', 'bbbb', 'import', 'seed');
                INSERT INTO file_refs(
                  file_ref_id, collection_id, logical_path_bytes, logical_path_encoding,
                  logical_path_display, object_id, external_identity_id, identity_state,
                  path_state, created_time_utc_ms, modified_time_utc_ms,
                  observed_size_bytes, first_seen_record_id, last_seen_record_id,
                  removed_record_id
                ) VALUES
                  ('file_a', 'collection_1', X'612e6a7067', 'utf8', 'a.jpg',
                   '{object_id}', NULL, 'resolved', 'active', 100, 100, 42,
                   'seed', 'seed', NULL),
                  ('file_b', 'collection_1', X'622e6a7067', 'utf8', 'b.jpg',
                   '{object_id}', NULL, 'resolved', 'active', 100, 100, 42,
                   'seed', 'seed', NULL);
                "#
            ))
            .unwrap();
        drop(connection);
        for observation in ["first", "second"] {
            store
                .append_batch(
                    "inventory",
                    2,
                    json!({}),
                    json!({
                        "content_observed": {
                            "file_ref_id": "file_a",
                            "object_id": object_id,
                        }
                    }),
                    vec![json!({
                        "kind": "content_observed",
                        "observation": observation,
                    })],
                )
                .unwrap();
        }
        (
            store,
            V2ProjectionDb::open_existing(database_path).unwrap(),
            object_id,
        )
    }

    #[test]
    fn file_review_is_lossless_paginated_and_stale_safe() {
        let temp = TempDir::new().unwrap();
        let database = seeded_database(&temp);
        let first = database
            .find_files(FilePageRequest {
                filter: FileFilter {
                    collection_id: Some("collection_1".to_owned()),
                    path_prefix: Some(utf8_path("photos/")),
                    ..FileFilter::default()
                },
                limit: 1,
                continuation: None,
            })
            .unwrap();
        assert_eq!(first.items[0].logical_path.display, "photos/a.jpg");
        assert_eq!(first.items[0].present_copy_count, 1);
        let second = database
            .find_files(FilePageRequest {
                filter: FileFilter {
                    collection_id: Some("collection_1".to_owned()),
                    path_prefix: Some(utf8_path("photos/")),
                    ..FileFilter::default()
                },
                limit: 1,
                continuation: first.next.clone(),
            })
            .unwrap();
        assert_eq!(second.items[0].logical_path.display, "photos/b.jpg");
        assert!(second.next.is_none());

        let exact = database
            .find_files(FilePageRequest {
                filter: FileFilter {
                    exact_path: Some(EncodedPath {
                        encoding: PathEncoding::UnixBytes,
                        bytes: vec![0xff, b'a'],
                        display: "ignored".to_owned(),
                    }),
                    ..FileFilter::default()
                },
                limit: 10,
                continuation: None,
            })
            .unwrap();
        assert_eq!(exact.items.len(), 1);
        assert_eq!(exact.items[0].logical_path.base64.as_deref(), Some("_2E"));

        let review = database.review_file("file_a").unwrap();
        assert_eq!(review.file.collection_name, "Photos");
        assert_eq!(
            review.copies[0].device_name.as_deref(),
            Some("Archive disk")
        );
        assert_eq!(
            review.copies[0].last_verification_result.as_deref(),
            Some("ok")
        );
        assert_eq!(review.copies.len(), 2);
        let unresolved = database.review_file("file_external").unwrap();
        assert_eq!(unresolved.external_namespace.as_deref(), Some("git-annex"));
        assert!(unresolved.copies.is_empty());
        let copies = database
            .list_copies(CopyPageRequest {
                filter: CopyFilter {
                    object_id: Some("object_1".to_owned()),
                    ..CopyFilter::default()
                },
                limit: 1,
                continuation: None,
            })
            .unwrap();
        assert_eq!(copies.items.len(), 1);
        assert!(copies.next.is_some());
        assert_eq!(database.review_copy("copy_2").unwrap().state, "missing");
        let needing_verification = database
            .list_copies(CopyPageRequest {
                filter: CopyFilter {
                    verified_before_utc_ms: Some(240),
                    ..CopyFilter::default()
                },
                limit: 10,
                continuation: None,
            })
            .unwrap();
        assert_eq!(needing_verification.items.len(), 1);
        assert_eq!(needing_verification.items[0].copy_claim_id, "copy_2");
        let not_recently_observed = database
            .list_copies(CopyPageRequest {
                filter: CopyFilter {
                    observed_before_utc_ms: Some(240),
                    ..CopyFilter::default()
                },
                limit: 10,
                continuation: None,
            })
            .unwrap();
        assert_eq!(not_recently_observed.items.len(), 1);
        assert_eq!(not_recently_observed.items[0].copy_claim_id, "copy_2");

        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                "INSERT INTO events(stream_id, seq, event_id, event_type, event_time_utc_ms,
                    actor_id, host_id, payload_json, previous_event_hash, event_hash)
                 VALUES ('stream_primary', 4, 'event_4', 'job_finished', 400,
                    'user', 'host', '{}', 'hash_3', 'hash_4');
                 UPDATE archive_meta SET value = '4' WHERE key = 'applied_event_seq';
                 UPDATE archive_meta SET value = 'hash_4' WHERE key = 'applied_event_hash';
                 UPDATE archive_meta SET value = '4' WHERE key = 'applied_segment_offset';",
            )
            .unwrap();
        let stale = database
            .find_files(FilePageRequest {
                filter: FileFilter {
                    collection_id: Some("collection_1".to_owned()),
                    path_prefix: Some(utf8_path("photos/")),
                    ..FileFilter::default()
                },
                limit: 1,
                continuation: first.next,
            })
            .unwrap_err();
        assert_eq!(stale.code(), "stale_continuation");
    }

    #[test]
    fn file_history_is_sqlite_only_and_complete_across_pages() {
        let temp = TempDir::new().unwrap();
        let database = seeded_database(&temp);
        let first = database.file_history("file_a", 0, 1).unwrap();
        assert_eq!(first.items[0].event_type, "file_ref_observed");
        assert_eq!(first.next_seq, Some(1));
        let second = database
            .file_history("file_a", first.next_seq.unwrap(), 10)
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].payload["change"], "renamed");
        assert_eq!(second.next_seq, None);

        let object = database.review_object("object_1", 1, None).unwrap();
        assert_eq!(object.size_bytes, 42);
        assert_eq!(object.hashes[0].hash_algo, "sha256");
        assert_eq!(object.files.items.len(), 1);
        assert!(object.files.next.is_some());
        let object_history = database.object_history("object_1", 0, 10).unwrap();
        assert_eq!(object_history.items.len(), 2);
    }

    #[test]
    fn v2_object_review_and_canonical_history_are_bounded_and_frontier_bound() {
        let temp = TempDir::new().unwrap();
        let (store, database, object_id) = seeded_v2_database(&temp);

        let object = database.review_object(&object_id, 1, None).unwrap();
        assert_eq!(object.version, 2);
        assert_eq!(object.size_bytes, 42);
        assert_eq!(object.files.items.len(), 1);
        assert!(object.files.next.is_some());

        let first = database.file_history(&store, "file_a", 1, None).unwrap();
        assert_eq!(first.items.len(), 1);
        assert_eq!(first.items[0].item_kind, "content_observed");
        assert_eq!(first.items[0].item["file_ref_id"], "file_a");
        assert_eq!(first.items[0].item["object_id"], object_id);
        let continuation = first.next.clone().unwrap();
        let second = database
            .file_history(&store, "file_a", 1, first.next)
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].item["observation"], "second");
        assert!(second.next.is_none());

        let object_history = database
            .object_history(&store, &object_id, 10, None)
            .unwrap();
        assert_eq!(object_history.items.len(), 2);
        assert!(matches!(
            database.file_history(&store, "missing", 10, None),
            Err(ReviewError::NotFound { kind: "file", .. })
        ));

        store
            .append_batch(
                "unrelated",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "job_finished", "job_id": "job_1"})],
            )
            .unwrap();
        assert!(matches!(
            database.file_history(&store, "file_a", 1, Some(continuation)),
            Err(ReviewError::StaleContinuation)
        ));
    }

    #[test]
    fn large_file_lists_are_complete_in_bounded_stable_pages() {
        let temp = TempDir::new().unwrap();
        let database = seeded_database(&temp);
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                "WITH RECURSIVE n(value) AS (
                   SELECT 0 UNION ALL SELECT value + 1 FROM n WHERE value < 4999
                 )
                 INSERT INTO file_refs(
                   file_ref_id, collection_id, logical_path_bytes, logical_path_encoding,
                   logical_path_display, identity_state, path_state, first_seen_event_id
                 )
                 SELECT printf('bulk_%05d', value), 'collection_1',
                        CAST(printf('bulk/%05d.dat', value) AS BLOB), 'utf8',
                        printf('bulk/%05d.dat', value), 'unknown', 'active', 'event_1'
                 FROM n;",
            )
            .unwrap();
        let mut continuation = None;
        let mut ids = BTreeSet::new();
        loop {
            let page = database
                .find_files(FilePageRequest {
                    filter: FileFilter {
                        collection_id: Some("collection_1".to_owned()),
                        path_prefix: Some(utf8_path("bulk/")),
                        ..FileFilter::default()
                    },
                    limit: 1_000,
                    continuation,
                })
                .unwrap();
            assert!(page.items.len() <= 1_000);
            for item in page.items {
                assert!(ids.insert(item.file_ref_id));
            }
            continuation = page.next;
            if continuation.is_none() {
                break;
            }
        }
        assert_eq!(ids.len(), 5_000);
    }
}
