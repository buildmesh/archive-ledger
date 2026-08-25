//! Bounded v2-native positive inventory for ordinary filesystem files.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::discovery::{
    encode_relative_path, modified_time_ms, DiscoveredFile, DiscoveryError, DiscoveryItem,
    EncodedPath, FileDiscovery,
};
use crate::registry::RegistryPath;
use crate::scan::ScanMode;
use crate::v2_projection::{V2ApplyStats, V2ProjectionDb, V2ProjectionError};
use crate::v2_store::{V2AppendResult, V2OriginStore, V2StoreError};

const HASH_BUFFER_BYTES: usize = 1024 * 1024;

pub type Result<T> = std::result::Result<T, V2InventoryError>;

#[derive(Debug, Error)]
pub enum V2InventoryError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Store(#[from] V2StoreError),
    #[error(transparent)]
    Projection(#[from] V2ProjectionError),
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("inventory SQLite query failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("invalid inventory configuration: {0}")]
    Invalid(String),
}

impl V2InventoryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Discovery(error) => error.code(),
            Self::Store(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Io { .. } => "v2_inventory_io",
            Self::Sqlite { .. } => "v2_inventory_sqlite",
            Self::Invalid(_) => "v2_inventory_invalid",
        }
    }
}

#[derive(Debug, Clone)]
pub struct V2InventoryConfig {
    pub root_path: PathBuf,
    pub location_prefix: Option<PathBuf>,
    pub logical_prefix: Option<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub collection_id: String,
    pub location_id: String,
    pub device_fingerprint_status: String,
    pub job_id: String,
    pub scan_id: String,
    pub scan_mode: ScanMode,
    pub max_items: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2InventorySummary {
    pub files_observed: u64,
    pub bytes_observed: u64,
    pub new_paths: u64,
    pub changed_paths: u64,
    pub confirmed_good: u64,
    pub observed_without_verification: u64,
    pub integrity_mismatches: u64,
    pub missing_paths: u64,
    pub ignored_symlinks: u64,
    pub ignored_special_files: u64,
    pub excluded_subtrees: u64,
    pub filesystem_boundaries: u64,
    pub read_errors: u64,
    pub concurrent_changes: u64,
    pub traversal_errors: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct V2InventoryResult {
    pub version: u32,
    pub status: String,
    pub job_id: String,
    pub scan_id: String,
    pub summary: V2InventorySummary,
    pub append: Option<V2AppendResult>,
    pub apply: Option<V2ApplyStats>,
}

#[derive(Debug, Clone)]
pub struct V2Placement {
    pub collection_id: String,
    pub location_id: String,
    pub file_ref_id: String,
    pub logical_path: RegistryPath,
    pub copy_path: RegistryPath,
    pub object_id: String,
    pub blake3_hex: String,
    pub size_bytes: u64,
    pub modified_time_utc_ms: Option<u64>,
    pub device_fingerprint_status: String,
    pub job_id: String,
    pub job_type: String,
    pub input_version: String,
}

pub fn record_placements(
    store: &V2OriginStore,
    projection: &V2ProjectionDb,
    placements: &[V2Placement],
) -> Result<Option<(V2AppendResult, V2ApplyStats)>> {
    if placements.is_empty() {
        return Ok(None);
    }
    if placements.len() > 1_000 {
        return Err(V2InventoryError::Invalid(
            "one placement batch may contain at most 1000 Objects".to_owned(),
        ));
    }
    let observed_time = now_utc_ms()?;
    let connection =
        Connection::open(projection.path()).map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    let pending = placements
        .iter()
        .map(|placement| {
            let copy_bytes = crate::registry::registry_path_bytes(&placement.copy_path)
                .map_err(|error| V2InventoryError::Invalid(error.to_string()))?;
            let copy_claim_id = stable_id(
                "copy",
                &[
                    placement.location_id.as_bytes(),
                    placement.copy_path.encoding.as_bytes(),
                    &copy_bytes,
                    placement.object_id.as_bytes(),
                ],
            );
            let operation_key = stable_id(
                "op",
                &[
                    placement.job_id.as_bytes(),
                    placement.job_type.as_bytes(),
                    placement.input_version.as_bytes(),
                    copy_claim_id.as_bytes(),
                    b"content_observed",
                    placement.object_id.as_bytes(),
                ],
            );
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM operation_outcomes WHERE operation_key = ?1)",
                    [&operation_key],
                    |row| row.get(0),
                )
                .map_err(|source| V2InventoryError::Sqlite {
                    path: projection.path().to_path_buf(),
                    source,
                })?;
            Ok((placement, operation_key, copy_claim_id, exists))
        })
        .collect::<Result<Vec<_>>>()?;
    let items = pending
        .iter()
        .filter(|(_, _, _, exists)| !exists)
        .map(|(placement, operation_key, copy_claim_id, _)| {
            json!({
                "kind": "content_observed",
                "collection_id": placement.collection_id,
                "location_id": placement.location_id,
                "logical_path": placement.logical_path,
                "copy_path": placement.copy_path,
                "file_ref_id": placement.file_ref_id,
                "copy_claim_id": copy_claim_id,
                "object_id": placement.object_id,
                "blake3_hex": placement.blake3_hex,
                "size_bytes": placement.size_bytes,
                "modified_time_utc_ms": placement.modified_time_utc_ms,
                "duration_ms": 0,
                "observed_time_utc_ms": observed_time,
                "device_fingerprint_status": placement.device_fingerprint_status,
                "representation": "ordinary_file",
                "job_id": placement.job_id,
                "job_type": placement.job_type,
                "item_type": "copy_claim",
                "item_key": copy_claim_id,
                "outcome_kind": "content_observed",
                "operation_key": operation_key,
            })
        })
        .collect::<Vec<_>>();
    if items.is_empty() {
        return Ok(None);
    }
    let first = pending
        .iter()
        .find(|(_, _, _, exists)| !exists)
        .map(|(placement, _, _, _)| *placement)
        .expect("non-empty pending placements have a first item");
    let append = store.append_batch(
        "copy_place",
        2,
        json!({
            "collection_id": first.collection_id,
            "location_id": first.location_id,
            "job_id": first.job_id,
        }),
        json!({
            "content_observed": {
                "collection_id": first.collection_id,
                "location_id": first.location_id,
                "job_id": first.job_id,
                "job_type": first.job_type,
                "observed_time_utc_ms": observed_time,
                "device_fingerprint_status": first.device_fingerprint_status,
                "representation": "ordinary_file",
                "item_type": "copy_claim",
                "outcome_kind": "content_observed",
                "duration_ms": 0,
            }
        }),
        items,
    )?;
    let apply = projection.apply(store)?;
    Ok(Some((append, apply)))
}

pub fn add_files(
    store: &V2OriginStore,
    projection: &V2ProjectionDb,
    config: &V2InventoryConfig,
) -> Result<V2InventoryResult> {
    validate_config(config)?;
    let coordination_remote =
        if config.scan_mode == ScanMode::Complete && store.coordination_required()? {
            let remote = store.coordination_remote()?;
            store.sync_remote(&remote)?;
            Some(remote)
        } else {
            None
        };
    let initial_apply = projection.apply(store)?;
    validate_scope(projection.path(), config)?;
    let job_type = if config.scan_mode == ScanMode::Add {
        "inventory_add"
    } else {
        "location_scan"
    };
    let job_root = projection
        .path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("local/jobs")
        .join(&config.job_id);
    let config_path = job_root.join("inventory-config.json");
    let spool_path = job_root.join("inventory-items.jsonl");
    let seen_path = job_root.join("inventory-seen.sqlite3");
    let summary_path = job_root.join("inventory-summary.json");
    let config_value = json!({
        "root_path": RegistryPath::from_path(&config.root_path),
        "location_prefix": config.location_prefix.as_deref().map(RegistryPath::from_path),
        "logical_prefix": config.logical_prefix.as_deref().map(RegistryPath::from_path),
        "exclusions": config.exclusions.iter().map(|path| RegistryPath::from_path(path)).collect::<Vec<_>>(),
        "collection_id": config.collection_id,
        "location_id": config.location_id,
        "device_fingerprint_status": config.device_fingerprint_status,
        "scan_id": config.scan_id,
        "scan_mode": config.scan_mode.as_str(),
    });
    let connection =
        Connection::open(projection.path()).map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    let completed: Option<(String, String, Option<String>)> = connection
        .query_row(
            "SELECT job_type, input_version, progress_json FROM jobs WHERE job_id = ?1 AND status IN ('complete', 'partial')",
            [&config.job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    if let Some((actual_type, input_version, progress)) = completed {
        if actual_type != job_type || input_version != config.scan_id {
            return Err(V2InventoryError::Invalid(format!(
                "job {} belongs to different immutable inputs",
                config.job_id
            )));
        }
        let summary = progress
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|error| V2InventoryError::Invalid(format!("job summary is invalid: {error}")))?
            .unwrap_or_default();
        if job_root.is_dir() {
            fs::remove_dir_all(&job_root).map_err(|source| {
                io_error("remove completed inventory job files", &job_root, source)
            })?;
        }
        return Ok(V2InventoryResult {
            version: 2,
            status: "complete".to_owned(),
            job_id: config.job_id.clone(),
            scan_id: config.scan_id.clone(),
            summary,
            append: None,
            apply: Some(initial_apply),
        });
    }
    fs::create_dir_all(&job_root)
        .map_err(|source| io_error("create inventory job directory", &job_root, source))?;
    let new_job = !config_path.exists();
    if new_job {
        let bytes = serde_json::to_vec(&config_value)
            .map_err(|error| V2InventoryError::Invalid(error.to_string()))?;
        fs::write(&config_path, bytes).map_err(|source| {
            io_error("write inventory job configuration", &config_path, source)
        })?;
    } else {
        let bytes = fs::read(&config_path)
            .map_err(|source| io_error("read inventory job configuration", &config_path, source))?;
        let existing: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            V2InventoryError::Invalid(format!("inventory job configuration is invalid: {error}"))
        })?;
        if existing != config_value {
            return Err(V2InventoryError::Invalid(format!(
                "job {} belongs to different immutable inputs",
                config.job_id
            )));
        }
    }
    let now_i64 = i64::try_from(now_utc_ms()?)
        .map_err(|_| V2InventoryError::Invalid("system time exceeds SQLite range".to_owned()))?;
    let params_text = serde_json::to_string(&config_value)
        .map_err(|error| V2InventoryError::Invalid(error.to_string()))?;
    connection
        .execute(
            "INSERT INTO jobs(job_id, job_type, status, created_time_utc_ms, started_time_utc_ms,
                              params_json, progress_json, input_version)
             VALUES (?1, ?2, 'running', ?3, ?3, ?4, NULL, ?5)
             ON CONFLICT(job_id) DO NOTHING",
            params![
                config.job_id,
                job_type,
                now_i64,
                params_text,
                config.scan_id
            ],
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    let actual: (String, String, String) = connection
        .query_row(
            "SELECT job_type, input_version, params_json FROM jobs WHERE job_id = ?1",
            [&config.job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    if actual.0 != job_type || actual.1 != config.scan_id || actual.2 != params_text {
        return Err(V2InventoryError::Invalid(format!(
            "job {} belongs to different immutable inputs",
            config.job_id
        )));
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let spool_file = options
        .open(&spool_path)
        .map_err(|source| io_error("open inventory spool", &spool_path, source))?;
    let mut spool = SpoolGuard {
        path: spool_path.clone(),
        writer: Some(BufWriter::new(spool_file)),
        preserve_on_drop: true,
    };
    let seen = Connection::open(&seen_path).map_err(|source| V2InventoryError::Sqlite {
        path: seen_path.clone(),
        source,
    })?;
    seen.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         CREATE TABLE IF NOT EXISTS seen(
             path_encoding TEXT NOT NULL,
             path_bytes BLOB NOT NULL,
             PRIMARY KEY(path_encoding, path_bytes)
         ) WITHOUT ROWID;",
    )
    .map_err(|source| V2InventoryError::Sqlite {
        path: seen_path.clone(),
        source,
    })?;
    recover_seen_from_spool(&spool_path, &seen, &seen_path)?;
    seen.execute_batch("BEGIN IMMEDIATE")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.clone(),
            source,
        })?;
    connection
        .execute(
            "ATTACH DATABASE ?1 AS scan_local",
            [seen_path.to_string_lossy().as_ref()],
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    let annex_imported: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM annex_imports WHERE collection_id = ?1 AND worktree_location_id = ?2 AND status = 'complete')",
            params![config.collection_id, config.location_id],
            |row| row.get(0),
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    let observed_time_utc_ms = now_utc_ms()?;
    let job_started_key = stable_id(
        "op",
        &[
            config.job_id.as_bytes(),
            config.scan_id.as_bytes(),
            b"job",
            b"started",
        ],
    );
    if new_job {
        write_spool_item(
            &mut spool,
            &json!({
            "kind": "job_started",
            "job_id": config.job_id,
            "job_type": job_type,
            "input_version": config.scan_id,
            "params": config_value,
            "item_type": "job",
            "item_key": config.job_id,
            "outcome_kind": "started",
            "operation_key": job_started_key,
            }),
        )?;
        write_spool_item(
            &mut spool,
            &json!({
            "kind": "scan_started",
            "scan_id": config.scan_id,
            "job_id": config.job_id,
            "scan_mode": config.scan_mode.as_str(),
            "collection_id": config.collection_id,
            "location_id": config.location_id,
            "started_time_utc_ms": observed_time_utc_ms,
            "scope": {"kind": "location", "version": 1},
            "exclusions": config.exclusions.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
            }),
        )?;
    }
    let device_id: Option<String> = connection
        .query_row(
            "SELECT device_id FROM locations WHERE location_id = ?1",
            [&config.location_id],
            |row| row.get(0),
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    if new_job {
        if let Some(device_id) = device_id {
            write_spool_item(
                &mut spool,
                &json!({
                    "kind": "device_checked_in",
                    "snapshot": {
                        "device_id": device_id,
                        "fingerprint_status": config.device_fingerprint_status,
                    },
                }),
            )?;
        }
    }
    let mut known = connection
        .prepare(
            "SELECT object_id FROM file_refs WHERE collection_id = ?1 AND logical_path_encoding = ?2 AND logical_path_bytes = ?3 AND path_state = 'active'",
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: projection.path().to_path_buf(),
            source,
        })?;
    let mut record_seen = seen
        .prepare("INSERT OR IGNORE INTO seen(path_encoding, path_bytes) VALUES (?1, ?2)")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.clone(),
            source,
        })?;
    let mut already_seen = seen
        .prepare("SELECT EXISTS(SELECT 1 FROM seen WHERE path_encoding = ?1 AND path_bytes = ?2)")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.clone(),
            source,
        })?;
    let mut summary = if summary_path.exists() {
        serde_json::from_slice(
            &fs::read(&summary_path)
                .map_err(|source| io_error("read inventory job summary", &summary_path, source))?,
        )
        .map_err(|error| {
            V2InventoryError::Invalid(format!("inventory job summary is invalid: {error}"))
        })?
    } else {
        V2InventorySummary::default()
    };
    let mut processed_this_run = 0_usize;
    let mut interrupted = false;
    let discovery = FileDiscovery::with_exclusions(&config.root_path, config.exclusions.clone())?;
    for discovered in discovery {
        match discovered {
            DiscoveryItem::File(file) => {
                let relative = raw_relative_path(&file.relative_path)?;
                let absolute = config.root_path.join(&relative);
                let logical_path = prefixed_path(config.logical_prefix.as_deref(), &relative);
                let ordinary_copy_path =
                    prefixed_path(config.location_prefix.as_deref(), &relative);
                let logical_encoded = encode_relative_path(&logical_path);
                let was_seen: bool = already_seen
                    .query_row(
                        params![logical_encoded.encoding.as_str(), logical_encoded.bytes],
                        |row| row.get(0),
                    )
                    .map_err(|source| V2InventoryError::Sqlite {
                        path: seen_path.clone(),
                        source,
                    })?;
                if was_seen {
                    continue;
                }
                if config
                    .max_items
                    .is_some_and(|limit| processed_this_run >= limit)
                {
                    interrupted = true;
                    break;
                }
                processed_this_run = processed_this_run.saturating_add(1);
                let annex = if annex_imported {
                    known_annex_entry(
                        &connection,
                        projection.path(),
                        &config.collection_id,
                        &config.location_id,
                        &logical_encoded,
                    )?
                } else {
                    None
                };
                if annex
                    .as_ref()
                    .is_some_and(|known| known.representation == "annex_pointer_file")
                {
                    record_seen
                        .execute(params![
                            logical_encoded.encoding.as_str(),
                            logical_encoded.bytes
                        ])
                        .map_err(|source| V2InventoryError::Sqlite {
                            path: projection.path().to_path_buf(),
                            source,
                        })?;
                    summary.files_observed = summary.files_observed.saturating_add(1);
                    summary.observed_without_verification =
                        summary.observed_without_verification.saturating_add(1);
                    continue;
                }
                let hashed = match hash_file_stable(&absolute, &file) {
                    HashOutcome::Stable(hashed) => hashed,
                    HashOutcome::ReadError => {
                        record_seen
                            .execute(params![
                                logical_encoded.encoding.as_str(),
                                logical_encoded.bytes
                            ])
                            .map_err(|source| V2InventoryError::Sqlite {
                                path: seen_path.clone(),
                                source,
                            })?;
                        summary.read_errors = summary.read_errors.saturating_add(1);
                        continue;
                    }
                    HashOutcome::Changed => {
                        record_seen
                            .execute(params![
                                logical_encoded.encoding.as_str(),
                                logical_encoded.bytes
                            ])
                            .map_err(|source| V2InventoryError::Sqlite {
                                path: seen_path.clone(),
                                source,
                            })?;
                        summary.concurrent_changes = summary.concurrent_changes.saturating_add(1);
                        continue;
                    }
                };
                let copy_path = annex
                    .as_ref()
                    .and_then(|known| known.copy_path.clone())
                    .unwrap_or(ordinary_copy_path);
                if annex.as_ref().is_some_and(|known| {
                    known
                        .expected_sha256
                        .as_deref()
                        .is_some_and(|expected| expected != hashed.sha256_hex)
                        || known
                            .expected_size
                            .is_some_and(|expected| expected != hashed.size_bytes)
                }) {
                    if let Some(item) = annex.as_ref().and_then(|known| {
                        annex_verification_failure_item(
                            known,
                            config,
                            &logical_path,
                            &copy_path,
                            &hashed,
                            observed_time_utc_ms,
                        )
                    }) {
                        write_spool_item(&mut spool, &item)?;
                    }
                    record_seen
                        .execute(params![
                            logical_encoded.encoding.as_str(),
                            logical_encoded.bytes
                        ])
                        .map_err(|source| V2InventoryError::Sqlite {
                            path: seen_path.clone(),
                            source,
                        })?;
                    summary.integrity_mismatches = summary.integrity_mismatches.saturating_add(1);
                    continue;
                }
                let copy_encoded = encode_relative_path(&copy_path);
                let existing: Option<String> = known
                    .query_row(
                        params![
                            config.collection_id,
                            logical_encoded.encoding.as_str(),
                            logical_encoded.bytes,
                        ],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|source| V2InventoryError::Sqlite {
                        path: projection.path().to_path_buf(),
                        source,
                    })?;
                let object_id = format!("blake3:{}", hashed.blake3_hex);
                match existing.as_deref() {
                    None => summary.new_paths = summary.new_paths.saturating_add(1),
                    Some(existing) if existing != object_id => {
                        summary.changed_paths = summary.changed_paths.saturating_add(1)
                    }
                    Some(_) => summary.confirmed_good = summary.confirmed_good.saturating_add(1),
                }
                let file_ref_id = stable_id(
                    "file",
                    &[
                        config.collection_id.as_bytes(),
                        logical_encoded.encoding.as_str().as_bytes(),
                        &logical_encoded.bytes,
                    ],
                );
                let copy_claim_id = annex
                    .as_ref()
                    .and_then(|known| known.copy_claim_id.clone())
                    .unwrap_or_else(|| {
                        stable_id(
                            "copy",
                            &[
                                config.location_id.as_bytes(),
                                copy_encoded.encoding.as_str().as_bytes(),
                                &copy_encoded.bytes,
                                object_id.as_bytes(),
                            ],
                        )
                    });
                let item = json!({
                    "kind": "content_observed",
                    "collection_id": config.collection_id,
                    "location_id": config.location_id,
                    "logical_path": registry_path(&logical_encoded),
                    "copy_path": registry_path(&copy_encoded),
                    "file_ref_id": file_ref_id,
                    "copy_claim_id": copy_claim_id,
                    "object_id": object_id,
                    "blake3_hex": hashed.blake3_hex,
                    "sha256_hex": annex.as_ref().map(|_| &hashed.sha256_hex),
                    "size_bytes": hashed.size_bytes,
                    "modified_time_utc_ms": file.modified_time_utc_ms,
                    "duration_ms": hashed.duration_ms,
                    "observed_time_utc_ms": observed_time_utc_ms,
                    "device_fingerprint_status": config.device_fingerprint_status,
                    "representation": annex.as_ref().map_or("ordinary_file", |known| known.representation.as_str()),
                    "external_identity_id": annex.as_ref().map(|known| &known.external_identity_id),
                    "extension_hint": Path::new(&relative).extension().and_then(|value| value.to_str()),
                    "job_id": config.job_id,
                    "scan_id": config.scan_id,
                    "job_type": if config.scan_mode == ScanMode::Add { "inventory_add" } else { "location_scan" },
                    "item_type": "copy_claim",
                    "item_key": copy_claim_id,
                    "outcome_kind": "content_observed",
                    "operation_key": stable_id(
                        "op",
                        &[
                            config.job_id.as_bytes(),
                            config.scan_id.as_bytes(),
                            copy_claim_id.as_bytes(),
                            b"content_observed",
                            object_id.as_bytes(),
                        ],
                    ),
                });
                write_spool_item(&mut spool, &item)?;
                record_seen
                    .execute(params![
                        logical_encoded.encoding.as_str(),
                        logical_encoded.bytes
                    ])
                    .map_err(|source| V2InventoryError::Sqlite {
                        path: seen_path.clone(),
                        source,
                    })?;
                summary.files_observed = summary.files_observed.saturating_add(1);
                summary.bytes_observed = summary.bytes_observed.saturating_add(hashed.size_bytes);
            }
            DiscoveryItem::Symlink(path) => {
                if !annex_imported {
                    summary.ignored_symlinks = summary.ignored_symlinks.saturating_add(1);
                    continue;
                }
                let relative = raw_relative_path(&path)?;
                let logical_path = prefixed_path(config.logical_prefix.as_deref(), &relative);
                let logical_encoded = encode_relative_path(&logical_path);
                let was_seen: bool = already_seen
                    .query_row(
                        params![logical_encoded.encoding.as_str(), logical_encoded.bytes],
                        |row| row.get(0),
                    )
                    .map_err(|source| V2InventoryError::Sqlite {
                        path: seen_path.clone(),
                        source,
                    })?;
                if was_seen {
                    continue;
                }
                if config
                    .max_items
                    .is_some_and(|limit| processed_this_run >= limit)
                {
                    interrupted = true;
                    break;
                }
                processed_this_run = processed_this_run.saturating_add(1);
                let Some(known) = known_annex_entry(
                    &connection,
                    projection.path(),
                    &config.collection_id,
                    &config.location_id,
                    &logical_encoded,
                )?
                else {
                    record_seen
                        .execute(params![
                            logical_encoded.encoding.as_str(),
                            logical_encoded.bytes
                        ])
                        .map_err(|source| V2InventoryError::Sqlite {
                            path: seen_path.clone(),
                            source,
                        })?;
                    summary.ignored_symlinks = summary.ignored_symlinks.saturating_add(1);
                    continue;
                };
                if known.representation != "annex_locked_symlink" {
                    record_seen
                        .execute(params![
                            logical_encoded.encoding.as_str(),
                            logical_encoded.bytes
                        ])
                        .map_err(|source| V2InventoryError::Sqlite {
                            path: seen_path.clone(),
                            source,
                        })?;
                    summary.observed_without_verification =
                        summary.observed_without_verification.saturating_add(1);
                    continue;
                }
                match observe_annex_symlink(
                    &config.root_path,
                    &relative,
                    &logical_encoded,
                    &known,
                    config,
                    observed_time_utc_ms,
                )? {
                    AnnexSymlinkObservation::Absent => {
                        record_seen
                            .execute(params![
                                logical_encoded.encoding.as_str(),
                                logical_encoded.bytes
                            ])
                            .map_err(|source| V2InventoryError::Sqlite {
                                path: seen_path.clone(),
                                source,
                            })?;
                        summary.files_observed = summary.files_observed.saturating_add(1);
                        summary.observed_without_verification =
                            summary.observed_without_verification.saturating_add(1);
                    }
                    AnnexSymlinkObservation::Mismatch { item } => {
                        if let Some(item) = item {
                            write_spool_item(&mut spool, &item)?;
                        }
                        record_seen
                            .execute(params![
                                logical_encoded.encoding.as_str(),
                                logical_encoded.bytes
                            ])
                            .map_err(|source| V2InventoryError::Sqlite {
                                path: seen_path.clone(),
                                source,
                            })?;
                        summary.files_observed = summary.files_observed.saturating_add(1);
                        summary.integrity_mismatches =
                            summary.integrity_mismatches.saturating_add(1);
                    }
                    AnnexSymlinkObservation::Error => {
                        record_seen
                            .execute(params![
                                logical_encoded.encoding.as_str(),
                                logical_encoded.bytes
                            ])
                            .map_err(|source| V2InventoryError::Sqlite {
                                path: seen_path.clone(),
                                source,
                            })?;
                        summary.read_errors = summary.read_errors.saturating_add(1);
                    }
                    AnnexSymlinkObservation::Observed { item, size } => {
                        write_spool_item(&mut spool, &item)?;
                        record_seen
                            .execute(params![
                                logical_encoded.encoding.as_str(),
                                logical_encoded.bytes
                            ])
                            .map_err(|source| V2InventoryError::Sqlite {
                                path: seen_path.clone(),
                                source,
                            })?;
                        summary.files_observed = summary.files_observed.saturating_add(1);
                        summary.bytes_observed = summary.bytes_observed.saturating_add(size);
                        summary.confirmed_good = summary.confirmed_good.saturating_add(1);
                    }
                }
            }
            DiscoveryItem::Special(_) => {
                summary.ignored_special_files = summary.ignored_special_files.saturating_add(1)
            }
            DiscoveryItem::Excluded(_) => {
                summary.excluded_subtrees = summary.excluded_subtrees.saturating_add(1)
            }
            DiscoveryItem::FilesystemBoundary(_) => {
                summary.filesystem_boundaries = summary.filesystem_boundaries.saturating_add(1)
            }
            DiscoveryItem::ConcurrentChange(_) => {
                summary.concurrent_changes = summary.concurrent_changes.saturating_add(1)
            }
            DiscoveryItem::Error { .. } => {
                summary.traversal_errors = summary.traversal_errors.saturating_add(1)
            }
        }
    }
    drop(known);
    drop(record_seen);
    drop(already_seen);
    spool.sync()?;
    seen.execute_batch("COMMIT")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.clone(),
            source,
        })?;
    if interrupted {
        let summary_bytes = serde_json::to_vec(&summary)
            .map_err(|error| V2InventoryError::Invalid(error.to_string()))?;
        fs::write(&summary_path, summary_bytes)
            .map_err(|source| io_error("write inventory job summary", &summary_path, source))?;
        connection
            .execute(
                "UPDATE jobs SET progress_json = ?2 WHERE job_id = ?1",
                params![
                    config.job_id,
                    serde_json::to_string(&json!({
                        "phase": "enumerating",
                        "files_processed": summary.files_observed,
                        "bytes_processed": summary.bytes_observed,
                    }))
                    .map_err(|error| V2InventoryError::Invalid(error.to_string()))?
                ],
            )
            .map_err(|source| V2InventoryError::Sqlite {
                path: projection.path().to_path_buf(),
                source,
            })?;
        spool.finish()?;
        return Ok(V2InventoryResult {
            version: 2,
            status: "running".to_owned(),
            job_id: config.job_id.clone(),
            scan_id: config.scan_id.clone(),
            summary,
            append: None,
            apply: Some(initial_apply),
        });
    }
    let complete_safe = config.scan_mode == ScanMode::Complete
        && summary.read_errors == 0
        && summary.concurrent_changes == 0
        && summary.traversal_errors == 0;
    if complete_safe {
        let mut missing = connection
            .prepare(
                "SELECT p.file_ref_id, p.observed_path_encoding, p.observed_path_bytes, p.observed_path_display,
                        (SELECT c.copy_claim_id FROM copy_claims c
                         WHERE c.location_id = p.location_id
                           AND c.relative_path_encoding = p.observed_path_encoding
                           AND c.relative_path_bytes = p.observed_path_bytes
                           AND c.state != 'superseded' LIMIT 1)
                 FROM path_observations p
                 JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                 WHERE p.location_id = ?1 AND f.collection_id = ?2 AND p.state = 'present'
                   AND NOT EXISTS (
                     SELECT 1 FROM scan_local.seen s
                     WHERE s.path_encoding = p.observed_path_encoding
                       AND s.path_bytes = p.observed_path_bytes
                   )
                 ORDER BY p.observed_path_encoding, p.observed_path_bytes, p.file_ref_id",
            )
            .map_err(|source| V2InventoryError::Sqlite {
                path: projection.path().to_path_buf(),
                source,
            })?;
        let rows = missing
            .query_map(params![config.location_id, config.collection_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|source| V2InventoryError::Sqlite {
                path: projection.path().to_path_buf(),
                source,
            })?;
        for row in rows {
            let (file_ref_id, encoding, bytes, display, copy_claim_id) =
                row.map_err(|source| V2InventoryError::Sqlite {
                    path: projection.path().to_path_buf(),
                    source,
                })?;
            let candidate_id = stable_id(
                "missing",
                &[
                    config.scan_id.as_bytes(),
                    b"path",
                    encoding.as_bytes(),
                    &bytes,
                ],
            );
            write_spool_item(
                &mut spool,
                &json!({
                    "kind": "scan_missing_candidate",
                    "candidate_id": candidate_id,
                    "scan_id": config.scan_id,
                    "candidate_kind": "path",
                    "file_ref_id": file_ref_id,
                    "copy_claim_id": copy_claim_id,
                    "location_id": config.location_id,
                    "path": registry_path_from_parts(&encoding, &bytes, &display)?,
                }),
            )?;
            summary.missing_paths = summary.missing_paths.saturating_add(1);
        }
    }
    let completion_status = if config.scan_mode == ScanMode::Complete && !complete_safe {
        "partial"
    } else {
        "complete"
    };
    let finished_time_utc_ms = now_utc_ms()?;
    write_spool_item(
        &mut spool,
        &json!({
            "kind": "scan_completed",
            "scan_id": config.scan_id,
            "status": completion_status,
            "finished_time_utc_ms": finished_time_utc_ms,
            "summary": summary,
        }),
    )?;
    write_spool_item(
        &mut spool,
        &json!({
            "kind": "job_finished",
            "job_id": config.job_id,
            "job_type": job_type,
            "input_version": config.scan_id,
            "status": completion_status,
            "summary": summary,
            "item_type": "job",
            "item_key": config.job_id,
            "outcome_kind": completion_status,
            "operation_key": stable_id(
                "op",
                &[
                    config.job_id.as_bytes(),
                    config.scan_id.as_bytes(),
                    b"job",
                    completion_status.as_bytes(),
                ],
            ),
        }),
    )?;
    let spool_path = spool.finish()?;
    drop(connection);
    drop(seen);
    let operation_kind = if config.scan_mode == ScanMode::Add {
        "inventory_add"
    } else {
        "location_scan"
    };
    let context = json!({
        "collection_id": config.collection_id,
        "location_id": config.location_id,
        "scan_mode": config.scan_mode.as_str(),
        "scan_id": config.scan_id,
        "job_id": config.job_id,
    });
    let defaults = json!({
        "content_observed": {
            "collection_id": config.collection_id,
            "location_id": config.location_id,
            "job_id": config.job_id,
            "scan_id": config.scan_id,
            "job_type": job_type,
            "observed_time_utc_ms": observed_time_utc_ms,
            "device_fingerprint_status": config.device_fingerprint_status,
            "representation": "ordinary_file",
            "item_type": "copy_claim",
            "outcome_kind": "content_observed",
            "sha256_hex": null,
            "external_identity_id": null,
            "extension_hint": null,
        }
    });
    let append = if let Some(remote) = coordination_remote {
        store.append_coordinated_jsonl_batch(
            &remote,
            operation_kind,
            2,
            context,
            defaults,
            &spool_path,
        )?
    } else {
        store.append_jsonl_batch(operation_kind, 2, context, defaults, &spool_path)?
    };
    let apply = projection.apply(store)?;
    fs::remove_dir_all(&job_root)
        .map_err(|source| io_error("remove completed inventory job files", &job_root, source))?;
    Ok(V2InventoryResult {
        version: 2,
        status: completion_status.to_owned(),
        job_id: config.job_id.clone(),
        scan_id: config.scan_id.clone(),
        summary,
        append: Some(append),
        apply: Some(apply),
    })
}

fn validate_config(config: &V2InventoryConfig) -> Result<()> {
    if config.collection_id.is_empty()
        || config.location_id.is_empty()
        || config.scan_id.is_empty()
        || config.job_id.is_empty()
    {
        return Err(V2InventoryError::Invalid(
            "Collection and Location IDs are required".to_owned(),
        ));
    }
    if config.scan_mode == ScanMode::Complete
        && (config.location_prefix.is_some() || config.logical_prefix.is_some())
    {
        return Err(V2InventoryError::Invalid(
            "a complete scan must cover the whole Location".to_owned(),
        ));
    }
    if !matches!(
        config.device_fingerprint_status.as_str(),
        "match" | "unavailable"
    ) {
        return Err(V2InventoryError::Invalid(
            "device fingerprint must match or be explicitly unavailable".to_owned(),
        ));
    }
    Ok(())
}

fn validate_scope(database: &Path, config: &V2InventoryConfig) -> Result<()> {
    let connection = Connection::open(database).map_err(|source| V2InventoryError::Sqlite {
        path: database.to_path_buf(),
        source,
    })?;
    let valid: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM collections WHERE collection_id = ?1 AND status = 'active') AND EXISTS(SELECT 1 FROM locations WHERE location_id = ?2 AND status = 'active' AND kind = 'filesystem')",
            params![config.collection_id, config.location_id],
            |row| row.get(0),
        )
        .map_err(|source| V2InventoryError::Sqlite {
            path: database.to_path_buf(),
            source,
        })?;
    if valid != 1 {
        return Err(V2InventoryError::Invalid(
            "inventory requires an active Collection and filesystem Location".to_owned(),
        ));
    }
    Ok(())
}

struct KnownAnnexEntry {
    representation: String,
    file_ref_id: String,
    external_identity_id: String,
    expected_sha256: Option<String>,
    expected_size: Option<u64>,
    object_id: Option<String>,
    copy_claim_id: Option<String>,
    copy_path: Option<PathBuf>,
}

fn known_annex_entry(
    connection: &Connection,
    database: &Path,
    collection_id: &str,
    location_id: &str,
    logical_path: &EncodedPath,
) -> Result<Option<KnownAnnexEntry>> {
    let row = connection
        .query_row(
            "SELECT p.representation, f.file_ref_id, e.external_identity_id,
                    e.expected_hash_hex, e.expected_size_bytes, e.object_id,
                    c.copy_claim_id, c.relative_path_encoding, c.relative_path_bytes,
                    c.relative_path_display
             FROM file_refs f
             JOIN path_observations p ON p.file_ref_id = f.file_ref_id
             JOIN external_identities e ON e.external_identity_id = f.external_identity_id
             LEFT JOIN copy_claims c ON c.external_identity_id = e.external_identity_id
               AND c.location_id = ?2 AND c.state != 'superseded'
             WHERE f.collection_id = ?1 AND p.location_id = ?2
               AND f.logical_path_encoding = ?3 AND f.logical_path_bytes = ?4
               AND f.path_state = 'active'
             ORDER BY c.copy_claim_id LIMIT 1",
            params![
                collection_id,
                location_id,
                logical_path.encoding.as_str(),
                logical_path.bytes,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(|source| V2InventoryError::Sqlite {
            path: database.to_path_buf(),
            source,
        })?;
    let Some((
        representation,
        file_ref_id,
        external_identity_id,
        expected_sha256,
        expected_size,
        object_id,
        copy_claim_id,
        copy_encoding,
        copy_bytes,
        copy_display,
    )) = row
    else {
        return Ok(None);
    };
    let copy_path = match (copy_encoding, copy_bytes, copy_display) {
        (Some(encoding), Some(bytes), Some(display)) => Some(
            registry_path_from_parts(&encoding, &bytes, &display)?
                .to_path_buf()
                .ok_or_else(|| {
                    V2InventoryError::Invalid(
                        "stored annex copy path is unavailable on this platform".to_owned(),
                    )
                })?,
        ),
        (None, None, None) => None,
        _ => {
            return Err(V2InventoryError::Invalid(
                "stored annex copy path is incomplete".to_owned(),
            ))
        }
    };
    Ok(Some(KnownAnnexEntry {
        representation,
        file_ref_id,
        external_identity_id,
        expected_sha256,
        object_id,
        expected_size: expected_size
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    V2InventoryError::Invalid("stored annex size is negative".to_owned())
                })
            })
            .transpose()?,
        copy_claim_id,
        copy_path,
    }))
}

fn annex_verification_failure_item(
    known: &KnownAnnexEntry,
    config: &V2InventoryConfig,
    logical_path: &Path,
    copy_path: &Path,
    hashed: &HashedContent,
    observed_time_utc_ms: u64,
) -> Option<serde_json::Value> {
    let copy_claim_id = known.copy_claim_id.as_ref()?;
    let operation_key = stable_id(
        "op",
        &[
            config.job_id.as_bytes(),
            config.scan_id.as_bytes(),
            copy_claim_id.as_bytes(),
            b"hash_mismatch",
            hashed.sha256_hex.as_bytes(),
        ],
    );
    Some(json!({
        "kind": "copy_verification_failed",
        "copy_claim_id": copy_claim_id,
        "object_id": known.object_id,
        "external_identity_id": known.external_identity_id,
        "location_id": config.location_id,
        "logical_path": RegistryPath::from_path(logical_path),
        "copy_path": RegistryPath::from_path(copy_path),
        "result": "hash_mismatch",
        "expected_hash_algo": "sha256",
        "expected_hash_hex": known.expected_sha256,
        "observed_hash_hex": hashed.sha256_hex,
        "size_bytes": hashed.size_bytes,
        "duration_ms": hashed.duration_ms,
        "verified_time_utc_ms": observed_time_utc_ms,
        "device_fingerprint_status": config.device_fingerprint_status,
        "error_detail": "git-annex content does not match its recorded key",
        "job_id": config.job_id,
        "scan_id": config.scan_id,
        "job_type": if config.scan_mode == ScanMode::Add { "inventory_add" } else { "location_scan" },
        "item_type": "copy_claim",
        "item_key": copy_claim_id,
        "outcome_kind": "hash_mismatch",
        "operation_key": operation_key,
    }))
}

enum AnnexSymlinkObservation {
    Absent,
    Mismatch { item: Option<serde_json::Value> },
    Error,
    Observed { item: serde_json::Value, size: u64 },
}

fn observe_annex_symlink(
    root: &Path,
    logical_relative: &Path,
    logical_encoded: &EncodedPath,
    known: &KnownAnnexEntry,
    config: &V2InventoryConfig,
    observed_time_utc_ms: u64,
) -> Result<AnnexSymlinkObservation> {
    let link = root.join(logical_relative);
    let target = match fs::read_link(&link) {
        Ok(target) => target,
        Err(_) => return Ok(AnnexSymlinkObservation::Error),
    };
    if target.is_absolute() {
        return Ok(AnnexSymlinkObservation::Error);
    }
    let unresolved = link.parent().unwrap_or(root).join(target);
    let content = match fs::canonicalize(&unresolved) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AnnexSymlinkObservation::Absent)
        }
        Err(_) => return Ok(AnnexSymlinkObservation::Error),
    };
    let cas_root = match fs::canonicalize(root.join(".git/annex/objects")) {
        Ok(path) => path,
        Err(_) => return Ok(AnnexSymlinkObservation::Error),
    };
    if !content.starts_with(&cas_root) {
        return Ok(AnnexSymlinkObservation::Error);
    }
    let copy_relative = content
        .strip_prefix(root)
        .map_err(|_| V2InventoryError::Invalid("annex content escaped its Location".to_owned()))?;
    if known
        .copy_path
        .as_deref()
        .is_some_and(|expected| expected != copy_relative)
    {
        return Ok(AnnexSymlinkObservation::Error);
    }
    let metadata = match fs::metadata(&content) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(AnnexSymlinkObservation::Error),
        Err(_) => return Ok(AnnexSymlinkObservation::Error),
    };
    let discovered = DiscoveredFile {
        relative_path: logical_encoded.clone(),
        size_bytes: metadata.len(),
        modified_time_utc_ms: modified_time_ms(&metadata),
    };
    let hashed = match hash_file_stable(&content, &discovered) {
        HashOutcome::Stable(hashed) => hashed,
        HashOutcome::ReadError | HashOutcome::Changed => return Ok(AnnexSymlinkObservation::Error),
    };
    if known
        .expected_sha256
        .as_deref()
        .is_some_and(|expected| expected != hashed.sha256_hex)
        || known
            .expected_size
            .is_some_and(|expected| expected != hashed.size_bytes)
    {
        return Ok(AnnexSymlinkObservation::Mismatch {
            item: annex_verification_failure_item(
                known,
                config,
                logical_relative,
                copy_relative,
                &hashed,
                observed_time_utc_ms,
            ),
        });
    }
    let copy_encoded = encode_relative_path(copy_relative);
    let copy_claim_id = known.copy_claim_id.clone().unwrap_or_else(|| {
        stable_id(
            "copy",
            &[
                config.location_id.as_bytes(),
                copy_encoded.encoding.as_str().as_bytes(),
                &copy_encoded.bytes,
            ],
        )
    });
    let object_id = format!("blake3:{}", hashed.blake3_hex);
    let item = json!({
        "kind": "content_observed",
        "collection_id": config.collection_id,
        "location_id": config.location_id,
        "logical_path": registry_path(logical_encoded),
        "copy_path": registry_path(&copy_encoded),
        "file_ref_id": known.file_ref_id,
        "copy_claim_id": copy_claim_id,
        "external_identity_id": known.external_identity_id,
        "object_id": object_id,
        "blake3_hex": hashed.blake3_hex,
        "sha256_hex": hashed.sha256_hex,
        "size_bytes": hashed.size_bytes,
        "modified_time_utc_ms": discovered.modified_time_utc_ms,
        "duration_ms": hashed.duration_ms,
        "observed_time_utc_ms": observed_time_utc_ms,
        "device_fingerprint_status": config.device_fingerprint_status,
        "representation": "annex_locked_symlink",
        "job_id": config.job_id,
        "scan_id": config.scan_id,
    });
    Ok(AnnexSymlinkObservation::Observed {
        item,
        size: hashed.size_bytes,
    })
}

struct HashedContent {
    blake3_hex: String,
    sha256_hex: String,
    size_bytes: u64,
    duration_ms: u64,
}

enum HashOutcome {
    Stable(HashedContent),
    ReadError,
    Changed,
}

fn hash_file_stable(path: &Path, discovered: &DiscoveredFile) -> HashOutcome {
    let started = Instant::now();
    let before = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return HashOutcome::ReadError,
    };
    if before.len() != discovered.size_bytes
        || modified_time_ms(&before) != discovered.modified_time_utc_ms
    {
        return HashOutcome::Changed;
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return HashOutcome::ReadError,
    };
    let mut hasher = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut bytes_read = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                sha256.update(&buffer[..read]);
                bytes_read = bytes_read.saturating_add(read as u64);
            }
            Err(_) => return HashOutcome::ReadError,
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
        sha256_hex: format!("{:x}", sha256.finalize()),
        size_bytes: bytes_read,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn registry_path(path: &EncodedPath) -> RegistryPath {
    RegistryPath::from_path(&raw_relative_path(path).expect("encoded discovery path is portable"))
}

fn registry_path_from_parts(encoding: &str, bytes: &[u8], display: &str) -> Result<RegistryPath> {
    match encoding {
        "utf8" => Ok(RegistryPath {
            encoding: encoding.to_owned(),
            text: Some(
                std::str::from_utf8(bytes)
                    .map_err(|_| {
                        V2InventoryError::Invalid("stored UTF-8 scan path is not UTF-8".to_owned())
                    })?
                    .to_owned(),
            ),
            base64: None,
            display: display.to_owned(),
        }),
        "unix_bytes" | "windows_utf16le" => Ok(RegistryPath {
            encoding: encoding.to_owned(),
            text: None,
            base64: Some(STANDARD.encode(bytes)),
            display: display.to_owned(),
        }),
        _ => Err(V2InventoryError::Invalid(format!(
            "stored scan path uses unsupported encoding {encoding:?}"
        ))),
    }
}

fn write_spool_item(spool: &mut SpoolGuard, item: &serde_json::Value) -> Result<()> {
    serde_json::to_writer(spool.writer_mut()?, item)
        .map_err(|error| V2InventoryError::Invalid(error.to_string()))?;
    let path = spool.path.clone();
    spool
        .writer_mut()?
        .write_all(b"\n")
        .map_err(|source| io_error("write inventory spool", path, source))
}

fn prefixed_path(prefix: Option<&Path>, relative: &Path) -> PathBuf {
    prefix.map_or_else(|| relative.to_path_buf(), |prefix| prefix.join(relative))
}

#[cfg(unix)]
fn raw_relative_path(path: &EncodedPath) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(
        path.bytes.clone(),
    )))
}

#[cfg(not(unix))]
fn raw_relative_path(_path: &EncodedPath) -> Result<PathBuf> {
    Err(V2InventoryError::Invalid(
        "lossless v2 inventory paths are not implemented on this platform".to_owned(),
    ))
}

fn stable_id(prefix: &str, pieces: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for piece in pieces {
        hasher.update(&(piece.len() as u64).to_le_bytes());
        hasher.update(piece);
    }
    format!("{prefix}_{}", &hasher.finalize().to_hex()[..32])
}

fn now_utc_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            V2InventoryError::Invalid(format!("system clock is before epoch: {error}"))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| V2InventoryError::Invalid("system time exceeds u64 milliseconds".to_owned()))
}

fn recover_seen_from_spool(spool_path: &Path, seen: &Connection, seen_path: &Path) -> Result<()> {
    if !spool_path.is_file() {
        return Ok(());
    }
    let reader = BufReader::new(
        File::open(spool_path)
            .map_err(|source| io_error("open inventory spool for recovery", spool_path, source))?,
    );
    seen.execute_batch("BEGIN IMMEDIATE")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.to_path_buf(),
            source,
        })?;
    let mut insert = seen
        .prepare("INSERT OR IGNORE INTO seen(path_encoding, path_bytes) VALUES (?1, ?2)")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.to_path_buf(),
            source,
        })?;
    for line in reader.lines() {
        let line = line
            .map_err(|source| io_error("read inventory spool for recovery", spool_path, source))?;
        if line.trim().is_empty() {
            continue;
        }
        let item: serde_json::Value = serde_json::from_str(&line).map_err(|error| {
            V2InventoryError::Invalid(format!(
                "inventory recovery spool contains invalid JSON: {error}"
            ))
        })?;
        if !matches!(
            item.get("kind").and_then(serde_json::Value::as_str),
            Some("content_observed" | "copy_verification_failed")
        ) {
            continue;
        }
        let path: RegistryPath =
            serde_json::from_value(item.get("logical_path").cloned().ok_or_else(|| {
                V2InventoryError::Invalid("content observation lacks a logical path".to_owned())
            })?)
            .map_err(|error| {
                V2InventoryError::Invalid(format!(
                    "content observation logical path is invalid: {error}"
                ))
            })?;
        let bytes = crate::registry::registry_path_bytes(&path)
            .map_err(|error| V2InventoryError::Invalid(error.to_string()))?;
        insert
            .execute(params![path.encoding, bytes])
            .map_err(|source| V2InventoryError::Sqlite {
                path: seen_path.to_path_buf(),
                source,
            })?;
    }
    drop(insert);
    seen.execute_batch("COMMIT")
        .map_err(|source| V2InventoryError::Sqlite {
            path: seen_path.to_path_buf(),
            source,
        })?;
    Ok(())
}

struct SpoolGuard {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    preserve_on_drop: bool,
}

impl SpoolGuard {
    fn sync(&mut self) -> Result<()> {
        let path = self.path.clone();
        let writer = self.writer_mut()?;
        writer
            .flush()
            .map_err(|source| io_error("flush inventory spool", &path, source))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|source| io_error("sync inventory spool", &path, source))
    }

    fn writer_mut(&mut self) -> Result<&mut BufWriter<File>> {
        self.writer
            .as_mut()
            .ok_or_else(|| V2InventoryError::Invalid("inventory spool is closed".to_owned()))
    }

    fn finish(mut self) -> Result<PathBuf> {
        let mut writer = self
            .writer
            .take()
            .ok_or_else(|| V2InventoryError::Invalid("inventory spool is closed".to_owned()))?;
        writer
            .flush()
            .map_err(|source| io_error("flush inventory spool", &self.path, source))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|source| io_error("sync inventory spool", &self.path, source))?;
        Ok(self.path.clone())
    }
}

impl Drop for SpoolGuard {
    fn drop(&mut self) {
        if self.writer.is_some() && !self.preserve_on_drop {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> V2InventoryError {
    V2InventoryError::Io {
        operation,
        path: path.into(),
        source,
    }
}
