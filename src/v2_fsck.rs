//! Layered, read-only health verification for version 2 Archives.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;

use crate::v2_projection::{V2ProjectionDb, V2ProjectionError};
use crate::v2_store::{V2OriginStore, V2StoreError};

const DIAGNOSTIC_LIMIT: usize = 64 * 1024;

const DERIVED_TABLES: &[(&str, Option<&str>)] = &[
    ("archive_meta", Some("key NOT IN ('projection_generation','policy_input_generation','last_verified_checkpoint_id','last_verified_checkpoint_frontier_hash')")),
    ("records", None),
    ("projection_origins", None),
    ("clients", None),
    ("batch_runs", None),
    ("coordination_tokens", None),
    ("fact_conflicts", None),
    ("sites", None),
    ("policies", None),
    ("collections", None),
    ("devices", None),
    ("device_site_history", None),
    ("archive_roots", None),
    ("locations", None),
    ("device_mounts", None),
    ("risk_domains", None),
    ("entity_risk_domains", None),
    ("objects", None),
    ("object_hashes", None),
    ("external_identities", None),
    ("external_availability", None),
    ("file_refs", None),
    ("path_observations", None),
    ("copy_claims", None),
    ("verification_results", None),
    ("scan_runs", None),
    ("scan_missing_candidates", None),
    ("scan_pending_completions", None),
    ("operation_outcomes", None),
    ("annex_imports", None),
    ("annex_remotes", None),
];

const LOCAL_OPERATIONAL_TABLES: &[&str] = &["jobs", "job_items"];

pub type Result<T> = std::result::Result<T, V2FsckError>;

#[derive(Debug, Error)]
pub enum V2FsckError {
    #[error(transparent)]
    Store(#[from] V2StoreError),
    #[error(transparent)]
    Projection(#[from] V2ProjectionError),
    #[error("fsck I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("fsck SQLite check failed at {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("fsck configuration is invalid: {0}")]
    Invalid(String),
}

impl V2FsckError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Store(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Io { .. } => "fsck_io",
            Self::Sqlite { .. } => "fsck_sqlite",
            Self::Invalid(_) => "fsck_invalid",
        }
    }
}

#[derive(Debug, Clone)]
pub struct V2FsckOptions {
    pub full: bool,
    pub keep_rebuild: bool,
    pub rebuild_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct V2FsckCheck {
    pub layer: String,
    pub status: String,
    pub code: String,
    pub summary: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2TableDigest {
    pub table: String,
    pub rows: u64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct V2FsckReport {
    pub version: u32,
    pub archive_id: Option<String>,
    pub full: bool,
    pub healthy: bool,
    pub projection_current: Option<bool>,
    pub checks: Vec<V2FsckCheck>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub table_digests: Vec<V2TableDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rebuild_path: Option<PathBuf>,
}

impl V2FsckReport {
    pub fn exit_code(&self) -> u8 {
        if self.checks.iter().any(|check| check.status == "error") {
            2
        } else if self.healthy {
            0
        } else {
            10
        }
    }
}

pub fn fsck_v2_archive(
    store: &V2OriginStore,
    database_path: &Path,
    options: &V2FsckOptions,
) -> Result<V2FsckReport> {
    if options.keep_rebuild && !options.full {
        return Err(V2FsckError::Invalid(
            "--keep-rebuild requires --full".to_owned(),
        ));
    }
    if options.rebuild_dir.is_some() && !options.full {
        return Err(V2FsckError::Invalid(
            "--rebuild-dir requires --full".to_owned(),
        ));
    }
    let mut report = V2FsckReport {
        version: 2,
        archive_id: None,
        full: options.full,
        healthy: true,
        projection_current: None,
        checks: Vec::new(),
        table_digests: Vec::new(),
        rebuild_path: None,
    };

    let started = Instant::now();
    let git = bounded_command(
        Command::new("git")
            .arg("-C")
            .arg(store.root())
            .args(["fsck", "--full", "--strict"]),
    )?;
    let git_success = git.success;
    push_check(
        &mut report,
        "git",
        git_success,
        "git_objects_valid",
        if git_success {
            "Git objects and references are valid".to_owned()
        } else {
            "Git found object or reference damage".to_owned()
        },
        started,
        nonempty(git.diagnostics()),
    );

    let event_started = Instant::now();
    let verified = match store.verification_report() {
        Ok(verified) => {
            report.archive_id = Some(verified.archive_id.clone());
            push_check(
                &mut report,
                "events",
                true,
                "canonical_events_valid",
                format!(
                    "{} signed records in {} segments and {} origins are valid",
                    verified.records, verified.segments, verified.origins
                ),
                event_started,
                None,
            );
            Some(verified)
        }
        Err(error) => {
            push_check(
                &mut report,
                "events",
                false,
                "canonical_events_invalid",
                "Canonical signed history could not be verified".to_owned(),
                event_started,
                Some(error.to_string()),
            );
            None
        }
    };

    let sqlite_started = Instant::now();
    let connection = open_read_only(database_path)?;
    let quick = sqlite_check_findings(&connection, database_path, "PRAGMA quick_check")?;
    push_check(
        &mut report,
        "sqlite",
        quick.total == 0,
        "sqlite_quick_check",
        if quick.total == 0 {
            "SQLite quick_check is ok".to_owned()
        } else {
            format!("SQLite quick_check found {} problem(s)", quick.total)
        },
        sqlite_started,
        (!quick.examples.is_empty()).then(|| quick.examples.join("; ")),
    );

    let fk_started = Instant::now();
    let foreign_keys = foreign_key_findings(&connection, database_path)?;
    push_check(
        &mut report,
        "sqlite",
        foreign_keys.total == 0,
        "sqlite_foreign_keys",
        if foreign_keys.total == 0 {
            "SQLite foreign keys are valid".to_owned()
        } else {
            format!("SQLite has {} foreign-key violation(s)", foreign_keys.total)
        },
        fk_started,
        (!foreign_keys.examples.is_empty()).then(|| foreign_keys.examples.join("; ")),
    );

    if let Some(verified) = &verified {
        let alignment_started = Instant::now();
        let archive_id = meta(&connection, database_path, "archive_id")?;
        let genesis_hash = meta(&connection, database_path, "genesis_hash")?;
        let accepted = meta(&connection, database_path, "accepted_frontier_hash")?;
        let applied = meta(&connection, database_path, "applied_frontier_hash")?;
        let identity_ok =
            archive_id == verified.archive_id && genesis_hash == verified.genesis_hash;
        push_check(
            &mut report,
            "projection",
            identity_ok,
            "projection_identity",
            if identity_ok {
                "SQLite Archive and genesis identities match canonical history".to_owned()
            } else {
                "SQLite Archive or genesis identity differs from canonical history".to_owned()
            },
            alignment_started,
            None,
        );
        let frontier_started = Instant::now();
        let frontiers_known = if git_success {
            let accepted_commit = commit_containing_frontier(store, &accepted)?;
            let applied_commit = if applied == accepted {
                accepted_commit.clone()
            } else {
                commit_containing_frontier(store, &applied)?
            };
            Some(accepted_commit.is_some() && applied_commit.is_some())
        } else {
            None
        };
        match frontiers_known {
            Some(known) => push_check(
                &mut report,
                "projection",
                known,
                "projection_frontiers_known",
                if known {
                    "SQLite accepted and applied frontiers occur in canonical Git history"
                        .to_owned()
                } else {
                    "SQLite names an accepted or applied frontier outside canonical Git history"
                        .to_owned()
                },
                frontier_started,
                (!known).then(|| format!("accepted={accepted}; applied={applied}")),
            ),
            None => push_error(
                &mut report,
                "projection",
                "projection_frontiers_unchecked",
                "Projection frontier ancestry could not be checked because Git objects are damaged",
                frontier_started,
                "Repair or restore canonical Git history, then rerun fsck".to_owned(),
            ),
        }
        let current = git_success.then_some(applied == verified.accepted_frontier_hash);
        report.projection_current = current;
        let current_started = Instant::now();
        if let Some(current) = current {
            push_check(
                &mut report,
                "projection",
                current,
                "projection_current",
                if current {
                    "SQLite is current with canonical history".to_owned()
                } else if frontiers_known == Some(true) {
                    "SQLite is behind canonical history; run `archive db apply`".to_owned()
                } else {
                    "SQLite is not current and its frontier is not canonical; restore or rebuild the projection"
                        .to_owned()
                },
                current_started,
                Some(format!(
                    "applied={applied}; accepted={}",
                    verified.accepted_frontier_hash
                )),
            );
        } else {
            push_error(
                &mut report,
                "projection",
                "projection_current_unchecked",
                "Projection currentness could not be trusted because Git objects are damaged",
                current_started,
                "Repair or restore canonical Git history, then rerun fsck".to_owned(),
            );
        }
        if current == Some(true) {
            let cursor_started = Instant::now();
            let database = V2ProjectionDb::open_existing(database_path)?;
            let result = database.validate_against_store(store);
            push_check(
                &mut report,
                "projection",
                result.is_ok(),
                "projection_cursors",
                if result.is_ok() {
                    "Projection record count and every origin cursor match canonical tails"
                        .to_owned()
                } else {
                    "Projection cursors or mirrored record count differ from canonical history"
                        .to_owned()
                },
                cursor_started,
                result.err().map(|error| error.to_string()),
            );
        }
    }

    if options.full && verified.is_some() && git_success {
        run_full_check(store, database_path, options, &mut report)?;
    } else if options.full {
        report.checks.push(V2FsckCheck {
            layer: "projection_equivalence".to_owned(),
            status: "error".to_owned(),
            code: "full_check_prerequisite_failed".to_owned(),
            summary: "Logical rebuild comparison requires healthy Git objects and canonical events"
                .to_owned(),
            duration_ms: 0,
            detail: None,
        });
    } else {
        report.checks.push(V2FsckCheck {
            layer: "projection_equivalence".to_owned(),
            status: "skipped".to_owned(),
            code: "full_check_not_requested".to_owned(),
            summary: "Logical rebuild comparison was not requested; run `archive fsck --full`"
                .to_owned(),
            duration_ms: 0,
            detail: None,
        });
    }
    report.healthy = !report
        .checks
        .iter()
        .any(|check| matches!(check.status.as_str(), "finding" | "error"));
    Ok(report)
}

fn run_full_check(
    store: &V2OriginStore,
    database_path: &Path,
    options: &V2FsckOptions,
    report: &mut V2FsckReport,
) -> Result<()> {
    let mut live = open_read_only(database_path)?;
    let transaction = live
        .transaction()
        .map_err(|source| sqlite_error(database_path, source))?;
    let captured_frontier = meta(&transaction, database_path, "applied_frontier_hash")?;
    validate_table_classification(&transaction, database_path)?;
    let live_digests = database_digests(&transaction, database_path)?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(database_path, source))?;
    let Some(captured_commit) = commit_containing_frontier(store, &captured_frontier)? else {
        report.checks.push(V2FsckCheck {
            layer: "projection_equivalence".to_owned(),
            status: "finding".to_owned(),
            code: "applied_frontier_not_canonical".to_owned(),
            summary: "The applied SQLite frontier does not occur in canonical Git history"
                .to_owned(),
            duration_ms: 0,
            detail: Some(format!("applied={captured_frontier}")),
        });
        return Ok(());
    };
    let base = options
        .rebuild_dir
        .clone()
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&base).map_err(|source| io_error(&base, source))?;
    let base = fs::canonicalize(&base).map_err(|source| io_error(&base, source))?;
    let canonical_root =
        fs::canonicalize(store.root()).map_err(|source| io_error(store.root(), source))?;
    if base.starts_with(&canonical_root) {
        return Err(V2FsckError::Invalid(format!(
            "disposable rebuild directory {} must not be inside canonical Git history {}",
            base.display(),
            canonical_root.display()
        )));
    }
    let required = fs::metadata(database_path)
        .map_err(|source| io_error(database_path, source))?
        .len()
        .saturating_mul(2)
        .saturating_add(directory_size(store.root())?)
        .saturating_add(64 * 1024 * 1024);
    let available = fs2::available_space(&base).map_err(|source| io_error(&base, source))?;
    if available < required {
        report.checks.push(V2FsckCheck {
            layer: "projection_equivalence".to_owned(),
            status: "error".to_owned(),
            code: "insufficient_rebuild_space".to_owned(),
            summary: "Not enough free space for a disposable full rebuild".to_owned(),
            duration_ms: 0,
            detail: Some(format!(
                "required_bytes={required}; available_bytes={available}"
            )),
        });
        return Ok(());
    }
    let started = Instant::now();
    let mut temp = FsckTemp::new(&base)?;
    let clone = temp.path.join("canonical");
    let clone_result = bounded_command(
        Command::new("git")
            .args(["clone", "--quiet", "--no-hardlinks"])
            .arg(store.root())
            .arg(&clone),
    )?;
    if !clone_result.success {
        push_error(
            report,
            "projection_equivalence",
            "rebuild_clone_failed",
            "Could not create the disposable canonical clone",
            started,
            clone_result.diagnostics(),
        );
        return Ok(());
    }
    let checkout = bounded_command(Command::new("git").arg("-C").arg(&clone).args([
        "checkout",
        "--quiet",
        "--detach",
        &captured_commit,
    ]))?;
    if !checkout.success {
        push_error(
            report,
            "projection_equivalence",
            "rebuild_checkout_failed",
            "Could not select the captured canonical commit in the disposable clone",
            started,
            checkout.diagnostics(),
        );
        return Ok(());
    }
    let cloned_store = V2OriginStore::open(&clone)?;
    let cloned_verified = cloned_store.verification_report()?;
    if cloned_verified.accepted_frontier_hash != captured_frontier {
        push_error(
            report,
            "projection_equivalence",
            "captured_frontier_commit_mismatch",
            "Could not bind the live SQLite snapshot to one canonical Git commit; retry fsck",
            started,
            format!(
                "sqlite_frontier={captured_frontier}; commit_frontier={}",
                cloned_verified.accepted_frontier_hash
            ),
        );
        return Ok(());
    }
    let rebuilt_path = temp.path.join("archive.db");
    V2ProjectionDb::create_from_store(&cloned_store, &rebuilt_path)?;
    let rebuilt = open_read_only(&rebuilt_path)?;
    validate_table_classification(&rebuilt, &rebuilt_path)?;
    let rebuilt_integrity_started = Instant::now();
    let rebuilt_integrity =
        sqlite_check_findings(&rebuilt, &rebuilt_path, "PRAGMA integrity_check")?;
    push_check(
        report,
        "rebuilt_sqlite",
        rebuilt_integrity.total == 0,
        "rebuilt_sqlite_integrity",
        if rebuilt_integrity.total == 0 {
            "Disposable rebuilt SQLite integrity_check is ok".to_owned()
        } else {
            format!(
                "Disposable rebuilt SQLite has {} integrity problem(s)",
                rebuilt_integrity.total
            )
        },
        rebuilt_integrity_started,
        (!rebuilt_integrity.examples.is_empty()).then(|| rebuilt_integrity.examples.join("; ")),
    );
    let rebuilt_fk_started = Instant::now();
    let rebuilt_foreign_keys = foreign_key_findings(&rebuilt, &rebuilt_path)?;
    push_check(
        report,
        "rebuilt_sqlite",
        rebuilt_foreign_keys.total == 0,
        "rebuilt_sqlite_foreign_keys",
        if rebuilt_foreign_keys.total == 0 {
            "Disposable rebuilt SQLite foreign keys are valid".to_owned()
        } else {
            format!(
                "Disposable rebuilt SQLite has {} foreign-key violation(s)",
                rebuilt_foreign_keys.total
            )
        },
        rebuilt_fk_started,
        (!rebuilt_foreign_keys.examples.is_empty())
            .then(|| rebuilt_foreign_keys.examples.join("; ")),
    );
    let rebuilt_digests = database_digests(&rebuilt, &rebuilt_path)?;
    let mismatch_detail = digest_mismatch_detail(&live_digests, &rebuilt_digests);
    let equal = mismatch_detail.is_none();
    report.table_digests = live_digests;
    push_check(
        report,
        "projection_equivalence",
        equal,
        "projection_logical_equivalence",
        if equal {
            "Live event-derived tables equal a disposable canonical rebuild".to_owned()
        } else {
            "Live event-derived tables differ from a disposable canonical rebuild".to_owned()
        },
        started,
        mismatch_detail,
    );
    if options.keep_rebuild {
        let kept = temp.keep();
        report.rebuild_path = Some(kept.join("archive.db"));
    }
    Ok(())
}

struct FsckTemp {
    path: PathBuf,
    preserve: bool,
}

impl FsckTemp {
    fn new(base: &Path) -> Result<Self> {
        let path = base.join(format!(
            "archive-ledger-fsck-{}",
            Ulid::new().to_string().to_ascii_lowercase()
        ));
        fs::create_dir(&path).map_err(|source| io_error(&path, source))?;
        Ok(Self {
            path,
            preserve: false,
        })
    }

    fn keep(&mut self) -> PathBuf {
        self.preserve = true;
        self.path.clone()
    }
}

impl Drop for FsckTemp {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn open_read_only(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|source| sqlite_error(path, source))
}

struct FindingSummary {
    total: u64,
    examples: Vec<String>,
}

fn sqlite_check_findings(
    connection: &Connection,
    path: &Path,
    pragma: &str,
) -> Result<FindingSummary> {
    let mut statement = connection
        .prepare(pragma)
        .map_err(|source| sqlite_error(path, source))?;
    let mut rows = statement
        .query([])
        .map_err(|source| sqlite_error(path, source))?;
    let mut findings = FindingSummary {
        total: 0,
        examples: Vec::new(),
    };
    while let Some(row) = rows.next().map_err(|source| sqlite_error(path, source))? {
        let text = row
            .get::<_, String>(0)
            .unwrap_or_else(|_| "unreadable SQLite diagnostic".to_owned());
        if text == "ok" {
            continue;
        }
        findings.total = findings.total.saturating_add(1);
        if findings.examples.len() < 100 {
            findings.examples.push(text);
        }
    }
    Ok(findings)
}

fn foreign_key_findings(connection: &Connection, path: &Path) -> Result<FindingSummary> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|source| sqlite_error(path, source))?;
    let mut rows = statement
        .query([])
        .map_err(|source| sqlite_error(path, source))?;
    let mut findings = FindingSummary {
        total: 0,
        examples: Vec::new(),
    };
    while let Some(row) = rows.next().map_err(|source| sqlite_error(path, source))? {
        findings.total = findings.total.saturating_add(1);
        if findings.examples.len() < 100 {
            findings.examples.push(format!(
                "table={} rowid={:?} parent={} fk={}",
                row.get::<_, String>(0).unwrap_or_else(|_| "?".to_owned()),
                row.get::<_, Option<i64>>(1).ok().flatten(),
                row.get::<_, String>(2).unwrap_or_else(|_| "?".to_owned()),
                row.get::<_, i64>(3).unwrap_or(-1),
            ));
        }
    }
    Ok(findings)
}

fn validate_table_classification(connection: &Connection, path: &Path) -> Result<()> {
    let mut actual = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|source| sqlite_error(path, source))?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| sqlite_error(path, source))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, source))?;
    let mut classified = DERIVED_TABLES
        .iter()
        .map(|(table, _)| (*table).to_owned())
        .chain(
            LOCAL_OPERATIONAL_TABLES
                .iter()
                .map(|table| (*table).to_owned()),
        )
        .collect::<Vec<_>>();
    actual.sort();
    classified.sort();
    if actual != classified {
        return Err(V2FsckError::Invalid(format!(
            "schema table classification is incomplete: actual={actual:?}, classified={classified:?}"
        )));
    }
    Ok(())
}

fn database_digests(connection: &Connection, path: &Path) -> Result<Vec<V2TableDigest>> {
    DERIVED_TABLES
        .iter()
        .map(|(table, filter)| table_digest(connection, path, table, *filter))
        .collect()
}

fn digest_mismatch_detail(live: &[V2TableDigest], rebuilt: &[V2TableDigest]) -> Option<String> {
    let mut differences = Vec::new();
    for (live, rebuilt) in live.iter().zip(rebuilt) {
        if live != rebuilt {
            differences.push(format!(
                "{}: live rows={} digest={}; rebuilt rows={} digest={}",
                live.table, live.rows, live.digest, rebuilt.rows, rebuilt.digest
            ));
        }
    }
    if live.len() != rebuilt.len() {
        differences.push(format!(
            "table digest count differs: live={}; rebuilt={}",
            live.len(),
            rebuilt.len()
        ));
    }
    (!differences.is_empty()).then(|| differences.join("; "))
}

fn table_digest(
    connection: &Connection,
    path: &Path,
    table: &str,
    filter: Option<&str>,
) -> Result<V2TableDigest> {
    let pragma = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
    let columns = connection
        .prepare(&pragma)
        .map_err(|source| sqlite_error(path, source))?
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|source| sqlite_error(path, source))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, source))?;
    if columns.is_empty() {
        return Err(V2FsckError::Invalid(format!(
            "table {table} has no columns"
        )));
    }
    let quoted = columns
        .iter()
        .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
        .collect::<Vec<_>>();
    let mut sql = format!("SELECT {} FROM \"{table}\"", quoted.join(","));
    if let Some(filter) = filter {
        sql.push_str(" WHERE ");
        sql.push_str(filter);
    }
    sql.push_str(" ORDER BY ");
    sql.push_str(&quoted.join(","));
    let mut statement = connection
        .prepare(&sql)
        .map_err(|source| sqlite_error(path, source))?;
    let mut rows = statement
        .query([])
        .map_err(|source| sqlite_error(path, source))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"archive-ledger-fsck-table-v1\0");
    hasher.update(table.as_bytes());
    let mut count = 0_u64;
    while let Some(row) = rows.next().map_err(|source| sqlite_error(path, source))? {
        for index in 0..columns.len() {
            let value = row
                .get_ref(index)
                .map_err(|source| sqlite_error(path, source))?;
            digest_value(&mut hasher, value);
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| V2FsckError::Invalid("table row count overflow".to_owned()))?;
    }
    Ok(V2TableDigest {
        table: table.to_owned(),
        rows: count,
        digest: format!("blake3:{}", hasher.finalize().to_hex()),
    })
}

fn digest_value(hasher: &mut blake3::Hasher, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update(&[0]),
        ValueRef::Integer(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_be_bytes())
        }
        ValueRef::Real(value) => {
            hasher.update(&[2]);
            hasher.update(&value.to_bits().to_be_bytes())
        }
        ValueRef::Text(value) => {
            hasher.update(&[3]);
            hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value)
        }
        ValueRef::Blob(value) => {
            hasher.update(&[4]);
            hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value)
        }
    };
}

struct CommandResult {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CommandResult {
    fn diagnostics(&self) -> String {
        match (self.stdout.is_empty(), self.stderr.is_empty()) {
            (false, false) => format!("{}\n{}", self.stdout, self.stderr),
            (false, true) => self.stdout.clone(),
            (true, false) => self.stderr.clone(),
            (true, true) => String::new(),
        }
    }
}

fn bounded_command(command: &mut Command) -> Result<CommandResult> {
    let display = format!("{command:?}");
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| V2FsckError::Io {
            path: PathBuf::from(display.clone()),
            source,
        })?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let out = std::thread::spawn(move || drain_bounded(stdout));
    let err = std::thread::spawn(move || drain_bounded(stderr));
    let status = child.wait().map_err(|source| V2FsckError::Io {
        path: PathBuf::from(display),
        source,
    })?;
    Ok(CommandResult {
        success: status.success(),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

fn drain_bounded(mut reader: impl Read) -> String {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    while let Ok(count) = reader.read(&mut buffer) {
        if count == 0 {
            break;
        }
        let remaining = DIAGNOSTIC_LIMIT.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    String::from_utf8_lossy(&kept).trim().to_owned()
}

fn push_check(
    report: &mut V2FsckReport,
    layer: &str,
    healthy: bool,
    code: &str,
    summary: String,
    started: Instant,
    detail: Option<String>,
) {
    report.checks.push(V2FsckCheck {
        layer: layer.to_owned(),
        status: if healthy { "pass" } else { "finding" }.to_owned(),
        code: code.to_owned(),
        summary,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        detail,
    });
}

fn push_error(
    report: &mut V2FsckReport,
    layer: &str,
    code: &str,
    summary: &str,
    started: Instant,
    detail: String,
) {
    report.checks.push(V2FsckCheck {
        layer: layer.to_owned(),
        status: "error".to_owned(),
        code: code.to_owned(),
        summary: summary.to_owned(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        detail: Some(detail),
    });
}

fn meta(connection: &Connection, path: &Path, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM archive_meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, source))
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn directory_size(root: &Path) -> Result<u64> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| io_error(&directory, source))? {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

/// Finds a canonical commit whose accepted-frontier pointer has the requested
/// value. `git log -S` normally returns the commit that removed the value
/// before the commit that introduced it, so every small candidate set is
/// checked rather than trusting log order.
fn commit_containing_frontier(
    store: &V2OriginStore,
    frontier_hash: &str,
) -> Result<Option<String>> {
    let pickaxe = format!("-S{frontier_hash}");
    let candidates = bounded_command(Command::new("git").arg("-C").arg(store.root()).args([
        "log",
        "--all",
        "--format=%H",
        &pickaxe,
        "--",
        "frontiers/v2/HEAD",
    ]))?;
    if !candidates.success {
        return Err(V2FsckError::Invalid(format!(
            "could not search canonical Git history for frontier {frontier_hash}: {}",
            candidates.diagnostics()
        )));
    }
    for commit in candidates.stdout.lines() {
        if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        let object = format!("{commit}:frontiers/v2/HEAD");
        let head = bounded_command(
            Command::new("git")
                .arg("-C")
                .arg(store.root())
                .args(["show", &object]),
        )?;
        if head.success && head.stdout.trim() == frontier_hash {
            return Ok(Some(commit.to_owned()));
        }
    }
    Ok(None)
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> V2FsckError {
    V2FsckError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

fn io_error(path: &Path, source: std::io::Error) -> V2FsckError {
    V2FsckError::Io {
        path: path.to_path_buf(),
        source,
    }
}
