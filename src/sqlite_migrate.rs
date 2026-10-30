//! Explicit, conservative legacy conversion. Originals are never rebuilt or activated.
use crate::v2_store::{V2StoreError, V2VerificationReport, VerifiedV2Archive};
use crate::{SqliteCatalog, V2OriginStore, V2ProjectionDb};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use fs2::FileExt;
use rusqlite::{params, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("migration refused: {0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Catalog(#[from] crate::SqliteCatalogError),
    #[error(transparent)]
    Legacy(#[from] crate::v2_projection::V2ProjectionError),
    #[error(transparent)]
    Store(#[from] V2StoreError),
    #[error(transparent)]
    Backup(#[from] crate::sqlite_backup::CatalogBackupError),
    #[error(transparent)]
    Placement(#[from] crate::safe_copy::SafeCopyError),
}
impl MigrationError {
    pub fn code(&self) -> &'static str {
        "catalog_migration_failed"
    }
}
type Result<T> = std::result::Result<T, MigrationError>;
#[derive(Debug, Serialize)]
pub struct MigrationReport {
    pub archive_id: String,
    pub destination: PathBuf,
    pub objects: u64,
    pub files: u64,
    pub legacy_records: u64,
    pub checks: u64,
    pub backup: PathBuf,
}

pub fn migrate_catalog(
    events: &Path,
    legacy_db: &Path,
    destination: &Path,
) -> Result<MigrationReport> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err(MigrationError::Invalid("destination already exists".into()));
    }
    let archive = events
        .parent()
        .ok_or_else(|| MigrationError::Invalid("canonical directory has no parent".into()))?;
    // Empty legacy archives have not created the append lock yet. Establish
    // the same persistent inode as the writer without truncating it. Never
    // unlink it: waiting writers must continue to share this coordination lock.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(archive.join("local/append.lock"))?;
    lock.try_lock_exclusive()
        .map_err(|e| MigrationError::Invalid(format!("cannot freeze legacy writer: {e}")))?;
    let original =
        Connection::open_with_flags(legacy_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let local = crate::local_job_ids(archive)?;
    for id in local {
        let terminal = original
            .query_row(
                "SELECT status IN ('complete','cancelled') FROM jobs WHERE job_id=?1",
                [&id],
                |r| r.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false);
        if !terminal {
            return Err(MigrationError::Invalid(format!(
                "unfinished local job {id}; finish or cancel it before migration"
            )));
        }
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if fs::canonicalize(parent)?.starts_with(fs::canonicalize(archive)?) {
        return Err(MigrationError::Invalid(
            "new directory must be outside the original Archive".into(),
        ));
    }
    let stage_path = parent.join(format!(".archive-ledger-migrate-{}", ulid::Ulid::new()));
    fs::create_dir(&stage_path)?;
    let stage = Staging(stage_path);
    let store = V2OriginStore::open(events)?;
    let snapshot = stage.0.join("legacy.db");
    let mut legacy = Connection::open(&snapshot)?;
    // SQLite backup includes committed WAL state without modifying the source.
    // Keep all conversion scratch tables in this private snapshot, not the original.
    rusqlite::backup::Backup::new(&original, &mut legacy)?.run_to_completion(
        256,
        std::time::Duration::from_millis(5),
        None,
    )?;
    legacy.execute_batch("PRAGMA journal_mode=DELETE;")?;
    let projection = V2ProjectionDb::open_existing(&snapshot)?;
    legacy.execute_batch("BEGIN IMMEDIATE")?;
    for (table, predicate) in [
        ("jobs", "status='running'"),
        ("batch_runs", "state!='complete'"),
        ("fact_conflicts", "state='unresolved'"),
        ("scan_runs", "status='running'"),
        ("annex_imports", "status='running'"),
    ] {
        let n: i64 = legacy.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
            [],
            |r| r.get(0),
        )?;
        if n > 0 {
            return Err(MigrationError::Invalid(format!(
                "{n} unfinished/conflicting {table} rows"
            )));
        }
    }
    let duplicate:Option<String>=legacy.query_row("SELECT c.collection_id||':'||COALESCE(f.path_display,hex(f.path_bytes)) FROM file_objects f JOIN collections c ON c.id=f.collection_id GROUP BY f.collection_id,f.path_encoding,f.path_bytes HAVING COUNT(*)>1 LIMIT 1",[],|r|r.get(0)).optional()?;
    if let Some(path) = duplicate {
        return Err(MigrationError::Invalid(format!(
            "multiple legacy identities at Collection/path {path}, including inactive expectations"
        )));
    }
    let archive_id: String = legacy.query_row(
        "SELECT value FROM archive_meta WHERE key='archive_id'",
        [],
        |r| r.get(0),
    )?;
    let source_id: String = original.query_row(
        "SELECT value FROM archive_meta WHERE key='archive_id'",
        [],
        |r| r.get(0),
    )?;
    if source_id != archive_id {
        return Err(MigrationError::Invalid(
            "legacy database and canonical history identify different Archives".into(),
        ));
    }
    let name: String = legacy.query_row(
        "SELECT value FROM archive_meta WHERE key='archive_display_name'",
        [],
        |r| r.get(0),
    )?;
    let path = stage.0.join("archive.db");
    let mut catalog = SqliteCatalog::create(&path, &archive_id, &name)?;
    legacy.execute_batch("CREATE TABLE migration_expectations(file TEXT,hash BLOB,size INTEGER,accepted INTEGER,origin TEXT,seq INTEGER,item INTEGER,frontier TEXT,time INTEGER,copy TEXT); CREATE INDEX migration_expectations_file ON migration_expectations(file); CREATE INDEX migration_expectations_copy ON migration_expectations(copy); CREATE TABLE migration_failures(copy TEXT,time INTEGER,hash BLOB); CREATE INDEX migration_failure_copy_time ON migration_failures(copy,time);")?;
    let tx = catalog.connection_mut().transaction()?;
    copy_registry(&legacy, &tx)?;
    let mut defaults = BTreeMap::<String, (u64, Value)>::new();
    let mut callback_error = None;
    let verified=store.visit_verified(|record|{
   let action=(||->Result<()>{
     let e=&record.record.envelope;
     tx.execute("INSERT INTO history(time_utc_ms,kind,details_json) VALUES(?1,'legacy_record',?2)",params![e.time_utc_ms as i64,json!({"record_id":e.record_id,"exact_line_base64":STANDARD_NO_PAD.encode(&record.exact_line_bytes),"segment_manifest_hash":record.segment_manifest_hash,"causal_frontier_hash":record.causal_frontier_hash}).to_string()])?;
     match e.record_kind {
       crate::v2_event::V2RecordKind::BatchStart=>{defaults.insert(e.batch_id.clone(),(e.payload["item_schema_version"].as_u64().unwrap_or(1),e.payload["defaults"].clone()));},
       crate::v2_event::V2RecordKind::BatchComplete=>{defaults.remove(&e.batch_id);},
       crate::v2_event::V2RecordKind::BatchChunk=>{
         let (version,defaults)=defaults.get(&e.batch_id).ok_or_else(||MigrationError::Invalid("missing authenticated batch start".into()))?;
         for (offset,raw) in e.payload["items"].as_array().ok_or_else(||MigrationError::Invalid("invalid items".into()))?.iter().enumerate(){
           let item=if *version==1 {raw.as_object().cloned().ok_or_else(||MigrationError::Invalid("invalid item".into()))?}else{crate::v2_projection::materialize_batch_item(raw,defaults)?};
           let kind=item.get("kind").and_then(Value::as_str).unwrap_or("");
           if kind=="copy_verification_failed" && item.get("expected_hash_algo").and_then(Value::as_str)==Some("blake3") {
             if let (Some(copy),Some(hash))=(item.get("copy_claim_id").and_then(Value::as_str),item.get("observed_hash_hex").and_then(Value::as_str)) {
               let hash=blake3::Hash::from_hex(hash).map_err(|e|MigrationError::Invalid(e.to_string()))?;
               legacy.execute("INSERT INTO migration_failures VALUES(?1,?2,?3)",params![copy,item.get("verified_time_utc_ms").and_then(Value::as_i64).unwrap_or(e.time_utc_ms as i64),hash.as_bytes().as_slice()])?;
             }
           }
           if matches!(kind,"content_observed"|"annex_entry_observed") {
             if let (Some(file),Some(hash))=(item.get("file_ref_id").and_then(Value::as_str),item.get("blake3_hex").and_then(Value::as_str)){
               // Only checksum-backed observations establish an expectation.
               if kind=="annex_entry_observed" && item.get("verification_result").and_then(Value::as_str)!=Some("ok"){continue;}
               let hash=blake3::Hash::from_hex(hash).map_err(|e|MigrationError::Invalid(e.to_string()))?;
               legacy.execute("INSERT INTO migration_expectations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![file,hash.as_bytes().as_slice(),item.get("size_bytes").and_then(Value::as_i64).or_else(||item.get("observed_size_bytes").and_then(Value::as_i64)),item.get("accepted_change").and_then(Value::as_bool).unwrap_or(false),e.origin_id,e.origin_seq as i64,e.payload["first_item_index"].as_u64().unwrap_or(0) as i64+offset as i64,record.causal_frontier_hash,item.get("observed_time_utc_ms").and_then(Value::as_i64).unwrap_or(e.time_utc_ms as i64),item.get("copy_claim_id").and_then(Value::as_str)])?;
             }
           }
         }
       }
     }
     Ok(())
   })();
   if let Err(error)=action {callback_error=Some(error);return Err(V2StoreError::Invalid("migration callback failed".into()));}
   Ok(())
 });
    if let Some(error) = callback_error {
        return Err(error);
    }
    let verified = verified?;
    // Release any exclusive lock acquired by scratch-table cache spills before
    // the validator opens its reader. This snapshot has no external writers.
    legacy.execute_batch("COMMIT")?;
    projection.validate_frontier(&verified).map_err(|error| {
        MigrationError::Invalid(format!(
            "existing SQLite projection is not current: {error}; run archive db apply on the original Archive and retry migration"
        ))
    })?;
    legacy.execute_batch("BEGIN IMMEDIATE")?;
    let report = V2VerificationReport {
        version: 2,
        archive_id: archive_id.clone(),
        genesis_hash: verified.genesis_hash.clone(),
        accepted_frontier_hash: verified.accepted_frontier_hash.clone(),
        origins: verified.accepted_frontier.origins.len() as u64,
        records: verified.record_count,
        segments: verified.segment_count,
        frontiers: verified.frontier_count,
    };
    if !store.unpublished_append_paths(&report)?.is_empty() {
        return Err(MigrationError::Invalid(
            "unpublished canonical append artifacts remain".into(),
        ));
    }
    tx.execute("INSERT INTO history(time_utc_ms,kind,details_json) VALUES(0,'legacy_provenance',?1)",[json!({"genesis":verified.genesis,"genesis_hash":verified.genesis_hash,"accepted_frontier":verified.accepted_frontier,"accepted_frontier_hash":verified.accepted_frontier_hash,"original_events":events,"original_database":legacy_db}).to_string()])?;
    let objects = copy_objects(&legacy, &tx, &verified)?;
    let files = copy_files(&legacy, &tx, &verified)?;
    let checks = copy_checks(&legacy, &tx)?;
    tx.execute("UPDATE catalog_metadata SET revision=1", [])?;
    tx.commit()?;
    legacy.execute_batch("COMMIT")?;
    let backup = stage.0.join("migration-backup.db");
    crate::sqlite_backup::backup_catalog(&catalog, &backup)?;
    let restored = stage.0.join("restore-check.db");
    crate::sqlite_backup::restore_catalog(&backup, &restored)?;
    let restore = SqliteCatalog::open_read_only(&restored)?;
    compare_catalogs(catalog.connection(), restore.connection())?;
    drop(restore);
    drop(catalog);
    drop(legacy);
    drop(original);
    fs::remove_file(restored)?;
    fs::remove_file(snapshot)?;
    File::open(&path)?.sync_all()?;
    crate::safe_copy::place_directory_no_replace(&stage.0, destination)?;
    Ok(MigrationReport {
        archive_id,
        destination: destination.to_path_buf(),
        objects,
        files,
        checks,
        legacy_records: verified.record_count,
        backup: destination.join("migration-backup.db"),
    })
}

fn copy_registry(source: &Connection, target: &Connection) -> Result<()> {
    for table in [
        "sites",
        "policies",
        "collections",
        "devices",
        "device_site_history",
        "archive_roots",
        "locations",
        "device_mounts",
        "risk_domains",
        "entity_risk_domains",
    ] {
        let columns = target
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let fields = columns.join(",");
        let mut read = source.prepare(&format!("SELECT {fields} FROM {table}"))?;
        let mut write = target.prepare(&format!(
            "INSERT INTO {table}({fields}) VALUES({})",
            vec!["?"; columns.len()].join(",")
        ))?;
        let mut rows = read.query([])?;
        while let Some(row) = rows.next()? {
            let values = (0..columns.len())
                .map(|i| row.get::<_, SqlValue>(i))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            write.execute(rusqlite::params_from_iter(values))?;
        }
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
struct Expectation {
    hash: Vec<u8>,
    size: Option<i64>,
    accepted: bool,
    origin: String,
    seq: u64,
    item: i64,
    frontier: String,
    time: i64,
}
fn precedes(a: &Expectation, b: &Expectation, v: &VerifiedV2Archive) -> bool {
    if a.origin == b.origin {
        return (a.seq, a.item) < (b.seq, b.item);
    }
    v.frontiers.get(&b.frontier).is_some_and(|f| {
        f.origins
            .iter()
            .any(|o| o.origin_id == a.origin && o.seq >= a.seq)
    })
}
fn expected_for(
    source: &Connection,
    file: &str,
    v: &VerifiedV2Archive,
) -> Result<Option<Expectation>> {
    let mut stmt=source.prepare("SELECT hash,size,accepted,origin,seq,item,frontier,time FROM migration_expectations WHERE file=?1 ORDER BY origin,seq,item")?;
    let mut pending = stmt
        .query_map([file], |r| {
            Ok(Expectation {
                hash: r.get(0)?,
                size: r.get(1)?,
                accepted: r.get(2)?,
                origin: r.get(3)?,
                seq: r.get::<_, i64>(4)? as u64,
                item: r.get(5)?,
                frontier: r.get(6)?,
                time: r.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if pending.is_empty() {
        // Annex metadata aliases may inherit an already authenticated source
        // identity without reading the same physical content once per alias.
        let mut shared=source.prepare("SELECT e.hash,e.size,e.accepted,e.origin,e.seq,e.item,e.frontier,e.time FROM migration_expectations e JOIN file_objects f ON f.canonical_id=e.file JOIN file_objects wanted ON wanted.external_id=f.external_id WHERE wanted.canonical_id=?1")?;
        pending = shared
            .query_map([file], |r| {
                Ok(Expectation {
                    hash: r.get(0)?,
                    size: r.get(1)?,
                    accepted: r.get(2)?,
                    origin: r.get(3)?,
                    seq: r.get::<_, i64>(4)? as u64,
                    item: r.get(5)?,
                    frontier: r.get(6)?,
                    time: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if pending.iter().any(|e| e.accepted) {
            return Err(MigrationError::Invalid(format!(
                "cannot infer accepted change through another annex alias for {file}"
            )));
        }
    }
    let mut applied: Vec<Expectation> = Vec::new();
    while !pending.is_empty() {
        let index = (0..pending.len())
            .find(|&i| {
                !pending
                    .iter()
                    .enumerate()
                    .any(|(j, a)| i != j && precedes(a, &pending[i], v))
            })
            .ok_or_else(|| {
                MigrationError::Invalid(format!("cyclic expectation history for {file}"))
            })?;
        let next = pending.remove(index);
        for previous in &applied {
            if previous.hash != next.hash
                && (!precedes(previous, &next, v)
                    || !applied.iter().chain(std::iter::once(&next)).any(|accept| {
                        accept.accepted
                            && accept.hash == next.hash
                            && precedes(previous, accept, v)
                            && (precedes(accept, &next, v)
                                || (accept.origin == next.origin
                                    && accept.seq == next.seq
                                    && accept.item == next.item))
                    }))
            {
                return Err(MigrationError::Invalid(format!("conflicting checksums for {file}; changed identity lacks an explicit causal accepted_change")));
            }
        }
        // A same-hash observation after an accepted change must not invalidate the
        // accept marker used to reject older copy evidence.
        applied.push(next);
    }
    let Some(result) = applied.last().cloned() else {
        return Ok(None);
    };
    let accepted = applied.iter().rev().find(|e| e.accepted);
    source.execute(
        "INSERT INTO migration_accepted VALUES(?1,?2)",
        params![file, accepted.map(serde_json::to_string).transpose()?],
    )?;
    Ok(Some(result))
}
fn copy_objects(source: &Connection, target: &Connection, v: &VerifiedV2Archive) -> Result<u64> {
    source
        .execute_batch("CREATE TABLE migration_accepted(file TEXT PRIMARY KEY,evidence TEXT);")?;
    let mut stmt=source.prepare("SELECT f.canonical_id,c.collection_id,f.path_encoding,f.path_bytes,COALESCE(f.path_display,CAST(f.path_bytes AS TEXT)),o.digest,o.size_bytes,f.identity_state,f.active FROM file_objects f JOIN collections c ON c.id=f.collection_id LEFT JOIN content_objects o ON o.id=f.content_id ORDER BY f.id")?;
    let mut rows = stmt.query([])?;
    let mut n = 0;
    while let Some(row) = rows.next()? {
        let file: String = row.get(0)?;
        let projected: Option<Vec<u8>> = row.get(5)?;
        if row.get::<_, String>(7)? == "conflict" {
            return Err(MigrationError::Invalid(format!(
                "unresolved identity conflict for {file}"
            )));
        }
        let expected = expected_for(source, &file, v)?;
        if expected.as_ref().map(|e| &e.hash) != projected.as_ref() {
            return Err(MigrationError::Invalid(format!(
                "cannot authenticate expected checksum for {file}"
            )));
        }
        let hash = expected.as_ref().map(|e| &e.hash);
        let size = expected
            .as_ref()
            .and_then(|e| e.size)
            .or(row.get::<_, Option<i64>>(6)?);
        target.execute("INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3,expected_size_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![file,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,String>(4)?,hash,size])?;
        target.execute("INSERT INTO history(object_id,time_utc_ms,kind,details_json) VALUES(?1,0,'legacy_object_mapping',?2)",params![file,json!({"file_ref_id":file,"active":row.get::<_,bool>(8)?,"identity_state":row.get::<_,String>(7)?}).to_string()])?;
        n += 1;
    }
    Ok(n)
}
fn copy_files(
    source: &Connection,
    target: &Connection,
    verified_archive: &VerifiedV2Archive,
) -> Result<u64> {
    // Match the exact attached copy, never another copy with equal content.
    let sql="SELECT f.canonical_id,l.location_id,p.representation,f.path_encoding,f.path_bytes,COALESCE(b.locator_encoding,owner.path_encoding),COALESCE(b.locator_bytes,owner.path_bytes),b.canonical_id,b.state,p.presence,pc.presence,pc.checked_at,ic.integrity,ic.checked_at,e.code,c.digest,a.evidence,p.id,b.location_id=p.location_id FROM file_locations p JOIN file_objects f ON f.id=p.file_id JOIN locations l ON l.id=p.location_id LEFT JOIN copy_bindings b ON b.id=p.copy_id LEFT JOIN file_locations op ON op.id=b.owner LEFT JOIN file_objects owner ON owner.id=op.file_id LEFT JOIN checks pc ON pc.id=COALESCE(b.latest_presence,p.latest_presence) LEFT JOIN checks ic ON ic.id=b.latest_integrity LEFT JOIN check_errors e ON e.check_id=ic.id LEFT JOIN content_objects c ON c.id=b.content_id LEFT JOIN migration_accepted a ON a.file=f.canonical_id ORDER BY p.id";
    let mut stmt = source.prepare(sql)?;
    let mut rows = stmt.query([])?;
    let mut n = 0;
    while let Some(row) = rows.next()? {
        let file: String = row.get(0)?;
        let location: String = row.get(1)?;
        let representation: String = row.get(2)?;
        let copy: Option<String> = row.get(7)?;
        let copy_state: Option<String> = row.get(8)?;
        if copy_state.as_deref() == Some("superseded") {
            return Err(MigrationError::Invalid(format!("superseded copy binding for {file} at {location}; reconcile the physical path before migration")));
        }
        if row.get::<_, Option<bool>>(18)? == Some(false) {
            return Err(MigrationError::Invalid(format!(
                "copy binding for {file} belongs to a different Location than {location}"
            )));
        }

        if representation == "annex_content" {
            return Err(MigrationError::Invalid(format!(
                "CAS-only binding for {file} at {location}; no mirror logical path"
            )));
        }
        if copy.is_some()
            && representation != "annex_locked_symlink"
            && (row.get::<_, Option<String>>(5)?.as_ref() != Some(&row.get::<_, String>(3)?)
                || row.get::<_, Option<Vec<u8>>>(6)?.as_ref() != Some(&row.get::<_, Vec<u8>>(4)?))
        {
            return Err(MigrationError::Invalid(format!(
                "alternate physical path for {file} at {location} violates mirror paths"
            )));
        }
        let p: Option<i64> = row.get(10)?;
        let pt: Option<i64> = row.get(11)?;
        let integrity: Option<i64> = row.get(12)?;
        let it: Option<i64> = row.get(13)?;
        let error: Option<String> = row.get(14)?;
        let presence = if row.get::<_, i64>(9)? == 0 || copy_state.as_deref() == Some("missing") {
            "missing"
        } else if copy_state.as_deref() == Some("unknown") {
            "unknown"
        } else {
            match p {
                Some(1) => "present",
                Some(0) => "missing",
                _ => {
                    if row.get::<_, i64>(9)? == 1 && copy.is_none() {
                        "present"
                    } else {
                        "unknown"
                    }
                }
            }
        };
        let expected: Option<Vec<u8>> = target.query_row(
            "SELECT expected_blake3 FROM objects WHERE object_id=?1",
            [&file],
            |r| r.get(0),
        )?;
        let observed: Option<Vec<u8>> = row.get(15)?;
        let accepted: Option<Expectation> = row
            .get::<_, Option<String>>(16)?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let mut successes = Vec::new();
        if let Some(copy) = &copy {
            let mut statement=source.prepare("SELECT hash,size,accepted,origin,seq,item,frontier,time FROM migration_expectations WHERE copy=?1")?;
            successes = statement
                .query_map([copy], |r| {
                    Ok(Expectation {
                        hash: r.get(0)?,
                        size: r.get(1)?,
                        accepted: r.get(2)?,
                        origin: r.get(3)?,
                        seq: r.get::<_, i64>(4)? as u64,
                        item: r.get(5)?,
                        frontier: r.get(6)?,
                        time: r.get(7)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
        }
        let after_accept = |e: &Expectation| {
            accepted.as_ref().is_none_or(|a| {
                precedes(a, e, verified_archive)
                    || (a.origin == e.origin && a.seq == e.seq && a.item == e.item)
            })
        };
        let check_events = successes
            .iter()
            .filter(|e| Some(e.time) == it)
            .collect::<Vec<_>>();
        let verified = copy_state.as_deref() == Some("present")
            && integrity == Some(1)
            && error.is_none()
            && expected.is_some()
            && expected == observed
            && (accepted.is_none()
                || (!check_events.is_empty() && check_events.iter().all(|e| after_accept(e))));
        if (copy_state.as_deref() == Some("present") && integrity == Some(2))
            || (copy_state.as_deref() == Some("corrupt") && integrity != Some(2))
        {
            return Err(MigrationError::Invalid(format!(
                "copy state and integrity evidence disagree for {file} at {location}"
            )));
        }
        let damaged = copy_state.as_deref() == Some("corrupt") && integrity == Some(2);
        let last_success = successes
            .iter()
            .filter(|e| after_accept(e) && expected.as_ref() == Some(&e.hash))
            .map(|e| e.time)
            .max();
        let state = if damaged {
            "damaged"
        } else if verified {
            "verified"
        } else {
            "unverified"
        };
        let (latest, result) =
            if presence == "missing" && pt.is_some_and(|p| it.is_none_or(|i| p >= i)) {
                (pt, Some("missing"))
            } else if error.is_some() {
                (
                    it,
                    Some(if integrity == Some(2) {
                        "mismatch"
                    } else {
                        "read_error"
                    }),
                )
            } else if integrity == Some(2) {
                (it, Some("mismatch"))
            } else if integrity == Some(1) {
                (it, Some("ok"))
            } else {
                (None, None)
            };
        let observed = if integrity == Some(1) {
            observed
        } else if damaged {
            let mut statement = source.prepare(
                "SELECT DISTINCT hash FROM migration_failures WHERE copy=?1 AND time=?2",
            )?;
            let hashes = statement
                .query_map(params![copy, it], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if hashes.len() > 1 {
                return Err(MigrationError::Invalid(format!(
                    "ambiguous mismatch checksum for {file} at {location}"
                )));
            }
            hashes.into_iter().next()
        } else {
            None
        };
        target.execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![file,location,presence,state,latest,result,observed,last_success.or(if verified{it}else{None})])?;
        target.execute("INSERT INTO history(object_id,location_id,time_utc_ms,kind,details_json) VALUES(?1,?2,0,'legacy_file_mapping',?3)",params![file,location,json!({"file_location_id":row.get::<_,i64>(17)?,"copy_claim_id":copy,"copy_state":row.get::<_,Option<String>>(8)?,"representation":representation}).to_string()])?;
        n += 1;
    }
    Ok(n)
}
fn copy_checks(source: &Connection, target: &Connection) -> Result<u64> {
    let mut stmt=source.prepare("SELECT f.canonical_id,l.location_id,c.id,c.checked_at,c.presence,c.integrity,e.code,e.detail FROM checks c JOIN file_locations p ON p.id=c.file_location_id JOIN file_objects f ON f.id=p.file_id JOIN locations l ON l.id=p.location_id LEFT JOIN check_errors e ON e.check_id=c.id ORDER BY c.id")?;
    let mut rows = stmt.query([])?;
    let mut n = 0;
    while let Some(r) = rows.next()? {
        let result = if r.get::<_, i64>(5)? == 2 {
            Some("mismatch")
        } else if r.get::<_, Option<String>>(6)?.is_some() {
            Some("read_error")
        } else if r.get::<_, i64>(5)? == 1 {
            Some("ok")
        } else if r.get::<_, i64>(4)? == 0 {
            Some("missing")
        } else {
            None
        };
        target.execute("INSERT INTO history(object_id,location_id,time_utc_ms,kind,check_result,details_json) VALUES(?1,?2,?3,'legacy_check',?4,?5)",params![r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(3)?,result,json!({"legacy_check_id":r.get::<_,i64>(2)?,"presence":r.get::<_,i64>(4)?,"integrity":r.get::<_,i64>(5)?,"error_code":r.get::<_,Option<String>>(6)?,"error_detail":r.get::<_,Option<String>>(7)?}).to_string()])?;
        n += 1;
    }
    Ok(n)
}
fn compare_catalogs(a: &Connection, b: &Connection) -> Result<()> {
    let tables=a.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        let digest = |connection: &Connection| -> Result<blake3::Hash> {
            let mut stmt =
                connection.prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))?;
            let columns = stmt.column_count();
            let mut rows = stmt.query([])?;
            let mut hash = blake3::Hasher::new();
            while let Some(row) = rows.next()? {
                for i in 0..columns {
                    let value = row.get::<_, SqlValue>(i)?;
                    let bytes = format!("{value:?}");
                    hash.update(&(bytes.len() as u64).to_le_bytes());
                    hash.update(bytes.as_bytes());
                }
            }
            Ok(hash.finalize())
        };
        if digest(a)? != digest(b)? {
            return Err(MigrationError::Invalid(format!(
                "restore verification differs in {table}"
            )));
        }
    }
    Ok(())
}
struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::*;
    fn fixture() -> (tempfile::TempDir, V2OriginStore, V2ProjectionDb) {
        let temp = tempfile::TempDir::new().unwrap();
        let archive = temp.path().join("legacy");
        crate::v2_store::initialize_v2_archive(&archive, "arc_fixture", "Files", 1_782_000_000_000)
            .unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        V2ProjectionDb::create_from_store(&store, archive.join("archive.db")).unwrap();
        let db = V2ProjectionDb::open_existing(archive.join("archive.db")).unwrap();
        let registry = V2Registry::new(&store, &db);
        registry
            .record(
                RegistryChange::Site(
                    RegistryAction::Register,
                    SiteSnapshot {
                        site_id: "site".into(),
                        display_name: "Home".into(),
                        site_kind: "home".into(),
                        description: None,
                        status: "active".into(),
                    },
                ),
                "host",
            )
            .unwrap();
        registry
            .record(
                RegistryChange::Collection(
                    RegistryAction::Register,
                    CollectionSnapshot {
                        collection_id: "collection".into(),
                        display_name: "Files".into(),
                        description: None,
                        home_site_id: Some("site".into()),
                        policy_id: None,
                        status: "active".into(),
                    },
                ),
                "host",
            )
            .unwrap();
        for id in ["location", "other"] {
            registry
                .record(
                    RegistryChange::Location(
                        RegistryAction::Register,
                        LocationSnapshot {
                            location_id: id.into(),
                            display_name: id.into(),
                            kind: "service".into(),
                            archive_root_id: None,
                            relative_path: None,
                            device_id: None,
                            site_id: Some("site".into()),
                            encryption_state: Some("unknown".into()),
                            trust_level: Some("trusted".into()),
                            expected_availability: "online".into(),
                            is_writable: true,
                            status: "active".into(),
                        },
                    ),
                    "host",
                )
                .unwrap();
        }
        (temp, store, db)
    }
    fn content(hash: &str, copy: &str, time: u64, accepted: bool) -> Value {
        json!({"kind":"content_observed","collection_id":"collection","location_id":"location","file_ref_id":"file","logical_path":RegistryPath::utf8("file"),"copy_path":RegistryPath::utf8("file"),"copy_claim_id":copy,"object_id":format!("blake3:{hash}"),"blake3_hex":hash,"size_bytes":4,"observed_time_utc_ms":time,"representation":"ordinary_file","device_fingerprint_status":"unavailable","accepted_change":accepted})
    }
    fn append(store: &V2OriginStore, db: &V2ProjectionDb, item: Value) {
        store
            .append_batch("migration_fixture", 1, json!({}), json!({}), vec![item])
            .unwrap();
        db.apply(store).unwrap();
    }
    fn original_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    dirs.push(entry.path());
                } else if entry.file_type().unwrap().is_file() {
                    files.insert(
                        entry.path().strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        files
    }
    #[test]
    fn migrates_expected_identity_damage_checks_and_restored_equivalence_without_source_changes() {
        let (temp, store, db) = fixture();
        let hash = "11".repeat(32);
        append(&store, &db, content(&hash, "copy", 10, false));
        append(
            &store,
            &db,
            json!({"kind":"copy_verification_failed","copy_claim_id":"copy","location_id":"location","result":"hash_mismatch","verified_time_utc_ms":20,"error_detail":"different bytes"}),
        );
        let before = original_bytes(store.root().parent().unwrap());
        let destination = temp.path().join("converted");
        let report = migrate_catalog(store.root(), db.path(), &destination).unwrap();
        assert_eq!((report.objects, report.files), (1, 1));
        assert_eq!(before, original_bytes(store.root().parent().unwrap()));
        let catalog = SqliteCatalog::open_read_only(destination.join("archive.db")).unwrap();
        let evidence: (String, String, Option<i64>) = catalog
            .connection()
            .query_row(
                "SELECT integrity,last_check_result,last_success_time_utc_ms FROM files",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(evidence, ("damaged".into(), "mismatch".into(), Some(10)));
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM history WHERE kind='legacy_record'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            report.legacy_records as i64
        );
        let recovered =
            SqliteCatalog::open_read_only(destination.join("migration-backup.db")).unwrap();
        compare_catalogs(catalog.connection(), recovered.connection()).unwrap();
        append(&store, &db, content(&hash, "copy", 30, false));
        let verified_path = temp.path().join("verified_again");
        migrate_catalog(store.root(), db.path(), &verified_path).unwrap();
        let verified = SqliteCatalog::open_read_only(verified_path.join("archive.db")).unwrap();
        assert_eq!(
            verified
                .connection()
                .query_row(
                    "SELECT integrity,last_success_time_utc_ms FROM files",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                )
                .unwrap(),
            ("verified".into(), 30)
        );
    }
    #[test]
    fn refuses_unaccepted_change_but_accepts_explicit_change_then_normal_verification() {
        let (temp, store, db) = fixture();
        let old = "11".repeat(32);
        let new = "22".repeat(32);
        append(&store, &db, content(&old, "copy_old", 100, false));
        append(&store, &db, content(&new, "copy_new", 50, true));
        append(&store, &db, content(&new, "copy_new", 51, false));
        let destination = temp.path().join("accepted");
        migrate_catalog(store.root(), db.path(), &destination).unwrap();
        let catalog = SqliteCatalog::open_read_only(destination.join("archive.db")).unwrap();
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT integrity FROM files", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "verified"
        );
        append(&store, &db, content(&old, "copy_reverted", 101, false));
        let before = original_bytes(store.root().parent().unwrap());
        let refused = temp.path().join("refused");
        assert!(migrate_catalog(store.root(), db.path(), &refused)
            .unwrap_err()
            .to_string()
            .contains("explicit causal accepted_change"));
        assert!(!refused.exists());
        assert_eq!(before, original_bytes(store.root().parent().unwrap()));
    }
    fn annex(file: &str, present: bool) -> Value {
        let hash = "33".repeat(32);
        json!({"kind":"annex_entry_observed","collection_id":"collection","file_ref_id":file,"logical_path":RegistryPath::utf8(file),"external_identity_id":"external","external_key":"SHA256-key","expected_hash_algo":"sha256","expected_hash_hex":hash,"expected_size_bytes":4,"observed_size_bytes":4,"resolution_state":if present{"resolved"}else{"unresolved"},"worktree_location_id":"location","cas_location_id":"location","source_repo_id":"repo","representation":"annex_locked_symlink","path_state":"present","local_availability":if present{"present"}else{"unknown"},"object_id":present.then(||format!("blake3:{hash}")),"blake3_hex":present.then_some(&hash),"sha256_hex":present.then_some(&hash),"claim_basis":if present{"observed_bytes"}else{"source_metadata"},"copy_claim_id":"annex_copy","copy_location_id":"location","copy_path":RegistryPath::utf8(".git/annex/objects/key"),"copy_state":if present{"present"}else{"unknown"},"verification_result":present.then_some("ok")})
    }
    #[test]
    fn preserves_annex_aliases_and_unresolved_paths_but_rejects_cas_only_locations() {
        let (temp, store, db) = fixture();
        append(&store, &db, annex("alias_a", true));
        append(&store, &db, annex("alias_b", true));
        let mut missing_alias = annex("alias_a", true);
        missing_alias["path_state"] = json!("missing");
        append(&store, &db, missing_alias);
        let mut unresolved = annex("unknown", false);
        unresolved["external_identity_id"] = json!("unknown_external");
        unresolved["external_key"] = json!("other-key");
        unresolved["copy_claim_id"] = json!("unknown_copy");
        unresolved["copy_path"] = json!(RegistryPath::utf8(".git/annex/objects/unknown"));
        append(&store, &db, unresolved);
        let destination = temp.path().join("aliases");
        let result = migrate_catalog(store.root(), db.path(), &destination).unwrap();
        assert_eq!(result.objects, 3);
        let catalog = SqliteCatalog::open_read_only(destination.join("archive.db")).unwrap();
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM files WHERE integrity='verified'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE expected_blake3 IS NULL",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT last_check_result FROM files WHERE object_id='unknown'",
                    [],
                    |r| r.get::<_, Option<String>>(0)
                )
                .unwrap(),
            None
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT presence FROM files WHERE object_id='alias_a'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "missing"
        );
        let mut cas = annex("cas_alias", true);
        cas["cas_location_id"] = json!("other");
        cas["copy_location_id"] = json!("other");
        cas["copy_claim_id"] = json!("cas_copy");
        append(&store, &db, cas);
        assert!(
            migrate_catalog(store.root(), db.path(), &temp.path().join("refused"))
                .unwrap_err()
                .to_string()
                // The worktree binding is visited before its CAS-only row;
                // its exact copy already proves the incompatible Location.
                .contains("belongs to a different Location")
        );
    }
    #[test]
    fn refuses_unfinished_local_work_without_publishing_or_touching_source() {
        let (temp, store, db) = fixture();
        let archive = store.root().parent().unwrap();
        let jobs = archive.join("local/jobs/job_interrupted");
        fs::create_dir_all(&jobs).unwrap();
        let before = original_bytes(archive);
        let destination = temp.path().join("refused");
        assert!(migrate_catalog(store.root(), db.path(), &destination)
            .unwrap_err()
            .to_string()
            .contains("unfinished local job"));
        assert!(!destination.exists());
        assert_eq!(before, original_bytes(archive));
    }
    #[test]
    fn refuses_superseded_binding_across_collections_at_the_same_physical_path() {
        let (temp, store, db) = fixture();
        append(
            &store,
            &db,
            content(&"11".repeat(32), "original_copy", 10, false),
        );
        V2Registry::new(&store, &db)
            .record(
                RegistryChange::Collection(
                    RegistryAction::Register,
                    CollectionSnapshot {
                        collection_id: "second_collection".into(),
                        display_name: "Other Files".into(),
                        description: None,
                        home_site_id: Some("site".into()),
                        policy_id: None,
                        status: "active".into(),
                    },
                ),
                "host",
            )
            .unwrap();
        let mut replacement = content(&"22".repeat(32), "replacement_copy", 20, false);
        replacement["collection_id"] = json!("second_collection");
        replacement["file_ref_id"] = json!("replacement_file");
        append(&store, &db, replacement);
        let source =
            Connection::open_with_flags(db.path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        assert_eq!(
            source
                .query_row(
                    "SELECT state FROM copy_bindings WHERE canonical_id='original_copy'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "superseded"
        );
        drop(source);
        let before = original_bytes(store.root().parent().unwrap());
        let destination = temp.path().join("refused");
        let error = migrate_catalog(store.root(), db.path(), &destination).unwrap_err();
        assert!(error
            .to_string()
            .contains("superseded copy binding for file at location"));
        assert!(!destination.exists());
        assert_eq!(before, original_bytes(store.root().parent().unwrap()));
    }
}
