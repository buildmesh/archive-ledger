//! Direct catalog transactions. Filesystem discovery supplies observations; it never
//! manufactures canonical events or treats a changed checksum as a new identity.
use crate::{RegistryPath, SqliteCatalog};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CatalogWriteError {
    #[error("catalog write failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid catalog write: {0}")]
    Invalid(String),
    #[error("catalog write JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, CatalogWriteError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObservationResult {
    MetadataPresent,
    MetadataUnknown,
    RejectedChecksum { blake3: [u8; 32] },
    Checksum { blake3: [u8; 32], size_bytes: u64 },
    ReadError,
    Missing,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogObservation {
    pub collection_id: String,
    pub location_id: String,
    pub path: RegistryPath,
    pub time_utc_ms: u64,
    pub result: ObservationResult,
    pub accept_change: bool,
    pub operation_key: Option<String>,
    pub job_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationOutcome {
    pub object_id: String,
    pub result: String,
    pub established_identity: bool,
    pub accepted_change: bool,
}

impl SqliteCatalog {
    pub fn observe(&mut self, observation: &CatalogObservation) -> Result<ObservationOutcome> {
        Ok(self
            .observe_batch(std::slice::from_ref(observation))?
            .remove(0))
    }

    /// Every observation, history row, coverage marker and deduplication outcome
    /// in the batch commits together, or none does.
    pub fn observe_batch(
        &mut self,
        observations: &[CatalogObservation],
    ) -> Result<Vec<ObservationOutcome>> {
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut outcomes = Vec::with_capacity(observations.len());
        let mut changed = false;
        for observation in observations {
            let request = serde_json::to_string(observation)?;
            if let Some(key) = &observation.operation_key {
                let previous: Option<(String,String)> = tx.query_row(
                    "SELECT request_json,outcome_json FROM catalog_write_operations WHERE operation_key=?1", [key],
                    |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
                if let Some((previous, outcome)) = previous {
                    if previous != request {
                        return Err(CatalogWriteError::Invalid(
                            "operation key reused for different immutable inputs".into(),
                        ));
                    }
                    let outcome: ObservationOutcome = serde_json::from_str(&outcome)?;
                    if let Some(job) = &observation.job_id {
                        require_observation_job(&tx, observation)?;
                        tx.execute("INSERT OR IGNORE INTO catalog_scan_seen(job_id,object_id) VALUES (?1,?2)",params![job,outcome.object_id])?;
                    }
                    outcomes.push(outcome);
                    continue;
                }
            }
            let outcome = observe_in_transaction(&tx, observation)?;
            if let Some(key) = &observation.operation_key {
                tx.execute(
                    "INSERT INTO catalog_write_operations VALUES (?1,?2,?3)",
                    params![key, request, serde_json::to_string(&outcome)?],
                )?;
            }
            outcomes.push(outcome);
            changed = true;
        }
        if changed {
            revision(&tx)?;
        }
        tx.commit()?;
        Ok(outcomes)
    }

    pub fn begin_catalog_job(
        &mut self,
        id: &str,
        kind: &str,
        parameters: &serde_json::Value,
        time: u64,
    ) -> Result<String> {
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let serialized = serde_json::to_string(parameters)?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT kind,params_json,status FROM catalog_jobs WHERE job_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((old_kind, old_params, status)) = existing {
            if old_kind != kind || old_params != serialized {
                return Err(CatalogWriteError::Invalid(format!(
                    "job {id} belongs to different immutable inputs"
                )));
            }
            return Ok(status);
        }
        tx.execute("INSERT INTO catalog_jobs(job_id,kind,params_json,status,started_time_utc_ms) VALUES (?1,?2,?3,'running',?4)",params![id,kind,serialized,sql_time(time)?])?;
        tx.execute(
            "INSERT INTO history(time_utc_ms,kind,details_json) VALUES (?1,'job_started',?2)",
            params![
                sql_time(time)?,
                serde_json::json!({"job_id":id,"kind":kind,"params":parameters}).to_string()
            ],
        )?;
        revision(&tx)?;
        tx.commit()?;
        Ok("running".into())
    }

    /// Start a fresh enumeration pass on resume. Previously committed checks stay
    /// valid, but only paths enumerated in this pass can establish full coverage.
    pub fn reset_scan_coverage(&mut self, job_id: &str) -> Result<()> {
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_job(&tx, job_id)?;
        tx.execute("DELETE FROM catalog_scan_seen WHERE job_id=?1", [job_id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn checkpoint_catalog_job(
        &mut self,
        job_id: &str,
        progress: &serde_json::Value,
    ) -> Result<()> {
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_job(&tx, job_id)?;
        tx.execute(
            "UPDATE catalog_jobs SET progress_json=?2 WHERE job_id=?1",
            params![job_id, serde_json::to_string(progress)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Finalize one complete clean whole-Location/Collection traversal. Callers
    /// must pass false on partial coverage, exclusions or any traversal failure.
    pub fn finish_catalog_scan(
        &mut self,
        job_id: &str,
        collection_id: &str,
        location_id: &str,
        complete_coverage: bool,
        time: u64,
        summary: &serde_json::Value,
    ) -> Result<usize> {
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_running_job(&tx, job_id)?;
        let parameters: String = tx.query_row(
            "SELECT params_json FROM catalog_jobs WHERE job_id=?1",
            [job_id],
            |r| r.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters)?;
        if parameters["collection_id"].as_str() != Some(collection_id)
            || parameters["location_id"].as_str() != Some(location_id)
        {
            return Err(CatalogWriteError::Invalid(
                "scan finalization scope differs from job inputs".into(),
            ));
        }
        let mut missing = 0;
        if complete_coverage {
            let time = sql_time(time)?;
            let newer: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM files f JOIN objects o ON o.object_id=f.object_id WHERE o.collection_id=?1 AND f.location_id=?2 AND f.last_check_time_utc_ms>?3)",params![collection_id,location_id,time],|r|r.get(0))?;
            if newer {
                return Err(CatalogWriteError::Invalid(
                    "scan finalization predates current checks".into(),
                ));
            }
            tx.execute("INSERT INTO history(object_id,location_id,time_utc_ms,kind,check_result,expected_blake3,details_json)
                SELECT f.object_id,f.location_id,?4,'scan_missing','missing',o.expected_blake3,?5
                FROM files f JOIN objects o ON o.object_id=f.object_id
                WHERE o.collection_id=?1 AND f.location_id=?2 AND f.presence!='missing'
                AND NOT EXISTS(SELECT 1 FROM catalog_scan_seen s WHERE s.job_id=?3 AND s.object_id=f.object_id)",params![collection_id,location_id,job_id,time,serde_json::json!({"job_id":job_id}).to_string()])?;
            missing=tx.execute("UPDATE files SET presence='missing',integrity='unverified',last_check_time_utc_ms=?4,last_check_result='missing',observed_blake3=NULL
                WHERE location_id=?2 AND presence!='missing'
                AND object_id IN (SELECT object_id FROM objects WHERE collection_id=?1)
                AND NOT EXISTS(SELECT 1 FROM catalog_scan_seen s WHERE s.job_id=?3 AND s.object_id=files.object_id)",params![collection_id,location_id,job_id,time])?;
        }
        finish_job(
            &tx,
            job_id,
            if complete_coverage {
                "complete"
            } else {
                "partial"
            },
            time,
            summary,
        )?;
        revision(&tx)?;
        tx.commit()?;
        Ok(missing)
    }

    pub fn finish_catalog_job(
        &mut self,
        job_id: &str,
        status: &str,
        time: u64,
        summary: &serde_json::Value,
    ) -> Result<()> {
        if !matches!(status, "complete" | "partial" | "cancelled") {
            return Err(CatalogWriteError::Invalid(
                "invalid terminal job status".into(),
            ));
        }
        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT status FROM catalog_jobs WHERE job_id=?1",
                [job_id],
                |r| r.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(status) {
            return Ok(());
        }
        require_running_job(&tx, job_id)?;
        finish_job(&tx, job_id, status, time, summary)?;
        revision(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

fn require_observation_job(tx: &Transaction<'_>, observation: &CatalogObservation) -> Result<()> {
    if let Some(job) = &observation.job_id {
        require_running_job(tx, job)?;
        let parameters: String = tx.query_row(
            "SELECT params_json FROM catalog_jobs WHERE job_id=?1",
            [job],
            |r| r.get(0),
        )?;
        let parameters: serde_json::Value = serde_json::from_str(&parameters)?;
        if parameters["collection_id"].as_str() != Some(&observation.collection_id)
            || parameters["location_id"].as_str() != Some(&observation.location_id)
        {
            return Err(CatalogWriteError::Invalid(
                "observation scope differs from job inputs".into(),
            ));
        }
    }
    Ok(())
}

fn require_running_job(tx: &Transaction<'_>, job_id: &str) -> Result<()> {
    let running: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM catalog_jobs WHERE job_id=?1 AND status='running')",
        [job_id],
        |r| r.get(0),
    )?;
    if !running {
        return Err(CatalogWriteError::Invalid(format!(
            "job {job_id} is not running"
        )));
    }
    Ok(())
}
fn finish_job(
    tx: &Transaction<'_>,
    id: &str,
    status: &str,
    time: u64,
    summary: &serde_json::Value,
) -> Result<()> {
    tx.execute("UPDATE catalog_jobs SET status=?2,finished_time_utc_ms=?3,progress_json=?4 WHERE job_id=?1",params![id,status,sql_time(time)?,summary.to_string()])?;
    tx.execute(
        "INSERT INTO history(time_utc_ms,kind,details_json) VALUES (?1,'job_finished',?2)",
        params![
            sql_time(time)?,
            serde_json::json!({"job_id":id,"status":status,"summary":summary}).to_string()
        ],
    )?;
    tx.execute("DELETE FROM catalog_scan_seen WHERE job_id=?1", [id])?;
    tx.execute("DELETE FROM catalog_job_items WHERE job_id=?1", [id])?;
    Ok(())
}
fn revision(tx: &Transaction<'_>) -> Result<()> {
    tx.execute(
        "UPDATE catalog_metadata SET revision=revision+1 WHERE singleton=1",
        [],
    )?;
    Ok(())
}
fn sql_time(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| CatalogWriteError::Invalid("integer exceeds SQLite range".into()))
}

fn observe_in_transaction(
    tx: &Transaction<'_>,
    observation: &CatalogObservation,
) -> Result<ObservationOutcome> {
    let bytes = crate::registry::registry_path_bytes(&observation.path)
        .map_err(|e| CatalogWriteError::Invalid(e.to_string()))?;
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(CatalogWriteError::Invalid(
            "empty or NUL-containing relative path".into(),
        ));
    }
    if observation.path.encoding == "utf8" || observation.path.encoding == "unix_bytes" {
        if bytes.starts_with(b"/")
            || bytes
                .split(|b| *b == b'/')
                .any(|part| part == b".." || part.is_empty() || part == b".")
        {
            return Err(CatalogWriteError::Invalid(
                "path must be a normalized Collection-relative path".into(),
            ));
        }
    } else {
        return Err(CatalogWriteError::Invalid(
            "unsupported relative path encoding".into(),
        ));
    }
    if observation.accept_change
        && !matches!(observation.result, ObservationResult::Checksum { .. })
    {
        return Err(CatalogWriteError::Invalid(
            "accepting a change requires successfully checksummed bytes".into(),
        ));
    }
    let time = sql_time(observation.time_utc_ms)?;
    let scope_active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM collections c,locations l WHERE c.collection_id=?1 AND l.location_id=?2 AND c.status='active' AND l.status='active')",params![observation.collection_id,observation.location_id],|r|r.get(0))?;
    if !scope_active {
        return Err(CatalogWriteError::Invalid(
            "Collection or Location is missing/retired".into(),
        ));
    }
    require_observation_job(tx, observation)?;
    let existing: Option<(String,Option<Vec<u8>>)> = tx.query_row("SELECT object_id,expected_blake3 FROM objects WHERE collection_id=?1 AND relative_path_encoding=?2 AND relative_path_bytes=?3",params![observation.collection_id,observation.path.encoding,bytes],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let (id, mut expected) = existing.unwrap_or_else(|| {
        (
            format!("obj_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()),
            None,
        )
    });
    tx.execute("INSERT OR IGNORE INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES (?1,?2,?3,?4,?5)",params![id,observation.collection_id,observation.path.encoding,bytes,observation.path.display])?;
    let prior_check: Option<i64> = tx
        .query_row(
            "SELECT last_check_time_utc_ms FROM files WHERE object_id=?1 AND location_id=?2",
            params![id, observation.location_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    if prior_check.is_some_and(|prior| prior > time) {
        return Err(CatalogWriteError::Invalid(
            "observation predates the current check".into(),
        ));
    }
    let mut established = false;
    let mut accepted = false;
    if let ObservationResult::Checksum { blake3, size_bytes } = &observation.result {
        if expected.is_none()
            || (observation.accept_change && expected.as_deref() != Some(blake3.as_slice()))
        {
            accepted = expected.is_some();
            established = expected.is_none();
            if accepted {
                tx.execute("UPDATE files SET integrity='unverified',last_success_time_utc_ms=NULL WHERE object_id=?1",[&id])?;
                tx.execute("INSERT INTO history(object_id,location_id,time_utc_ms,kind,expected_blake3,observed_blake3,details_json) VALUES (?1,?2,?3,'expected_checksum_changed',?4,?5,?6)",params![id,observation.location_id,time,expected,blake3.as_slice(),serde_json::json!({"job_id":observation.job_id}).to_string()])?;
            }
            expected = Some(blake3.to_vec());
            tx.execute(
                "UPDATE objects SET expected_blake3=?2,expected_size_bytes=?3 WHERE object_id=?1",
                params![id, blake3.as_slice(), sql_time(*size_bytes)?],
            )?;
        }
    }
    let (presence, integrity, result, observed) = match &observation.result {
        ObservationResult::MetadataPresent => ("present", "unverified", "observed", None),
        ObservationResult::MetadataUnknown => ("unknown", "unverified", "observed", None),
        ObservationResult::RejectedChecksum { blake3 } => {
            ("present", "damaged", "mismatch", Some(blake3.as_slice()))
        }
        ObservationResult::Checksum { blake3, .. }
            if expected.as_deref() == Some(blake3.as_slice()) =>
        {
            ("present", "verified", "ok", Some(blake3.as_slice()))
        }
        ObservationResult::Checksum { blake3, .. } => {
            ("present", "damaged", "mismatch", Some(blake3.as_slice()))
        }
        ObservationResult::ReadError => ("unknown", "unverified", "read_error", None),
        ObservationResult::Missing => ("missing", "unverified", "missing", None),
    };
    if matches!(observation.result, ObservationResult::MetadataUnknown) {
        tx.execute("INSERT OR IGNORE INTO files(object_id,location_id,presence,integrity) VALUES (?1,?2,'unknown','unverified')",params![id,observation.location_id])?;
    } else if matches!(observation.result, ObservationResult::MetadataPresent) {
        tx.execute("INSERT INTO files(object_id,location_id,presence,integrity) VALUES (?1,?2,'present','unverified')
            ON CONFLICT(object_id,location_id) DO UPDATE SET presence='present',integrity=CASE WHEN files.integrity='damaged' THEN 'damaged' WHEN files.presence='present' THEN files.integrity ELSE 'unverified' END",params![id,observation.location_id])?;
    } else {
        tx.execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,CASE WHEN ?6='ok' THEN ?5 END)
            ON CONFLICT(object_id,location_id) DO UPDATE SET presence=excluded.presence,integrity=CASE WHEN ?6='read_error' AND files.integrity='damaged' THEN 'damaged' ELSE excluded.integrity END,last_check_time_utc_ms=excluded.last_check_time_utc_ms,last_check_result=excluded.last_check_result,observed_blake3=excluded.observed_blake3,last_success_time_utc_ms=CASE WHEN ?6='ok' THEN ?5 ELSE files.last_success_time_utc_ms END",params![id,observation.location_id,presence,integrity,time,result,observed])?;
    }
    tx.execute("INSERT INTO history(object_id,location_id,time_utc_ms,kind,check_result,expected_blake3,observed_blake3,details_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![id,observation.location_id,time,if result=="observed" {"presence_observed"} else {"file_checked"},if result=="observed" {None} else {Some(result)},expected,observed,serde_json::json!({"job_id":observation.job_id}).to_string()])?;
    if let Some(job) = &observation.job_id {
        tx.execute(
            "INSERT OR IGNORE INTO catalog_scan_seen(job_id,object_id) VALUES (?1,?2)",
            params![job, id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO catalog_job_items(job_id,object_id) VALUES (?1,?2)",
            params![job, id],
        )?;
    }
    Ok(ObservationOutcome {
        object_id: id,
        result: result.into(),
        established_identity: established,
        accepted_change: accepted,
    })
}

/// Read a regular file through one descriptor and reject replacement or changes
/// during hashing. Annex callers must first resolve their approved content path.
pub fn hash_catalog_file(path: &std::path::Path) -> std::io::Result<([u8; 32], u64)> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let before_path = std::fs::symlink_metadata(path)?;
    if !before_path.is_file() {
        return Err(std::io::Error::other(
            "checksum target is not a regular file",
        ));
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !same_metadata(&before_path, &before) {
        return Err(std::io::Error::other(
            "checksum target changed before reading",
        ));
    }
    let mut hash = blake3::Hasher::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        bytes += read as u64;
    }
    if !same_metadata(&before, &file.metadata()?)
        || !same_metadata(&before, &std::fs::symlink_metadata(path)?)
        || bytes != before.len()
    {
        return Err(std::io::Error::other(
            "checksum target changed while reading",
        ));
    }
    Ok((*hash.finalize().as_bytes(), bytes))
}
fn same_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || !after.is_file()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.ino() != after.ino()
            || before.dev() != after.dev()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, SqliteCatalog) {
        let dir = tempfile::tempdir().unwrap();
        let catalog =
            SqliteCatalog::create(dir.path().join("archive.db"), "archive", "Archive").unwrap();
        catalog.connection().execute_batch("INSERT INTO sites VALUES ('site','Site','home',NULL,'active');
            INSERT INTO collections VALUES ('collection','Files',NULL,NULL,NULL,'active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status)
            VALUES ('primary','Primary','service','site','online','active'),('backup','Backup','service','site','offline','active');").unwrap();
        (dir, catalog)
    }
    fn observation(
        path: &str,
        location: &str,
        time: u64,
        result: ObservationResult,
    ) -> CatalogObservation {
        CatalogObservation {
            collection_id: "collection".into(),
            location_id: location.into(),
            path: RegistryPath::utf8(path),
            time_utc_ms: time,
            result,
            accept_change: false,
            operation_key: None,
            job_id: None,
        }
    }
    fn check(path: &str, location: &str, time: u64, hash: u8) -> CatalogObservation {
        observation(
            path,
            location,
            time,
            ObservationResult::Checksum {
                blake3: [hash; 32],
                size_bytes: 42,
            },
        )
    }
    fn state(catalog: &SqliteCatalog, id: &str, location: &str) -> (String, String, Option<i64>) {
        catalog.connection().query_row("SELECT presence,integrity,last_success_time_utc_ms FROM files WHERE object_id=?1 AND location_id=?2",params![id,location],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
    }
    #[test]
    fn immutable_identity_damage_and_explicit_change_invalidate_backups() {
        let (_dir, mut catalog) = fixture();
        let first = catalog.observe(&check("one", "primary", 1, 1)).unwrap();
        assert!(first.established_identity);
        catalog.observe(&check("one", "backup", 2, 1)).unwrap();
        assert_eq!(
            catalog
                .observe(&check("one", "primary", 3, 2))
                .unwrap()
                .result,
            "mismatch"
        );
        assert_eq!(
            state(&catalog, &first.object_id, "primary"),
            ("present".into(), "damaged".into(), Some(1))
        );
        catalog
            .observe(&observation(
                "one",
                "primary",
                4,
                ObservationResult::MetadataPresent,
            ))
            .unwrap();
        assert_eq!(state(&catalog, &first.object_id, "primary").1, "damaged");
        let expected: Vec<u8> = catalog
            .connection()
            .query_row("SELECT expected_blake3 FROM objects", [], |r| r.get(0))
            .unwrap();
        assert_eq!(expected, vec![1; 32]);
        let mut accepted = check("one", "primary", 5, 2);
        accepted.accept_change = true;
        assert!(catalog.observe(&accepted).unwrap().accepted_change);
        assert_eq!(
            state(&catalog, &first.object_id, "backup"),
            ("present".into(), "unverified".into(), None)
        );
        assert_eq!(
            catalog
                .observe(&check("one", "backup", 6, 1))
                .unwrap()
                .result,
            "mismatch"
        );
        assert_eq!(
            catalog
                .observe(&check("one", "backup", 7, 2))
                .unwrap()
                .result,
            "ok"
        );
        // Equal content at another path remains a distinct logical Object.
        assert_ne!(
            catalog
                .observe(&check("two", "primary", 8, 2))
                .unwrap()
                .object_id,
            first.object_id
        );
    }
    #[test]
    fn unknown_missing_and_read_error_never_gain_verification_from_metadata() {
        let (_dir, mut catalog) = fixture();
        let id = catalog
            .observe(&observation(
                "one",
                "primary",
                1,
                ObservationResult::MetadataPresent,
            ))
            .unwrap()
            .object_id;
        assert_eq!(state(&catalog, &id, "primary").1, "unverified");
        catalog.observe(&check("one", "primary", 2, 1)).unwrap();
        catalog
            .observe(&observation(
                "one",
                "primary",
                3,
                ObservationResult::Missing,
            ))
            .unwrap();
        catalog
            .observe(&observation(
                "one",
                "primary",
                4,
                ObservationResult::MetadataPresent,
            ))
            .unwrap();
        assert_eq!(
            state(&catalog, &id, "primary"),
            ("present".into(), "unverified".into(), Some(2))
        );
        catalog.observe(&check("one", "primary", 5, 1)).unwrap();
        catalog
            .observe(&observation(
                "one",
                "primary",
                6,
                ObservationResult::ReadError,
            ))
            .unwrap();
        catalog
            .observe(&observation(
                "one",
                "primary",
                7,
                ObservationResult::MetadataPresent,
            ))
            .unwrap();
        assert_eq!(state(&catalog, &id, "primary").1, "unverified");
    }
    #[test]
    fn transactions_roll_back_history_state_and_idempotent_outcomes() {
        let (_dir, mut catalog) = fixture();
        let mut valid = check("one", "primary", 1, 1);
        valid.operation_key = Some("once".into());
        let mut invalid = check("two", "missing-location", 2, 2);
        invalid.operation_key = Some("fail".into());
        assert!(catalog.observe_batch(&[valid.clone(), invalid]).is_err());
        for table in ["objects", "files", "history", "catalog_write_operations"] {
            let count: i64 = catalog
                .connection()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
        assert_eq!(catalog.metadata().unwrap().revision, 0);
        let first = catalog.observe(&valid).unwrap();
        let revision = catalog.metadata().unwrap().revision;
        assert_eq!(catalog.observe(&valid).unwrap(), first);
        assert_eq!(catalog.metadata().unwrap().revision, revision);
        valid.time_utc_ms = 2;
        assert!(catalog.observe(&valid).is_err());
    }
    #[test]
    fn interrupted_scans_resume_without_early_absence_and_only_clean_coverage_removes() {
        let (dir, mut catalog) = fixture();
        let first = catalog
            .observe(&check("one", "primary", 1, 1))
            .unwrap()
            .object_id;
        let second = catalog
            .observe(&check("two", "primary", 1, 2))
            .unwrap()
            .object_id;
        let params = serde_json::json!({"collection_id":"collection","location_id":"primary"});
        catalog
            .begin_catalog_job("scan", "scan", &params, 2)
            .unwrap();
        let mut seen = check("one", "primary", 3, 1);
        seen.job_id = Some("scan".into());
        catalog.observe(&seen).unwrap();
        drop(catalog);
        let mut catalog = SqliteCatalog::open(dir.path().join("archive.db")).unwrap();
        assert_eq!(
            catalog
                .begin_catalog_job("scan", "scan", &params, 4)
                .unwrap(),
            "running"
        );
        assert_eq!(state(&catalog, &second, "primary").0, "present");
        // An incomplete traversal cannot infer that the unvisited path vanished.
        assert_eq!(
            catalog
                .finish_catalog_scan(
                    "scan",
                    "collection",
                    "primary",
                    false,
                    5,
                    &serde_json::json!({})
                )
                .unwrap(),
            0
        );
        catalog
            .begin_catalog_job("clean", "scan", &params, 6)
            .unwrap();
        seen.job_id = Some("clean".into());
        seen.time_utc_ms = 7;
        catalog.observe(&seen).unwrap();
        assert_eq!(
            catalog
                .finish_catalog_scan(
                    "clean",
                    "collection",
                    "primary",
                    true,
                    8,
                    &serde_json::json!({})
                )
                .unwrap(),
            1
        );
        assert_eq!(state(&catalog, &first, "primary").0, "present");
        assert_eq!(state(&catalog, &second, "primary").0, "missing");
        assert!(catalog
            .begin_catalog_job("clean", "scan", &serde_json::json!({"changed":true}), 9)
            .is_err());
    }
    #[test]
    fn replayed_operations_restore_scan_coverage_and_scope_mismatch_rolls_back() {
        let (_dir, mut catalog) = fixture();
        let parameters = serde_json::json!({"collection_id":"collection","location_id":"primary"});
        catalog
            .begin_catalog_job("scan", "scan", &parameters, 1)
            .unwrap();
        let mut item = check("one", "primary", 2, 1);
        item.job_id = Some("scan".into());
        item.operation_key = Some("scan-one".into());
        let outcome = catalog.observe(&item).unwrap();
        catalog.reset_scan_coverage("scan").unwrap();
        catalog.observe(&item).unwrap();
        let mut invalid = check("two", "backup", 3, 1);
        invalid.job_id = Some("scan".into());
        assert!(catalog.observe(&invalid).is_err());
        assert_eq!(
            catalog
                .finish_catalog_scan(
                    "scan",
                    "collection",
                    "primary",
                    true,
                    4,
                    &serde_json::json!({})
                )
                .unwrap(),
            0
        );
        assert_eq!(state(&catalog, &outcome.object_id, "primary").0, "present");
        catalog.observe(&check("one", "primary", 5, 2)).unwrap();
        catalog
            .observe(&observation(
                "one",
                "primary",
                6,
                ObservationResult::ReadError,
            ))
            .unwrap();
        catalog
            .observe(&observation(
                "one",
                "primary",
                7,
                ObservationResult::MetadataPresent,
            ))
            .unwrap();
        assert_eq!(state(&catalog, &outcome.object_id, "primary").1, "damaged");
    }
    #[test]
    fn annex_inventory_and_rejected_key_never_establish_expected_identity() {
        let (_dir, mut catalog) = fixture();
        let observed = catalog
            .observe(&observation(
                "annex",
                "primary",
                1,
                ObservationResult::MetadataUnknown,
            ))
            .unwrap();
        assert_eq!(state(&catalog, &observed.object_id, "primary").0, "unknown");
        catalog
            .observe(&observation(
                "annex",
                "primary",
                2,
                ObservationResult::RejectedChecksum { blake3: [9; 32] },
            ))
            .unwrap();
        let expected: Option<Vec<u8>> = catalog
            .connection()
            .query_row(
                "SELECT expected_blake3 FROM objects WHERE object_id=?1",
                [&observed.object_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(expected.is_none());
        assert_eq!(state(&catalog, &observed.object_id, "primary").1, "damaged");
        catalog
            .observe(&observation(
                "annex",
                "primary",
                3,
                ObservationResult::MetadataUnknown,
            ))
            .unwrap();
        assert_eq!(state(&catalog, &observed.object_id, "primary").1, "damaged");
        let accepted = catalog.observe(&check("annex", "primary", 4, 1)).unwrap();
        assert!(accepted.established_identity);
        assert_eq!(
            state(&catalog, &observed.object_id, "primary").1,
            "verified"
        );
    }
}
