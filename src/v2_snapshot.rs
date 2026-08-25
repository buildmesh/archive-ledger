//! Portable, signed SQLite projection snapshots.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use ulid::Ulid;

use crate::genesis::V2_SCHEMA_VERSION;
use crate::safe_copy::place_directory_no_replace;
use crate::v2_projection::{Result, V2ProjectionDb, V2ProjectionError};
use crate::v2_store::{
    PortableSnapshotManifestBody, SignedPortableSnapshotManifest, V2OriginStore,
};

pub const SNAPSHOT_DATABASE_FILE: &str = "archive.db";
pub const SNAPSHOT_MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2PortableSnapshot {
    pub version: u32,
    pub directory: PathBuf,
    pub archive_id: String,
    pub canonical_git_commit: String,
    pub accepted_frontier_hash: String,
    pub database_blake3: String,
    pub database_bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2SnapshotInstall {
    pub version: u32,
    pub archive_id: String,
    pub snapshot_frontier_hash: String,
    pub final_frontier_hash: String,
    pub records_applied: u64,
}

pub fn create_portable_snapshot(
    database: &V2ProjectionDb,
    store: &V2OriginStore,
    output: impl AsRef<Path>,
) -> Result<V2PortableSnapshot> {
    database.validate_against_store(store)?;
    let output = output.as_ref();
    if output.exists() {
        return Err(V2ProjectionError::Invalid(format!(
            "refusing to replace portable snapshot {}",
            output.display()
        )));
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    let prepared = parent.join(format!(
        ".archive-ledger-snapshot-{}",
        Ulid::new().to_string().to_ascii_lowercase()
    ));
    fs::create_dir(&prepared).map_err(|source| io_error(&prepared, source))?;
    let result = (|| {
        let snapshot_db = prepared.join(SNAPSHOT_DATABASE_FILE);
        let source = Connection::open(database.path())
            .map_err(|source| sqlite_error(database.path(), source))?;
        let mut destination =
            Connection::open(&snapshot_db).map_err(|source| sqlite_error(&snapshot_db, source))?;
        rusqlite::backup::Backup::new(&source, &mut destination)
            .and_then(|backup| backup.run_to_completion(256, Duration::from_millis(5), None))
            .map_err(|source| sqlite_error(&snapshot_db, source))?;
        drop(destination);
        drop(source);

        let snapshot_connection =
            Connection::open(&snapshot_db).map_err(|source| sqlite_error(&snapshot_db, source))?;
        snapshot_connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 BEGIN IMMEDIATE;
                 DELETE FROM job_items WHERE job_id IN (SELECT job_id FROM jobs WHERE status != 'complete');
                 DELETE FROM jobs WHERE status != 'complete';
                 COMMIT;
                 PRAGMA wal_checkpoint(TRUNCATE);
                 PRAGMA optimize;",
            )
            .map_err(|source| sqlite_error(&snapshot_db, source))?;
        let integrity: String = snapshot_connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|source| sqlite_error(&snapshot_db, source))?;
        if integrity != "ok" {
            return Err(V2ProjectionError::Invalid(format!(
                "portable snapshot SQLite integrity check failed: {integrity}"
            )));
        }
        drop(snapshot_connection);
        File::open(&snapshot_db)
            .and_then(|file| file.sync_all())
            .map_err(|source| io_error(&snapshot_db, source))?;

        let status = V2ProjectionDb::open_existing(&snapshot_db)?.status()?;
        let (database_bytes, database_blake3) = hash_file(&snapshot_db)?;
        let signed = store.sign_portable_snapshot_manifest(PortableSnapshotManifestBody {
            snapshot_v: 1,
            archive_id: status.archive_id.clone(),
            genesis_hash: status.genesis_hash,
            schema_version: status.schema_version,
            projector_version: status.item_projection_version,
            canonical_git_commit: store.canonical_commit()?,
            accepted_frontier_hash: status.accepted_frontier_hash.clone(),
            applied_frontier_hash: status.applied_frontier_hash,
            database_blake3: database_blake3.clone(),
            database_bytes,
            created_time_utc_ms: now_utc_ms()?,
            signer_client_id: String::new(),
        })?;
        let manifest_path = prepared.join(SNAPSHOT_MANIFEST_FILE);
        let mut manifest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&manifest_path)
            .map_err(|source| io_error(&manifest_path, source))?;
        serde_json::to_writer(&mut manifest, &signed)?;
        manifest
            .write_all(b"\n")
            .map_err(|source| io_error(&manifest_path, source))?;
        manifest
            .sync_all()
            .map_err(|source| io_error(&manifest_path, source))?;
        File::open(&prepared)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(&prepared, source))?;
        store.verify_portable_snapshot_manifest(&signed)?;
        Ok(V2PortableSnapshot {
            version: 1,
            directory: output.to_path_buf(),
            archive_id: status.archive_id,
            canonical_git_commit: signed.body.canonical_git_commit,
            accepted_frontier_hash: status.accepted_frontier_hash,
            database_blake3,
            database_bytes,
        })
    })();
    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = fs::remove_dir_all(&prepared);
            return Err(error);
        }
    };
    place_directory_no_replace(&prepared, output)
        .map_err(|error| V2ProjectionError::Invalid(error.to_string()))?;
    Ok(snapshot)
}

pub fn inspect_portable_snapshot(
    store: &V2OriginStore,
    directory: impl AsRef<Path>,
) -> Result<V2PortableSnapshot> {
    let directory = directory.as_ref();
    let manifest_path = directory.join(SNAPSHOT_MANIFEST_FILE);
    let bytes = fs::read(&manifest_path).map_err(|source| io_error(&manifest_path, source))?;
    let signed: SignedPortableSnapshotManifest = serde_json::from_slice(&bytes)?;
    store.verify_portable_snapshot_manifest(&signed)?;
    if signed.body.schema_version != V2_SCHEMA_VERSION || signed.body.projector_version == 0 {
        return Err(V2ProjectionError::Invalid(format!(
            "portable snapshot uses unsupported schema/projector version {}/{}",
            signed.body.schema_version, signed.body.projector_version
        )));
    }
    let database_path = directory.join(SNAPSHOT_DATABASE_FILE);
    let (database_bytes, database_blake3) = hash_file(&database_path)?;
    if database_bytes != signed.body.database_bytes
        || database_blake3 != signed.body.database_blake3
    {
        return Err(V2ProjectionError::Invalid(
            "portable snapshot database size or BLAKE3 does not match its signed manifest"
                .to_owned(),
        ));
    }
    let read_only = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| sqlite_error(&database_path, source))?;
    let integrity: String = read_only
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|source| sqlite_error(&database_path, source))?;
    if integrity != "ok" {
        return Err(V2ProjectionError::Invalid(format!(
            "portable snapshot SQLite integrity check failed: {integrity}"
        )));
    }
    drop(read_only);
    let status = V2ProjectionDb::open_existing(&database_path)?.status()?;
    if status.archive_id != signed.body.archive_id
        || status.genesis_hash != signed.body.genesis_hash
        || status.schema_version != signed.body.schema_version
        || status.item_projection_version != signed.body.projector_version
        || status.accepted_frontier_hash != signed.body.accepted_frontier_hash
        || status.applied_frontier_hash != signed.body.applied_frontier_hash
    {
        return Err(V2ProjectionError::Invalid(
            "portable snapshot SQLite metadata does not match its signed manifest".to_owned(),
        ));
    }
    Ok(V2PortableSnapshot {
        version: 1,
        directory: directory.to_path_buf(),
        archive_id: signed.body.archive_id,
        canonical_git_commit: signed.body.canonical_git_commit,
        accepted_frontier_hash: signed.body.accepted_frontier_hash,
        database_blake3,
        database_bytes,
    })
}

pub fn install_portable_snapshot(
    store: &V2OriginStore,
    directory: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<V2SnapshotInstall> {
    let directory = directory.as_ref();
    let target = target.as_ref();
    let inspected = inspect_portable_snapshot(store, directory)?;
    if target.exists() {
        return Err(V2ProjectionError::Invalid(format!(
            "refusing to replace existing SQLite database {}",
            target.display()
        )));
    }
    let parent = target.parent().ok_or_else(|| {
        V2ProjectionError::Invalid(format!("{} has no parent directory", target.display()))
    })?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    let temp = parent.join(format!(
        ".archive-ledger-snapshot-install-{}.db",
        Ulid::new().to_string().to_ascii_lowercase()
    ));
    let result = (|| {
        let mut input = File::open(directory.join(SNAPSHOT_DATABASE_FILE))
            .map_err(|source| io_error(directory.join(SNAPSHOT_DATABASE_FILE), source))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|source| io_error(&temp, source))?;
        std::io::copy(&mut input, &mut output).map_err(|source| io_error(&temp, source))?;
        output
            .sync_all()
            .map_err(|source| io_error(&temp, source))?;
        let copied = V2ProjectionDb::open_existing(&temp)?;
        let copied_status = copied.status()?;
        if copied_status.accepted_frontier_hash != inspected.accepted_frontier_hash {
            return Err(V2ProjectionError::Invalid(
                "copied snapshot frontier changed during installation".to_owned(),
            ));
        }
        let applied = copied.apply(store)?;
        copied.validate_against_store(store)?;
        drop(copied);
        File::open(&temp)
            .and_then(|file| file.sync_all())
            .map_err(|source| io_error(&temp, source))?;
        fs::rename(&temp, target).map_err(|source| io_error(target, source))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))?;
        Ok(V2SnapshotInstall {
            version: 1,
            archive_id: applied.archive_id,
            snapshot_frontier_hash: inspected.accepted_frontier_hash,
            final_frontier_hash: applied.applied_frontier_hash,
            records_applied: applied.records_applied,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 128 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| io_error(path, source))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total = total
            .checked_add(u64::try_from(count).expect("buffer count fits u64"))
            .ok_or_else(|| V2ProjectionError::Invalid("snapshot size overflow".to_owned()))?;
    }
    Ok((total, format!("blake3:{}", hasher.finalize().to_hex())))
}

fn now_utc_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| V2ProjectionError::Invalid(format!("system clock error: {error}")))?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        V2ProjectionError::Invalid("current time is outside supported range".to_owned())
    })
}

fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> V2ProjectionError {
    V2ProjectionError::Io {
        path: path.into(),
        source,
    }
}

fn sqlite_error(path: impl Into<PathBuf>, source: rusqlite::Error) -> V2ProjectionError {
    V2ProjectionError::Sqlite {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialize_v2_archive;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn snapshot_installs_then_applies_a_newer_tail_and_scrubs_running_jobs() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("source");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let database = V2ProjectionDb::open_existing({
            V2ProjectionDb::create_from_store(&store, archive.join("archive.db")).unwrap();
            archive.join("archive.db")
        })
        .unwrap();
        store
            .append_batch(
                "test_job",
                1,
                json!({}),
                json!({}),
                vec![json!({
                    "kind": "job_started",
                    "job_id": "job_unfinished",
                    "job_type": "scan",
                    "input_version": "test",
                    "params": {}
                })],
            )
            .unwrap();
        database.apply(&store).unwrap();
        let artifact = temp.path().join("portable");
        let created = create_portable_snapshot(&database, &store, &artifact).unwrap();
        assert_eq!(created.archive_id, "arc_test");
        let artifact_db = Connection::open(artifact.join(SNAPSHOT_DATABASE_FILE)).unwrap();
        assert_eq!(
            artifact_db
                .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(artifact_db);

        store
            .append_batch(
                "archive_update",
                1,
                json!({"archive_id": "arc_test"}),
                json!({}),
                vec![json!({
                    "kind": "archive_updated",
                    "archive_id": "arc_test",
                    "archive_display_name": "Personal after snapshot"
                })],
            )
            .unwrap();
        database.apply(&store).unwrap();
        let installed_path = temp.path().join("clone/archive.db");
        let installed = install_portable_snapshot(&store, &artifact, &installed_path).unwrap();
        assert!(installed.records_applied > 0);
        let status = V2ProjectionDb::open_existing(installed_path)
            .unwrap()
            .validate_against_store(&store)
            .unwrap();
        assert_eq!(status.archive_name, "Personal after snapshot");
    }

    #[test]
    fn snapshot_rejects_corrupt_database_bytes() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("source");
        initialize_v2_archive(&archive, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let database_path = archive.join("archive.db");
        V2ProjectionDb::create_from_store(&store, &database_path).unwrap();
        let database = V2ProjectionDb::open_existing(&database_path).unwrap();
        let artifact = temp.path().join("portable");
        create_portable_snapshot(&database, &store, &artifact).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(artifact.join(SNAPSHOT_DATABASE_FILE))
            .unwrap();
        file.write_all(b"corruption").unwrap();
        assert!(inspect_portable_snapshot(&store, &artifact)
            .unwrap_err()
            .to_string()
            .contains("BLAKE3"));
        let target = temp.path().join("clone/archive.db");
        assert!(install_portable_snapshot(&store, &artifact, &target).is_err());
        assert!(!target.exists());
    }
}
