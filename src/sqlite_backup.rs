//! Consistent, verified catalog snapshots. Neither operation activates a catalog
//! or runs restored jobs; destinations are new database files, never directories.
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{backup::Backup, Connection};
use serde::Serialize;
use thiserror::Error;

use crate::safe_copy::{place_file_no_replace, SafeCopyError};
use crate::sqlite_catalog::{CatalogMetadata, SqliteCatalog, SqliteCatalogError};

#[derive(Debug, Error)]
pub enum CatalogBackupError {
    #[error("catalog backup I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog backup SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Catalog(#[from] SqliteCatalogError),
    #[error(transparent)]
    Placement(#[from] SafeCopyError),
    #[error("catalog backup validation failed: {0}")]
    Invalid(String),
}
impl CatalogBackupError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "catalog_backup_invalid",
            _ => "catalog_backup_failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub archive_id: String,
    pub archive_name: String,
    pub revision: u64,
    pub destination: PathBuf,
    /// These jobs are preserved as evidence, never automatically executed.
    pub pending_jobs: u64,
}

/// Snapshot committed catalog state, including WAL transactions, into a new
/// standalone database file. The caller must not already hold a transaction.
pub fn backup_catalog(
    source: &SqliteCatalog,
    destination: &Path,
) -> Result<BackupReport, CatalogBackupError> {
    refuse_existing_destination(destination)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = Staging::create(parent)?;
    let prepared = staging.0.join("catalog.db");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&prepared)?;
    // Reading metadata pins one snapshot before backup begins; metadata and all
    // copied rows therefore describe the same committed revision.
    let transaction = source.connection().unchecked_transaction()?;
    let expected = source.metadata()?;
    let mut output = Connection::open(&prepared)?;
    Backup::new(&transaction, &mut output)?.run_to_completion(
        256,
        Duration::from_millis(5),
        None,
    )?;
    drop(transaction);
    // Backup copies the source journal mode too. Make the artifact standalone
    // before verifying and moving its main file, rather than losing its WAL.
    let mode: String = output.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
    if mode != "delete" {
        return Err(CatalogBackupError::Invalid(
            "cannot make snapshot a standalone database".into(),
        ));
    }
    drop(output);
    let snapshot = SqliteCatalog::open_read_only(&prepared)?;
    let pending_jobs = validate(&snapshot, &expected)?;
    drop(snapshot);
    File::open(&prepared)?.sync_all()?;
    refuse_existing_destination(destination)?;
    place_file_no_replace(&prepared, destination)?;
    Ok(BackupReport {
        archive_id: expected.archive_id,
        archive_name: expected.display_name,
        revision: expected.revision,
        destination: destination.to_path_buf(),
        pending_jobs,
    })
}

/// Restore into a separate absent database path. The backup and any selected
/// active catalog remain untouched. Registration/activation is deliberately
/// separate; pending jobs need explicit review and manual resumption.
pub fn restore_catalog(
    backup: &Path,
    destination: &Path,
) -> Result<BackupReport, CatalogBackupError> {
    if !fs::symlink_metadata(backup)?.file_type().is_file() {
        return Err(CatalogBackupError::Invalid(
            "backup must be a regular database file".into(),
        ));
    }
    let source = SqliteCatalog::open_read_only(backup)?;
    backup_catalog(&source, destination)
}

fn refuse_existing_destination(destination: &Path) -> Result<(), CatalogBackupError> {
    // Stale sidecars can be interpreted as state belonging to a new DB placed at
    // the same name. Never adopt or remove an existing file or sidecar.
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut path = destination.as_os_str().to_os_string();
        path.push(suffix);
        match fs::symlink_metadata(Path::new(&path)) {
            Ok(_) => {
                return Err(CatalogBackupError::Invalid(format!(
                    "destination or SQLite sidecar already exists: {}",
                    Path::new(&path).display()
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate(
    catalog: &SqliteCatalog,
    expected: &CatalogMetadata,
) -> Result<u64, CatalogBackupError> {
    if catalog.metadata()? != *expected || expected.archive_id.trim().is_empty() {
        return Err(CatalogBackupError::Invalid(
            "snapshot identity or revision differs from source".into(),
        ));
    }
    let mut statement = catalog.connection().prepare("PRAGMA integrity_check")?;
    for value in statement.query_map([], |r| r.get::<_, String>(0))? {
        let value = value?;
        if value != "ok" {
            return Err(CatalogBackupError::Invalid(value));
        }
    }
    let mut statement = catalog.connection().prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err(CatalogBackupError::Invalid(
            "snapshot contains foreign key violations".into(),
        ));
    }
    let jobs: i64 = catalog.connection().query_row(
        "SELECT COUNT(*) FROM catalog_jobs WHERE status='running'",
        [],
        |r| r.get(0),
    )?;
    Ok(jobs as u64)
}

struct Staging(PathBuf);
impl Staging {
    fn create(parent: &Path) -> Result<Self, std::io::Error> {
        let path = parent.join(format!(".archive-ledger-backup-{}", ulid::Ulid::new()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite_writes::{CatalogObservation, ObservationResult};
    use crate::RegistryPath;
    use rusqlite::types::Value;
    use std::collections::BTreeMap;

    fn fixture(path: &Path) -> SqliteCatalog {
        let mut catalog = SqliteCatalog::create(path, "archive_fixture", "Files").unwrap();
        catalog.connection().execute_batch("INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('site','Home','home','active');
          INSERT INTO collections(collection_id,display_name,home_site_id,status) VALUES('collection','Files','site','active');
          INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('location','Backup','service','site','online','active');
          PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        catalog
            .begin_catalog_job(
                "pending",
                "inventory",
                &serde_json::json!({"collection_id":"collection","location_id":"location"}),
                1,
            )
            .unwrap();
        let mut observation = CatalogObservation {
            collection_id: "collection".into(),
            location_id: "location".into(),
            path: RegistryPath::utf8("file"),
            time_utc_ms: 2,
            result: ObservationResult::Checksum {
                blake3: [7; 32],
                size_bytes: 123,
            },
            accept_change: false,
            operation_key: None,
            job_id: Some("pending".into()),
        };
        catalog.observe(&observation).unwrap();
        observation.time_utc_ms = 3;
        observation.result = ObservationResult::Checksum {
            blake3: [8; 32],
            size_bytes: 123,
        };
        catalog.observe(&observation).unwrap();
        catalog
    }

    fn table_data(catalog: &SqliteCatalog) -> BTreeMap<String, Vec<Vec<Value>>> {
        let names=catalog.connection().prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        names
            .into_iter()
            .map(|name| {
                let mut statement = catalog
                    .connection()
                    .prepare(&format!(
                        "SELECT * FROM \"{}\" ORDER BY rowid",
                        name.replace('"', "\"\"")
                    ))
                    .unwrap();
                let columns = statement.column_count();
                let rows = statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| row.get::<_, Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                (name, rows)
            })
            .collect()
    }

    #[test]
    fn committed_wal_backup_restores_all_state_and_history_without_running_jobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let active = temp.path().join("active.db");
        let catalog = fixture(&active);
        assert!(
            fs::metadata(temp.path().join("active.db-wal"))
                .unwrap()
                .len()
                > 0
        );
        let original = table_data(&catalog);
        let backup = temp.path().join("backup.db");
        let report = backup_catalog(&catalog, &backup).unwrap();
        assert_eq!(report.archive_id, "archive_fixture");
        assert_eq!(report.pending_jobs, 1);
        assert_eq!(report.revision, catalog.metadata().unwrap().revision);
        assert!(!temp.path().join("backup.db-wal").exists());
        let backup_bytes = fs::read(&backup).unwrap();
        let restored = temp.path().join("restored.db");
        let result = restore_catalog(&backup, &restored).unwrap();
        assert_eq!(result.pending_jobs, 1);
        let recovered = SqliteCatalog::open_read_only(&restored).unwrap();
        assert_eq!(table_data(&recovered), original);
        assert_eq!(table_data(&catalog), original);
        assert_eq!(fs::read(&backup).unwrap(), backup_bytes);
        assert_eq!(
            recovered
                .connection()
                .query_row(
                    "SELECT status FROM catalog_jobs WHERE job_id='pending'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "running"
        );
        assert!(!temp.path().read_dir().unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".archive-ledger-backup-")));
    }

    #[test]
    fn destinations_and_sidecars_are_never_overwritten() {
        let temp = tempfile::TempDir::new().unwrap();
        let active = temp.path().join("active.db");
        let catalog = fixture(&active);
        let original = table_data(&catalog);
        assert!(backup_catalog(&catalog, &active).is_err());
        let destination = temp.path().join("existing.db");
        fs::write(&destination, b"original artifact").unwrap();
        assert!(backup_catalog(&catalog, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"original artifact");
        let new = temp.path().join("new.db");
        fs::write(temp.path().join("new.db-wal"), b"old WAL").unwrap();
        assert!(backup_catalog(&catalog, &new).is_err());
        assert!(!new.exists());
        assert_eq!(table_data(&catalog), original);
    }

    #[test]
    fn corrupt_or_wrong_schema_restore_never_replaces_active_catalog() {
        let temp = tempfile::TempDir::new().unwrap();
        let active = temp.path().join("active.db");
        let catalog = fixture(&active);
        let original = table_data(&catalog);
        let corrupt = temp.path().join("corrupt.db");
        fs::write(&corrupt, b"not a database").unwrap();
        let restored = temp.path().join("restored.db");
        assert!(restore_catalog(&corrupt, &restored).is_err());
        assert!(!restored.exists());
        assert_eq!(fs::read(&corrupt).unwrap(), b"not a database");
        let backup = temp.path().join("backup.db");
        backup_catalog(&catalog, &backup).unwrap();
        assert!(restore_catalog(&backup, &active).is_err());
        let changed = Connection::open(&backup).unwrap();
        changed.pragma_update(None, "user_version", 999).unwrap();
        drop(changed);
        assert!(restore_catalog(&backup, &restored).is_err());
        assert!(!restored.exists());
        assert_eq!(table_data(&catalog), original);
    }

    #[test]
    fn foreign_key_corruption_rejects_backup_before_publication() {
        let temp = tempfile::TempDir::new().unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("source.db"), "arc", "Archive").unwrap();
        catalog.connection().execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES('a','missing','utf8',X'61','a'); PRAGMA foreign_keys=ON;").unwrap();
        let destination = temp.path().join("backup.db");
        assert!(matches!(
            backup_catalog(&catalog, &destination),
            Err(CatalogBackupError::Invalid(_))
        ));
        assert!(!destination.exists());
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(temp.path().read_dir().unwrap().count(), 1);
    }
}
