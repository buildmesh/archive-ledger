//! Authoritative SQLite catalog. This format is independent of the legacy projection.
//!
//! Current state and its history must be changed in one transaction. This module
//! establishes the storage boundary; domain writers enforce checksum acceptance.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags};
use thiserror::Error;

/// Distinguishes authoritative catalogs from rebuildable projection databases.
pub const CATALOG_APPLICATION_ID: i32 = 0x414c5343; // ALSC
pub const CATALOG_SCHEMA_VERSION: i32 = 1;
const SCHEMA: &str = include_str!("sqlite_catalog.sql");

#[derive(Debug, Error)]
pub enum SqliteCatalogError {
    #[error("cannot create catalog: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("not a supported authoritative catalog (application ID {application_id}, schema {schema_version})")]
    UnsupportedFormat {
        application_id: i32,
        schema_version: i32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMetadata {
    pub archive_id: String,
    pub display_name: String,
    pub revision: u64,
}

/// A connection to an authoritative catalog. Opening never creates or migrates it.
pub struct SqliteCatalog {
    connection: Connection,
}

impl SqliteCatalog {
    /// Create a new catalog without replacing any existing file. A failed
    /// initialization may leave an incomplete file; it is never accepted by open.
    pub fn create(
        path: impl AsRef<Path>,
        archive_id: &str,
        display_name: &str,
    ) -> Result<Self, SqliteCatalogError> {
        let path = path.as_ref();
        OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure(&connection)?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT INTO catalog_metadata(singleton, archive_id, display_name) VALUES (1, ?1, ?2)",
            params![archive_id, display_name],
        )?;
        transaction.pragma_update(None, "application_id", CATALOG_APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", CATALOG_SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteCatalogError> {
        Self::open_with_flags(path.as_ref(), OpenFlags::SQLITE_OPEN_READ_WRITE)
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, SqliteCatalogError> {
        Self::open_with_flags(path.as_ref(), OpenFlags::SQLITE_OPEN_READ_ONLY)
    }

    fn open_with_flags(path: &Path, flags: OpenFlags) -> Result<Self, SqliteCatalogError> {
        let connection = Connection::open_with_flags(path, flags)?;
        let application_id =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let schema_version =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if application_id != CATALOG_APPLICATION_ID || schema_version != CATALOG_SCHEMA_VERSION {
            return Err(SqliteCatalogError::UnsupportedFormat {
                application_id,
                schema_version,
            });
        }
        configure(&connection)?;
        let catalog = Self { connection };
        catalog.metadata()?;
        Ok(catalog)
    }

    pub fn metadata(&self) -> Result<CatalogMetadata, SqliteCatalogError> {
        Ok(self.connection.query_row(
            "SELECT archive_id, display_name, revision FROM catalog_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok(CatalogMetadata {
                    archive_id: row.get(0)?,
                    display_name: row.get(1)?,
                    revision: {
                        let value: i64 = row.get(2)?;
                        u64::try_from(value)
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, value))?
                    },
                })
            },
        )?)
    }

    /// Shared SQL access for indexed reads and prepared statements.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Domain writers use this connection to transact state, history, and revision
    /// together. This deliberately does not create a second persistence framework.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

fn configure(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, SqliteCatalog) {
        let directory = tempfile::tempdir().unwrap();
        let catalog =
            SqliteCatalog::create(directory.path().join("catalog.sqlite"), "archive", "Test")
                .unwrap();
        catalog.connection().execute_batch(
            "INSERT INTO sites VALUES ('site', 'Site', 'home', NULL, 'active');
             INSERT INTO collections VALUES ('collection', 'Files', NULL, NULL, NULL, 'active');
             INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status)
             VALUES ('location','Backup','service','site','offline','active');"
        ).unwrap();
        (directory, catalog)
    }

    fn object(
        connection: &Connection,
        id: &str,
        path: &[u8],
        hash: Option<&[u8]>,
    ) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3)
             VALUES (?1,'collection','unix_bytes',?2,'display',?3)",
            params![id,path,hash],
        )
    }

    #[test]
    fn creates_distinct_format_and_never_replaces_existing_data() {
        let (directory, catalog) = fixture();
        assert_eq!(
            catalog.metadata().unwrap(),
            CatalogMetadata {
                archive_id: "archive".into(),
                display_name: "Test".into(),
                revision: 0
            }
        );
        let path = directory.path().join("catalog.sqlite");
        assert!(SqliteCatalog::create(&path, "other", "Other").is_err());
        let read_only = SqliteCatalog::open_read_only(&path).unwrap();
        assert_eq!(read_only.metadata().unwrap(), catalog.metadata().unwrap());
        assert!(read_only
            .connection()
            .execute("UPDATE catalog_metadata SET revision=1", [])
            .is_err());
        let missing = directory.path().join("missing.sqlite");
        assert!(SqliteCatalog::open(&missing).is_err());
        assert!(!missing.exists());
        let legacy = directory.path().join("legacy.sqlite");
        Connection::open(&legacy)
            .unwrap()
            .execute_batch(
                "CREATE TABLE preserved(value TEXT); INSERT INTO preserved VALUES ('original');",
            )
            .unwrap();
        assert!(matches!(
            SqliteCatalog::open(&legacy),
            Err(SqliteCatalogError::UnsupportedFormat { .. })
        ));
        assert_eq!(
            Connection::open(&legacy)
                .unwrap()
                .query_row("SELECT value FROM preserved", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "original"
        );
    }

    #[test]
    fn expected_identity_is_per_lossless_path_and_survives_missing_copies() {
        let (_directory, catalog) = fixture();
        let connection = catalog.connection();
        let hash = [7u8; 32];
        object(connection, "one", b"one", Some(&hash)).unwrap();
        object(connection, "two", b"two\xff", Some(&hash)).unwrap();
        object(connection, "unknown", b"unknown", None).unwrap();
        assert!(object(connection, "duplicate", b"one", None).is_err());
        assert!(object(connection, "bad-hash", b"bad", Some(&[1; 31])).is_err());
        connection.execute_batch("INSERT INTO files(object_id,location_id,presence,integrity) VALUES ('one','location','present','unverified');").unwrap();
        assert!(connection.execute("INSERT INTO files(object_id,location_id,presence,integrity) VALUES ('one','location','present','unverified')", []).is_err());
        connection.execute("UPDATE files SET presence='missing',last_check_result='missing',last_check_time_utc_ms=1",[]).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT expected_blake3 FROM objects WHERE object_id='one'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0)
                )
                .unwrap(),
            hash
        );
        connection.execute("UPDATE files SET presence='present',integrity='damaged',last_check_result='mismatch',observed_blake3=?1",params![[8u8;32].as_slice()]).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT expected_blake3 FROM objects WHERE object_id='one'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0)
                )
                .unwrap(),
            hash
        );
        assert!(connection
            .execute("UPDATE files SET integrity='verified'", [])
            .is_err());
        connection.execute("DELETE FROM files", []).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM objects", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn history_is_atomic_append_only_and_does_not_enter_current_query_plan() {
        let (_directory, mut catalog) = fixture();
        object(catalog.connection(), "one", b"one", None).unwrap();
        const QUERY: &str = "SELECT o.object_id, f.presence FROM objects o LEFT JOIN files f ON f.object_id=o.object_id WHERE o.collection_id='collection' AND o.relative_path_encoding='unix_bytes' AND o.relative_path_bytes=x'6f6e65'";
        fn plan(connection: &Connection) -> Vec<String> {
            connection
                .prepare(&format!("EXPLAIN QUERY PLAN {QUERY}"))
                .unwrap()
                .query_map([], |row| row.get(3))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }
        let before = plan(catalog.connection());
        {
            let transaction = catalog.connection_mut().transaction().unwrap();
            transaction.execute("INSERT INTO files(object_id,location_id,presence,integrity) VALUES ('one','location','missing','unverified')",[]).unwrap();
            transaction
                .execute(
                    "INSERT INTO history(object_id,time_utc_ms,kind) VALUES ('one',1,'missing')",
                    [],
                )
                .unwrap();
            // Dropping the transaction must roll back both pieces of user state.
        }
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT (SELECT count(*) FROM files)+(SELECT count(*) FROM history)",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        catalog.connection().execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) INSERT INTO history(object_id,time_utc_ms,kind) SELECT 'one',x,'checked' FROM n;").unwrap();
        assert_eq!(before, plan(catalog.connection()));
        assert!(before
            .iter()
            .all(|step| !step.contains("SCAN") && !step.contains("history")));
        assert!(catalog
            .connection()
            .execute("DELETE FROM history", [])
            .is_err());
        assert!(catalog
            .connection()
            .execute("UPDATE history SET kind='changed'", [])
            .is_err());
    }
}
