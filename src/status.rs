//! Fast SQLite-only Collection and Location summaries.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use thiserror::Error;

use crate::projection::ProjectionDb;

pub type Result<T> = std::result::Result<T, StatusError>;

#[derive(Debug, Error)]
pub enum StatusError {
    #[error("SQLite status query failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("Collection not found: {0}")]
    CollectionNotFound(String),
    #[error("Location not found: {0}")]
    LocationNotFound(String),
}

impl StatusError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Sqlite { .. } => "status_sqlite",
            Self::CollectionNotFound(_) => "collection_not_found",
            Self::LocationNotFound(_) => "location_not_found",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CollectionStatus {
    pub version: u32,
    pub collection_id: String,
    pub collection_name: String,
    pub file_count: u64,
    pub logical_bytes: u64,
    pub files_with_unknown_size: u64,
    pub unique_object_count: u64,
    pub unique_object_bytes: u64,
    pub unresolved_identity_count: u64,
    pub location_count: u64,
    pub violated_files: Option<u64>,
    pub uncertain_files: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LocationStatus {
    pub version: u32,
    pub location_id: String,
    pub location_name: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub site_id: Option<String>,
    pub site_name: Option<String>,
    pub logical_file_count: u64,
    pub present_count: u64,
    pub present_bytes: u64,
    pub missing_count: u64,
    pub missing_bytes: u64,
    pub corrupt_count: u64,
    pub corrupt_bytes: u64,
    pub unknown_count: u64,
    pub unknown_bytes: u64,
    pub unresolved_present_count: u64,
    pub unresolved_missing_count: u64,
    pub last_complete_inventory_utc_ms: Option<u64>,
    pub last_verification_utc_ms: Option<u64>,
}

struct LocationIdentity {
    name: String,
    device_id: Option<String>,
    device_name: Option<String>,
    site_id: Option<String>,
    site_name: Option<String>,
}

impl ProjectionDb {
    pub fn collection_summary(&self, collection_id: &str) -> Result<CollectionStatus> {
        let connection =
            Connection::open(self.path()).map_err(|source| sql(self.path(), source))?;
        let (collection_name, policy_id): (String, Option<String>) = connection
            .query_row(
                "SELECT display_name, policy_id FROM collections
                 WHERE collection_id = ?1 AND status = 'active'",
                [collection_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|source| sql(self.path(), source))?
            .ok_or_else(|| StatusError::CollectionNotFound(collection_id.to_owned()))?;
        let (file_count, logical_bytes, files_with_unknown_size, unresolved_identity_count): (
            i64,
            i64,
            i64,
            i64,
        ) = connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(observed_size_bytes), 0),
                        COALESCE(SUM(CASE WHEN observed_size_bytes IS NULL THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN object_id IS NULL THEN 1 ELSE 0 END), 0)
                 FROM file_refs
                 WHERE collection_id = ?1 AND path_state = 'active'",
                [collection_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|source| sql(self.path(), source))?;
        let (unique_object_count, unique_object_bytes): (i64, i64) = connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(o.size_bytes), 0)
                 FROM objects o
                 JOIN (
                   SELECT DISTINCT object_id FROM file_refs
                   WHERE collection_id = ?1 AND path_state = 'active'
                     AND object_id IS NOT NULL
                 ) f ON f.object_id = o.object_id",
                [collection_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|source| sql(self.path(), source))?;
        let location_count: i64 = connection
            .query_row(
                "SELECT COUNT(DISTINCT p.location_id)
                 FROM path_observations p
                 JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                 WHERE f.collection_id = ?1 AND f.path_state = 'active'",
                [collection_id],
                |row| row.get(0),
            )
            .map_err(|source| sql(self.path(), source))?;
        let risk = policy_id
            .as_deref()
            .map(|policy_id| current_collection_risk(&connection, collection_id, policy_id))
            .transpose()
            .map_err(|source| sql(self.path(), source))?
            .flatten();
        Ok(CollectionStatus {
            version: 1,
            collection_id: collection_id.to_owned(),
            collection_name,
            file_count: unsigned(file_count),
            logical_bytes: unsigned(logical_bytes),
            files_with_unknown_size: unsigned(files_with_unknown_size),
            unique_object_count: unsigned(unique_object_count),
            unique_object_bytes: unsigned(unique_object_bytes),
            unresolved_identity_count: unsigned(unresolved_identity_count),
            location_count: unsigned(location_count),
            violated_files: risk.map(|risk| unsigned(risk.0)),
            uncertain_files: risk.map(|risk| unsigned(risk.1)),
        })
    }

    pub fn location_summary(&self, location_id: &str) -> Result<LocationStatus> {
        let connection =
            Connection::open(self.path()).map_err(|source| sql(self.path(), source))?;
        let identity: Option<LocationIdentity> = connection
            .query_row(
                "SELECT l.display_name, l.device_id, d.display_name,
                        COALESCE(l.site_id, d.current_site_id), s.display_name
                 FROM locations l
                 LEFT JOIN devices d ON d.device_id = l.device_id
                 LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
                 WHERE l.location_id = ?1 AND l.status = 'active'",
                [location_id],
                |row| {
                    Ok(LocationIdentity {
                        name: row.get(0)?,
                        device_id: row.get(1)?,
                        device_name: row.get(2)?,
                        site_id: row.get(3)?,
                        site_name: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|source| sql(self.path(), source))?;
        let identity =
            identity.ok_or_else(|| StatusError::LocationNotFound(location_id.to_owned()))?;
        let logical_file_count: i64 = connection
            .query_row(
                "SELECT COUNT(DISTINCT p.file_ref_id)
                 FROM path_observations p
                 JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                 WHERE p.location_id = ?1 AND p.state = 'present'
                   AND f.path_state = 'active'",
                [location_id],
                |row| row.get(0),
            )
            .map_err(|source| sql(self.path(), source))?;
        let copy_counts = copy_state_counts(&connection, location_id)
            .map_err(|source| sql(self.path(), source))?;
        let (unresolved_present_count, unresolved_missing_count): (i64, i64) = connection
            .query_row(
                "SELECT
                   COUNT(DISTINCT CASE WHEN state = 'present' THEN external_identity_id END),
                   COUNT(DISTINCT CASE WHEN state = 'missing' THEN external_identity_id END)
                 FROM external_availability WHERE location_id = ?1",
                [location_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|source| sql(self.path(), source))?;
        let last_complete_inventory_utc_ms = optional_u64(
            connection
                .query_row(
                    "SELECT MAX(finished_time_utc_ms) FROM scan_runs
                     WHERE location_id = ?1 AND status = 'complete'
                       AND scan_mode = 'complete'",
                    [location_id],
                    |row| row.get(0),
                )
                .map_err(|source| sql(self.path(), source))?,
        );
        let last_verification_utc_ms = optional_u64(
            connection
                .query_row(
                    "SELECT MAX(last_verified_time_utc_ms) FROM copy_claims
                     WHERE location_id = ?1 AND state != 'superseded'",
                    [location_id],
                    |row| row.get(0),
                )
                .map_err(|source| sql(self.path(), source))?,
        );
        Ok(LocationStatus {
            version: 1,
            location_id: location_id.to_owned(),
            location_name: identity.name,
            device_id: identity.device_id,
            device_name: identity.device_name,
            site_id: identity.site_id,
            site_name: identity.site_name,
            logical_file_count: unsigned(logical_file_count),
            present_count: unsigned(copy_counts[0]),
            present_bytes: unsigned(copy_counts[1]),
            missing_count: unsigned(copy_counts[2]),
            missing_bytes: unsigned(copy_counts[3]),
            corrupt_count: unsigned(copy_counts[4]),
            corrupt_bytes: unsigned(copy_counts[5]),
            unknown_count: unsigned(copy_counts[6]),
            unknown_bytes: unsigned(copy_counts[7]),
            unresolved_present_count: unsigned(unresolved_present_count),
            unresolved_missing_count: unsigned(unresolved_missing_count),
            last_complete_inventory_utc_ms,
            last_verification_utc_ms,
        })
    }
}

fn current_collection_risk(
    connection: &Connection,
    collection_id: &str,
    policy_id: &str,
) -> rusqlite::Result<Option<(i64, i64)>> {
    connection.query_row(
            "SELECT COUNT(DISTINCT pe.evaluation_id),
               COALESCE(SUM(CASE WHEN f.file_ref_id IS NOT NULL AND ps.status = 'violated' THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN f.file_ref_id IS NOT NULL AND ps.status = 'uncertain' THEN 1 ELSE 0 END), 0)
             FROM policy_evaluations pe
             LEFT JOIN policy_status ps ON ps.evaluation_id = pe.evaluation_id
             LEFT JOIN file_refs f ON f.file_ref_id = ps.file_ref_id
               AND f.collection_id = ?1 AND f.path_state = 'active'
             WHERE pe.evaluation_id = (
               SELECT evaluation_id FROM policy_evaluations
               WHERE policy_id = ?2 AND status = 'complete'
                 AND evaluated_policy_input_seq = (
                   SELECT CAST(value AS INTEGER) FROM archive_meta
                   WHERE key = 'policy_input_event_seq'
                 )
               ORDER BY completed_time_utc_ms DESC, evaluation_id DESC LIMIT 1
             )",
            [collection_id, policy_id],
            |row| {
                let evaluations: i64 = row.get(0)?;
                let violated: i64 = row.get(1)?;
                let uncertain: i64 = row.get(2)?;
                Ok((evaluations > 0).then_some((violated, uncertain)))
            },
        )
}

fn copy_state_counts(connection: &Connection, location_id: &str) -> rusqlite::Result<[i64; 8]> {
    connection.query_row(
        "SELECT
           COALESCE(SUM(CASE WHEN cc.state = 'present' THEN 1 ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'present' THEN COALESCE(o.size_bytes, x.expected_size_bytes, 0) ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'missing' THEN 1 ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'missing' THEN COALESCE(o.size_bytes, x.expected_size_bytes, 0) ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'corrupt' THEN 1 ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'corrupt' THEN COALESCE(o.size_bytes, x.expected_size_bytes, 0) ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'unknown' THEN 1 ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN cc.state = 'unknown' THEN COALESCE(o.size_bytes, x.expected_size_bytes, 0) ELSE 0 END), 0)
         FROM copy_claims cc
         LEFT JOIN objects o ON o.object_id = cc.object_id
         LEFT JOIN external_identities x ON x.external_identity_id = cc.external_identity_id
         WHERE cc.location_id = ?1 AND cc.state != 'superseded'",
        [location_id],
        |row| {
            Ok([
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ])
        },
    )
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn optional_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

fn sql(path: &Path, source: rusqlite::Error) -> StatusError {
    StatusError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}
