//! Fast SQLite-only Collection and Location summaries.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
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
    #[error("Policy {policy_id} has invalid requirements: {message}")]
    InvalidPolicy { policy_id: String, message: String },
}

impl StatusError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Sqlite { .. } => "status_sqlite",
            Self::CollectionNotFound(_) => "collection_not_found",
            Self::LocationNotFound(_) => "location_not_found",
            Self::InvalidPolicy { .. } => "status_invalid_policy",
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StalePresenceThreshold {
    pub collection_id: String,
    pub collection_name: String,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub max_observation_age_days: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StalePresenceLocation {
    pub location_id: String,
    pub location_name: String,
    pub location_kind: String,
    pub stale_object_count: u64,
    pub unresolved_present_count: u64,
    pub unresolved_missing_count: u64,
    pub unresolved_unknown_count: u64,
    pub oldest_positive_observation_utc_ms: Option<u64>,
    pub last_complete_inventory_utc_ms: Option<u64>,
    pub suggested_action: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StalePresenceDevice {
    pub device_id: Option<String>,
    pub device_name: String,
    pub group_kind: String,
    pub site_id: Option<String>,
    pub site_name: Option<String>,
    pub expected_availability: String,
    pub stale_object_count: u64,
    pub unresolved_present_count: u64,
    pub unresolved_missing_count: u64,
    pub unresolved_unknown_count: u64,
    pub suggested_action: String,
    pub locations: Vec<StalePresenceLocation>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StalePresenceReport {
    pub version: u32,
    pub generated_time_utc_ms: u64,
    pub threshold_source: String,
    pub override_age_days: Option<u64>,
    pub minimum_age_days: Option<u64>,
    pub maximum_age_days: Option<u64>,
    pub thresholds: Vec<StalePresenceThreshold>,
    pub unconfigured_collections: Vec<String>,
    pub stale_object_count: u64,
    pub unresolved_present_count: u64,
    pub unresolved_missing_count: u64,
    pub unresolved_unknown_count: u64,
    pub unmapped_unresolved_present_count: u64,
    pub unmapped_unresolved_missing_count: u64,
    pub unmapped_unresolved_unknown_count: u64,
    pub devices: Vec<StalePresenceDevice>,
}

struct LocationIdentity {
    name: String,
    device_id: Option<String>,
    device_name: Option<String>,
    site_id: Option<String>,
    site_name: Option<String>,
}

struct StaleLocationRow {
    location: StalePresenceLocation,
    device_id: Option<String>,
    device_name: Option<String>,
    site_id: Option<String>,
    site_name: Option<String>,
    expected_availability: String,
}

struct DeviceCounts {
    stale: u64,
    unresolved_present: u64,
    unresolved_missing: u64,
    unresolved_unknown: u64,
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

    pub fn stale_presence_report(
        &self,
        now_utc_ms: u64,
        collection_id: Option<&str>,
        override_age_days: Option<u64>,
    ) -> Result<StalePresenceReport> {
        const DAY_MS: u64 = 86_400_000;
        let mut connection =
            Connection::open(self.path()).map_err(|source| sql(self.path(), source))?;
        if let Some(collection_id) = collection_id {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM collections
                     WHERE collection_id = ?1 AND status = 'active')",
                    [collection_id],
                    |row| row.get(0),
                )
                .map_err(|source| sql(self.path(), source))?;
            if !exists {
                return Err(StatusError::CollectionNotFound(collection_id.to_owned()));
            }
        }

        let mut statement = connection
            .prepare(
                "SELECT c.collection_id, c.display_name,
                        p.policy_id, p.display_name, p.requirements_json
                 FROM collections c
                 LEFT JOIN policies p ON p.policy_id = c.policy_id
                   AND p.status = 'active' AND p.enabled = 1
                 WHERE c.status = 'active' AND (?1 IS NULL OR c.collection_id = ?1)
                 ORDER BY c.display_name, c.collection_id",
            )
            .map_err(|source| sql(self.path(), source))?;
        let rows = statement
            .query_map([collection_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|source| sql(self.path(), source))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|source| sql(self.path(), source))?;
        drop(statement);

        connection
            .execute_batch(
                "CREATE TEMP TABLE stale_selected_collections(
                   collection_id TEXT PRIMARY KEY
                 ) WITHOUT ROWID;
                 CREATE TEMP TABLE stale_thresholds(
                   collection_id TEXT PRIMARY KEY,
                   cutoff_utc_ms INTEGER NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TEMP TABLE stale_location_objects(
                   location_id TEXT NOT NULL,
                   object_id TEXT NOT NULL,
                   effective_observation_utc_ms INTEGER NOT NULL,
                   PRIMARY KEY(location_id, object_id)
                 ) WITHOUT ROWID;",
            )
            .map_err(|source| sql(self.path(), source))?;

        let transaction = connection
            .transaction()
            .map_err(|source| sql(self.path(), source))?;
        let mut thresholds = Vec::new();
        let mut unconfigured_collections = Vec::new();
        for (collection_id, collection_name, policy_id, policy_name, requirements) in rows {
            transaction
                .execute(
                    "INSERT INTO stale_selected_collections(collection_id) VALUES (?1)",
                    [&collection_id],
                )
                .map_err(|source| sql(self.path(), source))?;
            let age_days = if let Some(age_days) = override_age_days {
                Some(age_days)
            } else if let (Some(policy_id), Some(requirements)) =
                (policy_id.as_deref(), requirements.as_deref())
            {
                let requirements: crate::policy::PolicyRequirements =
                    serde_json::from_str(requirements).map_err(|error| {
                        StatusError::InvalidPolicy {
                            policy_id: policy_id.to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                Some(requirements.max_observation_age_days)
            } else {
                None
            };
            let Some(age_days) = age_days else {
                unconfigured_collections.push(collection_name);
                continue;
            };
            let age_ms = age_days.saturating_mul(DAY_MS);
            let cutoff = now_utc_ms.saturating_sub(age_ms);
            transaction
                .execute(
                    "INSERT INTO stale_thresholds(collection_id, cutoff_utc_ms)
                     VALUES (?1, ?2)",
                    params![collection_id, integer(cutoff)],
                )
                .map_err(|source| sql(self.path(), source))?;
            thresholds.push(StalePresenceThreshold {
                collection_id,
                collection_name,
                policy_id: override_age_days.is_none().then_some(policy_id).flatten(),
                policy_name: override_age_days.is_none().then_some(policy_name).flatten(),
                max_observation_age_days: age_days,
            });
        }
        transaction
            .commit()
            .map_err(|source| sql(self.path(), source))?;

        connection
            .execute(
                "INSERT INTO stale_location_objects(
                   location_id, object_id, effective_observation_utc_ms
                 )
                 WITH object_locations AS (
                   SELECT cc.location_id, cc.object_id,
                          MAX(CASE
                            WHEN COALESCE(sr.finished_time_utc_ms, 0)
                               > COALESCE(cc.last_seen_time_utc_ms, 0)
                            THEN COALESCE(sr.finished_time_utc_ms, 0)
                            ELSE COALESCE(cc.last_seen_time_utc_ms, 0)
                          END) AS effective_time
                   FROM copy_claims cc
                   JOIN locations active_location
                     ON active_location.location_id = cc.location_id
                    AND active_location.status = 'active'
                   LEFT JOIN scan_runs sr ON sr.scan_id = cc.last_complete_scan_id
                     AND sr.status = 'complete' AND sr.scan_mode = 'complete'
                   WHERE cc.state = 'present' AND cc.object_id IS NOT NULL
                   GROUP BY cc.location_id, cc.object_id
                 )
                 SELECT ol.location_id, ol.object_id, ol.effective_time
                 FROM object_locations ol
                 WHERE EXISTS (
                   SELECT 1
                   FROM file_refs f
                   JOIN stale_thresholds t ON t.collection_id = f.collection_id
                   WHERE f.object_id = ol.object_id AND f.path_state = 'active'
                     AND ol.effective_time < t.cutoff_utc_ms
                 )",
                [],
            )
            .map_err(|source| sql(self.path(), source))?;

        let mut locations =
            stale_location_rows(&connection).map_err(|source| sql(self.path(), source))?;
        merge_unresolved_location_counts(&connection, &mut locations)
            .map_err(|source| sql(self.path(), source))?;
        let mut device_counts =
            stale_device_counts(&connection).map_err(|source| sql(self.path(), source))?;
        merge_unresolved_device_counts(&connection, &mut device_counts)
            .map_err(|source| sql(self.path(), source))?;

        let mut devices = BTreeMap::<String, StalePresenceDevice>::new();
        for (location_id, row) in locations {
            let group_key = row
                .device_id
                .clone()
                .unwrap_or_else(|| format!("service:{location_id}"));
            let counts = device_counts.remove(&group_key).unwrap_or(DeviceCounts {
                stale: 0,
                unresolved_present: 0,
                unresolved_missing: 0,
                unresolved_unknown: 0,
            });
            let is_device = row.device_id.is_some();
            let group = devices
                .entry(group_key)
                .or_insert_with(|| StalePresenceDevice {
                    device_id: row.device_id.clone(),
                    device_name: row
                        .device_name
                        .clone()
                        .unwrap_or_else(|| row.location.location_name.clone()),
                    group_kind: if is_device {
                        "device"
                    } else {
                        "service_location"
                    }
                    .to_owned(),
                    site_id: row.site_id.clone(),
                    site_name: row.site_name.clone(),
                    expected_availability: row.expected_availability.clone(),
                    stale_object_count: counts.stale,
                    unresolved_present_count: counts.unresolved_present,
                    unresolved_missing_count: counts.unresolved_missing,
                    unresolved_unknown_count: counts.unresolved_unknown,
                    suggested_action: if is_device {
                        format!(
                            "mount {} and scan its stale Locations",
                            row.device_name.as_deref().unwrap_or("the Device")
                        )
                    } else {
                        row.location.suggested_action.clone()
                    },
                    locations: Vec::new(),
                });
            group.locations.push(row.location);
        }
        let mut devices = devices.into_values().collect::<Vec<_>>();
        for device in &mut devices {
            device.locations.sort_by(|left, right| {
                left.location_name
                    .cmp(&right.location_name)
                    .then(left.location_id.cmp(&right.location_id))
            });
        }
        devices.sort_by(|left, right| {
            left.device_name.cmp(&right.device_name).then(
                left.device_id
                    .as_deref()
                    .unwrap_or("")
                    .cmp(right.device_id.as_deref().unwrap_or("")),
            )
        });

        let (
            stale_object_count,
            unresolved_present_count,
            unresolved_missing_count,
            unresolved_unknown_count,
        ): (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(DISTINCT object_id) FROM stale_location_objects),
                   (SELECT COUNT(DISTINCT a.external_identity_id)
                    FROM external_availability a
                    JOIN external_identities x USING(external_identity_id)
                    WHERE x.resolution_state != 'resolved' AND a.state = 'present'
                      AND EXISTS (
                        SELECT 1 FROM file_refs f
                        JOIN stale_selected_collections s
                          ON s.collection_id = f.collection_id
                        WHERE f.external_identity_id = a.external_identity_id
                          AND f.path_state = 'active'
                      )),
                   (SELECT COUNT(DISTINCT a.external_identity_id)
                    FROM external_availability a
                    JOIN external_identities x USING(external_identity_id)
                    WHERE x.resolution_state != 'resolved' AND a.state = 'missing'
                      AND EXISTS (
                        SELECT 1 FROM file_refs f
                        JOIN stale_selected_collections s
                          ON s.collection_id = f.collection_id
                        WHERE f.external_identity_id = a.external_identity_id
                          AND f.path_state = 'active'
                      )),
                   (SELECT COUNT(DISTINCT a.external_identity_id)
                    FROM external_availability a
                    JOIN external_identities x USING(external_identity_id)
                    WHERE x.resolution_state != 'resolved' AND a.state = 'unknown'
                      AND EXISTS (
                        SELECT 1 FROM file_refs f
                        JOIN stale_selected_collections s
                          ON s.collection_id = f.collection_id
                        WHERE f.external_identity_id = a.external_identity_id
                          AND f.path_state = 'active'
                      ))",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|source| sql(self.path(), source))?;
        let (unmapped_present, unmapped_missing, unmapped_unknown): (i64, i64, i64) = connection
            .query_row(
                "SELECT
                   COUNT(DISTINCT CASE WHEN a.state = 'present' THEN a.external_identity_id END),
                   COUNT(DISTINCT CASE WHEN a.state = 'missing' THEN a.external_identity_id END),
                   COUNT(DISTINCT CASE WHEN a.state = 'unknown' THEN a.external_identity_id END)
                 FROM external_availability a
                 JOIN external_identities x USING(external_identity_id)
                 WHERE x.resolution_state != 'resolved' AND a.location_id IS NULL
                   AND EXISTS (
                     SELECT 1 FROM file_refs f
                     JOIN stale_selected_collections s ON s.collection_id = f.collection_id
                     WHERE f.external_identity_id = a.external_identity_id
                       AND f.path_state = 'active'
                   )",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|source| sql(self.path(), source))?;
        let minimum_age_days = thresholds
            .iter()
            .map(|threshold| threshold.max_observation_age_days)
            .min();
        let maximum_age_days = thresholds
            .iter()
            .map(|threshold| threshold.max_observation_age_days)
            .max();
        Ok(StalePresenceReport {
            version: 1,
            generated_time_utc_ms: now_utc_ms,
            threshold_source: if override_age_days.is_some() {
                "override"
            } else {
                "collection_policies"
            }
            .to_owned(),
            override_age_days,
            minimum_age_days,
            maximum_age_days,
            thresholds,
            unconfigured_collections,
            stale_object_count: unsigned(stale_object_count),
            unresolved_present_count: unsigned(unresolved_present_count),
            unresolved_missing_count: unsigned(unresolved_missing_count),
            unresolved_unknown_count: unsigned(unresolved_unknown_count),
            unmapped_unresolved_present_count: unsigned(unmapped_present),
            unmapped_unresolved_missing_count: unsigned(unmapped_missing),
            unmapped_unresolved_unknown_count: unsigned(unmapped_unknown),
            devices,
        })
    }
}

fn stale_location_rows(
    connection: &Connection,
) -> rusqlite::Result<BTreeMap<String, StaleLocationRow>> {
    let mut statement = connection.prepare(
        "SELECT l.location_id, l.display_name, l.kind,
                l.device_id, d.display_name,
                COALESCE(l.site_id, d.current_site_id), s.display_name,
                COALESCE(d.expected_availability, l.expected_availability),
                COUNT(DISTINCT so.object_id), MIN(so.effective_observation_utc_ms),
                (SELECT MAX(sr.finished_time_utc_ms) FROM scan_runs sr
                 WHERE sr.location_id = l.location_id AND sr.status = 'complete'
                   AND sr.scan_mode = 'complete'),
                (SELECT ai.repo_path_display FROM annex_imports ai
                 WHERE ai.location_id = l.location_id
                 ORDER BY ai.import_id DESC LIMIT 1),
                (SELECT c.display_name FROM annex_imports ai
                 JOIN collections c ON c.collection_id = ai.collection_id
                 WHERE ai.location_id = l.location_id
                 ORDER BY ai.import_id DESC LIMIT 1)
         FROM stale_location_objects so
         JOIN locations l ON l.location_id = so.location_id AND l.status = 'active'
         LEFT JOIN devices d ON d.device_id = l.device_id
         LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
         GROUP BY l.location_id, l.display_name, l.kind, l.device_id, d.display_name,
                  COALESCE(l.site_id, d.current_site_id), s.display_name,
                  COALESCE(d.expected_availability, l.expected_availability)
         ORDER BY l.location_id",
    )?;
    let rows = statement.query_map([], stale_location_from_row)?.collect();
    rows
}

fn merge_unresolved_location_counts(
    connection: &Connection,
    locations: &mut BTreeMap<String, StaleLocationRow>,
) -> rusqlite::Result<()> {
    let mut statement = connection.prepare(
        "SELECT l.location_id, l.display_name, l.kind,
                l.device_id, d.display_name,
                COALESCE(l.site_id, d.current_site_id), s.display_name,
                COALESCE(d.expected_availability, l.expected_availability),
                COUNT(DISTINCT CASE WHEN a.state = 'present' THEN a.external_identity_id END),
                COUNT(DISTINCT CASE WHEN a.state = 'missing' THEN a.external_identity_id END),
                COUNT(DISTINCT CASE WHEN a.state = 'unknown' THEN a.external_identity_id END),
                (SELECT MAX(sr.finished_time_utc_ms) FROM scan_runs sr
                 WHERE sr.location_id = l.location_id AND sr.status = 'complete'
                   AND sr.scan_mode = 'complete'),
                (SELECT ai.repo_path_display FROM annex_imports ai
                 WHERE ai.location_id = l.location_id
                 ORDER BY ai.import_id DESC LIMIT 1),
                (SELECT c.display_name FROM annex_imports ai
                 JOIN collections c ON c.collection_id = ai.collection_id
                 WHERE ai.location_id = l.location_id
                 ORDER BY ai.import_id DESC LIMIT 1)
         FROM external_availability a
         JOIN external_identities x USING(external_identity_id)
         JOIN locations l ON l.location_id = a.location_id AND l.status = 'active'
         LEFT JOIN devices d ON d.device_id = l.device_id
         LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
         WHERE x.resolution_state != 'resolved'
           AND a.state IN ('present', 'missing', 'unknown')
           AND EXISTS (
             SELECT 1 FROM file_refs f
             JOIN stale_selected_collections c ON c.collection_id = f.collection_id
             WHERE f.external_identity_id = a.external_identity_id
               AND f.path_state = 'active'
           )
         GROUP BY l.location_id, l.display_name, l.kind, l.device_id, d.display_name,
                  COALESCE(l.site_id, d.current_site_id), s.display_name,
                  COALESCE(d.expected_availability, l.expected_availability)
         ORDER BY l.location_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let kind: String = row.get(2)?;
            let device_id = row.get(3)?;
            let device_name = row.get(4)?;
            let site_id = row.get(5)?;
            let site_name = row.get(6)?;
            let expected_availability = row.get(7)?;
            let present = unsigned(row.get(8)?);
            let missing = unsigned(row.get(9)?);
            let unknown = unsigned(row.get(10)?);
            let last_complete = optional_u64(row.get(11)?);
            let repo_path: Option<String> = row.get(12)?;
            let collection_name: Option<String> = row.get(13)?;
            Ok((
                id,
                name,
                kind,
                device_id,
                device_name,
                site_id,
                site_name,
                expected_availability,
                present,
                missing,
                unknown,
                last_complete,
                repo_path,
                collection_name,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (
        id,
        name,
        kind,
        device_id,
        device_name,
        site_id,
        site_name,
        expected_availability,
        present,
        missing,
        unknown,
        last_complete,
        repo_path,
        collection_name,
    ) in rows
    {
        let entry = locations
            .entry(id.clone())
            .or_insert_with(|| StaleLocationRow {
                location: StalePresenceLocation {
                    location_id: id,
                    location_name: name.clone(),
                    location_kind: kind,
                    stale_object_count: 0,
                    unresolved_present_count: 0,
                    unresolved_missing_count: 0,
                    unresolved_unknown_count: 0,
                    oldest_positive_observation_utc_ms: None,
                    last_complete_inventory_utc_ms: last_complete,
                    suggested_action: suggested_location_action(
                        &name,
                        repo_path.as_deref(),
                        collection_name.as_deref(),
                    ),
                },
                device_id,
                device_name,
                site_id,
                site_name,
                expected_availability,
            });
        entry.location.unresolved_present_count = present;
        entry.location.unresolved_missing_count = missing;
        entry.location.unresolved_unknown_count = unknown;
    }
    Ok(())
}

fn stale_location_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, StaleLocationRow)> {
    let id: String = row.get(0)?;
    let name: String = row.get(1)?;
    let repo_path: Option<String> = row.get(11)?;
    let collection_name: Option<String> = row.get(12)?;
    Ok((
        id.clone(),
        StaleLocationRow {
            location: StalePresenceLocation {
                location_id: id,
                location_name: name.clone(),
                location_kind: row.get(2)?,
                stale_object_count: unsigned(row.get(8)?),
                unresolved_present_count: 0,
                unresolved_missing_count: 0,
                unresolved_unknown_count: 0,
                oldest_positive_observation_utc_ms: optional_u64(row.get(9)?),
                last_complete_inventory_utc_ms: optional_u64(row.get(10)?),
                suggested_action: suggested_location_action(
                    &name,
                    repo_path.as_deref(),
                    collection_name.as_deref(),
                ),
            },
            device_id: row.get(3)?,
            device_name: row.get(4)?,
            site_id: row.get(5)?,
            site_name: row.get(6)?,
            expected_availability: row.get(7)?,
        },
    ))
}

fn suggested_location_action(
    location_name: &str,
    annex_repo_path: Option<&str>,
    annex_collection_name: Option<&str>,
) -> String {
    match (annex_repo_path, annex_collection_name) {
        (Some(path), Some(collection)) => {
            format!("cd {path:?} && archive location import-annex --collection {collection:?}")
        }
        _ => format!("archive location scan {location_name:?}"),
    }
}

fn stale_device_counts(
    connection: &Connection,
) -> rusqlite::Result<BTreeMap<String, DeviceCounts>> {
    let mut statement = connection.prepare(
        "SELECT COALESCE(l.device_id, 'service:' || l.location_id),
                COUNT(DISTINCT so.object_id)
         FROM stale_location_objects so
         JOIN locations l ON l.location_id = so.location_id AND l.status = 'active'
         GROUP BY COALESCE(l.device_id, 'service:' || l.location_id)",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                DeviceCounts {
                    stale: unsigned(row.get(1)?),
                    unresolved_present: 0,
                    unresolved_missing: 0,
                    unresolved_unknown: 0,
                },
            ))
        })?
        .collect();
    rows
}

fn merge_unresolved_device_counts(
    connection: &Connection,
    devices: &mut BTreeMap<String, DeviceCounts>,
) -> rusqlite::Result<()> {
    let mut statement = connection.prepare(
        "SELECT COALESCE(l.device_id, 'service:' || l.location_id),
                COUNT(DISTINCT CASE WHEN a.state = 'present' THEN a.external_identity_id END),
                COUNT(DISTINCT CASE WHEN a.state = 'missing' THEN a.external_identity_id END),
                COUNT(DISTINCT CASE WHEN a.state = 'unknown' THEN a.external_identity_id END)
         FROM external_availability a
         JOIN external_identities x USING(external_identity_id)
         JOIN locations l ON l.location_id = a.location_id AND l.status = 'active'
         WHERE x.resolution_state != 'resolved'
           AND a.state IN ('present', 'missing', 'unknown')
           AND EXISTS (
             SELECT 1 FROM file_refs f
             JOIN stale_selected_collections c ON c.collection_id = f.collection_id
             WHERE f.external_identity_id = a.external_identity_id
               AND f.path_state = 'active'
           )
         GROUP BY COALESCE(l.device_id, 'service:' || l.location_id)",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                unsigned(row.get(1)?),
                unsigned(row.get(2)?),
                unsigned(row.get(3)?),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (key, present, missing, unknown) in rows {
        let entry = devices.entry(key).or_insert(DeviceCounts {
            stale: 0,
            unresolved_present: 0,
            unresolved_missing: 0,
            unresolved_unknown: 0,
        });
        entry.unresolved_present = present;
        entry.unresolved_missing = missing;
        entry.unresolved_unknown = unknown;
    }
    Ok(())
}

fn integer(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
