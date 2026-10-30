//! Registry mutations committed directly with their audit history and revision.
use std::path::Path;

use rusqlite::{params, Connection, ToSql, Transaction, TransactionBehavior};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use crate::registry::{
    load_registry_entities, registry_path_bytes, validate_change_on, ArchiveRootSnapshot,
    CollectionSnapshot, DeviceSnapshot, LocationSnapshot, PolicySnapshot, RegistryAction,
    RegistryChange, RegistryError, RiskAssignment, RiskDomainSnapshot, SiteSnapshot,
};
use crate::sqlite_catalog::SqliteCatalog;

#[derive(Debug, Error)]
pub enum SqliteRegistryError {
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("catalog registry database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cannot serialize registry history: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid registry change: {0}")]
    Invalid(String),
}
impl SqliteRegistryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Registry(error) => error.code(),
            Self::Sqlite(_) => "registry_sqlite",
            Self::Json(_) | Self::Invalid(_) => "registry_invalid",
        }
    }
}
type Result<T> = std::result::Result<T, SqliteRegistryError>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegistryCommit {
    pub revision: u64,
    pub history_id: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegistryBatchCommit {
    pub revision: u64,
    pub history_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SqliteRegistryState {
    pub revision: u64,
    pub sites: Vec<SiteSnapshot>,
    pub policies: Vec<PolicySnapshot>,
    pub collections: Vec<CollectionSnapshot>,
    pub devices: Vec<DeviceSnapshot>,
    pub archive_roots: Vec<ArchiveRootSnapshot>,
    pub locations: Vec<LocationSnapshot>,
    pub risk_domains: Vec<RiskDomainSnapshot>,
    pub risk_assignments: Vec<RiskAssignment>,
}

impl SqliteCatalog {
    pub fn registry_state(&self, include_retired: bool) -> Result<SqliteRegistryState> {
        let connection = self.connection();
        let transaction = connection.unchecked_transaction()?;
        let entities =
            load_registry_entities(&transaction, catalog_path(connection), include_retired)?;
        let revision: u64 = transaction.query_row(
            "SELECT revision FROM catalog_metadata WHERE singleton=1",
            [],
            revision_from_row,
        )?;
        Ok(SqliteRegistryState {
            revision,
            sites: entities.sites,
            policies: entities.policies,
            collections: entities.collections,
            devices: entities.devices,
            archive_roots: entities.archive_roots,
            locations: entities.locations,
            risk_domains: entities.risk_domains,
            risk_assignments: entities.risk_assignments,
        })
    }
}

pub struct SqliteRegistry<'a> {
    catalog: &'a mut SqliteCatalog,
}
impl<'a> SqliteRegistry<'a> {
    pub fn new(catalog: &'a mut SqliteCatalog) -> Self {
        Self { catalog }
    }

    pub fn record(
        &mut self,
        change: RegistryChange,
        host_id: &str,
        time_utc_ms: u64,
    ) -> Result<RegistryCommit> {
        let commit = self.record_batch(&[change], host_id, time_utc_ms)?;
        Ok(RegistryCommit {
            revision: commit.revision,
            history_id: commit.history_ids[0],
        })
    }

    /// Commit a nonempty setup/change batch atomically. Later changes can refer
    /// to entities created earlier in this batch; any failure rolls all back.
    pub fn record_batch(
        &mut self,
        changes: &[RegistryChange],
        host_id: &str,
        time_utc_ms: u64,
    ) -> Result<RegistryBatchCommit> {
        if changes.is_empty() {
            return Err(SqliteRegistryError::Invalid(
                "registry batch must not be empty".into(),
            ));
        }
        let time = integer(time_utc_ms)?;
        let path = catalog_path(self.catalog.connection()).to_path_buf();
        let transaction = self
            .catalog
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut history_ids = Vec::with_capacity(changes.len());
        for change in changes {
            validate_change_on(&transaction, &path, change)?;
            let (kind, snapshot) = apply(&transaction, change, host_id, time)?;
            let location = match change {
                RegistryChange::Location(_, v) => Some(v.location_id.as_str()),
                _ => None,
            };
            history_ids.push(append_history(
                &transaction,
                &kind,
                location,
                time,
                json!({"snapshot":snapshot,"host_id":host_id}),
            )?);
        }
        let revision = advance_revision(&transaction)?;
        transaction.commit()?;
        Ok(RegistryBatchCommit {
            revision,
            history_ids,
        })
    }

    pub fn rename_archive(&mut self, name: &str, time_utc_ms: u64) -> Result<RegistryCommit> {
        if name.trim().is_empty() {
            return Err(SqliteRegistryError::Invalid(
                "display name must not be empty".into(),
            ));
        }
        let time = integer(time_utc_ms)?;
        let transaction = self
            .catalog
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: String = transaction.query_row(
            "SELECT display_name FROM catalog_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        transaction.execute(
            "UPDATE catalog_metadata SET display_name=?1 WHERE singleton=1",
            [name],
        )?;
        let commit = finish(
            &transaction,
            "archive_renamed",
            None,
            time,
            json!({"previous_name":previous,"display_name":name}),
        )?;
        transaction.commit()?;
        Ok(commit)
    }
}

fn catalog_path(connection: &Connection) -> &Path {
    Path::new(connection.path().unwrap_or("<catalog>"))
}
fn integer(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| SqliteRegistryError::Invalid("integer exceeds SQLite range".into()))
}
fn revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<u64> {
    let value: i64 = row.get(0)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn finish(
    transaction: &Transaction<'_>,
    kind: &str,
    location: Option<&str>,
    time: i64,
    details: serde_json::Value,
) -> Result<RegistryCommit> {
    let history_id = append_history(transaction, kind, location, time, details)?;
    let revision = advance_revision(transaction)?;
    Ok(RegistryCommit {
        revision,
        history_id,
    })
}

fn append_history(
    transaction: &Transaction<'_>,
    kind: &str,
    location: Option<&str>,
    time: i64,
    details: serde_json::Value,
) -> Result<i64> {
    transaction.execute(
        "INSERT INTO history(location_id,time_utc_ms,kind,details_json) VALUES (?1,?2,?3,?4)",
        params![location, time, kind, serde_json::to_string(&details)?],
    )?;
    Ok(transaction.last_insert_rowid())
}
fn advance_revision(transaction: &Transaction<'_>) -> Result<u64> {
    Ok(transaction.query_row(
        "UPDATE catalog_metadata SET revision=revision+1 WHERE singleton=1 RETURNING revision",
        [],
        revision_from_row,
    )?)
}

// Table and column names are fixed by the typed match below, never user input.
fn upsert(
    transaction: &Transaction<'_>,
    table: &str,
    columns: &[&str],
    values: &[&dyn ToSql],
) -> Result<()> {
    let placeholders = (1..=columns.len())
        .map(|n| format!("?{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let updates = columns[1..]
        .iter()
        .map(|column| format!("{column}=excluded.{column}"))
        .collect::<Vec<_>>()
        .join(",");
    transaction.execute(&format!("INSERT INTO {table}({}) VALUES ({placeholders}) ON CONFLICT({}) DO UPDATE SET {updates}", columns.join(","), columns[0]), values)?;
    Ok(())
}
fn kind(entity: &str, action: RegistryAction) -> Result<String> {
    let suffix = match action {
        RegistryAction::Register => "registered",
        RegistryAction::Update => "updated",
        RegistryAction::Retire => "retired",
        RegistryAction::Move if entity == "device" => "moved",
        RegistryAction::Move => {
            return Err(SqliteRegistryError::Invalid("only Devices can move".into()))
        }
    };
    Ok(format!("{entity}_{suffix}"))
}

fn apply(
    transaction: &Transaction<'_>,
    change: &RegistryChange,
    host: &str,
    time: i64,
) -> Result<(String, serde_json::Value)> {
    let result = match change {
        RegistryChange::Site(action, v) => {
            let k = kind("site", *action)?;
            upsert(
                transaction,
                "sites",
                &[
                    "site_id",
                    "display_name",
                    "site_kind",
                    "description",
                    "status",
                ],
                &[
                    &v.site_id,
                    &v.display_name,
                    &v.site_kind,
                    &v.description,
                    &v.status,
                ],
            )?;
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::Policy(action, v) => {
            let k = kind("policy", *action)?;
            upsert(
                transaction,
                "policies",
                &[
                    "policy_id",
                    "display_name",
                    "policy_version",
                    "requirements_json",
                    "enabled",
                    "status",
                ],
                &[
                    &v.policy_id,
                    &v.display_name,
                    &integer(v.policy_version)?,
                    &serde_json::to_string(&v.requirements)?,
                    &v.enabled,
                    &v.status,
                ],
            )?;
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::Collection(action, v) => {
            let k = kind("collection", *action)?;
            upsert(
                transaction,
                "collections",
                &[
                    "collection_id",
                    "display_name",
                    "description",
                    "home_site_id",
                    "policy_id",
                    "status",
                ],
                &[
                    &v.collection_id,
                    &v.display_name,
                    &v.description,
                    &v.home_site_id,
                    &v.policy_id,
                    &v.status,
                ],
            )?;
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::Device(action, v) => {
            let k = kind("device", *action)?;
            upsert(
                transaction,
                "devices",
                &[
                    "device_id",
                    "display_name",
                    "device_kind",
                    "serial_hint",
                    "hardware_fingerprint",
                    "fingerprint_kind",
                    "identity_state",
                    "owner",
                    "status",
                    "current_site_id",
                    "expected_availability",
                ],
                &[
                    &v.device_id,
                    &v.display_name,
                    &v.device_kind,
                    &v.serial_hint,
                    &v.hardware_fingerprint,
                    &v.fingerprint_kind,
                    &v.identity_state,
                    &v.owner,
                    &v.status,
                    &v.current_site_id,
                    &v.expected_availability,
                ],
            )?;
            if *action == RegistryAction::Move {
                transaction.execute("UPDATE device_site_history SET departed_time_utc_ms=?2 WHERE device_id=?1 AND departed_time_utc_ms IS NULL",params![v.device_id,time])?;
            }
            if matches!(action, RegistryAction::Register | RegistryAction::Move)
                && v.current_site_id.is_some()
            {
                transaction.execute("INSERT INTO device_site_history(device_id,site_id,arrived_time_utc_ms) VALUES (?1,?2,?3)",params![v.device_id,v.current_site_id,time])?;
            }
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::ArchiveRoot(action, v) => {
            let k = kind("archive_root", *action)?;
            // Root identity is immutable, including when retiring its snapshot.
            transaction.execute(
                "INSERT INTO archive_roots(archive_root_id,device_id,display_name,filesystem_fingerprint,fingerprint_kind,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status,last_seen_time_utc_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                 ON CONFLICT(archive_root_id) DO UPDATE SET display_name=excluded.display_name,status=excluded.status,last_seen_time_utc_ms=excluded.last_seen_time_utc_ms",
                params![v.archive_root_id,v.device_id,v.display_name,v.filesystem_fingerprint,v.fingerprint_kind,v.identity_state,registry_path_bytes(&v.root_path_on_device)?,v.root_path_on_device.encoding,v.root_path_on_device.display,v.status,time],
            )?;
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::Location(action, v) => {
            let k = kind("location", *action)?;
            let bytes = v
                .relative_path
                .as_ref()
                .map(registry_path_bytes)
                .transpose()?;
            let encoding = v.relative_path.as_ref().map(|p| p.encoding.as_str());
            let display = v.relative_path.as_ref().map(|p| p.display.as_str());
            upsert(
                transaction,
                "locations",
                &[
                    "location_id",
                    "display_name",
                    "kind",
                    "archive_root_id",
                    "relative_path_bytes",
                    "relative_path_encoding",
                    "relative_path_display",
                    "device_id",
                    "site_id",
                    "encryption_state",
                    "trust_level",
                    "expected_availability",
                    "is_writable",
                    "status",
                ],
                &[
                    &v.location_id,
                    &v.display_name,
                    &v.kind,
                    &v.archive_root_id,
                    &bytes,
                    &encoding,
                    &display,
                    &v.device_id,
                    &v.site_id,
                    &v.encryption_state,
                    &v.trust_level,
                    &v.expected_availability,
                    &v.is_writable,
                    &v.status,
                ],
            )?;
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::RiskDomain(action, v) => {
            let k = kind("risk_domain", *action)?;
            upsert(
                transaction,
                "risk_domains",
                &[
                    "risk_domain_id",
                    "display_name",
                    "risk_kind",
                    "description",
                    "status",
                ],
                &[
                    &v.risk_domain_id,
                    &v.display_name,
                    &v.risk_kind,
                    &v.description,
                    &v.status,
                ],
            )?;
            (k, serde_json::to_value(v)?)
        }
        RegistryChange::AssignRisk(v) | RegistryChange::UnassignRisk(v) => {
            let assign = matches!(change, RegistryChange::AssignRisk(_));
            let sql = if assign {
                "INSERT INTO entity_risk_domains(entity_type,entity_id,risk_domain_id) VALUES (?1,?2,?3)"
            } else {
                "DELETE FROM entity_risk_domains WHERE entity_type=?1 AND entity_id=?2 AND risk_domain_id=?3"
            };
            transaction.execute(sql, params![v.entity_type, v.entity_id, v.risk_domain_id])?;
            (
                if assign {
                    "risk_assigned"
                } else {
                    "risk_unassigned"
                }
                .into(),
                serde_json::to_value(v)?,
            )
        }
        RegistryChange::DeviceCheckIn(v) => {
            transaction.execute("UPDATE devices SET last_checkin_time_utc_ms=?2,last_fingerprint_match_time_utc_ms=CASE WHEN ?3='match' THEN ?2 ELSE last_fingerprint_match_time_utc_ms END,last_fingerprint_status=?3 WHERE device_id=?1",params![v.device_id,time,v.fingerprint_status])?;
            ("device_checked_in".into(), serde_json::to_value(v)?)
        }
        RegistryChange::DeviceMount(v) => {
            if host.trim().is_empty() {
                return Err(SqliteRegistryError::Invalid(
                    "host ID must not be empty".into(),
                ));
            }
            transaction.execute("INSERT INTO device_mounts(mount_id,device_id,archive_root_id,host_id,mount_root_uri,status,fingerprint_status,observed_time_utc_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![v.mount_id,v.device_id,v.archive_root_id,host,v.mount_root_uri,v.status,v.fingerprint_status,time])?;
            ("device_mount_observed".into(), serde_json::to_value(v)?)
        }
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{DeviceCheckIn, DeviceMount, RegistryPath};
    use tempfile::TempDir;

    fn site(id: &str) -> SiteSnapshot {
        SiteSnapshot {
            site_id: id.into(),
            display_name: id.into(),
            site_kind: "home".into(),
            description: None,
            status: "active".into(),
        }
    }
    fn device() -> DeviceSnapshot {
        serde_json::from_value(json!({"device_id":"disk","display_name":"Disk","device_kind":"external","serial_hint":null,"hardware_fingerprint":null,"fingerprint_kind":null,"identity_state":"unavailable","owner":null,"status":"active","current_site_id":"home","expected_availability":"offline"})).unwrap()
    }
    fn record(catalog: &mut SqliteCatalog, change: RegistryChange, time: u64) -> RegistryCommit {
        SqliteRegistry::new(catalog)
            .record(change, "host", time)
            .unwrap()
    }
    #[test]
    fn registry_lifecycle_mount_checkin_and_move_commit_with_history() {
        let temp = TempDir::new().unwrap();
        let mut catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        record(
            &mut catalog,
            RegistryChange::Site(RegistryAction::Register, site("home")),
            1,
        );
        record(
            &mut catalog,
            RegistryChange::Site(RegistryAction::Register, site("away")),
            2,
        );
        record(
            &mut catalog,
            RegistryChange::Collection(
                RegistryAction::Register,
                CollectionSnapshot {
                    collection_id: "collection".into(),
                    display_name: "Files".into(),
                    description: None,
                    home_site_id: Some("home".into()),
                    policy_id: None,
                    status: "active".into(),
                },
            ),
            3,
        );
        record(
            &mut catalog,
            RegistryChange::Device(RegistryAction::Register, device()),
            4,
        );
        let root = ArchiveRootSnapshot {
            archive_root_id: "root".into(),
            device_id: "disk".into(),
            display_name: "Root".into(),
            root_path_on_device: RegistryPath::utf8("."),
            status: "active".into(),
            filesystem_fingerprint: None,
            fingerprint_kind: None,
            identity_state: "unavailable".into(),
        };
        record(
            &mut catalog,
            RegistryChange::ArchiveRoot(RegistryAction::Register, root),
            5,
        );
        let location = LocationSnapshot {
            location_id: "location".into(),
            display_name: "Location".into(),
            kind: "filesystem".into(),
            archive_root_id: Some("root".into()),
            relative_path: Some(RegistryPath::utf8("files")),
            device_id: Some("disk".into()),
            site_id: None,
            encryption_state: Some("unknown".into()),
            trust_level: Some("trusted".into()),
            expected_availability: "offline".into(),
            is_writable: false,
            status: "active".into(),
        };
        record(
            &mut catalog,
            RegistryChange::Location(RegistryAction::Register, location.clone()),
            6,
        );
        record(
            &mut catalog,
            RegistryChange::DeviceCheckIn(DeviceCheckIn {
                device_id: "disk".into(),
                fingerprint_status: "match".into(),
            }),
            7,
        );
        record(
            &mut catalog,
            RegistryChange::DeviceCheckIn(DeviceCheckIn {
                device_id: "disk".into(),
                fingerprint_status: "mismatch".into(),
            }),
            8,
        );
        record(
            &mut catalog,
            RegistryChange::DeviceMount(DeviceMount {
                mount_id: "mount".into(),
                device_id: "disk".into(),
                archive_root_id: Some("root".into()),
                mount_root_uri: "/mnt/disk".into(),
                status: "mounted".into(),
                fingerprint_status: "match".into(),
            }),
            9,
        );
        let mut moved = device();
        moved.current_site_id = Some("away".into());
        record(
            &mut catalog,
            RegistryChange::Device(RegistryAction::Move, moved),
            10,
        );
        let mut retired = location;
        retired.status = "retired".into();
        record(
            &mut catalog,
            RegistryChange::Location(RegistryAction::Retire, retired),
            11,
        );
        let renamed = SqliteRegistry::new(&mut catalog)
            .rename_archive("Renamed", 12)
            .unwrap();
        assert_eq!(renamed.revision, 12);
        assert_eq!(catalog.metadata().unwrap().display_name, "Renamed");
        let state = catalog.registry_state(false).unwrap();
        assert_eq!(state.revision, 12);
        assert!(state.locations.is_empty());
        assert_eq!(catalog.registry_state(true).unwrap().locations.len(), 1);
        assert_eq!(state.devices[0].current_site_id.as_deref(), Some("away"));
        let checks:(i64,i64,String)=catalog.connection().query_row("SELECT last_checkin_time_utc_ms,last_fingerprint_match_time_utc_ms,last_fingerprint_status FROM devices",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(checks, (8, 7, "mismatch".into()));
        let history:Vec<(String,i64,Option<i64>)>=catalog.connection().prepare("SELECT site_id,arrived_time_utc_ms,departed_time_utc_ms FROM device_site_history ORDER BY arrived_time_utc_ms").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<std::result::Result<_,_>>().unwrap();
        assert_eq!(
            history,
            vec![("home".into(), 4, Some(10)), ("away".into(), 10, None)]
        );
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            12
        );
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT host_id FROM device_mounts", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "host"
        );
    }

    #[test]
    fn invalid_change_and_history_failure_roll_back_registry_and_revision() {
        let temp = TempDir::new().unwrap();
        let mut catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        record(
            &mut catalog,
            RegistryChange::Site(RegistryAction::Register, site("home")),
            1,
        );
        let before = catalog.registry_state(true).unwrap();
        assert!(SqliteRegistry::new(&mut catalog)
            .record(
                RegistryChange::Site(RegistryAction::Register, site("home")),
                "host",
                2
            )
            .is_err());
        assert_eq!(catalog.registry_state(true).unwrap(), before);
        catalog.connection().execute_batch("CREATE TRIGGER fail_history BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT,'history unavailable'); END;").unwrap();
        let mut changed = site("home");
        changed.display_name = "New name".into();
        assert!(SqliteRegistry::new(&mut catalog)
            .record(
                RegistryChange::Site(RegistryAction::Update, changed),
                "host",
                3
            )
            .is_err());
        assert!(SqliteRegistry::new(&mut catalog)
            .rename_archive("Not committed", 4)
            .is_err());
        assert_eq!(catalog.registry_state(true).unwrap(), before);
        assert_eq!(catalog.metadata().unwrap().display_name, "Archive");
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn setup_batch_validates_against_its_own_writes_and_rolls_back_on_late_error() {
        let temp = TempDir::new().unwrap();
        let mut catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        let mut changes = vec![
            RegistryChange::Site(RegistryAction::Register, site("home")),
            RegistryChange::Device(RegistryAction::Register, device()),
        ];
        // A duplicate after valid dependent inserts must undo both and their audit rows.
        changes.push(RegistryChange::Site(RegistryAction::Register, site("home")));
        assert!(SqliteRegistry::new(&mut catalog)
            .record_batch(&changes, "host", 1)
            .is_err());
        let state = catalog.registry_state(true).unwrap();
        assert!(state.sites.is_empty() && state.devices.is_empty());
        assert_eq!(state.revision, 0);
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        changes.pop();
        let result = SqliteRegistry::new(&mut catalog)
            .record_batch(&changes, "host", 2)
            .unwrap();
        assert_eq!(result.revision, 1);
        assert_eq!(result.history_ids.len(), 2);
        let state = catalog.registry_state(true).unwrap();
        assert_eq!((state.sites.len(), state.devices.len()), (1, 1));
        assert_eq!(state.devices[0].current_site_id.as_deref(), Some("home"));
    }

    #[test]
    fn immediate_write_lock_precedes_validation_and_leaves_no_partial_change() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("catalog.db");
        let mut catalog = SqliteCatalog::create(&path, "arc", "Archive").unwrap();
        catalog
            .connection()
            .busy_timeout(std::time::Duration::ZERO)
            .unwrap();
        let mut other = Connection::open(&path).unwrap();
        let lock = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = SqliteRegistry::new(&mut catalog)
            .record(
                RegistryChange::Site(RegistryAction::Register, site("home")),
                "host",
                1,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SqliteRegistryError::Sqlite(rusqlite::Error::SqliteFailure(_, _))
        ));
        drop(lock);
        assert!(catalog.registry_state(true).unwrap().sites.is_empty());
        assert_eq!(catalog.metadata().unwrap().revision, 0);
    }
}
