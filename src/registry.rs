//! Typed full-snapshot contracts and canonical registry mutation service.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::event_store::{EventReferences, EventRequest, EventStore, EventStoreError};
use crate::policy::PolicyRequirements;
use crate::projection::{ProjectionDb, ProjectionError};

pub type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    EventStore(#[from] EventStoreError),
    #[error(transparent)]
    Projection(#[from] ProjectionError),
    #[error("SQLite operation failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("invalid registry change: {0}")]
    Invalid(String),
    #[error("{kind} already exists: {id}")]
    AlreadyExists { kind: &'static str, id: String },
    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },
}

impl RegistryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EventStore(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Sqlite { .. } => "registry_sqlite",
            Self::Invalid(_) => "registry_invalid",
            Self::AlreadyExists { .. } => "already_exists",
            Self::NotFound { .. } => "not_found",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryAction {
    Register,
    Update,
    Move,
    Retire,
}

#[derive(Debug, Clone)]
pub enum RegistryChange {
    Site(RegistryAction, SiteSnapshot),
    Policy(RegistryAction, PolicySnapshot),
    Collection(RegistryAction, CollectionSnapshot),
    Device(RegistryAction, DeviceSnapshot),
    ArchiveRoot(RegistryAction, ArchiveRootSnapshot),
    Location(RegistryAction, LocationSnapshot),
    RiskDomain(RegistryAction, RiskDomainSnapshot),
    AssignRisk(RiskAssignment),
    UnassignRisk(RiskAssignment),
    DeviceCheckIn(DeviceCheckIn),
    DeviceMount(DeviceMount),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryMutationResult {
    pub version: u32,
    pub event_id: String,
    pub event_seq: u64,
    pub applied_event_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryState {
    pub version: u32,
    pub applied_event_seq: u64,
    pub sites: Vec<SiteSnapshot>,
    pub policies: Vec<PolicySnapshot>,
    pub collections: Vec<CollectionSnapshot>,
    pub devices: Vec<DeviceSnapshot>,
    pub archive_roots: Vec<ArchiveRootSnapshot>,
    pub locations: Vec<LocationSnapshot>,
    pub risk_domains: Vec<RiskDomainSnapshot>,
    pub risk_assignments: Vec<RiskAssignment>,
}

pub struct Registry<'a> {
    events: &'a EventStore,
    projection: &'a ProjectionDb,
}

impl<'a> Registry<'a> {
    pub fn new(events: &'a EventStore, projection: &'a ProjectionDb) -> Self {
        Self { events, projection }
    }

    pub fn record(&self, change: RegistryChange) -> Result<RegistryMutationResult> {
        self.projection.apply(self.events)?;
        validate_change(self.projection.path(), &change)?;
        let (event_type, payload, references) = event_parts(change)?;
        let record = self
            .events
            .append(EventRequest::new(event_type, payload).with_references(references))?;
        self.projection.apply(self.events)?;
        let applied_event_seq = self.projection.status()?.cursor.applied_seq;
        if applied_event_seq < record.envelope.seq {
            return Err(RegistryError::Invalid(
                "the registry event was durable but was not projected".to_owned(),
            ));
        }
        Ok(RegistryMutationResult {
            version: 1,
            event_id: record.envelope.event_id,
            event_seq: record.envelope.seq,
            applied_event_seq,
        })
    }
}

impl ProjectionDb {
    pub fn registry_state(&self, include_retired: bool) -> Result<RegistryState> {
        let applied_event_seq = self.status()?.cursor.applied_seq;
        let connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        let status = (!include_retired).then_some("active");
        let sites = query_rows(
            &connection,
            "SELECT site_id, display_name, site_kind, description, status
             FROM sites WHERE (?1 IS NULL OR status = ?1) ORDER BY display_name, site_id",
            status,
            |row| {
                Ok(SiteSnapshot {
                    site_id: row.get(0)?,
                    display_name: row.get(1)?,
                    site_kind: row.get(2)?,
                    description: row.get(3)?,
                    status: row.get(4)?,
                })
            },
            self.path(),
        )?;
        let policies = query_rows(
            &connection,
            "SELECT policy_id, display_name, policy_version, requirements_json, enabled, status
             FROM policies WHERE (?1 IS NULL OR status = ?1) ORDER BY display_name, policy_id",
            status,
            |row| {
                let id: String = row.get(0)?;
                let requirements: String = row.get(3)?;
                let requirements = serde_json::from_str(&requirements).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(PolicySnapshot {
                    policy_id: id,
                    display_name: row.get(1)?,
                    policy_version: u64::try_from(row.get::<_, i64>(2)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    requirements,
                    enabled: row.get(4)?,
                    status: row.get(5)?,
                })
            },
            self.path(),
        )?;
        let collections = query_rows(
            &connection,
            "SELECT collection_id, display_name, description, home_site_id, policy_id, status
             FROM collections WHERE (?1 IS NULL OR status = ?1) ORDER BY display_name, collection_id",
            status,
            |row| {
                Ok(CollectionSnapshot {
                    collection_id: row.get(0)?,
                    display_name: row.get(1)?,
                    description: row.get(2)?,
                    home_site_id: row.get(3)?,
                    policy_id: row.get(4)?,
                    status: row.get(5)?,
                })
            },
            self.path(),
        )?;
        let devices = query_rows(
            &connection,
            "SELECT device_id, display_name, device_kind, serial_hint, hardware_fingerprint,
                    fingerprint_kind, identity_state, owner, status, current_site_id,
                    expected_availability
             FROM devices WHERE (?1 IS NULL OR status = ?1) ORDER BY display_name, device_id",
            status,
            |row| {
                Ok(DeviceSnapshot {
                    device_id: row.get(0)?,
                    display_name: row.get(1)?,
                    device_kind: row.get(2)?,
                    serial_hint: row.get(3)?,
                    hardware_fingerprint: row.get(4)?,
                    fingerprint_kind: row.get(5)?,
                    identity_state: row.get(6)?,
                    owner: row.get(7)?,
                    status: row.get(8)?,
                    current_site_id: row.get(9)?,
                    expected_availability: row.get(10)?,
                })
            },
            self.path(),
        )?;
        let archive_roots = query_rows(
            &connection,
            "SELECT archive_root_id, device_id, display_name, root_path_encoding,
                    root_path_on_device_bytes, root_path_display, status
             FROM archive_roots WHERE (?1 IS NULL OR status = ?1)
             ORDER BY display_name, archive_root_id",
            status,
            |row| {
                Ok(ArchiveRootSnapshot {
                    archive_root_id: row.get(0)?,
                    device_id: row.get(1)?,
                    display_name: row.get(2)?,
                    root_path_on_device: registry_path_from_row(row, 3, 4, 5)?,
                    status: row.get(6)?,
                })
            },
            self.path(),
        )?;
        let locations = query_rows(
            &connection,
            "SELECT location_id, display_name, kind, archive_root_id,
                    relative_path_encoding, relative_path_bytes, relative_path_display,
                    device_id, site_id, encryption_state, trust_level,
                    expected_availability, is_writable, status
             FROM locations WHERE (?1 IS NULL OR status = ?1)
             ORDER BY display_name, location_id",
            status,
            |row| {
                let encoding: Option<String> = row.get(4)?;
                Ok(LocationSnapshot {
                    location_id: row.get(0)?,
                    display_name: row.get(1)?,
                    kind: row.get(2)?,
                    archive_root_id: row.get(3)?,
                    relative_path: encoding
                        .map(|encoding| {
                            registry_path_from_parts(encoding, row.get(5)?, row.get(6)?)
                        })
                        .transpose()?,
                    device_id: row.get(7)?,
                    site_id: row.get(8)?,
                    encryption_state: row.get(9)?,
                    trust_level: row.get(10)?,
                    expected_availability: row.get(11)?,
                    is_writable: row.get(12)?,
                    status: row.get(13)?,
                })
            },
            self.path(),
        )?;
        let risk_domains = query_rows(
            &connection,
            "SELECT risk_domain_id, display_name, risk_kind, description, status
             FROM risk_domains WHERE (?1 IS NULL OR status = ?1)
             ORDER BY display_name, risk_domain_id",
            status,
            |row| {
                Ok(RiskDomainSnapshot {
                    risk_domain_id: row.get(0)?,
                    display_name: row.get(1)?,
                    risk_kind: row.get(2)?,
                    description: row.get(3)?,
                    status: row.get(4)?,
                })
            },
            self.path(),
        )?;
        let risk_assignments = query_rows(
            &connection,
            "SELECT entity_type, entity_id, risk_domain_id FROM entity_risk_domains
             WHERE ?1 IS NULL
             ORDER BY entity_type, entity_id, risk_domain_id",
            None,
            |row| {
                Ok(RiskAssignment {
                    entity_type: row.get(0)?,
                    entity_id: row.get(1)?,
                    risk_domain_id: row.get(2)?,
                })
            },
            self.path(),
        )?;
        Ok(RegistryState {
            version: 1,
            applied_event_seq,
            sites,
            policies,
            collections,
            devices,
            archive_roots,
            locations,
            risk_domains,
            risk_assignments,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryPath {
    pub encoding: String,
    pub text: Option<String>,
    pub base64: Option<String>,
    pub display: String,
}

impl RegistryPath {
    pub fn utf8(value: impl Into<String>) -> Self {
        let value = value.into();
        Self {
            encoding: "utf8".to_owned(),
            display: value.clone(),
            text: Some(value),
            base64: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiteSnapshot {
    pub site_id: String,
    pub display_name: String,
    pub site_kind: String,
    pub description: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshot {
    pub policy_id: String,
    pub display_name: String,
    pub policy_version: u64,
    pub requirements: PolicyRequirements,
    pub enabled: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSnapshot {
    pub collection_id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub home_site_id: Option<String>,
    pub policy_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceSnapshot {
    pub device_id: String,
    pub display_name: String,
    pub device_kind: String,
    pub serial_hint: Option<String>,
    pub hardware_fingerprint: Option<String>,
    pub fingerprint_kind: Option<String>,
    pub identity_state: String,
    pub owner: Option<String>,
    pub status: String,
    pub current_site_id: Option<String>,
    pub expected_availability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRootSnapshot {
    pub archive_root_id: String,
    pub device_id: String,
    pub display_name: String,
    pub root_path_on_device: RegistryPath,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocationSnapshot {
    pub location_id: String,
    pub display_name: String,
    pub kind: String,
    pub archive_root_id: Option<String>,
    pub relative_path: Option<RegistryPath>,
    pub device_id: Option<String>,
    pub site_id: Option<String>,
    pub encryption_state: Option<String>,
    pub trust_level: Option<String>,
    pub expected_availability: String,
    pub is_writable: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RiskDomainSnapshot {
    pub risk_domain_id: String,
    pub display_name: String,
    pub risk_kind: String,
    pub description: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RiskAssignment {
    pub entity_type: String,
    pub entity_id: String,
    pub risk_domain_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceCheckIn {
    pub device_id: String,
    pub fingerprint_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceMount {
    pub mount_id: String,
    pub device_id: String,
    pub mount_root_uri: String,
    pub status: String,
    pub fingerprint_status: String,
}

fn query_rows<T, F>(
    connection: &Connection,
    sql: &str,
    status: Option<&str>,
    map: F,
    path: &Path,
) -> Result<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut statement = connection
        .prepare(sql)
        .map_err(|source| sqlite_error(path, source))?;
    let rows = statement
        .query_map([status], map)
        .map_err(|source| sqlite_error(path, source))?;
    let collected = rows.collect::<rusqlite::Result<Vec<_>>>();
    collected.map_err(|source| sqlite_error(path, source))
}

fn registry_path_from_row(
    row: &rusqlite::Row<'_>,
    encoding: usize,
    bytes: usize,
    display: usize,
) -> rusqlite::Result<RegistryPath> {
    registry_path_from_parts(row.get(encoding)?, row.get(bytes)?, row.get(display)?)
}

fn registry_path_from_parts(
    encoding: String,
    bytes: Vec<u8>,
    display: String,
) -> rusqlite::Result<RegistryPath> {
    if encoding == "utf8" {
        let text = String::from_utf8(bytes).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?;
        Ok(RegistryPath {
            encoding,
            text: Some(text),
            base64: None,
            display,
        })
    } else {
        Ok(RegistryPath {
            encoding,
            text: None,
            base64: Some(STANDARD.encode(bytes)),
            display,
        })
    }
}

fn event_parts(change: RegistryChange) -> Result<(&'static str, Value, EventReferences)> {
    match change {
        RegistryChange::Site(action, value) => {
            let references = EventReferences {
                site_id: Some(value.site_id.clone()),
                ..EventReferences::default()
            };
            Ok((
                lifecycle_event("site", action),
                serialize_payload(value)?,
                references,
            ))
        }
        RegistryChange::Policy(action, value) => Ok((
            lifecycle_event("policy", action),
            serialize_payload(&value)?,
            EventReferences::default(),
        )),
        RegistryChange::Collection(action, value) => Ok((
            lifecycle_event("collection", action),
            serialize_payload(&value)?,
            EventReferences {
                site_id: value.home_site_id.clone(),
                ..EventReferences::default()
            },
        )),
        RegistryChange::Device(action, value) => Ok((
            if action == RegistryAction::Move {
                "device_moved"
            } else if action == RegistryAction::Update {
                "device_updated"
            } else {
                lifecycle_event("device", action)
            },
            serialize_payload(&value)?,
            EventReferences {
                device_id: Some(value.device_id),
                site_id: value.current_site_id,
                ..EventReferences::default()
            },
        )),
        RegistryChange::ArchiveRoot(action, value) => Ok((
            lifecycle_event("archive_root", action),
            serialize_payload(&value)?,
            EventReferences {
                device_id: Some(value.device_id),
                ..EventReferences::default()
            },
        )),
        RegistryChange::Location(action, value) => Ok((
            lifecycle_event("location", action),
            serialize_payload(&value)?,
            EventReferences {
                location_id: Some(value.location_id),
                device_id: value.device_id,
                site_id: value.site_id,
                ..EventReferences::default()
            },
        )),
        RegistryChange::RiskDomain(action, value) => Ok((
            lifecycle_event("risk_domain", action),
            serialize_payload(value)?,
            EventReferences::default(),
        )),
        RegistryChange::AssignRisk(value) => Ok((
            "risk_assigned",
            serialize_payload(value)?,
            EventReferences::default(),
        )),
        RegistryChange::UnassignRisk(value) => Ok((
            "risk_unassigned",
            serialize_payload(value)?,
            EventReferences::default(),
        )),
        RegistryChange::DeviceCheckIn(value) => Ok((
            "device_checked_in",
            serialize_payload(&value)?,
            EventReferences {
                device_id: Some(value.device_id),
                ..EventReferences::default()
            },
        )),
        RegistryChange::DeviceMount(value) => Ok((
            "device_mount_observed",
            serialize_payload(&value)?,
            EventReferences {
                device_id: Some(value.device_id),
                ..EventReferences::default()
            },
        )),
    }
}

fn serialize_payload(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|error| RegistryError::Invalid(format!("cannot serialize snapshot: {error}")))
}

fn lifecycle_event(kind: &str, action: RegistryAction) -> &'static str {
    match (kind, action) {
        ("site", RegistryAction::Register) => "site_registered",
        ("site", RegistryAction::Update) => "site_updated",
        ("site", RegistryAction::Retire) => "site_retired",
        ("policy", RegistryAction::Register) => "policy_registered",
        ("policy", RegistryAction::Update) => "policy_updated",
        ("policy", RegistryAction::Retire) => "policy_retired",
        ("collection", RegistryAction::Register) => "collection_registered",
        ("collection", RegistryAction::Update) => "collection_updated",
        ("collection", RegistryAction::Retire) => "collection_retired",
        ("device", RegistryAction::Register) => "device_registered",
        ("device", RegistryAction::Update) => "device_updated",
        ("device", RegistryAction::Move) => "device_moved",
        ("device", RegistryAction::Retire) => "device_retired",
        ("archive_root", RegistryAction::Register) => "archive_root_registered",
        ("archive_root", RegistryAction::Update) => "archive_root_updated",
        ("archive_root", RegistryAction::Retire) => "archive_root_retired",
        ("location", RegistryAction::Register) => "location_registered",
        ("location", RegistryAction::Update) => "location_updated",
        ("location", RegistryAction::Retire) => "location_retired",
        ("risk_domain", RegistryAction::Register) => "risk_domain_registered",
        ("risk_domain", RegistryAction::Update) => "risk_domain_updated",
        ("risk_domain", RegistryAction::Retire) => "risk_domain_retired",
        _ => unreachable!("registry kind is fixed by RegistryChange"),
    }
}

fn validate_change(path: &Path, change: &RegistryChange) -> Result<()> {
    let connection = Connection::open(path).map_err(|source| sqlite_error(path, source))?;
    match change {
        RegistryChange::Site(action, value) => {
            validate_lifecycle(
                &connection,
                "sites",
                "site_id",
                "site",
                &value.site_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            require_nonempty("site_kind", &value.site_kind)?;
        }
        RegistryChange::Policy(action, value) => {
            validate_lifecycle(
                &connection,
                "policies",
                "policy_id",
                "policy",
                &value.policy_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            let requirements = serde_json::to_string(&value.requirements)
                .map_err(|error| RegistryError::Invalid(error.to_string()))?;
            PolicyRequirements::from_json(&value.policy_id, &requirements)
                .map_err(|error| RegistryError::Invalid(error.to_string()))?;
            if value.policy_version == 0 {
                return Err(RegistryError::Invalid(
                    "policy_version must be positive".to_owned(),
                ));
            }
            if *action == RegistryAction::Update {
                let current: i64 = connection
                    .query_row(
                        "SELECT policy_version FROM policies WHERE policy_id = ?1",
                        [&value.policy_id],
                        |row| row.get(0),
                    )
                    .map_err(|source| sqlite_error(path, source))?;
                if u64::try_from(current)
                    .ok()
                    .is_none_or(|current| value.policy_version <= current)
                {
                    return Err(RegistryError::Invalid(
                        "policy updates must increase policy_version".to_owned(),
                    ));
                }
            }
        }
        RegistryChange::Collection(action, value) => {
            validate_lifecycle(
                &connection,
                "collections",
                "collection_id",
                "collection",
                &value.collection_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            require_optional_entity(
                &connection,
                "sites",
                "site_id",
                value.home_site_id.as_deref(),
            )?;
            require_optional_entity(
                &connection,
                "policies",
                "policy_id",
                value.policy_id.as_deref(),
            )?;
        }
        RegistryChange::Device(action, value) => {
            validate_lifecycle(
                &connection,
                "devices",
                "device_id",
                "device",
                &value.device_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            require_optional_entity(
                &connection,
                "sites",
                "site_id",
                value.current_site_id.as_deref(),
            )?;
            if !matches!(
                value.identity_state.as_str(),
                "confirmed" | "unavailable" | "conflict"
            ) {
                return Err(RegistryError::Invalid(
                    "invalid device identity_state".to_owned(),
                ));
            }
            if !matches!(
                value.expected_availability.as_str(),
                "online" | "offline" | "intermittent"
            ) {
                return Err(RegistryError::Invalid(
                    "invalid expected_availability".to_owned(),
                ));
            }
            if value.identity_state == "confirmed"
                && (value
                    .hardware_fingerprint
                    .as_deref()
                    .is_none_or(str::is_empty)
                    || value.fingerprint_kind.as_deref().is_none_or(str::is_empty))
            {
                return Err(RegistryError::Invalid(
                    "confirmed devices require fingerprint kind and value".to_owned(),
                ));
            }
            if *action == RegistryAction::Update || *action == RegistryAction::Move {
                let current_site: Option<String> = connection
                    .query_row(
                        "SELECT current_site_id FROM devices WHERE device_id = ?1",
                        [&value.device_id],
                        |row| row.get(0),
                    )
                    .map_err(|source| sqlite_error(path, source))?;
                if *action == RegistryAction::Update && current_site != value.current_site_id {
                    return Err(RegistryError::Invalid(
                        "use device move when changing current_site_id".to_owned(),
                    ));
                }
                if *action == RegistryAction::Move && current_site == value.current_site_id {
                    return Err(RegistryError::Invalid(
                        "device move must change current_site_id".to_owned(),
                    ));
                }
            }
        }
        RegistryChange::ArchiveRoot(action, value) => {
            validate_lifecycle(
                &connection,
                "archive_roots",
                "archive_root_id",
                "archive root",
                &value.archive_root_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            require_entity(&connection, "devices", "device_id", &value.device_id)?;
            if *action != RegistryAction::Register {
                let current: String = connection
                    .query_row(
                        "SELECT device_id FROM archive_roots WHERE archive_root_id = ?1",
                        [&value.archive_root_id],
                        |row| row.get(0),
                    )
                    .map_err(|source| sqlite_error(path, source))?;
                if current != value.device_id {
                    return Err(RegistryError::Invalid(
                        "an archive root cannot move to another device".to_owned(),
                    ));
                }
            }
        }
        RegistryChange::Location(action, value) => {
            validate_lifecycle(
                &connection,
                "locations",
                "location_id",
                "location",
                &value.location_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            validate_location(&connection, value)?;
        }
        RegistryChange::RiskDomain(action, value) => {
            validate_lifecycle(
                &connection,
                "risk_domains",
                "risk_domain_id",
                "risk domain",
                &value.risk_domain_id,
                &value.display_name,
                &value.status,
                *action,
            )?;
            require_nonempty("risk_kind", &value.risk_kind)?;
        }
        RegistryChange::AssignRisk(value) | RegistryChange::UnassignRisk(value) => {
            require_entity(
                &connection,
                "risk_domains",
                "risk_domain_id",
                &value.risk_domain_id,
            )?;
            let (table, column) = entity_table(&value.entity_type)?;
            require_entity(&connection, table, column, &value.entity_id)?;
            let assigned: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM entity_risk_domains
                     WHERE entity_type = ?1 AND entity_id = ?2 AND risk_domain_id = ?3)",
                    [&value.entity_type, &value.entity_id, &value.risk_domain_id],
                    |row| row.get(0),
                )
                .map_err(|source| sqlite_error(path, source))?;
            if matches!(change, RegistryChange::AssignRisk(_)) && assigned {
                return Err(RegistryError::AlreadyExists {
                    kind: "risk assignment",
                    id: format!("{}:{}", value.entity_type, value.entity_id),
                });
            }
            if matches!(change, RegistryChange::UnassignRisk(_)) && !assigned {
                return Err(RegistryError::NotFound {
                    kind: "risk assignment",
                    id: format!("{}:{}", value.entity_type, value.entity_id),
                });
            }
        }
        RegistryChange::DeviceCheckIn(value) => {
            require_entity(&connection, "devices", "device_id", &value.device_id)?;
            if !matches!(
                value.fingerprint_status.as_str(),
                "match" | "unavailable" | "mismatch"
            ) {
                return Err(RegistryError::Invalid(
                    "invalid fingerprint_status".to_owned(),
                ));
            }
        }
        RegistryChange::DeviceMount(value) => {
            require_entity(&connection, "devices", "device_id", &value.device_id)?;
            require_nonempty("mount_id", &value.mount_id)?;
            require_nonempty("mount_root_uri", &value.mount_root_uri)?;
            if !matches!(value.status.as_str(), "mounted" | "unmounted" | "mismatch")
                || !matches!(
                    value.fingerprint_status.as_str(),
                    "match" | "unavailable" | "mismatch"
                )
            {
                return Err(RegistryError::Invalid(
                    "invalid device mount state".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_lifecycle(
    connection: &Connection,
    table: &'static str,
    column: &'static str,
    kind: &'static str,
    id: &str,
    display_name: &str,
    status: &str,
    action: RegistryAction,
) -> Result<()> {
    require_nonempty("ID", id)?;
    require_nonempty("display_name", display_name)?;
    let expected_status = if action == RegistryAction::Retire {
        "retired"
    } else {
        "active"
    };
    if status != expected_status {
        return Err(RegistryError::Invalid(format!(
            "{kind} status must be {expected_status} for this action"
        )));
    }
    let exists = entity_exists(connection, table, column, id)?;
    if action == RegistryAction::Register && exists {
        return Err(RegistryError::AlreadyExists {
            kind,
            id: id.to_owned(),
        });
    }
    if action != RegistryAction::Register && !exists {
        return Err(RegistryError::NotFound {
            kind,
            id: id.to_owned(),
        });
    }
    Ok(())
}

fn validate_location(connection: &Connection, value: &LocationSnapshot) -> Result<()> {
    if !matches!(
        value.expected_availability.as_str(),
        "online" | "offline" | "intermittent"
    ) {
        return Err(RegistryError::Invalid(
            "invalid expected_availability".to_owned(),
        ));
    }
    if value.kind == "filesystem" {
        let (Some(root), Some(device), Some(_path)) = (
            value.archive_root_id.as_deref(),
            value.device_id.as_deref(),
            value.relative_path.as_ref(),
        ) else {
            return Err(RegistryError::Invalid(
                "filesystem location requires root, device, and relative path".to_owned(),
            ));
        };
        if value.site_id.is_some() {
            return Err(RegistryError::Invalid(
                "filesystem location inherits its site from its device".to_owned(),
            ));
        }
        let matches: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM archive_roots
                 WHERE archive_root_id = ?1 AND device_id = ?2)",
                [root, device],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(connection_path(connection), source))?;
        if !matches {
            return Err(RegistryError::Invalid(
                "filesystem root and device do not match".to_owned(),
            ));
        }
    } else if value.kind == "service" {
        if value.site_id.is_none()
            || value.archive_root_id.is_some()
            || value.device_id.is_some()
            || value.relative_path.is_some()
        {
            return Err(RegistryError::Invalid(
                "service location requires only a site topology".to_owned(),
            ));
        }
        require_optional_entity(connection, "sites", "site_id", value.site_id.as_deref())?;
    } else {
        return Err(RegistryError::Invalid("invalid location kind".to_owned()));
    }
    Ok(())
}

fn entity_table(entity_type: &str) -> Result<(&'static str, &'static str)> {
    match entity_type {
        "location" => Ok(("locations", "location_id")),
        "archive_root" => Ok(("archive_roots", "archive_root_id")),
        "device" => Ok(("devices", "device_id")),
        "site" => Ok(("sites", "site_id")),
        _ => Err(RegistryError::Invalid(
            "invalid risk entity type".to_owned(),
        )),
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(RegistryError::Invalid(format!("{field} is required")));
    }
    Ok(())
}

fn require_optional_entity(
    connection: &Connection,
    table: &'static str,
    column: &'static str,
    id: Option<&str>,
) -> Result<()> {
    if let Some(id) = id {
        require_entity(connection, table, column, id)?;
    }
    Ok(())
}

fn require_entity(
    connection: &Connection,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<()> {
    if !entity_exists(connection, table, column, id)? {
        return Err(RegistryError::NotFound {
            kind: table,
            id: id.to_owned(),
        });
    }
    Ok(())
}

fn entity_exists(
    connection: &Connection,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<bool> {
    let sql = format!("SELECT 1 FROM {table} WHERE {column} = ?1");
    connection
        .query_row(&sql, [id], |_| Ok(true))
        .optional()
        .map(|value| value.unwrap_or(false))
        .map_err(|source| sqlite_error(connection_path(connection), source))
}

fn connection_path(connection: &Connection) -> &Path {
    Path::new(connection.path().unwrap_or(""))
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> RegistryError {
    RegistryError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventStoreConfig, ProjectionConfig};
    use tempfile::TempDir;

    #[test]
    fn typed_registry_rejects_invalid_changes_before_append_and_rebuilds() {
        let temp = TempDir::new().unwrap();
        let events = EventStore::open_or_create(
            temp.path().join("events"),
            EventStoreConfig {
                actor_id: "test-user".to_owned(),
                host_id: "test-host".to_owned(),
                ..EventStoreConfig::default()
            },
        )
        .unwrap();
        let projection = ProjectionDb::open_or_create(
            temp.path().join("archive.db"),
            "arc_registry",
            ProjectionConfig::default(),
        )
        .unwrap();
        let registry = Registry::new(&events, &projection);

        let site = SiteSnapshot {
            site_id: "site_home".to_owned(),
            display_name: "Home".to_owned(),
            site_kind: "home".to_owned(),
            description: None,
            status: "active".to_owned(),
        };
        assert_eq!(
            registry
                .record(RegistryChange::Site(RegistryAction::Register, site.clone()))
                .unwrap()
                .event_seq,
            1
        );
        let duplicate = registry
            .record(RegistryChange::Site(RegistryAction::Register, site))
            .unwrap_err();
        assert_eq!(duplicate.code(), "already_exists");
        assert_eq!(projection.status().unwrap().cursor.applied_seq, 1);

        registry
            .record(RegistryChange::Device(
                RegistryAction::Register,
                DeviceSnapshot {
                    device_id: "device_1".to_owned(),
                    display_name: "Archive disk".to_owned(),
                    device_kind: "disk".to_owned(),
                    serial_hint: None,
                    hardware_fingerprint: Some("fp1".to_owned()),
                    fingerprint_kind: Some("serial".to_owned()),
                    identity_state: "confirmed".to_owned(),
                    owner: None,
                    status: "active".to_owned(),
                    current_site_id: Some("site_home".to_owned()),
                    expected_availability: "online".to_owned(),
                },
            ))
            .unwrap();
        registry
            .record(RegistryChange::ArchiveRoot(
                RegistryAction::Register,
                ArchiveRootSnapshot {
                    archive_root_id: "root_1".to_owned(),
                    device_id: "device_1".to_owned(),
                    display_name: "Root".to_owned(),
                    root_path_on_device: RegistryPath::utf8("/archive"),
                    status: "active".to_owned(),
                },
            ))
            .unwrap();
        let bad = registry
            .record(RegistryChange::Location(
                RegistryAction::Register,
                LocationSnapshot {
                    location_id: "location_bad".to_owned(),
                    display_name: "Bad".to_owned(),
                    kind: "filesystem".to_owned(),
                    archive_root_id: Some("root_1".to_owned()),
                    relative_path: Some(RegistryPath::utf8("")),
                    device_id: Some("missing".to_owned()),
                    site_id: None,
                    encryption_state: Some("unknown".to_owned()),
                    trust_level: Some("unknown".to_owned()),
                    expected_availability: "online".to_owned(),
                    is_writable: false,
                    status: "active".to_owned(),
                },
            ))
            .unwrap_err();
        assert_eq!(bad.code(), "registry_invalid");
        assert_eq!(projection.status().unwrap().cursor.applied_seq, 3);

        registry
            .record(RegistryChange::Location(
                RegistryAction::Register,
                LocationSnapshot {
                    location_id: "location_1".to_owned(),
                    display_name: "Main archive".to_owned(),
                    kind: "filesystem".to_owned(),
                    archive_root_id: Some("root_1".to_owned()),
                    relative_path: Some(RegistryPath::utf8("")),
                    device_id: Some("device_1".to_owned()),
                    site_id: None,
                    encryption_state: Some("encrypted".to_owned()),
                    trust_level: Some("trusted".to_owned()),
                    expected_availability: "online".to_owned(),
                    is_writable: false,
                    status: "active".to_owned(),
                },
            ))
            .unwrap();
        registry
            .record(RegistryChange::Site(
                RegistryAction::Register,
                SiteSnapshot {
                    site_id: "site_remote".to_owned(),
                    display_name: "Remote".to_owned(),
                    site_kind: "office".to_owned(),
                    description: None,
                    status: "active".to_owned(),
                },
            ))
            .unwrap();
        registry
            .record(RegistryChange::Device(
                RegistryAction::Move,
                DeviceSnapshot {
                    device_id: "device_1".to_owned(),
                    display_name: "Archive disk".to_owned(),
                    device_kind: "disk".to_owned(),
                    serial_hint: None,
                    hardware_fingerprint: Some("fp1".to_owned()),
                    fingerprint_kind: Some("serial".to_owned()),
                    identity_state: "confirmed".to_owned(),
                    owner: None,
                    status: "active".to_owned(),
                    current_site_id: Some("site_remote".to_owned()),
                    expected_availability: "online".to_owned(),
                },
            ))
            .unwrap();
        let rebuilt_path = temp.path().join("rebuilt.db");
        ProjectionDb::rebuild(
            &events,
            &rebuilt_path,
            "arc_registry",
            ProjectionConfig::default(),
        )
        .unwrap();
        let connection = Connection::open(rebuilt_path).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT display_name FROM locations WHERE location_id='location_1'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "Main archive"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM device_site_history WHERE device_id='device_1'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
    }
}
