//! Canonical catalog-metadata protection registry and SQLite-only status.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use ulid::Ulid;

use crate::event_store::{Checkpoint, EventRequest, EventStore, EventStoreConfig, EventStoreError};
use crate::projection::{ProjectionConfig, ProjectionDb, ProjectionError};
use crate::registry::RegistryAction;

pub type Result<T> = std::result::Result<T, MetadataError>;

#[derive(Debug, Error)]
pub enum MetadataError {
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
    #[error("invalid metadata protection input: {0}")]
    Invalid(String),
    #[error("Git operation {operation} failed for {path}: {detail}")]
    Git {
        operation: &'static str,
        path: PathBuf,
        detail: String,
    },
    #[error("I/O operation {operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("metadata destination not found: {0}")]
    NotFound(String),
    #[error("metadata destination already exists: {0}")]
    AlreadyExists(String),
}

impl MetadataError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EventStore(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Sqlite { .. } => "metadata_sqlite",
            Self::Invalid(_) => "metadata_invalid",
            Self::Git { .. } => "metadata_git",
            Self::Io { .. } => "metadata_io",
            Self::NotFound(_) => "not_found",
            Self::AlreadyExists(_) => "already_exists",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetadataDestinationSnapshot {
    pub destination_id: String,
    pub display_name: String,
    pub location_id: String,
    pub git_remote_name: String,
    pub remote_locator: String,
    pub remote_ref: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataDestinationState {
    #[serde(flatten)]
    pub snapshot: MetadataDestinationSnapshot,
    pub latest_checkpoint_id: Option<String>,
    pub latest_replication_status: Option<String>,
    pub latest_independence_status: Option<String>,
    pub latest_observed_time_utc_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataProtectionStatus {
    pub version: u32,
    pub applied_event_seq: u64,
    pub applied_event_hash: Option<String>,
    pub checkpointed_through_seq: u64,
    pub checkpointed_through_hash: Option<String>,
    pub committed_through_seq: u64,
    pub committed_through_hash: Option<String>,
    pub independently_protected_through_seq: u64,
    pub independently_protected_through_hash: Option<String>,
    pub uncheckpointed_events: u64,
    pub uncommitted_events: u64,
    pub unreplicated_events: u64,
    pub catalog_location_id: Option<String>,
    pub destinations: Vec<MetadataDestinationState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndependenceAssessment {
    pub status: String,
    pub reasons: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataCheckpointResult {
    pub version: u32,
    pub checkpoint_id: String,
    pub event_last_seq: u64,
    pub event_last_hash: String,
    pub local_git_commit: String,
    pub replication_observations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreCheckResult {
    pub version: u32,
    pub archive_id: String,
    pub verified_event_seq: u64,
    pub verified_event_hash: Option<String>,
    pub checkpoints_verified: u64,
    pub rebuilt_event_seq: u64,
    pub rebuilt_event_hash: Option<String>,
}

pub struct MetadataRegistry<'a> {
    events: &'a EventStore,
    projection: &'a ProjectionDb,
}

impl<'a> MetadataRegistry<'a> {
    pub fn new(events: &'a EventStore, projection: &'a ProjectionDb) -> Self {
        Self { events, projection }
    }

    pub fn set_catalog_location(&self, location_id: &str) -> Result<u64> {
        self.projection.apply(self.events)?;
        require_active_location(self.projection.path(), location_id)?;
        let record = self.events.append(EventRequest::new(
            "catalog_location_set",
            json!({"location_id": location_id}),
        ))?;
        self.projection.apply(self.events)?;
        Ok(record.envelope.seq)
    }

    pub fn record_destination(
        &self,
        action: RegistryAction,
        snapshot: MetadataDestinationSnapshot,
    ) -> Result<u64> {
        self.projection.apply(self.events)?;
        validate_destination(self.projection.path(), action, &snapshot)?;
        let event_type = match action {
            RegistryAction::Register => "metadata_destination_registered",
            RegistryAction::Update => "metadata_destination_updated",
            RegistryAction::Retire => "metadata_destination_retired",
            RegistryAction::Move => {
                return Err(MetadataError::Invalid(
                    "metadata destinations do not support move".to_owned(),
                ))
            }
        };
        let record = self.events.append(EventRequest::new(
            event_type,
            serde_json::to_value(snapshot)
                .map_err(|error| MetadataError::Invalid(error.to_string()))?,
        ))?;
        self.projection.apply(self.events)?;
        Ok(record.envelope.seq)
    }
}

pub struct MetadataProtector<'a> {
    events: &'a EventStore,
    projection: &'a ProjectionDb,
}

impl<'a> MetadataProtector<'a> {
    pub fn new(events: &'a EventStore, projection: &'a ProjectionDb) -> Self {
        Self { events, projection }
    }

    pub fn checkpoint(&self, replicate: bool) -> Result<MetadataCheckpointResult> {
        self.projection.apply(self.events)?;
        let checkpoint = self.events.create_checkpoint()?;
        self.projection.apply(self.events)?;
        let commit = commit_checkpoint(self.events.root(), &checkpoint)?;
        self.record_commit(&checkpoint, &commit)?;
        let replication_observations = if replicate {
            self.replicate_checkpoint(&checkpoint, &commit, true)?
        } else {
            0
        };
        Ok(MetadataCheckpointResult {
            version: 1,
            checkpoint_id: checkpoint.checkpoint_id,
            event_last_seq: checkpoint.event_last_seq,
            event_last_hash: checkpoint.event_last_hash,
            local_git_commit: commit,
            replication_observations,
        })
    }

    pub fn reconcile(&self, checkpoint_id: &str) -> Result<MetadataCheckpointResult> {
        self.projection.apply(self.events)?;
        let checkpoint = self
            .events
            .verify()?
            .checkpoints
            .into_iter()
            .find(|checkpoint| checkpoint.checkpoint_id == checkpoint_id)
            .ok_or_else(|| {
                MetadataError::Invalid(format!("checkpoint not found: {checkpoint_id}"))
            })?;
        let connection = open(self.projection.path())?;
        let observed: Option<String> = connection
            .query_row(
                "SELECT local_git_commit FROM checkpoints WHERE checkpoint_id = ?1",
                [checkpoint_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(self.projection.path(), source))?
            .flatten();
        let commit = if let Some(commit) = observed {
            verify_checkpoint_commit(self.events.root(), &checkpoint, &commit)?;
            commit
        } else {
            let commit = find_checkpoint_commit(self.events.root(), &checkpoint)?;
            self.record_commit(&checkpoint, &commit)?;
            commit
        };
        Ok(MetadataCheckpointResult {
            version: 1,
            checkpoint_id: checkpoint.checkpoint_id,
            event_last_seq: checkpoint.event_last_seq,
            event_last_hash: checkpoint.event_last_hash,
            local_git_commit: commit,
            replication_observations: 0,
        })
    }

    pub fn check_destination(
        &self,
        checkpoint_id: &str,
        destination_id: &str,
        push: bool,
    ) -> Result<u64> {
        self.projection.apply(self.events)?;
        let checkpoint = self
            .events
            .verify()?
            .checkpoints
            .into_iter()
            .find(|checkpoint| checkpoint.checkpoint_id == checkpoint_id)
            .ok_or_else(|| {
                MetadataError::Invalid(format!("checkpoint not found: {checkpoint_id}"))
            })?;
        let destination = self
            .projection
            .metadata_protection_status()?
            .destinations
            .into_iter()
            .find(|destination| {
                destination.snapshot.destination_id == destination_id
                    && destination.snapshot.status == "active"
            })
            .ok_or_else(|| MetadataError::NotFound(destination_id.to_owned()))?
            .snapshot;
        let commit: String = open(self.projection.path())?
            .query_row(
                "SELECT local_git_commit FROM checkpoints WHERE checkpoint_id = ?1",
                [checkpoint_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(self.projection.path(), source))?;
        self.observe_destination(&checkpoint, &commit, &destination, push)?;
        Ok(self.projection.status()?.cursor.applied_seq)
    }

    fn record_commit(&self, checkpoint: &Checkpoint, commit: &str) -> Result<()> {
        self.events.append(EventRequest::new(
            "checkpoint_commit_observed",
            json!({
                "checkpoint_id": checkpoint.checkpoint_id,
                "git_commit": commit,
                "event_last_seq": checkpoint.event_last_seq,
                "event_last_hash": checkpoint.event_last_hash,
            }),
        ))?;
        self.projection.apply(self.events)?;
        Ok(())
    }

    fn replicate_checkpoint(
        &self,
        checkpoint: &Checkpoint,
        commit: &str,
        push: bool,
    ) -> Result<u64> {
        let destinations = self
            .projection
            .metadata_protection_status()?
            .destinations
            .into_iter()
            .filter(|destination| destination.snapshot.status == "active")
            .map(|destination| destination.snapshot)
            .collect::<Vec<_>>();
        let mut count = 0u64;
        for destination in destinations {
            self.observe_destination(checkpoint, commit, &destination, push)?;
            count += 1;
        }
        Ok(count)
    }

    fn observe_destination(
        &self,
        checkpoint: &Checkpoint,
        commit: &str,
        destination: &MetadataDestinationSnapshot,
        push: bool,
    ) -> Result<()> {
        let assessment = match git_required(
            self.events.root(),
            "read metadata remote configuration",
            &["remote", "get-url", &destination.git_remote_name],
        ) {
            Ok(configured) if configured == destination.remote_locator => {
                self.projection.assess_metadata_independence(destination)?
            }
            Ok(_) => IndependenceAssessment {
                status: "unknown".to_owned(),
                reasons: json!(["git_remote_locator_mismatch"]),
            },
            Err(_) => IndependenceAssessment {
                status: "unknown".to_owned(),
                reasons: json!(["git_remote_unconfigured"]),
            },
        };
        let observation = observe_remote(self.events.root(), destination, checkpoint, commit, push);
        let (status, observed_commit, observed_seq, observed_hash, error_code) = match observation {
            Ok(Some(observed)) if observed == commit => (
                "present",
                Some(observed),
                Some(checkpoint.event_last_seq),
                Some(checkpoint.event_last_hash.clone()),
                None,
            ),
            Ok(Some(observed)) => ("diverged", Some(observed), None, None, None),
            Ok(None) => ("missing", None, None, None, None),
            Err(_) => ("error", None, None, None, Some("git_remote_check_failed")),
        };
        self.events.append(EventRequest::new(
            "checkpoint_replication_observed",
            json!({
                "checkpoint_id": checkpoint.checkpoint_id,
                "destination_id": destination.destination_id,
                "status": status,
                "observed_git_commit": observed_commit,
                "observed_event_last_seq": observed_seq,
                "observed_event_last_hash": observed_hash,
                "independence_status": assessment.status,
                "independence_reasons": assessment.reasons,
                "error_code": error_code,
                "error_detail": Value::Null,
            }),
        ))?;
        self.projection.apply(self.events)?;
        Ok(())
    }
}

pub fn restore_check(
    event_repository: impl AsRef<Path>,
    database_path: impl AsRef<Path>,
) -> Result<RestoreCheckResult> {
    let event_repository = event_repository.as_ref();
    if !event_repository
        .join("events")
        .join("stream_primary")
        .is_dir()
        || !event_repository
            .join("manifests")
            .join("stream_primary")
            .is_dir()
        || !event_repository.join("checkpoints").is_dir()
    {
        return Err(MetadataError::Invalid(format!(
            "event repository is incomplete or missing: {}",
            event_repository.display()
        )));
    }
    let events = EventStore::open_or_create(event_repository, EventStoreConfig::default())?;
    let archive_id = events.archive_id()?;
    let verified = events.verify()?;
    let checkpoint_ids = verified
        .checkpoints
        .iter()
        .map(|checkpoint| checkpoint.checkpoint_id.clone())
        .collect::<Vec<_>>();
    ProjectionDb::rebuild(
        &events,
        database_path.as_ref(),
        &archive_id,
        ProjectionConfig::default(),
    )?;
    let rebuilt = ProjectionDb::open_existing(database_path, ProjectionConfig::default())?;
    let protector = MetadataProtector::new(&events, &rebuilt);
    for checkpoint_id in checkpoint_ids {
        protector.reconcile(&checkpoint_id)?;
    }
    let verified = events.verify()?;
    let status = rebuilt.status()?;
    if status.cursor.applied_seq != verified.last_seq
        || status.cursor.applied_event_hash != verified.last_event_hash
    {
        return Err(MetadataError::Invalid(
            "rebuilt SQLite cursor does not match the verified canonical stream".to_owned(),
        ));
    }
    Ok(RestoreCheckResult {
        version: 1,
        archive_id,
        verified_event_seq: verified.last_seq,
        verified_event_hash: verified.last_event_hash,
        checkpoints_verified: u64::try_from(verified.checkpoints.len())
            .map_err(|_| MetadataError::Invalid("checkpoint count exceeds u64".to_owned()))?,
        rebuilt_event_seq: status.cursor.applied_seq,
        rebuilt_event_hash: status.cursor.applied_event_hash,
    })
}

pub fn initialize_metadata_repository(event_repository: impl AsRef<Path>) -> Result<()> {
    ensure_git_repository(event_repository.as_ref())
}

impl ProjectionDb {
    pub fn metadata_protection_status(&self) -> Result<MetadataProtectionStatus> {
        let projection = self.status()?;
        let connection = open(self.path())?;
        let checkpoint = latest_checkpoint(&connection, self.path(), "1=1")?;
        let committed =
            latest_checkpoint(&connection, self.path(), "local_git_commit IS NOT NULL")?;
        let protected = connection
            .query_row(
                "SELECT c.event_last_seq, c.event_last_hash
                 FROM checkpoints c
                 JOIN checkpoint_replications r ON r.checkpoint_id = c.checkpoint_id
                 JOIN metadata_destinations d ON d.destination_id = r.destination_id
                 JOIN events re ON re.event_id = r.event_id
                 JOIN events de ON de.event_id = d.last_event_id
                 WHERE d.status = 'active' AND r.status = 'present'
                   AND r.independence_status = 'independent'
                   AND r.observed_git_commit = c.local_git_commit
                   AND r.observed_event_last_seq = c.event_last_seq
                   AND r.observed_event_last_hash = c.event_last_hash
                   AND re.seq > de.seq
                   AND re.seq >= COALESCE((SELECT MAX(e.seq) FROM events e
                     WHERE e.event_type IN (
                       'catalog_location_set', 'site_registered', 'site_updated', 'site_retired',
                       'device_registered', 'device_updated', 'device_moved', 'device_retired',
                       'archive_root_registered', 'archive_root_updated', 'archive_root_retired',
                       'location_registered', 'location_updated', 'location_retired',
                       'risk_domain_registered', 'risk_domain_updated', 'risk_domain_retired',
                       'risk_assigned', 'risk_unassigned', 'metadata_destination_registered',
                       'metadata_destination_updated', 'metadata_destination_retired')), 0)
                 ORDER BY c.event_last_seq DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|source| sqlite_error(self.path(), source))?
            .map(|(seq, hash)| sql_u64(seq).map(|seq| (seq, hash)))
            .transpose()?;
        let mut statement = connection
            .prepare(
                "SELECT d.destination_id, d.display_name, d.location_id,
                        d.git_remote_name, d.remote_locator, d.remote_ref, d.status,
                        r.checkpoint_id, r.status,
                        CASE WHEN re.seq > de.seq AND re.seq >= COALESCE((
                          SELECT MAX(e.seq) FROM events e WHERE e.event_type IN (
                           'catalog_location_set', 'site_registered', 'site_updated', 'site_retired',
                           'device_registered', 'device_updated', 'device_moved', 'device_retired',
                           'archive_root_registered', 'archive_root_updated', 'archive_root_retired',
                           'location_registered', 'location_updated', 'location_retired',
                           'risk_domain_registered', 'risk_domain_updated', 'risk_domain_retired',
                           'risk_assigned', 'risk_unassigned', 'metadata_destination_registered',
                           'metadata_destination_updated', 'metadata_destination_retired')), 0)
                        THEN r.independence_status ELSE 'unknown' END,
                        r.observed_time_utc_ms
                 FROM metadata_destinations d
                 LEFT JOIN checkpoint_replications r ON r.rowid = (
                   SELECT rr.rowid FROM checkpoint_replications rr
                   JOIN checkpoints c ON c.checkpoint_id = rr.checkpoint_id
                   WHERE rr.destination_id = d.destination_id
                   ORDER BY c.event_last_seq DESC LIMIT 1)
                 LEFT JOIN events re ON re.event_id = r.event_id
                 LEFT JOIN events de ON de.event_id = d.last_event_id
                 ORDER BY d.display_name, d.destination_id",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            })
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut destinations = Vec::new();
        for row in rows {
            let (
                id,
                name,
                location,
                remote,
                locator,
                remote_ref,
                status,
                checkpoint_id,
                replication_status,
                independence_status,
                observed_time,
            ) = row.map_err(|source| sqlite_error(self.path(), source))?;
            destinations.push(MetadataDestinationState {
                snapshot: MetadataDestinationSnapshot {
                    destination_id: id,
                    display_name: name,
                    location_id: location,
                    git_remote_name: remote,
                    remote_locator: locator,
                    remote_ref,
                    status,
                },
                latest_checkpoint_id: checkpoint_id,
                latest_replication_status: replication_status,
                latest_independence_status: independence_status,
                latest_observed_time_utc_ms: observed_time.map(sql_u64).transpose()?,
            });
        }
        let applied = projection.cursor.applied_seq;
        let checkpointed_seq = checkpoint.as_ref().map_or(0, |value| value.0);
        let committed_seq = committed.as_ref().map_or(0, |value| value.0);
        let protected_seq = protected.as_ref().map_or(0, |value| value.0);
        Ok(MetadataProtectionStatus {
            version: 1,
            applied_event_seq: applied,
            applied_event_hash: projection.cursor.applied_event_hash,
            checkpointed_through_seq: checkpointed_seq,
            checkpointed_through_hash: checkpoint.map(|value| value.1),
            committed_through_seq: committed_seq,
            committed_through_hash: committed.map(|value| value.1),
            independently_protected_through_seq: protected_seq,
            independently_protected_through_hash: protected.map(|value| value.1),
            uncheckpointed_events: applied.saturating_sub(checkpointed_seq),
            uncommitted_events: applied.saturating_sub(committed_seq),
            unreplicated_events: applied.saturating_sub(protected_seq),
            catalog_location_id: projection.catalog_location_id,
            destinations,
        })
    }

    pub fn assess_metadata_independence(
        &self,
        destination: &MetadataDestinationSnapshot,
    ) -> Result<IndependenceAssessment> {
        if is_local_locator(&destination.remote_locator) {
            return Ok(IndependenceAssessment {
                status: "unknown".to_owned(),
                reasons: json!(["local_remote_storage_identity_unverified"]),
            });
        }
        let connection = open(self.path())?;
        let Some(catalog_location_id) = self.status()?.catalog_location_id else {
            return Ok(IndependenceAssessment {
                status: "unknown".to_owned(),
                reasons: json!(["catalog_location_unconfigured"]),
            });
        };
        let catalog = location_topology(&connection, self.path(), &catalog_location_id)?;
        let destination_topology =
            location_topology(&connection, self.path(), &destination.location_id)?;
        let (Some(catalog), Some(remote)) = (catalog, destination_topology) else {
            return Ok(IndependenceAssessment {
                status: "unknown".to_owned(),
                reasons: json!(["location_topology_unresolved"]),
            });
        };
        let mut overlap = Vec::new();
        if catalog.storage_domain == remote.storage_domain {
            overlap.push("same_storage_domain");
        }
        if catalog.site_id == remote.site_id {
            overlap.push("same_site");
        }
        if !catalog.risk_domains.is_disjoint(&remote.risk_domains) {
            overlap.push("shared_custom_risk_domain");
        }
        Ok(IndependenceAssessment {
            status: if overlap.is_empty() {
                "independent"
            } else {
                "overlapping"
            }
            .to_owned(),
            reasons: json!(overlap),
        })
    }
}

#[derive(Debug)]
struct LocationTopology {
    storage_domain: String,
    site_id: String,
    risk_domains: BTreeSet<String>,
}

fn location_topology(
    connection: &Connection,
    path: &Path,
    location_id: &str,
) -> Result<Option<LocationTopology>> {
    let row = connection
        .query_row(
            "SELECT l.kind, l.device_id, COALESCE(l.site_id, d.current_site_id)
             FROM locations l LEFT JOIN devices d ON d.device_id = l.device_id
             WHERE l.location_id = ?1 AND l.status = 'active'",
            [location_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|source| sqlite_error(path, source))?;
    let Some((kind, device_id, Some(site_id))) = row else {
        return Ok(None);
    };
    let storage_domain = if kind == "service" {
        format!("service:{location_id}")
    } else if let Some(device_id) = device_id {
        format!("device:{device_id}")
    } else {
        return Ok(None);
    };
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT er.risk_domain_id
             FROM entity_risk_domains er
             JOIN risk_domains r ON r.risk_domain_id = er.risk_domain_id AND r.status = 'active'
             LEFT JOIN locations l ON l.location_id = ?1
             LEFT JOIN archive_roots ar ON ar.archive_root_id = l.archive_root_id
             WHERE (er.entity_type = 'location' AND er.entity_id = l.location_id)
                OR (er.entity_type = 'archive_root' AND er.entity_id = ar.archive_root_id)
                OR (er.entity_type = 'device' AND er.entity_id = l.device_id)
                OR (er.entity_type = 'site' AND er.entity_id = ?2)",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let risk_domains = statement
        .query_map(params![location_id, site_id], |row| row.get::<_, String>(0))
        .map_err(|source| sqlite_error(path, source))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()
        .map_err(|source| sqlite_error(path, source))?;
    Ok(Some(LocationTopology {
        storage_domain,
        site_id,
        risk_domains,
    }))
}

fn validate_destination(
    path: &Path,
    action: RegistryAction,
    value: &MetadataDestinationSnapshot,
) -> Result<()> {
    for (field, candidate) in [
        ("destination_id", value.destination_id.as_str()),
        ("display_name", value.display_name.as_str()),
        ("location_id", value.location_id.as_str()),
        ("git_remote_name", value.git_remote_name.as_str()),
        ("remote_locator", value.remote_locator.as_str()),
        ("remote_ref", value.remote_ref.as_str()),
    ] {
        if candidate.trim().is_empty() {
            return Err(MetadataError::Invalid(format!("{field} is required")));
        }
    }
    if !value.remote_ref.starts_with("refs/") {
        return Err(MetadataError::Invalid(
            "remote_ref must begin with refs/".to_owned(),
        ));
    }
    if !locator_is_secret_free(&value.remote_locator) {
        return Err(MetadataError::Invalid(
            "remote_locator must not contain embedded credentials or secret parameters".to_owned(),
        ));
    }
    let expected_status = if action == RegistryAction::Retire {
        "retired"
    } else {
        "active"
    };
    if value.status != expected_status {
        return Err(MetadataError::Invalid(format!(
            "destination status must be {expected_status}"
        )));
    }
    require_active_location(path, &value.location_id)?;
    let connection = open(path)?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata_destinations WHERE destination_id = ?1)",
            [&value.destination_id],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, source))?;
    if action == RegistryAction::Register && exists {
        return Err(MetadataError::AlreadyExists(value.destination_id.clone()));
    }
    if action != RegistryAction::Register && !exists {
        return Err(MetadataError::NotFound(value.destination_id.clone()));
    }
    Ok(())
}

fn require_active_location(path: &Path, location_id: &str) -> Result<()> {
    let connection = open(path)?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM locations WHERE location_id = ?1 AND status = 'active')",
            [location_id],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, source))?;
    if !exists {
        return Err(MetadataError::Invalid(format!(
            "active location not found: {location_id}"
        )));
    }
    Ok(())
}

fn latest_checkpoint(
    connection: &Connection,
    path: &Path,
    predicate: &str,
) -> Result<Option<(u64, String)>> {
    let sql = format!(
        "SELECT event_last_seq, event_last_hash FROM checkpoints
         WHERE {predicate} ORDER BY event_last_seq DESC LIMIT 1"
    );
    connection
        .query_row(&sql, [], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .optional()
        .map_err(|source| sqlite_error(path, source))?
        .map(|(seq, hash)| Ok((sql_u64(seq)?, hash)))
        .transpose()
}

fn is_local_locator(value: &str) -> bool {
    if value.starts_with("file://") {
        return true;
    }
    if value.contains("://") {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
    {
        return true;
    }
    !value.contains(':')
}

pub(crate) fn locator_is_secret_free(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if ["password=", "token=", "secret=", "access_key="]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return false;
    }
    let Some((_, remainder)) = value.split_once("://") else {
        return true;
    };
    let authority = remainder.split('/').next().unwrap_or(remainder);
    authority
        .split_once('@')
        .is_none_or(|(userinfo, _)| !userinfo.contains(':'))
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn commit_checkpoint(repository: &Path, checkpoint: &Checkpoint) -> Result<String> {
    ensure_git_repository(repository)?;
    let reference = "refs/heads/archive-ledger";
    let parent = git_ref_optional(repository, reference)?;
    let index = TemporaryIndex(std::env::temp_dir().join(format!(
        "archive-ledger-index-{}",
        Ulid::new().to_string().to_ascii_lowercase()
    )));
    let mut read_tree = git_command(repository);
    read_tree.env("GIT_INDEX_FILE", &index.0).arg("read-tree");
    if let Some(parent) = &parent {
        read_tree.arg(parent);
    } else {
        read_tree.arg("--empty");
    }
    run_git(repository, "prepare checkpoint index", &mut read_tree)?;
    let paths = checkpoint_paths(checkpoint);
    let mut add = git_command(repository);
    add.env("GIT_INDEX_FILE", &index.0).arg("add").arg("--");
    add.args(&paths);
    run_git(repository, "stage checkpoint files", &mut add)?;
    let mut write_tree = git_command(repository);
    write_tree.env("GIT_INDEX_FILE", &index.0).arg("write-tree");
    let tree = git_stdout(repository, "write checkpoint tree", &mut write_tree)?;
    let mut commit_tree = git_command(repository);
    commit_tree
        .env("GIT_AUTHOR_NAME", "Archive Ledger")
        .env("GIT_AUTHOR_EMAIL", "archive-ledger@localhost")
        .env("GIT_COMMITTER_NAME", "Archive Ledger")
        .env("GIT_COMMITTER_EMAIL", "archive-ledger@localhost")
        .arg("commit-tree")
        .arg(&tree);
    if let Some(parent) = &parent {
        commit_tree.arg("-p").arg(parent);
    }
    commit_tree.arg("-m").arg(format!(
        "Archive Ledger checkpoint {}",
        checkpoint.checkpoint_id
    ));
    let commit = git_stdout(repository, "commit checkpoint tree", &mut commit_tree)?;
    let mut update_ref = git_command(repository);
    update_ref.arg("update-ref").arg(reference).arg(&commit);
    if let Some(parent) = &parent {
        update_ref.arg(parent);
    } else {
        update_ref.arg("0".repeat(commit.len()));
    }
    run_git(repository, "publish checkpoint ref", &mut update_ref)?;
    verify_checkpoint_commit(repository, checkpoint, &commit)?;
    Ok(commit)
}

struct TemporaryIndex(PathBuf);

impl Drop for TemporaryIndex {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn find_checkpoint_commit(repository: &Path, checkpoint: &Checkpoint) -> Result<String> {
    let checkpoint_path = format!("checkpoints/{}.json", checkpoint.checkpoint_id);
    let output = git_required(
        repository,
        "find checkpoint commit",
        &[
            "log",
            "--diff-filter=A",
            "--format=%H",
            "refs/heads/archive-ledger",
            "--",
            &checkpoint_path,
        ],
    )?;
    let commits = output
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if commits.len() != 1 {
        return Err(MetadataError::Invalid(format!(
            "expected one commit introducing checkpoint {}, found {}",
            checkpoint.checkpoint_id,
            commits.len()
        )));
    }
    verify_checkpoint_commit(repository, checkpoint, commits[0])?;
    Ok(commits[0].to_owned())
}

fn verify_checkpoint_commit(
    repository: &Path,
    checkpoint: &Checkpoint,
    commit: &str,
) -> Result<()> {
    if !is_git_object_id(commit) {
        return Err(MetadataError::Invalid(
            "invalid checkpoint commit identity".to_owned(),
        ));
    }
    for relative in checkpoint_paths(checkpoint) {
        let worktree_object = git_required(
            repository,
            "hash checkpoint file",
            &["hash-object", &relative],
        )?;
        let committed = git_required(
            repository,
            "read committed checkpoint file",
            &["rev-parse", &format!("{commit}:{relative}")],
        )?;
        if worktree_object != committed {
            return Err(MetadataError::Invalid(format!(
                "checkpoint commit does not contain exact bytes for {relative}"
            )));
        }
    }
    Ok(())
}

fn checkpoint_paths(checkpoint: &Checkpoint) -> Vec<String> {
    let mut paths = checkpoint
        .segments
        .iter()
        .flat_map(|segment| [segment.file.clone(), segment.manifest.clone()])
        .collect::<Vec<_>>();
    paths.push(format!("checkpoints/{}.json", checkpoint.checkpoint_id));
    paths
}

fn observe_remote(
    repository: &Path,
    destination: &MetadataDestinationSnapshot,
    checkpoint: &Checkpoint,
    commit: &str,
    push: bool,
) -> Result<Option<String>> {
    if push {
        let refspec = format!("{commit}:{}", destination.remote_ref);
        git_required(
            repository,
            "push metadata checkpoint",
            &["push", &destination.git_remote_name, &refspec],
        )?;
    }
    let output = git_required(
        repository,
        "observe metadata checkpoint remote",
        &[
            "ls-remote",
            &destination.git_remote_name,
            &destination.remote_ref,
        ],
    )?;
    let mut lines = output.lines().filter(|line| !line.is_empty());
    let observed = lines.next().and_then(|line| line.split_whitespace().next());
    if lines.next().is_some() {
        return Err(MetadataError::Invalid(format!(
            "remote ref {} is ambiguous for checkpoint {}",
            destination.remote_ref, checkpoint.checkpoint_id
        )));
    }
    Ok(observed.map(str::to_owned))
}

fn ensure_git_repository(repository: &Path) -> Result<()> {
    if repository.join(".git").exists() {
        git_required(
            repository,
            "inspect Git repository",
            &["rev-parse", "--git-dir"],
        )?;
    } else {
        git_required(
            repository,
            "initialize Git repository",
            &["init", "--quiet"],
        )?;
    }
    Ok(())
}

fn git_command(repository: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(repository).env("LC_ALL", "C");
    command
}

fn git_required(repository: &Path, operation: &'static str, args: &[&str]) -> Result<String> {
    let mut command = git_command(repository);
    command.args(args);
    git_stdout(repository, operation, &mut command)
}

fn git_ref_optional(repository: &Path, reference: &str) -> Result<Option<String>> {
    let mut command = git_command(repository);
    command.args(["rev-parse", "--verify", "--quiet", reference]);
    let output = command.output().map_err(|source| MetadataError::Io {
        operation: "run Git",
        path: repository.to_path_buf(),
        source,
    })?;
    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ));
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    Err(git_failure(repository, "read checkpoint ref"))
}

fn run_git(repository: &Path, operation: &'static str, command: &mut Command) -> Result<()> {
    git_stdout(repository, operation, command).map(|_| ())
}

fn git_stdout(repository: &Path, operation: &'static str, command: &mut Command) -> Result<String> {
    let output = command.output().map_err(|source| MetadataError::Io {
        operation: "run Git",
        path: repository.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return Err(git_failure(repository, operation));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_failure(repository: &Path, operation: &'static str) -> MetadataError {
    MetadataError::Git {
        operation,
        path: repository.to_path_buf(),
        detail: "Git returned a non-zero status; credentials and remote details were not logged"
            .to_owned(),
    }
}

fn open(path: &Path) -> Result<Connection> {
    Connection::open(path).map_err(|source| sqlite_error(path, source))
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> MetadataError {
    MetadataError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

fn sql_u64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| MetadataError::Invalid("SQLite integer is outside u64 range".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventStoreConfig, ProjectionConfig};
    use tempfile::TempDir;

    #[test]
    fn local_git_locators_are_conservatively_classified() {
        for locator in [
            "/backup/repo.git",
            "../backup.git",
            "backup.git",
            "file:///backup",
        ] {
            assert!(is_local_locator(locator), "{locator}");
        }
        assert!(is_local_locator(r"C:\backup\repo.git"));
        assert!(!is_local_locator("ssh://host/repo.git"));
        assert!(!is_local_locator("user@host:repo.git"));
    }

    fn fixture(temp: &TempDir) -> (EventStore, ProjectionDb) {
        let events = EventStore::open_or_create(
            temp.path().join("canonical"),
            EventStoreConfig {
                actor_id: "test-user".to_owned(),
                host_id: "test-host".to_owned(),
                ..EventStoreConfig::default()
            },
        )
        .unwrap();
        let database = ProjectionDb::open_or_create(
            temp.path().join("archive.db"),
            "arc_metadata",
            ProjectionConfig::default(),
        )
        .unwrap();
        events
            .append_batch(vec![
                EventRequest::new("archive_initialized", json!({"archive_id":"arc_metadata"})),
                EventRequest::new("site_registered", json!({
                    "site_id":"site_home","display_name":"Home","site_kind":"home",
                    "description":null,"status":"active"})),
                EventRequest::new("site_registered", json!({
                    "site_id":"site_remote","display_name":"Remote","site_kind":"office",
                    "description":null,"status":"active"})),
                EventRequest::new("device_registered", json!({
                    "device_id":"device_home","display_name":"Catalog disk","device_kind":"disk",
                    "serial_hint":null,"hardware_fingerprint":"home","fingerprint_kind":"serial",
                    "identity_state":"confirmed","owner":null,"status":"active",
                    "current_site_id":"site_home","expected_availability":"online"})),
                EventRequest::new("device_registered", json!({
                    "device_id":"device_remote","display_name":"Remote disk","device_kind":"disk",
                    "serial_hint":null,"hardware_fingerprint":"remote","fingerprint_kind":"serial",
                    "identity_state":"confirmed","owner":null,"status":"active",
                    "current_site_id":"site_remote","expected_availability":"online"})),
                EventRequest::new("archive_root_registered", json!({
                    "archive_root_id":"root_home","device_id":"device_home","display_name":"Catalog root",
                    "root_path_on_device":{"encoding":"utf8","text":"/catalog","base64":null,"display":"/catalog"},
                    "status":"active"})),
                EventRequest::new("archive_root_registered", json!({
                    "archive_root_id":"root_remote","device_id":"device_remote","display_name":"Remote root",
                    "root_path_on_device":{"encoding":"utf8","text":"/backup","base64":null,"display":"/backup"},
                    "status":"active"})),
                EventRequest::new("location_registered", json!({
                    "location_id":"location_catalog","display_name":"Catalog","kind":"filesystem",
                    "archive_root_id":"root_home","relative_path":{"encoding":"utf8","text":"ledger","base64":null,"display":"ledger"},
                    "device_id":"device_home","site_id":null,"encryption_state":"encrypted",
                    "trust_level":"trusted","expected_availability":"online","is_writable":true,"status":"active"})),
                EventRequest::new("location_registered", json!({
                    "location_id":"location_remote","display_name":"Remote metadata","kind":"filesystem",
                    "archive_root_id":"root_remote","relative_path":{"encoding":"utf8","text":"ledger","base64":null,"display":"ledger"},
                    "device_id":"device_remote","site_id":null,"encryption_state":"encrypted",
                    "trust_level":"trusted","expected_availability":"online","is_writable":true,"status":"active"})),
            ])
            .unwrap();
        database.apply(&events).unwrap();
        (events, database)
    }

    #[test]
    fn checkpoint_replication_status_and_clean_restore_are_evidence_based() {
        let temp = TempDir::new().unwrap();
        let (events, database) = fixture(&temp);
        let registry = MetadataRegistry::new(&events, &database);
        registry.set_catalog_location("location_catalog").unwrap();

        let remote = temp.path().join("remote.git");
        assert!(Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&remote)
            .status()
            .unwrap()
            .success());
        let destination = MetadataDestinationSnapshot {
            destination_id: "destination_remote".to_owned(),
            display_name: "Remote Git".to_owned(),
            location_id: "location_remote".to_owned(),
            git_remote_name: "backup".to_owned(),
            remote_locator: remote.display().to_string(),
            remote_ref: "refs/heads/archive-ledger".to_owned(),
            status: "active".to_owned(),
        };
        registry
            .record_destination(RegistryAction::Register, destination.clone())
            .unwrap();
        let independent = database
            .assess_metadata_independence(&MetadataDestinationSnapshot {
                remote_locator: "ssh://backup.example/archive-ledger.git".to_owned(),
                ..destination.clone()
            })
            .unwrap();
        assert_eq!(independent.status, "independent");
        assert_eq!(
            database
                .assess_metadata_independence(&destination)
                .unwrap()
                .status,
            "unknown",
            "a local path must not be called independent without storage identity proof"
        );

        let protector = MetadataProtector::new(&events, &database);
        let checkpoint = protector.checkpoint(false).unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(events.root())
            .args(["remote", "add", "backup"])
            .arg(&remote)
            .status()
            .unwrap()
            .success());
        protector
            .check_destination(&checkpoint.checkpoint_id, "destination_remote", false)
            .unwrap();
        assert_eq!(
            database.metadata_protection_status().unwrap().destinations[0]
                .latest_replication_status
                .as_deref(),
            Some("missing")
        );
        protector
            .check_destination(&checkpoint.checkpoint_id, "destination_remote", true)
            .unwrap();
        let status = database.metadata_protection_status().unwrap();
        assert_eq!(status.checkpointed_through_seq, checkpoint.event_last_seq);
        assert_eq!(status.committed_through_seq, checkpoint.event_last_seq);
        assert_eq!(status.independently_protected_through_seq, 0);
        assert_eq!(
            status.destinations[0].latest_replication_status.as_deref(),
            Some("present")
        );
        assert_eq!(
            status.destinations[0].latest_independence_status.as_deref(),
            Some("unknown")
        );

        let clone = temp.path().join("restored-events");
        assert!(Command::new("git")
            .args(["clone", "--quiet", "--branch", "archive-ledger"])
            .arg(&remote)
            .arg(&clone)
            .status()
            .unwrap()
            .success());
        let restored_db = temp.path().join("restored.db");
        let restored = restore_check(&clone, &restored_db).unwrap();
        assert_eq!(restored.archive_id, "arc_metadata");
        assert_eq!(restored.verified_event_seq, checkpoint.event_last_seq + 1);
        assert_eq!(restored.rebuilt_event_seq, checkpoint.event_last_seq + 1);
        assert_eq!(restored.checkpoints_verified, 1);
        let rebuilt =
            ProjectionDb::open_existing(&restored_db, ProjectionConfig::default()).unwrap();
        assert_eq!(
            rebuilt
                .metadata_protection_status()
                .unwrap()
                .committed_through_seq,
            checkpoint.event_last_seq
        );
    }

    #[test]
    fn topology_change_invalidates_a_prior_independence_observation() {
        let temp = TempDir::new().unwrap();
        let (events, database) = fixture(&temp);
        let registry = MetadataRegistry::new(&events, &database);
        registry.set_catalog_location("location_catalog").unwrap();
        registry
            .record_destination(
                RegistryAction::Register,
                MetadataDestinationSnapshot {
                    destination_id: "destination_remote".to_owned(),
                    display_name: "Remote Git".to_owned(),
                    location_id: "location_remote".to_owned(),
                    git_remote_name: "backup".to_owned(),
                    remote_locator: "ssh://backup.example/archive-ledger.git".to_owned(),
                    remote_ref: "refs/heads/archive-ledger".to_owned(),
                    status: "active".to_owned(),
                },
            )
            .unwrap();
        let checkpoint = events.create_checkpoint().unwrap();
        database.apply(&events).unwrap();
        let commit = "a".repeat(40);
        events
            .append_batch(vec![
                EventRequest::new(
                    "checkpoint_commit_observed",
                    json!({
                        "checkpoint_id":checkpoint.checkpoint_id,
                        "git_commit":commit,
                        "event_last_seq":checkpoint.event_last_seq,
                        "event_last_hash":checkpoint.event_last_hash,
                    }),
                ),
                EventRequest::new(
                    "checkpoint_replication_observed",
                    json!({
                        "checkpoint_id":checkpoint.checkpoint_id,
                        "destination_id":"destination_remote",
                        "status":"present",
                        "observed_git_commit":commit,
                        "observed_event_last_seq":checkpoint.event_last_seq,
                        "observed_event_last_hash":checkpoint.event_last_hash,
                        "independence_status":"independent",
                        "independence_reasons":[],
                        "error_code":null,
                        "error_detail":null,
                    }),
                ),
            ])
            .unwrap();
        database.apply(&events).unwrap();
        assert_eq!(
            database
                .metadata_protection_status()
                .unwrap()
                .independently_protected_through_seq,
            checkpoint.event_last_seq
        );

        events
            .append(EventRequest::new(
                "site_updated",
                json!({"site_id":"site_remote","display_name":"Remote moved",
                    "site_kind":"office","description":null,"status":"active"}),
            ))
            .unwrap();
        database.apply(&events).unwrap();
        let status = database.metadata_protection_status().unwrap();
        assert_eq!(status.independently_protected_through_seq, 0);
        assert_eq!(
            status.destinations[0].latest_independence_status.as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn reconcile_records_a_verified_commit_after_the_crash_window() {
        let temp = TempDir::new().unwrap();
        let (events, database) = fixture(&temp);
        let checkpoint = events.create_checkpoint().unwrap();
        database.apply(&events).unwrap();
        let commit = commit_checkpoint(events.root(), &checkpoint).unwrap();
        assert_eq!(
            database
                .metadata_protection_status()
                .unwrap()
                .committed_through_seq,
            0,
            "a Git ref alone is not projected as an observed commit"
        );
        let reconciled = MetadataProtector::new(&events, &database)
            .reconcile(&checkpoint.checkpoint_id)
            .unwrap();
        assert_eq!(reconciled.local_git_commit, commit);
        assert_eq!(
            database
                .metadata_protection_status()
                .unwrap()
                .committed_through_seq,
            checkpoint.event_last_seq
        );
        let applied = database.status().unwrap().cursor.applied_seq;
        MetadataProtector::new(&events, &database)
            .reconcile(&checkpoint.checkpoint_id)
            .unwrap();
        assert_eq!(database.status().unwrap().cursor.applied_seq, applied);
    }
}
