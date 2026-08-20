//! Streaming preservation-policy and disaster-loss evaluation over SQLite state.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use ulid::Ulid;

use crate::projection::ProjectionDb;

const RULES_VERSION: u64 = 1;
const DAY_MS: u64 = 86_400_000;
const FINDING_PAGE_VERSION: u32 = 1;
const MAX_FINDING_PAGE_SIZE: usize = 1_000;

pub type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("SQLite operation failed for {path}: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("policy {policy_id} has invalid requirements: {message}")]
    InvalidRequirements { policy_id: String, message: String },

    #[error("policy evaluation cannot use projection state: {0}")]
    InvalidState(String),

    #[error("finding page limit must be between 1 and {MAX_FINDING_PAGE_SIZE}")]
    InvalidLimit,

    #[error("invalid policy finding continuation token")]
    InvalidContinuation,

    #[error("policy finding continuation token is stale; restart the query")]
    StaleContinuation,
}

impl PolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Sqlite { .. } => "policy_sqlite",
            Self::InvalidRequirements { .. } => "policy_invalid_requirements",
            Self::InvalidState(_) => "policy_invalid_state",
            Self::InvalidLimit => "invalid_limit",
            Self::InvalidContinuation => "invalid_continuation",
            Self::StaleContinuation => "stale_continuation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequirements {
    pub min_qualifying_copies: u64,
    pub min_devices: u64,
    pub min_sites: u64,
    pub require_offsite_copy: bool,
    pub require_offline_copy: bool,
    pub require_encrypted_offsite: bool,
    pub max_verification_age_days: u64,
    pub max_observation_age_days: u64,
    pub max_device_checkin_age_days: u64,
}

impl PolicyRequirements {
    pub fn from_json(policy_id: &str, text: &str) -> Result<Self> {
        let value: Self =
            serde_json::from_str(text).map_err(|error| PolicyError::InvalidRequirements {
                policy_id: policy_id.to_owned(),
                message: error.to_string(),
            })?;
        if [
            value.min_qualifying_copies,
            value.min_devices,
            value.min_sites,
            value.max_verification_age_days,
            value.max_observation_age_days,
            value.max_device_checkin_age_days,
        ]
        .contains(&0)
        {
            return Err(PolicyError::InvalidRequirements {
                policy_id: policy_id.to_owned(),
                message: "counts and age limits must be positive integers".to_owned(),
            });
        }
        for (field, days) in [
            ("max_verification_age_days", value.max_verification_age_days),
            ("max_observation_age_days", value.max_observation_age_days),
            (
                "max_device_checkin_age_days",
                value.max_device_checkin_age_days,
            ),
        ] {
            if days.checked_mul(DAY_MS).is_none() {
                return Err(PolicyError::InvalidRequirements {
                    policy_id: policy_id.to_owned(),
                    message: format!("{field} is too large"),
                });
            }
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub evaluation_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub files_total: u64,
    pub files_satisfied: u64,
    pub files_violated: u64,
    pub files_uncertain: u64,
    pub valid_until_utc_ms: Option<u64>,
    pub files_size_unknown: u64,
    pub bytes_known_total: u64,
    pub bytes_known_at_risk: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnconfiguredCollection {
    pub collection_id: String,
    pub display_name: String,
    pub reason: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvaluationResult {
    pub version: u32,
    pub evaluated_event_seq: u64,
    pub evaluated_policy_input_seq: u64,
    pub evaluations: Vec<PolicyEvaluation>,
    pub unconfigured_collections: Vec<UnconfiguredCollection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyFinding {
    pub evaluation_id: String,
    pub file_ref_id: String,
    pub object_id: Option<String>,
    pub policy_id: String,
    pub policy_version: u64,
    pub status: String,
    pub collection_id: String,
    pub collection_name: String,
    pub logical_path_display: String,
    pub size_bytes: Option<u64>,
    pub reasons: Value,
    pub recommended_actions: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyFindingFilter {
    pub policy_id: Option<String>,
    pub collection_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyFindingPage {
    pub version: u32,
    pub applied_event_seq: u64,
    pub items: Vec<PolicyFinding>,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicyFindingToken {
    version: u32,
    applied_event_seq: u64,
    evaluation_hash: String,
    query_hash: String,
    policy_id: String,
    file_ref_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvaluationValidity {
    pub evaluation_id: String,
    pub usable: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QualifyingCopyReview {
    pub copy_claim_id: String,
    pub location_id: String,
    pub location_name: String,
    pub device_id: Option<String>,
    pub site_id: String,
    pub offsite: bool,
    pub offline: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilePolicyReview {
    pub version: u32,
    pub applied_event_seq: u64,
    pub file_ref_id: String,
    pub logical_path_display: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub status: String,
    pub qualifying_copies: Vec<QualifyingCopyReview>,
    pub reasons: Value,
    pub recommended_actions: Value,
    pub valid_until_utc_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StalePolicyEvaluation {
    pub policy_id: String,
    pub evaluation_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedPolicyStatus {
    pub version: u32,
    pub applied_event_seq: u64,
    pub evaluations: Vec<PolicyEvaluation>,
    pub unconfigured_collections: Vec<UnconfiguredCollection>,
    pub stale_policies: Vec<StalePolicyEvaluation>,
}

#[derive(Debug, Clone)]
struct PolicyContext {
    evaluation_id: String,
    policy_id: String,
    policy_version: u64,
    requirements: PolicyRequirements,
    files_expected: u64,
    files_evaluated: u64,
    files_satisfied: u64,
    files_violated: u64,
    files_uncertain: u64,
    files_size_unknown: u64,
    bytes_known_total: u64,
    bytes_known_at_risk: u64,
    valid_until_utc_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct FileFact {
    file_ref_id: String,
    object_id: Option<String>,
    identity_state: String,
    logical_path_display: String,
    size_bytes: Option<u64>,
    hash_algo: Option<String>,
    policy_id: String,
    collection_id: String,
    collection_name: String,
    home_site_id: String,
    copies: Vec<CopyFact>,
}

#[derive(Debug, Clone)]
struct CopyFact {
    copy_claim_id: String,
    state: String,
    object_id: Option<String>,
    last_seen_time_utc_ms: Option<u64>,
    last_verified_time_utc_ms: Option<u64>,
    last_verification_result: Option<String>,
    location_id: String,
    location_name: String,
    location_kind: String,
    location_status: String,
    archive_root_id: Option<String>,
    archive_root_status: Option<String>,
    archive_root_device_id: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    device_status: Option<String>,
    device_identity_state: Option<String>,
    device_expected_availability: Option<String>,
    last_checkin_time_utc_ms: Option<u64>,
    last_fingerprint_match_time_utc_ms: Option<u64>,
    last_fingerprint_status: Option<String>,
    site_id: Option<String>,
    site_name: Option<String>,
    site_status: Option<String>,
    encryption_state: Option<String>,
    trust_level: Option<String>,
    location_expected_availability: String,
}

#[derive(Debug, Clone)]
struct QualifiedCopy {
    copy_claim_id: String,
    location_id: String,
    location_name: String,
    device_id: Option<String>,
    device_name: Option<String>,
    site_id: String,
    site_name: String,
    offsite: bool,
    offline: bool,
    encrypted: bool,
    domains: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct DomainTopology {
    names: BTreeMap<String, String>,
    assignments: HashMap<(String, String), BTreeSet<String>>,
}

#[derive(Debug)]
struct FileEvaluation {
    status: Option<String>,
    reasons: Value,
    actions: Value,
    valid_until_utc_ms: Option<u64>,
    qualifying_copies: Vec<QualifyingCopyReview>,
}

#[derive(Debug)]
struct ProjectionMarker {
    applied_seq: u64,
    applied_event_hash: String,
    policy_input_event_seq: u64,
}

#[derive(Debug)]
struct ValidityRow {
    status: String,
    files_expected: i64,
    files_evaluated: i64,
    evaluated_policy_input_seq: i64,
    evaluation_policy_version: i64,
    valid_until_utc_ms: Option<i64>,
    current_policy_version: i64,
    policy_status: String,
    policy_enabled: i64,
    rules_version: i64,
    rollup_total: Option<i64>,
    rollup_satisfied: Option<i64>,
    rollup_violated: Option<i64>,
    rollup_uncertain: Option<i64>,
    finding_count: i64,
}

#[derive(Debug)]
struct CopyAssessment {
    qualified: Option<QualifiedCopy>,
    reasons: Vec<String>,
    uncertain: bool,
}

impl ProjectionDb {
    /// Evaluates every configured active collection and atomically publishes
    /// complete local cache envelopes. Canonical archive data is never mutated.
    pub fn evaluate_policies(&self, now_utc_ms: u64) -> Result<PolicyEvaluationResult> {
        let mut connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(self.path(), source))?;
        let marker = load_projection_marker(&transaction, self.path())?;

        let topology = load_domain_topology(&transaction, self.path())?;
        let unconfigured = load_unconfigured_collections(&transaction, self.path())?;
        let mut policies = load_policy_contexts(
            &transaction,
            self.path(),
            marker.applied_seq,
            &marker.applied_event_hash,
            marker.policy_input_event_seq,
            now_utc_ms,
        )?;
        stream_and_evaluate_files(
            &transaction,
            self.path(),
            &topology,
            &mut policies,
            marker.applied_seq,
            marker.policy_input_event_seq,
            now_utc_ms,
        )?;
        finish_evaluations(
            &transaction,
            self.path(),
            &policies,
            marker.applied_seq,
            marker.policy_input_event_seq,
            now_utc_ms,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(self.path(), source))?;

        Ok(PolicyEvaluationResult {
            version: RULES_VERSION as u32,
            evaluated_event_seq: marker.applied_seq,
            evaluated_policy_input_seq: marker.policy_input_event_seq,
            evaluations: policies
                .into_values()
                .map(|policy| PolicyEvaluation {
                    evaluation_id: policy.evaluation_id,
                    policy_id: policy.policy_id,
                    policy_version: policy.policy_version,
                    files_total: policy.files_evaluated,
                    files_satisfied: policy.files_satisfied,
                    files_violated: policy.files_violated,
                    files_uncertain: policy.files_uncertain,
                    valid_until_utc_ms: policy.valid_until_utc_ms,
                    files_size_unknown: policy.files_size_unknown,
                    bytes_known_total: policy.bytes_known_total,
                    bytes_known_at_risk: policy.bytes_known_at_risk,
                })
                .collect(),
            unconfigured_collections: unconfigured,
        })
    }

    pub fn policy_evaluation_validity(
        &self,
        evaluation_id: &str,
        now_utc_ms: u64,
    ) -> Result<PolicyEvaluationValidity> {
        let connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        let marker = load_projection_marker(&connection, self.path())?;
        let row = connection
            .query_row(
                "SELECT e.status, e.files_expected, e.files_evaluated,
                        e.evaluated_policy_input_seq, e.policy_version,
                        e.valid_until_utc_ms, p.policy_version, p.status, p.enabled,
                        e.rules_version, r.files_total, r.files_satisfied,
                        r.files_violated, r.files_uncertain,
                        (SELECT COUNT(*) FROM policy_status s
                         WHERE s.evaluation_id = e.evaluation_id)
                 FROM policy_evaluations e
                 JOIN policies p ON p.policy_id = e.policy_id
                 LEFT JOIN policy_rollup r ON r.evaluation_id = e.evaluation_id
                                           AND r.policy_id = e.policy_id
                 WHERE e.evaluation_id = ?1",
                [evaluation_id],
                |row| {
                    Ok(ValidityRow {
                        status: row.get(0)?,
                        files_expected: row.get(1)?,
                        files_evaluated: row.get(2)?,
                        evaluated_policy_input_seq: row.get(3)?,
                        evaluation_policy_version: row.get(4)?,
                        valid_until_utc_ms: row.get(5)?,
                        current_policy_version: row.get(6)?,
                        policy_status: row.get(7)?,
                        policy_enabled: row.get(8)?,
                        rules_version: row.get(9)?,
                        rollup_total: row.get(10)?,
                        rollup_satisfied: row.get(11)?,
                        rollup_violated: row.get(12)?,
                        rollup_uncertain: row.get(13)?,
                        finding_count: row.get(14)?,
                    })
                },
            )
            .optional()
            .map_err(|source| sqlite_error(self.path(), source))?;
        let reason = row
            .as_ref()
            .and_then(|row| invalid_evaluation_reason(row, &marker, now_utc_ms).map(str::to_owned));
        let reason = if row.is_none() {
            Some("unknown_evaluation".to_owned())
        } else {
            reason
        };
        Ok(PolicyEvaluationValidity {
            evaluation_id: evaluation_id.to_owned(),
            usable: reason.is_none(),
            reason,
        })
    }

    pub fn cached_policy_status(&self, now_utc_ms: u64) -> Result<CachedPolicyStatus> {
        let connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        let marker = load_projection_marker(&connection, self.path())?;
        let unconfigured_collections = load_unconfigured_collections(&connection, self.path())?;
        let mut statement = connection
            .prepare(
                "SELECT DISTINCT p.policy_id,
                    (SELECT e.evaluation_id FROM policy_evaluations e
                     WHERE e.policy_id = p.policy_id AND e.status = 'complete'
                     ORDER BY e.completed_time_utc_ms DESC, e.evaluation_id DESC LIMIT 1)
                 FROM policies p
                 JOIN collections c ON c.policy_id = p.policy_id AND c.status = 'active'
                 WHERE p.status = 'active' AND p.enabled = 1
                 ORDER BY p.policy_id",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut evaluations = Vec::new();
        let mut stale_policies = Vec::new();
        for row in rows {
            let (policy_id, evaluation_id) =
                row.map_err(|source| sqlite_error(self.path(), source))?;
            let Some(evaluation_id) = evaluation_id else {
                stale_policies.push(StalePolicyEvaluation {
                    policy_id,
                    evaluation_id: None,
                    reason: "evaluation_missing".to_owned(),
                });
                continue;
            };
            let validity = self.policy_evaluation_validity(&evaluation_id, now_utc_ms)?;
            if let Some(reason) = validity.reason {
                stale_policies.push(StalePolicyEvaluation {
                    policy_id,
                    evaluation_id: Some(evaluation_id),
                    reason,
                });
                continue;
            }
            let evaluation = connection
                .query_row(
                    "SELECT r.policy_version, r.files_total, r.files_satisfied,
                            r.files_violated, r.files_uncertain, e.valid_until_utc_ms,
                            r.files_size_unknown, r.bytes_known_total, r.bytes_known_at_risk
                     FROM policy_rollup r
                     JOIN policy_evaluations e ON e.evaluation_id = r.evaluation_id
                     WHERE r.evaluation_id = ?1 AND r.policy_id = ?2",
                    params![evaluation_id, policy_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<i64>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, i64>(8)?,
                        ))
                    },
                )
                .map_err(|source| sqlite_error(self.path(), source))?;
            evaluations.push(PolicyEvaluation {
                evaluation_id,
                policy_id,
                policy_version: sql_u64(evaluation.0, "policy_version")?,
                files_total: sql_u64(evaluation.1, "files_total")?,
                files_satisfied: sql_u64(evaluation.2, "files_satisfied")?,
                files_violated: sql_u64(evaluation.3, "files_violated")?,
                files_uncertain: sql_u64(evaluation.4, "files_uncertain")?,
                valid_until_utc_ms: optional_u64(evaluation.5, "valid_until_utc_ms")?,
                files_size_unknown: sql_u64(evaluation.6, "files_size_unknown")?,
                bytes_known_total: sql_u64(evaluation.7, "bytes_known_total")?,
                bytes_known_at_risk: sql_u64(evaluation.8, "bytes_known_at_risk")?,
            });
        }
        Ok(CachedPolicyStatus {
            version: RULES_VERSION as u32,
            applied_event_seq: marker.applied_seq,
            evaluations,
            unconfigured_collections,
            stale_policies,
        })
    }

    /// Read one deterministic page from the latest usable cached evaluations.
    ///
    /// The supplied status is the validity envelope already shown to the user.
    /// The continuation token binds to that envelope, the filters, and SQLite's
    /// applied sequence so a later evaluation or projection update cannot cause
    /// a page to silently skip or duplicate findings.
    pub fn cached_policy_findings(
        &self,
        status: &CachedPolicyStatus,
        filter: &PolicyFindingFilter,
        limit: usize,
        continuation: Option<&str>,
    ) -> Result<PolicyFindingPage> {
        if !(1..=MAX_FINDING_PAGE_SIZE).contains(&limit) {
            return Err(PolicyError::InvalidLimit);
        }
        if filter
            .status
            .as_deref()
            .is_some_and(|value| !matches!(value, "violated" | "uncertain"))
        {
            return Err(PolicyError::InvalidState(
                "finding status must be violated or uncertain".to_owned(),
            ));
        }

        let connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        let marker = load_projection_marker(&connection, self.path())?;
        if marker.applied_seq != status.applied_event_seq {
            return Err(PolicyError::StaleContinuation);
        }

        let mut evaluations = status
            .evaluations
            .iter()
            .filter(|evaluation| {
                filter
                    .policy_id
                    .as_deref()
                    .is_none_or(|policy_id| evaluation.policy_id == policy_id)
            })
            .collect::<Vec<_>>();
        evaluations.sort_unstable_by(|left, right| left.policy_id.cmp(&right.policy_id));
        let evaluation_ids = evaluations
            .iter()
            .map(|evaluation| evaluation.evaluation_id.as_str())
            .collect::<Vec<_>>();
        let evaluation_hash = blake3::hash(
            serde_json::to_string(&evaluation_ids)
                .expect("evaluation IDs are serializable")
                .as_bytes(),
        )
        .to_hex()
        .to_string();
        let query_hash = policy_finding_query_hash(filter);
        let cursor = continuation.map(decode_policy_finding_token).transpose()?;
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.applied_event_seq != status.applied_event_seq
                || cursor.evaluation_hash != evaluation_hash
                || cursor.query_hash != query_hash
        }) {
            return Err(PolicyError::StaleContinuation);
        }
        if evaluation_ids.is_empty() {
            return Ok(PolicyFindingPage {
                version: FINDING_PAGE_VERSION,
                applied_event_seq: status.applied_event_seq,
                items: Vec::new(),
                next: None,
            });
        }

        let mut items = Vec::new();
        for evaluation in evaluations {
            if cursor
                .as_ref()
                .is_some_and(|cursor| evaluation.policy_id < cursor.policy_id)
            {
                continue;
            }
            let after_file_ref_id = cursor.as_ref().and_then(|cursor| {
                (cursor.policy_id == evaluation.policy_id).then_some(cursor.file_ref_id.as_str())
            });
            let remaining = limit + 1 - items.len();
            items.extend(self.policy_findings_filtered_after(
                &evaluation.evaluation_id,
                filter.collection_id.as_deref(),
                filter.status.as_deref(),
                after_file_ref_id,
                remaining,
            )?);
            if items.len() > limit {
                break;
            }
        }
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next = if has_more {
            items
                .last()
                .map(|finding| {
                    encode_policy_finding_token(
                        finding,
                        status.applied_event_seq,
                        &evaluation_hash,
                        &query_hash,
                    )
                })
                .transpose()?
        } else {
            None
        };
        Ok(PolicyFindingPage {
            version: FINDING_PAGE_VERSION,
            applied_event_seq: status.applied_event_seq,
            items,
            next,
        })
    }

    pub fn review_file_policy(
        &self,
        file_ref_id: &str,
        now_utc_ms: u64,
    ) -> Result<Option<FilePolicyReview>> {
        let connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        let marker = load_projection_marker(&connection, self.path())?;
        let topology = load_domain_topology(&connection, self.path())?;
        let mut statement = connection
            .prepare(
                "SELECT p.policy_id, c.collection_id, c.display_name, c.home_site_id,
                        f.file_ref_id, f.object_id, f.identity_state,
                        f.logical_path_display, COALESCE(o.size_bytes, f.observed_size_bytes),
                        cc.copy_claim_id, cc.state, cc.object_id,
                        cc.last_seen_time_utc_ms, cc.last_verified_time_utc_ms,
                        cc.last_verification_result,
                        l.location_id, l.display_name, l.kind, l.status,
                        l.archive_root_id, ar.status, l.device_id, d.display_name,
                        d.status, d.identity_state, d.expected_availability,
                        d.last_checkin_time_utc_ms, d.last_fingerprint_match_time_utc_ms,
                        d.last_fingerprint_status,
                        COALESCE(l.site_id, d.current_site_id), s.display_name, s.status,
                        l.encryption_state, l.trust_level, l.expected_availability,
                        o.canonical_hash_algo, ar.device_id,
                        p.policy_version, p.requirements_json
                 FROM file_refs f
                 JOIN collections c ON c.collection_id = f.collection_id AND c.status = 'active'
                 JOIN policies p ON p.policy_id = c.policy_id
                   AND p.status = 'active' AND p.enabled = 1
                 JOIN sites home ON home.site_id = c.home_site_id AND home.status = 'active'
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 LEFT JOIN copy_claims cc
                   ON ((f.object_id IS NOT NULL AND cc.object_id = f.object_id)
                       OR (f.object_id IS NULL AND f.external_identity_id IS NOT NULL
                           AND cc.external_identity_id = f.external_identity_id))
                  AND cc.state != 'superseded'
                 LEFT JOIN locations l ON l.location_id = cc.location_id
                 LEFT JOIN archive_roots ar ON ar.archive_root_id = l.archive_root_id
                 LEFT JOIN devices d ON d.device_id = l.device_id
                 LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
                 WHERE f.file_ref_id = ?1 AND f.path_state = 'active'
                 ORDER BY cc.copy_claim_id",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut rows = statement
            .query([file_ref_id])
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut file = None;
        let mut policy_version = 0;
        let mut requirements = None;
        while let Some(row) = rows
            .next()
            .map_err(|source| sqlite_error(self.path(), source))?
        {
            if file.is_none() {
                let policy_id: String = row
                    .get(0)
                    .map_err(|source| sqlite_error(self.path(), source))?;
                policy_version = sql_u64(
                    row.get(37)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    "policy_version",
                )?;
                requirements = Some(PolicyRequirements::from_json(
                    &policy_id,
                    &row.get::<_, String>(38)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                )?);
                file = Some(FileFact {
                    policy_id,
                    collection_id: row
                        .get(1)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    collection_name: row
                        .get(2)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    home_site_id: row
                        .get(3)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    file_ref_id: row
                        .get(4)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    object_id: row
                        .get(5)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    identity_state: row
                        .get(6)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    logical_path_display: row
                        .get(7)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    size_bytes: optional_u64(
                        row.get(8)
                            .map_err(|source| sqlite_error(self.path(), source))?,
                        "file size",
                    )?,
                    hash_algo: row
                        .get(35)
                        .map_err(|source| sqlite_error(self.path(), source))?,
                    copies: Vec::new(),
                });
            }
            if row
                .get::<_, Option<String>>(9)
                .map_err(|source| sqlite_error(self.path(), source))?
                .is_some()
            {
                file.as_mut()
                    .expect("file was initialized from this row")
                    .copies
                    .push(copy_from_row(row, self.path())?);
            }
        }
        let Some(file) = file else {
            return Ok(None);
        };
        let evaluation = evaluate_file(
            &file,
            &requirements.expect("configured file has requirements"),
            &topology,
            now_utc_ms,
        )?;
        Ok(Some(FilePolicyReview {
            version: RULES_VERSION as u32,
            applied_event_seq: marker.applied_seq,
            file_ref_id: file.file_ref_id,
            logical_path_display: file.logical_path_display,
            policy_id: file.policy_id,
            policy_version,
            status: evaluation.status.unwrap_or_else(|| "satisfied".to_owned()),
            qualifying_copies: evaluation.qualifying_copies,
            reasons: evaluation.reasons,
            recommended_actions: evaluation.actions,
            valid_until_utc_ms: evaluation.valid_until_utc_ms,
        }))
    }

    pub fn policy_findings_after(
        &self,
        evaluation_id: &str,
        after_file_ref_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PolicyFinding>> {
        self.policy_findings_filtered_after(evaluation_id, None, None, after_file_ref_id, limit)
    }

    pub fn policy_findings_filtered_after(
        &self,
        evaluation_id: &str,
        collection_id: Option<&str>,
        status: Option<&str>,
        after_file_ref_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<PolicyFinding>> {
        if limit == 0 {
            return Err(PolicyError::InvalidState(
                "finding page limit must be greater than zero".to_owned(),
            ));
        }
        let connection =
            Connection::open(self.path()).map_err(|source| sqlite_error(self.path(), source))?;
        let mut statement = connection
            .prepare(
                "SELECT s.evaluation_id, s.file_ref_id, s.object_id, s.policy_id,
                        s.policy_version, s.status, f.logical_path_display,
                        c.collection_id, c.display_name,
                        COALESCE(o.size_bytes, x.expected_size_bytes, f.observed_size_bytes),
                        s.reasons_json, s.recommended_actions_json
                 FROM policy_status s
                 JOIN file_refs f ON f.file_ref_id = s.file_ref_id
                 JOIN collections c ON c.collection_id = f.collection_id
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 LEFT JOIN external_identities x
                   ON x.external_identity_id = f.external_identity_id
                 WHERE s.evaluation_id = ?1
                   AND (?2 IS NULL OR f.collection_id = ?2)
                   AND (?3 IS NULL OR s.status = ?3)
                   AND (?4 IS NULL OR s.file_ref_id > ?4)
                 ORDER BY s.file_ref_id LIMIT ?5",
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let rows = statement
            .query_map(
                params![
                    evaluation_id,
                    collection_id,
                    status,
                    after_file_ref_id,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .map_err(|source| sqlite_error(self.path(), source))?;
        let mut findings = Vec::new();
        for row in rows {
            let (
                evaluation_id,
                file_ref_id,
                object_id,
                policy_id,
                policy_version,
                status,
                logical_path_display,
                collection_id,
                collection_name,
                size_bytes,
                reasons_json,
                actions_json,
            ) = row.map_err(|source| sqlite_error(self.path(), source))?;
            findings.push(PolicyFinding {
                evaluation_id,
                file_ref_id,
                object_id,
                policy_id,
                policy_version: sql_u64(policy_version, "policy_version")?,
                status,
                collection_id,
                collection_name,
                logical_path_display,
                size_bytes: optional_u64(size_bytes, "finding size")?,
                reasons: parse_cached_json(&reasons_json, "reasons")?,
                recommended_actions: parse_cached_json(&actions_json, "actions")?,
            });
        }
        Ok(findings)
    }
}

fn sqlite_error(path: &Path, source: rusqlite::Error) -> PolicyError {
    PolicyError::Sqlite {
        path: path.to_path_buf(),
        source,
    }
}

fn parse_cached_json(value: &str, field: &str) -> Result<Value> {
    serde_json::from_str(value).map_err(|error| {
        PolicyError::InvalidState(format!("cached {field} JSON is invalid: {error}"))
    })
}

fn policy_finding_query_hash(filter: &PolicyFindingFilter) -> String {
    blake3::hash(
        serde_json::to_string(filter)
            .expect("policy finding filters are serializable")
            .as_bytes(),
    )
    .to_hex()
    .to_string()
}

fn encode_policy_finding_token(
    finding: &PolicyFinding,
    applied_event_seq: u64,
    evaluation_hash: &str,
    query_hash: &str,
) -> Result<String> {
    let token = PolicyFindingToken {
        version: FINDING_PAGE_VERSION,
        applied_event_seq,
        evaluation_hash: evaluation_hash.to_owned(),
        query_hash: query_hash.to_owned(),
        policy_id: finding.policy_id.clone(),
        file_ref_id: finding.file_ref_id.clone(),
    };
    serde_json::to_vec(&token)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| PolicyError::InvalidContinuation)
}

fn decode_policy_finding_token(value: &str) -> Result<PolicyFindingToken> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PolicyError::InvalidContinuation)?;
    let token: PolicyFindingToken =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::InvalidContinuation)?;
    if token.version != FINDING_PAGE_VERSION {
        return Err(PolicyError::InvalidContinuation);
    }
    Ok(token)
}

fn sql_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| PolicyError::InvalidState(format!("{field} is outside the u64 range")))
}

fn optional_u64(value: Option<i64>, field: &str) -> Result<Option<u64>> {
    value.map(|value| sql_u64(value, field)).transpose()
}

fn sql_i64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| PolicyError::InvalidState(format!("{field} is outside the SQLite range")))
}

fn load_projection_marker(connection: &Connection, path: &Path) -> Result<ProjectionMarker> {
    let meta = |key: &str| {
        connection
            .query_row(
                "SELECT value FROM archive_meta WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .map_err(|source| sqlite_error(path, source))
    };
    let parse = |key: &str| -> Result<u64> {
        meta(key)?.parse::<u64>().map_err(|error| {
            PolicyError::InvalidState(format!("projection marker {key} is invalid: {error}"))
        })
    };
    let applied_seq = parse("applied_event_seq")?;
    let policy_input_event_seq = parse("policy_input_event_seq")?;
    if policy_input_event_seq > applied_seq {
        return Err(PolicyError::InvalidState(
            "policy input sequence exceeds the applied event sequence".to_owned(),
        ));
    }
    if applied_seq == 0 {
        return Err(PolicyError::InvalidState(
            "the projection has no applied event".to_owned(),
        ));
    }
    let applied_event_hash = meta("applied_event_hash")?;
    if applied_event_hash.is_empty() {
        return Err(PolicyError::InvalidState(
            "the applied event hash is empty".to_owned(),
        ));
    }
    let stream_id = meta("stream_id")?;
    let mirrored_hash = connection
        .query_row(
            "SELECT event_hash FROM events WHERE stream_id = ?1 AND seq = ?2",
            params![stream_id, sql_i64(applied_seq, "applied_event_seq")?],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| sqlite_error(path, source))?;
    if mirrored_hash.as_deref() != Some(applied_event_hash.as_str()) {
        return Err(PolicyError::InvalidState(
            "the applied event hash does not match the mirrored tail event".to_owned(),
        ));
    }
    Ok(ProjectionMarker {
        applied_seq,
        applied_event_hash,
        policy_input_event_seq,
    })
}

fn invalid_evaluation_reason(
    row: &ValidityRow,
    marker: &ProjectionMarker,
    now_utc_ms: u64,
) -> Option<&'static str> {
    if row.status != "complete" {
        return Some("evaluation_incomplete");
    }
    let (Ok(expected), Ok(evaluated)) = (
        u64::try_from(row.files_expected),
        u64::try_from(row.files_evaluated),
    ) else {
        return Some("invalid_file_count");
    };
    if expected != evaluated {
        return Some("file_count_mismatch");
    }
    if u64::try_from(row.evaluated_policy_input_seq).ok() != Some(marker.policy_input_event_seq) {
        return Some("policy_input_advanced");
    }
    let (Ok(evaluation_version), Ok(current_version)) = (
        u64::try_from(row.evaluation_policy_version),
        u64::try_from(row.current_policy_version),
    ) else {
        return Some("invalid_policy_version");
    };
    if evaluation_version != current_version {
        return Some("policy_version_changed");
    }
    if row.policy_status != "active" || row.policy_enabled != 1 {
        return Some("policy_inactive");
    }
    if let Some(valid_until) = row.valid_until_utc_ms {
        let Ok(valid_until) = u64::try_from(valid_until) else {
            return Some("invalid_valid_until");
        };
        if valid_until <= now_utc_ms {
            return Some("freshness_expired");
        }
    }
    if u64::try_from(row.rules_version).ok() != Some(RULES_VERSION) {
        return Some("rules_version_changed");
    }
    let (Some(total), Some(satisfied), Some(violated), Some(uncertain)) = (
        row.rollup_total.and_then(|value| u64::try_from(value).ok()),
        row.rollup_satisfied
            .and_then(|value| u64::try_from(value).ok()),
        row.rollup_violated
            .and_then(|value| u64::try_from(value).ok()),
        row.rollup_uncertain
            .and_then(|value| u64::try_from(value).ok()),
    ) else {
        return Some("rollup_missing_or_invalid");
    };
    let Some(classified) = satisfied
        .checked_add(violated)
        .and_then(|value| value.checked_add(uncertain))
    else {
        return Some("rollup_count_mismatch");
    };
    if total != expected || classified != total {
        return Some("rollup_count_mismatch");
    }
    if u64::try_from(row.finding_count).ok() != violated.checked_add(uncertain) {
        return Some("finding_count_mismatch");
    }
    None
}

fn load_unconfigured_collections(
    transaction: &Connection,
    path: &Path,
) -> Result<Vec<UnconfiguredCollection>> {
    let mut statement = transaction
        .prepare(
            "SELECT c.collection_id, c.display_name,
                    CASE
                      WHEN c.home_site_id IS NULL THEN 'home_site_missing'
                      WHEN c.policy_id IS NULL THEN 'policy_missing'
                      WHEN p.policy_id IS NULL THEN 'policy_unknown'
                      WHEN p.status != 'active' OR p.enabled != 1 THEN 'policy_inactive'
                      WHEN s.status != 'active' THEN 'home_site_inactive'
                      ELSE NULL
                    END
             FROM collections c
             LEFT JOIN policies p ON p.policy_id = c.policy_id
             LEFT JOIN sites s ON s.site_id = c.home_site_id
             WHERE c.status = 'active'
               AND (c.home_site_id IS NULL OR c.policy_id IS NULL OR p.policy_id IS NULL
                    OR p.status != 'active' OR p.enabled != 1 OR s.status != 'active')
             ORDER BY c.collection_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let rows = statement
        .query_map([], |row| {
            let reason: String = row.get(2)?;
            Ok(UnconfiguredCollection {
                collection_id: row.get(0)?,
                display_name: row.get(1)?,
                recommended_action: match reason.as_str() {
                    "home_site_missing" | "home_site_inactive" => {
                        "assign an active home site".to_owned()
                    }
                    _ => "assign an active policy".to_owned(),
                },
                reason,
            })
        })
        .map_err(|source| sqlite_error(path, source))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| sqlite_error(path, source))
}

#[allow(clippy::too_many_arguments)]
fn load_policy_contexts(
    transaction: &Transaction<'_>,
    path: &Path,
    evaluated_event_seq: u64,
    evaluated_event_hash: &str,
    evaluated_policy_input_seq: u64,
    now_utc_ms: u64,
) -> Result<BTreeMap<String, PolicyContext>> {
    let mut statement = transaction
        .prepare(
            "SELECT p.policy_id, p.policy_version, p.requirements_json,
                    COUNT(f.file_ref_id)
             FROM policies p
             JOIN collections c ON c.policy_id = p.policy_id
             JOIN sites home ON home.site_id = c.home_site_id AND home.status = 'active'
             LEFT JOIN file_refs f
               ON f.collection_id = c.collection_id AND f.path_state = 'active'
             WHERE p.status = 'active' AND p.enabled = 1 AND c.status = 'active'
             GROUP BY p.policy_id, p.policy_version, p.requirements_json
             ORDER BY p.policy_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|source| sqlite_error(path, source))?;
    let mut contexts = BTreeMap::new();
    for row in rows {
        let (policy_id, policy_version, requirements_json, files_expected) =
            row.map_err(|source| sqlite_error(path, source))?;
        let requirements = PolicyRequirements::from_json(&policy_id, &requirements_json)?;
        let evaluation_id = format!(
            "evaluation_{}",
            Ulid::new().to_string().to_ascii_lowercase()
        );
        let event_seq = sql_i64(evaluated_event_seq, "evaluated_event_seq")?;
        let input_seq = sql_i64(evaluated_policy_input_seq, "evaluated_policy_input_seq")?;
        let rules_version = sql_i64(RULES_VERSION, "rules_version")?;
        let started_time = sql_i64(now_utc_ms, "started_time_utc_ms")?;
        transaction
            .execute(
                "INSERT INTO policy_evaluations(
                    evaluation_id, policy_id, policy_version, evaluated_event_seq,
                    evaluated_event_hash, evaluated_policy_input_seq, rules_version,
                    started_time_utc_ms, status, files_expected, files_evaluated
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'running', ?9, 0)",
                params![
                    evaluation_id,
                    policy_id,
                    policy_version,
                    event_seq,
                    evaluated_event_hash,
                    input_seq,
                    rules_version,
                    started_time,
                    files_expected,
                ],
            )
            .map_err(|source| sqlite_error(path, source))?;
        contexts.insert(
            policy_id.clone(),
            PolicyContext {
                evaluation_id,
                policy_id,
                policy_version: sql_u64(policy_version, "policy_version")?,
                requirements,
                files_expected: sql_u64(files_expected, "files_expected")?,
                files_evaluated: 0,
                files_satisfied: 0,
                files_violated: 0,
                files_uncertain: 0,
                files_size_unknown: 0,
                bytes_known_total: 0,
                bytes_known_at_risk: 0,
                valid_until_utc_ms: None,
            },
        );
    }
    Ok(contexts)
}

fn load_domain_topology(transaction: &Connection, path: &Path) -> Result<DomainTopology> {
    let mut topology = DomainTopology::default();
    let mut domains = transaction
        .prepare(
            "SELECT risk_domain_id, display_name FROM risk_domains
             WHERE status = 'active' ORDER BY risk_domain_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let rows = domains
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| sqlite_error(path, source))?;
    for row in rows {
        let (id, name) = row.map_err(|source| sqlite_error(path, source))?;
        topology.names.insert(id, name);
    }
    drop(domains);

    let mut assignments = transaction
        .prepare(
            "SELECT a.entity_type, a.entity_id, a.risk_domain_id,
                    CASE a.entity_type
                      WHEN 'location' THEN EXISTS(SELECT 1 FROM locations x WHERE x.location_id = a.entity_id)
                      WHEN 'archive_root' THEN EXISTS(SELECT 1 FROM archive_roots x WHERE x.archive_root_id = a.entity_id)
                      WHEN 'device' THEN EXISTS(SELECT 1 FROM devices x WHERE x.device_id = a.entity_id)
                      WHEN 'site' THEN EXISTS(SELECT 1 FROM sites x WHERE x.site_id = a.entity_id)
                      ELSE 0
                    END
             FROM entity_risk_domains a
             JOIN risk_domains d ON d.risk_domain_id = a.risk_domain_id AND d.status = 'active'
             ORDER BY a.entity_type, a.entity_id, a.risk_domain_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let rows = assignments
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })
        .map_err(|source| sqlite_error(path, source))?;
    for row in rows {
        let (entity_type, entity_id, domain_id, exists) =
            row.map_err(|source| sqlite_error(path, source))?;
        if !exists {
            return Err(PolicyError::InvalidState(format!(
                "risk assignment refers to unknown {entity_type} {entity_id}"
            )));
        }
        topology
            .assignments
            .entry((entity_type, entity_id))
            .or_default()
            .insert(domain_id);
    }
    Ok(topology)
}

#[allow(clippy::too_many_arguments)]
fn stream_and_evaluate_files(
    transaction: &Transaction<'_>,
    path: &Path,
    topology: &DomainTopology,
    policies: &mut BTreeMap<String, PolicyContext>,
    evaluated_event_seq: u64,
    evaluated_policy_input_seq: u64,
    now_utc_ms: u64,
) -> Result<()> {
    let mut query = transaction
        .prepare(
            "SELECT p.policy_id, c.collection_id, c.display_name, c.home_site_id,
                    f.file_ref_id, f.object_id, f.identity_state,
                    f.logical_path_display, COALESCE(o.size_bytes, f.observed_size_bytes),
                    cc.copy_claim_id, cc.state, cc.object_id,
                    cc.last_seen_time_utc_ms, cc.last_verified_time_utc_ms,
                    cc.last_verification_result,
                    l.location_id, l.display_name, l.kind, l.status,
                    l.archive_root_id, ar.status, l.device_id, d.display_name,
                    d.status, d.identity_state, d.expected_availability,
                    d.last_checkin_time_utc_ms, d.last_fingerprint_match_time_utc_ms,
                    d.last_fingerprint_status,
                    COALESCE(l.site_id, d.current_site_id), s.display_name, s.status,
                    l.encryption_state, l.trust_level, l.expected_availability,
                    o.canonical_hash_algo, ar.device_id
             FROM collections c
             JOIN policies p ON p.policy_id = c.policy_id
               AND p.status = 'active' AND p.enabled = 1
             JOIN sites home ON home.site_id = c.home_site_id AND home.status = 'active'
             JOIN file_refs f ON f.collection_id = c.collection_id AND f.path_state = 'active'
             LEFT JOIN objects o ON o.object_id = f.object_id
             LEFT JOIN copy_claims cc
               ON ((f.object_id IS NOT NULL AND cc.object_id = f.object_id)
                   OR (f.object_id IS NULL AND f.external_identity_id IS NOT NULL
                       AND cc.external_identity_id = f.external_identity_id))
              AND cc.state != 'superseded'
             LEFT JOIN locations l ON l.location_id = cc.location_id
             LEFT JOIN archive_roots ar ON ar.archive_root_id = l.archive_root_id
             LEFT JOIN devices d ON d.device_id = l.device_id
             LEFT JOIN sites s ON s.site_id = COALESCE(l.site_id, d.current_site_id)
             WHERE c.status = 'active'
             ORDER BY f.file_ref_id",
        )
        .map_err(|source| sqlite_error(path, source))?;
    let mut rows = query
        .query([])
        .map_err(|source| sqlite_error(path, source))?;
    let mut current: Option<FileFact> = None;
    while let Some(row) = rows.next().map_err(|source| sqlite_error(path, source))? {
        let file_ref_id: String = row.get(4).map_err(|source| sqlite_error(path, source))?;
        if current
            .as_ref()
            .is_some_and(|file| file.file_ref_id != file_ref_id)
        {
            evaluate_and_store_file(
                transaction,
                path,
                topology,
                policies,
                current.take().expect("current file exists"),
                evaluated_event_seq,
                evaluated_policy_input_seq,
                now_utc_ms,
            )?;
        }
        if current.is_none() {
            current = Some(FileFact {
                policy_id: row.get(0).map_err(|source| sqlite_error(path, source))?,
                collection_id: row.get(1).map_err(|source| sqlite_error(path, source))?,
                collection_name: row.get(2).map_err(|source| sqlite_error(path, source))?,
                home_site_id: row.get(3).map_err(|source| sqlite_error(path, source))?,
                file_ref_id,
                object_id: row.get(5).map_err(|source| sqlite_error(path, source))?,
                identity_state: row.get(6).map_err(|source| sqlite_error(path, source))?,
                logical_path_display: row.get(7).map_err(|source| sqlite_error(path, source))?,
                size_bytes: optional_u64(
                    row.get(8).map_err(|source| sqlite_error(path, source))?,
                    "file size",
                )?,
                hash_algo: row.get(35).map_err(|source| sqlite_error(path, source))?,
                copies: Vec::new(),
            });
        }
        if row
            .get::<_, Option<String>>(9)
            .map_err(|source| sqlite_error(path, source))?
            .is_some()
        {
            current
                .as_mut()
                .expect("current file exists")
                .copies
                .push(copy_from_row(row, path)?);
        }
    }
    if let Some(file) = current {
        evaluate_and_store_file(
            transaction,
            path,
            topology,
            policies,
            file,
            evaluated_event_seq,
            evaluated_policy_input_seq,
            now_utc_ms,
        )?;
    }
    Ok(())
}

fn copy_from_row(row: &rusqlite::Row<'_>, path: &Path) -> Result<CopyFact> {
    Ok(CopyFact {
        copy_claim_id: row.get(9).map_err(|source| sqlite_error(path, source))?,
        state: row.get(10).map_err(|source| sqlite_error(path, source))?,
        object_id: row.get(11).map_err(|source| sqlite_error(path, source))?,
        last_seen_time_utc_ms: optional_u64(
            row.get(12).map_err(|source| sqlite_error(path, source))?,
            "last_seen_time_utc_ms",
        )?,
        last_verified_time_utc_ms: optional_u64(
            row.get(13).map_err(|source| sqlite_error(path, source))?,
            "last_verified_time_utc_ms",
        )?,
        last_verification_result: row.get(14).map_err(|source| sqlite_error(path, source))?,
        location_id: row.get(15).map_err(|source| sqlite_error(path, source))?,
        location_name: row.get(16).map_err(|source| sqlite_error(path, source))?,
        location_kind: row.get(17).map_err(|source| sqlite_error(path, source))?,
        location_status: row.get(18).map_err(|source| sqlite_error(path, source))?,
        archive_root_id: row.get(19).map_err(|source| sqlite_error(path, source))?,
        archive_root_status: row.get(20).map_err(|source| sqlite_error(path, source))?,
        device_id: row.get(21).map_err(|source| sqlite_error(path, source))?,
        device_name: row.get(22).map_err(|source| sqlite_error(path, source))?,
        device_status: row.get(23).map_err(|source| sqlite_error(path, source))?,
        device_identity_state: row.get(24).map_err(|source| sqlite_error(path, source))?,
        device_expected_availability: row.get(25).map_err(|source| sqlite_error(path, source))?,
        last_checkin_time_utc_ms: optional_u64(
            row.get(26).map_err(|source| sqlite_error(path, source))?,
            "last_checkin_time_utc_ms",
        )?,
        last_fingerprint_match_time_utc_ms: optional_u64(
            row.get(27).map_err(|source| sqlite_error(path, source))?,
            "last_fingerprint_match_time_utc_ms",
        )?,
        last_fingerprint_status: row.get(28).map_err(|source| sqlite_error(path, source))?,
        site_id: row.get(29).map_err(|source| sqlite_error(path, source))?,
        site_name: row.get(30).map_err(|source| sqlite_error(path, source))?,
        site_status: row.get(31).map_err(|source| sqlite_error(path, source))?,
        encryption_state: row.get(32).map_err(|source| sqlite_error(path, source))?,
        trust_level: row.get(33).map_err(|source| sqlite_error(path, source))?,
        location_expected_availability: row.get(34).map_err(|source| sqlite_error(path, source))?,
        archive_root_device_id: row.get(36).map_err(|source| sqlite_error(path, source))?,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_and_store_file(
    transaction: &Transaction<'_>,
    path: &Path,
    topology: &DomainTopology,
    policies: &mut BTreeMap<String, PolicyContext>,
    file: FileFact,
    evaluated_event_seq: u64,
    evaluated_policy_input_seq: u64,
    now_utc_ms: u64,
) -> Result<()> {
    let policy_id = file.policy_id.as_str();
    let requirements = policies
        .get(policy_id)
        .ok_or_else(|| PolicyError::InvalidState(format!("unknown policy context {policy_id}")))?
        .requirements
        .clone();
    let evaluation = evaluate_file(&file, &requirements, topology, now_utc_ms)?;
    let policy = policies
        .get_mut(policy_id)
        .expect("policy context was checked above");
    policy.files_evaluated += 1;
    if let Some(size) = file.size_bytes {
        policy.bytes_known_total = policy.bytes_known_total.saturating_add(size);
    } else {
        policy.files_size_unknown += 1;
    }
    policy.valid_until_utc_ms =
        minimum_time(policy.valid_until_utc_ms, evaluation.valid_until_utc_ms);

    match evaluation.status.as_deref() {
        None => policy.files_satisfied += 1,
        Some("violated") => policy.files_violated += 1,
        Some("uncertain") => policy.files_uncertain += 1,
        Some(status) => {
            return Err(PolicyError::InvalidState(format!(
                "unsupported policy result {status}"
            )))
        }
    }
    if let Some(status) = evaluation.status {
        if let Some(size) = file.size_bytes {
            policy.bytes_known_at_risk = policy.bytes_known_at_risk.saturating_add(size);
        }
        let reasons_json = serde_json::to_string(&evaluation.reasons).map_err(|error| {
            PolicyError::InvalidState(format!("could not serialize policy reasons: {error}"))
        })?;
        let actions_json = serde_json::to_string(&evaluation.actions).map_err(|error| {
            PolicyError::InvalidState(format!("could not serialize policy actions: {error}"))
        })?;
        let policy_version = sql_i64(policy.policy_version, "policy_version")?;
        let event_seq = sql_i64(evaluated_event_seq, "evaluated_event_seq")?;
        let input_seq = sql_i64(evaluated_policy_input_seq, "evaluated_policy_input_seq")?;
        let evaluated_time = sql_i64(now_utc_ms, "evaluated_time_utc_ms")?;
        transaction
            .execute(
                "INSERT INTO policy_status(
                    evaluation_id, file_ref_id, object_id, policy_id, policy_version,
                    evaluated_event_seq, evaluated_policy_input_seq, status,
                    evaluated_time_utc_ms, reasons_json, recommended_actions_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    policy.evaluation_id,
                    file.file_ref_id,
                    file.object_id,
                    policy.policy_id,
                    policy_version,
                    event_seq,
                    input_seq,
                    status,
                    evaluated_time,
                    reasons_json,
                    actions_json,
                ],
            )
            .map_err(|source| sqlite_error(path, source))?;
    }
    Ok(())
}

fn evaluate_file(
    file: &FileFact,
    requirements: &PolicyRequirements,
    topology: &DomainTopology,
    now_utc_ms: u64,
) -> Result<FileEvaluation> {
    let mut qualified = Vec::new();
    let mut nonqualifying = Vec::new();
    let mut has_uncertain_material = false;
    let mut valid_until = None;

    let identity_usable = file.identity_state == "resolved"
        && file.object_id.is_some()
        && file.hash_algo.as_deref() == Some("blake3");
    if identity_usable {
        for copy in &file.copies {
            let assessment = assess_copy(
                copy,
                file,
                requirements,
                topology,
                now_utc_ms,
                &mut valid_until,
            )?;
            if let Some(copy) = assessment.qualified {
                qualified.push(copy);
            } else {
                has_uncertain_material |= assessment.uncertain;
                nonqualifying.push(json!({
                    "copy_claim_id": copy.copy_claim_id,
                    "location_id": copy.location_id,
                    "location_name": copy.location_name,
                    "reasons": assessment.reasons,
                    "uncertain": assessment.uncertain,
                }));
            }
        }
    } else {
        has_uncertain_material = true;
        for copy in &file.copies {
            nonqualifying.push(json!({
                "copy_claim_id": copy.copy_claim_id,
                "location_id": copy.location_id,
                "location_name": copy.location_name,
                "reasons": ["file_identity_not_resolved_to_blake3"],
                "uncertain": true,
            }));
        }
    }

    let device_ids: BTreeSet<_> = qualified
        .iter()
        .filter_map(|copy| copy.device_id.clone())
        .collect();
    let site_ids: BTreeSet<_> = qualified.iter().map(|copy| copy.site_id.clone()).collect();
    let mut failed_requirements = Vec::new();
    if qualified.len() < usize_from_u64(requirements.min_qualifying_copies) {
        failed_requirements.push(json!({
            "requirement": "min_qualifying_copies",
            "required": requirements.min_qualifying_copies,
            "actual": qualified.len(),
        }));
    }
    if device_ids.len() < usize_from_u64(requirements.min_devices) {
        failed_requirements.push(json!({
            "requirement": "min_devices",
            "required": requirements.min_devices,
            "actual": device_ids.len(),
        }));
    }
    if site_ids.len() < usize_from_u64(requirements.min_sites) {
        failed_requirements.push(json!({
            "requirement": "min_sites",
            "required": requirements.min_sites,
            "actual": site_ids.len(),
        }));
    }
    if requirements.require_offsite_copy && !qualified.iter().any(|copy| copy.offsite) {
        failed_requirements.push(json!({"requirement": "require_offsite_copy"}));
    }
    if requirements.require_offline_copy && !qualified.iter().any(|copy| copy.offline) {
        failed_requirements.push(json!({"requirement": "require_offline_copy"}));
    }
    if requirements.require_encrypted_offsite
        && !qualified.iter().any(|copy| copy.offsite && copy.encrypted)
    {
        failed_requirements.push(json!({"requirement": "require_encrypted_offsite"}));
    }

    let loss_scenarios = loss_scenarios(&qualified, topology);
    let permanent_loss = loss_scenarios
        .iter()
        .any(|scenario| scenario["permanent_loss"] == Value::Bool(true));
    let has_failure = !failed_requirements.is_empty() || permanent_loss || !identity_usable;
    let status = if has_failure {
        Some(if has_uncertain_material || !identity_usable {
            "uncertain".to_owned()
        } else {
            "violated".to_owned()
        })
    } else {
        None
    };

    let actions = recommended_actions(
        identity_usable,
        &failed_requirements,
        &nonqualifying,
        permanent_loss,
    );
    Ok(FileEvaluation {
        status,
        reasons: json!({
            "logical_path": file.logical_path_display,
            "collection_id": file.collection_id,
            "collection_name": file.collection_name,
            "identity_state": file.identity_state,
            "hash_algo": file.hash_algo,
            "qualifying_copy_count": qualified.len(),
            "qualifying_device_ids": device_ids,
            "qualifying_site_ids": site_ids,
            "failed_requirements": failed_requirements,
            "loss_scenarios": loss_scenarios,
            "nonqualifying_copies": nonqualifying,
        }),
        actions: json!(actions),
        valid_until_utc_ms: valid_until,
        qualifying_copies: qualified
            .iter()
            .map(|copy| QualifyingCopyReview {
                copy_claim_id: copy.copy_claim_id.clone(),
                location_id: copy.location_id.clone(),
                location_name: copy.location_name.clone(),
                device_id: copy.device_id.clone(),
                site_id: copy.site_id.clone(),
                offsite: copy.offsite,
                offline: copy.offline,
                encrypted: copy.encrypted,
            })
            .collect(),
    })
}

fn assess_copy(
    copy: &CopyFact,
    file: &FileFact,
    requirements: &PolicyRequirements,
    topology: &DomainTopology,
    now_utc_ms: u64,
    valid_until: &mut Option<u64>,
) -> Result<CopyAssessment> {
    let mut reasons = Vec::new();
    let mut uncertain = false;
    if copy.object_id.as_ref() != file.object_id.as_ref() {
        reasons.push("object_identity_mismatch".to_owned());
    }
    if copy.state != "present" {
        reasons.push(format!("copy_state_{}", copy.state));
    }
    match copy.last_verification_result.as_deref() {
        Some("ok") => {}
        Some(result) => reasons.push(format!("verification_{result}")),
        None => mark_uncertain(&mut reasons, &mut uncertain, "verification_missing"),
    }
    check_freshness(
        copy.last_verified_time_utc_ms,
        requirements.max_verification_age_days,
        now_utc_ms,
        "verification",
        &mut reasons,
        &mut uncertain,
        valid_until,
    )?;
    check_freshness(
        copy.last_seen_time_utc_ms,
        requirements.max_observation_age_days,
        now_utc_ms,
        "observation",
        &mut reasons,
        &mut uncertain,
        valid_until,
    )?;
    if copy.location_status != "active" {
        reasons.push("location_inactive".to_owned());
    }
    match copy.trust_level.as_deref() {
        Some("trusted") => {}
        Some("untrusted") => reasons.push("location_untrusted".to_owned()),
        _ => mark_uncertain(&mut reasons, &mut uncertain, "location_trust_unknown"),
    }

    let site_id = match copy.site_id.as_deref() {
        Some(site_id) if copy.site_status.as_deref() == Some("active") => site_id,
        Some(_) => {
            reasons.push("site_inactive".to_owned());
            ""
        }
        None => {
            mark_uncertain(&mut reasons, &mut uncertain, "site_unknown");
            ""
        }
    };

    if copy.location_kind == "filesystem" {
        if copy.archive_root_status.as_deref() != Some("active") {
            reasons.push("archive_root_inactive".to_owned());
        }
        if copy.archive_root_device_id != copy.device_id {
            mark_uncertain(&mut reasons, &mut uncertain, "archive_root_device_mismatch");
        }
        if copy.device_status.as_deref() != Some("active") {
            reasons.push("device_inactive".to_owned());
        }
        if copy.device_identity_state.as_deref() != Some("confirmed") {
            mark_uncertain(&mut reasons, &mut uncertain, "device_identity_unconfirmed");
        }
        if copy.last_fingerprint_status.as_deref() != Some("match") {
            mark_uncertain(
                &mut reasons,
                &mut uncertain,
                "device_fingerprint_not_matched",
            );
        }
        check_freshness(
            copy.last_checkin_time_utc_ms,
            requirements.max_device_checkin_age_days,
            now_utc_ms,
            "device_checkin",
            &mut reasons,
            &mut uncertain,
            valid_until,
        )?;
        check_freshness(
            copy.last_fingerprint_match_time_utc_ms,
            requirements.max_device_checkin_age_days,
            now_utc_ms,
            "device_fingerprint",
            &mut reasons,
            &mut uncertain,
            valid_until,
        )?;
    } else if copy.location_kind != "service" {
        mark_uncertain(&mut reasons, &mut uncertain, "location_kind_unknown");
    }

    if requirements.require_encrypted_offsite
        && site_id != file.home_site_id.as_str()
        && copy.encryption_state.as_deref() != Some("encrypted")
    {
        match copy.encryption_state.as_deref() {
            Some("unencrypted") => reasons.push("offsite_copy_unencrypted".to_owned()),
            _ => mark_uncertain(&mut reasons, &mut uncertain, "offsite_encryption_unknown"),
        }
    }

    if !reasons.is_empty() {
        return Ok(CopyAssessment {
            qualified: None,
            reasons,
            uncertain,
        });
    }

    let mut domains = BTreeSet::new();
    if let Some(device_id) = &copy.device_id {
        domains.insert(format!("device:{device_id}"));
    } else {
        domains.insert(format!("service:{}", copy.location_id));
    }
    domains.insert(format!("site:{site_id}"));
    add_custom_domains(&mut domains, topology, "location", Some(&copy.location_id));
    add_custom_domains(
        &mut domains,
        topology,
        "archive_root",
        copy.archive_root_id.as_deref(),
    );
    add_custom_domains(&mut domains, topology, "device", copy.device_id.as_deref());
    add_custom_domains(&mut domains, topology, "site", Some(site_id));

    Ok(CopyAssessment {
        qualified: Some(QualifiedCopy {
            copy_claim_id: copy.copy_claim_id.clone(),
            location_id: copy.location_id.clone(),
            location_name: copy.location_name.clone(),
            device_id: copy.device_id.clone(),
            device_name: copy.device_name.clone(),
            site_id: site_id.to_owned(),
            site_name: copy.site_name.clone().unwrap_or_else(|| site_id.to_owned()),
            offsite: site_id != file.home_site_id.as_str(),
            offline: copy.location_expected_availability == "offline"
                || copy.device_expected_availability.as_deref() == Some("offline"),
            encrypted: copy.encryption_state.as_deref() == Some("encrypted"),
            domains,
        }),
        reasons,
        uncertain,
    })
}

fn mark_uncertain(reasons: &mut Vec<String>, uncertain: &mut bool, reason: &str) {
    reasons.push(reason.to_owned());
    *uncertain = true;
}

#[allow(clippy::too_many_arguments)]
fn check_freshness(
    timestamp: Option<u64>,
    max_age_days: u64,
    now_utc_ms: u64,
    label: &str,
    reasons: &mut Vec<String>,
    uncertain: &mut bool,
    valid_until: &mut Option<u64>,
) -> Result<()> {
    let Some(timestamp) = timestamp else {
        reasons.push(format!("{label}_time_missing"));
        *uncertain = true;
        return Ok(());
    };
    if timestamp > now_utc_ms {
        reasons.push(format!("{label}_time_in_future"));
        *uncertain = true;
        return Ok(());
    }
    let age_ms = max_age_days
        .checked_mul(DAY_MS)
        .ok_or_else(|| PolicyError::InvalidState(format!("{label} age limit overflows")))?;
    let expiry = timestamp
        .checked_add(age_ms)
        .ok_or_else(|| PolicyError::InvalidState(format!("{label} expiry overflows")))?;
    if expiry <= now_utc_ms {
        reasons.push(format!("{label}_stale"));
        *uncertain = true;
    } else {
        *valid_until = minimum_time(*valid_until, Some(expiry));
    }
    Ok(())
}

fn add_custom_domains(
    domains: &mut BTreeSet<String>,
    topology: &DomainTopology,
    entity_type: &str,
    entity_id: Option<&str>,
) {
    let Some(entity_id) = entity_id else {
        return;
    };
    if let Some(assigned) = topology
        .assignments
        .get(&(entity_type.to_owned(), entity_id.to_owned()))
    {
        domains.extend(assigned.iter().map(|id| format!("risk:{id}")));
    }
}

fn loss_scenarios(copies: &[QualifiedCopy], topology: &DomainTopology) -> Vec<Value> {
    let domains: BTreeSet<_> = copies
        .iter()
        .flat_map(|copy| copy.domains.iter().cloned())
        .collect();
    domains
        .into_iter()
        .map(|domain| {
            let (kind, id) = domain.split_once(':').unwrap_or(("unknown", &domain));
            let affected: Vec<_> = copies
                .iter()
                .filter(|copy| copy.domains.contains(&domain))
                .map(|copy| {
                    json!({
                        "copy_claim_id": copy.copy_claim_id,
                        "location_id": copy.location_id,
                        "location_name": copy.location_name,
                    })
                })
                .collect();
            let remaining = copies.len().saturating_sub(affected.len());
            let name = match kind {
                "risk" => topology.names.get(id).map(String::as_str).unwrap_or(id),
                "device" => copies
                    .iter()
                    .find(|copy| copy.device_id.as_deref() == Some(id))
                    .and_then(|copy| copy.device_name.as_deref())
                    .unwrap_or(id),
                "site" => copies
                    .iter()
                    .find(|copy| copy.site_id == id)
                    .map(|copy| copy.site_name.as_str())
                    .unwrap_or(id),
                "service" => copies
                    .iter()
                    .find(|copy| copy.location_id == id)
                    .map(|copy| copy.location_name.as_str())
                    .unwrap_or(id),
                _ => id,
            };
            json!({
                "domain_kind": kind,
                "domain_id": id,
                "domain_name": name,
                "affected_copies": affected,
                "remaining_qualifying_copies": remaining,
                "permanent_loss": !copies.is_empty() && remaining == 0,
            })
        })
        .collect()
}

fn recommended_actions(
    identity_usable: bool,
    failed_requirements: &[Value],
    nonqualifying: &[Value],
    permanent_loss: bool,
) -> Vec<String> {
    let mut actions = BTreeSet::new();
    if !identity_usable {
        actions.insert("resolve the file identity to BLAKE3".to_owned());
    }
    for copy in nonqualifying {
        let reasons = copy["reasons"].as_array().into_iter().flatten();
        for reason in reasons.filter_map(Value::as_str) {
            if reason.contains("verification") {
                actions.insert("verify the copy again".to_owned());
            }
            if reason.contains("observation") {
                actions.insert("scan the location again".to_owned());
            }
            if reason.contains("device") || reason.contains("fingerprint") {
                actions.insert("connect and check in the expected device".to_owned());
            }
            if reason.contains("unknown") || reason.contains("mismatch") {
                actions.insert("review and classify the location topology".to_owned());
            }
        }
    }
    if !failed_requirements.is_empty() || permanent_loss {
        actions.insert("create and verify an independent copy".to_owned());
    }
    actions.into_iter().collect()
}

fn minimum_time(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[allow(clippy::too_many_arguments)]
fn finish_evaluations(
    transaction: &Transaction<'_>,
    path: &Path,
    policies: &BTreeMap<String, PolicyContext>,
    evaluated_event_seq: u64,
    evaluated_policy_input_seq: u64,
    now_utc_ms: u64,
) -> Result<()> {
    for policy in policies.values() {
        if policy.files_evaluated != policy.files_expected {
            return Err(PolicyError::InvalidState(format!(
                "policy {} expected {} files but evaluated {}",
                policy.policy_id, policy.files_expected, policy.files_evaluated
            )));
        }
        let policy_version = sql_i64(policy.policy_version, "policy_version")?;
        let event_seq = sql_i64(evaluated_event_seq, "evaluated_event_seq")?;
        let input_seq = sql_i64(evaluated_policy_input_seq, "evaluated_policy_input_seq")?;
        let evaluated_time = sql_i64(now_utc_ms, "evaluated_time_utc_ms")?;
        let files_total = sql_i64(policy.files_evaluated, "files_total")?;
        let files_satisfied = sql_i64(policy.files_satisfied, "files_satisfied")?;
        let files_violated = sql_i64(policy.files_violated, "files_violated")?;
        let files_uncertain = sql_i64(policy.files_uncertain, "files_uncertain")?;
        let files_size_unknown = sql_i64(policy.files_size_unknown, "files_size_unknown")?;
        let bytes_known_total = sql_i64(policy.bytes_known_total, "bytes_known_total")?;
        let bytes_known_at_risk = sql_i64(policy.bytes_known_at_risk, "bytes_known_at_risk")?;
        transaction
            .execute(
                "INSERT INTO policy_rollup(
                    evaluation_id, policy_id, policy_version, evaluated_event_seq,
                    evaluated_policy_input_seq, evaluated_time_utc_ms, files_total,
                    files_satisfied, files_violated, files_uncertain, files_size_unknown,
                    bytes_known_total, bytes_known_at_risk
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    policy.evaluation_id,
                    policy.policy_id,
                    policy_version,
                    event_seq,
                    input_seq,
                    evaluated_time,
                    files_total,
                    files_satisfied,
                    files_violated,
                    files_uncertain,
                    files_size_unknown,
                    bytes_known_total,
                    bytes_known_at_risk,
                ],
            )
            .map_err(|source| sqlite_error(path, source))?;
        transaction
            .execute(
                "UPDATE policy_evaluations
                 SET completed_time_utc_ms = ?2, valid_until_utc_ms = ?3,
                     status = 'complete', files_evaluated = ?4
                 WHERE evaluation_id = ?1 AND status = 'running'",
                params![
                    policy.evaluation_id,
                    evaluated_time,
                    policy
                        .valid_until_utc_ms
                        .map(|value| sql_i64(value, "valid_until_utc_ms"))
                        .transpose()?,
                    files_total,
                ],
            )
            .map_err(|source| sqlite_error(path, source))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::ProjectionConfig;
    use tempfile::TempDir;

    const NOW: u64 = 1_000_000;

    fn seeded_database(temp: &TempDir) -> ProjectionDb {
        let database = ProjectionDb::open_or_create(
            temp.path().join("archive.db"),
            "arc_test",
            ProjectionConfig::default(),
        )
        .unwrap();
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                r#"
                PRAGMA foreign_keys = ON;
                INSERT INTO events(
                    stream_id, seq, event_id, event_type, event_time_utc_ms,
                    actor_id, host_id, payload_json, event_hash
                ) VALUES ('stream_primary', 1, 'event_1', 'job_started', 1,
                          'test-user', 'test-host', '{}', 'hash_1');
                UPDATE archive_meta SET value = '1' WHERE key = 'applied_event_seq';
                UPDATE archive_meta SET value = 'hash_1' WHERE key = 'applied_event_hash';
                UPDATE archive_meta SET value = '1' WHERE key = 'applied_segment_first_seq';
                UPDATE archive_meta SET value = '1' WHERE key = 'applied_segment_offset';
                UPDATE archive_meta SET value = '1' WHERE key = 'policy_input_event_seq';

                INSERT INTO sites VALUES
                  ('site_home', 'Home', 'home', NULL, 'active', 'event_1'),
                  ('site_remote', 'Remote office', 'office', NULL, 'active', 'event_1');
                INSERT INTO policies VALUES (
                  'policy_main', 'Starter', 1,
                  '{"min_qualifying_copies":2,"min_devices":2,"min_sites":2,"require_offsite_copy":true,"require_offline_copy":false,"require_encrypted_offsite":false,"max_verification_age_days":1,"max_observation_age_days":1,"max_device_checkin_age_days":1}',
                  1, 'active', 'event_1'
                );
                INSERT INTO collections VALUES
                  ('collection_main', 'Family archive', NULL, 'site_home', 'policy_main', 'active', 'event_1'),
                  ('collection_unconfigured', 'Needs setup', NULL, NULL, NULL, 'active', 'event_1');
                INSERT INTO objects VALUES
                  ('object_1', 'blake3', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                   1234, 'image/jpeg', 'jpg', 'event_1', 1);
                INSERT INTO file_refs VALUES (
                  'file_1', 'collection_main', X'70686f746f2e6a7067', 'utf8', 'photo.jpg',
                  'object_1', NULL, 'resolved', 'active', 1, 1, 1234,
                  'event_1', 'event_1', NULL
                );
                INSERT INTO devices VALUES
                  ('device_1', 'Home disk', 'disk', NULL, 'fp1', 'serial', 'confirmed', NULL,
                   'active', 'site_home', 'online', 'event_1', 900000, 900000, 'match', 'event_1'),
                  ('device_2', 'Remote disk', 'disk', NULL, 'fp2', 'serial', 'confirmed', NULL,
                   'active', 'site_remote', 'offline', 'event_1', 900000, 900000, 'match', 'event_1');
                INSERT INTO archive_roots VALUES
                  ('root_1', 'device_1', 'Home root', X'2f61726368697665', 'utf8', '/archive',
                   'active', 'event_1', 'event_1', 900000),
                  ('root_2', 'device_2', 'Remote root', X'2f6261636b7570', 'utf8', '/backup',
                   'active', 'event_1', 'event_1', 900000);
                INSERT INTO locations VALUES
                  ('location_1', 'Home copy', 'filesystem', 'root_1', X'', 'utf8', '',
                   'device_1', NULL, 'unencrypted', 'trusted', 'online', 0, 'active', 'event_1', 'event_1'),
                  ('location_2', 'Remote copy', 'filesystem', 'root_2', X'', 'utf8', '',
                   'device_2', NULL, 'encrypted', 'trusted', 'offline', 0, 'active', 'event_1', 'event_1');
                INSERT INTO copy_claims(
                  copy_claim_id, location_id, relative_path_bytes, relative_path_encoding,
                  relative_path_display, object_id, claim_basis, state, state_event_seq,
                  first_seen_event_id, last_seen_event_id, last_seen_time_utc_ms,
                  last_verified_event_id, last_verified_time_utc_ms, last_verification_result
                ) VALUES
                  ('copy_1', 'location_1', X'70686f746f2e6a7067', 'utf8', 'photo.jpg', 'object_1',
                   'observed_bytes', 'present', 1, 'event_1', 'event_1', 900000, 'event_1', 900000, 'ok'),
                  ('copy_2', 'location_2', X'70686f746f2e6a7067', 'utf8', 'photo.jpg', 'object_1',
                   'observed_bytes', 'present', 1, 'event_1', 'event_1', 900000, 'event_1', 900000, 'ok');
                INSERT INTO risk_domains VALUES
                  ('risk_power', 'Shared power system', 'infrastructure', NULL, 'active', 'event_1');
                INSERT INTO entity_risk_domains VALUES
                  ('archive_root', 'root_1', 'risk_power', 'event_1'),
                  ('site', 'site_home', 'risk_power', 'event_1'),
                  ('device', 'device_2', 'risk_power', 'event_1');
                "#,
            )
            .unwrap();
        database
    }

    #[test]
    fn evaluates_independence_loss_freshness_and_cache_validity() {
        let temp = TempDir::new().unwrap();
        let database = seeded_database(&temp);

        let result = database.evaluate_policies(NOW).unwrap();
        assert_eq!(result.unconfigured_collections.len(), 1);
        assert_eq!(
            result.unconfigured_collections[0].reason,
            "home_site_missing"
        );
        assert_eq!(result.evaluations.len(), 1);
        let rollup = &result.evaluations[0];
        assert_eq!(rollup.files_total, 1);
        assert_eq!(rollup.files_violated, 1);
        assert_eq!(rollup.files_uncertain, 0);
        assert_eq!(rollup.valid_until_utc_ms, Some(87_300_000));

        let findings = database
            .policy_findings_after(&rollup.evaluation_id, None, 10)
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].logical_path_display, "photo.jpg");
        assert_eq!(findings[0].collection_name, "Family archive");
        assert_eq!(findings[0].size_bytes, Some(1234));
        let file_review = database.review_file_policy("file_1", NOW).unwrap().unwrap();
        assert_eq!(file_review.status, "violated");
        assert_eq!(file_review.qualifying_copies.len(), 2);
        let scenarios = findings[0].reasons["loss_scenarios"].as_array().unwrap();
        assert_eq!(
            scenarios
                .iter()
                .filter(|scenario| scenario["domain_kind"] == "risk")
                .count(),
            1,
            "the root and site assignments on copy 1 must be inherited only once"
        );
        let shared = scenarios
            .iter()
            .find(|scenario| scenario["domain_kind"] == "risk")
            .unwrap();
        assert_eq!(shared["domain_name"], "Shared power system");
        assert_eq!(shared["permanent_loss"], true);
        assert_eq!(shared["affected_copies"].as_array().unwrap().len(), 2);
        assert!(scenarios.iter().any(|scenario| {
            scenario["domain_kind"] == "device" && scenario["domain_name"] == "Home disk"
        }));
        assert!(scenarios.iter().any(|scenario| {
            scenario["domain_kind"] == "site" && scenario["domain_name"] == "Remote office"
        }));
        assert!(
            database
                .policy_evaluation_validity(&rollup.evaluation_id, NOW)
                .unwrap()
                .usable
        );
        assert_eq!(
            database
                .policy_evaluation_validity(&rollup.evaluation_id, 87_300_000)
                .unwrap()
                .reason
                .as_deref(),
            Some("freshness_expired")
        );

        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute(
                "DELETE FROM entity_risk_domains WHERE entity_type = 'device' AND entity_id = 'device_2'",
                [],
            )
            .unwrap();
        let safe = database.evaluate_policies(NOW).unwrap();
        assert_eq!(safe.evaluations[0].files_satisfied, 1);
        assert!(database
            .policy_findings_after(&safe.evaluations[0].evaluation_id, None, 10)
            .unwrap()
            .is_empty());

        connection
            .execute(
                "UPDATE copy_claims SET last_verified_time_utc_ms = NULL,
                 last_verification_result = NULL WHERE copy_claim_id = 'copy_2'",
                [],
            )
            .unwrap();
        let stale = database.evaluate_policies(NOW).unwrap();
        assert_eq!(stale.evaluations[0].files_uncertain, 1);
        let stale_findings = database
            .policy_findings_after(&stale.evaluations[0].evaluation_id, None, 10)
            .unwrap();
        assert!(
            stale_findings[0].reasons["nonqualifying_copies"][0]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == "verification_missing")
        );

        connection
            .execute(
                "UPDATE archive_meta SET value = '0' WHERE key = 'policy_input_event_seq'",
                [],
            )
            .unwrap();
        let validity = database
            .policy_evaluation_validity(&stale.evaluations[0].evaluation_id, NOW)
            .unwrap();
        assert_eq!(validity.reason.as_deref(), Some("policy_input_advanced"));

        connection
            .execute(
                "UPDATE policy_status SET reasons_json = '{' WHERE evaluation_id = ?1",
                [&stale.evaluations[0].evaluation_id],
            )
            .unwrap();
        let error = database
            .policy_findings_after(&stale.evaluations[0].evaluation_id, None, 10)
            .unwrap_err();
        assert_eq!(error.code(), "policy_invalid_state");
    }

    #[test]
    fn cached_finding_pages_are_bounded_filtered_and_stale_safe() {
        let temp = TempDir::new().unwrap();
        let database = seeded_database(&temp);
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute(
                "INSERT INTO file_refs VALUES (
                   'file_2', 'collection_main', X'70686f746f322e6a7067', 'utf8', 'photo2.jpg',
                   'object_1', NULL, 'resolved', 'active', 1, 1, 1234,
                   'event_1', 'event_1', NULL
                 )",
                [],
            )
            .unwrap();

        database.evaluate_policies(NOW).unwrap();
        let status = database.cached_policy_status(NOW).unwrap();
        let filter = PolicyFindingFilter {
            policy_id: Some("policy_main".to_owned()),
            collection_id: Some("collection_main".to_owned()),
            status: Some("violated".to_owned()),
        };
        let first = database
            .cached_policy_findings(&status, &filter, 1, None)
            .unwrap();
        assert_eq!(first.items.len(), 1);
        assert!(first.next.is_some());
        let second = database
            .cached_policy_findings(&status, &filter, 1, first.next.as_deref())
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0].file_ref_id, second.items[0].file_ref_id);
        assert!(second.next.is_none());

        let empty = database
            .cached_policy_findings(
                &status,
                &PolicyFindingFilter {
                    collection_id: Some("other_collection".to_owned()),
                    ..filter.clone()
                },
                10,
                None,
            )
            .unwrap();
        assert!(empty.items.is_empty());

        connection
            .execute_batch(
                "INSERT INTO events(
                    stream_id, seq, event_id, event_type, event_time_utc_ms,
                    actor_id, host_id, payload_json, previous_event_hash, event_hash
                 ) VALUES ('stream_primary', 2, 'event_2', 'job_finished', 2,
                    'test-user', 'test-host', '{}', 'hash_1', 'hash_2');
                 UPDATE archive_meta SET value = '2' WHERE key = 'applied_event_seq';
                 UPDATE archive_meta SET value = 'hash_2' WHERE key = 'applied_event_hash';",
            )
            .unwrap();
        let error = database
            .cached_policy_findings(&status, &filter, 1, first.next.as_deref())
            .unwrap_err();
        assert_eq!(error.code(), "stale_continuation");
    }

    fn fresh_copy(
        id: &str,
        location_id: &str,
        location_name: &str,
        site_id: &str,
        site_name: &str,
        device_id: Option<&str>,
    ) -> CopyFact {
        let filesystem = device_id.is_some();
        CopyFact {
            copy_claim_id: id.to_owned(),
            state: "present".to_owned(),
            object_id: Some("object_1".to_owned()),
            last_seen_time_utc_ms: Some(900_000),
            last_verified_time_utc_ms: Some(900_000),
            last_verification_result: Some("ok".to_owned()),
            location_id: location_id.to_owned(),
            location_name: location_name.to_owned(),
            location_kind: if filesystem { "filesystem" } else { "service" }.to_owned(),
            location_status: "active".to_owned(),
            archive_root_id: filesystem.then(|| "root_1".to_owned()),
            archive_root_status: filesystem.then(|| "active".to_owned()),
            archive_root_device_id: device_id.map(str::to_owned),
            device_id: device_id.map(str::to_owned),
            device_name: device_id.map(|_| "Physical disk".to_owned()),
            device_status: filesystem.then(|| "active".to_owned()),
            device_identity_state: filesystem.then(|| "confirmed".to_owned()),
            device_expected_availability: filesystem.then(|| "online".to_owned()),
            last_checkin_time_utc_ms: filesystem.then_some(900_000),
            last_fingerprint_match_time_utc_ms: filesystem.then_some(900_000),
            last_fingerprint_status: filesystem.then(|| "match".to_owned()),
            site_id: Some(site_id.to_owned()),
            site_name: Some(site_name.to_owned()),
            site_status: Some("active".to_owned()),
            encryption_state: Some("encrypted".to_owned()),
            trust_level: Some("trusted".to_owned()),
            location_expected_availability: "online".to_owned(),
        }
    }

    #[test]
    fn classified_service_counts_as_copy_and_site_but_not_device() {
        let requirements = PolicyRequirements {
            min_qualifying_copies: 2,
            min_devices: 1,
            min_sites: 2,
            require_offsite_copy: true,
            require_offline_copy: false,
            require_encrypted_offsite: true,
            max_verification_age_days: 1,
            max_observation_age_days: 1,
            max_device_checkin_age_days: 1,
        };
        let file = FileFact {
            file_ref_id: "file_1".to_owned(),
            object_id: Some("object_1".to_owned()),
            identity_state: "resolved".to_owned(),
            logical_path_display: "photos/one.jpg".to_owned(),
            size_bytes: Some(1),
            hash_algo: Some("blake3".to_owned()),
            policy_id: "policy_1".to_owned(),
            collection_id: "collection_1".to_owned(),
            collection_name: "Photos".to_owned(),
            home_site_id: "site_home".to_owned(),
            copies: vec![
                fresh_copy(
                    "copy_disk",
                    "location_disk",
                    "Local disk",
                    "site_home",
                    "Home",
                    Some("device_1"),
                ),
                fresh_copy(
                    "copy_service",
                    "location_service",
                    "Cloud archive",
                    "site_remote",
                    "Cloud region",
                    None,
                ),
            ],
        };
        let result = evaluate_file(&file, &requirements, &DomainTopology::default(), NOW).unwrap();
        assert_eq!(result.status, None);
        assert!(result.reasons["failed_requirements"]
            .as_array()
            .unwrap()
            .is_empty());
        let scenarios = result.reasons["loss_scenarios"].as_array().unwrap();
        let service = scenarios
            .iter()
            .find(|scenario| scenario["domain_kind"] == "service")
            .unwrap();
        assert_eq!(service["domain_name"], "Cloud archive");
        assert_eq!(service["remaining_qualifying_copies"], 1);
        assert_eq!(service["permanent_loss"], false);
    }

    #[test]
    fn validates_complete_typed_requirements() {
        let missing = PolicyRequirements::from_json("policy_bad", r#"{"min_qualifying_copies":2}"#)
            .unwrap_err();
        assert_eq!(missing.code(), "policy_invalid_requirements");

        let zero = PolicyRequirements::from_json(
            "policy_bad",
            r#"{"min_qualifying_copies":0,"min_devices":1,"min_sites":1,"require_offsite_copy":false,"require_offline_copy":false,"require_encrypted_offsite":false,"max_verification_age_days":1,"max_observation_age_days":1,"max_device_checkin_age_days":1}"#,
        )
        .unwrap_err();
        assert_eq!(zero.code(), "policy_invalid_requirements");
    }
}
