//! Signed, immutable version 2 origin journals and frontier verification.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use ulid::Ulid;

use crate::frontier::{
    CausalFrontier, OriginFrontier, FRONTIER_VERSION, INITIAL_ITEM_PROJECTION_VERSION,
};
use crate::genesis::{client_id, GenesisBody, SignedGenesis};
use crate::v2_batch::{BatchChunkDescriptor, BatchCompletion, BatchLimits, BatchValidator};
use crate::v2_event::{
    parse_v2_record, V2Record, V2RecordEnvelope, V2RecordKind, DEFAULT_MAX_V2_RECORD_BYTES,
    V2_RECORD_VERSION,
};

const SEGMENT_NUMBER: u64 = 1;
const LOCAL_KEY_VERSION: u32 = 1;
const MANIFEST_VERSION: u32 = 2;
const CANONICAL_REF: &str = "refs/heads/archive-ledger";
const ACTIVE_CLIENT_FILE: &str = "ACTIVE";
const ENROLLMENT_REQUEST_VERSION: u32 = 1;
const COORDINATION_LEASE_VERSION: u32 = 1;
const PORTABLE_SNAPSHOT_VERSION: u32 = 1;
const DEFAULT_COORDINATION_LEASE_MS: u64 = 120_000;

pub type Result<T> = std::result::Result<T, V2StoreError>;

struct RemoveOnDrop {
    path: PathBuf,
    armed: bool,
}

impl RemoveOnDrop {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Error)]
pub enum V2StoreError {
    #[error("version 2 event tree is invalid: {0}")]
    Invalid(String),
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("version 2 JSON is invalid at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("version 2 genesis is invalid: {0}")]
    Genesis(#[from] crate::genesis::GenesisError),
    #[error("version 2 frontier is invalid: {0}")]
    Frontier(#[from] crate::frontier::FrontierError),
    #[error("version 2 record is invalid: {0}")]
    Record(#[from] crate::v2_event::V2RecordError),
    #[error("version 2 batch is invalid: {0}")]
    Batch(#[from] crate::v2_batch::BatchValidationError),
    #[error("Git operation {operation} failed in {path}")]
    Git {
        operation: &'static str,
        path: PathBuf,
    },
}

impl V2StoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "v2_store_io",
            Self::Json { .. } => "v2_store_json_invalid",
            Self::Git { .. } => "v2_store_git",
            Self::Invalid(_)
            | Self::Genesis(_)
            | Self::Frontier(_)
            | Self::Record(_)
            | Self::Batch(_) => "v2_event_tree_invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalClientKey {
    v: u32,
    archive_id: String,
    origin_id: String,
    secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequestBody {
    pub request_v: u32,
    pub archive_id: String,
    pub genesis_hash: String,
    pub client_id: String,
    pub public_key: String,
    pub display_name: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEnrollmentRequest {
    pub body: EnrollmentRequestBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableSnapshotManifestBody {
    pub snapshot_v: u32,
    pub archive_id: String,
    pub genesis_hash: String,
    pub schema_version: u32,
    pub projector_version: u32,
    pub canonical_git_commit: String,
    pub accepted_frontier_hash: String,
    pub applied_frontier_hash: String,
    pub database_blake3: String,
    pub database_bytes: u64,
    pub created_time_utc_ms: u64,
    pub signer_client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPortableSnapshotManifest {
    pub body: PortableSnapshotManifestBody,
    pub signature: String,
}

impl SignedEnrollmentRequest {
    pub fn verify(&self) -> Result<VerifyingKey> {
        if self.body.request_v != ENROLLMENT_REQUEST_VERSION
            || self.body.archive_id.is_empty()
            || self.body.genesis_hash.is_empty()
            || self.body.display_name.trim().is_empty()
            || self.body.capabilities.is_empty()
        {
            return Err(V2StoreError::Invalid(
                "client enrollment request is incomplete".to_owned(),
            ));
        }
        let bytes = STANDARD_NO_PAD.decode(&self.body.public_key).map_err(|_| {
            V2StoreError::Invalid("client enrollment public key is not base64".to_owned())
        })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            V2StoreError::Invalid("client enrollment public key has the wrong length".to_owned())
        })?;
        if self.body.client_id != client_id(&bytes) {
            return Err(V2StoreError::Invalid(
                "client enrollment ID does not match its public key".to_owned(),
            ));
        }
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            V2StoreError::Invalid("client enrollment public key is invalid".to_owned())
        })?;
        let signature = STANDARD_NO_PAD.decode(&self.signature).map_err(|_| {
            V2StoreError::Invalid("client enrollment signature is not base64".to_owned())
        })?;
        let signature = Signature::from_slice(&signature).map_err(|_| {
            V2StoreError::Invalid("client enrollment signature has the wrong length".to_owned())
        })?;
        key.verify_strict(&canonical_json(&self.body)?, &signature)
            .map_err(|_| {
                V2StoreError::Invalid("client enrollment signature is invalid".to_owned())
            })?;
        Ok(key)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentManifestBody {
    manifest_v: u32,
    archive_id: String,
    genesis_hash: String,
    origin_id: String,
    segment_path: String,
    first_seq: u64,
    last_seq: u64,
    first_record_id: String,
    last_record_id: String,
    first_record_hash: String,
    last_record_hash: String,
    record_count: u64,
    segment_bytes: u64,
    segment_blake3: String,
    causal_base_frontier_hash: String,
    previous_segment_manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedSegmentManifest {
    body: SegmentManifestBody,
    signature: String,
}

impl SignedSegmentManifest {
    fn create(body: SegmentManifestBody, key: &SigningKey) -> Result<Self> {
        validate_manifest_body(&body)?;
        let signature = key.sign(&canonical_json(&body)?);
        Ok(Self {
            body,
            signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
        })
    }

    fn verify(&self, key: &VerifyingKey) -> Result<()> {
        validate_manifest_body(&self.body)?;
        let signature = STANDARD_NO_PAD.decode(&self.signature).map_err(|_| {
            V2StoreError::Invalid("segment manifest signature is not base64".to_owned())
        })?;
        let signature = Signature::from_slice(&signature).map_err(|_| {
            V2StoreError::Invalid("segment manifest signature has the wrong length".to_owned())
        })?;
        key.verify_strict(&canonical_json(&self.body)?, &signature)
            .map_err(|_| V2StoreError::Invalid("segment manifest signature is invalid".to_owned()))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    fn manifest_hash(&self) -> Result<String> {
        Ok(blake3_id(&self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedV2Record {
    pub record: V2Record,
    pub exact_line_bytes: Vec<u8>,
    pub segment_manifest_hash: String,
    pub causal_frontier_hash: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedV2Archive {
    pub genesis: SignedGenesis,
    pub genesis_hash: String,
    pub accepted_frontier: CausalFrontier,
    pub accepted_frontier_hash: String,
    pub records: Vec<VerifiedV2Record>,
    /// Total records verified. Compact verification may retain only batch
    /// starts in `records` while still counting every canonical record here.
    pub record_count: u64,
    pub clients: BTreeMap<String, VerifiedV2Client>,
    pub(crate) frontiers: BTreeMap<String, CausalFrontier>,
    pub segment_count: u64,
    pub frontier_count: u64,
}

/// Immutable archive context made available while records are verified and
/// consumed one at a time.
#[derive(Debug, Clone)]
pub struct V2VerificationContext {
    pub genesis: SignedGenesis,
    pub genesis_hash: String,
    pub accepted_frontier: CausalFrontier,
    pub accepted_frontier_hash: String,
    pub(crate) frontiers: BTreeMap<String, CausalFrontier>,
}

impl From<&VerifiedV2Archive> for V2VerificationContext {
    fn from(verified: &VerifiedV2Archive) -> Self {
        Self {
            genesis: verified.genesis.clone(),
            genesis_hash: verified.genesis_hash.clone(),
            accepted_frontier: verified.accepted_frontier.clone(),
            accepted_frontier_hash: verified.accepted_frontier_hash.clone(),
            frontiers: verified.frontiers.clone(),
        }
    }
}

struct StreamingBatch {
    batch_id: String,
    validator: BatchValidator,
}

#[derive(Default)]
struct OriginVisitStats {
    records: u64,
    segments: u64,
    archive_initialized_at: Option<(String, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedV2Client {
    pub client_id: String,
    pub display_name: String,
    pub public_key: [u8; 32],
    pub capabilities: Vec<String>,
    pub approved_origin_id: String,
    pub approved_origin_seq: u64,
    pub revoked_origin_id: Option<String>,
    pub revoked_origin_seq: Option<u64>,
}

impl VerifiedV2Client {
    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| V2StoreError::Invalid("enrolled client public key is invalid".to_owned()))
    }

    fn is_revoked(&self) -> bool {
        self.revoked_origin_id.is_some()
    }
}

type VerifiedBatchRecords<'a> = (
    Option<&'a VerifiedV2Record>,
    Vec<&'a VerifiedV2Record>,
    Option<&'a VerifiedV2Record>,
);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2VerificationReport {
    pub version: u32,
    pub archive_id: String,
    pub genesis_hash: String,
    pub accepted_frontier_hash: String,
    pub origins: u64,
    pub records: u64,
    pub segments: u64,
    pub frontiers: u64,
}

#[derive(Debug, Clone)]
pub struct V2ArchiveInitialization {
    pub archive_id: String,
    pub archive_name: String,
    pub origin_id: String,
    pub genesis_hash: String,
    pub accepted_frontier_hash: String,
    pub git_commit: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2AppendResult {
    pub version: u32,
    pub batch_id: String,
    pub origin_id: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub records_written: u64,
    pub items_written: u64,
    pub segment_manifest_hash: String,
    pub accepted_frontier_hash: String,
    pub git_commit: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2SyncResult {
    pub version: u32,
    pub remote: String,
    pub local_commit_before: String,
    pub remote_commit_before: Option<String>,
    pub accepted_commit: String,
    pub accepted_frontier_hash: String,
    pub origins: u64,
    pub records: u64,
    pub fetched: bool,
    pub pushed: bool,
    pub merged: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2SyncRemote {
    pub name: String,
    pub locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinationLeaseBody {
    lease_v: u32,
    archive_id: String,
    genesis_hash: String,
    scope_kind: String,
    scope_id: String,
    token_id: String,
    holder_client_id: String,
    base_frontier_hash: String,
    state: String,
    not_before_utc_ms: u64,
    not_after_utc_ms: u64,
    previous_lease_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedCoordinationLease {
    body: CoordinationLeaseBody,
    signature: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct V2CoordinationLease {
    pub version: u32,
    pub remote: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub token_id: String,
    pub holder_client_id: String,
    pub base_frontier_hash: String,
    pub not_before_utc_ms: u64,
    pub not_after_utc_ms: u64,
    pub lease_commit: String,
    pub lease_proof: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2OriginCursor {
    pub applied_seq: u64,
    pub applied_record_hash: Option<String>,
    pub applied_segment_manifest_hash: Option<String>,
}

pub struct V2OriginStore {
    root: PathBuf,
}

impl V2OriginStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !is_v2_event_tree(&root) {
            return Err(V2StoreError::Invalid(format!(
                "{} is not a version 2 event tree (genesis.json is missing); recreate pre-v2 development Archives",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn canonical_commit(&self) -> Result<String> {
        git_stdout(&self.root, "read canonical commit", &["rev-parse", "HEAD"])
    }

    pub fn sign_portable_snapshot_manifest(
        &self,
        mut body: PortableSnapshotManifestBody,
    ) -> Result<SignedPortableSnapshotManifest> {
        let verified = self.verify_compact()?;
        let active = self.active_origin_id()?;
        let client = verified.clients.get(&active).ok_or_else(|| {
            V2StoreError::Invalid("active snapshot signer is not enrolled".to_owned())
        })?;
        if client.is_revoked() {
            return Err(V2StoreError::Invalid(
                "revoked client cannot sign a portable snapshot".to_owned(),
            ));
        }
        body.snapshot_v = PORTABLE_SNAPSHOT_VERSION;
        body.signer_client_id = active.clone();
        validate_snapshot_body(&body)?;
        if body.archive_id != verified.genesis.body.archive_id
            || body.genesis_hash != verified.genesis_hash
            || body.canonical_git_commit != self.canonical_commit()?
            || body.accepted_frontier_hash != verified.accepted_frontier_hash
            || body.applied_frontier_hash != verified.accepted_frontier_hash
        {
            return Err(V2StoreError::Invalid(
                "portable snapshot manifest does not bind the current canonical state".to_owned(),
            ));
        }
        let key = load_local_signing_key(
            self.root
                .parent()
                .expect("canonical tree has Archive parent"),
            &body.archive_id,
            &active,
        )?;
        let signature = key.sign(&canonical_json(&body)?);
        Ok(SignedPortableSnapshotManifest {
            body,
            signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify_portable_snapshot_manifest(
        &self,
        signed: &SignedPortableSnapshotManifest,
    ) -> Result<()> {
        validate_snapshot_body(&signed.body)?;
        let current_commit = self.canonical_commit()?;
        if !git_is_ancestor(
            &self.root,
            &signed.body.canonical_git_commit,
            &current_commit,
        )? {
            return Err(V2StoreError::Invalid(
                "portable snapshot commit is not in canonical history".to_owned(),
            ));
        }
        let historical_tree = GitWorktree::create(&self.root, &signed.body.canonical_git_commit)?;
        let historical_store = V2OriginStore::open(historical_tree.path())?;
        let verified = historical_store.verify_compact()?;
        if signed.body.archive_id != verified.genesis.body.archive_id
            || signed.body.genesis_hash != verified.genesis_hash
            || signed.body.accepted_frontier_hash != verified.accepted_frontier_hash
            || signed.body.applied_frontier_hash != verified.accepted_frontier_hash
        {
            return Err(V2StoreError::Invalid(
                "portable snapshot manifest does not match its canonical commit".to_owned(),
            ));
        }
        let client = verified
            .clients
            .get(&signed.body.signer_client_id)
            .ok_or_else(|| {
                V2StoreError::Invalid("portable snapshot signer is not enrolled".to_owned())
            })?;
        if client.is_revoked() {
            return Err(V2StoreError::Invalid(
                "portable snapshot signer was revoked at the bound commit".to_owned(),
            ));
        }
        let signature = STANDARD_NO_PAD.decode(&signed.signature).map_err(|_| {
            V2StoreError::Invalid("portable snapshot signature is not base64".to_owned())
        })?;
        let signature = Signature::from_slice(&signature).map_err(|_| {
            V2StoreError::Invalid("portable snapshot signature has the wrong length".to_owned())
        })?;
        client
            .verifying_key()?
            .verify_strict(&canonical_json(&signed.body)?, &signature)
            .map_err(|_| V2StoreError::Invalid("portable snapshot signature is invalid".to_owned()))
    }

    pub fn add_sync_remote(&self, name: &str, locator: &str) -> Result<()> {
        validate_remote_name(name)?;
        validate_remote_locator(locator)?;
        run_git(
            &self.root,
            "add synchronization remote",
            &["remote", "add", name, locator],
        )
    }

    pub fn remove_sync_remote(&self, name: &str) -> Result<()> {
        validate_remote_name(name)?;
        run_git(
            &self.root,
            "remove synchronization remote",
            &["remote", "remove", name],
        )
    }

    pub fn sync_remotes(&self) -> Result<Vec<V2SyncRemote>> {
        let names = git_stdout(&self.root, "list synchronization remotes", &["remote"])?;
        let mut remotes = Vec::new();
        for name in names.lines().filter(|name| !name.is_empty()) {
            validate_remote_name(name)?;
            let locator = git_stdout(
                &self.root,
                "read synchronization remote",
                &["remote", "get-url", name],
            )?;
            remotes.push(V2SyncRemote {
                name: name.to_owned(),
                locator,
            });
        }
        remotes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(remotes)
    }

    pub fn coordination_required(&self) -> Result<bool> {
        Ok(self.verify_compact()?.clients.len() > 1)
    }

    pub fn coordination_remote(&self) -> Result<String> {
        let remotes = self.sync_remotes()?;
        if remotes.len() == 1 {
            return Ok(remotes[0].name.clone());
        }
        if remotes.iter().any(|remote| remote.name == "origin") {
            return Ok("origin".to_owned());
        }
        if remotes.is_empty() {
            return Err(V2StoreError::Invalid(
                "multiple enrolled clients require a synchronization remote for coordinated changes"
                    .to_owned(),
            ));
        }
        Err(V2StoreError::Invalid(
            "multiple synchronization remotes are configured; an unambiguous coordination remote is required"
                .to_owned(),
        ))
    }

    pub fn append_coordinated_batch(
        &self,
        remote: &str,
        operation_kind: &str,
        item_schema_version: u32,
        mut context: Value,
        defaults: Value,
        items: Vec<Value>,
    ) -> Result<V2AppendResult> {
        self.sync_remote(remote)?;
        let lease = self.acquire_archive_lease(remote)?;
        let context_object = context.as_object_mut().ok_or_else(|| {
            V2StoreError::Invalid("coordinated batch context must be an object".to_owned())
        })?;
        context_object.insert("coordination".to_owned(), lease_context(&lease));
        let appended = match self.append_batch(
            operation_kind,
            item_schema_version,
            context,
            defaults,
            items,
        ) {
            Ok(appended) => appended,
            Err(error) => {
                let _ = self.release_archive_lease(&lease);
                return Err(error);
            }
        };
        self.sync_remote(remote)?;
        self.release_archive_lease(&lease)?;
        Ok(appended)
    }

    pub fn append_coordinated_jsonl_batch(
        &self,
        remote: &str,
        operation_kind: &str,
        item_schema_version: u32,
        mut context: Value,
        defaults: Value,
        spool_path: impl AsRef<Path>,
    ) -> Result<V2AppendResult> {
        let lease = self.acquire_archive_lease(remote)?;
        let context_object = context.as_object_mut().ok_or_else(|| {
            V2StoreError::Invalid("coordinated batch context must be an object".to_owned())
        })?;
        context_object.insert("coordination".to_owned(), lease_context(&lease));
        let appended = match self.append_jsonl_batch(
            operation_kind,
            item_schema_version,
            context,
            defaults,
            spool_path,
        ) {
            Ok(appended) => appended,
            Err(error) => {
                let _ = self.release_archive_lease(&lease);
                return Err(error);
            }
        };
        self.sync_remote(remote)?;
        self.release_archive_lease(&lease)?;
        Ok(appended)
    }

    pub fn sync_remote(&self, remote: &str) -> Result<V2SyncResult> {
        validate_remote_name(remote)?;
        ensure_git_clean(&self.root)?;
        let local_verified = self.verify_compact()?;
        let local_before =
            git_stdout(&self.root, "read local sync commit", &["rev-parse", "HEAD"])?;
        let remote_ref = format!("refs/archive-ledger/fetched/{remote}");
        for _attempt in 0..4 {
            let remote_before = remote_archive_commit(&self.root, remote)?;
            let Some(remote_commit) = remote_before.clone() else {
                if push_new_archive_ref(&self.root, remote, &local_before)? {
                    return sync_result(
                        remote,
                        local_before.clone(),
                        None,
                        local_before.clone(),
                        &local_verified,
                        false,
                        true,
                        false,
                    );
                }
                continue;
            };
            fetch_archive_ref(&self.root, remote, &remote_ref)?;
            let fetched_commit = git_stdout(
                &self.root,
                "read fetched synchronization commit",
                &["rev-parse", &remote_ref],
            )?;
            if fetched_commit != remote_commit {
                continue;
            }
            if fetched_commit == local_before {
                return sync_result(
                    remote,
                    local_before.clone(),
                    Some(remote_commit),
                    local_before.clone(),
                    &local_verified,
                    true,
                    false,
                    false,
                );
            }
            let remote_tree = GitWorktree::create(&self.root, &fetched_commit)?;
            let remote_store = V2OriginStore::open(remote_tree.path())?;
            let remote_verified = remote_store.verify_compact()?;
            validate_same_archive(&local_verified, &remote_verified)?;

            if git_is_ancestor(&self.root, &local_before, &fetched_commit)? {
                drop(remote_tree);
                run_git(
                    &self.root,
                    "fast-forward local synchronization ref",
                    &["merge", "--quiet", "--ff-only", &fetched_commit],
                )?;
                let verified = self.verify_compact()?;
                return sync_result(
                    remote,
                    local_before.clone(),
                    Some(remote_commit),
                    fetched_commit,
                    &verified,
                    true,
                    false,
                    false,
                );
            }
            if git_is_ancestor(&self.root, &fetched_commit, &local_before)? {
                validate_protected_publication(
                    &self.root,
                    remote,
                    &local_verified,
                    &remote_verified,
                )?;
                if push_archive_ref_cas(&self.root, remote, &local_before, &remote_commit)? {
                    return sync_result(
                        remote,
                        local_before.clone(),
                        Some(remote_commit),
                        local_before.clone(),
                        &local_verified,
                        true,
                        true,
                        false,
                    );
                }
                continue;
            }

            validate_protected_publication(&self.root, remote, &local_verified, &remote_verified)?;
            let union_tree = GitWorktree::create(&self.root, &local_before)?;
            merge_immutable_tree(remote_tree.path(), union_tree.path())?;
            let union_frontier = union_frontier(&local_verified, &remote_verified)?;
            write_frontier_idempotent(union_tree.path(), &union_frontier)?;
            let union_frontier_hash = union_frontier.frontier_hash()?;
            replace_synced(
                &union_tree.path().join("frontiers/v2/HEAD"),
                format!("{union_frontier_hash}\n").as_bytes(),
            )?;
            let union_store = V2OriginStore::open(union_tree.path())?;
            let union_verified = union_store.verify_compact()?;
            let union_commit = create_union_commit(
                union_tree.path(),
                &local_before,
                &remote_commit,
                &union_frontier_hash,
            )?;
            drop(remote_tree);
            drop(union_tree);
            if !push_archive_ref_cas(&self.root, remote, &union_commit, &remote_commit)? {
                continue;
            }
            run_git(
                &self.root,
                "fast-forward local synchronization union",
                &["merge", "--quiet", "--ff-only", &union_commit],
            )?;
            let verified = self.verify_compact()?;
            if verified.accepted_frontier_hash != union_verified.accepted_frontier_hash {
                return Err(V2StoreError::Invalid(
                    "local synchronization result differs from verified union".to_owned(),
                ));
            }
            return sync_result(
                remote,
                local_before.clone(),
                Some(remote_commit),
                union_commit,
                &verified,
                true,
                true,
                true,
            );
        }
        Err(V2StoreError::Invalid(
            "synchronization remote changed repeatedly; retry the sync".to_owned(),
        ))
    }

    pub fn acquire_archive_lease(&self, remote: &str) -> Result<V2CoordinationLease> {
        self.acquire_archive_lease_with_duration(remote, DEFAULT_COORDINATION_LEASE_MS)
    }

    fn acquire_archive_lease_with_duration(
        &self,
        remote: &str,
        duration_ms: u64,
    ) -> Result<V2CoordinationLease> {
        validate_remote_name(remote)?;
        if duration_ms == 0 {
            return Err(V2StoreError::Invalid(
                "coordination lease duration must be positive".to_owned(),
            ));
        }
        ensure_git_clean(&self.root)?;
        let verified = self.verify_compact()?;
        let active_client_id = self.active_origin_id()?;
        let client = verified
            .clients
            .get(&active_client_id)
            .ok_or_else(|| V2StoreError::Invalid("active client is not enrolled".to_owned()))?;
        if client.is_revoked()
            || !client
                .capabilities
                .iter()
                .any(|item| item == "coordination")
        {
            return Err(V2StoreError::Invalid(
                "active client is not authorized for coordination".to_owned(),
            ));
        }
        let local_commit =
            git_stdout(&self.root, "read lease base commit", &["rev-parse", "HEAD"])?;
        if remote_archive_commit(&self.root, remote)?.as_deref() != Some(&local_commit) {
            return Err(V2StoreError::Invalid(
                "synchronize the Archive before acquiring a coordination lease".to_owned(),
            ));
        }
        let signing_key = load_local_signing_key(
            self.root
                .parent()
                .expect("canonical tree has Archive parent"),
            &verified.genesis.body.archive_id,
            &active_client_id,
        )?;
        let scope_kind = "archive".to_owned();
        let scope_id = verified.genesis.body.archive_id.clone();
        let lease_ref = coordination_lease_ref(&scope_id);
        for _attempt in 0..4 {
            let previous_commit = remote_ref_commit(&self.root, remote, &lease_ref)?;
            let now = current_time_utc_ms()?;
            if let Some(previous_commit) = previous_commit.as_deref() {
                fetch_ref(
                    &self.root,
                    remote,
                    &lease_ref,
                    coordination_local_ref(&scope_id),
                )?;
                let previous = read_signed_lease_commit(
                    &self.root,
                    previous_commit,
                    &verified,
                    &scope_kind,
                    &scope_id,
                )?;
                if matches!(previous.body.state.as_str(), "acquired" | "renewed")
                    && now <= previous.body.not_after_utc_ms
                {
                    return Err(V2StoreError::Invalid(format!(
                        "coordination scope is held by client {} until {}",
                        previous.body.holder_client_id, previous.body.not_after_utc_ms
                    )));
                }
            }
            let not_after = now
                .checked_add(duration_ms)
                .ok_or_else(|| V2StoreError::Invalid("lease time overflow".to_owned()))?;
            let body = CoordinationLeaseBody {
                lease_v: COORDINATION_LEASE_VERSION,
                archive_id: verified.genesis.body.archive_id.clone(),
                genesis_hash: verified.genesis_hash.clone(),
                scope_kind: scope_kind.clone(),
                scope_id: scope_id.clone(),
                token_id: prefixed_ulid("lease_"),
                holder_client_id: active_client_id.clone(),
                base_frontier_hash: verified.accepted_frontier_hash.clone(),
                state: "acquired".to_owned(),
                not_before_utc_ms: now,
                not_after_utc_ms: not_after,
                previous_lease_commit: previous_commit.clone(),
            };
            let signed = sign_coordination_lease(body, &signing_key)?;
            let lease_commit =
                create_coordination_commit(&self.root, previous_commit.as_deref(), &signed)?;
            if push_ref_cas(
                &self.root,
                remote,
                &lease_commit,
                &lease_ref,
                previous_commit.as_deref(),
            )? {
                return Ok(V2CoordinationLease {
                    version: 2,
                    remote: remote.to_owned(),
                    scope_kind,
                    scope_id,
                    token_id: signed.body.token_id.clone(),
                    holder_client_id: active_client_id,
                    base_frontier_hash: signed.body.base_frontier_hash.clone(),
                    not_before_utc_ms: now,
                    not_after_utc_ms: not_after,
                    lease_commit,
                    lease_proof: serde_json::to_value(&signed).map_err(|error| {
                        V2StoreError::Invalid(format!(
                            "serialize coordination lease proof: {error}"
                        ))
                    })?,
                });
            }
        }
        Err(V2StoreError::Invalid(
            "coordination lease changed repeatedly; retry the operation".to_owned(),
        ))
    }

    pub fn release_archive_lease(&self, lease: &V2CoordinationLease) -> Result<()> {
        validate_remote_name(&lease.remote)?;
        let verified = self.verify_compact()?;
        if lease.scope_kind != "archive"
            || lease.scope_id != verified.genesis.body.archive_id
            || lease.holder_client_id != self.active_origin_id()?
        {
            return Err(V2StoreError::Invalid(
                "coordination lease does not belong to this active client and Archive".to_owned(),
            ));
        }
        let lease_ref = coordination_lease_ref(&lease.scope_id);
        if remote_ref_commit(&self.root, &lease.remote, &lease_ref)?.as_deref()
            != Some(&lease.lease_commit)
        {
            return Err(V2StoreError::Invalid(
                "coordination lease is no longer current".to_owned(),
            ));
        }
        let prior = read_signed_lease_commit(
            &self.root,
            &lease.lease_commit,
            &verified,
            &lease.scope_kind,
            &lease.scope_id,
        )?;
        if prior.body.token_id != lease.token_id
            || prior.body.holder_client_id != lease.holder_client_id
            || !matches!(prior.body.state.as_str(), "acquired" | "renewed")
        {
            return Err(V2StoreError::Invalid(
                "coordination lease token does not match the remote".to_owned(),
            ));
        }
        let signing_key = load_local_signing_key(
            self.root
                .parent()
                .expect("canonical tree has Archive parent"),
            &verified.genesis.body.archive_id,
            &lease.holder_client_id,
        )?;
        let now = current_time_utc_ms()?;
        let signed = sign_coordination_lease(
            CoordinationLeaseBody {
                lease_v: COORDINATION_LEASE_VERSION,
                archive_id: verified.genesis.body.archive_id,
                genesis_hash: verified.genesis_hash,
                scope_kind: lease.scope_kind.clone(),
                scope_id: lease.scope_id.clone(),
                token_id: lease.token_id.clone(),
                holder_client_id: lease.holder_client_id.clone(),
                base_frontier_hash: lease.base_frontier_hash.clone(),
                state: "released".to_owned(),
                not_before_utc_ms: lease.not_before_utc_ms,
                not_after_utc_ms: now,
                previous_lease_commit: Some(lease.lease_commit.clone()),
            },
            &signing_key,
        )?;
        let release_commit =
            create_coordination_commit(&self.root, Some(&lease.lease_commit), &signed)?;
        if !push_ref_cas(
            &self.root,
            &lease.remote,
            &release_commit,
            &lease_ref,
            Some(&lease.lease_commit),
        )? {
            return Err(V2StoreError::Invalid(
                "coordination lease changed before it could be released".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn active_origin_id(&self) -> Result<String> {
        let archive_root = self.root.parent().ok_or_else(|| {
            V2StoreError::Invalid("canonical event tree has no Archive parent".to_owned())
        })?;
        let active_path = archive_root.join("local/clients").join(ACTIVE_CLIENT_FILE);
        let active = String::from_utf8(read_file(&active_path)?)
            .map_err(|_| V2StoreError::Invalid("active client selector is not UTF-8".to_owned()))?;
        let origin_id = active.strip_suffix('\n').ok_or_else(|| {
            V2StoreError::Invalid("active client selector must end with one newline".to_owned())
        })?;
        validate_origin_id(origin_id)?;
        if active != format!("{origin_id}\n") {
            return Err(V2StoreError::Invalid(
                "active client selector must contain one origin ID".to_owned(),
            ));
        }
        Ok(origin_id.to_owned())
    }

    pub fn prepare_enrollment(&self, display_name: &str) -> Result<SignedEnrollmentRequest> {
        if display_name.trim().is_empty() {
            return Err(V2StoreError::Invalid(
                "client display name is required".to_owned(),
            ));
        }
        let genesis_path = self.root.join("genesis.json");
        let genesis_bytes = read_file(&genesis_path)?;
        let genesis: SignedGenesis = parse_json(&genesis_path, &genesis_bytes)?;
        genesis.verify()?;
        let archive_root = self.root.parent().ok_or_else(|| {
            V2StoreError::Invalid("canonical event tree has no Archive parent".to_owned())
        })?;
        let clients = archive_root.join("local/clients");
        fs::create_dir_all(&clients)
            .map_err(|source| io_error("create local client directory", &clients, source))?;
        set_private_directory_permissions(&archive_root.join("local"))?;
        set_private_directory_permissions(&clients)?;
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|error| {
            V2StoreError::Invalid(format!("operating-system randomness failed: {error}"))
        })?;
        let signing_key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        let public_key = signing_key.verifying_key().to_bytes();
        let origin_id = client_id(&public_key);
        let local_key = LocalClientKey {
            v: LOCAL_KEY_VERSION,
            archive_id: genesis.body.archive_id.clone(),
            origin_id: origin_id.clone(),
            secret_key: STANDARD_NO_PAD.encode(signing_key.to_bytes()),
        };
        let mut key_bytes = canonical_json(&local_key)?;
        key_bytes.push(b'\n');
        write_new_synced(
            &clients.join(format!("{origin_id}.key")),
            &key_bytes,
            Some(0o600),
        )?;
        replace_synced(
            &clients.join(ACTIVE_CLIENT_FILE),
            format!("{origin_id}\n").as_bytes(),
        )?;
        let genesis_hash = genesis.genesis_hash()?;
        let body = EnrollmentRequestBody {
            request_v: ENROLLMENT_REQUEST_VERSION,
            archive_id: genesis.body.archive_id.clone(),
            genesis_hash,
            client_id: origin_id,
            public_key: STANDARD_NO_PAD.encode(public_key),
            display_name: display_name.trim().to_owned(),
            capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
        };
        let signature = signing_key.sign(&canonical_json(&body)?);
        Ok(SignedEnrollmentRequest {
            body,
            signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn approve_enrollment(&self, request: &SignedEnrollmentRequest) -> Result<V2AppendResult> {
        let item = self.validated_enrollment_item(request)?;
        self.append_batch(
            "client_enroll",
            1,
            json!({"client_id": request.body.client_id}),
            json!({}),
            vec![item],
        )
    }

    pub fn approve_enrollment_coordinated(
        &self,
        remote: &str,
        request: &SignedEnrollmentRequest,
    ) -> Result<V2AppendResult> {
        let item = self.validated_enrollment_item(request)?;
        self.append_coordinated_batch(
            remote,
            "client_enroll",
            1,
            json!({"client_id": request.body.client_id}),
            json!({}),
            vec![item],
        )
    }

    fn validated_enrollment_item(&self, request: &SignedEnrollmentRequest) -> Result<Value> {
        request.verify()?;
        let verified = self.verify_compact()?;
        if request.body.archive_id != verified.genesis.body.archive_id
            || request.body.genesis_hash != verified.genesis_hash
        {
            return Err(V2StoreError::Invalid(
                "client enrollment request belongs to another Archive".to_owned(),
            ));
        }
        if verified.clients.contains_key(&request.body.client_id) {
            return Err(V2StoreError::Invalid(
                "the requested client is already enrolled".to_owned(),
            ));
        }
        Ok(json!({
            "kind": "client_enrolled",
            "client_id": request.body.client_id,
            "display_name": request.body.display_name,
            "public_key": request.body.public_key,
            "capabilities": request.body.capabilities,
        }))
    }

    pub fn revoke_client(&self, client_id: &str) -> Result<V2AppendResult> {
        validate_origin_id(client_id)?;
        if self.active_origin_id()? == client_id {
            return Err(V2StoreError::Invalid(
                "the active client cannot revoke itself".to_owned(),
            ));
        }
        self.append_batch(
            "client_revoke",
            1,
            json!({"client_id": client_id}),
            json!({}),
            vec![json!({"kind": "client_revoked", "client_id": client_id})],
        )
    }

    pub fn revoke_client_coordinated(
        &self,
        remote: &str,
        client_id: &str,
    ) -> Result<V2AppendResult> {
        validate_origin_id(client_id)?;
        if self.active_origin_id()? == client_id {
            return Err(V2StoreError::Invalid(
                "the active client cannot revoke itself".to_owned(),
            ));
        }
        self.append_coordinated_batch(
            remote,
            "client_revoke",
            1,
            json!({"client_id": client_id}),
            json!({}),
            vec![json!({"kind": "client_revoked", "client_id": client_id})],
        )
    }

    pub fn verify(&self) -> Result<VerifiedV2Archive> {
        let genesis_path = self.root.join("genesis.json");
        let genesis_bytes = read_file(&genesis_path)?;
        let genesis: SignedGenesis = parse_json(&genesis_path, &genesis_bytes)?;
        genesis.verify().map_err(V2StoreError::from)?;
        if genesis.canonical_bytes().map_err(V2StoreError::from)? != genesis_bytes {
            return Err(V2StoreError::Invalid(
                "genesis.json does not use deterministic bytes".to_owned(),
            ));
        }
        let genesis_hash = genesis.genesis_hash().map_err(V2StoreError::from)?;

        let head_path = self.root.join("frontiers/v2/HEAD");
        let head = String::from_utf8(read_file(&head_path)?)
            .map_err(|_| V2StoreError::Invalid("frontier HEAD is not UTF-8".to_owned()))?;
        let accepted_frontier_hash = head.trim_end_matches('\n');
        validate_blake3_id("frontier HEAD", accepted_frontier_hash)?;
        if head != format!("{accepted_frontier_hash}\n") {
            return Err(V2StoreError::Invalid(
                "frontier HEAD must contain one hash and a newline".to_owned(),
            ));
        }

        let mut visited = BTreeMap::new();
        load_frontier_graph(
            &self.root,
            accepted_frontier_hash,
            &genesis.body.archive_id,
            &genesis_hash,
            &mut visited,
        )?;
        let accepted_frontier = visited
            .get(accepted_frontier_hash)
            .cloned()
            .ok_or_else(|| V2StoreError::Invalid("accepted frontier was not loaded".to_owned()))?;

        let mut records = Vec::new();
        let mut segment_count = 0_u64;
        let initial_origin = accepted_frontier
            .origins
            .iter()
            .find(|origin| origin.origin_id == genesis.body.initial_client_id)
            .ok_or_else(|| {
                V2StoreError::Invalid("accepted frontier omits the genesis client".to_owned())
            })?;
        let initial_key = genesis.body.validate().map_err(V2StoreError::from)?;
        let (initial_records, initial_segments) = verify_origin(
            &self.root,
            &genesis,
            &genesis_hash,
            &initial_key,
            initial_origin,
        )?;
        segment_count = segment_count.saturating_add(
            u64::try_from(initial_segments)
                .map_err(|_| V2StoreError::Invalid("segment count overflow".to_owned()))?,
        );
        let approval = initial_records
            .iter()
            .find(|record| record_contains_item_kind(record, "archive_initialized"))
            .ok_or_else(|| {
                V2StoreError::Invalid("genesis origin lacks archive_initialized".to_owned())
            })?;
        let mut clients = BTreeMap::from([(
            genesis.body.initial_client_id.clone(),
            VerifiedV2Client {
                client_id: genesis.body.initial_client_id.clone(),
                display_name: "Initial client".to_owned(),
                public_key: initial_key.to_bytes(),
                capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
                approved_origin_id: approval.record.envelope.origin_id.clone(),
                approved_origin_seq: approval.record.envelope.origin_seq,
                revoked_origin_id: None,
                revoked_origin_seq: None,
            },
        )]);
        apply_client_registry_items(&initial_records, &mut clients)?;
        records.extend(initial_records);

        let mut pending = accepted_frontier
            .origins
            .iter()
            .filter(|origin| origin.origin_id != genesis.body.initial_client_id)
            .map(|origin| origin.origin_id.clone())
            .collect::<BTreeSet<_>>();
        while !pending.is_empty() {
            let mut progressed = false;
            let candidates = pending.iter().cloned().collect::<Vec<_>>();
            for origin_id in candidates {
                let Some(client) = clients.get(&origin_id).cloned() else {
                    continue;
                };
                let origin = accepted_frontier
                    .origins
                    .iter()
                    .find(|origin| origin.origin_id == origin_id)
                    .expect("pending origin came from the accepted frontier");
                let key = client.verifying_key()?;
                let (origin_records, origin_segments) =
                    verify_origin(&self.root, &genesis, &genesis_hash, &key, origin)?;
                validate_client_origin_records(&origin_records, &client, &visited)?;
                segment_count = segment_count.saturating_add(
                    u64::try_from(origin_segments)
                        .map_err(|_| V2StoreError::Invalid("segment count overflow".to_owned()))?,
                );
                apply_client_registry_items(&origin_records, &mut clients)?;
                records.extend(origin_records);
                pending.remove(&origin_id);
                progressed = true;
            }
            if !progressed {
                return Err(V2StoreError::Invalid(format!(
                    "accepted frontier contains origins without trusted enrollment: {}",
                    pending.into_iter().collect::<Vec<_>>().join(", ")
                )));
            }
        }
        for record in &records {
            if !visited.contains_key(&record.causal_frontier_hash) {
                return Err(V2StoreError::Invalid(format!(
                    "record {} depends on an unknown causal frontier",
                    record.record.envelope.record_id
                )));
            }
        }
        validate_coordination_contexts(&records, &clients)?;
        verify_batches(&records)?;

        let frontier_count = u64::try_from(visited.len())
            .map_err(|_| V2StoreError::Invalid("frontier count overflow".to_owned()))?;
        let record_count = accepted_frontier
            .origins
            .iter()
            .try_fold(0_u64, |total, origin| total.checked_add(origin.seq))
            .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
        Ok(VerifiedV2Archive {
            genesis,
            genesis_hash,
            accepted_frontier,
            accepted_frontier_hash: accepted_frontier_hash.to_owned(),
            records,
            record_count,
            clients,
            frontiers: visited,
            segment_count,
            frontier_count,
        })
    }

    /// Fully verifies canonical history while retaining only coordination
    /// batch starts and the initialization approval needed by consumers.
    pub fn verify_compact(&self) -> Result<VerifiedV2Archive> {
        let genesis_path = self.root.join("genesis.json");
        let genesis_bytes = read_file(&genesis_path)?;
        let genesis: SignedGenesis = parse_json(&genesis_path, &genesis_bytes)?;
        genesis.verify().map_err(V2StoreError::from)?;
        if genesis.canonical_bytes().map_err(V2StoreError::from)? != genesis_bytes {
            return Err(V2StoreError::Invalid(
                "genesis.json does not use deterministic bytes".to_owned(),
            ));
        }
        let genesis_hash = genesis.genesis_hash().map_err(V2StoreError::from)?;
        let head_path = self.root.join("frontiers/v2/HEAD");
        let head = String::from_utf8(read_file(&head_path)?)
            .map_err(|_| V2StoreError::Invalid("frontier HEAD is not UTF-8".to_owned()))?;
        let accepted_frontier_hash = head.trim_end_matches('\n');
        validate_blake3_id("frontier HEAD", accepted_frontier_hash)?;
        if head != format!("{accepted_frontier_hash}\n") {
            return Err(V2StoreError::Invalid(
                "frontier HEAD must contain one hash and a newline".to_owned(),
            ));
        }
        let mut frontiers = BTreeMap::new();
        load_frontier_graph(
            &self.root,
            accepted_frontier_hash,
            &genesis.body.archive_id,
            &genesis_hash,
            &mut frontiers,
        )?;
        let accepted_frontier = frontiers
            .get(accepted_frontier_hash)
            .cloned()
            .ok_or_else(|| V2StoreError::Invalid("accepted frontier was not loaded".to_owned()))?;
        let initial_key = genesis.body.validate().map_err(V2StoreError::from)?;
        let mut clients = BTreeMap::from([(
            genesis.body.initial_client_id.clone(),
            VerifiedV2Client {
                client_id: genesis.body.initial_client_id.clone(),
                display_name: "Initial client".to_owned(),
                public_key: initial_key.to_bytes(),
                capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
                approved_origin_id: genesis.body.initial_client_id.clone(),
                approved_origin_seq: 2,
                revoked_origin_id: None,
                revoked_origin_seq: None,
            },
        )]);
        let mut retained_starts = Vec::new();
        let mut record_count = 0_u64;
        let mut segment_count = 0_u64;
        let initial_origin = accepted_frontier
            .origins
            .iter()
            .find(|origin| origin.origin_id == genesis.body.initial_client_id)
            .ok_or_else(|| {
                V2StoreError::Invalid("accepted frontier omits the genesis client".to_owned())
            })?;
        let initial_stats = visit_origin_range::<V2StoreError, _>(
            &self.root,
            &genesis,
            &genesis_hash,
            &initial_key,
            initial_origin,
            V2OriginCursor {
                applied_seq: 0,
                applied_record_hash: None,
                applied_segment_manifest_hash: None,
            },
            &frontiers,
            None,
            &mut clients,
            true,
            &mut retained_starts,
            &mut |_| Ok(()),
        )?;
        let (approval_origin, approval_seq) =
            initial_stats.archive_initialized_at.ok_or_else(|| {
                V2StoreError::Invalid("genesis origin lacks archive_initialized".to_owned())
            })?;
        let initial_client = clients
            .get_mut(&genesis.body.initial_client_id)
            .expect("initial client was inserted");
        initial_client.approved_origin_id = approval_origin;
        initial_client.approved_origin_seq = approval_seq;
        record_count = record_count
            .checked_add(initial_stats.records)
            .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
        segment_count = segment_count
            .checked_add(initial_stats.segments)
            .ok_or_else(|| V2StoreError::Invalid("segment count overflow".to_owned()))?;

        let mut pending = accepted_frontier
            .origins
            .iter()
            .filter(|origin| origin.origin_id != genesis.body.initial_client_id)
            .map(|origin| origin.origin_id.clone())
            .collect::<BTreeSet<_>>();
        while !pending.is_empty() {
            let mut progressed = false;
            for origin_id in pending.iter().cloned().collect::<Vec<_>>() {
                let Some(client) = clients.get(&origin_id).cloned() else {
                    continue;
                };
                let origin = accepted_frontier
                    .origins
                    .iter()
                    .find(|origin| origin.origin_id == origin_id)
                    .expect("pending origin came from accepted frontier");
                let key = client.verifying_key()?;
                let stats = visit_origin_range::<V2StoreError, _>(
                    &self.root,
                    &genesis,
                    &genesis_hash,
                    &key,
                    origin,
                    V2OriginCursor {
                        applied_seq: 0,
                        applied_record_hash: None,
                        applied_segment_manifest_hash: None,
                    },
                    &frontiers,
                    Some(&client),
                    &mut clients,
                    true,
                    &mut retained_starts,
                    &mut |_| Ok(()),
                )?;
                record_count = record_count
                    .checked_add(stats.records)
                    .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
                segment_count = segment_count
                    .checked_add(stats.segments)
                    .ok_or_else(|| V2StoreError::Invalid("segment count overflow".to_owned()))?;
                pending.remove(&origin_id);
                progressed = true;
            }
            if !progressed {
                return Err(V2StoreError::Invalid(format!(
                    "accepted frontier contains origins without trusted enrollment: {}",
                    pending.into_iter().collect::<Vec<_>>().join(", ")
                )));
            }
        }
        let expected_records = accepted_frontier
            .origins
            .iter()
            .try_fold(0_u64, |total, origin| total.checked_add(origin.seq))
            .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
        if record_count != expected_records {
            return Err(V2StoreError::Invalid(
                "verified record count does not match accepted frontier".to_owned(),
            ));
        }
        let frontier_count = u64::try_from(frontiers.len())
            .map_err(|_| V2StoreError::Invalid("frontier count overflow".to_owned()))?;
        Ok(VerifiedV2Archive {
            genesis,
            genesis_hash,
            accepted_frontier,
            accepted_frontier_hash: accepted_frontier_hash.to_owned(),
            records: retained_starts,
            record_count,
            clients,
            frontiers,
            segment_count,
            frontier_count,
        })
    }

    pub fn verification_report(&self) -> Result<V2VerificationReport> {
        let verified = self.verify_compact()?;
        Ok(V2VerificationReport {
            version: 2,
            archive_id: verified.genesis.body.archive_id.clone(),
            genesis_hash: verified.genesis_hash,
            accepted_frontier_hash: verified.accepted_frontier_hash,
            origins: u64::try_from(verified.accepted_frontier.origins.len())
                .map_err(|_| V2StoreError::Invalid("origin count overflow".to_owned()))?,
            records: verified.record_count,
            segments: verified.segment_count,
            frontiers: verified.frontier_count,
        })
    }

    pub fn verify_since(
        &self,
        base_frontier_hash: &str,
        cursors: &BTreeMap<String, V2OriginCursor>,
    ) -> Result<VerifiedV2Archive> {
        let genesis_path = self.root.join("genesis.json");
        let genesis: SignedGenesis = parse_json(&genesis_path, &read_file(&genesis_path)?)?;
        let key = genesis.body.validate()?;
        let clients = BTreeMap::from([(
            genesis.body.initial_client_id.clone(),
            VerifiedV2Client {
                client_id: genesis.body.initial_client_id.clone(),
                display_name: "Initial client".to_owned(),
                public_key: key.to_bytes(),
                capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
                approved_origin_id: genesis.body.initial_client_id,
                approved_origin_seq: 2,
                revoked_origin_id: None,
                revoked_origin_seq: None,
            },
        )]);
        self.verify_since_with_clients(base_frontier_hash, cursors, &clients)
    }

    /// Verifies and returns only ranges newer than a trusted projection
    /// frontier/cursor set. This is the normal incremental projection path;
    /// [`Self::verify`] remains the explicit full-history audit path.
    pub fn verify_since_with_clients(
        &self,
        base_frontier_hash: &str,
        cursors: &BTreeMap<String, V2OriginCursor>,
        trusted_clients: &BTreeMap<String, VerifiedV2Client>,
    ) -> Result<VerifiedV2Archive> {
        validate_blake3_id("base frontier hash", base_frontier_hash)?;
        let genesis_path = self.root.join("genesis.json");
        let genesis_bytes = read_file(&genesis_path)?;
        let genesis: SignedGenesis = parse_json(&genesis_path, &genesis_bytes)?;
        genesis.verify()?;
        if genesis.canonical_bytes()? != genesis_bytes {
            return Err(V2StoreError::Invalid(
                "genesis.json does not use deterministic bytes".to_owned(),
            ));
        }
        let genesis_hash = genesis.genesis_hash()?;
        let head_path = self.root.join("frontiers/v2/HEAD");
        let head = String::from_utf8(read_file(&head_path)?)
            .map_err(|_| V2StoreError::Invalid("frontier HEAD is not UTF-8".to_owned()))?;
        let accepted_frontier_hash = head.trim_end_matches('\n');
        validate_blake3_id("frontier HEAD", accepted_frontier_hash)?;
        if head != format!("{accepted_frontier_hash}\n") {
            return Err(V2StoreError::Invalid(
                "frontier HEAD must contain one hash and a newline".to_owned(),
            ));
        }
        let mut visited = BTreeMap::new();
        load_frontier_path_to_base(
            &self.root,
            accepted_frontier_hash,
            base_frontier_hash,
            &genesis.body.archive_id,
            &genesis_hash,
            &mut visited,
        )?;
        if !visited.contains_key(base_frontier_hash) {
            return Err(V2StoreError::Invalid(
                "SQLite applied frontier is not an ancestor of canonical HEAD".to_owned(),
            ));
        }
        let accepted_frontier = visited
            .get(accepted_frontier_hash)
            .cloned()
            .ok_or_else(|| V2StoreError::Invalid("accepted frontier was not loaded".to_owned()))?;
        let initial_key = genesis.body.validate()?;
        let mut clients = trusted_clients.clone();
        clients
            .entry(genesis.body.initial_client_id.clone())
            .or_insert_with(|| VerifiedV2Client {
                client_id: genesis.body.initial_client_id.clone(),
                display_name: "Initial client".to_owned(),
                public_key: initial_key.to_bytes(),
                capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
                approved_origin_id: genesis.body.initial_client_id.clone(),
                approved_origin_seq: 2,
                revoked_origin_id: None,
                revoked_origin_seq: None,
            });
        let mut records = Vec::new();
        let mut segment_count = 0_u64;
        let mut pending = BTreeSet::new();
        for origin in &accepted_frontier.origins {
            let cursor = cursors
                .get(&origin.origin_id)
                .cloned()
                .unwrap_or(V2OriginCursor {
                    applied_seq: 0,
                    applied_record_hash: None,
                    applied_segment_manifest_hash: None,
                });
            if cursor.applied_seq > origin.seq
                || (cursor.applied_seq == 0
                    && (cursor.applied_record_hash.is_some()
                        || cursor.applied_segment_manifest_hash.is_some()))
                || (cursor.applied_seq > 0
                    && (cursor.applied_record_hash.is_none()
                        || cursor.applied_segment_manifest_hash.is_none()))
            {
                return Err(V2StoreError::Invalid(format!(
                    "projection cursor for origin {} is structurally invalid",
                    origin.origin_id
                )));
            }
            if cursor.applied_seq == origin.seq {
                if cursor.applied_record_hash.as_deref() != Some(&origin.event_hash)
                    || cursor.applied_segment_manifest_hash.as_deref()
                        != Some(&origin.segment_manifest_hash)
                {
                    return Err(V2StoreError::Invalid(format!(
                        "projection cursor does not match canonical origin {}",
                        origin.origin_id
                    )));
                }
                continue;
            }
            pending.insert(origin.origin_id.clone());
        }
        while !pending.is_empty() {
            let mut progressed = false;
            let candidates = pending.iter().cloned().collect::<Vec<_>>();
            for origin_id in candidates {
                let Some(client) = clients.get(&origin_id).cloned() else {
                    continue;
                };
                let origin = accepted_frontier
                    .origins
                    .iter()
                    .find(|origin| origin.origin_id == origin_id)
                    .expect("pending origin came from accepted frontier");
                let cursor = cursors.get(&origin_id).cloned().unwrap_or(V2OriginCursor {
                    applied_seq: 0,
                    applied_record_hash: None,
                    applied_segment_manifest_hash: None,
                });
                let key = client.verifying_key()?;
                let (range, segments) = verify_origin_range(
                    &self.root,
                    &genesis,
                    &genesis_hash,
                    &key,
                    origin,
                    cursor,
                    &visited,
                )?;
                if origin_id != genesis.body.initial_client_id {
                    validate_client_origin_records(&range, &client, &visited)?;
                }
                segment_count = segment_count
                    .checked_add(segments)
                    .ok_or_else(|| V2StoreError::Invalid("segment count overflow".to_owned()))?;
                apply_client_registry_items(&range, &mut clients)?;
                records.extend(range);
                pending.remove(&origin_id);
                progressed = true;
            }
            if !progressed {
                return Err(V2StoreError::Invalid(format!(
                    "unapplied frontier contains origins without trusted enrollment: {}",
                    pending.into_iter().collect::<Vec<_>>().join(", ")
                )));
            }
        }
        validate_coordination_contexts(&records, &clients)?;
        verify_batches(&records)?;
        let frontier_count = u64::try_from(visited.len())
            .map_err(|_| V2StoreError::Invalid("frontier count overflow".to_owned()))?;
        Ok(VerifiedV2Archive {
            clients,
            genesis,
            genesis_hash,
            accepted_frontier,
            accepted_frontier_hash: accepted_frontier_hash.to_owned(),
            record_count: u64::try_from(records.len())
                .map_err(|_| V2StoreError::Invalid("record count overflow".to_owned()))?,
            records,
            frontiers: visited,
            segment_count,
            frontier_count,
        })
    }

    /// Incrementally verifies canonical records and yields each authenticated
    /// record without retaining decoded batch chunks in memory.
    pub fn visit_verified_since_with_clients<E, F>(
        &self,
        base_frontier_hash: &str,
        cursors: &BTreeMap<String, V2OriginCursor>,
        trusted_clients: &BTreeMap<String, VerifiedV2Client>,
        mut visitor: F,
    ) -> std::result::Result<VerifiedV2Archive, E>
    where
        E: From<V2StoreError>,
        F: FnMut(&VerifiedV2Record, &V2VerificationContext) -> std::result::Result<(), E>,
    {
        validate_blake3_id("base frontier hash", base_frontier_hash)?;
        let genesis_path = self.root.join("genesis.json");
        let genesis_bytes = read_file(&genesis_path)?;
        let genesis: SignedGenesis = parse_json(&genesis_path, &genesis_bytes)?;
        genesis.verify().map_err(V2StoreError::from)?;
        if genesis.canonical_bytes().map_err(V2StoreError::from)? != genesis_bytes {
            return Err(V2StoreError::Invalid(
                "genesis.json does not use deterministic bytes".to_owned(),
            )
            .into());
        }
        let genesis_hash = genesis.genesis_hash().map_err(V2StoreError::from)?;
        let head_path = self.root.join("frontiers/v2/HEAD");
        let head = String::from_utf8(read_file(&head_path)?)
            .map_err(|_| V2StoreError::Invalid("frontier HEAD is not UTF-8".to_owned()))?;
        let accepted_frontier_hash = head.trim_end_matches('\n');
        validate_blake3_id("frontier HEAD", accepted_frontier_hash)?;
        if head != format!("{accepted_frontier_hash}\n") {
            return Err(V2StoreError::Invalid(
                "frontier HEAD must contain one hash and a newline".to_owned(),
            )
            .into());
        }
        let mut frontiers = BTreeMap::new();
        load_frontier_path_to_base(
            &self.root,
            accepted_frontier_hash,
            base_frontier_hash,
            &genesis.body.archive_id,
            &genesis_hash,
            &mut frontiers,
        )?;
        if !frontiers.contains_key(base_frontier_hash) {
            return Err(V2StoreError::Invalid(
                "SQLite applied frontier is not an ancestor of canonical HEAD".to_owned(),
            )
            .into());
        }
        let accepted_frontier = frontiers
            .get(accepted_frontier_hash)
            .cloned()
            .ok_or_else(|| V2StoreError::Invalid("accepted frontier was not loaded".to_owned()))?;
        let context = V2VerificationContext {
            genesis: genesis.clone(),
            genesis_hash: genesis_hash.clone(),
            accepted_frontier: accepted_frontier.clone(),
            accepted_frontier_hash: accepted_frontier_hash.to_owned(),
            frontiers: frontiers.clone(),
        };
        let initial_key = genesis.body.validate().map_err(V2StoreError::from)?;
        let mut clients = trusted_clients.clone();
        clients
            .entry(genesis.body.initial_client_id.clone())
            .or_insert_with(|| VerifiedV2Client {
                client_id: genesis.body.initial_client_id.clone(),
                display_name: "Initial client".to_owned(),
                public_key: initial_key.to_bytes(),
                capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
                approved_origin_id: genesis.body.initial_client_id.clone(),
                approved_origin_seq: 2,
                revoked_origin_id: None,
                revoked_origin_seq: None,
            });
        let mut pending = BTreeSet::new();
        for origin in &accepted_frontier.origins {
            let cursor = cursors
                .get(&origin.origin_id)
                .cloned()
                .unwrap_or(V2OriginCursor {
                    applied_seq: 0,
                    applied_record_hash: None,
                    applied_segment_manifest_hash: None,
                });
            if cursor.applied_seq > origin.seq
                || (cursor.applied_seq == 0
                    && (cursor.applied_record_hash.is_some()
                        || cursor.applied_segment_manifest_hash.is_some()))
                || (cursor.applied_seq > 0
                    && (cursor.applied_record_hash.is_none()
                        || cursor.applied_segment_manifest_hash.is_none()))
            {
                return Err(V2StoreError::Invalid(format!(
                    "projection cursor for origin {} is structurally invalid",
                    origin.origin_id
                ))
                .into());
            }
            if cursor.applied_seq == origin.seq {
                if cursor.applied_record_hash.as_deref() != Some(&origin.event_hash)
                    || cursor.applied_segment_manifest_hash.as_deref()
                        != Some(&origin.segment_manifest_hash)
                {
                    return Err(V2StoreError::Invalid(format!(
                        "projection cursor does not match canonical origin {}",
                        origin.origin_id
                    ))
                    .into());
                }
            } else {
                pending.insert(origin.origin_id.clone());
            }
        }
        let mut retained_starts = Vec::new();
        let mut record_count = 0_u64;
        let mut segment_count = 0_u64;
        while !pending.is_empty() {
            let mut progressed = false;
            for origin_id in pending.iter().cloned().collect::<Vec<_>>() {
                let Some(client) = clients.get(&origin_id).cloned() else {
                    continue;
                };
                let origin = accepted_frontier
                    .origins
                    .iter()
                    .find(|origin| origin.origin_id == origin_id)
                    .expect("pending origin came from accepted frontier");
                let cursor = cursors.get(&origin_id).cloned().unwrap_or(V2OriginCursor {
                    applied_seq: 0,
                    applied_record_hash: None,
                    applied_segment_manifest_hash: None,
                });
                let key = client.verifying_key()?;
                let validation_client =
                    (origin_id != genesis.body.initial_client_id).then_some(&client);
                let mut yield_record = |record: &VerifiedV2Record| visitor(record, &context);
                let stats = visit_origin_range(
                    &self.root,
                    &genesis,
                    &genesis_hash,
                    &key,
                    origin,
                    cursor,
                    &frontiers,
                    validation_client,
                    &mut clients,
                    true,
                    &mut retained_starts,
                    &mut yield_record,
                )?;
                record_count = record_count
                    .checked_add(stats.records)
                    .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
                segment_count = segment_count
                    .checked_add(stats.segments)
                    .ok_or_else(|| V2StoreError::Invalid("segment count overflow".to_owned()))?;
                pending.remove(&origin_id);
                progressed = true;
            }
            if !progressed {
                return Err(V2StoreError::Invalid(format!(
                    "unapplied frontier contains origins without trusted enrollment: {}",
                    pending.into_iter().collect::<Vec<_>>().join(", ")
                ))
                .into());
            }
        }
        let frontier_count = u64::try_from(frontiers.len())
            .map_err(|_| V2StoreError::Invalid("frontier count overflow".to_owned()))?;
        Ok(VerifiedV2Archive {
            clients,
            genesis,
            genesis_hash,
            accepted_frontier,
            accepted_frontier_hash: accepted_frontier_hash.to_owned(),
            records: retained_starts,
            record_count,
            frontiers,
            segment_count,
            frontier_count,
        })
    }

    /// Appends one complete logical mutation as a sealed, signed segment.
    ///
    /// The accepted frontier advances only after the immutable segment and its
    /// manifest are durable. The caller may then incrementally advance SQLite;
    /// canonical history remains authoritative if projection is interrupted.
    pub fn append_batch(
        &self,
        operation_kind: &str,
        item_schema_version: u32,
        context: Value,
        defaults: Value,
        items: Vec<Value>,
    ) -> Result<V2AppendResult> {
        self.append_batch_iter(
            operation_kind,
            item_schema_version,
            context,
            defaults,
            items.into_iter().map(Ok),
        )
    }

    /// Appends a logical batch from a local JSONL spool without loading all
    /// items into memory. Each non-empty line must contain one JSON object.
    pub fn append_jsonl_batch(
        &self,
        operation_kind: &str,
        item_schema_version: u32,
        context: Value,
        defaults: Value,
        spool_path: impl AsRef<Path>,
    ) -> Result<V2AppendResult> {
        let spool_path = spool_path.as_ref().to_path_buf();
        let file = File::open(&spool_path)
            .map_err(|source| io_error("open batch item spool", &spool_path, source))?;
        let items = BufReader::new(file).lines().map(|line| {
            let line =
                line.map_err(|source| io_error("read batch item spool", &spool_path, source))?;
            serde_json::from_str::<Value>(&line).map_err(|source| V2StoreError::Json {
                path: spool_path.clone(),
                source,
            })
        });
        self.append_batch_iter(
            operation_kind,
            item_schema_version,
            context,
            defaults,
            items,
        )
    }

    fn append_batch_iter<I>(
        &self,
        operation_kind: &str,
        item_schema_version: u32,
        context: Value,
        defaults: Value,
        items: I,
    ) -> Result<V2AppendResult>
    where
        I: Iterator<Item = Result<Value>>,
    {
        if operation_kind.is_empty() || item_schema_version == 0 {
            return Err(V2StoreError::Invalid(
                "batch operation kind and item schema version are required".to_owned(),
            ));
        }
        if !context.is_object() || !defaults.is_object() {
            return Err(V2StoreError::Invalid(
                "batch context and defaults must be JSON objects".to_owned(),
            ));
        }
        let local = self.root.parent().ok_or_else(|| {
            V2StoreError::Invalid("canonical event tree has no Archive parent".to_owned())
        })?;
        let lock_path = local.join("local/append.lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| io_error("create append lock directory", parent, source))?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_error("open append lock", &lock_path, source))?;
        lock.lock_exclusive()
            .map_err(|source| io_error("lock canonical append", &lock_path, source))?;
        let result = self.append_batch_locked(
            operation_kind,
            item_schema_version,
            context,
            defaults,
            items,
        );
        let unlock = FileExt::unlock(&lock)
            .map_err(|source| io_error("unlock canonical append", &lock_path, source));
        match (result, unlock) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(result), Ok(())) => Ok(result),
        }
    }

    fn append_batch_locked<I>(
        &self,
        operation_kind: &str,
        item_schema_version: u32,
        context: Value,
        defaults: Value,
        mut items: I,
    ) -> Result<V2AppendResult>
    where
        I: Iterator<Item = Result<Value>>,
    {
        let origin_id = self.active_origin_id()?;
        let genesis_path = self.root.join("genesis.json");
        let genesis: SignedGenesis = parse_json(&genesis_path, &read_file(&genesis_path)?)?;
        let verified = if origin_id == genesis.body.initial_client_id {
            match self.verify_append_base() {
                Ok(verified) => verified,
                Err(V2StoreError::Invalid(message))
                    if message.starts_with("local append after a merged frontier") =>
                {
                    self.verify_compact()?
                }
                Err(error) => return Err(error),
            }
        } else {
            self.verify_compact()?
        };
        let tail = verified
            .accepted_frontier
            .origins
            .iter()
            .find(|origin| origin.origin_id == origin_id);
        let signing_key = load_local_signing_key(
            self.root.parent().expect("checked Archive parent"),
            &verified.genesis.body.archive_id,
            &origin_id,
        )?;
        let enrolled = verified.clients.get(&origin_id).ok_or_else(|| {
            V2StoreError::Invalid(format!("active client {origin_id} is not enrolled"))
        })?;
        if enrolled.is_revoked() {
            return Err(V2StoreError::Invalid(format!(
                "active client {origin_id} is revoked"
            )));
        }
        if signing_key.verifying_key().to_bytes() != enrolled.public_key {
            return Err(V2StoreError::Invalid(
                "local signing key does not match the enrolled client".to_owned(),
            ));
        }

        let batch_id = prefixed_ulid("batch_");
        let time_utc_ms = current_time_utc_ms()?;
        let first_seq = tail
            .map(|tail| tail.seq)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
        let mut next_seq = first_seq;
        let mut previous_hash = tail.map(|tail| tail.event_hash.clone());
        let segment_relative = segment_relative_path(&origin_id, first_seq);
        let segment_path = self.root.join(&segment_relative);
        let segment_parent = segment_path.parent().expect("segment has parent");
        fs::create_dir_all(segment_parent).map_err(|source| {
            io_error("create origin segment directory", segment_parent, source)
        })?;
        if segment_path.exists() {
            return Err(V2StoreError::Invalid(format!(
                "immutable segment already exists: {}",
                segment_path.display()
            )));
        }
        let segment_temp = segment_parent.join(format!(".segment-{}.tmp", lower_ulid()));
        let mut segment_temp_guard = RemoveOnDrop::new(segment_temp.clone());
        let mut segment_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&segment_temp)
            .map_err(|source| io_error("create segment temporary file", &segment_temp, source))?;
        let mut segment_hasher = blake3::Hasher::new();
        let mut segment_bytes = 0_u64;
        let mut record_count = 0_u64;
        let start = V2RecordEnvelope {
            v: V2_RECORD_VERSION,
            origin_id: origin_id.clone(),
            origin_seq: next_seq,
            record_id: prefixed_ulid("rec_"),
            record_kind: V2RecordKind::BatchStart,
            time_utc_ms,
            batch_id: batch_id.clone(),
            previous_record_hash: previous_hash.clone(),
            payload: json!({
                "operation_kind": operation_kind,
                "item_schema_version": item_schema_version,
                "causal_frontier_hash": verified.accepted_frontier_hash,
                "context": context,
                "defaults": defaults
            }),
        };
        let start_line = canonical_json(&start)?;
        ensure_record_size(&start_line)?;
        let first_record_hash = blake3_id(&start_line);
        let first_record_id = start.record_id.clone();
        write_streamed_record(
            &mut segment_file,
            &mut segment_hasher,
            &mut segment_bytes,
            &start_line,
            &segment_temp,
        )?;
        record_count += 1;
        previous_hash = Some(first_record_hash.clone());
        next_seq = next_seq
            .checked_add(1)
            .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;

        let mut validator = BatchValidator::new(batch_id.clone(), BatchLimits::default())?;
        let mut item_index = 0_u64;
        let mut pending = VecDeque::new();
        let mut source_exhausted = false;
        loop {
            let mut chunk_items = Vec::new();
            let mut approximate_bytes = 0_usize;
            while chunk_items.len() < BatchLimits::default().max_items as usize {
                let next = if let Some(item) = pending.pop_front() {
                    Some(Ok(item))
                } else if source_exhausted {
                    None
                } else {
                    match items.next() {
                        Some(item) => Some(item),
                        None => {
                            source_exhausted = true;
                            None
                        }
                    }
                };
                let Some(item) = next else { break };
                let item = item?;
                if !item.is_object() {
                    return Err(V2StoreError::Invalid(format!(
                        "batch item {item_index} is not a JSON object"
                    )));
                }
                let item_bytes = canonical_json(&item)?.len().saturating_add(1);
                if !chunk_items.is_empty()
                    && approximate_bytes.saturating_add(item_bytes)
                        > DEFAULT_MAX_V2_RECORD_BYTES.saturating_sub(8 * 1024)
                {
                    pending.push_front(item);
                    break;
                }
                approximate_bytes = approximate_bytes.saturating_add(item_bytes);
                chunk_items.push(item);
            }
            if chunk_items.is_empty() {
                if source_exhausted && pending.is_empty() {
                    break;
                }
                return Err(V2StoreError::Invalid(
                    "batch item packing made no progress".to_owned(),
                ));
            }
            let (chunk, line) = loop {
                let chunk = V2RecordEnvelope {
                    v: V2_RECORD_VERSION,
                    origin_id: origin_id.clone(),
                    origin_seq: next_seq,
                    record_id: prefixed_ulid("rec_"),
                    record_kind: V2RecordKind::BatchChunk,
                    time_utc_ms,
                    batch_id: batch_id.clone(),
                    previous_record_hash: previous_hash.clone(),
                    payload: json!({
                        "first_item_index": item_index,
                        "items": &chunk_items
                    }),
                };
                let line = canonical_json(&chunk)?;
                if line.len() <= DEFAULT_MAX_V2_RECORD_BYTES {
                    break (chunk, line);
                }
                if chunk_items.len() == 1 {
                    return Err(V2StoreError::Invalid(format!(
                        "batch item {item_index} cannot fit in one bounded record"
                    )));
                }
                let item = chunk_items.pop().expect("chunk has multiple items");
                pending.push_front(item);
            };
            let take = u32::try_from(chunk_items.len())
                .map_err(|_| V2StoreError::Invalid("batch chunk count overflow".to_owned()))?;
            let chunk_hash = blake3_id(&line);
            validator.accept_chunk(&BatchChunkDescriptor {
                batch_id: batch_id.clone(),
                first_item_index: item_index,
                item_count: take,
                serialized_bytes: line.len(),
                record_hash: chunk_hash.clone(),
            })?;
            write_streamed_record(
                &mut segment_file,
                &mut segment_hasher,
                &mut segment_bytes,
                &line,
                &segment_temp,
            )?;
            record_count = record_count
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
            previous_hash = Some(chunk_hash);
            let _ = chunk;
            item_index = item_index
                .checked_add(u64::from(take))
                .ok_or_else(|| V2StoreError::Invalid("batch item count overflow".to_owned()))?;
            next_seq = next_seq
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
        }

        if item_index == 0 {
            return Err(V2StoreError::Invalid(
                "a mutation batch must contain one or more object items".to_owned(),
            ));
        }
        let total_items = item_index;
        let complete = V2RecordEnvelope {
            v: V2_RECORD_VERSION,
            origin_id: origin_id.clone(),
            origin_seq: next_seq,
            record_id: prefixed_ulid("rec_"),
            record_kind: V2RecordKind::BatchComplete,
            time_utc_ms,
            batch_id: batch_id.clone(),
            previous_record_hash: previous_hash,
            payload: json!({
                "total_items": total_items,
                "ordered_item_digest": validator.ordered_item_digest()?,
                "status": "complete",
                "errors": [],
                "coverage": null
            }),
        };
        let complete_line = canonical_json(&complete)?;
        ensure_record_size(&complete_line)?;
        let complete_hash = blake3_id(&complete_line);
        let last_record_id = complete.record_id.clone();
        write_streamed_record(
            &mut segment_file,
            &mut segment_hasher,
            &mut segment_bytes,
            &complete_line,
            &segment_temp,
        )?;
        record_count = record_count
            .checked_add(1)
            .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
        segment_file
            .sync_all()
            .map_err(|source| io_error("sync segment temporary file", &segment_temp, source))?;
        drop(segment_file);
        fs::rename(&segment_temp, &segment_path)
            .map_err(|source| io_error("publish immutable segment", &segment_path, source))?;
        segment_temp_guard.disarm();
        File::open(segment_parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error("sync origin segment directory", segment_parent, source))?;
        let segment_blake3 = format!("blake3:{}", segment_hasher.finalize().to_hex());
        let manifest = SignedSegmentManifest::create(
            SegmentManifestBody {
                manifest_v: MANIFEST_VERSION,
                archive_id: verified.genesis.body.archive_id.clone(),
                genesis_hash: verified.genesis_hash.clone(),
                origin_id: origin_id.clone(),
                segment_path: path_text(&segment_relative)?,
                first_seq,
                last_seq: next_seq,
                first_record_id,
                last_record_id,
                first_record_hash,
                last_record_hash: complete_hash.clone(),
                record_count,
                segment_bytes,
                segment_blake3,
                causal_base_frontier_hash: verified.accepted_frontier_hash.clone(),
                previous_segment_manifest_hash: tail.map(|tail| tail.segment_manifest_hash.clone()),
            },
            &signing_key,
        )?;
        let manifest_hash = manifest.manifest_hash()?;
        let manifest_relative = manifest_relative_path(&origin_id, first_seq);
        write_new_synced(
            &self.root.join(&manifest_relative),
            &manifest.canonical_bytes()?,
            None,
        )?;

        let mut origins = verified.accepted_frontier.origins.clone();
        let next_tail = OriginFrontier {
            origin_id: origin_id.clone(),
            seq: next_seq,
            event_hash: complete_hash,
            segment_manifest_hash: manifest_hash.clone(),
        };
        if let Some(local_tail) = origins
            .iter_mut()
            .find(|origin| origin.origin_id == origin_id)
        {
            *local_tail = next_tail;
        } else {
            origins.push(next_tail);
            origins.sort_by(|left, right| left.origin_id.cmp(&right.origin_id));
        }
        let successor = CausalFrontier {
            v: FRONTIER_VERSION,
            archive_id: verified.genesis.body.archive_id.clone(),
            genesis_hash: verified.genesis_hash,
            origins,
            previous_frontiers: vec![verified.accepted_frontier_hash],
            item_projection_version: verified.accepted_frontier.item_projection_version,
        };
        let accepted_frontier_hash = successor.frontier_hash()?;
        write_frontier(&self.root, &successor)?;
        replace_synced(
            &self.root.join("frontiers/v2/HEAD"),
            format!("{accepted_frontier_hash}\n").as_bytes(),
        )?;
        if origin_id == verified.genesis.body.initial_client_id {
            self.verify_append_base()?;
        } else {
            self.verify_compact()?;
        }
        let git_commit = commit_canonical_tree(self.root(), operation_kind)?;

        Ok(V2AppendResult {
            version: 2,
            batch_id,
            origin_id,
            first_seq,
            last_seq: next_seq,
            records_written: record_count,
            items_written: total_items,
            segment_manifest_hash: manifest_hash,
            accepted_frontier_hash,
            git_commit,
        })
    }

    fn verify_append_base(&self) -> Result<VerifiedV2Archive> {
        let genesis_path = self.root.join("genesis.json");
        let genesis_bytes = read_file(&genesis_path)?;
        let genesis: SignedGenesis = parse_json(&genesis_path, &genesis_bytes)?;
        genesis.verify()?;
        if genesis.canonical_bytes()? != genesis_bytes {
            return Err(V2StoreError::Invalid(
                "genesis.json does not use deterministic bytes".to_owned(),
            ));
        }
        let genesis_hash = genesis.genesis_hash()?;
        let head_path = self.root.join("frontiers/v2/HEAD");
        let head = String::from_utf8(read_file(&head_path)?)
            .map_err(|_| V2StoreError::Invalid("frontier HEAD is not UTF-8".to_owned()))?;
        let accepted_frontier_hash = head.trim_end_matches('\n');
        validate_blake3_id("frontier HEAD", accepted_frontier_hash)?;
        if head != format!("{accepted_frontier_hash}\n") {
            return Err(V2StoreError::Invalid(
                "frontier HEAD must contain one hash and a newline".to_owned(),
            ));
        }
        let accepted_frontier = read_frontier(
            &self.root,
            accepted_frontier_hash,
            &genesis.body.archive_id,
            &genesis_hash,
        )?;
        if accepted_frontier.previous_frontiers.len() != 1 {
            return Err(V2StoreError::Invalid(
                "local append after a merged frontier is not implemented yet; synchronize projection first"
                    .to_owned(),
            ));
        }
        let parent_hash = &accepted_frontier.previous_frontiers[0];
        let parent = read_frontier(
            &self.root,
            parent_hash,
            &genesis.body.archive_id,
            &genesis_hash,
        )?;
        accepted_frontier.validate_successor_of(&parent)?;
        let origin_id = &genesis.body.initial_client_id;
        let tail = accepted_frontier
            .origins
            .iter()
            .find(|origin| &origin.origin_id == origin_id)
            .ok_or_else(|| {
                V2StoreError::Invalid("local origin is absent from frontier".to_owned())
            })?;
        let parent_tail = parent
            .origins
            .iter()
            .find(|origin| &origin.origin_id == origin_id);
        let cursor = parent_tail.map_or(
            V2OriginCursor {
                applied_seq: 0,
                applied_record_hash: None,
                applied_segment_manifest_hash: None,
            },
            |origin| V2OriginCursor {
                applied_seq: origin.seq,
                applied_record_hash: Some(origin.event_hash.clone()),
                applied_segment_manifest_hash: Some(origin.segment_manifest_hash.clone()),
            },
        );
        if cursor.applied_seq >= tail.seq {
            return Err(V2StoreError::Invalid(
                "accepted frontier does not advance the local origin".to_owned(),
            ));
        }
        let known_frontiers = BTreeMap::from([
            (parent_hash.clone(), parent),
            (accepted_frontier_hash.to_owned(), accepted_frontier.clone()),
        ]);
        let key = genesis.body.validate()?;
        let initial_client = VerifiedV2Client {
            client_id: genesis.body.initial_client_id.clone(),
            display_name: "Initial client".to_owned(),
            public_key: key.to_bytes(),
            capabilities: vec!["additive_observation".to_owned(), "coordination".to_owned()],
            approved_origin_id: genesis.body.initial_client_id.clone(),
            approved_origin_seq: 2,
            revoked_origin_id: None,
            revoked_origin_seq: None,
        };
        let mut clients =
            BTreeMap::from([(genesis.body.initial_client_id.clone(), initial_client)]);
        let mut records = Vec::new();
        let stats = visit_origin_range::<V2StoreError, _>(
            &self.root,
            &genesis,
            &genesis_hash,
            &key,
            tail,
            cursor,
            &known_frontiers,
            None,
            &mut clients,
            false,
            &mut records,
            &mut |_| Ok(()),
        )?;
        Ok(VerifiedV2Archive {
            clients,
            genesis,
            genesis_hash,
            accepted_frontier,
            accepted_frontier_hash: accepted_frontier_hash.to_owned(),
            records,
            record_count: stats.records,
            frontiers: known_frontiers,
            segment_count: stats.segments,
            frontier_count: 2,
        })
    }
}

pub fn is_v2_event_tree(root: impl AsRef<Path>) -> bool {
    root.as_ref().join("genesis.json").is_file()
}

pub fn initialize_v2_archive(
    archive_root: &Path,
    archive_id: &str,
    archive_name: &str,
    created_time_utc_ms: u64,
) -> Result<V2ArchiveInitialization> {
    if archive_root.exists() {
        return Err(V2StoreError::Invalid(format!(
            "Archive initialization target already exists: {}",
            archive_root.display()
        )));
    }
    fs::create_dir(archive_root)
        .map_err(|source| io_error("create prepared Archive", archive_root, source))?;
    let canonical = archive_root.join("canonical");
    let local_clients = archive_root.join("local/clients");
    fs::create_dir_all(&canonical)
        .map_err(|source| io_error("create canonical tree", &canonical, source))?;
    fs::create_dir_all(&local_clients)
        .map_err(|source| io_error("create local client directory", &local_clients, source))?;
    set_private_directory_permissions(&archive_root.join("local"))?;
    set_private_directory_permissions(&local_clients)?;

    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| {
        V2StoreError::Invalid(format!("operating-system randomness failed: {error}"))
    })?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    let body = GenesisBody::new(
        archive_id,
        archive_name,
        created_time_utc_ms,
        &signing_key.verifying_key(),
    );
    let genesis = SignedGenesis::create(body, &signing_key)?;
    let genesis_hash = genesis.genesis_hash()?;
    write_new_synced(
        &canonical.join("genesis.json"),
        &genesis.canonical_bytes()?,
        None,
    )?;

    let local_key = LocalClientKey {
        v: LOCAL_KEY_VERSION,
        archive_id: archive_id.to_owned(),
        origin_id: genesis.body.initial_client_id.clone(),
        secret_key: STANDARD_NO_PAD.encode(signing_key.to_bytes()),
    };
    let mut key_bytes = canonical_json(&local_key)?;
    key_bytes.push(b'\n');
    write_new_synced(
        &local_clients.join(format!("{}.key", genesis.body.initial_client_id)),
        &key_bytes,
        Some(0o600),
    )?;
    write_new_synced(
        &local_clients.join(ACTIVE_CLIENT_FILE),
        format!("{}\n", genesis.body.initial_client_id).as_bytes(),
        Some(0o600),
    )?;

    let bootstrap = CausalFrontier {
        v: FRONTIER_VERSION,
        archive_id: archive_id.to_owned(),
        genesis_hash: genesis_hash.clone(),
        origins: Vec::new(),
        previous_frontiers: Vec::new(),
        item_projection_version: INITIAL_ITEM_PROJECTION_VERSION,
    };
    let bootstrap_hash = bootstrap.frontier_hash()?;
    write_frontier(&canonical, &bootstrap)?;

    let origin_id = genesis.body.initial_client_id.clone();
    let batch_id = prefixed_ulid("batch_");
    let record_time = created_time_utc_ms;
    let start = V2RecordEnvelope {
        v: V2_RECORD_VERSION,
        origin_id: origin_id.clone(),
        origin_seq: 1,
        record_id: prefixed_ulid("rec_"),
        record_kind: V2RecordKind::BatchStart,
        time_utc_ms: record_time,
        batch_id: batch_id.clone(),
        previous_record_hash: None,
        payload: json!({
            "operation_kind": "archive_init",
            "item_schema_version": 1,
            "causal_frontier_hash": bootstrap_hash,
            "context": {"archive_id": archive_id},
            "defaults": {}
        }),
    };
    let start_line = canonical_json(&start)?;
    let start_hash = blake3_id(&start_line);
    let chunk = V2RecordEnvelope {
        v: V2_RECORD_VERSION,
        origin_id: origin_id.clone(),
        origin_seq: 2,
        record_id: prefixed_ulid("rec_"),
        record_kind: V2RecordKind::BatchChunk,
        time_utc_ms: record_time,
        batch_id: batch_id.clone(),
        previous_record_hash: Some(start_hash),
        payload: json!({
            "first_item_index": 0,
            "items": [{
                "kind": "archive_initialized",
                "archive_id": archive_id,
                "archive_display_name": archive_name,
                "client_id": origin_id,
                "public_key": genesis.body.initial_public_key
            }]
        }),
    };
    let chunk_line = canonical_json(&chunk)?;
    let chunk_hash = blake3_id(&chunk_line);
    let mut batch = BatchValidator::new(batch_id.clone(), BatchLimits::default())?;
    batch.accept_chunk(&BatchChunkDescriptor {
        batch_id: batch_id.clone(),
        first_item_index: 0,
        item_count: 1,
        serialized_bytes: chunk_line.len(),
        record_hash: chunk_hash.clone(),
    })?;
    let ordered_item_digest = batch.ordered_item_digest()?;
    let complete = V2RecordEnvelope {
        v: V2_RECORD_VERSION,
        origin_id: origin_id.clone(),
        origin_seq: 3,
        record_id: prefixed_ulid("rec_"),
        record_kind: V2RecordKind::BatchComplete,
        time_utc_ms: record_time,
        batch_id,
        previous_record_hash: Some(chunk_hash),
        payload: json!({
            "total_items": 1,
            "ordered_item_digest": ordered_item_digest,
            "status": "complete",
            "errors": [],
            "coverage": null
        }),
    };
    let complete_line = canonical_json(&complete)?;
    let complete_hash = blake3_id(&complete_line);
    let lines = [&start_line, &chunk_line, &complete_line];
    let mut segment_bytes = Vec::new();
    for line in lines {
        segment_bytes.extend_from_slice(line);
        segment_bytes.push(b'\n');
    }
    let segment_relative = segment_relative_path(&origin_id, SEGMENT_NUMBER);
    write_new_synced(&canonical.join(&segment_relative), &segment_bytes, None)?;

    let manifest = SignedSegmentManifest::create(
        SegmentManifestBody {
            manifest_v: MANIFEST_VERSION,
            archive_id: archive_id.to_owned(),
            genesis_hash: genesis_hash.clone(),
            origin_id: origin_id.clone(),
            segment_path: path_text(&segment_relative)?,
            first_seq: 1,
            last_seq: 3,
            first_record_id: start.record_id,
            last_record_id: complete.record_id,
            first_record_hash: blake3_id(&start_line),
            last_record_hash: complete_hash.clone(),
            record_count: 3,
            segment_bytes: u64::try_from(segment_bytes.len())
                .map_err(|_| V2StoreError::Invalid("initial segment is too large".to_owned()))?,
            segment_blake3: blake3_id(&segment_bytes),
            causal_base_frontier_hash: bootstrap_hash.clone(),
            previous_segment_manifest_hash: None,
        },
        &signing_key,
    )?;
    let manifest_hash = manifest.manifest_hash()?;
    let manifest_relative = manifest_relative_path(&origin_id, SEGMENT_NUMBER);
    write_new_synced(
        &canonical.join(&manifest_relative),
        &manifest.canonical_bytes()?,
        None,
    )?;

    let accepted = CausalFrontier {
        v: FRONTIER_VERSION,
        archive_id: archive_id.to_owned(),
        genesis_hash: genesis_hash.clone(),
        origins: vec![OriginFrontier {
            origin_id: origin_id.clone(),
            seq: 3,
            event_hash: complete_hash,
            segment_manifest_hash: manifest_hash,
        }],
        previous_frontiers: vec![bootstrap_hash],
        item_projection_version: INITIAL_ITEM_PROJECTION_VERSION,
    };
    let accepted_frontier_hash = accepted.frontier_hash()?;
    write_frontier(&canonical, &accepted)?;
    write_new_synced(
        &canonical.join("frontiers/v2/HEAD"),
        format!("{accepted_frontier_hash}\n").as_bytes(),
        None,
    )?;

    let store = V2OriginStore::open(&canonical)?;
    store.verify_compact()?;
    let git_commit = commit_initial_tree(&canonical)?;
    sync_tree(archive_root)?;
    Ok(V2ArchiveInitialization {
        archive_id: archive_id.to_owned(),
        archive_name: archive_name.to_owned(),
        origin_id,
        genesis_hash,
        accepted_frontier_hash,
        git_commit,
    })
}

fn verify_origin(
    root: &Path,
    genesis: &SignedGenesis,
    genesis_hash: &str,
    key: &VerifyingKey,
    tail: &OriginFrontier,
) -> Result<(Vec<VerifiedV2Record>, usize)> {
    let manifest_dir = root.join("manifests/v2/origins").join(&tail.origin_id);
    let entries = read_sorted_files(&manifest_dir, ".manifest.json")?;
    if entries.is_empty() {
        return Err(V2StoreError::Invalid(format!(
            "origin {} has no signed segments",
            tail.origin_id
        )));
    }
    let mut expected_seq = 1_u64;
    let mut previous_record_hash: Option<String> = None;
    let mut previous_manifest_hash: Option<String> = None;
    let mut accepted_found = false;
    let mut verified_segments = 0_usize;
    let mut output = Vec::new();
    for path in &entries {
        let bytes = read_file(path)?;
        let manifest: SignedSegmentManifest = parse_json(path, &bytes)?;
        if manifest.canonical_bytes()? != bytes {
            return Err(V2StoreError::Invalid(format!(
                "{} does not use deterministic bytes",
                path.display()
            )));
        }
        manifest.verify(key)?;
        let body = &manifest.body;
        if body.archive_id != genesis.body.archive_id
            || body.genesis_hash != genesis_hash
            || body.origin_id != tail.origin_id
            || body.first_seq != expected_seq
            || body.previous_segment_manifest_hash != previous_manifest_hash
        {
            return Err(V2StoreError::Invalid(format!(
                "segment manifest chain is inconsistent at {}",
                path.display()
            )));
        }
        let manifest_hash = manifest.manifest_hash()?;
        let segment_path = root.join(&body.segment_path);
        let segment_bytes = read_file(&segment_path)?;
        if blake3_id(&segment_bytes) != body.segment_blake3
            || u64::try_from(segment_bytes.len()).ok() != Some(body.segment_bytes)
            || !segment_bytes.ends_with(b"\n")
        {
            return Err(V2StoreError::Invalid(format!(
                "segment bytes do not match manifest at {}",
                segment_path.display()
            )));
        }
        let mut segment_records = Vec::new();
        for line in segment_bytes[..segment_bytes.len() - 1].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                return Err(V2StoreError::Invalid(format!(
                    "segment contains an empty line at {}",
                    segment_path.display()
                )));
            }
            let record = parse_v2_record(
                line,
                &tail.origin_id,
                expected_seq,
                previous_record_hash.as_deref(),
                DEFAULT_MAX_V2_RECORD_BYTES,
            )?;
            previous_record_hash = Some(record.record_hash.clone());
            expected_seq = expected_seq
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
            segment_records.push(VerifiedV2Record {
                record,
                exact_line_bytes: line.to_vec(),
                segment_manifest_hash: manifest_hash.clone(),
                causal_frontier_hash: body.causal_base_frontier_hash.clone(),
            });
        }
        let first = segment_records
            .first()
            .ok_or_else(|| V2StoreError::Invalid("signed segment is empty".to_owned()))?;
        let last = segment_records.last().expect("nonempty segment");
        if body.last_seq != last.record.envelope.origin_seq
            || body.first_record_id != first.record.envelope.record_id
            || body.last_record_id != last.record.envelope.record_id
            || body.first_record_hash != first.record.record_hash
            || body.last_record_hash != last.record.record_hash
            || u64::try_from(segment_records.len()).ok() != Some(body.record_count)
        {
            return Err(V2StoreError::Invalid(format!(
                "record range does not match manifest at {}",
                path.display()
            )));
        }
        output.extend(segment_records);
        verified_segments += 1;
        previous_manifest_hash = Some(manifest_hash.clone());
        if manifest_hash == tail.segment_manifest_hash {
            if body.last_seq != tail.seq || body.last_record_hash != tail.event_hash {
                return Err(V2StoreError::Invalid(format!(
                    "accepted frontier tail does not match origin {}",
                    tail.origin_id
                )));
            }
            accepted_found = true;
            break;
        }
    }
    if !accepted_found {
        return Err(V2StoreError::Invalid(format!(
            "accepted segment manifest is missing for origin {}",
            tail.origin_id
        )));
    }
    if output.last().map(|item| item.record.envelope.origin_seq) != Some(tail.seq) {
        return Err(V2StoreError::Invalid(format!(
            "origin {} did not verify through its frontier",
            tail.origin_id
        )));
    }
    Ok((output, verified_segments))
}

fn record_contains_item_kind(record: &VerifiedV2Record, expected: &str) -> bool {
    record.record.envelope.record_kind == V2RecordKind::BatchChunk
        && record
            .record
            .envelope
            .payload
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.get("kind").and_then(Value::as_str) == Some(expected))
            })
}

fn apply_client_registry_items(
    records: &[VerifiedV2Record],
    clients: &mut BTreeMap<String, VerifiedV2Client>,
) -> Result<()> {
    for record in records {
        if record.record.envelope.record_kind != V2RecordKind::BatchChunk {
            continue;
        }
        let Some(items) = record
            .record
            .envelope
            .payload
            .get("items")
            .and_then(Value::as_array)
        else {
            continue;
        };
        for item in items {
            match item.get("kind").and_then(Value::as_str) {
                Some("client_enrolled") => {
                    let object = item.as_object().ok_or_else(|| {
                        V2StoreError::Invalid("client_enrolled item is not an object".to_owned())
                    })?;
                    let client = enrolled_client_from_item(object, record)?;
                    if clients.insert(client.client_id.clone(), client).is_some() {
                        return Err(V2StoreError::Invalid(
                            "a client ID was enrolled more than once".to_owned(),
                        ));
                    }
                }
                Some("client_revoked") => {
                    let client_id =
                        item.get("client_id")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                V2StoreError::Invalid(
                                    "client_revoked item lacks client_id".to_owned(),
                                )
                            })?;
                    validate_origin_id(client_id)?;
                    let client = clients.get_mut(client_id).ok_or_else(|| {
                        V2StoreError::Invalid(format!(
                            "client_revoked names an unenrolled client {client_id}"
                        ))
                    })?;
                    if client.is_revoked() {
                        return Err(V2StoreError::Invalid(format!(
                            "client {client_id} was revoked more than once"
                        )));
                    }
                    client.revoked_origin_id = Some(record.record.envelope.origin_id.clone());
                    client.revoked_origin_seq = Some(record.record.envelope.origin_seq);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn enrolled_client_from_item(
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
) -> Result<VerifiedV2Client> {
    let required_string = |field: &str| {
        item.get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| V2StoreError::Invalid(format!("client_enrolled lacks {field}")))
    };
    let client_id_value = required_string("client_id")?;
    validate_origin_id(client_id_value)?;
    let display_name = required_string("display_name")?;
    if display_name.trim().is_empty() {
        return Err(V2StoreError::Invalid(
            "client_enrolled display name is empty".to_owned(),
        ));
    }
    let public_key = STANDARD_NO_PAD
        .decode(required_string("public_key")?)
        .map_err(|_| V2StoreError::Invalid("client public key is not base64".to_owned()))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| V2StoreError::Invalid("client public key has the wrong length".to_owned()))?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| V2StoreError::Invalid("client public key is invalid".to_owned()))?;
    if client_id_value != client_id(&public_key) {
        return Err(V2StoreError::Invalid(
            "client ID does not match its public key".to_owned(),
        ));
    }
    let capabilities = item
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| V2StoreError::Invalid("client_enrolled lacks capabilities".to_owned()))?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                V2StoreError::Invalid("client capability is not a string".to_owned())
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if capabilities.is_empty() {
        return Err(V2StoreError::Invalid(
            "client_enrolled capabilities are empty".to_owned(),
        ));
    }
    Ok(VerifiedV2Client {
        client_id: client_id_value.to_owned(),
        display_name: display_name.to_owned(),
        public_key,
        capabilities,
        approved_origin_id: record.record.envelope.origin_id.clone(),
        approved_origin_seq: record.record.envelope.origin_seq,
        revoked_origin_id: None,
        revoked_origin_seq: None,
    })
}

fn validate_client_origin_records(
    records: &[VerifiedV2Record],
    client: &VerifiedV2Client,
    frontiers: &BTreeMap<String, CausalFrontier>,
) -> Result<()> {
    if records.is_empty() {
        return Err(V2StoreError::Invalid(format!(
            "accepted client origin {} has no records",
            client.client_id
        )));
    }
    for record in records {
        let base = frontiers.get(&record.causal_frontier_hash).ok_or_else(|| {
            V2StoreError::Invalid(format!(
                "client origin {} depends on an unknown frontier",
                client.client_id
            ))
        })?;
        if !frontier_includes_dot(base, &client.approved_origin_id, client.approved_origin_seq) {
            return Err(V2StoreError::Invalid(format!(
                "client origin {} does not causally follow its enrollment",
                client.client_id
            )));
        }
        if let (Some(origin_id), Some(origin_seq)) = (
            client.revoked_origin_id.as_deref(),
            client.revoked_origin_seq,
        ) {
            if frontier_includes_dot(base, origin_id, origin_seq) {
                return Err(V2StoreError::Invalid(format!(
                    "revoked client {} appended from a post-revocation frontier",
                    client.client_id
                )));
            }
        }
    }
    Ok(())
}

fn frontier_includes_dot(frontier: &CausalFrontier, origin_id: &str, origin_seq: u64) -> bool {
    frontier
        .origins
        .iter()
        .any(|origin| origin.origin_id == origin_id && origin.seq >= origin_seq)
}

fn validate_coordination_contexts(
    records: &[VerifiedV2Record],
    clients: &BTreeMap<String, VerifiedV2Client>,
) -> Result<()> {
    let verified = |signed: &SignedCoordinationLease| -> Result<()> {
        validate_coordination_lease_body(&signed.body)?;
        let client = clients.get(&signed.body.holder_client_id).ok_or_else(|| {
            V2StoreError::Invalid("coordination proof holder is not enrolled".to_owned())
        })?;
        let signature = STANDARD_NO_PAD.decode(&signed.signature).map_err(|_| {
            V2StoreError::Invalid("coordination proof signature is not base64".to_owned())
        })?;
        let signature = Signature::from_slice(&signature).map_err(|_| {
            V2StoreError::Invalid("coordination proof signature has the wrong length".to_owned())
        })?;
        client
            .verifying_key()?
            .verify_strict(&canonical_json(&signed.body)?, &signature)
            .map_err(|_| {
                V2StoreError::Invalid("coordination proof signature is invalid".to_owned())
            })
    };
    for record in records {
        if record.record.envelope.record_kind != V2RecordKind::BatchStart {
            continue;
        }
        let Some(coordination) = record
            .record
            .envelope
            .payload
            .get("context")
            .and_then(Value::as_object)
            .and_then(|context| context.get("coordination"))
        else {
            continue;
        };
        let coordination = coordination.as_object().ok_or_else(|| {
            V2StoreError::Invalid("batch coordination context is not an object".to_owned())
        })?;
        let proof: SignedCoordinationLease =
            serde_json::from_value(coordination.get("lease_proof").cloned().ok_or_else(|| {
                V2StoreError::Invalid("batch coordination context lacks lease proof".to_owned())
            })?)
            .map_err(|error| {
                V2StoreError::Invalid(format!("batch coordination proof is invalid: {error}"))
            })?;
        verified(&proof)?;
        let string = |field: &str| {
            coordination
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    V2StoreError::Invalid(format!("batch coordination context lacks {field}"))
                })
        };
        let number = |field: &str| {
            coordination
                .get(field)
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    V2StoreError::Invalid(format!("batch coordination context lacks {field}"))
                })
        };
        if proof.body.state != "acquired"
            || string("scope_kind")? != proof.body.scope_kind
            || string("scope_id")? != proof.body.scope_id
            || string("token_id")? != proof.body.token_id
            || string("holder_client_id")? != proof.body.holder_client_id
            || string("base_frontier_hash")? != proof.body.base_frontier_hash
            || number("not_before_utc_ms")? != proof.body.not_before_utc_ms
            || number("not_after_utc_ms")? != proof.body.not_after_utc_ms
            || record.record.envelope.origin_id != proof.body.holder_client_id
            || record.causal_frontier_hash != proof.body.base_frontier_hash
            || record.record.envelope.time_utc_ms < proof.body.not_before_utc_ms
            || record.record.envelope.time_utc_ms > proof.body.not_after_utc_ms
        {
            return Err(V2StoreError::Invalid(
                "batch coordination context does not match its signed lease".to_owned(),
            ));
        }
        let lease_commit = string("lease_commit")?;
        if !matches!(lease_commit.len(), 40 | 64)
            || !lease_commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(V2StoreError::Invalid(
                "batch coordination lease commit is invalid".to_owned(),
            ));
        }
        validate_remote_name(string("remote")?)?;
    }
    Ok(())
}

fn verify_batches(records: &[VerifiedV2Record]) -> Result<()> {
    let mut batches: BTreeMap<&str, VerifiedBatchRecords<'_>> = BTreeMap::new();
    for record in records {
        let entry = batches.entry(&record.record.envelope.batch_id).or_default();
        match record.record.envelope.record_kind {
            V2RecordKind::BatchStart if entry.0.replace(record).is_none() => {}
            V2RecordKind::BatchChunk => entry.1.push(record),
            V2RecordKind::BatchComplete if entry.2.replace(record).is_none() => {}
            _ => {
                return Err(V2StoreError::Invalid(format!(
                    "batch {} has duplicate control records",
                    record.record.envelope.batch_id
                )))
            }
        }
    }
    for (batch_id, (start, chunks, complete)) in batches {
        let start =
            start.ok_or_else(|| V2StoreError::Invalid(format!("batch {batch_id} has no start")))?;
        let complete = complete
            .ok_or_else(|| V2StoreError::Invalid(format!("batch {batch_id} has no completion")))?;
        if complete.record.envelope.origin_id != start.record.envelope.origin_id
            || complete.record.envelope.origin_seq <= start.record.envelope.origin_seq
            || chunks.iter().any(|chunk| {
                chunk.record.envelope.origin_id != start.record.envelope.origin_id
                    || chunk.record.envelope.origin_seq <= start.record.envelope.origin_seq
                    || chunk.record.envelope.origin_seq >= complete.record.envelope.origin_seq
            })
        {
            return Err(V2StoreError::Invalid(format!(
                "batch {batch_id} crosses origins or has invalid record ordering"
            )));
        }
        let start_object = start
            .record
            .envelope
            .payload
            .as_object()
            .expect("record parser checked object");
        let causal = string_field(start_object, "causal_frontier_hash")?;
        if causal != start.causal_frontier_hash {
            return Err(V2StoreError::Invalid(format!(
                "batch {batch_id} causal frontier does not match its segment manifest"
            )));
        }
        let mut validator = BatchValidator::new(batch_id, BatchLimits::default())?;
        for chunk in chunks {
            let payload = chunk
                .record
                .envelope
                .payload
                .as_object()
                .expect("record parser checked object");
            let first = u64_field(payload, "first_item_index")?;
            let items = payload
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    V2StoreError::Invalid(format!("batch {batch_id} chunk items are invalid"))
                })?;
            validator.accept_chunk(&BatchChunkDescriptor {
                batch_id: batch_id.to_owned(),
                first_item_index: first,
                item_count: u32::try_from(items.len())
                    .map_err(|_| V2StoreError::Invalid("batch item count overflow".to_owned()))?,
                serialized_bytes: chunk.exact_line_bytes.len(),
                record_hash: chunk.record.record_hash.clone(),
            })?;
        }
        let payload = complete
            .record
            .envelope
            .payload
            .as_object()
            .expect("record parser checked object");
        validator.validate_completion(&BatchCompletion {
            total_items: u64_field(payload, "total_items")?,
            ordered_item_digest: string_field(payload, "ordered_item_digest")?.to_owned(),
        })?;
        if string_field(payload, "status")? != "complete" {
            return Err(V2StoreError::Invalid(format!(
                "batch {batch_id} is not complete"
            )));
        }
    }
    Ok(())
}

fn load_frontier_graph(
    root: &Path,
    frontier_hash: &str,
    archive_id: &str,
    genesis_hash: &str,
    visited: &mut BTreeMap<String, CausalFrontier>,
) -> Result<()> {
    if visited.contains_key(frontier_hash) {
        return Ok(());
    }
    let path = frontier_path(root, frontier_hash)?;
    let bytes = read_file(&path)?;
    let frontier: CausalFrontier = parse_json(&path, &bytes)?;
    if frontier.canonical_bytes()? != bytes || frontier.frontier_hash()? != frontier_hash {
        return Err(V2StoreError::Invalid(format!(
            "frontier bytes or name do not match at {}",
            path.display()
        )));
    }
    if frontier.archive_id != archive_id || frontier.genesis_hash != genesis_hash {
        return Err(V2StoreError::Invalid(format!(
            "frontier belongs to another Archive at {}",
            path.display()
        )));
    }
    let parents = frontier.previous_frontiers.clone();
    for parent_hash in &parents {
        load_frontier_graph(root, parent_hash, archive_id, genesis_hash, visited)?;
        frontier.validate_successor_of(&visited[parent_hash])?;
    }
    if parents.is_empty() && !frontier.origins.is_empty() {
        return Err(V2StoreError::Invalid(
            "the parentless genesis frontier must have no origins".to_owned(),
        ));
    }
    visited.insert(frontier_hash.to_owned(), frontier);
    Ok(())
}

fn read_frontier(
    root: &Path,
    frontier_hash: &str,
    archive_id: &str,
    genesis_hash: &str,
) -> Result<CausalFrontier> {
    let path = frontier_path(root, frontier_hash)?;
    let bytes = read_file(&path)?;
    let frontier: CausalFrontier = parse_json(&path, &bytes)?;
    if frontier.canonical_bytes()? != bytes || frontier.frontier_hash()? != frontier_hash {
        return Err(V2StoreError::Invalid(format!(
            "frontier bytes or name do not match at {}",
            path.display()
        )));
    }
    if frontier.archive_id != archive_id || frontier.genesis_hash != genesis_hash {
        return Err(V2StoreError::Invalid(format!(
            "frontier belongs to another Archive at {}",
            path.display()
        )));
    }
    Ok(frontier)
}

fn load_frontier_path_to_base(
    root: &Path,
    frontier_hash: &str,
    base_frontier_hash: &str,
    archive_id: &str,
    genesis_hash: &str,
    visited: &mut BTreeMap<String, CausalFrontier>,
) -> Result<bool> {
    if visited.contains_key(frontier_hash) {
        return Ok(frontier_hash == base_frontier_hash);
    }
    let path = frontier_path(root, frontier_hash)?;
    let bytes = read_file(&path)?;
    let frontier: CausalFrontier = parse_json(&path, &bytes)?;
    if frontier.canonical_bytes()? != bytes || frontier.frontier_hash()? != frontier_hash {
        return Err(V2StoreError::Invalid(format!(
            "frontier bytes or name do not match at {}",
            path.display()
        )));
    }
    if frontier.archive_id != archive_id || frontier.genesis_hash != genesis_hash {
        return Err(V2StoreError::Invalid(format!(
            "frontier belongs to another Archive at {}",
            path.display()
        )));
    }
    if frontier_hash == base_frontier_hash {
        visited.insert(frontier_hash.to_owned(), frontier);
        return Ok(true);
    }
    let parents = frontier.previous_frontiers.clone();
    let mut found_base = false;
    for parent_hash in &parents {
        found_base |= load_frontier_path_to_base(
            root,
            parent_hash,
            base_frontier_hash,
            archive_id,
            genesis_hash,
            visited,
        )?;
        frontier.validate_successor_of(&visited[parent_hash])?;
    }
    if parents.is_empty() && !frontier.origins.is_empty() {
        return Err(V2StoreError::Invalid(
            "the parentless genesis frontier must have no origins".to_owned(),
        ));
    }
    visited.insert(frontier_hash.to_owned(), frontier);
    Ok(found_base)
}

fn verify_segment_file(path: &Path, expected_bytes: u64, expected_hash: &str) -> Result<()> {
    let file = File::open(path).map_err(|source| io_error("open signed segment", path, source))?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut observed = 0_u64;
    let mut last = None;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| io_error("read signed segment", path, source))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count).expect("buffer length fits u64"))
            .ok_or_else(|| V2StoreError::Invalid("segment byte count overflow".to_owned()))?;
        hasher.update(&buffer[..count]);
        last = Some(buffer[count - 1]);
    }
    let observed_hash = format!("blake3:{}", hasher.finalize().to_hex());
    if observed != expected_bytes || observed_hash != expected_hash || last != Some(b'\n') {
        return Err(V2StoreError::Invalid(format!(
            "segment bytes do not match manifest at {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_record_line(reader: &mut BufReader<File>, path: &Path) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let limit = u64::try_from(DEFAULT_MAX_V2_RECORD_BYTES)
        .expect("record limit fits u64")
        .saturating_add(2);
    let count = reader
        .take(limit)
        .read_until(b'\n', &mut line)
        .map_err(|source| io_error("read signed segment record", path, source))?;
    if count == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err(V2StoreError::Invalid(format!(
            "segment has an unterminated or oversized record at {}",
            path.display()
        )));
    }
    line.pop();
    if line.is_empty() {
        return Err(V2StoreError::Invalid(format!(
            "segment contains an empty line at {}",
            path.display()
        )));
    }
    Ok(Some(line))
}

fn validate_streamed_batch_record(
    record: &VerifiedV2Record,
    active: &mut Option<StreamingBatch>,
) -> Result<()> {
    let batch_id = &record.record.envelope.batch_id;
    match record.record.envelope.record_kind {
        V2RecordKind::BatchStart => {
            if active.is_some() {
                return Err(V2StoreError::Invalid(format!(
                    "batch {batch_id} starts before the preceding batch completed"
                )));
            }
            let payload = record
                .record
                .envelope
                .payload
                .as_object()
                .expect("record parser checked object");
            if string_field(payload, "causal_frontier_hash")? != record.causal_frontier_hash {
                return Err(V2StoreError::Invalid(format!(
                    "batch {batch_id} causal frontier does not match its segment manifest"
                )));
            }
            *active = Some(StreamingBatch {
                batch_id: batch_id.clone(),
                validator: BatchValidator::new(batch_id, BatchLimits::default())?,
            });
        }
        V2RecordKind::BatchChunk => {
            let state = active
                .as_mut()
                .ok_or_else(|| V2StoreError::Invalid(format!("batch {batch_id} has no start")))?;
            if state.batch_id != *batch_id {
                return Err(V2StoreError::Invalid(format!(
                    "batch {batch_id} crosses another batch"
                )));
            }
            let payload = record
                .record
                .envelope
                .payload
                .as_object()
                .expect("record parser checked object");
            let items = payload
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    V2StoreError::Invalid(format!("batch {batch_id} chunk items are invalid"))
                })?;
            state.validator.accept_chunk(&BatchChunkDescriptor {
                batch_id: batch_id.clone(),
                first_item_index: u64_field(payload, "first_item_index")?,
                item_count: u32::try_from(items.len())
                    .map_err(|_| V2StoreError::Invalid("batch item count overflow".to_owned()))?,
                serialized_bytes: record.exact_line_bytes.len(),
                record_hash: record.record.record_hash.clone(),
            })?;
        }
        V2RecordKind::BatchComplete => {
            let state = active
                .take()
                .ok_or_else(|| V2StoreError::Invalid(format!("batch {batch_id} has no start")))?;
            if state.batch_id != *batch_id {
                return Err(V2StoreError::Invalid(format!(
                    "batch {batch_id} crosses another batch"
                )));
            }
            let payload = record
                .record
                .envelope
                .payload
                .as_object()
                .expect("record parser checked object");
            state.validator.validate_completion(&BatchCompletion {
                total_items: u64_field(payload, "total_items")?,
                ordered_item_digest: string_field(payload, "ordered_item_digest")?.to_owned(),
            })?;
            if string_field(payload, "status")? != "complete" {
                return Err(V2StoreError::Invalid(format!(
                    "batch {batch_id} is not complete"
                )));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn visit_origin_range<E, F>(
    root: &Path,
    genesis: &SignedGenesis,
    genesis_hash: &str,
    key: &VerifyingKey,
    tail: &OriginFrontier,
    cursor: V2OriginCursor,
    known_frontiers: &BTreeMap<String, CausalFrontier>,
    client: Option<&VerifiedV2Client>,
    clients: &mut BTreeMap<String, VerifiedV2Client>,
    apply_registry: bool,
    retained_starts: &mut Vec<VerifiedV2Record>,
    visitor: &mut F,
) -> std::result::Result<OriginVisitStats, E>
where
    E: From<V2StoreError>,
    F: FnMut(&VerifiedV2Record) -> std::result::Result<(), E>,
{
    let mut expected_seq = cursor
        .applied_seq
        .checked_add(1)
        .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
    let mut previous_record_hash = cursor.applied_record_hash;
    let mut previous_manifest_hash = cursor.applied_segment_manifest_hash;
    let mut stats = OriginVisitStats::default();
    loop {
        let manifest_path = root.join(manifest_relative_path(&tail.origin_id, expected_seq));
        let bytes = read_file(&manifest_path)?;
        let manifest: SignedSegmentManifest = parse_json(&manifest_path, &bytes)?;
        if manifest.canonical_bytes()? != bytes {
            return Err(V2StoreError::Invalid(format!(
                "{} does not use deterministic bytes",
                manifest_path.display()
            ))
            .into());
        }
        manifest.verify(key)?;
        let body = &manifest.body;
        if body.archive_id != genesis.body.archive_id
            || body.genesis_hash != genesis_hash
            || body.origin_id != tail.origin_id
            || body.first_seq != expected_seq
            || body.previous_segment_manifest_hash != previous_manifest_hash
            || !known_frontiers.contains_key(&body.causal_base_frontier_hash)
        {
            return Err(V2StoreError::Invalid(format!(
                "incremental segment manifest chain is inconsistent at {}",
                manifest_path.display()
            ))
            .into());
        }
        let manifest_hash = manifest.manifest_hash()?;
        let segment_path = root.join(&body.segment_path);
        verify_segment_file(&segment_path, body.segment_bytes, &body.segment_blake3)?;

        let segment_start_seq = expected_seq;
        let segment_start_previous_hash = previous_record_hash.clone();
        let mut reader = BufReader::new(
            File::open(&segment_path)
                .map_err(|source| io_error("open signed segment", &segment_path, source))?,
        );
        let mut active = None;
        let mut segment_records = 0_u64;
        let mut first_id = None;
        let mut first_hash = None;
        let mut last_id = None;
        let mut last_hash = None;
        while let Some(line) = read_record_line(&mut reader, &segment_path)? {
            let parsed = parse_v2_record(
                &line,
                &tail.origin_id,
                expected_seq,
                previous_record_hash.as_deref(),
                DEFAULT_MAX_V2_RECORD_BYTES,
            )
            .map_err(V2StoreError::from)?;
            previous_record_hash = Some(parsed.record_hash.clone());
            expected_seq = expected_seq
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
            let record = VerifiedV2Record {
                record: parsed,
                exact_line_bytes: line,
                segment_manifest_hash: manifest_hash.clone(),
                causal_frontier_hash: body.causal_base_frontier_hash.clone(),
            };
            if let Some(client) = client {
                validate_client_origin_records(
                    std::slice::from_ref(&record),
                    client,
                    known_frontiers,
                )?;
            }
            validate_coordination_contexts(std::slice::from_ref(&record), clients)?;
            validate_streamed_batch_record(&record, &mut active)?;
            if record_contains_item_kind(&record, "archive_initialized") {
                if stats.archive_initialized_at.is_some() {
                    return Err(V2StoreError::Invalid(
                        "archive_initialized appears more than once".to_owned(),
                    )
                    .into());
                }
                stats.archive_initialized_at = Some((
                    record.record.envelope.origin_id.clone(),
                    record.record.envelope.origin_seq,
                ));
            }
            if apply_registry {
                apply_client_registry_items(std::slice::from_ref(&record), clients)?;
            }
            if record.record.envelope.record_kind == V2RecordKind::BatchStart
                || record_contains_item_kind(&record, "archive_initialized")
            {
                retained_starts.push(record.clone());
            }
            first_id.get_or_insert_with(|| record.record.envelope.record_id.clone());
            first_hash.get_or_insert_with(|| record.record.record_hash.clone());
            last_id = Some(record.record.envelope.record_id.clone());
            last_hash = Some(record.record.record_hash.clone());
            segment_records = segment_records
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
        }
        if active.is_some() {
            return Err(V2StoreError::Invalid(format!(
                "signed segment contains an incomplete batch at {}",
                segment_path.display()
            ))
            .into());
        }
        if body.last_seq != expected_seq.saturating_sub(1)
            || first_id.as_deref() != Some(&body.first_record_id)
            || last_id.as_deref() != Some(&body.last_record_id)
            || first_hash.as_deref() != Some(&body.first_record_hash)
            || last_hash.as_deref() != Some(&body.last_record_hash)
            || segment_records != body.record_count
        {
            return Err(V2StoreError::Invalid(format!(
                "record range does not match manifest at {}",
                manifest_path.display()
            ))
            .into());
        }

        // The segment is now completely authenticated and its batch digest is
        // valid. Re-read only this bounded record stream for immediate use.
        let mut replay_seq = segment_start_seq;
        let mut replay_previous_hash = segment_start_previous_hash;
        let mut replay = BufReader::new(
            File::open(&segment_path)
                .map_err(|source| io_error("reopen signed segment", &segment_path, source))?,
        );
        while let Some(line) = read_record_line(&mut replay, &segment_path)? {
            let parsed = parse_v2_record(
                &line,
                &tail.origin_id,
                replay_seq,
                replay_previous_hash.as_deref(),
                DEFAULT_MAX_V2_RECORD_BYTES,
            )
            .map_err(V2StoreError::from)?;
            replay_previous_hash = Some(parsed.record_hash.clone());
            replay_seq = replay_seq
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
            visitor(&VerifiedV2Record {
                record: parsed,
                exact_line_bytes: line,
                segment_manifest_hash: manifest_hash.clone(),
                causal_frontier_hash: body.causal_base_frontier_hash.clone(),
            })?;
        }
        stats.records = stats
            .records
            .checked_add(segment_records)
            .ok_or_else(|| V2StoreError::Invalid("record count overflow".to_owned()))?;
        stats.segments = stats
            .segments
            .checked_add(1)
            .ok_or_else(|| V2StoreError::Invalid("segment count overflow".to_owned()))?;
        previous_manifest_hash = Some(manifest_hash.clone());
        if manifest_hash == tail.segment_manifest_hash {
            if body.last_seq != tail.seq || body.last_record_hash != tail.event_hash {
                return Err(V2StoreError::Invalid(format!(
                    "accepted frontier tail does not match origin {}",
                    tail.origin_id
                ))
                .into());
            }
            break;
        }
        if body.last_seq >= tail.seq {
            return Err(V2StoreError::Invalid(format!(
                "incremental manifest chain passed accepted origin {}",
                tail.origin_id
            ))
            .into());
        }
    }
    Ok(stats)
}

fn verify_origin_range(
    root: &Path,
    genesis: &SignedGenesis,
    genesis_hash: &str,
    key: &VerifyingKey,
    tail: &OriginFrontier,
    cursor: V2OriginCursor,
    known_frontiers: &BTreeMap<String, CausalFrontier>,
) -> Result<(Vec<VerifiedV2Record>, u64)> {
    let mut expected_seq = cursor
        .applied_seq
        .checked_add(1)
        .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
    let mut previous_record_hash = cursor.applied_record_hash;
    let mut previous_manifest_hash = cursor.applied_segment_manifest_hash;
    let mut output = Vec::new();
    let mut segments = 0_u64;
    loop {
        let manifest_path = root.join(manifest_relative_path(&tail.origin_id, expected_seq));
        let bytes = read_file(&manifest_path)?;
        let manifest: SignedSegmentManifest = parse_json(&manifest_path, &bytes)?;
        if manifest.canonical_bytes()? != bytes {
            return Err(V2StoreError::Invalid(format!(
                "{} does not use deterministic bytes",
                manifest_path.display()
            )));
        }
        manifest.verify(key)?;
        let body = &manifest.body;
        if body.archive_id != genesis.body.archive_id
            || body.genesis_hash != genesis_hash
            || body.origin_id != tail.origin_id
            || body.first_seq != expected_seq
            || body.previous_segment_manifest_hash != previous_manifest_hash
            || !known_frontiers.contains_key(&body.causal_base_frontier_hash)
        {
            return Err(V2StoreError::Invalid(format!(
                "incremental segment manifest chain is inconsistent at {}",
                manifest_path.display()
            )));
        }
        let manifest_hash = manifest.manifest_hash()?;
        let segment_path = root.join(&body.segment_path);
        let segment_bytes = read_file(&segment_path)?;
        if blake3_id(&segment_bytes) != body.segment_blake3
            || u64::try_from(segment_bytes.len()).ok() != Some(body.segment_bytes)
            || !segment_bytes.ends_with(b"\n")
        {
            return Err(V2StoreError::Invalid(format!(
                "segment bytes do not match manifest at {}",
                segment_path.display()
            )));
        }
        let range_start = output.len();
        for line in segment_bytes[..segment_bytes.len() - 1].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                return Err(V2StoreError::Invalid(format!(
                    "segment contains an empty line at {}",
                    segment_path.display()
                )));
            }
            let record = parse_v2_record(
                line,
                &tail.origin_id,
                expected_seq,
                previous_record_hash.as_deref(),
                DEFAULT_MAX_V2_RECORD_BYTES,
            )?;
            previous_record_hash = Some(record.record_hash.clone());
            expected_seq = expected_seq
                .checked_add(1)
                .ok_or_else(|| V2StoreError::Invalid("origin sequence overflow".to_owned()))?;
            output.push(VerifiedV2Record {
                record,
                exact_line_bytes: line.to_vec(),
                segment_manifest_hash: manifest_hash.clone(),
                causal_frontier_hash: body.causal_base_frontier_hash.clone(),
            });
        }
        let segment_records = &output[range_start..];
        let first = segment_records
            .first()
            .ok_or_else(|| V2StoreError::Invalid("signed segment is empty".to_owned()))?;
        let last = segment_records.last().expect("nonempty segment");
        if body.last_seq != last.record.envelope.origin_seq
            || body.first_record_id != first.record.envelope.record_id
            || body.last_record_id != last.record.envelope.record_id
            || body.first_record_hash != first.record.record_hash
            || body.last_record_hash != last.record.record_hash
            || u64::try_from(segment_records.len()).ok() != Some(body.record_count)
        {
            return Err(V2StoreError::Invalid(format!(
                "record range does not match manifest at {}",
                manifest_path.display()
            )));
        }
        segments = segments
            .checked_add(1)
            .ok_or_else(|| V2StoreError::Invalid("segment count overflow".to_owned()))?;
        previous_manifest_hash = Some(manifest_hash.clone());
        if manifest_hash == tail.segment_manifest_hash {
            if body.last_seq != tail.seq || body.last_record_hash != tail.event_hash {
                return Err(V2StoreError::Invalid(format!(
                    "accepted frontier tail does not match origin {}",
                    tail.origin_id
                )));
            }
            break;
        }
        if body.last_seq >= tail.seq {
            return Err(V2StoreError::Invalid(format!(
                "incremental manifest chain passed accepted origin {}",
                tail.origin_id
            )));
        }
    }
    Ok((output, segments))
}

fn write_frontier(root: &Path, frontier: &CausalFrontier) -> Result<()> {
    let hash = frontier.frontier_hash()?;
    let path = frontier_path(root, &hash)?;
    write_new_synced(&path, &frontier.canonical_bytes()?, None)
}

fn frontier_path(root: &Path, hash: &str) -> Result<PathBuf> {
    let hex = hash
        .strip_prefix("blake3:")
        .ok_or_else(|| V2StoreError::Invalid("frontier hash has the wrong algorithm".to_owned()))?;
    validate_blake3_id("frontier hash", hash)?;
    Ok(root
        .join("frontiers/v2")
        .join(format!("frontier-{hex}.json")))
}

fn segment_relative_path(origin: &str, number: u64) -> PathBuf {
    PathBuf::from("events/v2/origins")
        .join(origin)
        .join(format!("seg-{number:012}.jsonl"))
}

fn manifest_relative_path(origin: &str, number: u64) -> PathBuf {
    PathBuf::from("manifests/v2/origins")
        .join(origin)
        .join(format!("seg-{number:012}.manifest.json"))
}

fn validate_manifest_body(body: &SegmentManifestBody) -> Result<()> {
    if body.manifest_v != MANIFEST_VERSION
        || body.archive_id.is_empty()
        || body.origin_id.is_empty()
        || body.first_seq == 0
        || body.last_seq < body.first_seq
        || body.record_count != body.last_seq - body.first_seq + 1
        || body.segment_bytes == 0
    {
        return Err(V2StoreError::Invalid(
            "segment manifest has invalid structural fields".to_owned(),
        ));
    }
    for (field, value) in [
        ("genesis_hash", body.genesis_hash.as_str()),
        ("first_record_hash", body.first_record_hash.as_str()),
        ("last_record_hash", body.last_record_hash.as_str()),
        ("segment_blake3", body.segment_blake3.as_str()),
        (
            "causal_base_frontier_hash",
            body.causal_base_frontier_hash.as_str(),
        ),
    ] {
        validate_blake3_id(field, value)?;
    }
    if let Some(previous) = &body.previous_segment_manifest_hash {
        validate_blake3_id("previous_segment_manifest_hash", previous)?;
    }
    Ok(())
}

fn read_sorted_files(directory: &Path, suffix: &str) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(directory)
        .map_err(|source| io_error("read origin manifest directory", directory, source))?
        .map(|entry| {
            entry
                .map(|item| item.path())
                .map_err(|source| io_error("read origin manifest entry", directory, source))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(suffix))
    });
    paths.sort();
    let unique = paths.iter().collect::<BTreeSet<_>>();
    if unique.len() != paths.len() {
        return Err(V2StoreError::Invalid(
            "duplicate origin manifest path".to_owned(),
        ));
    }
    Ok(paths)
}

fn commit_initial_tree(root: &Path) -> Result<String> {
    run_git(root, "initialize repository", &["init", "--quiet"])?;
    run_git(
        root,
        "select canonical branch",
        &["symbolic-ref", "HEAD", CANONICAL_REF],
    )?;
    run_git(
        root,
        "stage initial canonical tree",
        &[
            "add",
            "--",
            "genesis.json",
            "events",
            "manifests",
            "frontiers",
        ],
    )?;
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "Archive Ledger")
        .env("GIT_AUTHOR_EMAIL", "archive-ledger@localhost")
        .env("GIT_COMMITTER_NAME", "Archive Ledger")
        .env("GIT_COMMITTER_EMAIL", "archive-ledger@localhost")
        .args(["commit", "--quiet", "-m", "Initialize Archive Ledger v2"])
        .status()
        .map_err(|source| io_error("run Git initial commit", root, source))?;
    if !output.success() {
        return Err(V2StoreError::Git {
            operation: "commit initial canonical tree",
            path: root.to_path_buf(),
        });
    }
    git_stdout(root, "read initial commit", &["rev-parse", "HEAD"])
}

fn commit_canonical_tree(root: &Path, operation_kind: &str) -> Result<String> {
    run_git(
        root,
        "stage canonical mutation",
        &["add", "--", "events", "manifests", "frontiers"],
    )?;
    let message = format!("Archive Ledger: {operation_kind}");
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "Archive Ledger")
        .env("GIT_AUTHOR_EMAIL", "archive-ledger@localhost")
        .env("GIT_COMMITTER_NAME", "Archive Ledger")
        .env("GIT_COMMITTER_EMAIL", "archive-ledger@localhost")
        .args(["commit", "--quiet", "-m", &message])
        .status()
        .map_err(|source| io_error("run Git canonical commit", root, source))?;
    if !output.success() {
        return Err(V2StoreError::Git {
            operation: "commit canonical mutation",
            path: root.to_path_buf(),
        });
    }
    git_stdout(root, "read canonical commit", &["rev-parse", "HEAD"])
}

fn run_git(root: &Path, operation: &'static str, args: &[&str]) -> Result<()> {
    git_stdout(root, operation, args).map(|_| ())
}

fn git_stdout(root: &Path, operation: &'static str, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .map_err(|source| io_error("run Git", root, source))?;
    if !output.status.success() {
        return Err(V2StoreError::Git {
            operation,
            path: root.to_path_buf(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

struct GitWorktree {
    repository: PathBuf,
    path: PathBuf,
}

impl GitWorktree {
    fn create(repository: &Path, commit: &str) -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("archive-ledger-sync-worktree-{}", lower_ulid()));
        let path_text = path_text(&path)?;
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .env("LC_ALL", "C")
            .args(["worktree", "add", "--quiet", "--detach", &path_text, commit])
            .output()
            .map_err(|source| {
                io_error("create Git synchronization worktree", repository, source)
            })?;
        if !output.status.success() {
            return Err(V2StoreError::Git {
                operation: "create synchronization worktree",
                path: repository.to_path_buf(),
            });
        }
        Ok(Self {
            repository: repository.to_path_buf(),
            path,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for GitWorktree {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .env("LC_ALL", "C")
            .arg("worktree")
            .arg("remove")
            .arg("--force")
            .arg(&self.path)
            .output();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validate_remote_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(V2StoreError::Invalid(format!(
            "invalid synchronization remote name {name:?}"
        )));
    }
    Ok(())
}

fn validate_remote_locator(locator: &str) -> Result<()> {
    if locator.trim() != locator || locator.is_empty() || locator.contains(['\n', '\r', '\0']) {
        return Err(V2StoreError::Invalid(
            "synchronization remote locator is empty or contains control characters".to_owned(),
        ));
    }
    if let Some((_, remainder)) = locator.split_once("://") {
        let authority = remainder.split('/').next().unwrap_or(remainder);
        if authority
            .split_once('@')
            .is_some_and(|(userinfo, _)| userinfo.contains(':'))
        {
            return Err(V2StoreError::Invalid(
                "remote locators must not embed passwords or tokens; use Git credential configuration"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn ensure_git_clean(root: &Path) -> Result<()> {
    let status = git_stdout(
        root,
        "inspect canonical synchronization worktree",
        &["status", "--porcelain", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(V2StoreError::Invalid(
            "canonical Git worktree has uncommitted or untracked files; refusing synchronization"
                .to_owned(),
        ));
    }
    Ok(())
}

fn remote_archive_commit(root: &Path, remote: &str) -> Result<Option<String>> {
    remote_ref_commit(root, remote, CANONICAL_REF)
}

fn remote_ref_commit(root: &Path, remote: &str, remote_ref: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .args(["ls-remote", remote, remote_ref])
        .output()
        .map_err(|source| io_error("query synchronization remote", root, source))?;
    if !output.status.success() {
        return Err(V2StoreError::Git {
            operation: "query synchronization remote",
            path: root.to_path_buf(),
        });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        return Err(V2StoreError::Invalid(
            "synchronization remote returned duplicate canonical refs".to_owned(),
        ));
    }
    let (commit, reference) = line.split_once(char::is_whitespace).ok_or_else(|| {
        V2StoreError::Invalid("synchronization remote returned an invalid ref".to_owned())
    })?;
    if reference.trim() != remote_ref
        || !matches!(commit.len(), 40 | 64)
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(V2StoreError::Invalid(
            "synchronization remote returned an invalid canonical commit".to_owned(),
        ));
    }
    Ok(Some(commit.to_ascii_lowercase()))
}

fn fetch_archive_ref(root: &Path, remote: &str, local_ref: &str) -> Result<()> {
    fetch_ref(root, remote, CANONICAL_REF, local_ref.to_owned())
}

fn fetch_ref(root: &Path, remote: &str, remote_ref: &str, local_ref: String) -> Result<()> {
    let refspec = format!("+{remote_ref}:{local_ref}");
    git_command(
        root,
        "fetch synchronization remote",
        [
            OsString::from("fetch"),
            OsString::from("--quiet"),
            OsString::from("--no-tags"),
            OsString::from(remote),
            OsString::from(refspec),
        ],
    )
    .map(|_| ())
}

fn push_new_archive_ref(root: &Path, remote: &str, commit: &str) -> Result<bool> {
    let refspec = format!("{commit}:{CANONICAL_REF}");
    git_command_status(
        root,
        [
            OsString::from("push"),
            OsString::from("--quiet"),
            OsString::from(remote),
            OsString::from(refspec),
        ],
    )
}

fn push_archive_ref_cas(root: &Path, remote: &str, commit: &str, expected: &str) -> Result<bool> {
    let lease = format!("--force-with-lease={CANONICAL_REF}:{expected}");
    let refspec = format!("{commit}:{CANONICAL_REF}");
    git_command_status(
        root,
        [
            OsString::from("push"),
            OsString::from("--quiet"),
            OsString::from(lease),
            OsString::from(remote),
            OsString::from(refspec),
        ],
    )
}

fn push_ref_cas(
    root: &Path,
    remote: &str,
    commit: &str,
    remote_ref: &str,
    expected: Option<&str>,
) -> Result<bool> {
    let lease = format!(
        "--force-with-lease={remote_ref}:{}",
        expected.unwrap_or_default()
    );
    let refspec = format!("{commit}:{remote_ref}");
    git_command_status(
        root,
        [
            OsString::from("push"),
            OsString::from("--quiet"),
            OsString::from(lease),
            OsString::from(remote),
            OsString::from(refspec),
        ],
    )
}

fn coordination_lease_ref(scope_id: &str) -> String {
    format!(
        "refs/archive-ledger/leases/{}",
        blake3::hash(scope_id.as_bytes()).to_hex()
    )
}

fn coordination_local_ref(scope_id: &str) -> String {
    format!(
        "refs/archive-ledger/fetched-leases/{}",
        blake3::hash(scope_id.as_bytes()).to_hex()
    )
}

fn lease_context(lease: &V2CoordinationLease) -> Value {
    json!({
        "scope_kind": lease.scope_kind,
        "scope_id": lease.scope_id,
        "token_id": lease.token_id,
        "holder_client_id": lease.holder_client_id,
        "base_frontier_hash": lease.base_frontier_hash,
        "not_before_utc_ms": lease.not_before_utc_ms,
        "not_after_utc_ms": lease.not_after_utc_ms,
        "lease_commit": lease.lease_commit,
        "remote": lease.remote,
        "lease_proof": lease.lease_proof,
    })
}

fn sign_coordination_lease(
    body: CoordinationLeaseBody,
    signing_key: &SigningKey,
) -> Result<SignedCoordinationLease> {
    validate_coordination_lease_body(&body)?;
    let signature = signing_key.sign(&canonical_json(&body)?);
    Ok(SignedCoordinationLease {
        body,
        signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
    })
}

fn validate_coordination_lease_body(body: &CoordinationLeaseBody) -> Result<()> {
    if body.lease_v != COORDINATION_LEASE_VERSION
        || body.archive_id.is_empty()
        || body.scope_kind != "archive"
        || body.scope_id != body.archive_id
        || !body.token_id.starts_with("lease_")
        || body.not_before_utc_ms > body.not_after_utc_ms
        || !matches!(
            body.state.as_str(),
            "acquired" | "renewed" | "released" | "broken"
        )
    {
        return Err(V2StoreError::Invalid(
            "coordination lease has invalid structural fields".to_owned(),
        ));
    }
    validate_origin_id(&body.holder_client_id)?;
    validate_blake3_id("coordination genesis hash", &body.genesis_hash)?;
    validate_blake3_id("coordination base frontier hash", &body.base_frontier_hash)?;
    Ok(())
}

fn verify_signed_coordination_lease(
    signed: &SignedCoordinationLease,
    verified: &VerifiedV2Archive,
) -> Result<()> {
    validate_coordination_lease_body(&signed.body)?;
    if signed.body.archive_id != verified.genesis.body.archive_id
        || signed.body.genesis_hash != verified.genesis_hash
    {
        return Err(V2StoreError::Invalid(
            "coordination lease belongs to another Archive".to_owned(),
        ));
    }
    let client = verified
        .clients
        .get(&signed.body.holder_client_id)
        .ok_or_else(|| V2StoreError::Invalid("lease holder is not enrolled".to_owned()))?;
    let signature = STANDARD_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| V2StoreError::Invalid("lease signature is not base64".to_owned()))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| V2StoreError::Invalid("lease signature has the wrong length".to_owned()))?;
    client
        .verifying_key()?
        .verify_strict(&canonical_json(&signed.body)?, &signature)
        .map_err(|_| V2StoreError::Invalid("coordination lease signature is invalid".to_owned()))
}

fn read_signed_lease_commit(
    root: &Path,
    commit: &str,
    verified: &VerifiedV2Archive,
    scope_kind: &str,
    scope_id: &str,
) -> Result<SignedCoordinationLease> {
    let raw = git_stdout_preserve(
        root,
        "read coordination lease commit",
        &["cat-file", "commit", commit],
    )?;
    let (headers, message) = raw.split_once("\n\n").ok_or_else(|| {
        V2StoreError::Invalid("coordination lease commit has no message".to_owned())
    })?;
    let message = message.strip_suffix('\n').unwrap_or(message);
    if message.contains('\n') {
        return Err(V2StoreError::Invalid(
            "coordination lease commit message is not one JSON line".to_owned(),
        ));
    }
    let signed: SignedCoordinationLease =
        serde_json::from_str(message).map_err(|source| V2StoreError::Json {
            path: PathBuf::from(format!("git:{commit}")),
            source,
        })?;
    verify_signed_coordination_lease(&signed, verified)?;
    if signed.body.scope_kind != scope_kind || signed.body.scope_id != scope_id {
        return Err(V2StoreError::Invalid(
            "coordination lease commit uses the wrong scope".to_owned(),
        ));
    }
    let parents = headers
        .lines()
        .filter_map(|line| line.strip_prefix("parent "))
        .collect::<Vec<_>>();
    match signed.body.previous_lease_commit.as_deref() {
        None if parents.is_empty() => {}
        Some(parent) if parents == [parent] => {}
        _ => {
            return Err(V2StoreError::Invalid(
                "coordination lease Git ancestry does not match its signed chain".to_owned(),
            ))
        }
    }
    Ok(signed)
}

fn create_coordination_commit(
    root: &Path,
    parent: Option<&str>,
    signed: &SignedCoordinationLease,
) -> Result<String> {
    let tree = git_stdout(
        root,
        "read coordination commit tree",
        &["rev-parse", "HEAD^{tree}"],
    )?;
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "Archive Ledger")
        .env("GIT_AUTHOR_EMAIL", "archive-ledger@localhost")
        .env("GIT_COMMITTER_NAME", "Archive Ledger")
        .env("GIT_COMMITTER_EMAIL", "archive-ledger@localhost")
        .args(["commit-tree", &tree]);
    if let Some(parent) = parent {
        command.args(["-p", parent]);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| io_error("create coordination lease commit", root, source))?;
    let mut bytes = canonical_json(signed)?;
    bytes.push(b'\n');
    child
        .stdin
        .as_mut()
        .expect("piped Git stdin")
        .write_all(&bytes)
        .map_err(|source| io_error("write coordination lease commit", root, source))?;
    let output = child
        .wait_with_output()
        .map_err(|source| io_error("finish coordination lease commit", root, source))?;
    if !output.status.success() {
        return Err(V2StoreError::Git {
            operation: "create coordination lease commit",
            path: root.to_path_buf(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_stdout_preserve(root: &Path, operation: &'static str, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .map_err(|source| io_error("run Git", root, source))?;
    if !output.status.success() {
        return Err(V2StoreError::Git {
            operation,
            path: root.to_path_buf(),
        });
    }
    String::from_utf8(output.stdout)
        .map_err(|_| V2StoreError::Invalid("Git coordination output is not UTF-8".to_owned()))
}

fn git_command_status<I>(root: &Path, args: I) -> Result<bool>
where
    I: IntoIterator<Item = OsString>,
{
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .args(args)
        .status()
        .map_err(|source| io_error("run Git synchronization command", root, source))?;
    Ok(status.success())
}

fn git_command<I>(root: &Path, operation: &'static str, args: I) -> Result<String>
where
    I: IntoIterator<Item = OsString>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .map_err(|source| io_error("run Git synchronization command", root, source))?;
    if !output.status.success() {
        return Err(V2StoreError::Git {
            operation,
            path: root.to_path_buf(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_is_ancestor(root: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .env("LC_ALL", "C")
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()
        .map_err(|source| io_error("compare synchronization commits", root, source))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(V2StoreError::Git {
            operation: "compare synchronization commits",
            path: root.to_path_buf(),
        }),
    }
}

fn validate_same_archive(left: &VerifiedV2Archive, right: &VerifiedV2Archive) -> Result<()> {
    if left.genesis_hash != right.genesis_hash
        || left.genesis.body.archive_id != right.genesis.body.archive_id
        || left.genesis.canonical_bytes()? != right.genesis.canonical_bytes()?
    {
        return Err(V2StoreError::Invalid(
            "synchronization remote belongs to another Archive".to_owned(),
        ));
    }
    if left.accepted_frontier.item_projection_version
        != right.accepted_frontier.item_projection_version
    {
        return Err(V2StoreError::Invalid(
            "synchronization peers use different item projection versions".to_owned(),
        ));
    }
    Ok(())
}

fn operation_requires_coordination(operation_kind: &str) -> bool {
    operation_kind == "archive_update"
        || operation_kind == "client_revoke"
        || operation_kind == "location_scan"
        || operation_kind.starts_with("site_")
        || operation_kind.starts_with("policy_")
        || operation_kind.starts_with("collection_")
        || (operation_kind.starts_with("device_")
            && !matches!(
                operation_kind,
                "device_checked_in" | "device_mount_observed"
            ))
        || operation_kind.starts_with("archive_root_")
        || operation_kind.starts_with("location_")
        || operation_kind.starts_with("risk_domain_")
        || matches!(operation_kind, "risk_assigned" | "risk_unassigned")
}

fn validate_protected_publication(
    root: &Path,
    remote: &str,
    local: &VerifiedV2Archive,
    remote_verified: &VerifiedV2Archive,
) -> Result<()> {
    if remote_verified.clients.len() <= 1 {
        return Ok(());
    }
    let remote_sequences = remote_verified
        .accepted_frontier
        .origins
        .iter()
        .map(|origin| (origin.origin_id.as_str(), origin.seq))
        .collect::<BTreeMap<_, _>>();
    let now = current_time_utc_ms()?;
    let lease_ref = coordination_lease_ref(&local.genesis.body.archive_id);
    let current_lease_commit = remote_ref_commit(root, remote, &lease_ref)?;
    for record in &local.records {
        if record.record.envelope.record_kind != V2RecordKind::BatchStart
            || record.record.envelope.origin_seq
                <= remote_sequences
                    .get(record.record.envelope.origin_id.as_str())
                    .copied()
                    .unwrap_or(0)
        {
            continue;
        }
        let payload = record
            .record
            .envelope
            .payload
            .as_object()
            .expect("record parser checked payload object");
        let operation_kind = string_field(payload, "operation_kind")?;
        let requires = operation_requires_coordination(operation_kind)
            || (operation_kind == "client_enroll" && remote_verified.clients.len() > 1);
        if !requires {
            continue;
        }
        let coordination = payload
            .get("context")
            .and_then(Value::as_object)
            .and_then(|context| context.get("coordination"))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                V2StoreError::Invalid(format!(
                    "protected operation {operation_kind} lacks a coordination lease"
                ))
            })?;
        let lease_commit = coordination
            .get("lease_commit")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                V2StoreError::Invalid("protected operation lacks lease commit".to_owned())
            })?;
        let not_before = coordination
            .get("not_before_utc_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                V2StoreError::Invalid("protected operation lacks lease start".to_owned())
            })?;
        let not_after = coordination
            .get("not_after_utc_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                V2StoreError::Invalid("protected operation lacks lease expiry".to_owned())
            })?;
        if current_lease_commit.as_deref() != Some(lease_commit)
            || now < not_before
            || now > not_after
        {
            return Err(V2StoreError::Invalid(format!(
                "protected operation {operation_kind} cannot publish because its coordination lease is not current"
            )));
        }
    }
    Ok(())
}

fn union_frontier(left: &VerifiedV2Archive, right: &VerifiedV2Archive) -> Result<CausalFrontier> {
    validate_same_archive(left, right)?;
    let mut origins = BTreeMap::<String, OriginFrontier>::new();
    for origin in left
        .accepted_frontier
        .origins
        .iter()
        .chain(right.accepted_frontier.origins.iter())
    {
        match origins.get(&origin.origin_id) {
            None => {
                origins.insert(origin.origin_id.clone(), origin.clone());
            }
            Some(existing) if origin.seq > existing.seq => {
                origins.insert(origin.origin_id.clone(), origin.clone());
            }
            Some(existing) if origin.seq == existing.seq => {
                if origin != existing {
                    return Err(V2StoreError::Invalid(format!(
                        "origin {} has different immutable tails at sequence {}",
                        origin.origin_id, origin.seq
                    )));
                }
            }
            Some(_) => {}
        }
    }
    let mut previous_frontiers = vec![
        left.accepted_frontier_hash.clone(),
        right.accepted_frontier_hash.clone(),
    ];
    previous_frontiers.sort();
    previous_frontiers.dedup();
    Ok(CausalFrontier {
        v: FRONTIER_VERSION,
        archive_id: left.genesis.body.archive_id.clone(),
        genesis_hash: left.genesis_hash.clone(),
        origins: origins.into_values().collect(),
        previous_frontiers,
        item_projection_version: left.accepted_frontier.item_projection_version,
    })
}

fn merge_immutable_tree(source: &Path, target: &Path) -> Result<()> {
    merge_immutable_directory(source, target, Path::new(""))
}

fn merge_immutable_directory(source: &Path, target: &Path, relative: &Path) -> Result<()> {
    let source_directory = source.join(relative);
    for entry in fs::read_dir(&source_directory)
        .map_err(|source| io_error("read synchronization tree", &source_directory, source))?
    {
        let entry = entry.map_err(|source| {
            io_error("read synchronization tree entry", &source_directory, source)
        })?;
        let name = entry.file_name();
        if relative.as_os_str().is_empty() && name == ".git" {
            continue;
        }
        let child_relative = relative.join(&name);
        if child_relative == Path::new("frontiers/v2/HEAD") {
            continue;
        }
        let source_path = entry.path();
        let target_path = target.join(&child_relative);
        let file_type = entry.file_type().map_err(|source| {
            io_error("inspect synchronization tree entry", &source_path, source)
        })?;
        if file_type.is_symlink() {
            return Err(V2StoreError::Invalid(format!(
                "canonical synchronization tree contains a symlink at {}",
                child_relative.display()
            )));
        }
        if file_type.is_dir() {
            if target_path.exists() && !target_path.is_dir() {
                return Err(V2StoreError::Invalid(format!(
                    "canonical synchronization path type conflicts at {}",
                    child_relative.display()
                )));
            }
            fs::create_dir_all(&target_path).map_err(|source| {
                io_error(
                    "create synchronization union directory",
                    &target_path,
                    source,
                )
            })?;
            merge_immutable_directory(source, target, &child_relative)?;
        } else if file_type.is_file() {
            if target_path.exists() {
                if !target_path.is_file() || read_file(&source_path)? != read_file(&target_path)? {
                    return Err(V2StoreError::Invalid(format!(
                        "immutable canonical path differs between peers: {}",
                        child_relative.display()
                    )));
                }
            } else {
                let parent = target_path.parent().expect("tree entry has parent");
                fs::create_dir_all(parent).map_err(|source| {
                    io_error("create synchronization union parent", parent, source)
                })?;
                fs::copy(&source_path, &target_path).map_err(|source| {
                    io_error("copy immutable synchronization file", &target_path, source)
                })?;
            }
        } else {
            return Err(V2StoreError::Invalid(format!(
                "canonical synchronization tree contains a special file at {}",
                child_relative.display()
            )));
        }
    }
    Ok(())
}

fn write_frontier_idempotent(root: &Path, frontier: &CausalFrontier) -> Result<()> {
    let hash = frontier.frontier_hash()?;
    let path = frontier_path(root, &hash)?;
    let bytes = frontier.canonical_bytes()?;
    if path.exists() {
        if read_file(&path)? != bytes {
            return Err(V2StoreError::Invalid(
                "frontier hash path contains different bytes".to_owned(),
            ));
        }
        return Ok(());
    }
    write_new_synced(&path, &bytes, None)
}

fn create_union_commit(
    worktree: &Path,
    local_parent: &str,
    remote_parent: &str,
    frontier_hash: &str,
) -> Result<String> {
    run_git(worktree, "stage synchronization union", &["add", "-A"])?;
    let tree = git_stdout(
        worktree,
        "write synchronization union tree",
        &["write-tree"],
    )?;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "Archive Ledger")
        .env("GIT_AUTHOR_EMAIL", "archive-ledger@localhost")
        .env("GIT_COMMITTER_NAME", "Archive Ledger")
        .env("GIT_COMMITTER_EMAIL", "archive-ledger@localhost")
        .args([
            "commit-tree",
            &tree,
            "-p",
            local_parent,
            "-p",
            remote_parent,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| io_error("create synchronization union commit", worktree, source))?;
    child
        .stdin
        .as_mut()
        .expect("piped Git stdin")
        .write_all(format!("Archive Ledger: synchronize {frontier_hash}\n").as_bytes())
        .map_err(|source| io_error("write synchronization commit message", worktree, source))?;
    let output = child
        .wait_with_output()
        .map_err(|source| io_error("finish synchronization union commit", worktree, source))?;
    if !output.status.success() {
        return Err(V2StoreError::Git {
            operation: "create synchronization union commit",
            path: worktree.to_path_buf(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[allow(clippy::too_many_arguments)]
fn sync_result(
    remote: &str,
    local_commit_before: String,
    remote_commit_before: Option<String>,
    accepted_commit: String,
    verified: &VerifiedV2Archive,
    fetched: bool,
    pushed: bool,
    merged: bool,
) -> Result<V2SyncResult> {
    Ok(V2SyncResult {
        version: 2,
        remote: remote.to_owned(),
        local_commit_before,
        remote_commit_before,
        accepted_commit,
        accepted_frontier_hash: verified.accepted_frontier_hash.clone(),
        origins: u64::try_from(verified.accepted_frontier.origins.len())
            .map_err(|_| V2StoreError::Invalid("origin count overflow".to_owned()))?,
        records: verified.record_count,
        fetched,
        pushed,
        merged,
    })
}

fn write_new_synced(path: &Path, bytes: &[u8], unix_mode: Option<u32>) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| V2StoreError::Invalid(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(parent)
        .map_err(|source| io_error("create parent directory", parent, source))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = unix_mode;
    let mut file = options
        .open(path)
        .map_err(|source| io_error("create immutable file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write immutable file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync immutable file", path, source))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync parent directory", parent, source))
}

fn write_streamed_record(
    file: &mut File,
    hasher: &mut blake3::Hasher,
    byte_count: &mut u64,
    line: &[u8],
    path: &Path,
) -> Result<()> {
    ensure_record_size(line)?;
    file.write_all(line)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| io_error("write segment record", path, source))?;
    hasher.update(line);
    hasher.update(b"\n");
    let written = u64::try_from(line.len().saturating_add(1))
        .map_err(|_| V2StoreError::Invalid("segment byte count overflow".to_owned()))?;
    *byte_count = byte_count
        .checked_add(written)
        .ok_or_else(|| V2StoreError::Invalid("segment byte count overflow".to_owned()))?;
    Ok(())
}

fn replace_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| V2StoreError::Invalid(format!("{} has no parent", path.display())))?;
    let temp = parent.join(format!(".head-{}.tmp", lower_ulid()));
    write_new_synced(&temp, bytes, None)?;
    fs::rename(&temp, path)
        .map_err(|source| io_error("replace accepted frontier HEAD", path, source))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync frontier directory", parent, source))
}

fn load_local_signing_key(
    archive_root: &Path,
    archive_id: &str,
    origin_id: &str,
) -> Result<SigningKey> {
    let path = archive_root
        .join("local/clients")
        .join(format!("{origin_id}.key"));
    let bytes = read_file(&path)?;
    let local: LocalClientKey = parse_json(&path, &bytes)?;
    if local.v != LOCAL_KEY_VERSION
        || local.archive_id != archive_id
        || local.origin_id != origin_id
    {
        return Err(V2StoreError::Invalid(
            "local signing key belongs to another Archive or origin".to_owned(),
        ));
    }
    let decoded = STANDARD_NO_PAD
        .decode(local.secret_key)
        .map_err(|_| V2StoreError::Invalid("local secret key is not base64".to_owned()))?;
    let secret: [u8; 32] = decoded
        .try_into()
        .map_err(|_| V2StoreError::Invalid("local secret key has the wrong length".to_owned()))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn ensure_record_size(line: &[u8]) -> Result<()> {
    if line.len() > DEFAULT_MAX_V2_RECORD_BYTES {
        Err(V2StoreError::Invalid(format!(
            "record contains {} bytes; maximum is {DEFAULT_MAX_V2_RECORD_BYTES}",
            line.len()
        )))
    } else {
        Ok(())
    }
}

fn current_time_utc_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            V2StoreError::Invalid(format!("system clock is before Unix epoch: {error}"))
        })?;
    u64::try_from(duration.as_millis())
        .map_err(|_| V2StoreError::Invalid("current time is outside supported range".to_owned()))
}

fn sync_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect prepared Archive", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(V2StoreError::Invalid(format!(
            "prepared Archive unexpectedly contains a symlink at {}",
            path.display()
        )));
    }
    if metadata.is_dir() {
        for entry in
            fs::read_dir(path).map_err(|source| io_error("read prepared Archive", path, source))?
        {
            let entry =
                entry.map_err(|source| io_error("read prepared Archive entry", path, source))?;
            sync_tree(&entry.path())?;
        }
    }
    File::open(path)
        .and_then(|entry| entry.sync_all())
        .map_err(|source| io_error("sync prepared Archive", path, source))
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("secure local key directory", path, source))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| io_error("read canonical file", path, source))
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &Path, bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|source| V2StoreError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| {
        V2StoreError::Invalid(format!("deterministic JSON serialization failed: {error}"))
    })
}

fn validate_snapshot_body(body: &PortableSnapshotManifestBody) -> Result<()> {
    if body.snapshot_v != PORTABLE_SNAPSHOT_VERSION {
        return Err(V2StoreError::Invalid(format!(
            "unsupported portable snapshot version {}; expected {PORTABLE_SNAPSHOT_VERSION}",
            body.snapshot_v
        )));
    }
    if body.archive_id.is_empty()
        || body.canonical_git_commit.len() != 40
        || !body
            .canonical_git_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || body.schema_version == 0
        || body.projector_version == 0
        || body.database_bytes == 0
        || body.created_time_utc_ms == 0
    {
        return Err(V2StoreError::Invalid(
            "portable snapshot manifest is incomplete".to_owned(),
        ));
    }
    validate_origin_id(&body.signer_client_id)?;
    validate_blake3_id("snapshot genesis hash", &body.genesis_hash)?;
    validate_blake3_id(
        "snapshot accepted frontier hash",
        &body.accepted_frontier_hash,
    )?;
    validate_blake3_id(
        "snapshot applied frontier hash",
        &body.applied_frontier_hash,
    )?;
    validate_blake3_id("snapshot database hash", &body.database_blake3)
}

fn validate_blake3_id(field: &str, value: &str) -> Result<()> {
    if value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        Ok(())
    } else {
        Err(V2StoreError::Invalid(format!(
            "{field} is not a lowercase BLAKE3 identifier"
        )))
    }
}

fn validate_origin_id(value: &str) -> Result<()> {
    if value.strip_prefix("origin_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        Ok(())
    } else {
        Err(V2StoreError::Invalid(
            "client origin ID is not lowercase origin_<blake3-hex>".to_owned(),
        ))
    }
}

fn blake3_id(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str> {
    object.get(field).and_then(Value::as_str).ok_or_else(|| {
        V2StoreError::Invalid(format!("batch payload field {field} is missing or invalid"))
    })
}

fn u64_field(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64> {
    object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        V2StoreError::Invalid(format!("batch payload field {field} is missing or invalid"))
    })
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| V2StoreError::Invalid("canonical path is not UTF-8".to_owned()))
}

fn prefixed_ulid(prefix: &str) -> String {
    format!("{prefix}{}", Ulid::new().to_string().to_ascii_lowercase())
}

fn lower_ulid() -> String {
    Ulid::new().to_string().to_ascii_lowercase()
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> V2StoreError {
    V2StoreError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&source_path, &target_path);
            } else {
                fs::copy(source_path, target_path).unwrap();
            }
        }
    }

    fn git_command_success(directory: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn initializes_and_verifies_signed_origin_tree() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("archive");
        let initialized =
            initialize_v2_archive(&root, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(root.join("canonical")).unwrap();
        let report = store.verification_report().unwrap();
        assert_eq!(report.records, 3);
        assert_eq!(report.segments, 1);
        assert_eq!(report.frontiers, 2);
        assert_eq!(
            report.accepted_frontier_hash,
            initialized.accepted_frontier_hash
        );
        let key = root
            .join("local/clients")
            .join(format!("{}.key", initialized.origin_id));
        assert!(key.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn detects_canonical_record_corruption() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("archive");
        let initialized =
            initialize_v2_archive(&root, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let segment = root
            .join("canonical")
            .join(segment_relative_path(&initialized.origin_id, 1));
        let mut bytes = fs::read(&segment).unwrap();
        bytes[10] ^= 1;
        fs::write(segment, bytes).unwrap();
        let store = V2OriginStore::open(root.join("canonical")).unwrap();
        assert!(store.verify().is_err());
        assert!(store.verify_compact().is_err());
    }

    #[test]
    fn appends_large_logical_mutation_as_one_bounded_sealed_batch() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("archive");
        initialize_v2_archive(&root, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(root.join("canonical")).unwrap();
        let items = (0..2_501)
            .map(|index| json!({"kind": "test_fact", "index": index}))
            .collect();
        let appended = store
            .append_batch("test_mutation", 1, json!({}), json!({}), items)
            .unwrap();

        assert_eq!(appended.items_written, 2_501);
        assert_eq!(appended.records_written, 5);
        assert_eq!(appended.first_seq, 4);
        assert_eq!(appended.last_seq, 8);
        let verified = store.verify().unwrap();
        assert_eq!(verified.records.len(), 8);
        assert_eq!(verified.segment_count, 2);
        assert_eq!(
            verified.accepted_frontier_hash,
            appended.accepted_frontier_hash
        );
        assert_eq!(
            git_stdout(store.root(), "test Git HEAD", &["rev-parse", "HEAD"]).unwrap(),
            appended.git_commit
        );
    }

    #[test]
    fn streams_jsonl_items_into_bounded_records() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("archive");
        initialize_v2_archive(&root, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let spool = temp.path().join("items.jsonl");
        let mut spool_file = File::create(&spool).unwrap();
        for index in 0..10_001_u64 {
            writeln!(spool_file, "{{\"index\":{index},\"kind\":\"test_fact\"}}").unwrap();
        }
        spool_file.sync_all().unwrap();

        let store = V2OriginStore::open(root.join("canonical")).unwrap();
        let appended = store
            .append_jsonl_batch("stream_test", 1, json!({}), json!({}), &spool)
            .unwrap();

        assert_eq!(appended.items_written, 10_001);
        assert_eq!(appended.records_written, 13);
        let verified = store.verify().unwrap();
        assert_eq!(verified.records.len(), 16);
        assert!(verified
            .records
            .iter()
            .all(|record| { record.exact_line_bytes.len() <= DEFAULT_MAX_V2_RECORD_BYTES }));
        let compact = store.verify_compact().unwrap();
        assert_eq!(compact.record_count, 16);
        assert_eq!(compact.records.len(), 3);
        assert_eq!(
            compact
                .records
                .iter()
                .filter(|record| record.record.envelope.record_kind == V2RecordKind::BatchChunk)
                .count(),
            1
        );
    }

    #[test]
    fn enrolls_a_second_client_and_accepts_its_independent_origin() {
        let temp = TempDir::new().unwrap();
        let primary = temp.path().join("primary");
        let replica = temp.path().join("replica");
        initialize_v2_archive(&primary, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        copy_tree(&primary, &replica);

        let replica_store = V2OriginStore::open(replica.join("canonical")).unwrap();
        let request = replica_store.prepare_enrollment("Laptop").unwrap();
        assert_eq!(
            replica_store.active_origin_id().unwrap(),
            request.body.client_id
        );
        assert_eq!(
            request.verify().unwrap().to_bytes(),
            STANDARD_NO_PAD
                .decode(&request.body.public_key)
                .unwrap()
                .as_slice()
        );
        let unapproved = replica_store
            .append_batch(
                "laptop_observation",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact"})],
            )
            .unwrap_err();
        assert!(unapproved.to_string().contains("not enrolled"));

        let primary_store = V2OriginStore::open(primary.join("canonical")).unwrap();
        let approval = primary_store.approve_enrollment(&request).unwrap();
        assert_eq!(
            approval.origin_id,
            primary_store.active_origin_id().unwrap()
        );

        fs::remove_dir_all(replica.join("canonical")).unwrap();
        copy_tree(&primary.join("canonical"), &replica.join("canonical"));
        let replica_store = V2OriginStore::open(replica.join("canonical")).unwrap();
        let appended = replica_store
            .append_batch(
                "laptop_observation",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact", "source": "laptop"})],
            )
            .unwrap();
        assert_eq!(appended.origin_id, request.body.client_id);
        assert_eq!(appended.first_seq, 1);

        let verified = replica_store.verify().unwrap();
        assert_eq!(verified.accepted_frontier.origins.len(), 2);
        assert_eq!(verified.clients.len(), 2);
        assert_eq!(
            verified.clients[&request.body.client_id].display_name,
            "Laptop"
        );
    }

    #[test]
    fn refuses_append_from_a_revoked_client() {
        let temp = TempDir::new().unwrap();
        let primary = temp.path().join("primary");
        let replica = temp.path().join("replica");
        initialize_v2_archive(&primary, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        copy_tree(&primary, &replica);
        let request = V2OriginStore::open(replica.join("canonical"))
            .unwrap()
            .prepare_enrollment("Laptop")
            .unwrap();
        let primary_store = V2OriginStore::open(primary.join("canonical")).unwrap();
        primary_store.approve_enrollment(&request).unwrap();
        primary_store
            .revoke_client(&request.body.client_id)
            .unwrap();

        fs::remove_dir_all(replica.join("canonical")).unwrap();
        copy_tree(&primary.join("canonical"), &replica.join("canonical"));
        let error = V2OriginStore::open(replica.join("canonical"))
            .unwrap()
            .append_batch(
                "laptop_observation",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact"})],
            )
            .unwrap_err();
        assert!(error.to_string().contains("revoked"));
    }

    #[test]
    fn git_sync_unions_divergent_enrolled_origins_without_text_merging() {
        let temp = TempDir::new().unwrap();
        let primary = temp.path().join("primary");
        let replica = temp.path().join("replica");
        let remote = temp.path().join("central.git");
        fs::create_dir(&remote).unwrap();
        git_command_success(&remote, &["init", "--bare", "--quiet"]);

        initialize_v2_archive(&primary, "arc_test", "Personal", 1_782_000_000_000).unwrap();
        let primary_store = V2OriginStore::open(primary.join("canonical")).unwrap();
        primary_store
            .add_sync_remote("central", remote.to_str().unwrap())
            .unwrap();
        assert!(primary_store.sync_remote("central").unwrap().pushed);

        fs::create_dir(&replica).unwrap();
        let cloned = Command::new("git")
            .args(["clone", "--quiet", "--branch", "archive-ledger"])
            .arg(&remote)
            .arg(replica.join("canonical"))
            .output()
            .unwrap();
        assert!(
            cloned.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&cloned.stderr)
        );
        let replica_store = V2OriginStore::open(replica.join("canonical")).unwrap();
        let request = replica_store.prepare_enrollment("Laptop").unwrap();
        primary_store.approve_enrollment(&request).unwrap();
        primary_store.sync_remote("central").unwrap();
        replica_store.sync_remote("origin").unwrap();

        replica_store
            .append_batch(
                "laptop_observation",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact", "source": "laptop"})],
            )
            .unwrap();
        primary_store
            .append_batch(
                "desktop_observation",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact", "source": "desktop"})],
            )
            .unwrap();

        replica_store.sync_remote("origin").unwrap();
        let merged = primary_store.sync_remote("central").unwrap();
        assert!(merged.merged);
        assert!(merged.pushed);
        replica_store.sync_remote("origin").unwrap();

        let primary_verified = primary_store.verify().unwrap();
        let replica_verified = replica_store.verify().unwrap();
        assert_eq!(
            primary_verified.accepted_frontier_hash,
            replica_verified.accepted_frontier_hash
        );
        assert_eq!(primary_verified.accepted_frontier.origins.len(), 2);
        assert_eq!(primary_verified.records.len(), 12);
        assert_eq!(
            git_stdout(primary_store.root(), "primary HEAD", &["rev-parse", "HEAD"]).unwrap(),
            git_stdout(replica_store.root(), "replica HEAD", &["rev-parse", "HEAD"]).unwrap()
        );
        primary_store
            .append_batch(
                "post_merge_observation",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact", "source": "desktop-after-merge"})],
            )
            .unwrap();
        primary_store.sync_remote("central").unwrap();
        replica_store.sync_remote("origin").unwrap();
        assert_eq!(
            primary_store.verify().unwrap().accepted_frontier_hash,
            replica_store.verify().unwrap().accepted_frontier_hash
        );
        let primary_lease = primary_store.acquire_archive_lease("central").unwrap();
        let held = replica_store.acquire_archive_lease("origin").unwrap_err();
        assert!(held.to_string().contains("is held by client"));
        primary_store.release_archive_lease(&primary_lease).unwrap();
        let replica_lease = replica_store.acquire_archive_lease("origin").unwrap();
        replica_store.release_archive_lease(&replica_lease).unwrap();

        let abandoned = primary_store
            .acquire_archive_lease_with_duration("central", 1)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let recovered = replica_store.acquire_archive_lease("origin").unwrap();
        assert_ne!(abandoned.token_id, recovered.token_id);
        assert!(primary_store.release_archive_lease(&abandoned).is_err());
        replica_store.release_archive_lease(&recovered).unwrap();
        primary_store
            .append_batch(
                "site_registered",
                1,
                json!({}),
                json!({}),
                vec![json!({"kind": "test_fact"})],
            )
            .unwrap();
        let uncoordinated = primary_store.sync_remote("central").unwrap_err();
        assert!(uncoordinated
            .to_string()
            .contains("lacks a coordination lease"));
        assert!(git_stdout(
            primary_store.root(),
            "primary status",
            &["status", "--short"]
        )
        .unwrap()
        .is_empty());
        assert!(git_stdout(
            replica_store.root(),
            "replica status",
            &["status", "--short"]
        )
        .unwrap()
        .is_empty());
    }
}
