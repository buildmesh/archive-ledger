//! Core library for Archive Ledger.

pub mod annex;
pub mod app_integration;
pub mod catalog;
pub mod discovery;
pub mod event_store;
pub mod frontier;
pub mod genesis;
pub mod metadata;
pub mod policy;
pub mod projection;
pub mod registry;
pub mod review;
pub mod safe_copy;
pub mod scan;
pub mod stage;
pub mod status;
pub mod storage;
pub mod v2_batch;
pub mod v2_event;
pub mod v2_fsck;
pub mod v2_inventory;
pub mod v2_projection;
pub mod v2_snapshot;
pub mod v2_store;

pub use annex::{
    is_git_annex_repository, validate_annex_repository, AnnexImportConfig, AnnexImportError,
    AnnexImportResult, AnnexImportStatus, AnnexImporter, AnnexSummary, V2AnnexImporter,
};
pub use app_integration::{
    access_plan, introduced_files, AccessCandidate, AccessPlanPage, AccessRequestSummary,
    AppCheckpoint, AppIntegrationError, AppPath, AttachmentLocation, AttachmentPlan,
    AttachmentStep, ChangeFeedPage, FileAccess, IntroducedFile,
};
pub use catalog::{central_archive, CatalogError, CatalogRegistry, KnownArchive};
pub use discovery::{
    DiscoveredFile, DiscoveryError, DiscoveryItem, DiscoveryStats, EncodedPath, FileDiscovery,
    NamespaceFingerprint, PathEncoding,
};
pub use event_store::{
    AppendStats, Checkpoint, CheckpointSegment, EventBatch, EventCursor, EventEnvelope,
    EventReadStats, EventRecord, EventReferences, EventRequest, EventStore, EventStoreConfig,
    EventStoreError, PositionedEvent, SegmentManifest, VerificationReport, VerifiedSegment,
};
pub use frontier::{
    CausalFrontier, FrontierAdvance, FrontierError, OriginFrontier, FRONTIER_VERSION,
    INITIAL_ITEM_PROJECTION_VERSION,
};
pub use genesis::{
    client_id, GenesisBody, GenesisError, SignedGenesis, GENESIS_VERSION, V2_SCHEMA_VERSION,
};
pub use metadata::{
    initialize_metadata_repository, restore_check, IndependenceAssessment,
    MetadataCheckpointResult, MetadataDestinationSnapshot, MetadataDestinationState, MetadataError,
    MetadataProtectionStatus, MetadataProtector, MetadataRegistry, RestoreCheckResult,
};
pub use policy::{
    CachedPolicyStatus, FilePolicyReview, PolicyError, PolicyEvaluation, PolicyEvaluationResult,
    PolicyEvaluationValidity, PolicyFinding, PolicyFindingFilter, PolicyFindingPage,
    PolicyRequirements, QualifyingCopyReview, StalePolicyEvaluation, UnconfiguredCollection,
};
pub use projection::{
    ApplyStats, LocationFreshness, ProjectionConfig, ProjectionDb, ProjectionError,
    ProjectionStatus, SUPPORTED_EVENT_TYPES,
};
pub use registry::{
    ArchiveRootSnapshot, CollectionSnapshot, DeviceCheckIn, DeviceMount, DeviceSnapshot,
    LocationSnapshot, PolicySnapshot, Registry, RegistryAction, RegistryChange, RegistryError,
    RegistryMutationResult, RegistryPath, RegistryState, RiskAssignment, RiskDomainSnapshot,
    SiteSnapshot, V2Registry, V2RegistryMutationResult,
};
pub use review::{
    utf8_path, CopyFilter, CopyPage, CopyPageRequest, CopyReview, FileFilter, FilePage,
    FilePageRequest, FileReview, FileSummary, HistoryEntry, HistoryPage, LosslessPath,
    ObjectHashReview, ObjectReview, ReviewError, V2HistoryEntry, V2HistoryPage,
};
pub use safe_copy::{
    copy_verified_no_replace, place_directory_no_replace, verify_existing_file, SafeCopyError,
    VerifiedCopy,
};
pub use scan::{
    LocationScanner, ScanConfig, ScanError, ScanMode, ScanResult, ScanStatus, ScanSummary,
};
pub use stage::{
    audit_stage, audit_stage_v2, prepare_stage_import, prepare_stage_import_v2,
    select_stage_import, select_stage_import_v2, stage_import_candidates,
    stage_import_candidates_v2, StageAuditOptions, StageError, StageFileReview,
    StageImportCandidate, StageImportCursor, StageImportPage, StageImportPlan, StageReport,
    DEFAULT_STAGE_DIRECTORY, DEFAULT_STAGE_MANIFEST,
};
pub use status::{
    CollectionStatus, DeviceMountStatus, LocationStatus, StalePresenceDevice,
    StalePresenceLocation, StalePresenceReport, StalePresenceThreshold, StatusError,
};
pub use storage::{discover_mounted_filesystem, MountedFilesystem, StorageDiscoveryError};
pub use v2_batch::{
    BatchChunkDescriptor, BatchCompletion, BatchLimits, BatchValidationError, BatchValidator,
    DEFAULT_MAX_BATCH_CHUNK_BYTES, DEFAULT_MAX_BATCH_CHUNK_ITEMS,
};
pub use v2_event::{
    parse_v2_record, V2Record, V2RecordEnvelope, V2RecordError, V2RecordKind,
    DEFAULT_MAX_V2_RECORD_BYTES, V2_RECORD_VERSION,
};
pub use v2_fsck::{
    fsck_v2_archive, V2FsckCheck, V2FsckError, V2FsckOptions, V2FsckReport, V2TableDigest,
};
pub use v2_inventory::{
    add_files as v2_add_files, record_placements as v2_record_placements, V2InventoryConfig,
    V2InventoryError, V2InventoryResult, V2InventorySummary, V2Placement,
};
pub use v2_projection::{
    V2ApplyStats, V2ProjectionDb, V2ProjectionError, V2ProjectionStatus, V2RebuildStats,
};
pub use v2_snapshot::{
    create_portable_snapshot, inspect_portable_snapshot, install_portable_snapshot,
    V2PortableSnapshot, V2SnapshotInstall, SNAPSHOT_DATABASE_FILE, SNAPSHOT_MANIFEST_FILE,
};
pub use v2_store::{
    initialize_v2_archive, is_v2_event_tree, EnrollmentRequestBody, PortableSnapshotManifestBody,
    SignedEnrollmentRequest, SignedPortableSnapshotManifest, V2AppendResult,
    V2ArchiveInitialization, V2CanonicalCursor, V2CoordinationLease, V2OriginCursor, V2OriginStore,
    V2StoreError, V2SyncRemote, V2SyncResult, V2VerificationReport, VerifiedV2Client,
};
