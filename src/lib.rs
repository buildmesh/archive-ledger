//! Core library for Archive Ledger.

pub mod annex;
pub mod discovery;
pub mod event_store;
pub mod policy;
pub mod projection;
pub mod registry;
pub mod review;
pub mod scan;

pub use annex::{
    AnnexImportConfig, AnnexImportError, AnnexImportResult, AnnexImportStatus, AnnexImporter,
    AnnexSummary,
};
pub use discovery::{
    DiscoveredFile, DiscoveryError, DiscoveryItem, DiscoveryStats, EncodedPath, FileDiscovery,
    NamespaceFingerprint, PathEncoding,
};
pub use event_store::{
    AppendStats, Checkpoint, CheckpointSegment, EventBatch, EventCursor, EventEnvelope,
    EventReadStats, EventRecord, EventReferences, EventRequest, EventStore, EventStoreConfig,
    EventStoreError, PositionedEvent, SegmentManifest, VerificationReport, VerifiedSegment,
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
    SiteSnapshot,
};
pub use review::{
    utf8_path, CopyFilter, CopyPage, CopyPageRequest, CopyReview, FileFilter, FilePage,
    FilePageRequest, FileReview, FileSummary, HistoryEntry, HistoryPage, LosslessPath,
    ObjectHashReview, ObjectReview, ReviewError,
};
pub use scan::{LocationScanner, ScanConfig, ScanError, ScanResult, ScanStatus, ScanSummary};
