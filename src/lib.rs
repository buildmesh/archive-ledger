//! Core library for Archive Ledger.

pub mod discovery;
pub mod event_store;
pub mod projection;

pub use discovery::{
    DiscoveredFile, DiscoveryError, DiscoveryItem, DiscoveryStats, EncodedPath, FileDiscovery,
    PathEncoding,
};
pub use event_store::{
    AppendStats, Checkpoint, CheckpointSegment, EventBatch, EventCursor, EventEnvelope,
    EventReadStats, EventRecord, EventReferences, EventRequest, EventStore, EventStoreConfig,
    EventStoreError, PositionedEvent, SegmentManifest, VerificationReport, VerifiedSegment,
};
pub use projection::{
    ApplyStats, ProjectionConfig, ProjectionDb, ProjectionError, ProjectionStatus,
    SUPPORTED_EVENT_TYPES,
};
