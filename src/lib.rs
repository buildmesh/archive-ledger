//! Core library for Archive Ledger.

pub mod event_store;

pub use event_store::{
    Checkpoint, CheckpointSegment, EventEnvelope, EventRecord, EventReferences, EventRequest,
    EventStore, EventStoreConfig, EventStoreError, SegmentManifest, VerificationReport,
    VerifiedSegment,
};
