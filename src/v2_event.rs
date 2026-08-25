//! Strict parser for the inactive version 2 origin-record envelope.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;

use crate::v2_batch::DEFAULT_MAX_BATCH_CHUNK_BYTES;

pub const V2_RECORD_VERSION: u32 = 2;
pub const DEFAULT_MAX_V2_RECORD_BYTES: usize = DEFAULT_MAX_BATCH_CHUNK_BYTES;

pub type Result<T> = std::result::Result<T, V2RecordError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum V2RecordError {
    #[error("record line must not include a newline")]
    ContainsNewline,

    #[error("record contains {actual} bytes; maximum is {maximum}")]
    TooManyBytes { actual: usize, maximum: usize },

    #[error("record is not a supported version 2 envelope: {0}")]
    InvalidJson(String),

    #[error("unsupported record version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u32, expected: u32 },

    #[error("record origin {actual:?} does not match expected origin {expected:?}")]
    OriginMismatch { expected: String, actual: String },

    #[error("invalid origin ID {0:?}")]
    InvalidOriginId(String),

    #[error("record sequence {actual} does not match expected sequence {expected}")]
    SequenceMismatch { expected: u64, actual: u64 },

    #[error("record ID must be rec_ plus a lowercase ULID")]
    InvalidRecordId,

    #[error("batch ID must be batch_ plus a lowercase ULID")]
    InvalidBatchId,

    #[error("record payload must be an object")]
    InvalidPayload,

    #[error("record previous hash does not match its origin chain")]
    PreviousHashMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum V2RecordKind {
    BatchStart,
    BatchChunk,
    BatchComplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2RecordEnvelope {
    pub v: u32,
    pub origin_id: String,
    pub origin_seq: u64,
    pub record_id: String,
    pub record_kind: V2RecordKind,
    pub time_utc_ms: u64,
    pub batch_id: String,
    pub previous_record_hash: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct V2Record {
    pub envelope: V2RecordEnvelope,
    pub record_hash: String,
}

/// Parses and validates canonical line bytes without their terminating newline.
pub fn parse_v2_record(
    line: &[u8],
    expected_origin_id: &str,
    expected_origin_seq: u64,
    expected_previous_hash: Option<&str>,
    max_record_bytes: usize,
) -> Result<V2Record> {
    if line.contains(&b'\n') || line.contains(&b'\r') {
        return Err(V2RecordError::ContainsNewline);
    }
    let effective_max = max_record_bytes.min(DEFAULT_MAX_V2_RECORD_BYTES);
    if line.len() > effective_max {
        return Err(V2RecordError::TooManyBytes {
            actual: line.len(),
            maximum: effective_max,
        });
    }
    let envelope: V2RecordEnvelope = serde_json::from_slice(line)
        .map_err(|error| V2RecordError::InvalidJson(error.to_string()))?;

    if envelope.v != V2_RECORD_VERSION {
        return Err(V2RecordError::UnsupportedVersion {
            actual: envelope.v,
            expected: V2_RECORD_VERSION,
        });
    }
    if !is_origin_id(&envelope.origin_id) {
        return Err(V2RecordError::InvalidOriginId(envelope.origin_id));
    }
    if envelope.origin_id != expected_origin_id {
        return Err(V2RecordError::OriginMismatch {
            expected: expected_origin_id.to_owned(),
            actual: envelope.origin_id,
        });
    }
    if envelope.origin_seq != expected_origin_seq || expected_origin_seq == 0 {
        return Err(V2RecordError::SequenceMismatch {
            expected: expected_origin_seq,
            actual: envelope.origin_seq,
        });
    }
    if !is_prefixed_lowercase_ulid(&envelope.record_id, "rec_") {
        return Err(V2RecordError::InvalidRecordId);
    }
    if !is_prefixed_lowercase_ulid(&envelope.batch_id, "batch_") {
        return Err(V2RecordError::InvalidBatchId);
    }
    if !envelope.payload.is_object() {
        return Err(V2RecordError::InvalidPayload);
    }
    if envelope.previous_record_hash.as_deref() != expected_previous_hash
        || envelope
            .previous_record_hash
            .as_deref()
            .is_some_and(|hash| !is_blake3_identifier(hash))
        || (expected_origin_seq == 1 && envelope.previous_record_hash.is_some())
        || (expected_origin_seq > 1 && envelope.previous_record_hash.is_none())
    {
        return Err(V2RecordError::PreviousHashMismatch);
    }

    Ok(V2Record {
        envelope,
        record_hash: format!("blake3:{}", blake3::hash(line).to_hex()),
    })
}

fn is_origin_id(value: &str) -> bool {
    value.strip_prefix("origin_").is_some_and(is_lower_hex_64)
}

fn is_blake3_identifier(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(is_lower_hex_64)
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_prefixed_lowercase_ulid(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|ulid| ulid == ulid.to_ascii_lowercase() && Ulid::from_string(ulid).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn origin() -> String {
        format!("origin_{}", "a".repeat(64))
    }

    fn record(seq: u64, previous: Option<String>) -> V2RecordEnvelope {
        V2RecordEnvelope {
            v: V2_RECORD_VERSION,
            origin_id: origin(),
            origin_seq: seq,
            record_id: "rec_01arz3ndektsv4rrffq69g5fav".to_owned(),
            record_kind: V2RecordKind::BatchChunk,
            time_utc_ms: 1_781_042_405_123,
            batch_id: "batch_01arz3ndektsv4rrffq69g5fav".to_owned(),
            previous_record_hash: previous,
            payload: json!({"first_item_index": 0, "items": []}),
        }
    }

    #[test]
    fn parses_exact_line_and_returns_stable_hash() {
        let line = serde_json::to_vec(&record(1, None)).unwrap();
        let parsed = parse_v2_record(&line, &origin(), 1, None, line.len()).unwrap();
        assert_eq!(parsed.envelope, record(1, None));
        assert_eq!(
            parsed.record_hash,
            "blake3:d7debf20b2fbab3f101b4a2de95884ea2ea90bb8f82b9fc54ec000abe07a4612"
        );
    }

    #[test]
    fn validates_origin_sequence_and_previous_hash() {
        let previous = format!("blake3:{}", "b".repeat(64));
        let line = serde_json::to_vec(&record(2, Some(previous.clone()))).unwrap();
        assert!(matches!(
            parse_v2_record(&line, &origin(), 3, Some(&previous), line.len()),
            Err(V2RecordError::SequenceMismatch { .. })
        ));
        assert_eq!(
            parse_v2_record(
                &line,
                &format!("origin_{}", "c".repeat(64)),
                2,
                Some(&previous),
                line.len()
            ),
            Err(V2RecordError::OriginMismatch {
                expected: format!("origin_{}", "c".repeat(64)),
                actual: origin(),
            })
        );
        assert_eq!(
            parse_v2_record(
                &line,
                &origin(),
                2,
                Some(&format!("blake3:{}", "d".repeat(64))),
                line.len()
            ),
            Err(V2RecordError::PreviousHashMismatch)
        );
    }

    #[test]
    fn rejects_unknown_fields_kinds_and_non_object_payloads() {
        let mut value = serde_json::to_value(record(1, None)).unwrap();
        value["extra"] = json!(true);
        assert!(matches!(
            parse_v2_record(
                &serde_json::to_vec(&value).unwrap(),
                &origin(),
                1,
                None,
                1_024
            ),
            Err(V2RecordError::InvalidJson(_))
        ));

        value.as_object_mut().unwrap().remove("extra");
        value["record_kind"] = json!("other");
        assert!(matches!(
            parse_v2_record(
                &serde_json::to_vec(&value).unwrap(),
                &origin(),
                1,
                None,
                1_024
            ),
            Err(V2RecordError::InvalidJson(_))
        ));

        value["record_kind"] = json!("batch_start");
        value["payload"] = json!([]);
        assert_eq!(
            parse_v2_record(
                &serde_json::to_vec(&value).unwrap(),
                &origin(),
                1,
                None,
                1_024
            ),
            Err(V2RecordError::InvalidPayload)
        );
    }

    #[test]
    fn enforces_exact_line_byte_limit_and_no_newlines() {
        let mut line = serde_json::to_vec(&record(1, None)).unwrap();
        assert!(matches!(
            parse_v2_record(&line, &origin(), 1, None, line.len() - 1),
            Err(V2RecordError::TooManyBytes { .. })
        ));
        line.push(b'\n');
        assert_eq!(
            parse_v2_record(&line, &origin(), 1, None, line.len()),
            Err(V2RecordError::ContainsNewline)
        );
    }
}
