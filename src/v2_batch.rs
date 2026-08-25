//! Bounded version 2 batch validation independent of the inactive v2 writer.

use thiserror::Error;

pub const DEFAULT_MAX_BATCH_CHUNK_ITEMS: u32 = 1_000;
pub const DEFAULT_MAX_BATCH_CHUNK_BYTES: usize = 1024 * 1024;

const DIGEST_DOMAIN: &[u8] = b"archive-ledger-batch-items-v1\0";

pub type Result<T> = std::result::Result<T, BatchValidationError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BatchValidationError {
    #[error("batch ID must be non-empty")]
    EmptyBatchId,

    #[error(
        "batch chunk limits must be greater than zero and no greater than the protocol maxima"
    )]
    InvalidLimits,

    #[error("chunk belongs to batch {actual:?}, not {expected:?}")]
    BatchMismatch { expected: String, actual: String },

    #[error("batch chunks must contain at least one item")]
    EmptyChunk,

    #[error("chunk contains {actual} items; maximum is {maximum}")]
    TooManyItems { actual: u32, maximum: u32 },

    #[error("chunk contains {actual} serialized bytes; maximum is {maximum}")]
    TooManyBytes { actual: usize, maximum: usize },

    #[error("chunk starts at item {actual}; expected {expected}")]
    NonConsecutiveRange { expected: u64, actual: u64 },

    #[error("batch item count overflow")]
    ItemCountOverflow,

    #[error("record_hash must be a lowercase blake3 identifier")]
    InvalidRecordHash,

    #[error("a batch must contain at least one chunk")]
    NoChunks,

    #[error("completion declares {actual} items; observed {expected}")]
    CompletionCountMismatch { expected: u64, actual: u64 },

    #[error("completion ordered item digest does not match observed chunks")]
    CompletionDigestMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchLimits {
    pub max_items: u32,
    pub max_serialized_bytes: usize,
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self {
            max_items: DEFAULT_MAX_BATCH_CHUNK_ITEMS,
            max_serialized_bytes: DEFAULT_MAX_BATCH_CHUNK_BYTES,
        }
    }
}

impl BatchLimits {
    pub fn validate(self) -> Result<Self> {
        if self.max_items == 0
            || self.max_serialized_bytes == 0
            || self.max_items > DEFAULT_MAX_BATCH_CHUNK_ITEMS
            || self.max_serialized_bytes > DEFAULT_MAX_BATCH_CHUNK_BYTES
        {
            Err(BatchValidationError::InvalidLimits)
        } else {
            Ok(self)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchChunkDescriptor {
    pub batch_id: String,
    pub first_item_index: u64,
    pub item_count: u32,
    /// Exact serialized `batch_chunk` line length, excluding its newline.
    pub serialized_bytes: usize,
    /// Exact serialized record hash after origin-chain verification.
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCompletion {
    pub total_items: u64,
    pub ordered_item_digest: String,
}

pub struct BatchValidator {
    batch_id: String,
    limits: BatchLimits,
    next_item_index: u64,
    chunk_count: u64,
    digest: blake3::Hasher,
}

impl BatchValidator {
    pub fn new(batch_id: impl Into<String>, limits: BatchLimits) -> Result<Self> {
        let batch_id = batch_id.into();
        if batch_id.is_empty() {
            return Err(BatchValidationError::EmptyBatchId);
        }
        let limits = limits.validate()?;
        let mut digest = blake3::Hasher::new();
        digest.update(DIGEST_DOMAIN);
        Ok(Self {
            batch_id,
            limits,
            next_item_index: 0,
            chunk_count: 0,
            digest,
        })
    }

    pub fn accept_chunk(&mut self, chunk: &BatchChunkDescriptor) -> Result<()> {
        if chunk.batch_id != self.batch_id {
            return Err(BatchValidationError::BatchMismatch {
                expected: self.batch_id.clone(),
                actual: chunk.batch_id.clone(),
            });
        }
        if chunk.item_count == 0 {
            return Err(BatchValidationError::EmptyChunk);
        }
        if chunk.item_count > self.limits.max_items {
            return Err(BatchValidationError::TooManyItems {
                actual: chunk.item_count,
                maximum: self.limits.max_items,
            });
        }
        if chunk.serialized_bytes > self.limits.max_serialized_bytes {
            return Err(BatchValidationError::TooManyBytes {
                actual: chunk.serialized_bytes,
                maximum: self.limits.max_serialized_bytes,
            });
        }
        if chunk.first_item_index != self.next_item_index {
            return Err(BatchValidationError::NonConsecutiveRange {
                expected: self.next_item_index,
                actual: chunk.first_item_index,
            });
        }
        let record_hash = decode_blake3(&chunk.record_hash)?;
        let next_item_index = self
            .next_item_index
            .checked_add(u64::from(chunk.item_count))
            .ok_or(BatchValidationError::ItemCountOverflow)?;

        self.digest.update(&chunk.first_item_index.to_be_bytes());
        self.digest.update(&chunk.item_count.to_be_bytes());
        self.digest.update(&record_hash);
        self.next_item_index = next_item_index;
        self.chunk_count += 1;
        Ok(())
    }

    pub fn observed_items(&self) -> u64 {
        self.next_item_index
    }

    pub fn ordered_item_digest(&self) -> Result<String> {
        if self.chunk_count == 0 {
            return Err(BatchValidationError::NoChunks);
        }
        Ok(format!(
            "blake3:{}",
            self.digest.clone().finalize().to_hex()
        ))
    }

    pub fn validate_completion(&self, completion: &BatchCompletion) -> Result<()> {
        if self.chunk_count == 0 {
            return Err(BatchValidationError::NoChunks);
        }
        if completion.total_items != self.next_item_index {
            return Err(BatchValidationError::CompletionCountMismatch {
                expected: self.next_item_index,
                actual: completion.total_items,
            });
        }
        if completion.ordered_item_digest != self.ordered_item_digest()? {
            return Err(BatchValidationError::CompletionDigestMismatch);
        }
        Ok(())
    }
}

fn decode_blake3(value: &str) -> Result<[u8; 32]> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(BatchValidationError::InvalidRecordHash);
    };
    if hex.len() != 64 {
        return Err(BatchValidationError::InvalidRecordHash);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn decode_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(BatchValidationError::InvalidRecordHash),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(first: u64, count: u32, hash_character: char) -> BatchChunkDescriptor {
        BatchChunkDescriptor {
            batch_id: "batch_test".to_owned(),
            first_item_index: first,
            item_count: count,
            serialized_bytes: 512,
            record_hash: format!("blake3:{}", hash_character.to_string().repeat(64)),
        }
    }

    #[test]
    fn validates_consecutive_bounded_chunks_and_stable_digest() {
        let mut validator = BatchValidator::new("batch_test", BatchLimits::default()).unwrap();
        validator.accept_chunk(&chunk(0, 1_000, 'a')).unwrap();
        validator.accept_chunk(&chunk(1_000, 4, 'b')).unwrap();
        assert_eq!(validator.observed_items(), 1_004);

        let digest = validator.ordered_item_digest().unwrap();
        assert_eq!(
            digest,
            "blake3:a8f6375bd0aec486720636c488b47c21b5fe671b1e2202a5ad4942ad566d3a72"
        );
        validator
            .validate_completion(&BatchCompletion {
                total_items: 1_004,
                ordered_item_digest: digest,
            })
            .unwrap();
    }

    #[test]
    fn rejects_gaps_empty_chunks_and_bounds() {
        assert_eq!(
            BatchLimits {
                max_items: DEFAULT_MAX_BATCH_CHUNK_ITEMS + 1,
                max_serialized_bytes: DEFAULT_MAX_BATCH_CHUNK_BYTES,
            }
            .validate(),
            Err(BatchValidationError::InvalidLimits)
        );
        let mut validator = BatchValidator::new("batch_test", BatchLimits::default()).unwrap();
        let mut empty = chunk(0, 0, 'a');
        assert_eq!(
            validator.accept_chunk(&empty),
            Err(BatchValidationError::EmptyChunk)
        );

        empty.item_count = 1_001;
        assert!(matches!(
            validator.accept_chunk(&empty),
            Err(BatchValidationError::TooManyItems { .. })
        ));

        let mut oversized = chunk(0, 1, 'a');
        oversized.serialized_bytes = DEFAULT_MAX_BATCH_CHUNK_BYTES + 1;
        assert!(matches!(
            validator.accept_chunk(&oversized),
            Err(BatchValidationError::TooManyBytes { .. })
        ));

        assert!(matches!(
            validator.accept_chunk(&chunk(1, 1, 'a')),
            Err(BatchValidationError::NonConsecutiveRange { .. })
        ));
    }

    #[test]
    fn rejects_wrong_batch_hash_and_completion() {
        let mut validator = BatchValidator::new("batch_test", BatchLimits::default()).unwrap();
        let mut wrong_batch = chunk(0, 1, 'a');
        wrong_batch.batch_id = "batch_other".to_owned();
        assert!(matches!(
            validator.accept_chunk(&wrong_batch),
            Err(BatchValidationError::BatchMismatch { .. })
        ));

        let mut invalid_hash = chunk(0, 1, 'g');
        assert_eq!(
            validator.accept_chunk(&invalid_hash),
            Err(BatchValidationError::InvalidRecordHash)
        );
        invalid_hash.record_hash = format!("blake3:{}", "a".repeat(64));
        validator.accept_chunk(&invalid_hash).unwrap();

        assert!(matches!(
            validator.validate_completion(&BatchCompletion {
                total_items: 2,
                ordered_item_digest: validator.ordered_item_digest().unwrap(),
            }),
            Err(BatchValidationError::CompletionCountMismatch { .. })
        ));
        assert_eq!(
            validator.validate_completion(&BatchCompletion {
                total_items: 1,
                ordered_item_digest: format!("blake3:{}", "f".repeat(64)),
            }),
            Err(BatchValidationError::CompletionDigestMismatch)
        );
    }
}
