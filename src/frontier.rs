//! Version 2 causal-frontier validation.
//!
//! This module deliberately does not activate the version 2 writer. It provides
//! the deterministic, independently testable value layer needed before Git
//! synchronization or multi-origin projection can trust a frontier manifest.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FRONTIER_VERSION: u32 = 2;
pub const INITIAL_ITEM_PROJECTION_VERSION: u32 = 1;

pub type Result<T> = std::result::Result<T, FrontierError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrontierError {
    #[error("unsupported frontier version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u32, expected: u32 },

    #[error("archive_id must be non-empty")]
    EmptyArchiveId,

    #[error("item_projection_version must be greater than zero")]
    InvalidProjectionVersion,

    #[error("{field} must be a lowercase blake3 identifier")]
    InvalidHash { field: &'static str },

    #[error(
        "invalid origin ID {origin_id:?}; expected origin_ followed by 64 lowercase hex characters"
    )]
    InvalidOriginId { origin_id: String },

    #[error("origin {origin_id} has sequence zero")]
    ZeroOriginSequence { origin_id: String },

    #[error("origin entries must be strictly sorted by origin ID")]
    OriginsNotStrictlySorted,

    #[error("previous frontier hashes must be strictly sorted")]
    PreviousFrontiersNotStrictlySorted,

    #[error("successor belongs to Archive {successor:?}, not {base:?}")]
    ArchiveMismatch { base: String, successor: String },

    #[error("successor changed the immutable Archive genesis hash")]
    GenesisMismatch,

    #[error("successor regressed item projection rules from {base} to {successor}")]
    ProjectionVersionRegression { base: u32, successor: u32 },

    #[error("successor does not name the base frontier as a parent")]
    MissingBaseFrontier,

    #[error("successor omitted origin {origin_id}")]
    OriginOmitted { origin_id: String },

    #[error("successor regressed origin {origin_id} from sequence {base} to {successor}")]
    OriginRegression {
        origin_id: String,
        base: u64,
        successor: u64,
    },

    #[error("successor changed the accepted tail for unchanged origin {origin_id}")]
    ChangedOriginTail { origin_id: String },

    #[error("frontier serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginFrontier {
    pub origin_id: String,
    pub seq: u64,
    pub event_hash: String,
    pub segment_manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CausalFrontier {
    pub v: u32,
    pub archive_id: String,
    pub genesis_hash: String,
    pub origins: Vec<OriginFrontier>,
    pub previous_frontiers: Vec<String>,
    pub item_projection_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierAdvance {
    /// Existing origins whose immutable manifest ancestry still must be proved.
    pub advanced_origins: Vec<String>,
    /// Newly accepted enrolled origins whose first manifest still must be proved.
    pub added_origins: Vec<String>,
}

impl CausalFrontier {
    pub fn validate(&self) -> Result<()> {
        if self.v != FRONTIER_VERSION {
            return Err(FrontierError::UnsupportedVersion {
                actual: self.v,
                expected: FRONTIER_VERSION,
            });
        }
        if self.archive_id.is_empty() {
            return Err(FrontierError::EmptyArchiveId);
        }
        if self.item_projection_version == 0 {
            return Err(FrontierError::InvalidProjectionVersion);
        }

        validate_hash("genesis_hash", &self.genesis_hash)?;

        let mut prior_origin: Option<&str> = None;
        for origin in &self.origins {
            if !is_origin_id(&origin.origin_id) {
                return Err(FrontierError::InvalidOriginId {
                    origin_id: origin.origin_id.clone(),
                });
            }
            if origin.seq == 0 {
                return Err(FrontierError::ZeroOriginSequence {
                    origin_id: origin.origin_id.clone(),
                });
            }
            if prior_origin.is_some_and(|prior| prior >= origin.origin_id.as_str()) {
                return Err(FrontierError::OriginsNotStrictlySorted);
            }
            validate_hash("origins.event_hash", &origin.event_hash)?;
            validate_hash(
                "origins.segment_manifest_hash",
                &origin.segment_manifest_hash,
            )?;
            prior_origin = Some(&origin.origin_id);
        }

        let mut prior_frontier: Option<&str> = None;
        for frontier in &self.previous_frontiers {
            validate_hash("previous_frontiers", frontier)?;
            if prior_frontier.is_some_and(|prior| prior >= frontier.as_str()) {
                return Err(FrontierError::PreviousFrontiersNotStrictlySorted);
            }
            prior_frontier = Some(frontier);
        }
        Ok(())
    }

    /// Returns the exact deterministic bytes whose BLAKE3 identifies this frontier.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| FrontierError::Serialization(error.to_string()))
    }

    pub fn frontier_hash(&self) -> Result<String> {
        Ok(format!(
            "blake3:{}",
            blake3::hash(&self.canonical_bytes()?).to_hex()
        ))
    }

    /// Validates frontier-level successor rules and returns ranges that still
    /// require cryptographic manifest-chain verification by the event store.
    pub fn validate_successor_of(&self, base: &Self) -> Result<FrontierAdvance> {
        base.validate()?;
        self.validate()?;

        if self.archive_id != base.archive_id {
            return Err(FrontierError::ArchiveMismatch {
                base: base.archive_id.clone(),
                successor: self.archive_id.clone(),
            });
        }
        if self.genesis_hash != base.genesis_hash {
            return Err(FrontierError::GenesisMismatch);
        }
        if self.item_projection_version < base.item_projection_version {
            return Err(FrontierError::ProjectionVersionRegression {
                base: base.item_projection_version,
                successor: self.item_projection_version,
            });
        }

        let base_hash = base.frontier_hash()?;
        if self.previous_frontiers.binary_search(&base_hash).is_err() {
            return Err(FrontierError::MissingBaseFrontier);
        }

        let mut advanced_origins = Vec::new();
        for base_origin in &base.origins {
            let Ok(index) = self
                .origins
                .binary_search_by(|origin| origin.origin_id.cmp(&base_origin.origin_id))
            else {
                return Err(FrontierError::OriginOmitted {
                    origin_id: base_origin.origin_id.clone(),
                });
            };
            let successor_origin = &self.origins[index];
            if successor_origin.seq < base_origin.seq {
                return Err(FrontierError::OriginRegression {
                    origin_id: base_origin.origin_id.clone(),
                    base: base_origin.seq,
                    successor: successor_origin.seq,
                });
            }
            if successor_origin.seq == base_origin.seq {
                if successor_origin.event_hash != base_origin.event_hash
                    || successor_origin.segment_manifest_hash != base_origin.segment_manifest_hash
                {
                    return Err(FrontierError::ChangedOriginTail {
                        origin_id: base_origin.origin_id.clone(),
                    });
                }
            } else {
                advanced_origins.push(base_origin.origin_id.clone());
            }
        }

        let added_origins = self
            .origins
            .iter()
            .filter(|origin| {
                base.origins
                    .binary_search_by(|item| item.origin_id.cmp(&origin.origin_id))
                    .is_err()
            })
            .map(|origin| origin.origin_id.clone())
            .collect();

        Ok(FrontierAdvance {
            advanced_origins,
            added_origins,
        })
    }
}

fn validate_hash(field: &'static str, value: &str) -> Result<()> {
    if is_blake3_identifier(value) {
        Ok(())
    } else {
        Err(FrontierError::InvalidHash { field })
    }
}

fn is_blake3_identifier(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(is_lower_hex_64)
}

fn is_origin_id(value: &str) -> bool {
    value.strip_prefix("origin_").is_some_and(is_lower_hex_64)
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(character: char) -> String {
        format!("blake3:{}", character.to_string().repeat(64))
    }

    fn origin(character: char) -> String {
        format!("origin_{}", character.to_string().repeat(64))
    }

    fn frontier(entries: &[(char, u64, char, char)]) -> CausalFrontier {
        CausalFrontier {
            v: FRONTIER_VERSION,
            archive_id: "arc_test".to_owned(),
            genesis_hash: hash('a'),
            origins: entries
                .iter()
                .map(|(id, seq, event, manifest)| OriginFrontier {
                    origin_id: origin(*id),
                    seq: *seq,
                    event_hash: hash(*event),
                    segment_manifest_hash: hash(*manifest),
                })
                .collect(),
            previous_frontiers: Vec::new(),
            item_projection_version: INITIAL_ITEM_PROJECTION_VERSION,
        }
    }

    #[test]
    fn canonical_bytes_and_hash_are_stable() {
        let value = frontier(&[('1', 7, 'b', 'c')]);
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(
            serde_json::from_slice::<CausalFrontier>(&bytes).unwrap(),
            value
        );
        assert_eq!(
            value.frontier_hash().unwrap(),
            "blake3:b0eefb8518e757d44adf7310938a34543988aaf9ec5afa0913b7d466b6487438"
        );
        assert!(!bytes.ends_with(b"\n"));
    }

    #[test]
    fn rejects_unsorted_or_duplicate_members() {
        let unsorted = frontier(&[('2', 1, 'a', 'b'), ('1', 1, 'c', 'd')]);
        assert_eq!(
            unsorted.validate(),
            Err(FrontierError::OriginsNotStrictlySorted)
        );

        let mut duplicate_parents = frontier(&[('1', 1, 'a', 'b')]);
        duplicate_parents.previous_frontiers = vec![hash('c'), hash('c')];
        assert_eq!(
            duplicate_parents.validate(),
            Err(FrontierError::PreviousFrontiersNotStrictlySorted)
        );
    }

    #[test]
    fn successor_rejects_omission_regression_and_equal_dot_rewrite() {
        let base = frontier(&[('1', 4, 'a', 'b'), ('2', 5, 'c', 'd')]);
        let base_hash = base.frontier_hash().unwrap();

        let mut omitted = frontier(&[('1', 4, 'a', 'b')]);
        omitted.previous_frontiers = vec![base_hash.clone()];
        assert!(matches!(
            omitted.validate_successor_of(&base),
            Err(FrontierError::OriginOmitted { .. })
        ));

        let mut regressed = frontier(&[('1', 3, 'a', 'b'), ('2', 5, 'c', 'd')]);
        regressed.previous_frontiers = vec![base_hash.clone()];
        assert!(matches!(
            regressed.validate_successor_of(&base),
            Err(FrontierError::OriginRegression { .. })
        ));

        let mut rewritten = frontier(&[('1', 4, 'f', 'b'), ('2', 5, 'c', 'd')]);
        rewritten.previous_frontiers = vec![base_hash];
        assert!(matches!(
            rewritten.validate_successor_of(&base),
            Err(FrontierError::ChangedOriginTail { .. })
        ));
    }

    #[test]
    fn successor_reports_manifest_proofs_still_required() {
        let base = frontier(&[('1', 4, 'a', 'b')]);
        let mut successor = frontier(&[('1', 8, 'c', 'd'), ('2', 1, 'e', 'f')]);
        successor.previous_frontiers = vec![base.frontier_hash().unwrap()];

        assert_eq!(
            successor.validate_successor_of(&base).unwrap(),
            FrontierAdvance {
                advanced_origins: vec![origin('1')],
                added_origins: vec![origin('2')],
            }
        );
    }

    #[test]
    fn successor_requires_explicit_parent_and_same_archive() {
        let base = frontier(&[('1', 4, 'a', 'b')]);
        let successor = frontier(&[('1', 5, 'c', 'd')]);
        assert_eq!(
            successor.validate_successor_of(&base),
            Err(FrontierError::MissingBaseFrontier)
        );

        let mut wrong_archive = successor;
        wrong_archive.archive_id = "arc_other".to_owned();
        wrong_archive.previous_frontiers = vec![base.frontier_hash().unwrap()];
        assert!(matches!(
            wrong_archive.validate_successor_of(&base),
            Err(FrontierError::ArchiveMismatch { .. })
        ));

        let mut wrong_genesis = frontier(&[('1', 5, 'c', 'd')]);
        wrong_genesis.genesis_hash = hash('f');
        wrong_genesis.previous_frontiers = vec![base.frontier_hash().unwrap()];
        assert_eq!(
            wrong_genesis.validate_successor_of(&base),
            Err(FrontierError::GenesisMismatch)
        );
    }
}
