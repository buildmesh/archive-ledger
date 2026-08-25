//! Deterministic, self-signed trust root for a new v2 Archive.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::frontier::{FRONTIER_VERSION, INITIAL_ITEM_PROJECTION_VERSION};
use crate::v2_event::V2_RECORD_VERSION;

pub const GENESIS_VERSION: u32 = 2;
pub const V2_SCHEMA_VERSION: u32 = 6;

pub type Result<T> = std::result::Result<T, GenesisError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GenesisError {
    #[error("Archive ID and display name must be non-empty")]
    InvalidArchiveIdentity,

    #[error("unsupported genesis or component format version")]
    UnsupportedVersion,

    #[error("initial client ID or public key is invalid")]
    InvalidInitialClient,

    #[error("genesis signature is invalid")]
    InvalidSignature,

    #[error("genesis serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisBody {
    pub genesis_v: u32,
    pub archive_id: String,
    pub archive_display_name: String,
    pub created_time_utc_ms: u64,
    pub record_v: u32,
    pub frontier_v: u32,
    pub item_projection_v: u32,
    pub schema_v: u32,
    pub initial_client_id: String,
    pub initial_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedGenesis {
    pub body: GenesisBody,
    pub signature: String,
}

impl GenesisBody {
    pub fn new(
        archive_id: impl Into<String>,
        archive_display_name: impl Into<String>,
        created_time_utc_ms: u64,
        verifying_key: &VerifyingKey,
    ) -> Self {
        let public_key = verifying_key.to_bytes();
        Self {
            genesis_v: GENESIS_VERSION,
            archive_id: archive_id.into(),
            archive_display_name: archive_display_name.into(),
            created_time_utc_ms,
            record_v: V2_RECORD_VERSION,
            frontier_v: FRONTIER_VERSION,
            item_projection_v: INITIAL_ITEM_PROJECTION_VERSION,
            schema_v: V2_SCHEMA_VERSION,
            initial_client_id: client_id(&public_key),
            initial_public_key: STANDARD_NO_PAD.encode(public_key),
        }
    }

    pub fn validate(&self) -> Result<VerifyingKey> {
        if self.archive_id.is_empty() || self.archive_display_name.trim().is_empty() {
            return Err(GenesisError::InvalidArchiveIdentity);
        }
        if self.genesis_v != GENESIS_VERSION
            || self.record_v != V2_RECORD_VERSION
            || self.frontier_v != FRONTIER_VERSION
            || self.item_projection_v != INITIAL_ITEM_PROJECTION_VERSION
            || self.schema_v != V2_SCHEMA_VERSION
        {
            return Err(GenesisError::UnsupportedVersion);
        }
        let bytes = STANDARD_NO_PAD
            .decode(&self.initial_public_key)
            .map_err(|_| GenesisError::InvalidInitialClient)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| GenesisError::InvalidInitialClient)?;
        if self.initial_client_id != client_id(&bytes) {
            return Err(GenesisError::InvalidInitialClient);
        }
        VerifyingKey::from_bytes(&bytes).map_err(|_| GenesisError::InvalidInitialClient)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| GenesisError::Serialization(error.to_string()))
    }
}

impl SignedGenesis {
    pub fn create(body: GenesisBody, signing_key: &SigningKey) -> Result<Self> {
        if body.validate()? != signing_key.verifying_key() {
            return Err(GenesisError::InvalidInitialClient);
        }
        let signature = signing_key.sign(&body.canonical_bytes()?);
        let genesis = Self {
            body,
            signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
        };
        genesis.verify()?;
        Ok(genesis)
    }

    pub fn verify(&self) -> Result<()> {
        let verifying_key = self.body.validate()?;
        let signature = STANDARD_NO_PAD
            .decode(&self.signature)
            .map_err(|_| GenesisError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| GenesisError::InvalidSignature)?;
        verifying_key
            .verify_strict(&self.body.canonical_bytes()?, &signature)
            .map_err(|_| GenesisError::InvalidSignature)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.verify()?;
        serde_json::to_vec(self).map_err(|error| GenesisError::Serialization(error.to_string()))
    }

    pub fn genesis_hash(&self) -> Result<String> {
        Ok(format!(
            "blake3:{}",
            blake3::hash(&self.canonical_bytes()?).to_hex()
        ))
    }
}

pub fn client_id(public_key: &[u8; 32]) -> String {
    format!("origin_{}", blake3::hash(public_key).to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKey, SignedGenesis) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let body = GenesisBody::new(
            "arc_test",
            "Personal",
            1_781_042_405_123,
            &key.verifying_key(),
        );
        let genesis = SignedGenesis::create(body, &key).unwrap();
        (key, genesis)
    }

    #[test]
    fn creates_verifies_and_hashes_deterministic_genesis() {
        let (_, genesis) = fixture();
        genesis.verify().unwrap();
        assert_eq!(
            genesis.genesis_hash().unwrap(),
            "blake3:e54929326fdac82c9c547ff8d17dba898c074d3ebf5e61725f54b09e3d55c786"
        );
    }

    #[test]
    fn rejects_wrong_client_key_and_tampering() {
        let (key, genesis) = fixture();
        let other_key = SigningKey::from_bytes(&[8_u8; 32]);
        assert_eq!(
            SignedGenesis::create(genesis.body.clone(), &other_key),
            Err(GenesisError::InvalidInitialClient)
        );

        let mut tampered = genesis;
        tampered.body.archive_display_name = "Other".to_owned();
        assert_eq!(tampered.verify(), Err(GenesisError::InvalidSignature));
        assert_ne!(key.verifying_key(), other_key.verifying_key());
    }

    #[test]
    fn rejects_unknown_component_version_and_client_identity() {
        let (_, genesis) = fixture();
        let mut wrong_version = genesis.body.clone();
        wrong_version.schema_v += 1;
        assert_eq!(
            wrong_version.validate(),
            Err(GenesisError::UnsupportedVersion)
        );

        let mut wrong_client = genesis.body;
        wrong_client.initial_client_id = format!("origin_{}", "0".repeat(64));
        assert_eq!(
            wrong_client.validate(),
            Err(GenesisError::InvalidInitialClient)
        );
    }
}
