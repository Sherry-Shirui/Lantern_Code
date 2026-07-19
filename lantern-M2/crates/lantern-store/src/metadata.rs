use lantern_types::{Hash32, NetworkId};

use crate::{Error, Result};

/// M1 database schema version.
pub const STORE_SCHEMA_VERSION: u32 = 1;

const IDENTITY_MAGIC: &[u8; 4] = b"LNSI";
const COMMIT_MAGIC: &[u8; 4] = b"LNCM";
const HASH_BYTES: usize = 32;
const COMMIT_METADATA_BYTES: usize = 225;

/// Immutable identity stored when a Lantern database is first created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreIdentityV1 {
    chain_id: NetworkId,
    config_hash: Hash32,
}

impl StoreIdentityV1 {
    /// Creates a database identity.
    #[must_use]
    pub const fn new(chain_id: NetworkId, config_hash: Hash32) -> Self {
        Self {
            chain_id,
            config_hash,
        }
    }

    /// Returns the bound chain ID.
    #[must_use]
    pub const fn chain_id(&self) -> &NetworkId {
        &self.chain_id
    }

    /// Returns the deterministic application configuration hash.
    #[must_use]
    pub const fn config_hash(&self) -> Hash32 {
        self.config_hash
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let chain_id = self.chain_id.as_str().as_bytes();
        let length = u16::try_from(chain_id.len())
            .map_err(|_| Error::Metadata("chain ID does not fit in u16".to_owned()))?;
        let mut bytes = Vec::with_capacity(4 + 4 + 2 + chain_id.len() + HASH_BYTES);
        bytes.extend_from_slice(IDENTITY_MAGIC);
        bytes.extend_from_slice(&STORE_SCHEMA_VERSION.to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(chain_id);
        bytes.extend_from_slice(self.config_hash.as_bytes());
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 4 + 2 + HASH_BYTES || &bytes[..4] != IDENTITY_MAGIC {
            return Err(Error::Metadata(
                "database identity has an invalid prefix or length".to_owned(),
            ));
        }
        let schema = read_u32(bytes, 4)?;
        if schema != STORE_SCHEMA_VERSION {
            return Err(Error::Metadata(format!(
                "database schema {schema} is not supported"
            )));
        }
        let chain_length = usize::from(read_u16(bytes, 8)?);
        let expected_length = 4 + 4 + 2 + chain_length + HASH_BYTES;
        if bytes.len() != expected_length {
            return Err(Error::Metadata(format!(
                "database identity is {} bytes, expected {expected_length}",
                bytes.len()
            )));
        }
        let chain_end = 10 + chain_length;
        let chain = std::str::from_utf8(&bytes[10..chain_end])
            .map_err(|error| Error::Metadata(format!("chain ID is not UTF-8: {error}")))?;
        let chain_id = NetworkId::new(chain.to_owned())
            .map_err(|error| Error::Metadata(format!("chain ID is invalid: {error}")))?;
        let hash = read_hash(bytes, chain_end)?;
        Ok(Self::new(chain_id, hash))
    }
}

/// State metadata atomically committed with every application block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMetadataV1 {
    /// Last committed ABCI application height.
    pub app_height: u64,
    /// CometBFT-facing `AppHash` for `app_height`.
    pub app_hash: Hash32,
    /// Latest-state authenticated-map root.
    pub latest_root: Hash32,
    /// Append-only history root.
    pub history_root: Hash32,
    /// Stable number of history leaves.
    pub history_size: u64,
    /// Last epoch closed into a Lantern head.
    pub last_closed_epoch: u64,
    /// Head ID for `last_closed_epoch`; absent before the first close.
    pub last_closed_head_id: Option<Hash32>,
    /// Active validator-configuration hash.
    pub validator_config_hash: Hash32,
    /// Deterministic application configuration hash.
    pub config_hash: Hash32,
}

impl CommitMetadataV1 {
    /// Validates cross-field invariants that do not depend on prior state.
    ///
    /// # Errors
    ///
    /// Rejects an epoch-zero `HeadID` or a missing `HeadID` after epoch zero.
    pub fn validate(&self) -> Result<()> {
        if self.last_closed_epoch == 0 && self.last_closed_head_id.is_some() {
            return Err(Error::Metadata(
                "closed head must be absent when the closed epoch is zero".to_owned(),
            ));
        }
        if self.last_closed_epoch > 0 && self.last_closed_head_id.is_none() {
            return Err(Error::Metadata(
                "closed head is required after the first closed epoch".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(COMMIT_METADATA_BYTES);
        bytes.extend_from_slice(COMMIT_MAGIC);
        bytes.extend_from_slice(&STORE_SCHEMA_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.app_height.to_be_bytes());
        bytes.extend_from_slice(self.app_hash.as_bytes());
        bytes.extend_from_slice(self.latest_root.as_bytes());
        bytes.extend_from_slice(self.history_root.as_bytes());
        bytes.extend_from_slice(&self.history_size.to_be_bytes());
        bytes.extend_from_slice(&self.last_closed_epoch.to_be_bytes());
        if let Some(head_id) = self.last_closed_head_id {
            bytes.push(1);
            bytes.extend_from_slice(head_id.as_bytes());
        } else {
            bytes.push(0);
            bytes.extend_from_slice(&[0; HASH_BYTES]);
        }
        bytes.extend_from_slice(self.validator_config_hash.as_bytes());
        bytes.extend_from_slice(self.config_hash.as_bytes());
        debug_assert_eq!(bytes.len(), COMMIT_METADATA_BYTES);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != COMMIT_METADATA_BYTES || &bytes[..4] != COMMIT_MAGIC {
            return Err(Error::Metadata(format!(
                "commit metadata is {} bytes with an invalid prefix; expected {COMMIT_METADATA_BYTES}",
                bytes.len()
            )));
        }
        let schema = read_u32(bytes, 4)?;
        if schema != STORE_SCHEMA_VERSION {
            return Err(Error::Metadata(format!(
                "commit metadata schema {schema} is not supported"
            )));
        }
        let head_flag = bytes[128];
        let head_bytes = read_hash(bytes, 129)?;
        let last_closed_head_id = match head_flag {
            0 if head_bytes.as_bytes() == &[0; HASH_BYTES] => None,
            0 => {
                return Err(Error::Metadata(
                    "absent closed head contains non-zero bytes".to_owned(),
                ));
            }
            1 => Some(head_bytes),
            other => {
                return Err(Error::Metadata(format!(
                    "closed-head presence flag {other} is invalid"
                )));
            }
        };
        let value = Self {
            app_height: read_u64(bytes, 8)?,
            app_hash: read_hash(bytes, 16)?,
            latest_root: read_hash(bytes, 48)?,
            history_root: read_hash(bytes, 80)?,
            history_size: read_u64(bytes, 112)?,
            last_closed_epoch: read_u64(bytes, 120)?,
            last_closed_head_id,
            validator_config_hash: read_hash(bytes, 161)?,
            config_hash: read_hash(bytes, 193)?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| Error::Metadata("truncated u16".to_owned()))?;
    let array: [u8; 2] = value
        .try_into()
        .map_err(|_| Error::Metadata("invalid u16 width".to_owned()))?;
    Ok(u16::from_be_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Metadata("truncated u32".to_owned()))?;
    let array: [u8; 4] = value
        .try_into()
        .map_err(|_| Error::Metadata("invalid u32 width".to_owned()))?;
    Ok(u32::from_be_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| Error::Metadata("truncated u64".to_owned()))?;
    let array: [u8; 8] = value
        .try_into()
        .map_err(|_| Error::Metadata("invalid u64 width".to_owned()))?;
    Ok(u64::from_be_bytes(array))
}

fn read_hash(bytes: &[u8], offset: usize) -> Result<Hash32> {
    let value = bytes
        .get(offset..offset + HASH_BYTES)
        .ok_or_else(|| Error::Metadata("truncated hash".to_owned()))?;
    let array: [u8; HASH_BYTES] = value
        .try_into()
        .map_err(|_| Error::Metadata("invalid hash width".to_owned()))?;
    Ok(Hash32::new(array))
}
