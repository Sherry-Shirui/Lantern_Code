use std::collections::BTreeMap;

use anyhow::{Result as AnyResult, anyhow, bail};
use jmt::{
    JellyfishMerkleTree, KeyHash,
    storage::{LeafNode, Node, NodeKey, StaleNodeIndex, TreeReader, TreeUpdateBatch},
};
use lantern_store::{ColumnFamily, ReadStore, StoreBatch};
use lantern_types::Hash32;

use crate::{
    Error, LatestProofV1, LatestQueryV1, MAX_LATEST_VALUE_BYTES, Result,
    proof::decode_latest_leaf_bytes,
};
use crate::{latest_key, latest_leaf_bytes};

const NODE_PREFIX: &[u8] = b"lantern/latest/v1/node/";
const VALUE_COUNT_PREFIX: &[u8] = b"lantern/latest/v1/value-count/";
const VALUE_PREFIX: &[u8] = b"lantern/latest/v1/value/";
const STALE_PREFIX: &[u8] = b"lantern/latest/v1/stale/";
const ROOT_PREFIX: &[u8] = b"lantern/latest/v1/root/";
const LATEST_VERSION_KEY: &[u8] = b"lantern/latest/v1/latest-version";
const MAX_STORED_LEAF_BYTES: usize = MAX_LATEST_VALUE_BYTES + 128;

/// One set or delete operation applied to a CA's latest-state entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestMutationV1 {
    /// Stable CA identifier; M2 derives the domain-separated JMT key.
    pub ca_id: Hash32,
    /// Raw canonical latest-state value, or `None` to delete the entry.
    pub value: Option<Vec<u8>>,
}

impl LatestMutationV1 {
    /// Creates a membership-producing set operation.
    #[must_use]
    pub fn set(ca_id: Hash32, value: impl Into<Vec<u8>>) -> Self {
        Self {
            ca_id,
            value: Some(value.into()),
        }
    }

    /// Creates a deletion that produces non-membership at the new version.
    #[must_use]
    pub const fn delete(ca_id: Hash32) -> Self {
        Self { ca_id, value: None }
    }
}

/// Observable size/cost counters for one prepared JMT update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestUpdateStats {
    /// Number of distinct CA mutations supplied by the caller.
    pub mutations: usize,
    /// Number of versioned JMT nodes written.
    pub node_writes: usize,
    /// Number of value-history entries written, including tombstones.
    pub value_writes: usize,
    /// Number of stale-node indices retained for audit/future pruning policy.
    pub stale_index_writes: usize,
    /// Total M2 puts appended to the shared M1 batch.
    pub total_storage_writes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingWrite {
    key: Vec<u8>,
    value: Vec<u8>,
}

/// Uncommitted M2 result. It becomes visible only when M4 commits the shared
/// M1 `StoreBatch` with typed block metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLatestUpdate {
    version: u64,
    root: Hash32,
    stats: LatestUpdateStats,
    writes: Vec<PendingWrite>,
}

impl PreparedLatestUpdate {
    /// Version produced by this update.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// JMT root produced by this update.
    #[must_use]
    pub const fn root(&self) -> Hash32 {
        self.root
    }

    /// Deterministic node/value/write counters.
    #[must_use]
    pub const fn stats(&self) -> LatestUpdateStats {
        self.stats
    }

    /// Adds all M2 writes to a caller-owned M1 batch without committing it.
    ///
    /// # Errors
    ///
    /// Propagates M1 key/value, duplicate-operation, or batch-limit errors.
    /// On failure the caller must discard the partially populated batch.
    pub fn append_to(&self, batch: &mut StoreBatch) -> Result<()> {
        for write in &self.writes {
            batch.put(ColumnFamily::LatestTreeNodes, &write.key, &write.value)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn writes(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.writes
            .iter()
            .map(|write| (write.key.as_slice(), write.value.as_slice()))
    }
}

/// Versioned latest-state map over an arbitrary M1 `ReadStore` implementation.
pub struct LatestMap<'a, S: ReadStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: ReadStore + ?Sized> LatestMap<'a, S> {
    /// Binds the map to a live M1 store or an M1 read snapshot.
    #[must_use]
    pub const fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Returns the last committed M2 version, if genesis has been committed.
    ///
    /// # Errors
    ///
    /// Returns a backend or corrupt-metadata error.
    pub fn latest_version(&self) -> Result<Option<u64>> {
        self.store
            .get(ColumnFamily::LatestTreeNodes, LATEST_VERSION_KEY)?
            .map(|bytes| decode_u64(&bytes, "latest version"))
            .transpose()
    }

    /// Returns the committed root at an exact historical version.
    ///
    /// # Errors
    ///
    /// Returns `MissingVersion` if the version was never atomically committed,
    /// or a typed backend/corruption error.
    pub fn root(&self, version: u64) -> Result<Hash32> {
        let key = root_key(version);
        let bytes = self
            .store
            .get(ColumnFamily::LatestTreeNodes, &key)?
            .ok_or(Error::MissingVersion(version))?;
        let root: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            Error::CorruptStorage(format!(
                "root at version {version} is {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        Ok(Hash32::new(root))
    }

    /// Prepares one exact successor version without persisting it.
    ///
    /// Mutations are canonicalized by the derived latest key, and duplicate
    /// keys are rejected rather than relying on last-write-wins behavior.
    /// Empty mutation sets still create a new version root.
    ///
    /// # Errors
    ///
    /// Rejects gaps/overwrites, duplicate keys, invalid values, corrupt prior
    /// storage, or a JMT update failure.
    pub fn prepare_update(
        &self,
        version: u64,
        mutations: &[LatestMutationV1],
    ) -> Result<PreparedLatestUpdate> {
        let previous = self.latest_version()?;
        let expected_previous = version.checked_sub(1);
        if previous != expected_previous {
            return Err(Error::NonSuccessorVersion {
                previous,
                actual: version,
            });
        }

        let mut ordered = BTreeMap::<Hash32, Option<Vec<u8>>>::new();
        for mutation in mutations {
            let key = latest_key(mutation.ca_id)?;
            let value = mutation
                .value
                .as_deref()
                .map(latest_leaf_bytes)
                .transpose()?;
            if ordered.insert(key, value).is_some() {
                return Err(Error::InvalidInput(format!(
                    "duplicate or colliding latest key {key}"
                )));
            }
        }

        let reader = StoreTreeReader { store: self.store };
        let tree = JellyfishMerkleTree::<_, sha2_jmt::Sha256>::new(&reader);
        let jmt_mutations = ordered
            .into_iter()
            .map(|(key, value)| (KeyHash(*key.as_bytes()), value));
        let (root, update_batch) = tree
            .put_value_set(jmt_mutations, version)
            .map_err(|error| Error::Jmt(error.to_string()))?;
        build_prepared_update(
            self.store,
            version,
            Hash32::new(root.0),
            mutations.len(),
            &update_batch,
        )
    }

    /// Queries one CA at an exact committed historical version.
    ///
    /// # Errors
    ///
    /// Returns a missing-version, storage-corruption, JMT, or proof error.
    pub fn query_ca(&self, ca_id: Hash32, version: u64) -> Result<LatestQueryV1> {
        self.query_key(latest_key(ca_id)?, version)
    }

    /// Queries one already domain-separated latest key at an exact version.
    ///
    /// # Errors
    ///
    /// Returns a missing-version, storage-corruption, JMT, or proof error.
    pub fn query_key(&self, key: Hash32, version: u64) -> Result<LatestQueryV1> {
        let root = self.root(version)?;
        let reader = StoreTreeReader { store: self.store };
        let tree = JellyfishMerkleTree::<_, sha2_jmt::Sha256>::new(&reader);
        let (encoded_value, proof) = tree
            .get_with_proof(KeyHash(*key.as_bytes()), version)
            .map_err(|error| Error::Jmt(error.to_string()))?;
        let value = encoded_value
            .as_deref()
            .map(decode_latest_leaf_bytes)
            .transpose()?;
        let result = LatestQueryV1 {
            version,
            root,
            key,
            value,
            proof: LatestProofV1::from_inner(proof),
        };
        result.verify().map_err(|error| {
            Error::CorruptStorage(format!(
                "stored nodes generated a proof inconsistent with root {root}: {error}"
            ))
        })?;
        Ok(result)
    }
}

struct StoreTreeReader<'a, S: ReadStore + ?Sized> {
    store: &'a S,
}

impl<S: ReadStore + ?Sized> TreeReader for StoreTreeReader<'_, S> {
    fn get_node_option(&self, node_key: &NodeKey) -> AnyResult<Option<Node>> {
        let key = node_key_storage_key(node_key).map_err(to_anyhow)?;
        let value = self
            .store
            .get(ColumnFamily::LatestTreeNodes, &key)
            .map_err(to_anyhow)?;
        value
            .map(|bytes| {
                borsh::from_slice(&bytes)
                    .map_err(|error| anyhow!("invalid persisted JMT node at {node_key:?}: {error}"))
            })
            .transpose()
    }

    fn get_value_option(&self, max_version: u64, key_hash: KeyHash) -> AnyResult<Option<Vec<u8>>> {
        read_value_at_or_before(self.store, max_version, key_hash).map_err(to_anyhow)
    }

    fn get_rightmost_leaf(&self) -> AnyResult<Option<(NodeKey, LeafNode)>> {
        bail!("M2 disables JMT migration/restore-by-rightmost-leaf mode")
    }
}

fn build_prepared_update<S: ReadStore + ?Sized>(
    store: &S,
    version: u64,
    root: Hash32,
    mutation_count: usize,
    update_batch: &TreeUpdateBatch,
) -> Result<PreparedLatestUpdate> {
    let node_writes = update_batch.node_batch.nodes().len();
    let value_writes = update_batch.node_batch.values().len();
    let stale_index_writes = update_batch.stale_node_index_batch.len();
    let mut writes = Vec::new();

    for (node_key, node) in update_batch.node_batch.nodes() {
        writes.push(PendingWrite {
            key: node_key_storage_key(node_key)?,
            value: borsh::to_vec(node).map_err(|error| {
                Error::CorruptStorage(format!("cannot encode JMT node {node_key:?}: {error}"))
            })?,
        });
    }

    for ((value_version, key_hash), value) in update_batch.node_batch.values() {
        if *value_version != version {
            return Err(Error::CorruptStorage(format!(
                "JMT batch value version {value_version} differs from update version {version}"
            )));
        }
        let count = read_value_count(store, *key_hash)?;
        if count > 0 {
            let previous = read_value_entry(store, *key_hash, count - 1)?;
            if previous.version >= version {
                return Err(Error::CorruptStorage(format!(
                    "value history for {key_hash:?} ends at {}, cannot append version {version}",
                    previous.version
                )));
            }
        }
        let next_count = count.checked_add(1).ok_or_else(|| {
            Error::CorruptStorage(format!("value history count overflow for {key_hash:?}"))
        })?;
        writes.push(PendingWrite {
            key: value_entry_key(*key_hash, count),
            value: encode_value_entry(version, value.as_deref())?,
        });
        writes.push(PendingWrite {
            key: value_count_key(*key_hash),
            value: next_count.to_be_bytes().to_vec(),
        });
    }

    for stale in &update_batch.stale_node_index_batch {
        writes.push(PendingWrite {
            key: stale_key(stale)?,
            value: Vec::new(),
        });
    }

    writes.push(PendingWrite {
        key: root_key(version),
        value: root.as_bytes().to_vec(),
    });
    writes.push(PendingWrite {
        key: LATEST_VERSION_KEY.to_vec(),
        value: version.to_be_bytes().to_vec(),
    });

    let stats = LatestUpdateStats {
        mutations: mutation_count,
        node_writes,
        value_writes,
        stale_index_writes,
        total_storage_writes: writes.len(),
    };
    Ok(PreparedLatestUpdate {
        version,
        root,
        stats,
        writes,
    })
}

#[derive(Debug)]
struct ValueEntry {
    version: u64,
    value: Option<Vec<u8>>,
}

fn read_value_at_or_before<S: ReadStore + ?Sized>(
    store: &S,
    max_version: u64,
    key_hash: KeyHash,
) -> Result<Option<Vec<u8>>> {
    let count = read_value_count(store, key_hash)?;
    let mut low = 0_u64;
    let mut high = count;
    while low < high {
        let middle = low + (high - low) / 2;
        let entry = read_value_entry(store, key_hash, middle)?;
        if entry.version <= max_version {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if low == 0 {
        return Ok(None);
    }
    read_value_entry(store, key_hash, low - 1).map(|entry| entry.value)
}

fn read_value_count<S: ReadStore + ?Sized>(store: &S, key_hash: KeyHash) -> Result<u64> {
    store
        .get(ColumnFamily::LatestTreeNodes, &value_count_key(key_hash))?
        .map(|bytes| decode_u64(&bytes, "value history count"))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn read_value_entry<S: ReadStore + ?Sized>(
    store: &S,
    key_hash: KeyHash,
    ordinal: u64,
) -> Result<ValueEntry> {
    let bytes = store
        .get(
            ColumnFamily::LatestTreeNodes,
            &value_entry_key(key_hash, ordinal),
        )?
        .ok_or_else(|| {
            Error::CorruptStorage(format!(
                "missing value history entry {ordinal} for {key_hash:?}"
            ))
        })?;
    decode_value_entry(&bytes)
}

fn encode_value_entry(version: u64, value: Option<&[u8]>) -> Result<Vec<u8>> {
    let value_length = value.map_or(0, <[u8]>::len);
    if value_length > MAX_STORED_LEAF_BYTES {
        return Err(Error::CorruptStorage(format!(
            "JMT leaf value is {value_length} bytes; limit is {MAX_STORED_LEAF_BYTES}"
        )));
    }
    let value_length_u32 = u32::try_from(value_length)
        .map_err(|_| Error::CorruptStorage("JMT leaf length exceeds u32".to_owned()))?;
    let mut bytes = Vec::with_capacity(8 + 1 + 4 + value_length);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(u8::from(value.is_some()));
    bytes.extend_from_slice(&value_length_u32.to_be_bytes());
    if let Some(value) = value {
        bytes.extend_from_slice(value);
    }
    Ok(bytes)
}

fn decode_value_entry(bytes: &[u8]) -> Result<ValueEntry> {
    const HEADER_BYTES: usize = 8 + 1 + 4;
    if bytes.len() < HEADER_BYTES {
        return Err(Error::CorruptStorage(
            "value history entry is truncated".to_owned(),
        ));
    }
    let version = decode_u64(&bytes[..8], "value history version")?;
    let tag = bytes[8];
    let value_length = bytes
        .get(9..13)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .map(|value| value as usize)
        .ok_or_else(|| Error::CorruptStorage("invalid value history length".to_owned()))?;
    if value_length > MAX_STORED_LEAF_BYTES {
        return Err(Error::CorruptStorage(format!(
            "stored JMT leaf is {value_length} bytes; limit is {MAX_STORED_LEAF_BYTES}"
        )));
    }
    let expected_length = HEADER_BYTES.checked_add(value_length).ok_or_else(|| {
        Error::CorruptStorage("value history length arithmetic overflow".to_owned())
    })?;
    if bytes.len() != expected_length {
        return Err(Error::CorruptStorage(format!(
            "value history entry declares {value_length} bytes but total length is {}",
            bytes.len()
        )));
    }
    let value = match tag {
        0 if value_length == 0 => None,
        0 => {
            return Err(Error::CorruptStorage(
                "tombstone value history entry has a payload".to_owned(),
            ));
        }
        1 if value_length > 0 => Some(bytes[HEADER_BYTES..].to_vec()),
        1 => {
            return Err(Error::CorruptStorage(
                "present value history entry has an empty payload".to_owned(),
            ));
        }
        other => {
            return Err(Error::CorruptStorage(format!(
                "value history presence tag {other} is invalid"
            )));
        }
    };
    Ok(ValueEntry { version, value })
}

fn node_key_storage_key(node_key: &NodeKey) -> Result<Vec<u8>> {
    let encoded = borsh::to_vec(node_key).map_err(|error| {
        Error::CorruptStorage(format!("cannot encode JMT node key {node_key:?}: {error}"))
    })?;
    Ok(prefixed(NODE_PREFIX, &encoded))
}

fn value_count_key(key_hash: KeyHash) -> Vec<u8> {
    prefixed(VALUE_COUNT_PREFIX, &key_hash.0)
}

fn value_entry_key(key_hash: KeyHash, ordinal: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(VALUE_PREFIX.len() + 32 + 8);
    key.extend_from_slice(VALUE_PREFIX);
    key.extend_from_slice(&key_hash.0);
    key.extend_from_slice(&ordinal.to_be_bytes());
    key
}

fn stale_key(stale: &StaleNodeIndex) -> Result<Vec<u8>> {
    let encoded = borsh::to_vec(stale).map_err(|error| {
        Error::CorruptStorage(format!("cannot encode stale JMT index {stale:?}: {error}"))
    })?;
    Ok(prefixed(STALE_PREFIX, &encoded))
}

fn root_key(version: u64) -> Vec<u8> {
    prefixed(ROOT_PREFIX, &version.to_be_bytes())
}

fn prefixed(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

fn decode_u64(bytes: &[u8], label: &str) -> Result<u64> {
    let array: [u8; 8] = bytes.try_into().map_err(|_| {
        Error::CorruptStorage(format!("{label} is {} bytes, expected 8", bytes.len()))
    })?;
    Ok(u64::from_be_bytes(array))
}

fn to_anyhow(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(error.to_string())
}
