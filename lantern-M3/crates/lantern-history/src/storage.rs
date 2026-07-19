use lantern_store::{ColumnFamily, ReadStore, StoreBatch};
use lantern_types::Hash32;

use crate::{
    Error, HistoryConsistencyProofV1, HistoryConsistencyQueryV1, HistoryInclusionProofV1,
    HistoryInclusionQueryV1, MAX_HISTORY_APPEND_BYTES, MAX_HISTORY_APPEND_RECORDS,
    MAX_HISTORY_LEAVES, Result,
    structure::{
        NodeCoordinate, Peak, canonical_range_layout, empty_history_root, history_leaf_hash,
        mmr_node_count, node_position, parent_hash, peak_layout, root_from_peaks, subtree_width,
        validate_record,
    },
};

const NODE_PREFIX: &[u8] = b"lantern/history/v1/node/";
const ROOT_PREFIX: &[u8] = b"lantern/history/v1/root/";
const CURRENT_SIZE_KEY: &[u8] = b"lantern/history/v1/current-size";
const CURRENT_ROOT_KEY: &[u8] = b"lantern/history/v1/current-root";

/// Current authenticated MMR state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryState {
    /// Stable leaf count.
    pub leaf_count: u64,
    /// Number of immutable postorder MMR nodes.
    pub node_count: u64,
    /// Root committing the leaf count and ordered peak list.
    pub root: Hash32,
}

/// Observable size/cost counters for one prepared history append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryAppendStats {
    /// Compact records appended in caller order.
    pub records: usize,
    /// New immutable leaf and parent nodes.
    pub node_writes: usize,
    /// New exact-prefix root entries.
    pub prefix_root_writes: usize,
    /// Total M3 puts appended to the shared M1 batch.
    pub total_storage_writes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingWrite {
    key: Vec<u8>,
    value: Vec<u8>,
}

struct AppendBuilder<'a, S: ReadStore + ?Sized> {
    store: &'a S,
    peaks: Vec<Peak>,
    writes: Vec<PendingWrite>,
    leaf_count: u64,
    next_position: u64,
    node_writes: usize,
    root: Hash32,
}

impl<'a, S: ReadStore + ?Sized> AppendBuilder<'a, S> {
    fn new(store: &'a S, state: HistoryState, peaks: Vec<Peak>) -> Self {
        Self {
            store,
            peaks,
            writes: Vec::new(),
            leaf_count: state.leaf_count,
            next_position: state.node_count,
            node_writes: 0,
            root: state.root,
        }
    }

    fn append_record(&mut self, record: &[u8]) -> Result<()> {
        let leaf_coordinate = NodeCoordinate {
            start: self.leaf_count,
            height: 0,
        };
        let mut carry = Peak {
            coordinate: leaf_coordinate,
            hash: history_leaf_hash(self.leaf_count, record)?,
        };
        self.write_node(carry.coordinate, carry.hash)?;

        while self
            .peaks
            .last()
            .is_some_and(|peak| peak.coordinate.height == carry.coordinate.height)
        {
            let left = self.peaks.pop().ok_or_else(|| {
                Error::CorruptStorage("MMR peak stack unexpectedly empty".to_owned())
            })?;
            let expected_right = left
                .coordinate
                .start
                .checked_add(subtree_width(left.coordinate.height))
                .ok_or_else(|| Error::CorruptStorage("MMR peak range overflow".to_owned()))?;
            if carry.coordinate.start != expected_right {
                return Err(Error::CorruptStorage(
                    "stored MMR peaks are not adjacent".to_owned(),
                ));
            }
            let parent_height = carry
                .coordinate
                .height
                .checked_add(1)
                .ok_or_else(|| Error::InvalidInput("MMR parent height overflow".to_owned()))?;
            carry = Peak {
                coordinate: NodeCoordinate {
                    start: left.coordinate.start,
                    height: parent_height,
                },
                hash: parent_hash(parent_height, left.hash, carry.hash)?,
            };
            self.write_node(carry.coordinate, carry.hash)?;
        }
        self.peaks.push(carry);
        self.leaf_count = self
            .leaf_count
            .checked_add(1)
            .ok_or_else(|| Error::InvalidInput("history size overflow".to_owned()))?;
        self.root = root_from_peaks(self.leaf_count, &self.peaks)?;
        let key = root_key(self.leaf_count);
        ensure_absent(self.store, &key, "future prefix root")?;
        self.writes.push(PendingWrite {
            key,
            value: self.root.as_bytes().to_vec(),
        });
        Ok(())
    }

    fn write_node(&mut self, coordinate: NodeCoordinate, hash: Hash32) -> Result<()> {
        append_new_node(
            self.store,
            &mut self.writes,
            coordinate,
            self.next_position,
            hash,
        )?;
        self.next_position = self
            .next_position
            .checked_add(1)
            .ok_or_else(|| Error::InvalidInput("MMR position space exhausted".to_owned()))?;
        self.node_writes = self
            .node_writes
            .checked_add(1)
            .ok_or_else(|| Error::InvalidInput("node-write counter overflow".to_owned()))?;
        Ok(())
    }

    fn finish(
        mut self,
        start_size: u64,
        end_size: u64,
        record_count: usize,
    ) -> Result<PreparedHistoryAppend> {
        if self.leaf_count != end_size || self.next_position != mmr_node_count(end_size)? {
            return Err(Error::CorruptStorage(
                "prepared MMR counters do not match the append result".to_owned(),
            ));
        }
        self.writes.push(PendingWrite {
            key: CURRENT_SIZE_KEY.to_vec(),
            value: end_size.to_be_bytes().to_vec(),
        });
        self.writes.push(PendingWrite {
            key: CURRENT_ROOT_KEY.to_vec(),
            value: self.root.as_bytes().to_vec(),
        });
        let total_storage_writes = self
            .node_writes
            .checked_add(record_count)
            .and_then(|count| count.checked_add(2))
            .ok_or_else(|| Error::InvalidInput("storage-write counter overflow".to_owned()))?;
        if self.writes.len() != total_storage_writes {
            return Err(Error::CorruptStorage(
                "prepared MMR write counter is inconsistent".to_owned(),
            ));
        }
        Ok(PreparedHistoryAppend {
            start_size,
            end_size,
            root: self.root,
            stats: HistoryAppendStats {
                records: record_count,
                node_writes: self.node_writes,
                prefix_root_writes: record_count,
                total_storage_writes,
            },
            writes: self.writes,
        })
    }
}

/// Uncommitted M3 result. Visibility begins only when M4 commits the shared
/// M1 batch with M2 state, records, and typed block metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedHistoryAppend {
    start_size: u64,
    end_size: u64,
    root: Hash32,
    stats: HistoryAppendStats,
    writes: Vec<PendingWrite>,
}

impl PreparedHistoryAppend {
    /// Leaf count before this append.
    #[must_use]
    pub const fn start_size(&self) -> u64 {
        self.start_size
    }

    /// Leaf count after this append.
    #[must_use]
    pub const fn end_size(&self) -> u64 {
        self.end_size
    }

    /// Root after this append.
    #[must_use]
    pub const fn root(&self) -> Hash32 {
        self.root
    }

    /// Deterministic node/root/write counters.
    #[must_use]
    pub const fn stats(&self) -> HistoryAppendStats {
        self.stats
    }

    /// Adds all M3 writes to a caller-owned M1 batch without committing it.
    ///
    /// # Errors
    ///
    /// Propagates M1 key/value, duplicate-operation, or batch-limit errors.
    /// On failure the caller must discard the partially populated batch.
    pub fn append_to(&self, batch: &mut StoreBatch) -> Result<()> {
        for write in &self.writes {
            batch.put(ColumnFamily::MmrNodes, &write.key, &write.value)?;
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

/// Append-only MMR over an arbitrary M1 `ReadStore` implementation.
pub struct HistoryLog<'a, S: ReadStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: ReadStore + ?Sized> HistoryLog<'a, S> {
    /// Binds the history log to a live M1 store or consistent M1 snapshot.
    #[must_use]
    pub const fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// Reads and validates the current committed MMR state.
    ///
    /// # Errors
    ///
    /// Returns a backend, missing-node, or corrupt-metadata error. An
    /// uninitialized store is the canonical empty history.
    pub fn current_state(&self) -> Result<HistoryState> {
        self.load_current().map(|(state, _)| state)
    }

    /// Returns the authenticated root at an exact historical prefix size.
    ///
    /// # Errors
    ///
    /// Returns `MissingSize` for a future/uncommitted size, or a typed
    /// storage/corruption error.
    pub fn root_at(&self, leaf_count: u64) -> Result<Hash32> {
        let state = self.current_state()?;
        if leaf_count > state.leaf_count {
            return Err(Error::MissingSize(leaf_count));
        }
        self.read_root_at(leaf_count)
    }

    /// Prepares ordered records for one append without persisting them.
    ///
    /// Every new leaf/internal node and prefix root must be absent. An empty
    /// record slice is a no-op. M4 must call this method once with all records
    /// ordered for the block, then append the result to its shared M1 batch.
    ///
    /// # Errors
    ///
    /// Rejects record/count/aggregate limits, leaf-space exhaustion,
    /// pre-existing future keys, corrupt prior state, or storage failures.
    pub fn prepare_append<T: AsRef<[u8]>>(&self, records: &[T]) -> Result<PreparedHistoryAppend> {
        validate_append_input(records)?;
        let (state, peaks) = self.load_current()?;
        let record_count = u64::try_from(records.len())
            .map_err(|_| Error::InvalidInput("record count exceeds u64".to_owned()))?;
        let end_size = state
            .leaf_count
            .checked_add(record_count)
            .filter(|size| *size <= MAX_HISTORY_LEAVES)
            .ok_or_else(|| Error::InvalidInput("history leaf-count limit exceeded".to_owned()))?;
        if records.is_empty() {
            return Ok(PreparedHistoryAppend {
                start_size: state.leaf_count,
                end_size,
                root: state.root,
                stats: HistoryAppendStats {
                    records: 0,
                    node_writes: 0,
                    prefix_root_writes: 0,
                    total_storage_writes: 0,
                },
                writes: Vec::new(),
            });
        }

        let mut builder = AppendBuilder::new(self.store, state, peaks);
        for record in records {
            builder.append_record(record.as_ref())?;
        }
        builder.finish(state.leaf_count, end_size, records.len())
    }

    /// Generates and self-verifies one exact historical inclusion query.
    ///
    /// M3 does not own record storage, so the caller supplies the canonical
    /// compact record bytes read from M4's immutable record archive.
    ///
    /// # Errors
    ///
    /// Rejects an invalid index/size/record, missing/corrupt MMR nodes, a leaf
    /// commitment different from `record`, or a self-verification failure.
    pub fn inclusion_query(
        &self,
        record: &[u8],
        leaf_index: u64,
        leaf_count: u64,
    ) -> Result<HistoryInclusionQueryV1> {
        validate_record(record)?;
        let state = self.current_state()?;
        if leaf_count == 0 || leaf_count > state.leaf_count {
            return Err(Error::MissingSize(leaf_count));
        }
        if leaf_index >= leaf_count {
            return Err(Error::InvalidInput(format!(
                "leaf index {leaf_index} is outside prefix size {leaf_count}"
            )));
        }
        let root = self.read_root_at(leaf_count)?;
        let layout = peak_layout(leaf_count)?;
        let target = layout
            .iter()
            .copied()
            .find(|coordinate| {
                coordinate
                    .start
                    .checked_add(subtree_width(coordinate.height))
                    .is_some_and(|end| (coordinate.start..end).contains(&leaf_index))
            })
            .ok_or_else(|| Error::CorruptStorage("leaf is not covered by a peak".to_owned()))?;

        let stored_leaf = self.read_node(NodeCoordinate {
            start: leaf_index,
            height: 0,
        })?;
        let expected_leaf = history_leaf_hash(leaf_index, record)?;
        if stored_leaf != expected_leaf {
            return Err(Error::ProofVerification(
                "supplied record does not match the persisted history leaf".to_owned(),
            ));
        }

        let mut siblings = Vec::with_capacity(usize::from(target.height));
        for level in 0..target.height {
            let width = subtree_width(level);
            let node_start = leaf_index & !(width - 1);
            let sibling_start = if (leaf_index & width) == 0 {
                node_start
                    .checked_add(width)
                    .ok_or_else(|| Error::CorruptStorage("sibling position overflow".to_owned()))?
            } else {
                node_start
                    .checked_sub(width)
                    .ok_or_else(|| Error::CorruptStorage("sibling position underflow".to_owned()))?
            };
            siblings.push(self.read_node(NodeCoordinate {
                start: sibling_start,
                height: level,
            })?);
        }
        let peaks = self.read_peak_hashes(leaf_count)?;
        let proof = HistoryInclusionProofV1::from_parts(leaf_index, leaf_count, siblings, peaks)?;
        let query = HistoryInclusionQueryV1 {
            root,
            leaf_index,
            leaf_count,
            record: record.to_vec(),
            proof,
        };
        query.verify().map_err(|error| {
            Error::CorruptStorage(format!(
                "stored MMR nodes generated an invalid inclusion proof: {error}"
            ))
        })?;
        Ok(query)
    }

    /// Generates and self-verifies an old-root-to-new-root append-consistency
    /// query.
    ///
    /// # Errors
    ///
    /// Rejects reversed/future sizes, missing/corrupt nodes, or a generated
    /// proof inconsistent with either historical root.
    pub fn consistency_query(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<HistoryConsistencyQueryV1> {
        if old_size > new_size {
            return Err(Error::InvalidInput(format!(
                "old history size {old_size} exceeds new size {new_size}"
            )));
        }
        let state = self.current_state()?;
        if new_size > state.leaf_count {
            return Err(Error::MissingSize(new_size));
        }
        let old_root = self.read_root_at(old_size)?;
        let new_root = self.read_root_at(new_size)?;
        let old_peaks = self.read_peak_hashes(old_size)?;
        let appended_subtrees = canonical_range_layout(old_size, new_size)?
            .into_iter()
            .map(|coordinate| self.read_node(coordinate))
            .collect::<Result<Vec<_>>>()?;
        let proof = HistoryConsistencyProofV1::from_parts(
            old_size,
            new_size,
            old_peaks,
            appended_subtrees,
        )?;
        let query = HistoryConsistencyQueryV1 {
            old_root,
            new_root,
            old_size,
            new_size,
            proof,
        };
        query.verify().map_err(|error| {
            Error::CorruptStorage(format!(
                "stored MMR nodes generated an invalid consistency proof: {error}"
            ))
        })?;
        Ok(query)
    }

    fn load_current(&self) -> Result<(HistoryState, Vec<Peak>)> {
        let size = self.store.get(ColumnFamily::MmrNodes, CURRENT_SIZE_KEY)?;
        let root = self.store.get(ColumnFamily::MmrNodes, CURRENT_ROOT_KEY)?;
        match (size, root) {
            (None, None) => {
                let root = empty_history_root()?;
                Ok((
                    HistoryState {
                        leaf_count: 0,
                        node_count: 0,
                        root,
                    },
                    Vec::new(),
                ))
            }
            (Some(size), Some(root)) => {
                let leaf_count = decode_u64(&size, "current history size")?;
                if leaf_count == 0 || leaf_count > MAX_HISTORY_LEAVES {
                    return Err(Error::CorruptStorage(format!(
                        "persisted history size {leaf_count} is outside 1..={MAX_HISTORY_LEAVES}"
                    )));
                }
                let root = decode_hash(&root, "current history root")?;
                let exact_root = self.read_root_unchecked(leaf_count)?;
                if root != exact_root {
                    return Err(Error::CorruptStorage(
                        "current history root differs from exact-prefix root".to_owned(),
                    ));
                }
                let layout = peak_layout(leaf_count)?;
                let peaks: Vec<_> = layout
                    .into_iter()
                    .map(|coordinate| {
                        self.read_node(coordinate)
                            .map(|hash| Peak { coordinate, hash })
                    })
                    .collect::<Result<_>>()?;
                let calculated = root_from_peaks(leaf_count, &peaks)?;
                if calculated != root {
                    return Err(Error::CorruptStorage(format!(
                        "persisted peaks calculate root {calculated}, expected {root}"
                    )));
                }
                Ok((
                    HistoryState {
                        leaf_count,
                        node_count: mmr_node_count(leaf_count)?,
                        root,
                    },
                    peaks,
                ))
            }
            _ => Err(Error::CorruptStorage(
                "current history size/root metadata is only partially present".to_owned(),
            )),
        }
    }

    fn read_root_at(&self, leaf_count: u64) -> Result<Hash32> {
        if leaf_count == 0 {
            return empty_history_root();
        }
        self.read_root_unchecked(leaf_count)
    }

    fn read_root_unchecked(&self, leaf_count: u64) -> Result<Hash32> {
        let key = root_key(leaf_count);
        let value = self
            .store
            .get(ColumnFamily::MmrNodes, &key)?
            .ok_or(Error::MissingSize(leaf_count))?;
        decode_hash(&value, "history prefix root")
    }

    fn read_peak_hashes(&self, leaf_count: u64) -> Result<Vec<Hash32>> {
        peak_layout(leaf_count)?
            .into_iter()
            .map(|coordinate| self.read_node(coordinate))
            .collect()
    }

    fn read_node(&self, coordinate: NodeCoordinate) -> Result<Hash32> {
        let position = node_position(coordinate)?;
        let key = node_key(position);
        let value = self
            .store
            .get(ColumnFamily::MmrNodes, &key)?
            .ok_or(Error::MissingNode(position))?;
        decode_hash(&value, "MMR node")
    }
}

fn validate_append_input<T: AsRef<[u8]>>(records: &[T]) -> Result<()> {
    if records.len() > MAX_HISTORY_APPEND_RECORDS {
        return Err(Error::InvalidInput(format!(
            "append contains {} records; limit is {MAX_HISTORY_APPEND_RECORDS}",
            records.len()
        )));
    }
    let mut total = 0_usize;
    for record in records {
        let record = record.as_ref();
        validate_record(record)?;
        total = total.checked_add(record.len()).ok_or_else(|| {
            Error::InvalidInput("aggregate record byte count overflow".to_owned())
        })?;
        if total > MAX_HISTORY_APPEND_BYTES {
            return Err(Error::InvalidInput(format!(
                "append contains {total} record bytes; limit is {MAX_HISTORY_APPEND_BYTES}"
            )));
        }
    }
    Ok(())
}

fn append_new_node<S: ReadStore + ?Sized>(
    store: &S,
    writes: &mut Vec<PendingWrite>,
    coordinate: NodeCoordinate,
    expected_position: u64,
    hash: Hash32,
) -> Result<()> {
    let position = node_position(coordinate)?;
    if position != expected_position {
        return Err(Error::CorruptStorage(format!(
            "MMR coordinate {coordinate:?} maps to position {position}, expected {expected_position}"
        )));
    }
    let key = node_key(position);
    ensure_absent(store, &key, "future MMR node")?;
    writes.push(PendingWrite {
        key,
        value: hash.as_bytes().to_vec(),
    });
    Ok(())
}

fn ensure_absent<S: ReadStore + ?Sized>(store: &S, key: &[u8], label: &str) -> Result<()> {
    if store.get(ColumnFamily::MmrNodes, key)?.is_some() {
        return Err(Error::CorruptStorage(format!(
            "{label} key already exists; refusing an overwrite"
        )));
    }
    Ok(())
}

fn node_key(position: u64) -> Vec<u8> {
    prefixed(NODE_PREFIX, &position.to_be_bytes())
}

fn root_key(leaf_count: u64) -> Vec<u8> {
    prefixed(ROOT_PREFIX, &leaf_count.to_be_bytes())
}

fn prefixed(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

fn decode_u64(bytes: &[u8], label: &str) -> Result<u64> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| {
        Error::CorruptStorage(format!("{label} is {} bytes, expected 8", bytes.len()))
    })?;
    Ok(u64::from_be_bytes(value))
}

fn decode_hash(bytes: &[u8], label: &str) -> Result<Hash32> {
    let value: [u8; 32] = bytes.try_into().map_err(|_| {
        Error::CorruptStorage(format!("{label} is {} bytes, expected 32", bytes.len()))
    })?;
    Ok(Hash32::new(value))
}
