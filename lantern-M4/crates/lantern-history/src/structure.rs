use lantern_types::{DomainV1, Hash32, hash_with_domain};

use crate::{Error, Result};

const LEAF_KIND: u8 = 0;
const PARENT_KIND: u8 = 0;
const ROOT_KIND: u8 = 1;

/// Maximum compact history-record size accepted by M3.
pub const MAX_HISTORY_RECORD_BYTES: usize = 1024 * 1024;
/// Maximum record count accepted by one prepared append.
pub const MAX_HISTORY_APPEND_RECORDS: usize = 65_536;
/// Maximum aggregate compact-record bytes accepted by one prepared append.
pub const MAX_HISTORY_APPEND_BYTES: usize = 64 * 1024 * 1024;
/// Maximum leaf count representable by the v1 postorder position space.
pub const MAX_HISTORY_LEAVES: u64 = 1_u64 << 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodeCoordinate {
    pub(crate) start: u64,
    pub(crate) height: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peak {
    pub(crate) coordinate: NodeCoordinate,
    pub(crate) hash: Hash32,
}

/// Hashes one exact compact history record at its stable zero-based leaf index.
///
/// # Errors
///
/// Rejects an empty/oversized record or a framing-length overflow.
pub fn history_leaf_hash(leaf_index: u64, record: &[u8]) -> Result<Hash32> {
    validate_record(record)?;
    if leaf_index >= MAX_HISTORY_LEAVES {
        return Err(Error::InvalidInput(format!(
            "leaf index {leaf_index} reaches the MMR v1 limit"
        )));
    }
    let record_length = u64::try_from(record.len())
        .map_err(|_| Error::InvalidInput("record length exceeds u64".to_owned()))?;
    let mut payload = Vec::with_capacity(1 + 8 + 8 + record.len());
    payload.push(LEAF_KIND);
    payload.extend_from_slice(&leaf_index.to_be_bytes());
    payload.extend_from_slice(&record_length.to_be_bytes());
    payload.extend_from_slice(record);
    hash_with_domain(DomainV1::HistoryLeaf, &payload).map_err(Into::into)
}

/// Returns the deterministic authenticated root of an empty history.
///
/// # Errors
///
/// Propagates an M0 domain-framing failure.
pub fn empty_history_root() -> Result<Hash32> {
    root_from_peak_hashes(0, &[])
}

/// Returns the number of standard postorder MMR nodes after `leaf_count`
/// leaves: `2*n - popcount(n)`.
///
/// # Errors
///
/// Rejects a leaf count outside the MMR v1 position space.
pub fn mmr_node_count(leaf_count: u64) -> Result<u64> {
    validate_leaf_count(leaf_count)?;
    let count = u128::from(leaf_count)
        .checked_mul(2)
        .and_then(|value| value.checked_sub(u128::from(leaf_count.count_ones())))
        .ok_or_else(|| Error::InvalidInput("MMR node-count arithmetic overflow".to_owned()))?;
    u64::try_from(count).map_err(|_| Error::InvalidInput("MMR node count exceeds u64".to_owned()))
}

pub(crate) fn validate_record(record: &[u8]) -> Result<()> {
    if record.is_empty() {
        return Err(Error::InvalidInput(
            "compact history record must not be empty".to_owned(),
        ));
    }
    if record.len() > MAX_HISTORY_RECORD_BYTES {
        return Err(Error::InvalidInput(format!(
            "compact history record is {} bytes; limit is {MAX_HISTORY_RECORD_BYTES}",
            record.len()
        )));
    }
    Ok(())
}

pub(crate) fn validate_leaf_count(leaf_count: u64) -> Result<()> {
    if leaf_count > MAX_HISTORY_LEAVES {
        return Err(Error::InvalidInput(format!(
            "leaf count {leaf_count} exceeds MMR v1 limit {MAX_HISTORY_LEAVES}"
        )));
    }
    Ok(())
}

pub(crate) fn peak_layout(leaf_count: u64) -> Result<Vec<NodeCoordinate>> {
    validate_leaf_count(leaf_count)?;
    let mut peaks = Vec::with_capacity(leaf_count.count_ones() as usize);
    let mut start = 0_u64;
    for height in (0_u8..=63).rev() {
        let width = subtree_width(height);
        if leaf_count & width != 0 {
            peaks.push(NodeCoordinate { start, height });
            start = start
                .checked_add(width)
                .ok_or_else(|| Error::InvalidInput("peak-layout leaf count overflow".to_owned()))?;
        }
    }
    if start != leaf_count {
        return Err(Error::InvalidInput(
            "peak layout does not cover the leaf count".to_owned(),
        ));
    }
    Ok(peaks)
}

pub(crate) fn canonical_range_layout(old_size: u64, new_size: u64) -> Result<Vec<NodeCoordinate>> {
    validate_leaf_count(old_size)?;
    validate_leaf_count(new_size)?;
    if old_size > new_size {
        return Err(Error::InvalidInput(format!(
            "old history size {old_size} exceeds new size {new_size}"
        )));
    }

    let mut cursor = old_size;
    let mut output = Vec::new();
    while cursor < new_size {
        let remaining = new_size - cursor;
        let remaining_height = u8::try_from(remaining.ilog2())
            .map_err(|_| Error::InvalidInput("range height exceeds u8".to_owned()))?;
        let alignment_height = if cursor == 0 {
            63
        } else {
            u8::try_from(cursor.trailing_zeros().min(63))
                .map_err(|_| Error::InvalidInput("alignment height exceeds u8".to_owned()))?
        };
        let height = remaining_height.min(alignment_height);
        output.push(NodeCoordinate {
            start: cursor,
            height,
        });
        cursor = cursor.checked_add(subtree_width(height)).ok_or_else(|| {
            Error::InvalidInput("consistency range arithmetic overflow".to_owned())
        })?;
    }
    Ok(output)
}

pub(crate) const fn subtree_width(height: u8) -> u64 {
    1_u64 << height
}

#[cfg(feature = "storage")]
pub(crate) fn node_position(coordinate: NodeCoordinate) -> Result<u64> {
    let width = subtree_width(coordinate.height);
    if !coordinate.start.is_multiple_of(width) {
        return Err(Error::InvalidInput(format!(
            "node start {} is not aligned for height {}",
            coordinate.start, coordinate.height
        )));
    }
    let end_exclusive = coordinate
        .start
        .checked_add(width)
        .ok_or_else(|| Error::InvalidInput("node leaf range overflows u64".to_owned()))?;
    if end_exclusive > MAX_HISTORY_LEAVES {
        return Err(Error::InvalidInput(
            "node leaf range exceeds the MMR v1 limit".to_owned(),
        ));
    }
    let end = end_exclusive - 1;
    let position = u128::from(end)
        .checked_mul(2)
        .and_then(|value| value.checked_sub(u128::from(end.count_ones())))
        .and_then(|value| value.checked_add(u128::from(coordinate.height)))
        .ok_or_else(|| Error::InvalidInput("MMR position arithmetic overflow".to_owned()))?;
    u64::try_from(position).map_err(|_| Error::InvalidInput("MMR position exceeds u64".to_owned()))
}

pub(crate) fn parent_hash(parent_height: u8, left: Hash32, right: Hash32) -> Result<Hash32> {
    if !(1..=63).contains(&parent_height) {
        return Err(Error::InvalidInput(format!(
            "parent height {parent_height} is outside 1..=63"
        )));
    }
    let mut payload = Vec::with_capacity(1 + 1 + 32 + 32);
    payload.push(PARENT_KIND);
    payload.push(parent_height);
    payload.extend_from_slice(left.as_bytes());
    payload.extend_from_slice(right.as_bytes());
    hash_with_domain(DomainV1::HistoryNode, &payload).map_err(Into::into)
}

pub(crate) fn root_from_peaks(leaf_count: u64, peaks: &[Peak]) -> Result<Hash32> {
    let expected = peak_layout(leaf_count)?;
    if peaks.len() != expected.len()
        || peaks
            .iter()
            .zip(&expected)
            .any(|(peak, coordinate)| peak.coordinate != *coordinate)
    {
        return Err(Error::InvalidInput(
            "peak coordinates do not match the leaf count".to_owned(),
        ));
    }
    let hashes: Vec<_> = peaks.iter().map(|peak| peak.hash).collect();
    root_from_peak_hashes(leaf_count, &hashes)
}

pub(crate) fn root_from_peak_hashes(leaf_count: u64, hashes: &[Hash32]) -> Result<Hash32> {
    let layout = peak_layout(leaf_count)?;
    if hashes.len() != layout.len() {
        return Err(Error::InvalidInput(format!(
            "history size {leaf_count} requires {} peaks, got {}",
            layout.len(),
            hashes.len()
        )));
    }
    let peak_count = u16::try_from(hashes.len())
        .map_err(|_| Error::InvalidInput("peak count exceeds u16".to_owned()))?;
    let mut payload = Vec::with_capacity(1 + 8 + 2 + hashes.len() * 33);
    payload.push(ROOT_KIND);
    payload.extend_from_slice(&leaf_count.to_be_bytes());
    payload.extend_from_slice(&peak_count.to_be_bytes());
    for (coordinate, hash) in layout.iter().zip(hashes) {
        payload.push(coordinate.height);
        payload.extend_from_slice(hash.as_bytes());
    }
    hash_with_domain(DomainV1::HistoryNode, &payload).map_err(Into::into)
}

pub(crate) fn merge_peak(peaks: &mut Vec<Peak>, mut carry: Peak) -> Result<()> {
    while peaks
        .last()
        .is_some_and(|peak| peak.coordinate.height == carry.coordinate.height)
    {
        let left = peaks.pop().ok_or_else(|| {
            Error::InvalidInput("MMR peak stack unexpectedly became empty".to_owned())
        })?;
        let width = subtree_width(left.coordinate.height);
        let expected_right = left
            .coordinate
            .start
            .checked_add(width)
            .ok_or_else(|| Error::InvalidInput("MMR peak range overflow".to_owned()))?;
        if carry.coordinate.start != expected_right {
            return Err(Error::InvalidInput(
                "MMR carry is not adjacent to the left peak".to_owned(),
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
    }
    peaks.push(carry);
    Ok(())
}
