use lantern_types::Hash32;

use crate::{
    Error, Result,
    structure::{
        NodeCoordinate, Peak, canonical_range_layout, history_leaf_hash, merge_peak, parent_hash,
        peak_layout, root_from_peak_hashes, root_from_peaks, subtree_width,
    },
};

const INCLUSION_MAGIC: [u8; 8] = *b"LNHINCL\0";
const CONSISTENCY_MAGIC: [u8; 8] = *b"LNHCONS\0";
const PROOF_HEADER_BYTES: usize = 8 + 2 + 4;
const PROOF_BODY_FIXED_BYTES: usize = 8 + 8 + 2 + 2;
const HASH_BYTES: usize = 32;

/// Version of both deterministic Lantern MMR proof envelopes.
pub const HISTORY_PROOF_FORMAT_VERSION: u16 = 1;
/// Maximum accepted encoded MMR proof size, including the envelope.
pub const MAX_HISTORY_PROOF_BYTES: usize = 32 * 1024;

/// Opaque proof that one exact record occupies one MMR leaf at a prefix size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInclusionProofV1 {
    leaf_index: u64,
    leaf_count: u64,
    siblings: Vec<Hash32>,
    peaks: Vec<Hash32>,
}

impl HistoryInclusionProofV1 {
    pub(crate) fn from_parts(
        leaf_index: u64,
        leaf_count: u64,
        siblings: Vec<Hash32>,
        peaks: Vec<Hash32>,
    ) -> Result<Self> {
        let proof = Self {
            leaf_index,
            leaf_count,
            siblings,
            peaks,
        };
        proof.validate_structure()?;
        Ok(proof)
    }

    /// Stable zero-based leaf index authenticated by the proof.
    #[must_use]
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Exact MMR prefix size authenticated by the proof.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Decodes a strict, size-bounded inclusion-proof envelope.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, unknown-version, trailing, or
    /// structurally impossible proof bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let body = decode_envelope(bytes, INCLUSION_MAGIC)?;
        let leaf_index = read_u64(body, 0)?;
        let leaf_count = read_u64(body, 8)?;
        let sibling_count = usize::from(read_u16(body, 16)?);
        let peak_count = usize::from(read_u16(body, 18)?);
        let expected = proof_body_length(sibling_count, peak_count)?;
        if body.len() != expected {
            return Err(Error::InvalidProofEncoding(format!(
                "inclusion body is {} bytes; counts require {expected}",
                body.len()
            )));
        }
        let siblings = read_hashes(body, PROOF_BODY_FIXED_BYTES, sibling_count)?;
        let peaks = read_hashes(
            body,
            PROOF_BODY_FIXED_BYTES + sibling_count * HASH_BYTES,
            peak_count,
        )?;
        Self::from_parts(leaf_index, leaf_count, siblings, peaks)
    }

    /// Encodes this proof in the deterministic M3 inclusion envelope.
    ///
    /// # Errors
    ///
    /// Rejects an internally impossible or oversized proof.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        encode_proof_body(
            INCLUSION_MAGIC,
            self.leaf_index,
            self.leaf_count,
            &self.siblings,
            &self.peaks,
        )
    }

    fn validate_structure(&self) -> Result<()> {
        let layout = peak_layout(self.leaf_count).map_err(proof_encoding_error)?;
        if self.leaf_index >= self.leaf_count {
            return Err(Error::InvalidProofEncoding(format!(
                "leaf index {} is outside prefix size {}",
                self.leaf_index, self.leaf_count
            )));
        }
        let (_, target) = target_peak(&layout, self.leaf_index).ok_or_else(|| {
            Error::InvalidProofEncoding("leaf is not covered by an MMR peak".to_owned())
        })?;
        if self.siblings.len() != usize::from(target.height) {
            return Err(Error::InvalidProofEncoding(format!(
                "target peak height {} requires {} siblings, got {}",
                target.height,
                target.height,
                self.siblings.len()
            )));
        }
        if self.peaks.len() != layout.len() {
            return Err(Error::InvalidProofEncoding(format!(
                "prefix size {} requires {} peaks, got {}",
                self.leaf_count,
                layout.len(),
                self.peaks.len()
            )));
        }
        Ok(())
    }
}

/// Opaque proof that one MMR prefix is an append-only ancestor of another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryConsistencyProofV1 {
    old_size: u64,
    new_size: u64,
    old_peaks: Vec<Hash32>,
    appended_subtrees: Vec<Hash32>,
}

impl HistoryConsistencyProofV1 {
    pub(crate) fn from_parts(
        old_size: u64,
        new_size: u64,
        old_peaks: Vec<Hash32>,
        appended_subtrees: Vec<Hash32>,
    ) -> Result<Self> {
        let proof = Self {
            old_size,
            new_size,
            old_peaks,
            appended_subtrees,
        };
        proof.validate_structure()?;
        Ok(proof)
    }

    /// Older MMR prefix size.
    #[must_use]
    pub const fn old_size(&self) -> u64 {
        self.old_size
    }

    /// Newer MMR prefix size.
    #[must_use]
    pub const fn new_size(&self) -> u64 {
        self.new_size
    }

    /// Decodes a strict, size-bounded consistency-proof envelope.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, unknown-version, trailing, or
    /// non-canonical range proofs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let body = decode_envelope(bytes, CONSISTENCY_MAGIC)?;
        let old_size = read_u64(body, 0)?;
        let new_size = read_u64(body, 8)?;
        let old_peak_count = usize::from(read_u16(body, 16)?);
        let appended_count = usize::from(read_u16(body, 18)?);
        let expected = proof_body_length(old_peak_count, appended_count)?;
        if body.len() != expected {
            return Err(Error::InvalidProofEncoding(format!(
                "consistency body is {} bytes; counts require {expected}",
                body.len()
            )));
        }
        let old_peaks = read_hashes(body, PROOF_BODY_FIXED_BYTES, old_peak_count)?;
        let appended_subtrees = read_hashes(
            body,
            PROOF_BODY_FIXED_BYTES + old_peak_count * HASH_BYTES,
            appended_count,
        )?;
        Self::from_parts(old_size, new_size, old_peaks, appended_subtrees)
    }

    /// Encodes this proof in the deterministic M3 consistency envelope.
    ///
    /// # Errors
    ///
    /// Rejects an internally impossible or oversized proof.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        encode_proof_body(
            CONSISTENCY_MAGIC,
            self.old_size,
            self.new_size,
            &self.old_peaks,
            &self.appended_subtrees,
        )
    }

    fn validate_structure(&self) -> Result<()> {
        let old_layout = peak_layout(self.old_size).map_err(proof_encoding_error)?;
        let range_layout =
            canonical_range_layout(self.old_size, self.new_size).map_err(proof_encoding_error)?;
        if self.old_peaks.len() != old_layout.len() {
            return Err(Error::InvalidProofEncoding(format!(
                "old size {} requires {} peaks, got {}",
                self.old_size,
                old_layout.len(),
                self.old_peaks.len()
            )));
        }
        if self.appended_subtrees.len() != range_layout.len() {
            return Err(Error::InvalidProofEncoding(format!(
                "canonical range [{}, {}) requires {} subtrees, got {}",
                self.old_size,
                self.new_size,
                range_layout.len(),
                self.appended_subtrees.len()
            )));
        }
        Ok(())
    }
}

/// Complete storage-produced inclusion result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryInclusionQueryV1 {
    /// Exact historical MMR root.
    pub root: Hash32,
    /// Stable zero-based leaf index.
    pub leaf_index: u64,
    /// Exact MMR prefix size.
    pub leaf_count: u64,
    /// Exact canonical compact record bytes.
    pub record: Vec<u8>,
    /// Inclusion proof under `root`.
    pub proof: HistoryInclusionProofV1,
}

impl HistoryInclusionQueryV1 {
    /// Verifies the complete result without storage.
    ///
    /// # Errors
    ///
    /// Rejects metadata disagreement or an invalid record/proof/root tuple.
    pub fn verify(&self) -> Result<()> {
        if self.leaf_index != self.proof.leaf_index || self.leaf_count != self.proof.leaf_count {
            return Err(Error::ProofVerification(
                "query metadata differs from the inclusion proof".to_owned(),
            ));
        }
        verify_history_inclusion(self.root, &self.record, &self.proof)
    }
}

/// Complete storage-produced append-consistency result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryConsistencyQueryV1 {
    /// Authenticated older root.
    pub old_root: Hash32,
    /// Authenticated newer root.
    pub new_root: Hash32,
    /// Older prefix size.
    pub old_size: u64,
    /// Newer prefix size.
    pub new_size: u64,
    /// Append-consistency proof.
    pub proof: HistoryConsistencyProofV1,
}

impl HistoryConsistencyQueryV1 {
    /// Verifies this append-only relationship without storage.
    ///
    /// # Errors
    ///
    /// Rejects metadata disagreement or a proof that does not bind both roots.
    pub fn verify(&self) -> Result<()> {
        if self.old_size != self.proof.old_size || self.new_size != self.proof.new_size {
            return Err(Error::ProofVerification(
                "query sizes differ from the consistency proof".to_owned(),
            ));
        }
        verify_history_consistency(self.old_root, self.new_root, &self.proof)
    }
}

/// Verifies one exact record's inclusion without consulting storage.
///
/// # Errors
///
/// Rejects an invalid record, malformed proof structure, or root mismatch.
pub fn verify_history_inclusion(
    root: Hash32,
    record: &[u8],
    proof: &HistoryInclusionProofV1,
) -> Result<()> {
    proof.validate_structure()?;
    let layout = peak_layout(proof.leaf_count).map_err(proof_verification_error)?;
    let (target_index, _) = target_peak(&layout, proof.leaf_index)
        .ok_or_else(|| Error::ProofVerification("leaf is not covered by an MMR peak".to_owned()))?;

    let mut current = history_leaf_hash(proof.leaf_index, record)?;
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let parent_height = u8::try_from(level + 1)
            .map_err(|_| Error::ProofVerification("inclusion path height exceeds u8".to_owned()))?;
        let bit = u32::try_from(level)
            .map_err(|_| Error::ProofVerification("path level exceeds u32".to_owned()))?;
        current = if (proof.leaf_index >> bit) & 1 == 0 {
            parent_hash(parent_height, current, *sibling)?
        } else {
            parent_hash(parent_height, *sibling, current)?
        };
    }
    if proof.peaks.get(target_index) != Some(&current) {
        return Err(Error::ProofVerification(
            "inclusion path does not reconstruct the target peak".to_owned(),
        ));
    }
    let calculated =
        root_from_peak_hashes(proof.leaf_count, &proof.peaks).map_err(proof_verification_error)?;
    if calculated != root {
        return Err(Error::ProofVerification(format!(
            "calculated history root {calculated} differs from expected {root}"
        )));
    }
    Ok(())
}

/// Verifies that `new_root` is obtained only by appending leaves after
/// `old_root`.
///
/// # Errors
///
/// Rejects malformed proof structure, either root mismatch, or an invalid MMR
/// carry sequence.
pub fn verify_history_consistency(
    old_root: Hash32,
    new_root: Hash32,
    proof: &HistoryConsistencyProofV1,
) -> Result<()> {
    proof.validate_structure()?;
    let old_calculated = root_from_peak_hashes(proof.old_size, &proof.old_peaks)
        .map_err(proof_verification_error)?;
    if old_calculated != old_root {
        return Err(Error::ProofVerification(format!(
            "calculated old root {old_calculated} differs from expected {old_root}"
        )));
    }

    let old_layout = peak_layout(proof.old_size).map_err(proof_verification_error)?;
    let mut peaks: Vec<_> = old_layout
        .into_iter()
        .zip(&proof.old_peaks)
        .map(|(coordinate, hash)| Peak {
            coordinate,
            hash: *hash,
        })
        .collect();
    let range_layout =
        canonical_range_layout(proof.old_size, proof.new_size).map_err(proof_verification_error)?;
    for (coordinate, hash) in range_layout.into_iter().zip(&proof.appended_subtrees) {
        merge_peak(
            &mut peaks,
            Peak {
                coordinate,
                hash: *hash,
            },
        )
        .map_err(proof_verification_error)?;
    }
    let calculated = root_from_peaks(proof.new_size, &peaks).map_err(proof_verification_error)?;
    if calculated != new_root {
        return Err(Error::ProofVerification(format!(
            "calculated new root {calculated} differs from expected {new_root}"
        )));
    }
    Ok(())
}

fn target_peak(layout: &[NodeCoordinate], leaf_index: u64) -> Option<(usize, NodeCoordinate)> {
    layout.iter().copied().enumerate().find(|(_, coordinate)| {
        coordinate
            .start
            .checked_add(subtree_width(coordinate.height))
            .is_some_and(|end| (coordinate.start..end).contains(&leaf_index))
    })
}

fn encode_proof_body(
    magic: [u8; 8],
    first: u64,
    second: u64,
    first_hashes: &[Hash32],
    second_hashes: &[Hash32],
) -> Result<Vec<u8>> {
    let first_count = u16::try_from(first_hashes.len()).map_err(|_| {
        Error::InvalidProofEncoding("first proof hash count exceeds u16".to_owned())
    })?;
    let second_count = u16::try_from(second_hashes.len()).map_err(|_| {
        Error::InvalidProofEncoding("second proof hash count exceeds u16".to_owned())
    })?;
    let body_length = proof_body_length(first_hashes.len(), second_hashes.len())?;
    let total_length = PROOF_HEADER_BYTES
        .checked_add(body_length)
        .ok_or_else(|| Error::InvalidProofEncoding("proof length overflow".to_owned()))?;
    if total_length > MAX_HISTORY_PROOF_BYTES {
        return Err(Error::InvalidProofEncoding(format!(
            "history proof is {total_length} bytes; limit is {MAX_HISTORY_PROOF_BYTES}"
        )));
    }
    let body_length_u32 = u32::try_from(body_length)
        .map_err(|_| Error::InvalidProofEncoding("proof body exceeds u32".to_owned()))?;
    let mut output = Vec::with_capacity(total_length);
    output.extend_from_slice(&magic);
    output.extend_from_slice(&HISTORY_PROOF_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&body_length_u32.to_be_bytes());
    output.extend_from_slice(&first.to_be_bytes());
    output.extend_from_slice(&second.to_be_bytes());
    output.extend_from_slice(&first_count.to_be_bytes());
    output.extend_from_slice(&second_count.to_be_bytes());
    for hash in first_hashes.iter().chain(second_hashes) {
        output.extend_from_slice(hash.as_bytes());
    }
    Ok(output)
}

fn decode_envelope(bytes: &[u8], magic: [u8; 8]) -> Result<&[u8]> {
    if !(PROOF_HEADER_BYTES + PROOF_BODY_FIXED_BYTES..=MAX_HISTORY_PROOF_BYTES)
        .contains(&bytes.len())
    {
        return Err(Error::InvalidProofEncoding(format!(
            "history proof is {} bytes; expected {}..={MAX_HISTORY_PROOF_BYTES}",
            bytes.len(),
            PROOF_HEADER_BYTES + PROOF_BODY_FIXED_BYTES
        )));
    }
    if bytes.get(..8) != Some(magic.as_slice()) {
        return Err(Error::InvalidProofEncoding(
            "proof magic does not identify the expected Lantern history proof".to_owned(),
        ));
    }
    let version = read_u16(bytes, 8)?;
    if version != HISTORY_PROOF_FORMAT_VERSION {
        return Err(Error::InvalidProofEncoding(format!(
            "history proof version {version} is unsupported"
        )));
    }
    let body_length = usize::try_from(read_u32(bytes, 10)?)
        .map_err(|_| Error::InvalidProofEncoding("proof length exceeds usize".to_owned()))?;
    let expected = PROOF_HEADER_BYTES
        .checked_add(body_length)
        .ok_or_else(|| Error::InvalidProofEncoding("proof length overflow".to_owned()))?;
    if bytes.len() != expected {
        return Err(Error::InvalidProofEncoding(format!(
            "proof declares {body_length} body bytes but total length is {}",
            bytes.len()
        )));
    }
    Ok(&bytes[PROOF_HEADER_BYTES..])
}

fn proof_body_length(first_count: usize, second_count: usize) -> Result<usize> {
    first_count
        .checked_add(second_count)
        .and_then(|count| count.checked_mul(HASH_BYTES))
        .and_then(|bytes| bytes.checked_add(PROOF_BODY_FIXED_BYTES))
        .ok_or_else(|| Error::InvalidProofEncoding("proof count arithmetic overflow".to_owned()))
}

fn read_hashes(bytes: &[u8], offset: usize, count: usize) -> Result<Vec<Hash32>> {
    let mut hashes = Vec::with_capacity(count);
    for index in 0..count {
        let start = offset
            .checked_add(index.checked_mul(HASH_BYTES).ok_or_else(|| {
                Error::InvalidProofEncoding("proof hash offset overflow".to_owned())
            })?)
            .ok_or_else(|| Error::InvalidProofEncoding("proof hash offset overflow".to_owned()))?;
        let end = start
            .checked_add(HASH_BYTES)
            .ok_or_else(|| Error::InvalidProofEncoding("proof hash end overflow".to_owned()))?;
        let hash: [u8; HASH_BYTES] = bytes
            .get(start..end)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| Error::InvalidProofEncoding("truncated proof hash".to_owned()))?;
        hashes.push(Hash32::new(hash));
    }
    Ok(hashes)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| Error::InvalidProofEncoding("truncated proof u16".to_owned()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| Error::InvalidProofEncoding("truncated proof u32".to_owned()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| Error::InvalidProofEncoding("truncated proof u64".to_owned()))
}

fn proof_encoding_error(error: impl std::fmt::Display) -> Error {
    Error::InvalidProofEncoding(error.to_string())
}

fn proof_verification_error(error: impl std::fmt::Display) -> Error {
    Error::ProofVerification(error.to_string())
}

#[cfg(test)]
mod tests {
    use lantern_types::{DomainV1, hash_with_domain};

    use super::*;
    use crate::structure::{NodeCoordinate, Peak, merge_peak, root_from_peaks};

    fn forest(records: &[Vec<u8>]) -> Result<(Vec<Peak>, Vec<Vec<Hash32>>)> {
        let mut peaks = Vec::new();
        let mut snapshots = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let leaf_index = u64::try_from(index)
                .map_err(|_| Error::InvalidInput("test index exceeds u64".to_owned()))?;
            merge_peak(
                &mut peaks,
                Peak {
                    coordinate: NodeCoordinate {
                        start: leaf_index,
                        height: 0,
                    },
                    hash: history_leaf_hash(leaf_index, record)?,
                },
            )?;
            snapshots.push(peaks.iter().map(|peak| peak.hash).collect());
        }
        Ok((peaks, snapshots))
    }

    fn inclusion_fixture() -> Result<(Hash32, Vec<u8>, HistoryInclusionProofV1)> {
        let records: Vec<_> = (0_u8..7).map(|value| vec![value, value + 1]).collect();
        let (peaks, _) = forest(&records)?;
        let root = root_from_peaks(7, &peaks)?;
        let leaf_index = 2;
        let leaf = history_leaf_hash(2, &records[2])?;
        let sibling = history_leaf_hash(3, &records[3])?;
        let left = parent_hash(
            1,
            history_leaf_hash(0, &records[0])?,
            history_leaf_hash(1, &records[1])?,
        )?;
        let siblings = vec![sibling, left];
        let peak_hashes = peaks.iter().map(|peak| peak.hash).collect();
        let proof = HistoryInclusionProofV1::from_parts(leaf_index, 7, siblings, peak_hashes)?;
        let expected_peak = parent_hash(2, left, parent_hash(1, leaf, sibling)?)?;
        assert_eq!(proof.peaks[0], expected_peak);
        Ok((root, records[2].clone(), proof))
    }

    #[test]
    fn proof_only_inclusion_verifier_round_trips() -> Result<()> {
        let (root, record, proof) = inclusion_fixture()?;
        verify_history_inclusion(root, &record, &proof)?;
        let bytes = proof.to_bytes()?;
        let decoded = HistoryInclusionProofV1::from_bytes(&bytes)?;
        assert_eq!(decoded, proof);
        verify_history_inclusion(root, &record, &decoded)
    }

    #[test]
    fn proof_only_consistency_verifier_round_trips() -> Result<()> {
        let records: Vec<_> = (0_u8..11).map(|value| vec![value]).collect();
        let (_, snapshots) = forest(&records)?;
        let old_size = 5;
        let new_size = 11;
        let old_root = root_from_peak_hashes(old_size, &snapshots[4])?;
        let new_root = root_from_peak_hashes(new_size, &snapshots[10])?;

        let old_peaks = snapshots[4].clone();
        let range = canonical_range_layout(old_size, new_size)?;
        let mut appended = Vec::new();
        for coordinate in range {
            let start = usize::try_from(coordinate.start)
                .map_err(|_| Error::InvalidInput("test range exceeds usize".to_owned()))?;
            let width = usize::try_from(subtree_width(coordinate.height))
                .map_err(|_| Error::InvalidInput("test width exceeds usize".to_owned()))?;
            let (subtree, _) = forest(&records[start..start + width])?;
            let relative_hashes: Vec<_> = subtree.iter().map(|peak| peak.hash).collect();
            if relative_hashes.len() != 1 {
                return Err(Error::InvalidInput(
                    "perfect test range did not produce one peak".to_owned(),
                ));
            }
            // `forest` hashes relative indices; rebuild this small perfect tree
            // with the absolute indices used by the protocol.
            appended.push(perfect_subtree_hash(&records, coordinate)?);
        }
        let proof = HistoryConsistencyProofV1::from_parts(old_size, new_size, old_peaks, appended)?;
        verify_history_consistency(old_root, new_root, &proof)?;
        let decoded = HistoryConsistencyProofV1::from_bytes(&proof.to_bytes()?)?;
        assert_eq!(decoded, proof);
        verify_history_consistency(old_root, new_root, &decoded)
    }

    fn perfect_subtree_hash(records: &[Vec<u8>], coordinate: NodeCoordinate) -> Result<Hash32> {
        let width = subtree_width(coordinate.height);
        if coordinate.height == 0 {
            let index = usize::try_from(coordinate.start)
                .map_err(|_| Error::InvalidInput("test index exceeds usize".to_owned()))?;
            return history_leaf_hash(coordinate.start, &records[index]);
        }
        let child_height = coordinate.height - 1;
        let left = NodeCoordinate {
            start: coordinate.start,
            height: child_height,
        };
        let right = NodeCoordinate {
            start: coordinate.start + width / 2,
            height: child_height,
        };
        parent_hash(
            coordinate.height,
            perfect_subtree_hash(records, left)?,
            perfect_subtree_hash(records, right)?,
        )
    }

    #[test]
    fn malformed_and_mutated_proofs_fail_closed() -> Result<()> {
        let (root, record, proof) = inclusion_fixture()?;
        let bytes = proof.to_bytes()?;
        assert!(HistoryInclusionProofV1::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(HistoryInclusionProofV1::from_bytes(&bad_magic).is_err());
        let mut bad_version = bytes.clone();
        bad_version[9] = 2;
        assert!(HistoryInclusionProofV1::from_bytes(&bad_version).is_err());
        assert!(
            HistoryInclusionProofV1::from_bytes(&vec![0; MAX_HISTORY_PROOF_BYTES + 1]).is_err()
        );

        let mut wrong_root_bytes = *root.as_bytes();
        wrong_root_bytes[0] ^= 1;
        assert!(verify_history_inclusion(Hash32::new(wrong_root_bytes), &record, &proof).is_err());
        assert!(verify_history_inclusion(root, b"wrong-record", &proof).is_err());

        let mut leaf_payload = Vec::new();
        leaf_payload.push(0);
        leaf_payload.extend_from_slice(&proof.leaf_index.to_be_bytes());
        leaf_payload.extend_from_slice(
            &u64::try_from(record.len())
                .map_err(|_| Error::InvalidInput("test record exceeds u64".to_owned()))?
                .to_be_bytes(),
        );
        leaf_payload.extend_from_slice(&record);
        let wrong_domain = hash_with_domain(DomainV1::HistoryNode, &leaf_payload)?;
        assert_ne!(wrong_domain, history_leaf_hash(proof.leaf_index, &record)?);

        let mut mutated = bytes;
        let hash_offset = PROOF_HEADER_BYTES + PROOF_BODY_FIXED_BYTES;
        mutated[hash_offset] ^= 1;
        if let Ok(decoded) = HistoryInclusionProofV1::from_bytes(&mutated) {
            assert!(verify_history_inclusion(root, &record, &decoded).is_err());
        }
        Ok(())
    }
}
