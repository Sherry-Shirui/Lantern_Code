use std::fmt;

use jmt::{KeyHash, RootHash, proof::SparseMerkleProof};
use lantern_types::{DomainV1, Hash32, domain_separated_message, hash_with_domain};

use crate::{Error, Result};

type JmtProof = SparseMerkleProof<sha2_jmt::Sha256>;

const PROOF_MAGIC: &[u8; 8] = b"LNLTPRF\0";
const PROOF_HEADER_BYTES: usize = 8 + 2 + 4;
#[cfg(feature = "storage")]
const DOMAIN_PREAMBLE: &[u8; 8] = b"LANTERN\0";

/// Version of the deterministic Lantern latest-proof envelope.
pub const LATEST_PROOF_FORMAT_VERSION: u16 = 1;
/// Maximum accepted encoded proof size, including the envelope.
pub const MAX_LATEST_PROOF_BYTES: usize = 32 * 1024;
/// Maximum raw latest-state value accepted by M2.
pub const MAX_LATEST_VALUE_BYTES: usize = 1024 * 1024;

/// Opaque, deterministic proof for one JMT membership or non-membership query.
///
/// The envelope is Lantern-owned, while its body is the Borsh encoding of the
/// proof type from the exactly pinned `jmt 0.12.0` dependency.
#[derive(Clone)]
pub struct LatestProofV1 {
    inner: JmtProof,
}

impl LatestProofV1 {
    #[cfg(any(feature = "storage", test))]
    pub(crate) const fn from_inner(inner: JmtProof) -> Self {
        Self { inner }
    }

    /// Decodes a size-bounded, versioned proof envelope.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, unknown-version, trailing, or invalid
    /// Borsh proof bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !(PROOF_HEADER_BYTES..=MAX_LATEST_PROOF_BYTES).contains(&bytes.len()) {
            return Err(Error::InvalidProofEncoding(format!(
                "proof is {} bytes; expected {PROOF_HEADER_BYTES}..={MAX_LATEST_PROOF_BYTES}",
                bytes.len()
            )));
        }
        if bytes.get(..PROOF_MAGIC.len()) != Some(PROOF_MAGIC) {
            return Err(Error::InvalidProofEncoding(
                "proof magic does not identify Lantern latest-proof v1".to_owned(),
            ));
        }
        let version = read_u16(bytes, 8)?;
        if version != LATEST_PROOF_FORMAT_VERSION {
            return Err(Error::InvalidProofEncoding(format!(
                "proof version {version} is unsupported"
            )));
        }
        let body_length = usize::try_from(read_u32(bytes, 10)?)
            .map_err(|_| Error::InvalidProofEncoding("proof length overflows usize".to_owned()))?;
        let expected_length = PROOF_HEADER_BYTES.checked_add(body_length).ok_or_else(|| {
            Error::InvalidProofEncoding("proof length arithmetic overflow".to_owned())
        })?;
        if bytes.len() != expected_length {
            return Err(Error::InvalidProofEncoding(format!(
                "proof envelope declares {body_length} body bytes but total length is {}",
                bytes.len()
            )));
        }
        let inner = borsh::from_slice(&bytes[PROOF_HEADER_BYTES..]).map_err(|error| {
            Error::InvalidProofEncoding(format!("invalid JMT proof body: {error}"))
        })?;
        Ok(Self { inner })
    }

    /// Encodes the proof using the deterministic M2 envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the pinned JMT proof unexpectedly exceeds M2's
    /// defensive bound or cannot be represented by the envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = borsh::to_vec(&self.inner).map_err(|error| {
            Error::InvalidProofEncoding(format!("cannot encode JMT proof: {error}"))
        })?;
        let body_length = u32::try_from(body.len()).map_err(|_| {
            Error::InvalidProofEncoding("JMT proof body is longer than u32".to_owned())
        })?;
        let total_length = PROOF_HEADER_BYTES
            .checked_add(body.len())
            .ok_or_else(|| Error::InvalidProofEncoding("proof length overflow".to_owned()))?;
        if total_length > MAX_LATEST_PROOF_BYTES {
            return Err(Error::InvalidProofEncoding(format!(
                "proof is {total_length} bytes; limit is {MAX_LATEST_PROOF_BYTES}"
            )));
        }
        let mut output = Vec::with_capacity(total_length);
        output.extend_from_slice(PROOF_MAGIC);
        output.extend_from_slice(&LATEST_PROOF_FORMAT_VERSION.to_be_bytes());
        output.extend_from_slice(&body_length.to_be_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }
}

impl fmt::Debug for LatestProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LatestProofV1")
            .field("jmt_proof", &self.inner)
            .finish()
    }
}

impl PartialEq for LatestProofV1 {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// Complete result of a historical latest-map query.
#[derive(Debug, Clone, PartialEq)]
pub struct LatestQueryV1 {
    /// Exact committed JMT version used by the query.
    pub version: u64,
    /// Root committed for `version`.
    pub root: Hash32,
    /// Domain-separated map key.
    pub key: Hash32,
    /// Raw Lantern latest-state value, or `None` for non-membership.
    pub value: Option<Vec<u8>>,
    /// Membership or non-membership proof under `root`.
    pub proof: LatestProofV1,
}

impl LatestQueryV1 {
    /// Verifies this result without consulting storage.
    ///
    /// # Errors
    ///
    /// Returns an error if any root, key, value, or proof component is
    /// inconsistent.
    pub fn verify(&self) -> Result<()> {
        verify_latest_proof(self.root, self.key, self.value.as_deref(), &self.proof)
    }
}

/// Derives `LatestKey = H(DOM_LATEST_KEY || CA_ID)` using M0 framing.
///
/// # Errors
///
/// Propagates a domain-framing failure.
pub fn latest_key(ca_id: Hash32) -> Result<Hash32> {
    hash_with_domain(DomainV1::LatestKey, ca_id.as_bytes()).map_err(Into::into)
}

/// Encodes a raw latest-state value in the `latest-leaf` protocol domain.
///
/// The resulting bytes, rather than the raw value, are supplied as JMT's
/// value. This keeps Lantern's protocol domain separate from JMT's own leaf
/// and internal-node hash domains.
///
/// # Errors
///
/// Rejects empty or oversized values and propagates framing failures.
pub fn latest_leaf_bytes(value: &[u8]) -> Result<Vec<u8>> {
    validate_raw_value(value)?;
    domain_separated_message(DomainV1::LatestLeaf, value).map_err(Into::into)
}

/// Verifies membership (`Some(value)`) or non-membership (`None`) without a
/// database, service, or `RocksDB` handle.
///
/// # Errors
///
/// Rejects an invalid expected value or a proof that does not bind the exact
/// root/key/value tuple.
pub fn verify_latest_proof(
    root: Hash32,
    key: Hash32,
    value: Option<&[u8]>,
    proof: &LatestProofV1,
) -> Result<()> {
    let root = RootHash(*root.as_bytes());
    let key = KeyHash(*key.as_bytes());
    let verification = match value {
        Some(value) => proof
            .inner
            .verify_existence(root, key, latest_leaf_bytes(value)?),
        None => proof.inner.verify_nonexistence(root, key),
    };
    verification.map_err(|error| Error::ProofVerification(error.to_string()))
}

#[cfg(feature = "storage")]
pub(crate) fn decode_latest_leaf_bytes(encoded: &[u8]) -> Result<Vec<u8>> {
    let domain = DomainV1::LatestLeaf.as_str().as_bytes();
    let header_length = DOMAIN_PREAMBLE
        .len()
        .checked_add(2)
        .and_then(|length| length.checked_add(domain.len()))
        .and_then(|length| length.checked_add(8))
        .ok_or_else(|| Error::CorruptStorage("latest-leaf header overflow".to_owned()))?;
    if encoded.len() < header_length || encoded.get(..8) != Some(DOMAIN_PREAMBLE) {
        return Err(Error::CorruptStorage(
            "latest-leaf value has an invalid preamble or is truncated".to_owned(),
        ));
    }
    let domain_length = usize::from(read_u16_corrupt(encoded, 8)?);
    if domain_length != domain.len() || encoded.get(10..10 + domain.len()) != Some(domain) {
        return Err(Error::CorruptStorage(
            "latest-leaf value has the wrong protocol domain".to_owned(),
        ));
    }
    let payload_offset = 10 + domain.len() + 8;
    let payload_length_u64 = read_u64_corrupt(encoded, 10 + domain.len())?;
    let payload_length = usize::try_from(payload_length_u64).map_err(|_| {
        Error::CorruptStorage("latest-leaf payload length overflows usize".to_owned())
    })?;
    let expected_length = payload_offset
        .checked_add(payload_length)
        .ok_or_else(|| Error::CorruptStorage("latest-leaf payload length overflow".to_owned()))?;
    if encoded.len() != expected_length {
        return Err(Error::CorruptStorage(format!(
            "latest-leaf declares {payload_length} payload bytes but has {} total bytes",
            encoded.len()
        )));
    }
    let payload = encoded[payload_offset..].to_vec();
    validate_raw_value(&payload).map_err(|error| Error::CorruptStorage(error.to_string()))?;
    Ok(payload)
}

fn validate_raw_value(value: &[u8]) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidInput(
            "latest-state value must not be empty".to_owned(),
        ));
    }
    if value.len() > MAX_LATEST_VALUE_BYTES {
        return Err(Error::InvalidInput(format!(
            "latest-state value is {} bytes; limit is {MAX_LATEST_VALUE_BYTES}",
            value.len()
        )));
    }
    Ok(())
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

#[cfg(feature = "storage")]
fn read_u16_corrupt(bytes: &[u8], offset: usize) -> Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| Error::CorruptStorage("truncated latest-leaf u16".to_owned()))
}

#[cfg(feature = "storage")]
fn read_u64_corrupt(bytes: &[u8], offset: usize) -> Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| Error::CorruptStorage("truncated latest-leaf u64".to_owned()))
}

#[cfg(test)]
mod tests {
    use jmt::{JellyfishMerkleTree, KeyHash, mock::MockTreeStore};
    use lantern_types::{DomainV1, Hash32, hash_with_domain};

    use super::*;

    fn proof_fixture() -> (Hash32, Hash32, Vec<u8>, LatestProofV1) {
        let store = MockTreeStore::default();
        let key = latest_key(Hash32::new([7; 32])).expect("fixed input hashes");
        let value = b"latest-state".to_vec();
        let tree = JellyfishMerkleTree::<_, sha2_jmt::Sha256>::new(&store);
        let (root, batch) = tree
            .put_value_set(
                [(
                    KeyHash(*key.as_bytes()),
                    Some(latest_leaf_bytes(&value).expect("value frames")),
                )],
                0,
            )
            .expect("fixture update succeeds");
        store
            .write_tree_update_batch(batch)
            .expect("fixture batch persists");
        let (_, proof) = tree
            .get_with_proof(KeyHash(*key.as_bytes()), 0)
            .expect("fixture proof exists");
        (
            Hash32::new(root.0),
            key,
            value,
            LatestProofV1::from_inner(proof),
        )
    }

    #[test]
    fn verifier_feature_does_not_need_storage() {
        let (root, key, value, proof) = proof_fixture();
        verify_latest_proof(root, key, Some(&value), &proof).expect("valid proof verifies");
    }

    #[test]
    fn proof_envelope_round_trips_and_rejects_malformed_inputs() {
        let (root, key, value, proof) = proof_fixture();
        let bytes = proof.to_bytes().expect("proof encodes");
        let decoded = LatestProofV1::from_bytes(&bytes).expect("proof decodes");
        assert_eq!(decoded, proof);
        verify_latest_proof(root, key, Some(&value), &decoded).expect("decoded proof verifies");

        assert!(LatestProofV1::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(LatestProofV1::from_bytes(&bad_magic).is_err());
        let mut bad_version = bytes.clone();
        bad_version[9] = 2;
        assert!(LatestProofV1::from_bytes(&bad_version).is_err());
        assert!(LatestProofV1::from_bytes(&vec![0; MAX_LATEST_PROOF_BYTES + 1]).is_err());
    }

    #[test]
    fn verifier_rejects_root_key_value_domain_and_proof_mutations() {
        let (root, key, value, proof) = proof_fixture();
        let mut wrong_root = root;
        let mut root_bytes = *wrong_root.as_bytes();
        root_bytes[0] ^= 1;
        wrong_root = Hash32::new(root_bytes);
        assert!(verify_latest_proof(wrong_root, key, Some(&value), &proof).is_err());

        let wrong_key = Hash32::new([3; 32]);
        assert!(verify_latest_proof(root, wrong_key, Some(&value), &proof).is_err());
        assert!(verify_latest_proof(root, key, Some(b"wrong-value"), &proof).is_err());
        assert!(verify_latest_proof(root, key, None, &proof).is_err());

        let wrong_domain =
            hash_with_domain(DomainV1::HistoryLeaf, &[7; 32]).expect("fixed input hashes");
        assert!(verify_latest_proof(root, wrong_domain, Some(&value), &proof).is_err());

        let mut proof_bytes = proof.to_bytes().expect("proof encodes");
        let last = proof_bytes.len() - 1;
        proof_bytes[last] ^= 1;
        if let Ok(mutated) = LatestProofV1::from_bytes(&proof_bytes) {
            assert!(verify_latest_proof(root, key, Some(&value), &mutated).is_err());
        }
    }
}
