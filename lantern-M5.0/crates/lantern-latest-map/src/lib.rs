#![forbid(unsafe_code)]
#![doc = "Versioned JMT latest-state map and storage-independent proof verifier."]

mod error;
mod proof;
#[cfg(feature = "storage")]
mod storage;

pub use error::{Error, Result};
pub use proof::{
    LATEST_PROOF_FORMAT_VERSION, LatestProofV1, LatestQueryV1, MAX_LATEST_PROOF_BYTES,
    MAX_LATEST_VALUE_BYTES, empty_latest_root, latest_key, latest_leaf_bytes, verify_latest_proof,
};
#[cfg(feature = "storage")]
pub use storage::{LatestMap, LatestMutationV1, LatestUpdateStats, PreparedLatestUpdate};

#[cfg(all(test, feature = "storage"))]
mod tests;
