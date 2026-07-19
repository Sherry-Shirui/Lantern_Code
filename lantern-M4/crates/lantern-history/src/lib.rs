#![forbid(unsafe_code)]
#![doc = "Append-only MMR history and storage-independent proof verifiers."]

mod error;
mod proof;
#[cfg(feature = "storage")]
mod storage;
mod structure;

pub use error::{Error, Result};
pub use proof::{
    HISTORY_PROOF_FORMAT_VERSION, HistoryConsistencyProofV1, HistoryConsistencyQueryV1,
    HistoryInclusionProofV1, HistoryInclusionQueryV1, MAX_HISTORY_PROOF_BYTES,
    verify_history_consistency, verify_history_inclusion,
};
#[cfg(feature = "storage")]
pub use storage::{HistoryAppendStats, HistoryLog, HistoryState, PreparedHistoryAppend};
pub use structure::{
    MAX_HISTORY_APPEND_BYTES, MAX_HISTORY_APPEND_RECORDS, MAX_HISTORY_LEAVES,
    MAX_HISTORY_RECORD_BYTES, empty_history_root, history_leaf_hash, mmr_node_count,
};

#[cfg(all(test, feature = "storage"))]
mod tests;
