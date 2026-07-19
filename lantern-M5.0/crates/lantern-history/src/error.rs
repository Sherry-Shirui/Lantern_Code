/// M3 history result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Typed errors returned by the history MMR and independent verifiers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A caller supplied an out-of-range size, index, or record.
    #[error("invalid history input: {0}")]
    InvalidInput(String),
    /// A proof envelope is malformed, unsupported, non-canonical, or too large.
    #[error("invalid history-proof encoding: {0}")]
    InvalidProofEncoding(String),
    /// A well-formed proof does not authenticate the expected statement.
    #[error("history-proof verification failed: {0}")]
    ProofVerification(String),
    /// The requested prefix root has not been committed.
    #[error("history prefix of {0} leaves is not committed")]
    MissingSize(u64),
    /// A required immutable MMR node is missing.
    #[error("history MMR node at postorder position {0} is missing")]
    MissingNode(u64),
    /// Persisted history bytes violate the frozen M3 storage format.
    #[error("corrupt history storage: {0}")]
    CorruptStorage(String),
    /// M0 domain framing or hashing failed.
    #[error(transparent)]
    Types(#[from] lantern_types::Error),
    /// M1 could not complete a backend-neutral read or batch append.
    #[cfg(feature = "storage")]
    #[error(transparent)]
    Storage(#[from] lantern_store::Error),
}
