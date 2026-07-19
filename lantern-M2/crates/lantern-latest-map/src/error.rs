/// M2 latest-map result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Typed errors returned by the latest-map and its independent verifier.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A caller supplied a non-canonical or out-of-range value.
    #[error("invalid latest-map input: {0}")]
    InvalidInput(String),
    /// A proof envelope is malformed, unsupported, or too large.
    #[error("invalid latest-proof encoding: {0}")]
    InvalidProofEncoding(String),
    /// A well-formed proof does not authenticate the expected tuple.
    #[error("latest-proof verification failed: {0}")]
    ProofVerification(String),
    /// The requested historical version has no committed root.
    #[error("latest-map version {0} is not committed")]
    MissingVersion(u64),
    /// An update does not extend the committed version sequence by exactly one.
    #[error("latest-map update version {actual} does not follow {previous:?}")]
    NonSuccessorVersion {
        /// Last committed version, or `None` before genesis.
        previous: Option<u64>,
        /// Proposed version.
        actual: u64,
    },
    /// Persisted latest-map bytes violate the frozen M2 storage format.
    #[error("corrupt latest-map storage: {0}")]
    CorruptStorage(String),
    /// JMT rejected a read or update.
    #[error("JMT operation failed: {0}")]
    Jmt(String),
    /// M0 domain framing or hashing failed.
    #[error(transparent)]
    Types(#[from] lantern_types::Error),
    /// M1 could not complete a backend-neutral read or batch append.
    #[cfg(feature = "storage")]
    #[error(transparent)]
    Storage(#[from] lantern_store::Error),
}
