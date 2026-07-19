use std::{io, path::PathBuf};

/// Errors returned by the M1 persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `RocksDB` rejected an operation.
    #[error("RocksDB error: {0}")]
    RocksDb(String),

    /// A filesystem operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// Description of the failed operation.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The database column-family layout is not the M1 layout.
    #[error("invalid column-family layout: {0}")]
    ColumnFamilyLayout(String),

    /// A required column-family handle was unexpectedly absent.
    #[error("required column family is unavailable: {0}")]
    MissingColumnFamily(&'static str),

    /// A batch violated a defensive limit or a reserved-key rule.
    #[error("invalid atomic batch: {0}")]
    InvalidBatch(String),

    /// Stored metadata was malformed or violated a state invariant.
    #[error("invalid store metadata: {0}")]
    Metadata(String),

    /// The on-disk database identity differs from the requested identity.
    #[error("database identity mismatch: {0}")]
    IdentityMismatch(String),

    /// A checkpoint or snapshot manifest failed validation.
    #[error("invalid checkpoint: {0}")]
    Checkpoint(String),

    /// Snapshot JSON was malformed.
    #[error("snapshot manifest JSON error: {0}")]
    Json(String),

    /// The internal commit/checkpoint mutex was poisoned.
    #[error("store coordination lock is poisoned")]
    LockPoisoned,
}

impl Error {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }
}

impl From<rocksdb::Error> for Error {
    fn from(error: rocksdb::Error) -> Self {
        Self::RocksDb(error.into_string())
    }
}

/// Result type used by `lantern-store`.
pub type Result<T> = std::result::Result<T, Error>;
