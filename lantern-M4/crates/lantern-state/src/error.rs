use lantern_types::Hash32;

/// M4 preparation, recovery, or commit failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid state-machine input: {0}")]
    InvalidInput(String),
    #[error("committed state is missing or inconsistent: {0}")]
    CorruptState(String),
    #[error("epoch catch-up requires {required} heads, limit is {limit}")]
    EpochBacklog { required: u64, limit: u16 },
    #[error("prepared block was built for config {prepared}, store expects another identity")]
    ConfigMismatch { prepared: Hash32 },
    #[error("M0 schema error: {0}")]
    Types(#[from] lantern_types::Error),
    #[error("M1 storage error: {0}")]
    Store(#[from] lantern_store::Error),
    #[error("M2 latest-map error: {0}")]
    Latest(#[from] lantern_latest_map::Error),
    #[error("M3 history error: {0}")]
    History(#[from] lantern_history::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
