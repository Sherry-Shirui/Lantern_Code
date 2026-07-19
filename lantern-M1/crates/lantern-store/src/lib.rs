#![forbid(unsafe_code)]
#![doc = "Atomic `RocksDB` persistence and verified checkpoints for Lantern."]

mod batch;
mod cf;
mod error;
mod metadata;
mod snapshot;
mod store;

pub use batch::{
    CommitReceipt, Durability, MAX_BATCH_BYTES, MAX_BATCH_OPERATIONS, MAX_KEY_BYTES,
    MAX_VALUE_BYTES, StoreBatch,
};
pub use cf::{ColumnFamily, REQUIRED_COLUMN_FAMILY_NAMES};
pub use error::{Error, Result};
pub use metadata::{CommitMetadataV1, STORE_SCHEMA_VERSION, StoreIdentityV1};
pub use snapshot::{
    SNAPSHOT_FORMAT_VERSION, SnapshotFileDigestV1, SnapshotManifestV1, VerifiedCheckpoint,
};
pub use store::{BlockStore, ReadSnapshot, ReadStore, RocksStore, SnapshotSource};
