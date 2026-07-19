use std::collections::BTreeSet;

use crate::{ColumnFamily, Error, Result};

/// Maximum number of operations accepted in one logical batch.
pub const MAX_BATCH_OPERATIONS: usize = 1_000_000;
/// Maximum total key/value bytes accepted in one logical batch.
pub const MAX_BATCH_BYTES: usize = 256 * 1024 * 1024;
/// Maximum key length accepted by the storage boundary.
pub const MAX_KEY_BYTES: usize = 64 * 1024;
/// Maximum value length accepted by the storage boundary.
pub const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) const IDENTITY_KEY: &[u8] = b"lantern/store-identity/v1";
pub(crate) const COMMIT_METADATA_KEY: &[u8] = b"lantern/commit-metadata/v1";

/// Durability requested for one atomic `RocksDB` write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Append to the enabled WAL before returning; rely on the OS page cache.
    Wal,
    /// Append to the WAL and synchronously flush it before returning.
    SyncWal,
}

impl Durability {
    pub(crate) const fn sync(self) -> bool {
        matches!(self, Self::SyncWal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BatchOperation {
    Put {
        column_family: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        column_family: ColumnFamily,
        key: Vec<u8>,
    },
}

/// Backend-neutral collection of writes committed by one `RocksDB` `WriteBatch`.
///
/// Duplicate `(column family, key)` operations are rejected so the final state
/// cannot depend on accidental last-write-wins ordering inside a block.
#[derive(Debug, Default, Clone)]
pub struct StoreBatch {
    operations: Vec<BatchOperation>,
    touched_keys: BTreeSet<(ColumnFamily, Vec<u8>)>,
    payload_bytes: usize,
}

impl StoreBatch {
    /// Creates an empty, uncommitted batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: Vec::new(),
            touched_keys: BTreeSet::new(),
            payload_bytes: 0,
        }
    }

    /// Adds one put operation.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized keys, oversized values, reserved metadata keys,
    /// duplicate keys, and batches over the configured defensive limits.
    pub fn put(
        &mut self,
        column_family: ColumnFamily,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.put_inner(column_family, key.as_ref(), value.as_ref(), false)
    }

    /// Adds one delete operation.
    ///
    /// # Errors
    ///
    /// Applies the same key, reserved-key, duplicate, and batch-size checks as
    /// [`Self::put`].
    pub fn delete(&mut self, column_family: ColumnFamily, key: impl AsRef<[u8]>) -> Result<()> {
        let key = key.as_ref();
        validate_key(column_family, key, false)?;
        self.reserve_operation(column_family, key, key.len())?;
        self.operations.push(BatchOperation::Delete {
            column_family,
            key: key.to_vec(),
        });
        Ok(())
    }

    /// Returns the number of operations in the uncommitted batch.
    #[must_use]
    pub const fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Returns the total key/value payload bytes in the batch.
    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// Returns whether the batch contains no operations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub(crate) fn put_reserved(
        &mut self,
        column_family: ColumnFamily,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        self.put_inner(column_family, key, value, true)
    }

    pub(crate) fn operations(&self) -> &[BatchOperation] {
        &self.operations
    }

    fn put_inner(
        &mut self,
        column_family: ColumnFamily,
        key: &[u8],
        value: &[u8],
        allow_reserved: bool,
    ) -> Result<()> {
        validate_key(column_family, key, allow_reserved)?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(Error::InvalidBatch(format!(
                "value is {} bytes; limit is {MAX_VALUE_BYTES}",
                value.len()
            )));
        }
        let operation_bytes = key
            .len()
            .checked_add(value.len())
            .ok_or_else(|| Error::InvalidBatch("operation byte count overflow".to_owned()))?;
        self.reserve_operation(column_family, key, operation_bytes)?;
        self.operations.push(BatchOperation::Put {
            column_family,
            key: key.to_vec(),
            value: value.to_vec(),
        });
        Ok(())
    }

    fn reserve_operation(
        &mut self,
        column_family: ColumnFamily,
        key: &[u8],
        operation_bytes: usize,
    ) -> Result<()> {
        if self.operations.len() >= MAX_BATCH_OPERATIONS {
            return Err(Error::InvalidBatch(format!(
                "operation count exceeds {MAX_BATCH_OPERATIONS}"
            )));
        }
        let new_bytes = self
            .payload_bytes
            .checked_add(operation_bytes)
            .ok_or_else(|| Error::InvalidBatch("batch byte count overflow".to_owned()))?;
        if new_bytes > MAX_BATCH_BYTES {
            return Err(Error::InvalidBatch(format!(
                "batch payload would be {new_bytes} bytes; limit is {MAX_BATCH_BYTES}"
            )));
        }
        if !self.touched_keys.insert((column_family, key.to_vec())) {
            return Err(Error::InvalidBatch(format!(
                "duplicate key {} in column family {}",
                hex::encode(key),
                column_family.name()
            )));
        }
        self.payload_bytes = new_bytes;
        Ok(())
    }
}

fn validate_key(column_family: ColumnFamily, key: &[u8], allow_reserved: bool) -> Result<()> {
    if key.is_empty() {
        return Err(Error::InvalidBatch("keys must not be empty".to_owned()));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(Error::InvalidBatch(format!(
            "key is {} bytes; limit is {MAX_KEY_BYTES}",
            key.len()
        )));
    }
    if !allow_reserved
        && column_family == ColumnFamily::Metadata
        && matches!(key, IDENTITY_KEY | COMMIT_METADATA_KEY)
    {
        return Err(Error::InvalidBatch(
            "reserved metadata keys require a typed store operation".to_owned(),
        ));
    }
    Ok(())
}

/// Observable result of one successful atomic commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Number of put/delete operations written atomically.
    pub operation_count: usize,
    /// Total key/value payload bytes submitted to `RocksDB`.
    pub payload_bytes: usize,
    /// Whether `RocksDB` synchronously flushed the WAL before returning.
    pub wal_synced: bool,
}
