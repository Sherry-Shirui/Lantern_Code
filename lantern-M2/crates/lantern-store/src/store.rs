use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use rocksdb::{
    ColumnFamily as RocksColumnFamily, ColumnFamilyDescriptor, DB, Options, Snapshot, WriteBatch,
    WriteOptions,
};

use crate::{
    ColumnFamily, CommitMetadataV1, CommitReceipt, Durability, Error, Result, StoreBatch,
    StoreIdentityV1,
    batch::{BatchOperation, COMMIT_METADATA_KEY, IDENTITY_KEY},
};

/// Read-only key/value interface consumed by M2 and M3.
pub trait ReadStore {
    /// Reads one key from one logical column family.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the read cannot be completed.
    fn get(&self, column_family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Tests whether one key is present.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the read cannot be completed.
    fn contains_key(&self, column_family: ColumnFamily, key: &[u8]) -> Result<bool> {
        self.get(column_family, key).map(|value| value.is_some())
    }
}

/// Block-commit interface; every implementation must apply the batch and
/// typed commit metadata together or apply neither.
pub trait BlockStore: ReadStore {
    /// Commits one block's backend-neutral batch with WAL enabled.
    ///
    /// # Errors
    ///
    /// Rejects invalid/non-successor metadata, an invalid batch, or a backend
    /// commit error.
    fn commit_block(
        &self,
        batch: StoreBatch,
        metadata: &CommitMetadataV1,
        durability: Durability,
    ) -> Result<CommitReceipt>;
}

/// Provider of a consistent point-in-time read view.
pub trait SnapshotSource: ReadStore {
    /// Concrete snapshot tied to the borrow of the source store.
    type Snapshot<'a>: ReadStore
    where
        Self: 'a;

    /// Captures a consistent point-in-time read snapshot.
    fn read_snapshot(&self) -> Self::Snapshot<'_>;
}

/// Concrete RocksDB-backed Lantern store.
pub struct RocksStore {
    pub(crate) db: DB,
    pub(crate) path: PathBuf,
    pub(crate) identity: StoreIdentityV1,
    pub(crate) coordination: Mutex<()>,
}

impl RocksStore {
    /// Creates a new database or opens an existing database with the exact M1
    /// column-family layout and identity.
    ///
    /// # Errors
    ///
    /// Rejects unknown/missing column families, missing identity metadata,
    /// schema mismatches, or a different chain/config identity.
    pub fn open(path: impl AsRef<Path>, identity: &StoreIdentityV1) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let existing = path.join("CURRENT").is_file();
        if existing {
            validate_existing_layout(&path)?;
        }

        let mut database_options = Options::default();
        database_options.create_if_missing(!existing);
        database_options.create_missing_column_families(!existing);
        database_options.set_unordered_write(false);
        database_options.set_manual_wal_flush(false);
        database_options.set_atomic_flush(true);

        let descriptors =
            std::iter::once(ColumnFamilyDescriptor::new("default", Options::default())).chain(
                ColumnFamily::ALL.into_iter().map(|column_family| {
                    ColumnFamilyDescriptor::new(column_family.name(), Options::default())
                }),
            );
        let db = DB::open_cf_descriptors(&database_options, &path, descriptors)?;
        let store = Self {
            db,
            path,
            identity: identity.clone(),
            coordination: Mutex::new(()),
        };

        if existing {
            let stored = store.read_identity()?.ok_or_else(|| {
                Error::Metadata("existing database has no store identity".to_owned())
            })?;
            if stored != *identity {
                return Err(Error::IdentityMismatch(format!(
                    "stored chain/config is {}/{}, requested {}/{}",
                    stored.chain_id(),
                    stored.config_hash(),
                    identity.chain_id(),
                    identity.config_hash()
                )));
            }
        } else {
            store.initialize_identity()?;
        }
        Ok(store)
    }

    /// Returns the immutable database identity.
    #[must_use]
    pub const fn identity(&self) -> &StoreIdentityV1 {
        &self.identity
    }

    /// Returns the database directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the last atomically committed application metadata, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when `RocksDB` cannot read the value or the fixed-width
    /// metadata encoding is invalid.
    pub fn current_metadata(&self) -> Result<Option<CommitMetadataV1>> {
        self.get(ColumnFamily::Metadata, COMMIT_METADATA_KEY)?
            .map(|bytes| CommitMetadataV1::decode(&bytes))
            .transpose()
    }

    /// Atomically commits block writes and typed application metadata in one
    /// `RocksDB` `WriteBatch`.
    ///
    /// # Errors
    ///
    /// Rejects a non-successor height, metadata regression, a changed immutable
    /// config hash, or any invalid batch operation.
    pub fn commit_block(
        &self,
        mut batch: StoreBatch,
        metadata: &CommitMetadataV1,
        durability: Durability,
    ) -> Result<CommitReceipt> {
        metadata.validate()?;
        if metadata.config_hash != self.identity.config_hash() {
            return Err(Error::Metadata(format!(
                "commit config hash {} differs from database identity {}",
                metadata.config_hash,
                self.identity.config_hash()
            )));
        }
        let guard = self.lock_coordination()?;
        let previous = self.current_metadata()?;
        validate_successor(previous.as_ref(), metadata)?;
        batch.put_reserved(
            ColumnFamily::Metadata,
            COMMIT_METADATA_KEY,
            &metadata.encode()?,
        )?;
        self.commit_locked(&batch, durability, &guard)
    }

    pub(crate) fn lock_coordination(&self) -> Result<MutexGuard<'_, ()>> {
        self.coordination.lock().map_err(|_| Error::LockPoisoned)
    }

    pub(crate) fn column_family(&self, column_family: ColumnFamily) -> Result<&RocksColumnFamily> {
        self.db
            .cf_handle(column_family.name())
            .ok_or(Error::MissingColumnFamily(column_family.name()))
    }

    fn initialize_identity(&self) -> Result<()> {
        let mut batch = StoreBatch::new();
        batch.put_reserved(
            ColumnFamily::Metadata,
            IDENTITY_KEY,
            &self.identity.encode()?,
        )?;
        let guard = self.lock_coordination()?;
        self.commit_locked(&batch, Durability::SyncWal, &guard)?;
        Ok(())
    }

    fn read_identity(&self) -> Result<Option<StoreIdentityV1>> {
        self.get(ColumnFamily::Metadata, IDENTITY_KEY)?
            .map(|bytes| StoreIdentityV1::decode(&bytes))
            .transpose()
    }

    fn commit_locked(
        &self,
        batch: &StoreBatch,
        durability: Durability,
        _guard: &MutexGuard<'_, ()>,
    ) -> Result<CommitReceipt> {
        if batch.is_empty() {
            return Err(Error::InvalidBatch(
                "an empty batch cannot be committed".to_owned(),
            ));
        }
        let receipt = CommitReceipt {
            operation_count: batch.operation_count(),
            payload_bytes: batch.payload_bytes(),
            wal_synced: durability.sync(),
        };
        let mut rocks_batch = WriteBatch::default();
        for operation in batch.operations() {
            match operation {
                BatchOperation::Put {
                    column_family,
                    key,
                    value,
                } => rocks_batch.put_cf(self.column_family(*column_family)?, key, value),
                BatchOperation::Delete { column_family, key } => {
                    rocks_batch.delete_cf(self.column_family(*column_family)?, key);
                }
            }
        }
        let mut options = WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(durability.sync());
        self.db.write_opt(rocks_batch, &options)?;
        Ok(receipt)
    }
}

impl ReadStore for RocksStore {
    fn get(&self, column_family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db
            .get_cf(self.column_family(column_family)?, key)
            .map_err(Into::into)
    }
}

impl BlockStore for RocksStore {
    fn commit_block(
        &self,
        batch: StoreBatch,
        metadata: &CommitMetadataV1,
        durability: Durability,
    ) -> Result<CommitReceipt> {
        Self::commit_block(self, batch, metadata, durability)
    }
}

impl SnapshotSource for RocksStore {
    type Snapshot<'a> = ReadSnapshot<'a>;

    fn read_snapshot(&self) -> Self::Snapshot<'_> {
        ReadSnapshot {
            store: self,
            snapshot: self.db.snapshot(),
        }
    }
}

/// Consistent point-in-time `RocksDB` read view.
pub struct ReadSnapshot<'a> {
    store: &'a RocksStore,
    snapshot: Snapshot<'a>,
}

impl ReadStore for ReadSnapshot<'_> {
    fn get(&self, column_family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.snapshot
            .get_cf(self.store.column_family(column_family)?, key)
            .map_err(Into::into)
    }
}

fn validate_existing_layout(path: &Path) -> Result<()> {
    let mut actual = DB::list_cf(&Options::default(), path)?;
    actual.sort();
    let mut expected = vec!["default".to_owned()];
    expected.extend(
        ColumnFamily::ALL
            .into_iter()
            .map(|column_family| column_family.name().to_owned()),
    );
    expected.sort();
    if actual != expected {
        return Err(Error::ColumnFamilyLayout(format!(
            "found {actual:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

fn validate_successor(previous: Option<&CommitMetadataV1>, next: &CommitMetadataV1) -> Result<()> {
    let expected_height = previous.map_or(Ok(1), |metadata| {
        metadata
            .app_height
            .checked_add(1)
            .ok_or_else(|| Error::Metadata("application height overflow".to_owned()))
    })?;
    if next.app_height != expected_height {
        return Err(Error::Metadata(format!(
            "commit height {} is not the required successor {expected_height}",
            next.app_height
        )));
    }
    let Some(previous) = previous else {
        return Ok(());
    };
    if next.history_size < previous.history_size {
        return Err(Error::Metadata(format!(
            "history size regressed from {} to {}",
            previous.history_size, next.history_size
        )));
    }
    if next.last_closed_epoch < previous.last_closed_epoch {
        return Err(Error::Metadata(format!(
            "closed epoch regressed from {} to {}",
            previous.last_closed_epoch, next.last_closed_epoch
        )));
    }
    if next.last_closed_epoch == previous.last_closed_epoch
        && next.last_closed_head_id != previous.last_closed_head_id
    {
        return Err(Error::Metadata(
            "closed HeadID changed without advancing the closed epoch".to_owned(),
        ));
    }
    Ok(())
}
