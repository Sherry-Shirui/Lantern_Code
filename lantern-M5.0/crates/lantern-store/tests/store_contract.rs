use std::{
    env, fs,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use lantern_store::{
    ColumnFamily, CommitMetadataV1, Durability, REQUIRED_COLUMN_FAMILY_NAMES, ReadStore,
    RocksStore, SnapshotSource, StoreBatch, StoreIdentityV1,
};
use lantern_types::{Hash32, NetworkId};
use rocksdb::{DB, Options};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const CRASH_CHILD_ENV: &str = "LANTERN_STORE_CRASH_CHILD";
const CRASH_PATH_ENV: &str = "LANTERN_STORE_CRASH_PATH";
const CRASH_READY_ENV: &str = "LANTERN_STORE_CRASH_READY";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "lantern-store-{label}-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn hash(byte: u8) -> Hash32 {
    Hash32::new([byte; 32])
}

fn identity() -> Result<StoreIdentityV1, lantern_types::Error> {
    Ok(StoreIdentityV1::new(
        NetworkId::new("lantern-m1-test")?,
        hash(0x90),
    ))
}

fn metadata(height: u64, history_size: u64, epoch: u64) -> CommitMetadataV1 {
    let height_byte = u8::try_from(height).unwrap_or(u8::MAX);
    let epoch_byte = u8::try_from(epoch).unwrap_or(u8::MAX);
    CommitMetadataV1 {
        app_height: height,
        app_hash: hash(height_byte),
        latest_root: hash(0x20_u8.saturating_add(height_byte)),
        history_root: hash(0x40_u8.saturating_add(height_byte)),
        history_size,
        last_closed_epoch: (epoch > 0).then_some(epoch),
        last_closed_head_id: (epoch > 0).then(|| hash(0x60_u8.saturating_add(epoch_byte))),
        validator_config_hash: hash(0x80),
        config_hash: hash(0x90),
    }
}

#[test]
fn creates_exact_column_family_layout_and_checks_identity() -> TestResult {
    let temporary = TestDirectory::new("layout")?;
    let database = temporary.child("db");
    let expected_identity = identity()?;
    {
        let store = RocksStore::open(&database, &expected_identity)?;
        assert_eq!(store.identity(), &expected_identity);
        assert_eq!(store.current_metadata()?, None);
    }

    let mut actual = DB::list_cf(&Options::default(), &database)?;
    actual.sort();
    let mut expected = vec!["default".to_owned()];
    expected.extend(REQUIRED_COLUMN_FAMILY_NAMES.map(str::to_owned));
    expected.sort();
    assert_eq!(actual, expected);

    let reopened = RocksStore::open(&database, &expected_identity)?;
    drop(reopened);
    let wrong_identity = StoreIdentityV1::new(NetworkId::new("wrong-chain")?, hash(0x90));
    let error = RocksStore::open(&database, &wrong_identity).err();
    assert!(error.is_some());

    let mut raw_database =
        DB::open_cf(&Options::default(), &database, REQUIRED_COLUMN_FAMILY_NAMES)?;
    raw_database.create_cf("unexpected", &Options::default())?;
    drop(raw_database);
    assert!(RocksStore::open(&database, &expected_identity).is_err());
    Ok(())
}

#[test]
fn commits_all_column_families_and_metadata_atomically_then_reopens() -> TestResult {
    let temporary = TestDirectory::new("atomic")?;
    let database = temporary.child("db");
    let expected_identity = identity()?;
    {
        let store = RocksStore::open(&database, &expected_identity)?;
        let mut batch = StoreBatch::new();
        let fixtures = [
            (
                ColumnFamily::Records,
                b"record".as_slice(),
                b"r1".as_slice(),
            ),
            (
                ColumnFamily::IntentArchive,
                b"intent".as_slice(),
                b"i1".as_slice(),
            ),
            (
                ColumnFamily::LatestTreeNodes,
                b"latest".as_slice(),
                b"l1".as_slice(),
            ),
            (ColumnFamily::MmrNodes, b"mmr".as_slice(), b"m1".as_slice()),
            (
                ColumnFamily::ProofIndex,
                b"proof".as_slice(),
                b"p1".as_slice(),
            ),
            (
                ColumnFamily::Idempotency,
                b"nonce".as_slice(),
                b"n1".as_slice(),
            ),
            (
                ColumnFamily::ConfigReconfiguration,
                b"config".as_slice(),
                b"c1".as_slice(),
            ),
        ];
        for (column_family, key, value) in fixtures {
            batch.put(column_family, key, value)?;
        }
        let receipt = store.commit_block(batch, &metadata(1, 7, 0), Durability::SyncWal)?;
        assert_eq!(receipt.operation_count, fixtures.len() + 1);
        assert!(receipt.wal_synced);
        for (column_family, key, value) in fixtures {
            assert_eq!(store.get(column_family, key)?, Some(value.to_vec()));
        }
        assert_eq!(store.current_metadata()?, Some(metadata(1, 7, 0)));
    }

    let reopened = RocksStore::open(&database, &expected_identity)?;
    assert_eq!(
        reopened.get(ColumnFamily::Records, b"record")?,
        Some(b"r1".to_vec())
    );
    assert_eq!(reopened.current_metadata()?, Some(metadata(1, 7, 0)));
    Ok(())
}

#[test]
fn epoch_zero_presence_survives_commit_reopen_and_snapshot_restore() -> TestResult {
    let temporary = TestDirectory::new("epoch-zero")?;
    let database = temporary.child("db");
    let checkpoint = temporary.child("checkpoint");
    let restored_path = temporary.child("restored");
    let expected_identity = identity()?;
    let mut epoch_zero = metadata(1, 1, 0);
    epoch_zero.last_closed_epoch = Some(0);
    epoch_zero.last_closed_head_id = Some(hash(0x60));
    {
        let store = RocksStore::open(&database, &expected_identity)?;
        let mut batch = StoreBatch::new();
        batch.put(ColumnFamily::Records, b"epoch-zero", b"present")?;
        store.commit_block(batch, &epoch_zero, Durability::SyncWal)?;
        assert_eq!(store.current_metadata()?, Some(epoch_zero.clone()));
        let manifest = store.create_checkpoint(&checkpoint)?;
        assert_eq!(manifest.last_closed_epoch, Some(0));
        assert_eq!(manifest.last_closed_head_id, Some(hash(0x60).to_hex()));
    }
    let reopened = RocksStore::open(&database, &expected_identity)?;
    assert_eq!(reopened.current_metadata()?, Some(epoch_zero.clone()));
    drop(reopened);
    let restored = RocksStore::restore_checkpoint(&checkpoint, &restored_path, &expected_identity)?;
    assert_eq!(restored.current_metadata()?, Some(epoch_zero));
    Ok(())
}

#[test]
fn read_snapshot_remains_consistent_across_a_later_atomic_commit() -> TestResult {
    let temporary = TestDirectory::new("read-snapshot")?;
    let store = RocksStore::open(temporary.child("db"), &identity()?)?;
    let mut first = StoreBatch::new();
    first.put(ColumnFamily::Records, b"record", b"before")?;
    first.put(ColumnFamily::MmrNodes, b"node", b"before")?;
    store.commit_block(first, &metadata(1, 1, 0), Durability::Wal)?;

    let snapshot = store.read_snapshot();
    let mut second = StoreBatch::new();
    second.put(ColumnFamily::Records, b"record-2", b"after")?;
    second.put(ColumnFamily::MmrNodes, b"node-2", b"after")?;
    store.commit_block(second, &metadata(2, 2, 0), Durability::Wal)?;

    assert_eq!(snapshot.get(ColumnFamily::Records, b"record-2")?, None);
    assert_eq!(snapshot.get(ColumnFamily::MmrNodes, b"node-2")?, None);
    assert_eq!(
        store.get(ColumnFamily::Records, b"record-2")?,
        Some(b"after".to_vec())
    );
    assert_eq!(
        store.get(ColumnFamily::MmrNodes, b"node-2")?,
        Some(b"after".to_vec())
    );
    Ok(())
}

#[test]
fn rejected_or_discarded_batches_leave_no_partial_state() -> TestResult {
    let temporary = TestDirectory::new("discard")?;
    let database = temporary.child("db");
    let expected_identity = identity()?;
    {
        let store = RocksStore::open(&database, &expected_identity)?;
        let mut skipped = StoreBatch::new();
        skipped.put(ColumnFamily::Records, b"skipped", b"must-not-appear")?;
        assert!(
            store
                .commit_block(skipped, &metadata(2, 1, 0), Durability::Wal)
                .is_err()
        );
        assert_eq!(store.get(ColumnFamily::Records, b"skipped")?, None);

        let mut discarded = StoreBatch::new();
        discarded.put(ColumnFamily::Records, b"discarded", b"must-not-appear")?;
        drop(discarded);
    }
    let reopened = RocksStore::open(&database, &expected_identity)?;
    assert_eq!(reopened.get(ColumnFamily::Records, b"skipped")?, None);
    assert_eq!(reopened.get(ColumnFamily::Records, b"discarded")?, None);
    assert_eq!(reopened.current_metadata()?, None);
    Ok(())
}

#[test]
fn enforces_batch_and_commit_metadata_invariants() -> TestResult {
    let mut batch = StoreBatch::new();
    assert!(batch.put(ColumnFamily::Records, [], b"value").is_err());
    batch.put(ColumnFamily::Records, b"duplicate", b"one")?;
    assert!(
        batch
            .put(ColumnFamily::Records, b"duplicate", b"two")
            .is_err()
    );
    assert!(
        StoreBatch::new()
            .put(
                ColumnFamily::Metadata,
                b"lantern/commit-metadata/v1",
                b"forbidden"
            )
            .is_err()
    );

    let temporary = TestDirectory::new("invariants")?;
    let store = RocksStore::open(temporary.child("db"), &identity()?)?;
    store.commit_block(StoreBatch::new(), &metadata(1, 5, 1), Durability::Wal)?;

    let mut history_regression = metadata(2, 4, 1);
    history_regression.last_closed_head_id = metadata(1, 5, 1).last_closed_head_id;
    assert!(
        store
            .commit_block(StoreBatch::new(), &history_regression, Durability::Wal)
            .is_err()
    );
    let mut changed_head = metadata(2, 5, 1);
    changed_head.last_closed_head_id = Some(hash(0xee));
    assert!(
        store
            .commit_block(StoreBatch::new(), &changed_head, Durability::Wal)
            .is_err()
    );
    assert_eq!(store.current_metadata()?, Some(metadata(1, 5, 1)));
    Ok(())
}

#[test]
fn checkpoint_verification_and_atomic_restore_round_trip() -> TestResult {
    let temporary = TestDirectory::new("checkpoint")?;
    let database = temporary.child("db");
    let checkpoint = temporary.child("checkpoint");
    let restored_path = temporary.child("restored");
    let expected_identity = identity()?;
    let store = RocksStore::open(&database, &expected_identity)?;
    let mut batch = StoreBatch::new();
    batch.put(ColumnFamily::Records, b"record", b"checkpointed")?;
    batch.put(ColumnFamily::MmrNodes, b"node", b"checkpointed")?;
    store.commit_block(batch, &metadata(1, 2, 1), Durability::SyncWal)?;

    let manifest = store.create_checkpoint(&checkpoint)?;
    assert_eq!(manifest.app_height, 1);
    assert!(!manifest.files.is_empty());
    assert!(
        manifest
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
    let verified = RocksStore::verify_checkpoint(&checkpoint, &expected_identity)?;
    assert_eq!(verified.manifest(), &manifest);

    let restored = RocksStore::restore_checkpoint(&checkpoint, &restored_path, &expected_identity)?;
    assert_eq!(restored.current_metadata()?, Some(metadata(1, 2, 1)));
    assert_eq!(
        restored.get(ColumnFamily::Records, b"record")?,
        Some(b"checkpointed".to_vec())
    );
    assert!(
        RocksStore::restore_checkpoint(&checkpoint, &restored_path, &expected_identity).is_err()
    );
    Ok(())
}

#[test]
fn corrupted_checkpoint_is_rejected_before_destination_publish() -> TestResult {
    let temporary = TestDirectory::new("corrupt-checkpoint")?;
    let checkpoint = temporary.child("checkpoint");
    let destination = temporary.child("must-stay-absent");
    let expected_identity = identity()?;
    let store = RocksStore::open(temporary.child("db"), &expected_identity)?;
    store.commit_block(StoreBatch::new(), &metadata(1, 0, 0), Durability::SyncWal)?;
    let manifest = store.create_checkpoint(&checkpoint)?;
    let first_nonempty = manifest
        .files
        .iter()
        .find(|file| file.size > 0)
        .ok_or_else(|| std::io::Error::other("checkpoint has no non-empty file"))?;
    let corrupt_path = checkpoint.join("db").join(&first_nonempty.path);
    let mut file = fs::OpenOptions::new().write(true).open(&corrupt_path)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(b"X")?;
    file.sync_all()?;

    assert!(RocksStore::verify_checkpoint(&checkpoint, &expected_identity).is_err());
    assert!(RocksStore::restore_checkpoint(&checkpoint, &destination, &expected_identity).is_err());
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn checkpoint_rejects_wrong_chain_identity() -> TestResult {
    let temporary = TestDirectory::new("wrong-chain-checkpoint")?;
    let checkpoint = temporary.child("checkpoint");
    let store = RocksStore::open(temporary.child("db"), &identity()?)?;
    store.commit_block(StoreBatch::new(), &metadata(1, 0, 0), Durability::Wal)?;
    store.create_checkpoint(&checkpoint)?;
    let wrong = StoreIdentityV1::new(NetworkId::new("other-chain")?, hash(0x90));
    assert!(RocksStore::verify_checkpoint(&checkpoint, &wrong).is_err());
    Ok(())
}

#[test]
fn old_schema_and_truncated_manifests_fail_before_restore_publish() -> TestResult {
    let temporary = TestDirectory::new("manifest-negative")?;
    let expected_identity = identity()?;
    let store = RocksStore::open(temporary.child("db"), &expected_identity)?;
    store.commit_block(StoreBatch::new(), &metadata(1, 0, 0), Durability::Wal)?;

    let old_schema = temporary.child("old-schema");
    store.create_checkpoint(&old_schema)?;
    let old_manifest_path = old_schema.join("manifest.json");
    let mut document: serde_json::Value = serde_json::from_slice(&fs::read(&old_manifest_path)?)?;
    document["store_schema_version"] = serde_json::Value::from(0);
    let mut old_manifest = serde_json::to_vec_pretty(&document)?;
    old_manifest.push(b'\n');
    fs::write(&old_manifest_path, old_manifest)?;
    let old_destination = temporary.child("old-schema-destination");
    assert!(
        RocksStore::restore_checkpoint(&old_schema, &old_destination, &expected_identity).is_err()
    );
    assert!(!old_destination.exists());

    let truncated = temporary.child("truncated");
    store.create_checkpoint(&truncated)?;
    let truncated_manifest_path = truncated.join("manifest.json");
    fs::write(&truncated_manifest_path, b"{")?;
    let truncated_destination = temporary.child("truncated-destination");
    assert!(
        RocksStore::restore_checkpoint(&truncated, &truncated_destination, &expected_identity)
            .is_err()
    );
    assert!(!truncated_destination.exists());
    Ok(())
}

#[test]
fn wal_commit_survives_sigkill_without_destructors() -> TestResult {
    let temporary = TestDirectory::new("wal-crash")?;
    let database = temporary.child("db");
    let ready = temporary.child("committed.ready");
    let mut child = Command::new(env::current_exe()?)
        .arg("--exact")
        .arg("crash_writer_child")
        .arg("--nocapture")
        .env(CRASH_CHILD_ENV, "1")
        .env(CRASH_PATH_ENV, &database)
        .env(CRASH_READY_ENV, &ready)
        .spawn()?;
    let committed = (0..500).any(|_| {
        if ready.is_file() {
            true
        } else {
            thread::sleep(Duration::from_millis(10));
            false
        }
    });
    if !committed {
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(std::io::Error::other("child did not report a committed WAL batch").into());
    }
    child.kill()?;
    let status = child.wait()?;
    assert!(!status.success());

    let reopened = RocksStore::open(&database, &identity()?)?;
    assert_eq!(
        reopened.get(ColumnFamily::Records, b"after-rocksdb-commit")?,
        Some(b"durable-via-wal".to_vec())
    );
    assert_eq!(reopened.current_metadata()?, Some(metadata(1, 1, 0)));
    Ok(())
}

#[test]
fn crash_writer_child() -> TestResult {
    if env::var_os(CRASH_CHILD_ENV).is_none() {
        return Ok(());
    }
    let database = env::var_os(CRASH_PATH_ENV)
        .ok_or_else(|| std::io::Error::other("missing crash child database path"))?;
    let ready = env::var_os(CRASH_READY_ENV)
        .ok_or_else(|| std::io::Error::other("missing crash child ready path"))?;
    let store = RocksStore::open(PathBuf::from(database), &identity()?)?;
    let mut batch = StoreBatch::new();
    batch.put(
        ColumnFamily::Records,
        b"after-rocksdb-commit",
        b"durable-via-wal",
    )?;
    store.commit_block(batch, &metadata(1, 1, 0), Durability::Wal)?;
    fs::write(PathBuf::from(ready), b"committed")?;
    loop {
        thread::sleep(Duration::from_mins(1));
    }
}
