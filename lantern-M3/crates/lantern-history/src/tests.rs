use std::collections::BTreeMap;
use std::{
    env, fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use lantern_store::{ColumnFamily, ReadStore, StoreBatch};
use lantern_types::{DomainV1, Hash32, hash_with_domain};
use proptest::prelude::*;

use crate::{
    Error, HistoryConsistencyProofV1, HistoryInclusionProofV1, HistoryLog,
    MAX_HISTORY_APPEND_RECORDS, MAX_HISTORY_PROOF_BYTES, MAX_HISTORY_RECORD_BYTES,
    empty_history_root, mmr_node_count, verify_history_consistency, verify_history_inclusion,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MemoryStore {
    values: BTreeMap<(ColumnFamily, Vec<u8>), Vec<u8>>,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "lantern-history-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn database(&self) -> PathBuf {
        self.0.join("db")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

impl MemoryStore {
    fn apply(&mut self, update: &crate::PreparedHistoryAppend) {
        for (key, value) in update.writes() {
            self.values
                .insert((ColumnFamily::MmrNodes, key.to_vec()), value.to_vec());
        }
    }
}

impl ReadStore for MemoryStore {
    fn get(
        &self,
        column_family: ColumnFamily,
        key: &[u8],
    ) -> lantern_store::Result<Option<Vec<u8>>> {
        Ok(self.values.get(&(column_family, key.to_vec())).cloned())
    }
}

fn reference_leaf(index: u64, record: &[u8]) -> Hash32 {
    let mut payload = Vec::with_capacity(17 + record.len());
    payload.push(0);
    payload.extend_from_slice(&index.to_be_bytes());
    payload.extend_from_slice(
        &u64::try_from(record.len())
            .expect("test records fit u64")
            .to_be_bytes(),
    );
    payload.extend_from_slice(record);
    hash_with_domain(DomainV1::HistoryLeaf, &payload).expect("test framing succeeds")
}

fn reference_parent(height: u8, left: Hash32, right: Hash32) -> Hash32 {
    let mut payload = Vec::with_capacity(66);
    payload.push(0);
    payload.push(height);
    payload.extend_from_slice(left.as_bytes());
    payload.extend_from_slice(right.as_bytes());
    hash_with_domain(DomainV1::HistoryNode, &payload).expect("test framing succeeds")
}

fn reference_subtree(records: &[Vec<u8>], start: usize, height: u8) -> Hash32 {
    if height == 0 {
        return reference_leaf(
            u64::try_from(start).expect("test index fits u64"),
            &records[start],
        );
    }
    let child_height = height - 1;
    let half = 1_usize << child_height;
    reference_parent(
        height,
        reference_subtree(records, start, child_height),
        reference_subtree(records, start + half, child_height),
    )
}

fn reference_root(records: &[Vec<u8>]) -> Hash32 {
    let count = u64::try_from(records.len()).expect("test length fits u64");
    let mut cursor = 0_usize;
    let mut peaks = Vec::new();
    for height in (0_u8..=63).rev() {
        if count & (1_u64 << height) != 0 {
            peaks.push((height, reference_subtree(records, cursor, height)));
            cursor += 1_usize << height;
        }
    }
    assert_eq!(cursor, records.len());
    let mut payload = Vec::with_capacity(11 + peaks.len() * 33);
    payload.push(1);
    payload.extend_from_slice(&count.to_be_bytes());
    payload.extend_from_slice(
        &u16::try_from(peaks.len())
            .expect("peak count fits u16")
            .to_be_bytes(),
    );
    for (height, hash) in peaks {
        payload.push(height);
        payload.extend_from_slice(hash.as_bytes());
    }
    hash_with_domain(DomainV1::HistoryNode, &payload).expect("test framing succeeds")
}

#[test]
fn append_inclusion_and_historical_prefixes_match_reference() -> crate::Result<()> {
    let mut store = MemoryStore::default();
    let records = vec![
        b"record-0".to_vec(),
        b"record-1".to_vec(),
        b"record-2".to_vec(),
    ];
    let empty = HistoryLog::new(&store).current_state()?;
    assert_eq!(empty.leaf_count, 0);
    assert_eq!(empty.node_count, 0);
    assert_eq!(empty.root, empty_history_root()?);

    let prepared = HistoryLog::new(&store).prepare_append(&records)?;
    assert_eq!(prepared.start_size(), 0);
    assert_eq!(prepared.end_size(), 3);
    assert_eq!(prepared.root(), reference_root(&records));
    assert_eq!(prepared.stats().node_writes, 4);
    store.apply(&prepared);

    let state = HistoryLog::new(&store).current_state()?;
    assert_eq!(state.leaf_count, 3);
    assert_eq!(state.node_count, mmr_node_count(3)?);
    for size in 1..=3 {
        let prefix = usize::try_from(size)
            .map_err(|_| Error::InvalidInput("test size exceeds usize".to_owned()))?;
        assert_eq!(
            HistoryLog::new(&store).root_at(size)?,
            reference_root(&records[..prefix])
        );
    }
    for (index, record) in records.iter().enumerate() {
        let query = HistoryLog::new(&store).inclusion_query(
            record,
            u64::try_from(index)
                .map_err(|_| Error::InvalidInput("test index exceeds u64".to_owned()))?,
            3,
        )?;
        query.verify()?;
        let decoded = HistoryInclusionProofV1::from_bytes(&query.proof.to_bytes()?)?;
        verify_history_inclusion(query.root, record, &decoded)?;
    }
    let historical = HistoryLog::new(&store).inclusion_query(&records[0], 0, 1)?;
    historical.verify()
}

#[test]
fn stable_indices_and_consistency_survive_later_appends() -> crate::Result<()> {
    let mut store = MemoryStore::default();
    let first = vec![b"a".to_vec(), b"b".to_vec()];
    let update = HistoryLog::new(&store).prepare_append(&first)?;
    store.apply(&update);
    let old_root = update.root();

    let second = vec![b"c".to_vec(), b"d".to_vec(), b"e".to_vec()];
    let update = HistoryLog::new(&store).prepare_append(&second)?;
    store.apply(&update);
    assert_eq!(update.start_size(), 2);
    assert_eq!(update.end_size(), 5);

    let old_leaf = HistoryLog::new(&store).inclusion_query(&first[1], 1, 5)?;
    old_leaf.verify()?;
    let consistency = HistoryLog::new(&store).consistency_query(2, 5)?;
    assert_eq!(consistency.old_root, old_root);
    consistency.verify()?;
    let decoded = HistoryConsistencyProofV1::from_bytes(&consistency.proof.to_bytes()?)?;
    verify_history_consistency(consistency.old_root, consistency.new_root, &decoded)?;

    HistoryLog::new(&store).consistency_query(0, 5)?.verify()?;
    HistoryLog::new(&store).consistency_query(5, 5)?.verify()
}

#[test]
fn four_replicas_emit_identical_roots_and_storage_deltas() -> crate::Result<()> {
    let mut stores: [MemoryStore; 4] = std::array::from_fn(|_| MemoryStore::default());
    let blocks = [
        vec![b"one".to_vec(), b"two".to_vec()],
        vec![b"three".to_vec()],
        Vec::new(),
        vec![b"four".to_vec(), b"five".to_vec(), b"six".to_vec()],
    ];
    for records in blocks {
        let updates: Vec<_> = stores
            .iter()
            .map(|store| HistoryLog::new(store).prepare_append(&records))
            .collect::<Result<_, _>>()?;
        assert!(updates.windows(2).all(|pair| pair[0] == pair[1]));
        for (store, update) in stores.iter_mut().zip(&updates) {
            store.apply(update);
        }
    }
    assert!(stores.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[test]
fn shared_batch_and_empty_append_do_not_commit() -> crate::Result<()> {
    let store = MemoryStore::default();
    let empty_records: Vec<Vec<u8>> = Vec::new();
    let empty = HistoryLog::new(&store).prepare_append(&empty_records)?;
    assert_eq!(empty.stats().total_storage_writes, 0);
    let mut empty_batch = StoreBatch::new();
    empty.append_to(&mut empty_batch)?;
    assert!(empty_batch.is_empty());

    let records = vec![b"record".to_vec()];
    let prepared = HistoryLog::new(&store).prepare_append(&records)?;
    let mut batch = StoreBatch::new();
    prepared.append_to(&mut batch)?;
    assert_eq!(
        batch.operation_count(),
        prepared.stats().total_storage_writes
    );
    assert_eq!(HistoryLog::new(&store).current_state()?.leaf_count, 0);
    Ok(())
}

#[test]
fn rejects_invalid_inputs_and_corrupt_current_metadata() -> crate::Result<()> {
    let mut store = MemoryStore::default();
    assert!(
        HistoryLog::new(&store)
            .prepare_append(&[Vec::new()])
            .is_err()
    );
    assert!(
        HistoryLog::new(&store)
            .prepare_append(&[vec![0; MAX_HISTORY_RECORD_BYTES + 1]])
            .is_err()
    );
    let too_many = vec![vec![1]; MAX_HISTORY_APPEND_RECORDS + 1];
    assert!(HistoryLog::new(&store).prepare_append(&too_many).is_err());

    let records = vec![b"good".to_vec()];
    let prepared = HistoryLog::new(&store).prepare_append(&records)?;
    store.apply(&prepared);
    assert!(
        HistoryLog::new(&store)
            .inclusion_query(b"wrong", 0, 1)
            .is_err()
    );
    assert!(
        HistoryLog::new(&store)
            .inclusion_query(&records[0], 1, 1)
            .is_err()
    );
    assert!(HistoryLog::new(&store).root_at(2).is_err());
    assert!(HistoryLog::new(&store).consistency_query(2, 1).is_err());

    store.values.insert(
        (
            ColumnFamily::MmrNodes,
            b"lantern/history/v1/current-root".to_vec(),
        ),
        vec![0; 32],
    );
    assert!(matches!(
        HistoryLog::new(&store).current_state(),
        Err(Error::CorruptStorage(_))
    ));
    Ok(())
}

#[test]
fn proof_mutations_and_wrong_roots_fail_closed() -> crate::Result<()> {
    let mut store = MemoryStore::default();
    let records: Vec<_> = (0_u8..12).map(|value| vec![value]).collect();
    let prepared = HistoryLog::new(&store).prepare_append(&records)?;
    store.apply(&prepared);

    let inclusion = HistoryLog::new(&store).inclusion_query(&records[5], 5, 12)?;
    let mut wrong_root = *inclusion.root.as_bytes();
    wrong_root[0] ^= 1;
    assert!(
        verify_history_inclusion(Hash32::new(wrong_root), &records[5], &inclusion.proof).is_err()
    );
    let mut inclusion_bytes = inclusion.proof.to_bytes()?;
    let last = inclusion_bytes.len() - 1;
    inclusion_bytes[last] ^= 1;
    if let Ok(mutated) = HistoryInclusionProofV1::from_bytes(&inclusion_bytes) {
        assert!(verify_history_inclusion(inclusion.root, &records[5], &mutated).is_err());
    }

    let consistency = HistoryLog::new(&store).consistency_query(3, 12)?;
    let mut wrong_old = *consistency.old_root.as_bytes();
    wrong_old[0] ^= 1;
    assert!(
        verify_history_consistency(
            Hash32::new(wrong_old),
            consistency.new_root,
            &consistency.proof
        )
        .is_err()
    );
    let mut bytes = consistency.proof.to_bytes()?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    if let Ok(mutated) = HistoryConsistencyProofV1::from_bytes(&bytes) {
        assert!(
            verify_history_consistency(consistency.old_root, consistency.new_root, &mutated)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn proof_sizes_remain_logarithmic_for_large_delta() -> crate::Result<()> {
    let mut store = MemoryStore::default();
    let records: Vec<_> = (0_u16..4096)
        .map(|value| value.to_be_bytes().to_vec())
        .collect();
    let prepared = HistoryLog::new(&store).prepare_append(&records)?;
    assert!(prepared.stats().node_writes < records.len() * 2);
    store.apply(&prepared);

    let inclusion = HistoryLog::new(&store).inclusion_query(&records[2047], 2047, 4096)?;
    let consistency = HistoryLog::new(&store).consistency_query(1, 4096)?;
    assert!(inclusion.proof.to_bytes()?.len() < 2048);
    assert!(consistency.proof.to_bytes()?.len() < 2048);
    assert!(inclusion.proof.to_bytes()?.len() <= MAX_HISTORY_PROOF_BYTES);
    assert!(consistency.proof.to_bytes()?.len() <= MAX_HISTORY_PROOF_BYTES);
    Ok(())
}

#[test]
fn rocksdb_commit_reopen_append_and_historical_proofs() -> Result<(), Box<dyn std::error::Error>> {
    use lantern_store::{Durability, RocksStore, StoreIdentityV1};
    use lantern_types::NetworkId;

    let temporary = TestDirectory::new()?;
    let identity = StoreIdentityV1::new(NetworkId::new("lantern-m3-test")?, hash(0x90));
    let first = vec![b"r0".to_vec(), b"r1".to_vec(), b"r2".to_vec()];
    let old_root;
    {
        let store = RocksStore::open(temporary.database(), &identity)?;
        let prepared = HistoryLog::new(&store).prepare_append(&first)?;
        old_root = prepared.root();
        let mut batch = StoreBatch::new();
        prepared.append_to(&mut batch)?;
        store.commit_block(
            batch,
            &commit_metadata(1, prepared.root(), prepared.end_size()),
            Durability::SyncWal,
        )?;
    }
    {
        let store = RocksStore::open(temporary.database(), &identity)?;
        assert_eq!(HistoryLog::new(&store).current_state()?.leaf_count, 3);
        HistoryLog::new(&store)
            .inclusion_query(&first[0], 0, 3)?
            .verify()?;
        let second = vec![b"r3".to_vec(), b"r4".to_vec()];
        let prepared = HistoryLog::new(&store).prepare_append(&second)?;
        let mut batch = StoreBatch::new();
        prepared.append_to(&mut batch)?;
        store.commit_block(
            batch,
            &commit_metadata(2, prepared.root(), prepared.end_size()),
            Durability::SyncWal,
        )?;
    }
    let reopened = RocksStore::open(temporary.database(), &identity)?;
    let log = HistoryLog::new(&reopened);
    assert_eq!(log.current_state()?.leaf_count, 5);
    assert_eq!(log.root_at(3)?, old_root);
    log.inclusion_query(&first[1], 1, 5)?.verify()?;
    log.consistency_query(3, 5)?.verify()?;
    Ok(())
}

#[test]
fn checkpoint_restore_preserves_indices_and_allows_append() -> Result<(), Box<dyn std::error::Error>>
{
    use lantern_store::{Durability, RocksStore, StoreIdentityV1};
    use lantern_types::NetworkId;

    let temporary = TestDirectory::new()?;
    let identity = StoreIdentityV1::new(NetworkId::new("lantern-m3-restore")?, hash(0x90));
    let source_path = temporary.0.join("source-db");
    let checkpoint_path = temporary.0.join("checkpoint");
    let restore_path = temporary.0.join("restored-db");
    let records = vec![
        b"restore-0".to_vec(),
        b"restore-1".to_vec(),
        b"restore-2".to_vec(),
        b"restore-3".to_vec(),
    ];
    let checkpoint_root;
    {
        let store = RocksStore::open(&source_path, &identity)?;
        let prepared = HistoryLog::new(&store).prepare_append(&records)?;
        checkpoint_root = prepared.root();
        let mut batch = StoreBatch::new();
        prepared.append_to(&mut batch)?;
        store.commit_block(
            batch,
            &commit_metadata(1, prepared.root(), prepared.end_size()),
            Durability::SyncWal,
        )?;
        store.create_checkpoint(&checkpoint_path)?;
    }

    let restored = RocksStore::restore_checkpoint(&checkpoint_path, &restore_path, &identity)?;
    let restored_log = HistoryLog::new(&restored);
    assert_eq!(restored_log.current_state()?.leaf_count, 4);
    assert_eq!(restored_log.current_state()?.root, checkpoint_root);
    restored_log.inclusion_query(&records[1], 1, 4)?.verify()?;

    let successor = vec![b"restore-4".to_vec()];
    let prepared = HistoryLog::new(&restored).prepare_append(&successor)?;
    assert_eq!(prepared.start_size(), 4);
    assert_eq!(prepared.end_size(), 5);
    let mut batch = StoreBatch::new();
    prepared.append_to(&mut batch)?;
    restored.commit_block(
        batch,
        &commit_metadata(2, prepared.root(), prepared.end_size()),
        Durability::SyncWal,
    )?;
    let log = HistoryLog::new(&restored);
    assert_eq!(log.root_at(4)?, checkpoint_root);
    log.inclusion_query(&records[1], 1, 5)?.verify()?;
    log.consistency_query(4, 5)?.verify()?;
    Ok(())
}

fn hash(byte: u8) -> Hash32 {
    Hash32::new([byte; 32])
}

fn commit_metadata(
    app_height: u64,
    history_root: Hash32,
    history_size: u64,
) -> lantern_store::CommitMetadataV1 {
    lantern_store::CommitMetadataV1 {
        app_height,
        app_hash: hash(u8::try_from(app_height).unwrap_or(u8::MAX)),
        latest_root: hash(0x30),
        history_root,
        history_size,
        last_closed_epoch: 0,
        last_closed_head_id: None,
        validator_config_hash: hash(0x80),
        config_hash: hash(0x90),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn differential_roots_inclusion_and_consistency_match_independent_forest(
        operations in prop::collection::vec((any::<u16>(), any::<u8>()), 1..48)
    ) {
        let mut store = MemoryStore::default();
        let mut records = Vec::new();
        let mut roots = Vec::new();

        for (nonce, tag) in operations {
            let mut record = nonce.to_be_bytes().to_vec();
            record.push(tag);
            let prepared = HistoryLog::new(&store)
                .prepare_append(std::slice::from_ref(&record))
                .expect("generated record is valid");
            records.push(record);
            prop_assert_eq!(prepared.end_size(), records.len() as u64);
            prop_assert_eq!(prepared.root(), reference_root(&records));
            roots.push(prepared.root());
            store.apply(&prepared);
        }

        let size = records.len();
        let selected = [0, size / 2, size - 1];
        for index in selected {
            let query = HistoryLog::new(&store)
                .inclusion_query(&records[index], index as u64, size as u64)
                .expect("generated inclusion query succeeds");
            prop_assert!(query.verify().is_ok());
        }
        let old_size = size / 2;
        let consistency = HistoryLog::new(&store)
            .consistency_query(old_size as u64, size as u64)
            .expect("generated consistency query succeeds");
        let expected_old = if old_size == 0 {
            empty_history_root().expect("empty root hashes")
        } else {
            roots[old_size - 1]
        };
        prop_assert_eq!(consistency.old_root, expected_old);
        prop_assert_eq!(consistency.new_root, roots[size - 1]);
        prop_assert!(consistency.verify().is_ok());
    }
}
