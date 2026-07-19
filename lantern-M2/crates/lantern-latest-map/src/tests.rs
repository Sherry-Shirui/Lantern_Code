use std::collections::BTreeMap;
use std::{
    env, fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use jmt::{JellyfishMerkleTree, KeyHash, mock::MockTreeStore};
use lantern_store::{ColumnFamily, ReadStore, StoreBatch};
use lantern_types::Hash32;
use proptest::prelude::*;

use crate::{
    Error, LatestMap, LatestMutationV1, MAX_LATEST_VALUE_BYTES, latest_key, latest_leaf_bytes,
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
            "lantern-latest-map-{}-{nanos}-{counter}",
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
    fn apply(&mut self, update: &crate::PreparedLatestUpdate) {
        for (key, value) in update.writes() {
            self.values.insert(
                (ColumnFamily::LatestTreeNodes, key.to_vec()),
                value.to_vec(),
            );
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

fn ca(byte: u8) -> Hash32 {
    Hash32::new([byte; 32])
}

fn reference_update(store: &MockTreeStore, version: u64, mutations: &[LatestMutationV1]) -> Hash32 {
    let mut ordered = BTreeMap::new();
    for mutation in mutations {
        let key = latest_key(mutation.ca_id).expect("fixed-size CA ID hashes");
        let value = mutation
            .value
            .as_deref()
            .map(latest_leaf_bytes)
            .transpose()
            .expect("test values are valid");
        assert!(ordered.insert(key, value).is_none());
    }
    let tree = JellyfishMerkleTree::<_, sha2_jmt::Sha256>::new(store);
    let (root, batch) = tree
        .put_value_set(
            ordered
                .into_iter()
                .map(|(key, value)| (KeyHash(*key.as_bytes()), value)),
            version,
        )
        .expect("reference JMT accepts update");
    store
        .write_tree_update_batch(batch)
        .expect("reference memory store accepts batch");
    Hash32::new(root.0)
}

#[test]
fn membership_nonmembership_and_historical_versions_round_trip() {
    let mut store = MemoryStore::default();

    let update0 = LatestMap::new(&store)
        .prepare_update(0, &[LatestMutationV1::set(ca(1), b"a-v0".to_vec())])
        .expect("genesis prepares");
    store.apply(&update0);

    let update1 = LatestMap::new(&store)
        .prepare_update(
            1,
            &[
                LatestMutationV1::set(ca(1), b"a-v1".to_vec()),
                LatestMutationV1::set(ca(2), b"b-v1".to_vec()),
            ],
        )
        .expect("successor prepares");
    store.apply(&update1);

    let update2 = LatestMap::new(&store)
        .prepare_update(2, &[LatestMutationV1::delete(ca(1))])
        .expect("deletion prepares");
    store.apply(&update2);

    let map = LatestMap::new(&store);
    assert_eq!(map.latest_version().expect("version reads"), Some(2));
    let a0 = map.query_ca(ca(1), 0).expect("historical membership");
    let a1 = map.query_ca(ca(1), 1).expect("new membership");
    let a2 = map.query_ca(ca(1), 2).expect("post-delete query");
    let b0 = map.query_ca(ca(2), 0).expect("historical absence");
    let b2 = map.query_ca(ca(2), 2).expect("retained membership");

    assert_eq!(a0.value.as_deref(), Some(b"a-v0".as_slice()));
    assert_eq!(a1.value.as_deref(), Some(b"a-v1".as_slice()));
    assert_eq!(a2.value, None);
    assert_eq!(b0.value, None);
    assert_eq!(b2.value.as_deref(), Some(b"b-v1".as_slice()));
    for query in [&a0, &a1, &a2, &b0, &b2] {
        query.verify().expect("query proof verifies independently");
        let encoded = query.proof.to_bytes().expect("proof encodes");
        assert_eq!(
            crate::LatestProofV1::from_bytes(&encoded).expect("proof decodes"),
            query.proof
        );
    }
    assert_ne!(update0.root(), update1.root());
    assert_ne!(update1.root(), update2.root());
}

#[test]
fn empty_versions_copy_the_root_and_remain_queryable() {
    let mut store = MemoryStore::default();
    let genesis = LatestMap::new(&store)
        .prepare_update(0, &[])
        .expect("empty genesis prepares");
    store.apply(&genesis);
    let successor = LatestMap::new(&store)
        .prepare_update(1, &[])
        .expect("empty successor prepares");
    store.apply(&successor);

    assert_eq!(genesis.root(), successor.root());
    let absent = LatestMap::new(&store)
        .query_ca(ca(9), 1)
        .expect("empty-tree non-membership proof");
    assert_eq!(absent.value, None);
    absent.verify().expect("non-membership verifies");
}

#[test]
fn four_replicas_emit_identical_roots_and_storage_deltas() {
    let mut stores: [MemoryStore; 4] = std::array::from_fn(|_| MemoryStore::default());
    let blocks = [
        vec![
            LatestMutationV1::set(ca(4), b"four".to_vec()),
            LatestMutationV1::set(ca(1), b"one".to_vec()),
        ],
        vec![LatestMutationV1::set(ca(4), b"four-next".to_vec())],
        Vec::new(),
        vec![
            LatestMutationV1::delete(ca(1)),
            LatestMutationV1::set(ca(8), b"eight".to_vec()),
        ],
    ];

    for (version, mutations) in blocks.iter().enumerate() {
        let updates: Vec<_> = stores
            .iter()
            .map(|store| {
                LatestMap::new(store)
                    .prepare_update(version as u64, mutations)
                    .expect("replica update prepares")
            })
            .collect();
        assert!(updates.windows(2).all(|pair| pair[0] == pair[1]));
        for (store, update) in stores.iter_mut().zip(&updates) {
            store.apply(update);
        }
    }
    assert!(stores.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn shared_m1_batch_receives_only_prepared_writes() {
    let store = MemoryStore::default();
    let prepared = LatestMap::new(&store)
        .prepare_update(0, &[LatestMutationV1::set(ca(3), b"value".to_vec())])
        .expect("update prepares");
    let mut batch = StoreBatch::new();
    prepared
        .append_to(&mut batch)
        .expect("batch append succeeds");
    assert_eq!(
        batch.operation_count(),
        prepared.stats().total_storage_writes
    );
    assert!(!batch.is_empty());
    assert_eq!(
        LatestMap::new(&store).latest_version().expect("read works"),
        None
    );
}

#[test]
fn rocksdb_commit_reopen_and_historical_query_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    use lantern_store::{Durability, RocksStore, StoreIdentityV1};
    use lantern_types::NetworkId;

    let temporary = TestDirectory::new()?;
    let identity = StoreIdentityV1::new(NetworkId::new("lantern-m2-test")?, ca(0x90));
    {
        let store = RocksStore::open(temporary.database(), &identity)?;
        let prepared0 = LatestMap::new(&store)
            .prepare_update(0, &[LatestMutationV1::set(ca(1), b"v0".to_vec())])?;
        let mut batch0 = StoreBatch::new();
        prepared0.append_to(&mut batch0)?;
        store.commit_block(
            batch0,
            &commit_metadata(1, prepared0.root()),
            Durability::SyncWal,
        )?;
        assert_eq!(
            LatestMap::new(&store).query_ca(ca(1), 0)?.value,
            Some(b"v0".to_vec())
        );
    }
    {
        let store = RocksStore::open(temporary.database(), &identity)?;
        let prepared1 = LatestMap::new(&store)
            .prepare_update(1, &[LatestMutationV1::set(ca(1), b"v1".to_vec())])?;
        let mut batch1 = StoreBatch::new();
        prepared1.append_to(&mut batch1)?;
        store.commit_block(
            batch1,
            &commit_metadata(2, prepared1.root()),
            Durability::SyncWal,
        )?;
    }
    let reopened = RocksStore::open(temporary.database(), &identity)?;
    let map = LatestMap::new(&reopened);
    assert_eq!(map.query_ca(ca(1), 0)?.value, Some(b"v0".to_vec()));
    assert_eq!(map.query_ca(ca(1), 1)?.value, Some(b"v1".to_vec()));
    Ok(())
}

fn commit_metadata(app_height: u64, latest_root: Hash32) -> lantern_store::CommitMetadataV1 {
    lantern_store::CommitMetadataV1 {
        app_height,
        app_hash: ca(u8::try_from(app_height).unwrap_or(u8::MAX)),
        latest_root,
        history_root: ca(0x40),
        history_size: 0,
        last_closed_epoch: 0,
        last_closed_head_id: None,
        validator_config_hash: ca(0x80),
        config_hash: ca(0x90),
    }
}

#[test]
fn rejects_version_gaps_duplicates_and_invalid_values() {
    let mut store = MemoryStore::default();
    assert!(matches!(
        LatestMap::new(&store).prepare_update(1, &[]),
        Err(Error::NonSuccessorVersion { .. })
    ));
    let duplicate = [
        LatestMutationV1::set(ca(1), b"first".to_vec()),
        LatestMutationV1::delete(ca(1)),
    ];
    assert!(matches!(
        LatestMap::new(&store).prepare_update(0, &duplicate),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        LatestMap::new(&store).prepare_update(0, &[LatestMutationV1::set(ca(1), Vec::new())]),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        LatestMap::new(&store).prepare_update(
            0,
            &[LatestMutationV1::set(
                ca(1),
                vec![0; MAX_LATEST_VALUE_BYTES + 1]
            )]
        ),
        Err(Error::InvalidInput(_))
    ));

    let genesis = LatestMap::new(&store)
        .prepare_update(0, &[])
        .expect("genesis prepares");
    store.apply(&genesis);
    assert!(matches!(
        LatestMap::new(&store).prepare_update(0, &[]),
        Err(Error::NonSuccessorVersion { .. })
    ));
    assert!(matches!(
        LatestMap::new(&store).root(7),
        Err(Error::MissingVersion(7))
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn differential_roots_queries_and_proofs_match_reference_jmt(
        operations in prop::collection::vec((0_u8..12, any::<bool>(), any::<u16>()), 1..40)
    ) {
        let mut store = MemoryStore::default();
        let reference = MockTreeStore::default();
        let mut model = BTreeMap::<u8, Vec<u8>>::new();
        let mut snapshots = Vec::new();
        let mut roots = Vec::new();

        for (index, (key_id, delete, nonce)) in operations.iter().copied().enumerate() {
            let version = index as u64;
            let mutation = if delete {
                model.remove(&key_id);
                LatestMutationV1::delete(ca(key_id))
            } else {
                let mut value = vec![key_id];
                value.extend_from_slice(&version.to_be_bytes());
                value.extend_from_slice(&nonce.to_be_bytes());
                model.insert(key_id, value.clone());
                LatestMutationV1::set(ca(key_id), value)
            };

            let prepared = LatestMap::new(&store)
                .prepare_update(version, std::slice::from_ref(&mutation))
                .expect("adapter update matches valid generated operation");
            let reference_root = reference_update(&reference, version, &[mutation]);
            prop_assert_eq!(prepared.root(), reference_root);
            store.apply(&prepared);

            let query = LatestMap::new(&store)
                .query_ca(ca(key_id), version)
                .expect("current query succeeds");
            prop_assert_eq!(query.value.as_ref(), model.get(&key_id));
            prop_assert!(query.verify().is_ok());

            let reference_tree = JellyfishMerkleTree::<_, sha2_jmt::Sha256>::new(&reference);
            let reference_key = latest_key(ca(key_id)).expect("fixed key hashes");
            let (reference_value, reference_proof) = reference_tree
                .get_with_proof(KeyHash(*reference_key.as_bytes()), version)
                .expect("reference proof succeeds");
            let reference_raw = reference_value
                .as_deref()
                .map(crate::proof::decode_latest_leaf_bytes)
                .transpose()
                .expect("reference stores framed values");
            prop_assert_eq!(query.value, reference_raw);
            reference_proof
                .verify(
                    jmt::RootHash(*reference_root.as_bytes()),
                    KeyHash(*reference_key.as_bytes()),
                    reference_value.as_deref(),
                )
                .expect("reference proof verifies");

            snapshots.push(model.clone());
            roots.push(prepared.root());
        }

        let selected = [0, snapshots.len() / 2, snapshots.len() - 1];
        for version_index in selected {
            let key_id = operations[version_index].0;
            let historical = LatestMap::new(&store)
                .query_ca(ca(key_id), version_index as u64)
                .expect("historical proof succeeds after later updates");
            prop_assert_eq!(historical.root, roots[version_index]);
            prop_assert_eq!(historical.value.as_ref(), snapshots[version_index].get(&key_id));
            prop_assert!(historical.verify().is_ok());
        }

        let absent = LatestMap::new(&store)
            .query_ca(ca(250), (snapshots.len() - 1) as u64)
            .expect("unseen CA non-membership proof succeeds");
        prop_assert!(absent.value.is_none());
        prop_assert!(absent.verify().is_ok());
    }
}
