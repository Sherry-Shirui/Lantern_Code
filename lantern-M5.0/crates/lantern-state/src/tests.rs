use std::{
    error::Error as StdError,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lantern_history::HistoryLog;
use lantern_latest_map::LatestMap;
use lantern_store::{Durability, RocksStore, StoreIdentityV1, read_commit_metadata};
use lantern_types::{
    CaStatusV1, ControlActionV1, ControlEventV1, ControlTransactionV1, Ed25519PublicKey,
    EpochProfileV1, Hash32, HistoryEventTypeV1, LatestValueV1, NetworkId, Nonce16,
    PROTOCOL_VERSION_V1, PublicationEventTypeV1, PublicationIntentV1,
    PublicationSignatureAlgorithmV1, PublicationTransactionV1, StateConfigV1, StateTransactionV1,
    TimestampV1, TransactionResultCodeV1, WireObject, ca_state_hash, head_id, manifest_hash,
    publication_signing_message, sign_control_event, state_config_hash, verify_control_event,
};
use proptest::prelude::*;

use crate::{
    PublicationAuthorizationError, PublicationAuthorizationInput, PublicationAuthorizationV1,
    PublicationAuthorizer, StateMachine,
};

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;
const GENESIS: i64 = 1_700_000_000;
static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct StrictFixtureAuthorizer {
    calls: AtomicUsize,
}

impl StrictFixtureAuthorizer {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PublicationAuthorizer for StrictFixtureAuthorizer {
    fn authorize(
        &self,
        input: PublicationAuthorizationInput<'_>,
    ) -> Result<PublicationAuthorizationV1, PublicationAuthorizationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if input.intent.to_canonical_cbor().map_err(auth_error)? != input.intent_cbor {
            return Err(PublicationAuthorizationError::new(
                "fixture intent bytes were reconstructed",
            ));
        }
        if input.ee_certificate_chain.len() != 1
            || input.ee_certificate_chain[0].len() != 32
            || input.exact_manifest_der.len() < 45
            || input.exact_manifest_der.get(..4) != Some(b"LFM4")
        {
            return Err(PublicationAuthorizationError::new(
                "fixture certificate/manifest structure is invalid",
            ));
        }
        let ca_bytes: [u8; 32] = input.exact_manifest_der[4..36]
            .try_into()
            .map_err(|_| PublicationAuthorizationError::new("fixture CA_ID is truncated"))?;
        let number_bytes: [u8; 8] = input.exact_manifest_der[36..44]
            .try_into()
            .map_err(|_| PublicationAuthorizationError::new("fixture number is truncated"))?;
        let algorithm = match input.exact_manifest_der[44] {
            1 => PublicationSignatureAlgorithmV1::RsaPkcs1V15Sha256,
            2 => PublicationSignatureAlgorithmV1::EcdsaP256Sha256,
            3 => PublicationSignatureAlgorithmV1::Ed25519,
            _ => {
                return Err(PublicationAuthorizationError::new(
                    "fixture algorithm is unknown",
                ));
            }
        };
        let public_key: [u8; 32] = input.ee_certificate_chain[0]
            .as_slice()
            .try_into()
            .map_err(|_| PublicationAuthorizationError::new("fixture EE key is invalid"))?;
        let signature: [u8; 64] = input.intent_signature.try_into().map_err(|_| {
            PublicationAuthorizationError::new("fixture signature width is invalid")
        })?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(auth_error)?
            .verify_strict(
                &publication_signing_message(input.intent).map_err(auth_error)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(auth_error)?;
        Ok(PublicationAuthorizationV1 {
            derived_ca_id: Hash32::new(ca_bytes),
            manifest_number: u64::from_be_bytes(number_bytes),
            manifest_hash: manifest_hash(input.exact_manifest_der),
            signature_algorithm: algorithm,
        })
    }
}

fn auth_error(error: impl std::fmt::Display) -> PublicationAuthorizationError {
    PublicationAuthorizationError::new(error.to_string())
}

struct TestDb {
    store: Option<RocksStore>,
    path: PathBuf,
}

impl TestDb {
    fn new(config: &StateConfigV1) -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "lantern-m4-{}-{}",
            std::process::id(),
            NEXT_DB_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let identity = StoreIdentityV1::new(config.network_id.clone(), state_config_hash(config)?);
        let store = RocksStore::open(&path, &identity)?;
        Ok(Self {
            store: Some(store),
            path,
        })
    }

    fn store(&self) -> &RocksStore {
        self.store.as_ref().expect("test store exists")
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn reopen(&mut self, config: &StateConfigV1) -> TestResult {
        let closed = self.store.take();
        drop(closed);
        let identity = StoreIdentityV1::new(config.network_id.clone(), state_config_hash(config)?);
        self.store = Some(RocksStore::open(&self.path, &identity)?);
        Ok(())
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self.store.take();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn hash(byte: u8) -> Hash32 {
    Hash32::new([byte; 32])
}

fn config() -> StateConfigV1 {
    StateConfigV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: NetworkId::new("lantern-m4-test").expect("valid network"),
        genesis_time: TimestampV1::new(GENESIS, 0).expect("valid genesis"),
        epoch_profile: EpochProfileV1::Integration30Seconds,
        validator_config_hash: hash(0xa1),
        governance_config_hash: hash(0xa2),
        key_epoch: 7,
        max_epoch_catchup: 16,
    }
}

fn time(offset: i64) -> TimestampV1 {
    TimestampV1::new(GENESIS + offset, 0).expect("valid fixture time")
}

fn fixture_manifest(ca_id: Hash32, number: u64, body: u8) -> Vec<u8> {
    let mut manifest = Vec::with_capacity(48);
    manifest.extend_from_slice(b"LFM4");
    manifest.extend_from_slice(ca_id.as_bytes());
    manifest.extend_from_slice(&number.to_be_bytes());
    manifest.push(PublicationSignatureAlgorithmV1::Ed25519 as u8);
    manifest.extend_from_slice(&[body; 3]);
    manifest
}

fn publication(
    ca_id: Hash32,
    number: u64,
    previous: Option<Hash32>,
    nonce: u8,
    body: u8,
    ee_key: &SigningKey,
) -> StateTransactionV1 {
    let exact_manifest_der = fixture_manifest(ca_id, number, body);
    let intent = PublicationIntentV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: config().network_id,
        event_type: PublicationEventTypeV1::Publish,
        ca_id,
        manifest_number: number,
        manifest_hash: manifest_hash(&exact_manifest_der),
        previous_manifest_hash: previous,
        nonce: Nonce16::new([nonce; 16]),
        signature_algorithm: PublicationSignatureAlgorithmV1::Ed25519,
    };
    let signature = ee_key
        .sign(&publication_signing_message(&intent).expect("fixture publication message frames"));
    StateTransactionV1::Publication(PublicationTransactionV1 {
        intent,
        exact_manifest_der,
        intent_signature: signature.to_bytes().to_vec(),
        ee_certificate_chain: vec![ee_key.verifying_key().to_bytes().to_vec()],
    })
}

fn control(
    ca_id: Hash32,
    sequence: u64,
    previous_state_hash: Option<Hash32>,
    nonce: u8,
    action: ControlActionV1,
    key: &SigningKey,
) -> StateTransactionV1 {
    let event = ControlEventV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: config().network_id,
        ca_id,
        admin_sequence: sequence,
        previous_state_hash,
        nonce: Nonce16::new([nonce; 16]),
        action,
    };
    let authorization = sign_control_event(&event, key).expect("fixture control event signs");
    StateTransactionV1::Control(ControlTransactionV1 {
        event,
        authorization,
    })
}

fn initial_enable(
    ca_id: Hash32,
    expected_manifest_hash: Hash32,
    nonce: u8,
    key: &SigningKey,
) -> StateTransactionV1 {
    control(
        ca_id,
        1,
        None,
        nonce,
        ControlActionV1::Enable {
            initial_manifest_hash: expected_manifest_hash,
            initial_admin_key: Ed25519PublicKey::new(key.verifying_key().to_bytes()),
        },
        key,
    )
}

fn prepare_and_commit(
    db: &TestDb,
    authorizer: &StrictFixtureAuthorizer,
    height: u64,
    block_time: TimestampV1,
    transactions: &[StateTransactionV1],
) -> TestResult<(Hash32, Vec<lantern_types::TransactionResultV1>)> {
    let machine = StateMachine::new(db.store(), authorizer, config())?;
    let prepared = machine.prepare_block(height, block_time, transactions)?;
    let app_hash = prepared.app_hash();
    let results = prepared.results().to_vec();
    prepared.commit(db.store(), Durability::SyncWal)?;
    Ok((app_hash, results))
}

#[test]
fn enable_publish_epoch_close_and_cancel_restore_authenticated_predecessor() -> TestResult {
    let config = config();
    let db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let ca_id = hash(1);
    let admin = SigningKey::from_bytes(&[2; 32]);
    let ee = SigningKey::from_bytes(&[3; 32]);
    let publish1 = publication(ca_id, 10, None, 11, 0x31, &ee);
    let publish1_hash = match &publish1 {
        StateTransactionV1::Publication(value) => value.intent.manifest_hash,
        StateTransactionV1::Control(_) => unreachable!(),
    };
    let enable = initial_enable(ca_id, publish1_hash, 10, &admin);
    let (_, results1) = prepare_and_commit(&db, &authorizer, 1, time(0), &[enable])?;
    assert_eq!(results1[0].code, TransactionResultCodeV1::Admitted);
    prepare_and_commit(
        &db,
        &authorizer,
        2,
        time(5),
        std::slice::from_ref(&publish1),
    )?;

    let publish2 = publication(ca_id, 11, Some(publish1_hash), 12, 0x32, &ee);
    let publish2_hash = match &publish2 {
        StateTransactionV1::Publication(value) => value.intent.manifest_hash,
        StateTransactionV1::Control(_) => unreachable!(),
    };
    let (_, results3) = prepare_and_commit(&db, &authorizer, 3, time(30), &[publish2])?;
    assert_eq!(results3[0].history_index, Some(2));

    let machine = StateMachine::new(db.store(), &authorizer, config.clone())?;
    let head0 = machine.closed_head(0)?.expect("epoch zero closed");
    assert_eq!(
        head0.history_length, 2,
        "boundary tx must not leak into epoch zero"
    );
    assert_eq!(head0.latest_entry_count, 1);
    let before_cancel = machine.ca_state(ca_id)?.expect("CA exists");
    let cancel = control(
        ca_id,
        before_cancel.admin_sequence + 1,
        Some(ca_state_hash(&before_cancel)?),
        13,
        ControlActionV1::Cancel {
            target_version: before_cancel.last_version,
            target_manifest_hash: publish2_hash,
            restore_manifest_hash: publish1_hash,
            reason_code: 7,
        },
        &admin,
    );
    prepare_and_commit(&db, &authorizer, 4, time(31), &[cancel])?;

    let machine = StateMachine::new(db.store(), &authorizer, config)?;
    let after_cancel = machine.ca_state(ca_id)?.expect("CA remains");
    assert_eq!(after_cancel.effective_manifest_hash, Some(publish1_hash));
    assert_eq!(after_cancel.latest_event_type, HistoryEventTypeV1::Cancel);
    assert_eq!(
        machine.history_index_for_manifest(ca_id, publish2_hash)?,
        Some(2)
    );
    assert_eq!(machine.history_index_for_ca_version(ca_id, 4)?, Some(3));
    let record = machine.history_record(3)?.expect("cancel record exists");
    let archived_control = machine
        .control_authorization(record.authorization_digest)?
        .ok_or("cancel authorization archive is absent")?;
    verify_control_event(
        &archived_control.event,
        Ed25519PublicKey::new(admin.verifying_key().to_bytes()),
        &archived_control.authorization,
    )?;
    let record_bytes = record.to_canonical_cbor()?;
    HistoryLog::new(db.store())
        .inclusion_query(&record_bytes, 3, 4)?
        .verify()?;
    let latest = LatestMap::new(db.store()).query_ca(ca_id, 3)?;
    latest.verify()?;
    let latest_value =
        LatestValueV1::from_canonical_cbor(latest.value.as_deref().expect("latest value exists"))?;
    assert_eq!(latest_value.effective_manifest_hash, Some(publish1_hash));
    assert_eq!(authorizer.calls(), 2);
    Ok(())
}

#[test]
fn dropping_prepared_block_is_invisible_and_retryable() -> TestResult {
    let config = config();
    let db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let ca_id = hash(0x10);
    let admin = SigningKey::from_bytes(&[0x11; 32]);
    let enable = initial_enable(ca_id, hash(0x12), 1, &admin);
    {
        let machine = StateMachine::new(db.store(), &authorizer, config.clone())?;
        let prepared = machine.prepare_block(1, time(0), std::slice::from_ref(&enable))?;
        assert_eq!(prepared.appended_records(), 1);
    }
    assert!(read_commit_metadata(db.store())?.is_none());
    assert!(LatestMap::new(db.store()).latest_version()?.is_none());
    assert_eq!(HistoryLog::new(db.store()).current_state()?.leaf_count, 0);
    assert!(
        StateMachine::new(db.store(), &authorizer, config.clone())?
            .ca_state(ca_id)?
            .is_none()
    );
    prepare_and_commit(&db, &authorizer, 1, time(0), &[enable])?;
    assert!(db.path().join("CURRENT").is_file());
    Ok(())
}

#[test]
fn reopen_cross_checks_all_roots_and_continues_at_exact_successor_height() -> TestResult {
    let config = config();
    let mut db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let ca_id = hash(0x18);
    let admin = SigningKey::from_bytes(&[0x19; 32]);
    let first_hash = prepare_and_commit(
        &db,
        &authorizer,
        1,
        time(0),
        &[initial_enable(ca_id, hash(0x1a), 1, &admin)],
    )?
    .0;
    db.reopen(&config)?;
    let machine = StateMachine::new(db.store(), &authorizer, config.clone())?;
    assert_eq!(
        machine
            .committed_app_state()?
            .ok_or("reopened AppState is missing")?
            .app_height,
        1
    );
    assert_eq!(
        read_commit_metadata(db.store())?
            .ok_or("M1 metadata missing")?
            .app_hash,
        first_hash
    );
    let prepared = machine.prepare_block(2, time(1), &[])?;
    prepared.commit(db.store(), Durability::SyncWal)?;
    db.reopen(&config)?;
    assert_eq!(
        StateMachine::new(db.store(), &authorizer, config)?
            .committed_app_state()?
            .ok_or("successor AppState is missing")?
            .app_height,
        2
    );
    Ok(())
}

#[test]
fn exact_idempotency_replay_returns_original_and_conflict_never_overwrites() -> TestResult {
    let config = config();
    let db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let ca_id = hash(0x20);
    let admin = SigningKey::from_bytes(&[0x21; 32]);
    let enable = initial_enable(ca_id, hash(0x22), 5, &admin);
    let (_, first) =
        prepare_and_commit(&db, &authorizer, 1, time(0), std::slice::from_ref(&enable))?;
    let machine = StateMachine::new(db.store(), &authorizer, config.clone())?;
    let replay = machine.prepare_block(2, time(1), std::slice::from_ref(&enable))?;
    assert_eq!(replay.results(), first.as_slice());
    assert_eq!(replay.appended_records(), 0);
    replay.commit(db.store(), Durability::SyncWal)?;

    let conflict = initial_enable(ca_id, hash(0x23), 5, &admin);
    let (_, conflict_result) = prepare_and_commit(&db, &authorizer, 3, time(2), &[conflict])?;
    assert_eq!(
        conflict_result[0].code,
        TransactionResultCodeV1::RejectedIdempotencyConflict
    );
    let machine = StateMachine::new(db.store(), &authorizer, config)?;
    assert_eq!(machine.ca_state(ca_id)?.expect("CA exists").last_version, 1);
    assert_eq!(HistoryLog::new(db.store()).current_state()?.leaf_count, 1);
    Ok(())
}

#[test]
fn failed_publication_authorization_has_no_state_effect() -> TestResult {
    let config = config();
    let db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let ca_id = hash(0x30);
    let admin = SigningKey::from_bytes(&[0x31; 32]);
    let ee = SigningKey::from_bytes(&[0x32; 32]);
    let mut publish = publication(ca_id, 1, None, 2, 0x33, &ee);
    let expected = match &publish {
        StateTransactionV1::Publication(value) => value.intent.manifest_hash,
        StateTransactionV1::Control(_) => unreachable!(),
    };
    prepare_and_commit(
        &db,
        &authorizer,
        1,
        time(0),
        &[initial_enable(ca_id, expected, 1, &admin)],
    )?;
    if let StateTransactionV1::Publication(value) = &mut publish {
        value.intent_signature[0] ^= 1;
    }
    let (_, result) = prepare_and_commit(&db, &authorizer, 2, time(1), &[publish])?;
    assert_eq!(
        result[0].code,
        TransactionResultCodeV1::RejectedAuthorization
    );
    let state = StateMachine::new(db.store(), &authorizer, config)?
        .ca_state(ca_id)?
        .expect("CA exists");
    assert_eq!(state.last_version, 1);
    assert_eq!(HistoryLog::new(db.store()).current_state()?.leaf_count, 1);
    assert_eq!(authorizer.calls(), 1);
    Ok(())
}

#[test]
fn rollover_is_terminal_and_successor_key_is_preauthorized() -> TestResult {
    let config = config();
    let db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let old_ca = hash(0x40);
    let new_ca = hash(0x41);
    let old_admin = SigningKey::from_bytes(&[0x42; 32]);
    let new_admin = SigningKey::from_bytes(&[0x43; 32]);
    prepare_and_commit(
        &db,
        &authorizer,
        1,
        time(0),
        &[initial_enable(old_ca, hash(0x44), 1, &old_admin)],
    )?;
    let old_state = StateMachine::new(db.store(), &authorizer, config.clone())?
        .ca_state(old_ca)?
        .expect("old CA exists");
    let rollover = control(
        old_ca,
        2,
        Some(ca_state_hash(&old_state)?),
        2,
        ControlActionV1::Rollover {
            successor_ca_id: new_ca,
            successor_admin_key: Ed25519PublicKey::new(new_admin.verifying_key().to_bytes()),
        },
        &old_admin,
    );
    prepare_and_commit(&db, &authorizer, 2, time(1), &[rollover])?;
    let wrong_admin = SigningKey::from_bytes(&[0x45; 32]);
    let wrong_enable = initial_enable(new_ca, hash(0x46), 3, &wrong_admin);
    let (_, wrong_result) = prepare_and_commit(&db, &authorizer, 3, time(2), &[wrong_enable])?;
    assert_eq!(wrong_result[0].code, TransactionResultCodeV1::RejectedState);
    let correct_enable = initial_enable(new_ca, hash(0x46), 4, &new_admin);
    prepare_and_commit(&db, &authorizer, 4, time(3), &[correct_enable])?;

    let machine = StateMachine::new(db.store(), &authorizer, config)?;
    let old = machine.ca_state(old_ca)?.expect("old CA remains");
    let new = machine.ca_state(new_ca)?.expect("successor exists");
    assert_eq!(old.status, CaStatusV1::Terminal);
    assert_eq!(old.rollover_link, Some(new_ca));
    assert_eq!(new.status, CaStatusV1::Enabled);
    assert_eq!(
        new.admin_public_key,
        Ed25519PublicKey::new(new_admin.verifying_key().to_bytes())
    );
    Ok(())
}

#[test]
fn four_replicas_commit_identical_roots_results_and_head_ids() -> TestResult {
    let config = config();
    let databases = (0..4)
        .map(|_| TestDb::new(&config))
        .collect::<TestResult<Vec<_>>>()?;
    let authorizers = (0..4)
        .map(|_| Arc::new(StrictFixtureAuthorizer::default()))
        .collect::<Vec<_>>();
    let ca_id = hash(0x50);
    let admin = SigningKey::from_bytes(&[0x51; 32]);
    let ee = SigningKey::from_bytes(&[0x52; 32]);
    let publish = publication(ca_id, 1, None, 2, 0x53, &ee);
    let expected = match &publish {
        StateTransactionV1::Publication(value) => value.intent.manifest_hash,
        StateTransactionV1::Control(_) => unreachable!(),
    };
    let enable = initial_enable(ca_id, expected, 1, &admin);
    let mut commitments = Vec::new();
    for (db, authorizer) in databases.iter().zip(&authorizers) {
        prepare_and_commit(
            db,
            authorizer.as_ref(),
            1,
            time(0),
            std::slice::from_ref(&enable),
        )?;
        prepare_and_commit(
            db,
            authorizer.as_ref(),
            2,
            time(2),
            std::slice::from_ref(&publish),
        )?;
        let (hash, results) = prepare_and_commit(db, authorizer.as_ref(), 3, time(30), &[])?;
        let machine = StateMachine::new(db.store(), authorizer.as_ref(), config.clone())?;
        commitments.push((
            hash,
            machine.committed_app_state()?.expect("app state exists"),
            machine.closed_head(0)?.expect("head exists"),
            results,
        ));
    }
    for replica in &commitments[1..] {
        assert_eq!(replica, &commitments[0]);
    }
    Ok(())
}

#[test]
fn p1_through_p7_authenticated_fixture_matrix_is_constructible() -> TestResult {
    let config = config();
    let db = TestDb::new(&config)?;
    let authorizer = StrictFixtureAuthorizer::default();
    let enabled_ca = hash(0x60);
    let disabled_ca = hash(0x61);
    let enabled_admin = SigningKey::from_bytes(&[0x62; 32]);
    let disabled_admin = SigningKey::from_bytes(&[0x63; 32]);
    let ee = SigningKey::from_bytes(&[0x64; 32]);
    let publish1 = publication(enabled_ca, 1, None, 3, 0x65, &ee);
    let publish1_hash = match &publish1 {
        StateTransactionV1::Publication(value) => value.intent.manifest_hash,
        StateTransactionV1::Control(_) => return Err("fixture publication has wrong type".into()),
    };
    prepare_and_commit(
        &db,
        &authorizer,
        1,
        time(0),
        &[
            initial_enable(enabled_ca, publish1_hash, 1, &enabled_admin),
            initial_enable(disabled_ca, hash(0x66), 2, &disabled_admin),
            publish1,
        ],
    )?;
    let disabled_state = StateMachine::new(db.store(), &authorizer, config.clone())?
        .ca_state(disabled_ca)?
        .ok_or("disabled fixture CA is missing")?;
    let publish2 = publication(enabled_ca, 2, Some(publish1_hash), 4, 0x67, &ee);
    let publish2_hash = match &publish2 {
        StateTransactionV1::Publication(value) => value.intent.manifest_hash,
        StateTransactionV1::Control(_) => return Err("fixture publication has wrong type".into()),
    };
    let disable = control(
        disabled_ca,
        2,
        Some(ca_state_hash(&disabled_state)?),
        5,
        ControlActionV1::Disable { reason_code: 1 },
        &disabled_admin,
    );
    prepare_and_commit(&db, &authorizer, 2, time(30), &[publish2, disable])?;
    prepare_and_commit(&db, &authorizer, 3, time(60), &[])?;

    let machine = StateMachine::new(db.store(), &authorizer, config)?;
    let app = machine
        .committed_app_state()?
        .ok_or("P1 AppState is missing")?;
    assert_eq!(app.last_closed_epoch, Some(1));
    assert!(
        machine.closed_head(2)?.is_none(),
        "P1: current head is not yet closed"
    );

    let disabled_query = LatestMap::new(db.store()).query_ca(disabled_ca, 2)?;
    disabled_query.verify()?;
    let disabled_latest = LatestValueV1::from_canonical_cbor(
        disabled_query
            .value
            .as_deref()
            .ok_or("P2 value is absent")?,
    )?;
    assert_eq!(disabled_latest.status, CaStatusV1::Disabled, "P2");

    let enabled_query = LatestMap::new(db.store()).query_ca(enabled_ca, 2)?;
    enabled_query.verify()?;
    let enabled_latest = LatestValueV1::from_canonical_cbor(
        enabled_query.value.as_deref().ok_or("P3 value is absent")?,
    )?;
    assert_eq!(enabled_latest.status, CaStatusV1::Enabled);
    assert_eq!(
        enabled_latest.effective_manifest_hash,
        Some(publish2_hash),
        "P3"
    );

    let old_index = machine
        .history_index_for_manifest(enabled_ca, publish1_hash)?
        .ok_or("P4/P5 old publication index is absent")?;
    let old_record = machine
        .history_record(old_index)?
        .ok_or("old record is absent")?;
    let old_bytes = old_record.to_canonical_cbor()?;
    HistoryLog::new(db.store())
        .inclusion_query(&old_bytes, old_index, app.history_length)?
        .verify()?;
    assert_eq!(old_record.admission_epoch, 0);
    assert!(1_u64 - old_record.admission_epoch <= 2, "P4 within grace");
    assert!(3_u64 - old_record.admission_epoch > 2, "P5 beyond grace");

    assert!(
        machine
            .history_index_for_ca_version(enabled_ca, 99)?
            .is_none(),
        "P6 missing admission index"
    );

    let head1 = machine.closed_head(1)?.ok_or("P7 head one is absent")?;
    let mut conflicting = head1.clone();
    conflicting.bundle_hash = hash(0xee);
    assert_ne!(
        head_id(&head1)?,
        head_id(&conflicting)?,
        "P7 distinct bodies"
    );
    Ok(())
}

proptest! {
    #[test]
    fn epoch_calculation_is_exact_on_both_sides_of_every_boundary(
        epoch in 0_u64..10_000,
    ) {
        let config = config();
        let boundary = GENESIS + i64::try_from(epoch * 30).expect("bounded epoch fits");
        let at = TimestampV1::new(boundary, 0).expect("valid boundary");
        prop_assert_eq!(super::machine::epoch_at(&config, at).expect("epoch computes"), epoch);
        if epoch > 0 {
            let before = TimestampV1::new(boundary - 1, 999_999_999).expect("valid prior time");
            prop_assert_eq!(
                super::machine::epoch_at(&config, before).expect("epoch computes"),
                epoch - 1
            );
        }
    }
}
