use std::{error::Error as StdError, io, str::FromStr};

use ed25519_dalek::SigningKey;
use lantern_types::{
    AppStateCommitmentV1, ControlActionV1, ControlEventV1, DomainV1, Ed25519AuthorizationV1,
    Ed25519PublicKey, Error, Hash32, HeadBodyV1, PublicationIntentV1, TimestampV1,
    ValidatorConfigV1, ValidatorInfoV1, ValidatorUpdateV1, WireObject, ed25519_key_id,
    hash_with_domain, verify_control_event, verify_validator_update,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

fn vector_value() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../test-vectors/v1.json"
    ))?)
}

fn string_at(value: &Value, pointer: &str) -> TestResult<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("missing vector field {pointer}")).into())
}

fn decode_at<T: WireObject>(pointer: &str) -> TestResult<T> {
    let value = vector_value()?;
    let encoded = hex::decode(string_at(&value, pointer)?)?;
    Ok(T::from_canonical_cbor(&encoded)?)
}

fn require_error<T>(result: lantern_types::Result<T>) -> TestResult<Error> {
    match result {
        Ok(_) => Err(io::Error::other("operation unexpectedly succeeded").into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn semantic_validation_rejects_invalid_publication_and_time_values() -> TestResult {
    let mut intent: PublicationIntentV1 =
        decode_at("/golden/publication_intent/canonical_cbor_hex")?;
    intent.previous_manifest_hash = Some(intent.manifest_hash);
    assert!(matches!(intent.validate(), Err(Error::Validation(_))));

    let bad_timestamp = TimestampV1 {
        seconds: 1,
        nanos: 1_000_000_000,
    };
    assert!(matches!(
        bad_timestamp.validate(),
        Err(Error::Validation(_))
    ));

    let mut head: HeadBodyV1 = decode_at("/golden/head_body/canonical_cbor_hex")?;
    head.issued_at = TimestampV1::new(head.epoch_end.seconds - 1, 0)?;
    assert!(matches!(head.validate(), Err(Error::Validation(_))));
    head.issued_at = head.epoch_end;
    head.previous_head_id = None;
    assert!(matches!(head.validate(), Err(Error::Validation(_))));
    Ok(())
}

#[test]
fn app_state_requires_atomic_closed_epoch_and_head_id_pair() -> TestResult {
    let mut app: AppStateCommitmentV1 =
        decode_at("/golden/app_state_commitment/canonical_cbor_hex")?;
    app.closed_head_id = None;
    assert!(matches!(app.validate(), Err(Error::Validation(_))));
    app.closed_head_id = Some(Hash32::new([0x44; 32]));
    app.latest_entry_count = app.history_length + 1;
    assert!(matches!(app.validate(), Err(Error::Validation(_))));
    Ok(())
}

#[test]
fn only_initial_enable_may_omit_previous_state() -> TestResult {
    let event: ControlEventV1 = decode_at("/golden/control_event/canonical_cbor_hex")?;
    let mut invalid = event.clone();
    invalid.action = ControlActionV1::Disable { reason_code: 1 };
    assert!(matches!(invalid.validate(), Err(Error::Validation(_))));

    invalid = event;
    invalid.action = ControlActionV1::Cancel {
        target_version: 2,
        target_manifest_hash: Hash32::new([0x55; 32]),
        restore_manifest_hash: Hash32::new([0x55; 32]),
        reason_code: 1,
    };
    invalid.previous_state_hash = Some(Hash32::new([0x77; 32]));
    assert!(matches!(invalid.validate(), Err(Error::Validation(_))));
    Ok(())
}

#[test]
fn validator_config_rejects_wrong_order_power_address_and_count() -> TestResult {
    let config: ValidatorConfigV1 = decode_at("/golden/validator_config/canonical_cbor_hex")?;

    let mut wrong_order = config.clone();
    wrong_order.validators.swap(0, 1);
    assert!(matches!(wrong_order.validate(), Err(Error::Validation(_))));

    let mut wrong_power = config.clone();
    wrong_power.validators[0].voting_power = 2;
    assert!(matches!(wrong_power.validate(), Err(Error::Validation(_))));

    let mut wrong_address = config.clone();
    wrong_address.validators[0].address = lantern_types::ValidatorAddress::new([0; 20]);
    assert!(matches!(
        wrong_address.validate(),
        Err(Error::Validation(_))
    ));

    let mut wrong_count = config;
    let removed = wrong_count.validators.pop();
    assert!(removed.is_some());
    assert!(matches!(wrong_count.validate(), Err(Error::Validation(_))));
    Ok(())
}

#[test]
fn governance_requires_two_distinct_authorized_signers() -> TestResult {
    let update: ValidatorUpdateV1 = decode_at("/golden/validator_update/authorization_cbor_hex")?;
    let value = vector_value()?;
    let key_values = value
        .pointer("/inputs/governance_public_keys_hex")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("missing governance key vector"))?;
    let key_vec = key_values
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| io::Error::other("governance key is not a string"))
                .and_then(|text| {
                    Ed25519PublicKey::from_str(text)
                        .map_err(|error| io::Error::other(error.to_string()))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys: [Ed25519PublicKey; 3] = key_vec.try_into().map_err(|values: Vec<_>| {
        io::Error::other(format!("expected 3 keys, got {}", values.len()))
    })?;
    verify_validator_update(&update, &keys)?;

    let mut one_signature = update.clone();
    one_signature.signatures.truncate(1);
    assert!(matches!(
        one_signature.validate(),
        Err(Error::Validation(_))
    ));

    let mut duplicate = update.clone();
    duplicate.signatures[1].signer_index = duplicate.signatures[0].signer_index;
    assert!(matches!(duplicate.validate(), Err(Error::Validation(_))));

    let mut wrong_keys = keys;
    wrong_keys[0] = Ed25519PublicKey::new(
        SigningKey::from_bytes(&[0x7f; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert_eq!(
        require_error(verify_validator_update(&update, &wrong_keys))?,
        Error::InvalidSignature
    );
    Ok(())
}

#[test]
fn strict_control_verifier_checks_key_id_and_signature() -> TestResult {
    let event: ControlEventV1 = decode_at("/golden/control_event/canonical_cbor_hex")?;
    let authorization: Ed25519AuthorizationV1 =
        decode_at("/golden/control_event/authorization_cbor_hex")?;
    let value = vector_value()?;
    let public_key =
        Ed25519PublicKey::from_str(&string_at(&value, "/inputs/control_public_key_hex")?)?;
    verify_control_event(&event, public_key, &authorization)?;

    let mut wrong_key_id = authorization;
    wrong_key_id.key_id = ed25519_key_id(Ed25519PublicKey::new([0x99; 32]))?;
    assert_eq!(
        require_error(verify_control_event(&event, public_key, &wrong_key_id))?,
        Error::InvalidSignature
    );
    Ok(())
}

#[test]
fn indefinite_top_level_array_is_rejected() -> TestResult {
    let value = vector_value()?;
    let mut canonical = hex::decode(string_at(
        &value,
        "/golden/publication_intent/canonical_cbor_hex",
    )?)?;
    canonical[0] = 0x9f;
    canonical.push(0xff);
    assert!(matches!(
        PublicationIntentV1::from_canonical_cbor(&canonical),
        Err(Error::Validation(_))
    ));
    Ok(())
}

#[test]
fn validator_address_constructor_matches_comet_rule() -> TestResult {
    let public_key = Ed25519PublicKey::new([0x42; 32]);
    let validator = ValidatorInfoV1::from_public_key(public_key);
    let expected = lantern_types::sha256(public_key.as_bytes());
    assert_eq!(validator.address.as_bytes(), &expected.as_bytes()[..20]);
    validator.validate()?;
    Ok(())
}

#[test]
fn every_v1_domain_label_is_frozen_and_separated() -> TestResult {
    let domains = [
        (DomainV1::CaId, "lantern/v1/ca-id"),
        (DomainV1::Intent, "lantern/v1/intent"),
        (DomainV1::Control, "lantern/v1/control"),
        (DomainV1::LatestKey, "lantern/v1/latest-key"),
        (DomainV1::LatestLeaf, "lantern/v1/latest-leaf"),
        (DomainV1::HistoryLeaf, "lantern/v1/history-leaf"),
        (DomainV1::HistoryNode, "lantern/v1/history-node"),
        (DomainV1::HeadBody, "lantern/v1/head-body"),
        (DomainV1::AppState, "lantern/v1/app-state"),
        (DomainV1::ValidatorConfig, "lantern/v1/validator-config"),
        (DomainV1::Governance, "lantern/v1/governance"),
        (DomainV1::Ed25519KeyId, "lantern/v1/ed25519-key-id"),
    ];
    let domain_count = domains.len();
    let mut hashes = Vec::with_capacity(domain_count);
    for (domain, label) in domains {
        assert_eq!(domain.as_str(), label);
        hashes.push(hash_with_domain(domain, b"same-payload")?);
    }
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(hashes.len(), domain_count);
    Ok(())
}
