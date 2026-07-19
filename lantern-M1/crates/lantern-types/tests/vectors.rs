use std::{error::Error as StdError, io, str::FromStr};

use lantern_types::{
    AppStateCommitmentV1, ControlEventV1, Ed25519AuthorizationV1, Ed25519PublicKey, Error, Hash32,
    HeadBodyV1, MAX_WIRE_OBJECT_BYTES, PublicationIntentV1, UnsignedValidatorUpdateV1,
    ValidatorConfigV1, ValidatorUpdateV1, WireObject, app_hash, ca_id, control_event_id,
    governance_signing_message, head_id, intent_id, manifest_hash, publication_signing_message,
    ta_key_digest, validator_config_hash, validator_update_id, verify_control_event,
    verify_validator_update,
};
use serde::Deserialize;

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

#[allow(dead_code)]
#[derive(Deserialize)]
struct Document {
    schema: String,
    rust_toolchain: String,
    inputs: Inputs,
    golden: Golden,
    negative: Vec<Negative>,
}

#[derive(Deserialize)]
struct Inputs {
    network_id: String,
    trust_anchor_spki_hex: String,
    resource_ca_spki_hex: String,
    exact_manifest_der_hex: String,
    control_public_key_hex: String,
    governance_public_keys_hex: Vec<String>,
}

#[derive(Deserialize)]
struct Golden {
    ta_key_digest_hex: String,
    ca_id_hex: String,
    manifest_hash_hex: String,
    publication_intent: ObjectVector,
    control_event: SignedObjectVector,
    head_body: ObjectVector,
    app_state_commitment: ObjectVector,
    validator_config: ObjectVector,
    validator_update: SignedObjectVector,
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct ObjectVector {
    canonical_cbor_hex: String,
    object_hash_hex: String,
    signing_message_hex: Option<String>,
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct SignedObjectVector {
    canonical_cbor_hex: String,
    object_hash_hex: String,
    signing_message_hex: String,
    authorization_cbor_hex: String,
}

#[derive(Deserialize)]
struct Negative {
    name: String,
    target: String,
    input_hex: String,
    expected_error: String,
}

fn document() -> TestResult<Document> {
    Ok(serde_json::from_str(include_str!(
        "../test-vectors/v1.json"
    ))?)
}

fn bytes(value: &str) -> TestResult<Vec<u8>> {
    Ok(hex::decode(value)?)
}

fn required_string(value: Option<&String>, field: &str) -> TestResult<String> {
    value
        .cloned()
        .ok_or_else(|| io::Error::other(format!("missing {field}")).into())
}

fn error_name(error: &Error) -> &'static str {
    match error {
        Error::ObjectTooLarge { .. } => "ObjectTooLarge",
        Error::CborEncode(_) => "CborEncode",
        Error::CborDecode(_) => "CborDecode",
        Error::TrailingData => "TrailingData",
        Error::NonCanonical => "NonCanonical",
        Error::Validation(_) => "Validation",
        Error::InvalidHex(_) => "InvalidHex",
        Error::InvalidSignature => "InvalidSignature",
    }
}

fn require_error<T>(result: lantern_types::Result<T>) -> TestResult<Error> {
    match result {
        Ok(_) => Err(io::Error::other("operation unexpectedly succeeded").into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn golden_identity_and_exact_manifest_hashes_are_stable() -> TestResult {
    let vectors = document()?;
    assert_eq!(vectors.inputs.network_id, "lantern-m0");

    let ta_spki = bytes(&vectors.inputs.trust_anchor_spki_hex)?;
    let resource_ca_spki = bytes(&vectors.inputs.resource_ca_spki_hex)?;
    let manifest_der = bytes(&vectors.inputs.exact_manifest_der_hex)?;
    let ta_digest = ta_key_digest(&ta_spki);
    assert_eq!(
        ta_digest,
        Hash32::from_str(&vectors.golden.ta_key_digest_hex)?
    );
    assert_eq!(
        ca_id(ta_digest, &resource_ca_spki)?,
        Hash32::from_str(&vectors.golden.ca_id_hex)?
    );
    assert_eq!(
        manifest_hash(&manifest_der),
        Hash32::from_str(&vectors.golden.manifest_hash_hex)?
    );
    Ok(())
}

#[test]
fn golden_publication_intent_round_trips_and_hashes() -> TestResult {
    let vector = document()?.golden.publication_intent;
    let canonical = bytes(&vector.canonical_cbor_hex)?;
    let intent = PublicationIntentV1::from_canonical_cbor(&canonical)?;
    assert_eq!(intent.to_canonical_cbor()?, canonical);
    assert_eq!(
        intent_id(&intent)?,
        Hash32::from_str(&vector.object_hash_hex)?
    );
    assert_eq!(
        publication_signing_message(&intent)?,
        bytes(&required_string(
            vector.signing_message_hex.as_ref(),
            "publication signing message"
        )?)?
    );
    Ok(())
}

#[test]
fn golden_control_event_and_strict_signature_verify() -> TestResult {
    let vectors = document()?;
    let vector = vectors.golden.control_event;
    let event = ControlEventV1::from_canonical_cbor(&bytes(&vector.canonical_cbor_hex)?)?;
    let authorization =
        Ed25519AuthorizationV1::from_canonical_cbor(&bytes(&vector.authorization_cbor_hex)?)?;
    let public_key = Ed25519PublicKey::from_str(&vectors.inputs.control_public_key_hex)?;

    assert_eq!(
        control_event_id(&event)?,
        Hash32::from_str(&vector.object_hash_hex)?
    );
    assert_eq!(
        lantern_types::control_signing_message(&event)?,
        bytes(&vector.signing_message_hex)?
    );
    verify_control_event(&event, public_key, &authorization)?;

    let mut changed = event;
    let mut nonce = *changed.nonce.as_bytes();
    nonce[0] ^= 1;
    changed.nonce = lantern_types::Nonce16::new(nonce);
    assert_eq!(
        require_error(verify_control_event(&changed, public_key, &authorization))?,
        Error::InvalidSignature
    );
    Ok(())
}

#[test]
fn golden_head_and_app_hash_binding_are_stable() -> TestResult {
    let vectors = document()?;
    let head_vector = vectors.golden.head_body;
    let head = HeadBodyV1::from_canonical_cbor(&bytes(&head_vector.canonical_cbor_hex)?)?;
    let expected_head_id = Hash32::from_str(&head_vector.object_hash_hex)?;
    assert_eq!(head_id(&head)?, expected_head_id);

    let app_vector = vectors.golden.app_state_commitment;
    let app = AppStateCommitmentV1::from_canonical_cbor(&bytes(&app_vector.canonical_cbor_hex)?)?;
    assert_eq!(app.closed_head_id, Some(expected_head_id));
    assert_eq!(
        app_hash(&app)?,
        Hash32::from_str(&app_vector.object_hash_hex)?
    );
    Ok(())
}

#[test]
fn golden_validator_config_and_governance_update_verify() -> TestResult {
    let vectors = document()?;
    let config_vector = vectors.golden.validator_config;
    let config =
        ValidatorConfigV1::from_canonical_cbor(&bytes(&config_vector.canonical_cbor_hex)?)?;
    assert_eq!(
        validator_config_hash(&config)?,
        Hash32::from_str(&config_vector.object_hash_hex)?
    );

    let update_vector = vectors.golden.validator_update;
    let unsigned =
        UnsignedValidatorUpdateV1::from_canonical_cbor(&bytes(&update_vector.canonical_cbor_hex)?)?;
    assert_eq!(
        validator_update_id(&unsigned)?,
        Hash32::from_str(&update_vector.object_hash_hex)?
    );
    assert_eq!(
        governance_signing_message(&unsigned)?,
        bytes(&update_vector.signing_message_hex)?
    );

    let update =
        ValidatorUpdateV1::from_canonical_cbor(&bytes(&update_vector.authorization_cbor_hex)?)?;
    assert_eq!(update.unsigned, unsigned);
    let governance_key_vec = vectors
        .inputs
        .governance_public_keys_hex
        .iter()
        .map(|value| Ed25519PublicKey::from_str(value))
        .collect::<lantern_types::Result<Vec<_>>>()?;
    let governance_keys: [Ed25519PublicKey; 3] = governance_key_vec
        .try_into()
        .map_err(|keys: Vec<_>| io::Error::other(format!("expected 3 keys, got {}", keys.len())))?;
    verify_validator_update(&update, &governance_keys)?;
    Ok(())
}

#[test]
fn checked_in_negative_vectors_fail_as_declared() -> TestResult {
    let vectors = document()?;
    let golden_event = ControlEventV1::from_canonical_cbor(&bytes(
        &vectors.golden.control_event.canonical_cbor_hex,
    )?)?;
    let control_public_key = Ed25519PublicKey::from_str(&vectors.inputs.control_public_key_hex)?;

    for vector in vectors.negative {
        let input = bytes(&vector.input_hex)?;
        let error = match vector.target.as_str() {
            "PublicationIntentV1" => {
                require_error(PublicationIntentV1::from_canonical_cbor(&input))?
            }
            "Ed25519AuthorizationV1" => {
                let authorization = Ed25519AuthorizationV1::from_canonical_cbor(&input)?;
                require_error(verify_control_event(
                    &golden_event,
                    control_public_key,
                    &authorization,
                ))?
            }
            target => {
                return Err(
                    io::Error::other(format!("unknown negative vector target {target}")).into(),
                );
            }
        };
        assert_eq!(
            error_name(&error),
            vector.expected_error,
            "negative vector {} returned {error}",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn defensive_size_limit_precedes_cbor_parsing() -> TestResult {
    let oversized = vec![0_u8; MAX_WIRE_OBJECT_BYTES + 1];
    let error = require_error(PublicationIntentV1::from_canonical_cbor(&oversized))?;
    assert!(matches!(error, Error::ObjectTooLarge { .. }));
    Ok(())
}

#[test]
fn vector_file_metadata_is_pinned() -> TestResult {
    // Byte-for-byte regeneration is checked by the M0 verification command;
    // this unit test also pins the schema/toolchain metadata consumers see.
    let vectors = document()?;
    assert_eq!(vectors.schema, "lantern-m0-v1");
    assert_eq!(
        vectors.rust_toolchain,
        "rustc 1.97.1 (8bab26f4f 2026-07-14)"
    );
    Ok(())
}
