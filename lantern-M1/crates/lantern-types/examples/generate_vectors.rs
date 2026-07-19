use ed25519_dalek::SigningKey;
use lantern_types::{
    AppStateCommitmentV1, ControlActionV1, ControlEventV1, Ed25519PublicKey, Hash32, HeadBodyV1,
    NetworkId, Nonce16, PROTOCOL_VERSION_V1, PublicationEventTypeV1, PublicationIntentV1,
    PublicationSignatureAlgorithmV1, TimestampV1, UnsignedValidatorUpdateV1, ValidatorConfigV1,
    ValidatorInfoV1, WireObject, app_hash, ca_id, control_event_id, governance_signing_message,
    head_id, intent_id, manifest_hash, publication_signing_message, sha256, sign_control_event,
    sign_validator_update, ta_key_digest, validator_config_hash, validator_update_id,
};
use serde::Serialize;

#[derive(Serialize)]
struct Document {
    schema: &'static str,
    rust_toolchain: &'static str,
    inputs: Inputs,
    golden: Golden,
    negative: Vec<Negative>,
}

#[derive(Serialize)]
struct Inputs {
    network_id: &'static str,
    trust_anchor_spki_hex: String,
    resource_ca_spki_hex: String,
    exact_manifest_der_hex: String,
    control_public_key_hex: String,
    governance_public_keys_hex: Vec<String>,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct ObjectVector {
    canonical_cbor_hex: String,
    object_hash_hex: String,
    signing_message_hex: Option<String>,
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct SignedObjectVector {
    canonical_cbor_hex: String,
    object_hash_hex: String,
    signing_message_hex: String,
    authorization_cbor_hex: String,
}

#[derive(Serialize)]
struct Negative {
    name: &'static str,
    target: &'static str,
    input_hex: String,
    expected_error: &'static str,
}

fn tagged_hash(label: &[u8]) -> Hash32 {
    sha256(label)
}

fn validator_config(network_id: &NetworkId) -> ValidatorConfigV1 {
    let mut validators = (0x21_u8..=0x24)
        .map(|byte| {
            let signing_key = SigningKey::from_bytes(&[byte; 32]);
            ValidatorInfoV1::from_public_key(Ed25519PublicKey::new(
                signing_key.verifying_key().to_bytes(),
            ))
        })
        .collect::<Vec<_>>();
    validators.sort_by(|left, right| {
        right
            .voting_power
            .cmp(&left.voting_power)
            .then_with(|| left.address.cmp(&right.address))
    });
    ValidatorConfigV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: network_id.clone(),
        key_epoch: 2,
        effective_height: 100,
        validators,
    }
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let network_id = NetworkId::new("lantern-m0")?;
    let ta_spki = b"test-ta-spki-der-v1";
    let resource_ca_spki = b"test-resource-ca-spki-der-v1";
    let exact_manifest = b"test-manifest-der-v1";
    let ta_digest = ta_key_digest(ta_spki);
    let ca_identifier = ca_id(ta_digest, resource_ca_spki)?;
    let exact_manifest_hash = manifest_hash(exact_manifest);

    let publication_intent = PublicationIntentV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: network_id.clone(),
        event_type: PublicationEventTypeV1::Publish,
        ca_id: ca_identifier,
        manifest_number: 42,
        manifest_hash: exact_manifest_hash,
        previous_manifest_hash: Some(manifest_hash(b"previous-manifest-der-v1")),
        nonce: Nonce16::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
        signature_algorithm: PublicationSignatureAlgorithmV1::RsaPkcs1V15Sha256,
    };
    let intent_cbor = publication_intent.to_canonical_cbor()?;

    let control_event = ControlEventV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: network_id.clone(),
        ca_id: ca_identifier,
        admin_sequence: 1,
        previous_state_hash: None,
        nonce: Nonce16::new([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]),
        action: ControlActionV1::Enable {
            initial_manifest_hash: exact_manifest_hash,
        },
    };
    let control_signing_key = SigningKey::from_bytes(&[0x11; 32]);
    let control_authorization = sign_control_event(&control_event, &control_signing_key)?;

    let head_body = HeadBodyV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: network_id.clone(),
        epoch: 7,
        epoch_start: TimestampV1::new(1_800_000_000, 0)?,
        epoch_end: TimestampV1::new(1_800_000_300, 0)?,
        issued_at: TimestampV1::new(1_800_000_301, 123_456_789)?,
        latest_root: tagged_hash(b"latest-root-v1"),
        history_root: tagged_hash(b"history-root-v1"),
        previous_head_id: Some(tagged_hash(b"previous-head-id-v1")),
        bundle_hash: tagged_hash(b"epoch-bundle-v1"),
        history_length: 128,
        latest_entry_count: 17,
        key_epoch: 2,
    };
    let computed_head_id = head_id(&head_body)?;

    let app_state = AppStateCommitmentV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: network_id.clone(),
        app_height: 9_001,
        pending_latest_root: head_body.latest_root,
        pending_history_root: head_body.history_root,
        history_length: head_body.history_length,
        latest_entry_count: head_body.latest_entry_count,
        last_closed_epoch: Some(head_body.epoch),
        closed_head_id: Some(computed_head_id),
        validator_config_hash: tagged_hash(b"active-validator-config-v1"),
        ca_admin_registry_hash: tagged_hash(b"ca-admin-registry-v1"),
        governance_config_hash: tagged_hash(b"governance-config-v1"),
        transaction_results_hash: tagged_hash(b"tx-results-v1"),
        schema_config_hash: tagged_hash(b"schema-config-v1"),
    };

    let next_validator_config = validator_config(&network_id);
    let unsigned_validator_update = UnsignedValidatorUpdateV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        network_id: network_id.clone(),
        sequence: 8,
        current_config_hash: tagged_hash(b"current-validator-config-v1"),
        next_config: next_validator_config.clone(),
    };
    let governance_keys = [
        SigningKey::from_bytes(&[0x31; 32]),
        SigningKey::from_bytes(&[0x32; 32]),
        SigningKey::from_bytes(&[0x33; 32]),
    ];
    let validator_update = sign_validator_update(
        unsigned_validator_update,
        &[(0, &governance_keys[0]), (2, &governance_keys[2])],
    )?;

    let mut non_canonical_version = Vec::with_capacity(intent_cbor.len() + 1);
    non_canonical_version.push(intent_cbor[0]);
    non_canonical_version.extend_from_slice(&[0x18, 0x01]);
    non_canonical_version.extend_from_slice(&intent_cbor[2..]);

    let mut trailing = intent_cbor.clone();
    trailing.push(0x00);

    let mut wrong_array_length = intent_cbor.clone();
    wrong_array_length[0] = 0x88;

    let mut wrong_protocol_version = intent_cbor.clone();
    wrong_protocol_version[1] = 0x02;

    let mut invalid_network = intent_cbor.clone();
    if let Some(position) = invalid_network
        .windows(network_id.as_str().len())
        .position(|window| window == network_id.as_str().as_bytes())
    {
        invalid_network[position + 7] = b'/';
    }

    let mut invalid_control_authorization = control_authorization;
    let mut invalid_signature = *invalid_control_authorization.signature.as_bytes();
    invalid_signature[63] ^= 0x01;
    invalid_control_authorization.signature =
        lantern_types::Ed25519Signature::new(invalid_signature);

    let control_public_key = Ed25519PublicKey::new(control_signing_key.verifying_key().to_bytes());
    let governance_public_keys = governance_keys
        .iter()
        .map(|key| hex::encode(key.verifying_key().to_bytes()))
        .collect::<Vec<_>>();

    let document = Document {
        schema: "lantern-m0-v1",
        rust_toolchain: "rustc 1.97.1 (8bab26f4f 2026-07-14)",
        inputs: Inputs {
            network_id: "lantern-m0",
            trust_anchor_spki_hex: hex::encode(ta_spki),
            resource_ca_spki_hex: hex::encode(resource_ca_spki),
            exact_manifest_der_hex: hex::encode(exact_manifest),
            control_public_key_hex: control_public_key.to_hex(),
            governance_public_keys_hex: governance_public_keys,
        },
        golden: Golden {
            ta_key_digest_hex: ta_digest.to_hex(),
            ca_id_hex: ca_identifier.to_hex(),
            manifest_hash_hex: exact_manifest_hash.to_hex(),
            publication_intent: ObjectVector {
                canonical_cbor_hex: hex::encode(&intent_cbor),
                object_hash_hex: intent_id(&publication_intent)?.to_hex(),
                signing_message_hex: Some(hex::encode(publication_signing_message(
                    &publication_intent,
                )?)),
            },
            control_event: SignedObjectVector {
                canonical_cbor_hex: hex::encode(control_event.to_canonical_cbor()?),
                object_hash_hex: control_event_id(&control_event)?.to_hex(),
                signing_message_hex: hex::encode(lantern_types::control_signing_message(
                    &control_event,
                )?),
                authorization_cbor_hex: hex::encode(control_authorization.to_canonical_cbor()?),
            },
            head_body: ObjectVector {
                canonical_cbor_hex: hex::encode(head_body.to_canonical_cbor()?),
                object_hash_hex: computed_head_id.to_hex(),
                signing_message_hex: None,
            },
            app_state_commitment: ObjectVector {
                canonical_cbor_hex: hex::encode(app_state.to_canonical_cbor()?),
                object_hash_hex: app_hash(&app_state)?.to_hex(),
                signing_message_hex: None,
            },
            validator_config: ObjectVector {
                canonical_cbor_hex: hex::encode(next_validator_config.to_canonical_cbor()?),
                object_hash_hex: validator_config_hash(&next_validator_config)?.to_hex(),
                signing_message_hex: None,
            },
            validator_update: SignedObjectVector {
                canonical_cbor_hex: hex::encode(validator_update.unsigned.to_canonical_cbor()?),
                object_hash_hex: validator_update_id(&validator_update.unsigned)?.to_hex(),
                signing_message_hex: hex::encode(governance_signing_message(
                    &validator_update.unsigned,
                )?),
                authorization_cbor_hex: hex::encode(validator_update.to_canonical_cbor()?),
            },
        },
        negative: vec![
            Negative {
                name: "non_canonical_integer_width",
                target: "PublicationIntentV1",
                input_hex: hex::encode(non_canonical_version),
                expected_error: "NonCanonical",
            },
            Negative {
                name: "trailing_data",
                target: "PublicationIntentV1",
                input_hex: hex::encode(trailing),
                expected_error: "TrailingData",
            },
            Negative {
                name: "wrong_array_length",
                target: "PublicationIntentV1",
                input_hex: hex::encode(wrong_array_length),
                expected_error: "Validation",
            },
            Negative {
                name: "wrong_protocol_version",
                target: "PublicationIntentV1",
                input_hex: hex::encode(wrong_protocol_version),
                expected_error: "Validation",
            },
            Negative {
                name: "invalid_network_character",
                target: "PublicationIntentV1",
                input_hex: hex::encode(invalid_network),
                expected_error: "Validation",
            },
            Negative {
                name: "wrong_control_signature",
                target: "Ed25519AuthorizationV1",
                input_hex: hex::encode(invalid_control_authorization.to_canonical_cbor()?),
                expected_error: "InvalidSignature",
            },
        ],
    };

    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}
