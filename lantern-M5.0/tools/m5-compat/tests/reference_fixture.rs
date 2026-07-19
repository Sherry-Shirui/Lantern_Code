use lantern_comet_compat::{
    CompatibilityError, ReferenceFixture, verify_reference_fixture, verify_reference_json,
};
use prost::Message;
use tendermint_proto::v0_38::types::SignedHeader as RawSignedHeader;

const FIXTURE: &[u8] = include_bytes!("../test-vectors/cometbft-v0.38.23.json");

#[test]
fn official_go_fixture_passes_every_cross_language_check() -> Result<(), Box<dyn std::error::Error>>
{
    let verified = verify_reference_json(FIXTURE)?;
    assert_eq!(verified.cometbft_tag, "v0.38.23");
    assert_eq!(verified.tendermint_rs_family, "0.40.4");
    assert_eq!(verified.validator_count, 4);
    assert_eq!(verified.signed_voting_power, 4);
    assert_eq!(verified.total_voting_power, 4);
    assert_eq!(verified.signer_bitmap_lsb0_hex, "0f");
    Ok(())
}

#[test]
fn tampered_go_signature_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture: ReferenceFixture = serde_json::from_slice(FIXTURE)?;
    let wire = hex::decode(&fixture.signed_header_v0_38_proto_hex)?;
    let mut signed_header = RawSignedHeader::decode(wire.as_slice())?;
    let commit = signed_header
        .commit
        .as_mut()
        .ok_or("fixture has no commit")?;
    let signature = commit
        .signatures
        .first_mut()
        .ok_or("fixture has no signatures")?;
    let first = signature
        .signature
        .first_mut()
        .ok_or("fixture signature is empty")?;
    *first ^= 0x01;
    fixture
        .validators
        .first_mut()
        .ok_or("fixture has no validator vectors")?
        .signature_hex = hex::encode(&signature.signature);
    fixture.signed_header_v0_38_proto_hex = hex::encode(signed_header.encode_to_vec());

    assert!(matches!(
        verify_reference_fixture(&fixture),
        Err(CompatibilityError::Signature { index: 0, .. })
    ));
    Ok(())
}

#[test]
fn validator_hash_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture: ReferenceFixture = serde_json::from_slice(FIXTURE)?;
    fixture.validator_set_hash_hex = "00".repeat(32);
    assert!(matches!(
        verify_reference_fixture(&fixture),
        Err(CompatibilityError::Mismatch {
            field: "validator_set_hash_hex",
            ..
        })
    ));
    Ok(())
}

#[test]
fn truncated_v038_protobuf_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture: ReferenceFixture = serde_json::from_slice(FIXTURE)?;
    let mut wire = hex::decode(&fixture.signed_header_v0_38_proto_hex)?;
    let _discarded = wire.pop().ok_or("fixture wire bytes are empty")?;
    fixture.signed_header_v0_38_proto_hex = hex::encode(wire);
    assert!(matches!(
        verify_reference_fixture(&fixture),
        Err(CompatibilityError::ProtobufDecode {
            object: "SignedHeader",
            ..
        })
    ));
    Ok(())
}
