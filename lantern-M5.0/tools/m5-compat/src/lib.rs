//! M5.0 compatibility checks between `CometBFT` v0.38.23 Go wire objects and
//! the `tendermint-rs` 0.40.4 family.
//!
//! This crate is a gate and test tool. It is deliberately not the production
//! `lantern-qc` or `lantern-comet` implementation scheduled for later M5
//! stages, and it has no dependency on the M1--M4 application crates.

use prost::Message;
use serde::{Deserialize, Serialize};
use tendermint::{
    Vote,
    block::{CommitSig, signed_header::SignedHeader},
    chain::Id as ChainId,
    crypto::default::signature::Verifier as Ed25519Verifier,
    validator::Set as ValidatorSet,
    vote::{Type as VoteType, ValidatorIndex},
};
use tendermint_proto::v0_38::types::{
    SignedHeader as RawSignedHeader, ValidatorSet as RawValidatorSet,
};
use thiserror::Error;

/// The exact `CometBFT` source revision accepted by this compatibility gate.
pub const COMETBFT_COMMIT: &str = "feb2aea4dc271d612129afc958cb844713ec792b";
/// The exact `CometBFT` release tag accepted by this compatibility gate.
pub const COMETBFT_TAG: &str = "v0.38.23";
/// The exact `tendermint-rs` release family accepted by this gate.
pub const TENDERMINT_RS_FAMILY: &str = "0.40.4";

/// One validator entry emitted by the official Go reference generator.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidatorVector {
    pub index: usize,
    pub address_hex: String,
    pub public_key_hex: String,
    pub voting_power: i64,
    pub sign_bytes_hex: String,
    pub signature_hex: String,
}

/// Reference fixture produced by `reference/main.go` against pinned upstream
/// `CometBFT` source.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReferenceFixture {
    pub format_version: u64,
    pub reference_implementation: String,
    pub cometbft_tag: String,
    pub cometbft_commit: String,
    pub cometbft_source_version: String,
    pub rust_family: String,
    pub chain_id: String,
    pub height: i64,
    pub round: i32,
    pub header_hash_hex: String,
    pub validator_set_hash_hex: String,
    pub signed_header_v0_38_proto_hex: String,
    pub validator_set_v0_38_proto_hex: String,
    pub signer_bitmap_lsb0_hex: String,
    pub validators: Vec<ValidatorVector>,
}

/// Evidence returned after every M5.0 compatibility assertion has passed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedReference {
    pub cometbft_tag: String,
    pub cometbft_commit: String,
    pub cometbft_source_version: String,
    pub tendermint_rs_family: String,
    pub chain_id: String,
    pub height: u64,
    pub round: u32,
    pub header_hash_hex: String,
    pub validator_set_hash_hex: String,
    pub signer_bitmap_lsb0_hex: String,
    pub validator_count: usize,
    pub signed_voting_power: u64,
    pub total_voting_power: u64,
}

/// A fail-closed interoperability error.
#[derive(Debug, Error)]
pub enum CompatibilityError {
    #[error("invalid fixture JSON: {0}")]
    FixtureJson(String),
    #[error("invalid hexadecimal field {field}: {detail}")]
    Hex { field: &'static str, detail: String },
    #[error("cannot decode {object} as v0.38 protobuf: {detail}")]
    ProtobufDecode {
        object: &'static str,
        detail: String,
    },
    #[error("{object} is not canonical protobuf for this compatibility profile")]
    NonCanonicalProtobuf { object: &'static str },
    #[error("cannot convert {object} to tendermint-rs 0.40.4: {detail}")]
    DomainConversion {
        object: &'static str,
        detail: String,
    },
    #[error("compatibility mismatch for {field}: expected {expected}, got {actual}")]
    Mismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("commit signature at validator index {index} is absent or for nil")]
    NonCommitSignature { index: usize },
    #[error("commit signature at validator index {index} is missing")]
    MissingSignature { index: usize },
    #[error("invalid validator index {index}: {detail}")]
    ValidatorIndex { index: usize, detail: String },
    #[error("invalid chain ID: {0}")]
    ChainId(String),
    #[error("signature verification failed at validator index {index}: {detail}")]
    Signature { index: usize, detail: String },
    #[error(
        "insufficient commit voting power: signed {signed}, total {total}; strictly more than 2/3 required"
    )]
    InsufficientVotingPower { signed: u64, total: u64 },
}

// Values are intentionally consumed here so call sites can pass both owned
// formatting results and borrowed domain values without temporary bindings.
#[allow(clippy::needless_pass_by_value)]
fn mismatch(
    field: &'static str,
    expected: impl ToString,
    actual: impl ToString,
) -> CompatibilityError {
    CompatibilityError::Mismatch {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    }
}

fn decode_hex(field: &'static str, encoded: &str) -> Result<Vec<u8>, CompatibilityError> {
    hex::decode(encoded).map_err(|error| CompatibilityError::Hex {
        field,
        detail: error.to_string(),
    })
}

fn check_fixture_metadata(fixture: &ReferenceFixture) -> Result<(), CompatibilityError> {
    if fixture.format_version != 1 {
        return Err(mismatch("format_version", 1, fixture.format_version));
    }
    if fixture.cometbft_tag != COMETBFT_TAG {
        return Err(mismatch(
            "cometbft_tag",
            COMETBFT_TAG,
            &fixture.cometbft_tag,
        ));
    }
    if fixture.cometbft_commit != COMETBFT_COMMIT {
        return Err(mismatch(
            "cometbft_commit",
            COMETBFT_COMMIT,
            &fixture.cometbft_commit,
        ));
    }
    if fixture.rust_family != TENDERMINT_RS_FAMILY {
        return Err(mismatch(
            "rust_family",
            TENDERMINT_RS_FAMILY,
            &fixture.rust_family,
        ));
    }
    Ok(())
}

/// Parse and validate a JSON fixture.
///
/// # Errors
///
/// Returns a fail-closed compatibility error for malformed JSON or for any
/// wire, hash, ordering, sign-byte, signature, bitmap, or threshold mismatch.
pub fn verify_reference_json(input: &[u8]) -> Result<VerifiedReference, CompatibilityError> {
    let fixture: ReferenceFixture = serde_json::from_slice(input)
        .map_err(|error| CompatibilityError::FixtureJson(error.to_string()))?;
    verify_reference_fixture(&fixture)
}

/// Validate Go-produced v0.38 wire bytes, hash computations, vote sign bytes,
/// signatures, canonical validator order, signer bitmap, and voting threshold.
///
/// # Errors
///
/// Returns a fail-closed compatibility error on the first failed invariant.
// Keeping the assertions together makes this gate auditable against the
// M5.0 checklist; each branch names the exact cross-language invariant.
#[allow(clippy::too_many_lines)]
pub fn verify_reference_fixture(
    fixture: &ReferenceFixture,
) -> Result<VerifiedReference, CompatibilityError> {
    check_fixture_metadata(fixture)?;

    let signed_header_bytes = decode_hex(
        "signed_header_v0_38_proto_hex",
        &fixture.signed_header_v0_38_proto_hex,
    )?;
    let validator_set_bytes = decode_hex(
        "validator_set_v0_38_proto_hex",
        &fixture.validator_set_v0_38_proto_hex,
    )?;
    let raw_signed_header =
        RawSignedHeader::decode(signed_header_bytes.as_slice()).map_err(|error| {
            CompatibilityError::ProtobufDecode {
                object: "SignedHeader",
                detail: error.to_string(),
            }
        })?;
    let raw_validator_set =
        RawValidatorSet::decode(validator_set_bytes.as_slice()).map_err(|error| {
            CompatibilityError::ProtobufDecode {
                object: "ValidatorSet",
                detail: error.to_string(),
            }
        })?;

    if raw_signed_header.encode_to_vec() != signed_header_bytes {
        return Err(CompatibilityError::NonCanonicalProtobuf {
            object: "SignedHeader",
        });
    }
    if raw_validator_set.encode_to_vec() != validator_set_bytes {
        return Err(CompatibilityError::NonCanonicalProtobuf {
            object: "ValidatorSet",
        });
    }

    let signed_header = SignedHeader::try_from(raw_signed_header).map_err(|error| {
        CompatibilityError::DomainConversion {
            object: "SignedHeader",
            detail: error.to_string(),
        }
    })?;
    let validator_set = ValidatorSet::try_from(raw_validator_set).map_err(|error| {
        CompatibilityError::DomainConversion {
            object: "ValidatorSet",
            detail: error.to_string(),
        }
    })?;

    if signed_header.header.chain_id.to_string() != fixture.chain_id {
        return Err(mismatch(
            "chain_id",
            &fixture.chain_id,
            signed_header.header.chain_id,
        ));
    }
    let height = signed_header.header.height.value();
    let fixture_height = u64::try_from(fixture.height)
        .map_err(|error| mismatch("height", "a non-negative u64", error))?;
    if height != fixture_height {
        return Err(mismatch("height", fixture_height, height));
    }
    let round = signed_header.commit.round.value();
    let fixture_round = u32::try_from(fixture.round)
        .map_err(|error| mismatch("round", "a non-negative u32", error))?;
    if round != fixture_round {
        return Err(mismatch("round", fixture_round, round));
    }
    if signed_header.commit.height != signed_header.header.height {
        return Err(mismatch(
            "commit.height",
            signed_header.header.height,
            signed_header.commit.height,
        ));
    }

    let header_hash = signed_header.header.hash();
    if signed_header.commit.block_id.hash != header_hash {
        return Err(mismatch(
            "commit.block_id.hash",
            header_hash,
            signed_header.commit.block_id.hash,
        ));
    }
    let expected_header_hash = decode_hex("header_hash_hex", &fixture.header_hash_hex)?;
    if header_hash.as_bytes() != expected_header_hash {
        return Err(mismatch(
            "header_hash_hex",
            &fixture.header_hash_hex,
            hex::encode(header_hash.as_bytes()),
        ));
    }

    let validator_set_hash = validator_set.hash();
    if signed_header.header.validators_hash != validator_set_hash {
        return Err(mismatch(
            "header.validators_hash",
            validator_set_hash,
            signed_header.header.validators_hash,
        ));
    }
    let expected_validator_set_hash =
        decode_hex("validator_set_hash_hex", &fixture.validator_set_hash_hex)?;
    if validator_set_hash.as_bytes() != expected_validator_set_hash {
        return Err(mismatch(
            "validator_set_hash_hex",
            &fixture.validator_set_hash_hex,
            hex::encode(validator_set_hash.as_bytes()),
        ));
    }

    let validators = validator_set.validators();
    if fixture.validators.len() != validators.len() {
        return Err(mismatch(
            "validators.length",
            validators.len(),
            fixture.validators.len(),
        ));
    }
    if signed_header.commit.signatures.len() != validators.len() {
        return Err(mismatch(
            "commit.signatures.length",
            validators.len(),
            signed_header.commit.signatures.len(),
        ));
    }

    let chain_id = fixture
        .chain_id
        .parse::<ChainId>()
        .map_err(|error| CompatibilityError::ChainId(error.to_string()))?;
    let mut signer_bitmap = vec![0_u8; validators.len().div_ceil(8)];
    let mut signed_voting_power = 0_u64;

    for (index, ((validator, commit_signature), vector)) in validators
        .iter()
        .zip(&signed_header.commit.signatures)
        .zip(&fixture.validators)
        .enumerate()
    {
        if vector.index != index {
            return Err(mismatch("validator.index", index, vector.index));
        }
        if hex::encode(validator.address.as_bytes()) != vector.address_hex {
            return Err(mismatch(
                "validator.address_hex",
                &vector.address_hex,
                hex::encode(validator.address.as_bytes()),
            ));
        }
        if hex::encode(validator.pub_key.to_bytes()) != vector.public_key_hex {
            return Err(mismatch(
                "validator.public_key_hex",
                &vector.public_key_hex,
                hex::encode(validator.pub_key.to_bytes()),
            ));
        }
        let vector_power = u64::try_from(vector.voting_power)
            .map_err(|error| mismatch("validator.voting_power", validator.power(), error))?;
        if validator.power() != vector_power {
            return Err(mismatch(
                "validator.voting_power",
                vector_power,
                validator.power(),
            ));
        }

        let (validator_address, timestamp, signature) = match commit_signature {
            CommitSig::BlockIdFlagCommit {
                validator_address,
                timestamp,
                signature,
            } => (
                *validator_address,
                *timestamp,
                signature
                    .clone()
                    .ok_or(CompatibilityError::MissingSignature { index })?,
            ),
            CommitSig::BlockIdFlagAbsent | CommitSig::BlockIdFlagNil { .. } => {
                return Err(CompatibilityError::NonCommitSignature { index });
            }
        };
        if validator_address != validator.address {
            return Err(mismatch(
                "commit.validator_address",
                validator.address,
                validator_address,
            ));
        }

        let validator_index = ValidatorIndex::try_from(index).map_err(|error| {
            CompatibilityError::ValidatorIndex {
                index,
                detail: error.to_string(),
            }
        })?;
        let vote = Vote {
            vote_type: VoteType::Precommit,
            height: signed_header.commit.height,
            round: signed_header.commit.round,
            block_id: Some(signed_header.commit.block_id),
            timestamp: Some(timestamp),
            validator_address,
            validator_index,
            signature: Some(signature.clone()),
            extension: Vec::new(),
            extension_signature: None,
        };
        let sign_bytes = vote.into_signable_vec(chain_id.clone());
        let expected_sign_bytes = decode_hex("validator.sign_bytes_hex", &vector.sign_bytes_hex)?;
        if sign_bytes != expected_sign_bytes {
            return Err(mismatch(
                "validator.sign_bytes_hex",
                &vector.sign_bytes_hex,
                hex::encode(&sign_bytes),
            ));
        }
        let expected_signature = decode_hex("validator.signature_hex", &vector.signature_hex)?;
        if signature.as_bytes() != expected_signature {
            return Err(mismatch(
                "validator.signature_hex",
                &vector.signature_hex,
                hex::encode(signature.as_bytes()),
            ));
        }
        validator
            .verify_signature::<Ed25519Verifier>(&sign_bytes, &signature)
            .map_err(|error| CompatibilityError::Signature {
                index,
                detail: error.to_string(),
            })?;
        signer_bitmap[index / 8] |= 1_u8 << (index % 8);
        signed_voting_power = signed_voting_power.saturating_add(validator.power());
    }

    let total_voting_power = validator_set.total_voting_power().value();
    if u128::from(signed_voting_power) * 3 <= u128::from(total_voting_power) * 2 {
        return Err(CompatibilityError::InsufficientVotingPower {
            signed: signed_voting_power,
            total: total_voting_power,
        });
    }
    let expected_signer_bitmap =
        decode_hex("signer_bitmap_lsb0_hex", &fixture.signer_bitmap_lsb0_hex)?;
    if signer_bitmap != expected_signer_bitmap {
        return Err(mismatch(
            "signer_bitmap_lsb0_hex",
            &fixture.signer_bitmap_lsb0_hex,
            hex::encode(&signer_bitmap),
        ));
    }

    Ok(VerifiedReference {
        cometbft_tag: fixture.cometbft_tag.clone(),
        cometbft_commit: fixture.cometbft_commit.clone(),
        cometbft_source_version: fixture.cometbft_source_version.clone(),
        tendermint_rs_family: fixture.rust_family.clone(),
        chain_id: fixture.chain_id.clone(),
        height,
        round,
        header_hash_hex: hex::encode(header_hash.as_bytes()),
        validator_set_hash_hex: hex::encode(validator_set_hash.as_bytes()),
        signer_bitmap_lsb0_hex: hex::encode(signer_bitmap),
        validator_count: validators.len(),
        signed_voting_power,
        total_voting_power,
    })
}
