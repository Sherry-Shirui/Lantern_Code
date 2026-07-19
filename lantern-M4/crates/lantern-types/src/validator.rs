use ed25519_dalek::SigningKey;
use minicbor::{Decoder, Encoder};

use crate::{
    DomainV1, Ed25519AuthorizationV1, Ed25519PublicKey, Ed25519Signature, Error, Hash32, NetworkId,
    PROTOCOL_VERSION_V1, Result, ValidatorAddress, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{decode_error, encode_array, encode_error, expect_array},
    domain::domain_separated_message,
    hash::{sha256, validator_config_hash},
    signature::{sign_ed25519_message, verify_ed25519_message},
};

/// One equal-weight Ed25519 validator entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorInfoV1 {
    /// `CometBFT` Ed25519 address (`SHA-256(pubkey)[0..20]`).
    pub address: ValidatorAddress,
    /// Raw Ed25519 consensus public key.
    pub public_key: Ed25519PublicKey,
    /// Voting power; M0/MVP requires exactly one.
    pub voting_power: u64,
}

impl ValidatorInfoV1 {
    /// Constructs the canonical equal-weight validator entry from a public key.
    #[must_use]
    pub fn from_public_key(public_key: Ed25519PublicKey) -> Self {
        let digest = sha256(public_key.as_bytes());
        let mut address = [0_u8; 20];
        address.copy_from_slice(&digest.as_bytes()[..20]);
        Self {
            address: ValidatorAddress::new(address),
            public_key,
            voting_power: 1,
        }
    }
}

impl WireValue for ValidatorInfoV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 3)?;
        encoder
            .bytes(self.address.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.public_key.as_bytes())
            .map_err(encode_error)?;
        encoder.u64(self.voting_power).map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 3, "ValidatorInfoV1")?;
        Ok(Self {
            address: ValidatorAddress::decode_value(decoder)?,
            public_key: Ed25519PublicKey::decode_value(decoder)?,
            voting_power: decoder.u64().map_err(decode_error)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.voting_power != 1 {
            return Err(Error::Validation(
                "MVP validator voting power must equal one".to_owned(),
            ));
        }
        if Self::from_public_key(self.public_key).address != self.address {
            return Err(Error::Validation(
                "validator address does not match Ed25519 public key".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(ValidatorInfoV1);

/// The governance-authorized validator configuration for one key epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorConfigV1 {
    /// Wire protocol version; must be one.
    pub protocol_version: u16,
    /// Lantern/Comet chain identifier.
    pub network_id: NetworkId,
    /// Monotonic key epoch.
    pub key_epoch: u64,
    /// First block height at which this set is current.
    pub effective_height: u64,
    /// Exactly four validators in `CometBFT` canonical order.
    pub validators: Vec<ValidatorInfoV1>,
}

impl WireValue for ValidatorConfigV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 5)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        encoder.u64(self.key_epoch).map_err(encode_error)?;
        encoder.u64(self.effective_height).map_err(encode_error)?;
        let length = u64::try_from(self.validators.len())
            .map_err(|_| Error::Validation("validator count exceeds u64".to_owned()))?;
        encode_array(encoder, length)?;
        for validator in &self.validators {
            validator.encode_value(encoder)?;
        }
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 5, "ValidatorConfigV1")?;
        let protocol_version = decoder.u16().map_err(decode_error)?;
        let network_id = NetworkId::decode_value(decoder)?;
        let key_epoch = decoder.u64().map_err(decode_error)?;
        let effective_height = decoder.u64().map_err(decode_error)?;
        let length = decoder.array().map_err(decode_error)?.ok_or_else(|| {
            Error::Validation("validator list must be definite-length".to_owned())
        })?;
        let capacity = usize::try_from(length)
            .map_err(|_| Error::Validation("validator count exceeds usize".to_owned()))?;
        let mut validators = Vec::with_capacity(capacity.min(4));
        for _ in 0..length {
            validators.push(ValidatorInfoV1::decode_value(decoder)?);
        }
        Ok(Self {
            protocol_version,
            network_id,
            key_epoch,
            effective_height,
            validators,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(format!(
                "validator config protocol version is {}, expected {PROTOCOL_VERSION_V1}",
                self.protocol_version
            )));
        }
        self.network_id.validate()?;
        if self.effective_height == 0 {
            return Err(Error::Validation(
                "validator effective height must be non-zero".to_owned(),
            ));
        }
        if self.validators.len() != 4 {
            return Err(Error::Validation(format!(
                "validator configuration has {}, expected 4",
                self.validators.len()
            )));
        }
        for validator in &self.validators {
            validator.validate()?;
        }
        for pair in self.validators.windows(2) {
            let left = pair[0];
            let right = pair[1];
            let ordered = left.voting_power > right.voting_power
                || (left.voting_power == right.voting_power && left.address < right.address);
            if !ordered {
                return Err(Error::Validation(
                    "validators are not in voting-power/address canonical order or are duplicated"
                        .to_owned(),
                ));
            }
        }
        for (index, validator) in self.validators.iter().enumerate() {
            if self.validators[index + 1..]
                .iter()
                .any(|other| other.public_key == validator.public_key)
            {
                return Err(Error::Validation(
                    "validator public keys must be unique".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl_wire_object!(ValidatorConfigV1);

/// Governance-signed validator update payload, excluding signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedValidatorUpdateV1 {
    /// Wire protocol version; must be one.
    pub protocol_version: u16,
    /// Lantern/Comet chain identifier.
    pub network_id: NetworkId,
    /// Monotonic governance update sequence.
    pub sequence: u64,
    /// Hash of the currently authorized validator configuration.
    pub current_config_hash: Hash32,
    /// Complete replacement configuration. M5 enforces one-at-a-time changes
    /// and `CometBFT` `H+2` activation semantics.
    pub next_config: ValidatorConfigV1,
}

impl WireValue for UnsignedValidatorUpdateV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 5)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        encoder.u64(self.sequence).map_err(encode_error)?;
        encoder
            .bytes(self.current_config_hash.as_bytes())
            .map_err(encode_error)?;
        self.next_config.encode_value(encoder)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 5, "UnsignedValidatorUpdateV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            sequence: decoder.u64().map_err(decode_error)?,
            current_config_hash: Hash32::decode_value(decoder)?,
            next_config: ValidatorConfigV1::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(format!(
                "validator update protocol version is {}, expected {PROTOCOL_VERSION_V1}",
                self.protocol_version
            )));
        }
        self.network_id.validate()?;
        if self.sequence == 0 {
            return Err(Error::Validation(
                "validator update sequence must be non-zero".to_owned(),
            ));
        }
        self.next_config.validate()?;
        if self.next_config.network_id != self.network_id {
            return Err(Error::Validation(
                "validator update and next configuration use different networks".to_owned(),
            ));
        }
        if validator_config_hash(&self.next_config)? == self.current_config_hash {
            return Err(Error::Validation(
                "validator update does not change the configuration".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(UnsignedValidatorUpdateV1);

/// One signature slot in a governance-authorized update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceSignatureV1 {
    /// Index into the three-key governance trust configuration.
    pub signer_index: u8,
    /// Domain-separated key identifier.
    pub key_id: Hash32,
    /// Raw Ed25519 signature.
    pub signature: Ed25519Signature,
}

impl WireValue for GovernanceSignatureV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 3)?;
        encoder.u8(self.signer_index).map_err(encode_error)?;
        encoder
            .bytes(self.key_id.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.signature.as_bytes())
            .map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 3, "GovernanceSignatureV1")?;
        Ok(Self {
            signer_index: decoder.u8().map_err(decode_error)?,
            key_id: Hash32::decode_value(decoder)?,
            signature: Ed25519Signature::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.signer_index >= 3 {
            return Err(Error::Validation(
                "governance signer index must be 0, 1, or 2".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(GovernanceSignatureV1);

/// A complete 2-of-3 governance-authorized validator update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorUpdateV1 {
    /// Signed update payload.
    pub unsigned: UnsignedValidatorUpdateV1,
    /// Two or three signatures, sorted by signer index.
    pub signatures: Vec<GovernanceSignatureV1>,
}

impl WireValue for ValidatorUpdateV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 2)?;
        self.unsigned.encode_value(encoder)?;
        let length = u64::try_from(self.signatures.len())
            .map_err(|_| Error::Validation("signature count exceeds u64".to_owned()))?;
        encode_array(encoder, length)?;
        for signature in &self.signatures {
            signature.encode_value(encoder)?;
        }
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 2, "ValidatorUpdateV1")?;
        let unsigned = UnsignedValidatorUpdateV1::decode_value(decoder)?;
        let length = decoder.array().map_err(decode_error)?.ok_or_else(|| {
            Error::Validation("signature list must be definite-length".to_owned())
        })?;
        let capacity = usize::try_from(length)
            .map_err(|_| Error::Validation("signature count exceeds usize".to_owned()))?;
        let mut signatures = Vec::with_capacity(capacity.min(3));
        for _ in 0..length {
            signatures.push(GovernanceSignatureV1::decode_value(decoder)?);
        }
        Ok(Self {
            unsigned,
            signatures,
        })
    }

    fn validate_value(&self) -> Result<()> {
        self.unsigned.validate()?;
        if !(2..=3).contains(&self.signatures.len()) {
            return Err(Error::Validation(
                "validator update requires two or three governance signatures".to_owned(),
            ));
        }
        for signature in &self.signatures {
            signature.validate()?;
        }
        if self
            .signatures
            .windows(2)
            .any(|pair| pair[0].signer_index >= pair[1].signer_index)
        {
            return Err(Error::Validation(
                "governance signatures must have unique ascending signer indices".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(ValidatorUpdateV1);

/// Returns the exact domain-separated message signed by governance keys.
///
/// # Errors
///
/// Returns an error if the update is invalid, cannot be encoded, or cannot be
/// length-framed.
pub fn governance_signing_message(update: &UnsignedValidatorUpdateV1) -> Result<Vec<u8>> {
    domain_separated_message(DomainV1::Governance, &update.to_canonical_cbor()?)
}

/// Produces a sorted 2-of-3 or 3-of-3 authorization for a validator update.
///
/// # Errors
///
/// Returns an error for an invalid update, an invalid signer set, or encoding
/// and key-ID framing failures.
pub fn sign_validator_update(
    unsigned: UnsignedValidatorUpdateV1,
    signers: &[(u8, &SigningKey)],
) -> Result<ValidatorUpdateV1> {
    unsigned.validate()?;
    if !(2..=3).contains(&signers.len()) {
        return Err(Error::Validation(
            "validator update signing requires two or three signers".to_owned(),
        ));
    }

    let message = governance_signing_message(&unsigned)?;
    let mut ordered = signers.to_vec();
    ordered.sort_by_key(|(index, _)| *index);
    if ordered.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || ordered.iter().any(|(index, _)| *index >= 3)
    {
        return Err(Error::Validation(
            "governance signer indices must be distinct values 0, 1, or 2".to_owned(),
        ));
    }

    let mut signatures = Vec::with_capacity(ordered.len());
    for (signer_index, signing_key) in ordered {
        let authorization = sign_ed25519_message(signing_key, &message)?;
        signatures.push(GovernanceSignatureV1 {
            signer_index,
            key_id: authorization.key_id,
            signature: authorization.signature,
        });
    }
    let update = ValidatorUpdateV1 {
        unsigned,
        signatures,
    };
    update.validate()?;
    Ok(update)
}

/// Strictly verifies a complete validator update against the three locally
/// trusted governance keys.
///
/// # Errors
///
/// Returns an error for an invalid update structure, key ID, public key, or
/// Ed25519 signature.
pub fn verify_validator_update(
    update: &ValidatorUpdateV1,
    governance_keys: &[Ed25519PublicKey; 3],
) -> Result<()> {
    update.validate()?;
    let message = governance_signing_message(&update.unsigned)?;
    for signature in &update.signatures {
        let public_key = governance_keys[usize::from(signature.signer_index)];
        let authorization = Ed25519AuthorizationV1 {
            key_id: signature.key_id,
            signature: signature.signature,
        };
        verify_ed25519_message(public_key, &message, &authorization)?;
    }
    Ok(())
}
