use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};

use crate::{
    ControlEventV1, DomainV1, Ed25519PublicKey, Ed25519Signature, Error, Hash32,
    PublicationIntentV1, Result, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{encode_array, encode_error, expect_array},
    domain::domain_separated_message,
    ed25519_key_id,
};

/// A strict Ed25519 authorization carrying an independently derived key ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519AuthorizationV1 {
    /// Domain-separated SHA-256 identifier of the verifying key.
    pub key_id: Hash32,
    /// Raw 64-byte Ed25519 signature.
    pub signature: Ed25519Signature,
}

impl WireValue for Ed25519AuthorizationV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 2)?;
        encoder
            .bytes(self.key_id.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.signature.as_bytes())
            .map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 2, "Ed25519AuthorizationV1")?;
        Ok(Self {
            key_id: Hash32::decode_value(decoder)?,
            signature: Ed25519Signature::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        Ok(())
    }
}

impl_wire_object!(Ed25519AuthorizationV1);

/// Returns the exact domain-separated message that a manifest's one-time EE
/// key must sign. Algorithm-specific signing and EE-certificate validation are
/// intentionally delegated to the RPKI adapter.
///
/// # Errors
///
/// Returns an error if the intent is invalid, cannot be encoded, or cannot be
/// length-framed.
pub fn publication_signing_message(intent: &PublicationIntentV1) -> Result<Vec<u8>> {
    domain_separated_message(DomainV1::Intent, &intent.to_canonical_cbor()?)
}

/// Returns the exact message signed by a CA administrative Ed25519 key.
///
/// # Errors
///
/// Returns an error if the event is invalid, cannot be encoded, or cannot be
/// length-framed.
pub fn control_signing_message(event: &ControlEventV1) -> Result<Vec<u8>> {
    domain_separated_message(DomainV1::Control, &event.to_canonical_cbor()?)
}

pub(crate) fn sign_ed25519_message(
    signing_key: &SigningKey,
    message: &[u8],
) -> Result<Ed25519AuthorizationV1> {
    let public_key = Ed25519PublicKey::new(signing_key.verifying_key().to_bytes());
    let signature = signing_key.sign(message);
    Ok(Ed25519AuthorizationV1 {
        key_id: ed25519_key_id(public_key)?,
        signature: Ed25519Signature::new(signature.to_bytes()),
    })
}

pub(crate) fn verify_ed25519_message(
    public_key: Ed25519PublicKey,
    message: &[u8],
    authorization: &Ed25519AuthorizationV1,
) -> Result<()> {
    if authorization.key_id != ed25519_key_id(public_key)? {
        return Err(Error::InvalidSignature);
    }
    let verifying_key =
        VerifyingKey::from_bytes(public_key.as_bytes()).map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_bytes(authorization.signature.as_bytes());
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Signs a canonical control event with a CA administrative key.
///
/// # Errors
///
/// Returns an error if the event is invalid or message/key-ID framing fails.
pub fn sign_control_event(
    event: &ControlEventV1,
    signing_key: &SigningKey,
) -> Result<Ed25519AuthorizationV1> {
    sign_ed25519_message(signing_key, &control_signing_message(event)?)
}

/// Strictly verifies a control event authorization and key identifier.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] for a wrong key ID, malformed key, or
/// invalid strict Ed25519 signature, and propagates event/framing errors.
pub fn verify_control_event(
    event: &ControlEventV1,
    public_key: Ed25519PublicKey,
    authorization: &Ed25519AuthorizationV1,
) -> Result<()> {
    verify_ed25519_message(public_key, &control_signing_message(event)?, authorization)
}
