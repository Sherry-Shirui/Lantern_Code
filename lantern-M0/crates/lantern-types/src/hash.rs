use sha2::{Digest, Sha256};

use crate::{
    AppStateCommitmentV1, ControlEventV1, DomainV1, Ed25519PublicKey, Hash32, HeadBodyV1,
    PublicationIntentV1, Result, UnsignedValidatorUpdateV1, ValidatorConfigV1, WireObject,
    domain::{domain_separated_message, framed_parts},
};

/// Computes plain SHA-256. This is used for exact DER manifest bytes and SPKI
/// digests; protocol objects use a domain-separated helper instead.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Hash32 {
    let digest = Sha256::digest(bytes);
    Hash32::new(digest.into())
}

/// Hashes a payload with the exact Lantern v1 domain framing.
///
/// # Errors
///
/// Returns an error if domain framing overflows.
pub fn hash_with_domain(domain: DomainV1, payload: &[u8]) -> Result<Hash32> {
    domain_separated_message(domain, payload).map(|message| sha256(&message))
}

/// Hashes the exact DER bytes selected by Krill or Routinator.
#[must_use]
pub fn manifest_hash(exact_manifest_der: &[u8]) -> Hash32 {
    sha256(exact_manifest_der)
}

/// Hashes the canonical DER `SubjectPublicKeyInfo` of a trust anchor.
#[must_use]
pub fn ta_key_digest(trust_anchor_spki_der: &[u8]) -> Hash32 {
    sha256(trust_anchor_spki_der)
}

/// Derives `CA_ID` from a trust-anchor key digest and resource CA SPKI.
///
/// # Errors
///
/// Returns an error if length framing overflows the wire limits.
pub fn ca_id(ta_digest: Hash32, resource_ca_spki_der: &[u8]) -> Result<Hash32> {
    let payload = framed_parts(&[ta_digest.as_bytes(), resource_ca_spki_der])?;
    hash_with_domain(DomainV1::CaId, &payload)
}

/// Computes the stable publication intent identifier.
///
/// # Errors
///
/// Returns an error if the intent is invalid or cannot be encoded.
pub fn intent_id(intent: &PublicationIntentV1) -> Result<Hash32> {
    hash_with_domain(DomainV1::Intent, &intent.to_canonical_cbor()?)
}

/// Computes the stable control event identifier.
///
/// # Errors
///
/// Returns an error if the event is invalid or cannot be encoded.
pub fn control_event_id(event: &ControlEventV1) -> Result<Hash32> {
    hash_with_domain(DomainV1::Control, &event.to_canonical_cbor()?)
}

/// Computes `HeadID = H(domain || canonical body)`. The QC is deliberately
/// excluded from this identifier.
///
/// # Errors
///
/// Returns an error if the body is invalid or cannot be encoded.
pub fn head_id(body: &HeadBodyV1) -> Result<Hash32> {
    hash_with_domain(DomainV1::HeadBody, &body.to_canonical_cbor()?)
}

/// Computes the application hash that a subsequent `CometBFT` header carries.
///
/// # Errors
///
/// Returns an error if the commitment is invalid or cannot be encoded.
pub fn app_hash(commitment: &AppStateCommitmentV1) -> Result<Hash32> {
    hash_with_domain(DomainV1::AppState, &commitment.to_canonical_cbor()?)
}

/// Computes a validator configuration identifier anchored by governance.
///
/// # Errors
///
/// Returns an error if the configuration is invalid or cannot be encoded.
pub fn validator_config_hash(config: &ValidatorConfigV1) -> Result<Hash32> {
    hash_with_domain(DomainV1::ValidatorConfig, &config.to_canonical_cbor()?)
}

/// Computes the governance-domain identifier of an unsigned validator update.
///
/// # Errors
///
/// Returns an error if the update is invalid or cannot be encoded.
pub fn validator_update_id(update: &UnsignedValidatorUpdateV1) -> Result<Hash32> {
    hash_with_domain(DomainV1::Governance, &update.to_canonical_cbor()?)
}

/// Computes the key identifier placed beside an Ed25519 authorization.
///
/// # Errors
///
/// Returns an error if domain framing overflows the wire limits.
pub fn ed25519_key_id(public_key: Ed25519PublicKey) -> Result<Hash32> {
    hash_with_domain(DomainV1::Ed25519KeyId, public_key.as_bytes())
}
