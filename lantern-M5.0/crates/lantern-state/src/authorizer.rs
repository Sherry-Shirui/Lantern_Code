use std::fmt;

use lantern_types::{Hash32, PublicationIntentV1, PublicationSignatureAlgorithmV1, TimestampV1};

/// Exact byte inputs supplied to the publication authorization boundary.
///
/// Implementations must validate the certificate chain and exact manifest
/// before accepting the detached intent signature. `intent_cbor` is included
/// explicitly so an adapter cannot silently sign a reconstructed structure.
#[derive(Debug, Clone, Copy)]
pub struct PublicationAuthorizationInput<'a> {
    pub intent: &'a PublicationIntentV1,
    pub intent_cbor: &'a [u8],
    pub exact_manifest_der: &'a [u8],
    pub intent_signature: &'a [u8],
    pub ee_certificate_chain: &'a [Vec<u8>],
    pub consensus_time: TimestampV1,
}

/// Independently extracted values returned after complete publication
/// authorization. M4 compares every field with the signed intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationAuthorizationV1 {
    pub derived_ca_id: Hash32,
    pub manifest_number: u64,
    pub manifest_hash: Hash32,
    pub signature_algorithm: PublicationSignatureAlgorithmV1,
}

/// Opaque adapter failure. The state machine deliberately maps all adapter
/// detail to one stable authorization rejection code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationAuthorizationError {
    detail: String,
}

impl PublicationAuthorizationError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for PublicationAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for PublicationAuthorizationError {}

/// Deterministic publication-verification boundary.
///
/// M7 supplies the production RPKI implementation. M4 property/integration
/// tests use an explicitly marked strict fixture implementation.
pub trait PublicationAuthorizer {
    /// Authorizes one exact publication input and returns independently
    /// extracted manifest identity fields.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure after any chain, manifest, algorithm, time,
    /// or signature validation failure. Implementations must fail closed.
    fn authorize(
        &self,
        input: PublicationAuthorizationInput<'_>,
    ) -> std::result::Result<PublicationAuthorizationV1, PublicationAuthorizationError>;
}
