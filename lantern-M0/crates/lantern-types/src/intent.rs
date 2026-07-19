use minicbor::{Decoder, Encoder};

use crate::{
    Error, Hash32, NetworkId, Nonce16, PROTOCOL_VERSION_V1, Result, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{
        decode_error, decode_optional_fixed, encode_array, encode_error, encode_optional_bytes,
        expect_array,
    },
};

/// Publication intent event type. M0 intentionally admits no implicit or
/// untyped publication operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicationEventTypeV1 {
    /// Admit an exact, already-signed manifest before repository publication.
    Publish = 1,
}

impl PublicationEventTypeV1 {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Publish),
            _ => Err(Error::Validation(format!(
                "unknown publication event type {code}"
            ))),
        }
    }
}

/// Signature algorithm declared by a publication intent.
///
/// M0 only frames the canonical signing message. The RPKI adapter must verify
/// that this algorithm agrees with the manifest EE certificate and then use
/// the corresponding certificate implementation; it may not substitute an
/// administrative or publisher key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicationSignatureAlgorithmV1 {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1V15Sha256 = 1,
    /// ECDSA P-256 with SHA-256 and the canonical signature form required by
    /// the RPKI adapter.
    EcdsaP256Sha256 = 2,
    /// Pure Ed25519, included for algorithm agility and test profiles.
    Ed25519 = 3,
}

impl PublicationSignatureAlgorithmV1 {
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::RsaPkcs1V15Sha256),
            2 => Ok(Self::EcdsaP256Sha256),
            3 => Ok(Self::Ed25519),
            _ => Err(Error::Validation(format!(
                "unknown publication signature algorithm {code}"
            ))),
        }
    }
}

/// The normal CA-signed pre-publication intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationIntentV1 {
    /// Wire protocol version; must be one.
    pub protocol_version: u16,
    /// Lantern/Comet chain identifier.
    pub network_id: NetworkId,
    /// Typed publication operation.
    pub event_type: PublicationEventTypeV1,
    /// Stable CA identifier derived from TA digest and resource CA SPKI.
    pub ca_id: Hash32,
    /// Manifest number carried by the exact DER manifest.
    pub manifest_number: u64,
    /// Plain SHA-256 of the exact DER bytes later published.
    pub manifest_hash: Hash32,
    /// Previous admitted manifest hash, or `None` for the first publication.
    pub previous_manifest_hash: Option<Hash32>,
    /// Caller-generated idempotency/replay nonce.
    pub nonce: Nonce16,
    /// Algorithm expected from the one-time manifest EE key.
    pub signature_algorithm: PublicationSignatureAlgorithmV1,
}

impl WireValue for PublicationIntentV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 9)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        encoder.u8(self.event_type as u8).map_err(encode_error)?;
        encoder.bytes(self.ca_id.as_bytes()).map_err(encode_error)?;
        encoder.u64(self.manifest_number).map_err(encode_error)?;
        encoder
            .bytes(self.manifest_hash.as_bytes())
            .map_err(encode_error)?;
        encode_optional_bytes(
            encoder,
            self.previous_manifest_hash.as_ref().map(Hash32::as_bytes),
        )?;
        encoder.bytes(self.nonce.as_bytes()).map_err(encode_error)?;
        encoder
            .u8(self.signature_algorithm as u8)
            .map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 9, "PublicationIntentV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            event_type: PublicationEventTypeV1::from_code(decoder.u8().map_err(decode_error)?)?,
            ca_id: Hash32::decode_value(decoder)?,
            manifest_number: decoder.u64().map_err(decode_error)?,
            manifest_hash: Hash32::decode_value(decoder)?,
            previous_manifest_hash: decode_optional_fixed(decoder, "previous manifest hash")?
                .map(Hash32::new),
            nonce: Nonce16::decode_value(decoder)?,
            signature_algorithm: PublicationSignatureAlgorithmV1::from_code(
                decoder.u8().map_err(decode_error)?,
            )?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(format!(
                "publication intent protocol version is {}, expected {PROTOCOL_VERSION_V1}",
                self.protocol_version
            )));
        }
        self.network_id.validate()?;
        if self.manifest_number == 0 {
            return Err(Error::Validation(
                "manifest number must be non-zero".to_owned(),
            ));
        }
        if self.previous_manifest_hash == Some(self.manifest_hash) {
            return Err(Error::Validation(
                "manifest hash must differ from previous manifest hash".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(PublicationIntentV1);
