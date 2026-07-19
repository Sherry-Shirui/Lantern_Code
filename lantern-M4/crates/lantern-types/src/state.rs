use minicbor::{Decoder, Encoder};

use crate::{
    ControlEventV1, Ed25519AuthorizationV1, Ed25519PublicKey, Error, Hash32, NetworkId, Nonce16,
    PROTOCOL_VERSION_V1, PublicationIntentV1, Result, TimestampV1, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{
        decode_error, decode_optional_fixed, decode_optional_u64, encode_array, encode_error,
        encode_optional_bytes, encode_optional_u64, expect_array,
    },
};

/// Maximum exact DER manifest accepted inside one publication transaction.
pub const MAX_EXACT_MANIFEST_BYTES: usize = 512 * 1024;
/// Maximum detached intent-signature size accepted by the state machine.
pub const MAX_PUBLICATION_SIGNATURE_BYTES: usize = 8 * 1024;
/// Maximum number of DER certificates in a publication EE chain.
pub const MAX_EE_CERTIFICATE_CHAIN_ITEMS: usize = 16;
/// Maximum size of any one DER certificate in a publication EE chain.
pub const MAX_EE_CERTIFICATE_BYTES: usize = 64 * 1024;

/// Type of an immutable compact history record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HistoryEventTypeV1 {
    Publish = 1,
    Enable = 2,
    Disable = 3,
    Cancel = 4,
    Rollover = 5,
    Terminal = 6,
}

impl HistoryEventTypeV1 {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Publish),
            2 => Ok(Self::Enable),
            3 => Ok(Self::Disable),
            4 => Ok(Self::Cancel),
            5 => Ok(Self::Rollover),
            6 => Ok(Self::Terminal),
            _ => Err(Error::Validation(format!(
                "unknown history event type {code}"
            ))),
        }
    }
}

/// Lifecycle state of a CA instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaStatusV1 {
    Enabled = 1,
    Disabled = 2,
    Terminal = 3,
}

impl CaStatusV1 {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Enabled),
            2 => Ok(Self::Disabled),
            3 => Ok(Self::Terminal),
            _ => Err(Error::Validation(format!("unknown CA status {code}"))),
        }
    }
}

/// Consensus-critical epoch-duration profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpochProfileV1 {
    Integration30Seconds = 1,
    Paper300Seconds = 2,
}

impl EpochProfileV1 {
    /// Returns the exact epoch duration in seconds.
    #[must_use]
    pub const fn delta_seconds(self) -> u64 {
        match self {
            Self::Integration30Seconds => 30,
            Self::Paper300Seconds => 300,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Integration30Seconds),
            2 => Ok(Self::Paper300Seconds),
            _ => Err(Error::Validation(format!("unknown epoch profile {code}"))),
        }
    }
}

/// Stable deterministic transaction result code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransactionResultCodeV1 {
    Admitted = 1,
    RejectedNetwork = 10,
    RejectedAuthorization = 11,
    RejectedState = 12,
    RejectedIdempotencyConflict = 13,
    RejectedLimits = 14,
    RejectedEpochBacklog = 15,
}

impl TransactionResultCodeV1 {
    /// Returns whether this code denotes an admitted state transition.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }

    fn from_code(code: u16) -> Result<Self> {
        match code {
            1 => Ok(Self::Admitted),
            10 => Ok(Self::RejectedNetwork),
            11 => Ok(Self::RejectedAuthorization),
            12 => Ok(Self::RejectedState),
            13 => Ok(Self::RejectedIdempotencyConflict),
            14 => Ok(Self::RejectedLimits),
            15 => Ok(Self::RejectedEpochBacklog),
            _ => Err(Error::Validation(format!(
                "unknown transaction result code {code}"
            ))),
        }
    }
}

fn encode_manifest_tuple(
    encoder: &mut Encoder<Vec<u8>>,
    number: Option<u64>,
    hash: Option<Hash32>,
    intent: Option<Hash32>,
) -> Result<()> {
    encode_optional_u64(encoder, number)?;
    encode_optional_bytes(encoder, hash.as_ref().map(Hash32::as_bytes))?;
    encode_optional_bytes(encoder, intent.as_ref().map(Hash32::as_bytes))
}

fn validate_manifest_tuple(
    number: Option<u64>,
    hash: Option<Hash32>,
    intent: Option<Hash32>,
    field: &str,
) -> Result<()> {
    if number.is_some() != hash.is_some() || number.is_some() != intent.is_some() {
        return Err(Error::Validation(format!(
            "{field} manifest number/hash/intent must be simultaneously present"
        )));
    }
    if number == Some(0) {
        return Err(Error::Validation(format!(
            "{field} manifest number must be non-zero"
        )));
    }
    Ok(())
}

/// Canonical immutable leaf payload appended to M3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRecordV1 {
    pub protocol_version: u16,
    pub network_id: NetworkId,
    pub ca_id: Hash32,
    pub version: u64,
    pub event_type: HistoryEventTypeV1,
    pub manifest_number: Option<u64>,
    pub manifest_hash: Option<Hash32>,
    pub previous_manifest_hash: Option<Hash32>,
    pub admission_epoch: u64,
    pub flags: u16,
    pub authorization_digest: Hash32,
}

impl WireValue for HistoryRecordV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 11)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        self.ca_id.encode_value(encoder)?;
        encoder.u64(self.version).map_err(encode_error)?;
        encoder.u8(self.event_type.code()).map_err(encode_error)?;
        encode_optional_u64(encoder, self.manifest_number)?;
        encode_optional_bytes(encoder, self.manifest_hash.as_ref().map(Hash32::as_bytes))?;
        encode_optional_bytes(
            encoder,
            self.previous_manifest_hash.as_ref().map(Hash32::as_bytes),
        )?;
        encoder.u64(self.admission_epoch).map_err(encode_error)?;
        encoder.u16(self.flags).map_err(encode_error)?;
        self.authorization_digest.encode_value(encoder)
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 11, "HistoryRecordV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            ca_id: Hash32::decode_value(decoder)?,
            version: decoder.u64().map_err(decode_error)?,
            event_type: HistoryEventTypeV1::from_code(decoder.u8().map_err(decode_error)?)?,
            manifest_number: decode_optional_u64(decoder)?,
            manifest_hash: decode_optional_fixed(decoder, "manifest hash")?.map(Hash32::new),
            previous_manifest_hash: decode_optional_fixed(decoder, "previous manifest hash")?
                .map(Hash32::new),
            admission_epoch: decoder.u64().map_err(decode_error)?,
            flags: decoder.u16().map_err(decode_error)?,
            authorization_digest: Hash32::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(
                "history-record protocol version must be one".into(),
            ));
        }
        self.network_id.validate()?;
        if self.version == 0 || self.flags == 0 {
            return Err(Error::Validation(
                "history-record version and flags must be non-zero".into(),
            ));
        }
        if self.manifest_number.is_some() != self.manifest_hash.is_some() {
            return Err(Error::Validation(
                "history manifest number/hash must be simultaneously present".into(),
            ));
        }
        if self.manifest_number == Some(0) {
            return Err(Error::Validation(
                "history manifest number must be non-zero".into(),
            ));
        }
        if self.previous_manifest_hash.is_some() && self.manifest_hash.is_none() {
            return Err(Error::Validation(
                "previous manifest hash requires a current/target manifest".into(),
            ));
        }
        if self.event_type == HistoryEventTypeV1::Publish && self.manifest_hash.is_none() {
            return Err(Error::Validation(
                "publish history record requires a manifest".into(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(HistoryRecordV1);

/// Canonical value stored under a CA key in the M2 latest map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestValueV1 {
    pub protocol_version: u16,
    pub network_id: NetworkId,
    pub ca_id: Hash32,
    pub record_digest: Hash32,
    pub version: u64,
    pub event_type: HistoryEventTypeV1,
    pub effective_manifest_number: Option<u64>,
    pub effective_manifest_hash: Option<Hash32>,
    pub effective_intent_digest: Option<Hash32>,
    pub admission_epoch: u64,
    pub status: CaStatusV1,
    pub rollover_link: Option<Hash32>,
}

impl WireValue for LatestValueV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 12)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        self.ca_id.encode_value(encoder)?;
        self.record_digest.encode_value(encoder)?;
        encoder.u64(self.version).map_err(encode_error)?;
        encoder.u8(self.event_type.code()).map_err(encode_error)?;
        encode_manifest_tuple(
            encoder,
            self.effective_manifest_number,
            self.effective_manifest_hash,
            self.effective_intent_digest,
        )?;
        encoder.u64(self.admission_epoch).map_err(encode_error)?;
        encoder.u8(self.status.code()).map_err(encode_error)?;
        encode_optional_bytes(encoder, self.rollover_link.as_ref().map(Hash32::as_bytes))
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 12, "LatestValueV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            ca_id: Hash32::decode_value(decoder)?,
            record_digest: Hash32::decode_value(decoder)?,
            version: decoder.u64().map_err(decode_error)?,
            event_type: HistoryEventTypeV1::from_code(decoder.u8().map_err(decode_error)?)?,
            effective_manifest_number: decode_optional_u64(decoder)?,
            effective_manifest_hash: decode_optional_fixed(decoder, "effective manifest hash")?
                .map(Hash32::new),
            effective_intent_digest: decode_optional_fixed(decoder, "effective intent digest")?
                .map(Hash32::new),
            admission_epoch: decoder.u64().map_err(decode_error)?,
            status: CaStatusV1::from_code(decoder.u8().map_err(decode_error)?)?,
            rollover_link: decode_optional_fixed(decoder, "rollover link")?.map(Hash32::new),
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 || self.version == 0 {
            return Err(Error::Validation(
                "latest value requires protocol version one and non-zero version".into(),
            ));
        }
        self.network_id.validate()?;
        validate_manifest_tuple(
            self.effective_manifest_number,
            self.effective_manifest_hash,
            self.effective_intent_digest,
            "effective",
        )?;
        if self.rollover_link.is_some()
            && (self.status != CaStatusV1::Terminal
                || self.event_type != HistoryEventTypeV1::Rollover)
        {
            return Err(Error::Validation(
                "rollover link requires a terminal rollover latest value".into(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(LatestValueV1);

/// Complete deterministic CA state kept by M4 outside the public M2 value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaStateV1 {
    pub protocol_version: u16,
    pub network_id: NetworkId,
    pub ca_id: Hash32,
    pub status: CaStatusV1,
    pub admin_public_key: Ed25519PublicKey,
    pub admin_sequence: u64,
    pub last_version: u64,
    pub latest_record_digest: Hash32,
    pub latest_event_type: HistoryEventTypeV1,
    pub latest_admission_epoch: u64,
    pub effective_manifest_number: Option<u64>,
    pub effective_manifest_hash: Option<Hash32>,
    pub effective_intent_digest: Option<Hash32>,
    pub predecessor_manifest_number: Option<u64>,
    pub predecessor_manifest_hash: Option<Hash32>,
    pub predecessor_intent_digest: Option<Hash32>,
    pub expected_manifest_hash: Option<Hash32>,
    pub rollover_link: Option<Hash32>,
}

impl CaStateV1 {
    /// Builds the public M2 value for this exact CA state.
    #[must_use]
    pub fn latest_value(&self) -> LatestValueV1 {
        LatestValueV1 {
            protocol_version: self.protocol_version,
            network_id: self.network_id.clone(),
            ca_id: self.ca_id,
            record_digest: self.latest_record_digest,
            version: self.last_version,
            event_type: self.latest_event_type,
            effective_manifest_number: self.effective_manifest_number,
            effective_manifest_hash: self.effective_manifest_hash,
            effective_intent_digest: self.effective_intent_digest,
            admission_epoch: self.latest_admission_epoch,
            status: self.status,
            rollover_link: self.rollover_link,
        }
    }
}

impl WireValue for CaStateV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 18)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        self.ca_id.encode_value(encoder)?;
        encoder.u8(self.status.code()).map_err(encode_error)?;
        self.admin_public_key.encode_value(encoder)?;
        encoder.u64(self.admin_sequence).map_err(encode_error)?;
        encoder.u64(self.last_version).map_err(encode_error)?;
        self.latest_record_digest.encode_value(encoder)?;
        encoder
            .u8(self.latest_event_type.code())
            .map_err(encode_error)?;
        encoder
            .u64(self.latest_admission_epoch)
            .map_err(encode_error)?;
        encode_manifest_tuple(
            encoder,
            self.effective_manifest_number,
            self.effective_manifest_hash,
            self.effective_intent_digest,
        )?;
        encode_manifest_tuple(
            encoder,
            self.predecessor_manifest_number,
            self.predecessor_manifest_hash,
            self.predecessor_intent_digest,
        )?;
        encode_optional_bytes(
            encoder,
            self.expected_manifest_hash.as_ref().map(Hash32::as_bytes),
        )?;
        encode_optional_bytes(encoder, self.rollover_link.as_ref().map(Hash32::as_bytes))
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 18, "CaStateV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            ca_id: Hash32::decode_value(decoder)?,
            status: CaStatusV1::from_code(decoder.u8().map_err(decode_error)?)?,
            admin_public_key: Ed25519PublicKey::decode_value(decoder)?,
            admin_sequence: decoder.u64().map_err(decode_error)?,
            last_version: decoder.u64().map_err(decode_error)?,
            latest_record_digest: Hash32::decode_value(decoder)?,
            latest_event_type: HistoryEventTypeV1::from_code(decoder.u8().map_err(decode_error)?)?,
            latest_admission_epoch: decoder.u64().map_err(decode_error)?,
            effective_manifest_number: decode_optional_u64(decoder)?,
            effective_manifest_hash: decode_optional_fixed(decoder, "effective manifest hash")?
                .map(Hash32::new),
            effective_intent_digest: decode_optional_fixed(decoder, "effective intent digest")?
                .map(Hash32::new),
            predecessor_manifest_number: decode_optional_u64(decoder)?,
            predecessor_manifest_hash: decode_optional_fixed(decoder, "predecessor manifest hash")?
                .map(Hash32::new),
            predecessor_intent_digest: decode_optional_fixed(decoder, "predecessor intent digest")?
                .map(Hash32::new),
            expected_manifest_hash: decode_optional_fixed(decoder, "expected manifest hash")?
                .map(Hash32::new),
            rollover_link: decode_optional_fixed(decoder, "rollover link")?.map(Hash32::new),
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1
            || self.admin_sequence == 0
            || self.last_version == 0
        {
            return Err(Error::Validation(
                "CA state requires version one and positive sequences".into(),
            ));
        }
        self.network_id.validate()?;
        validate_manifest_tuple(
            self.effective_manifest_number,
            self.effective_manifest_hash,
            self.effective_intent_digest,
            "effective",
        )?;
        validate_manifest_tuple(
            self.predecessor_manifest_number,
            self.predecessor_manifest_hash,
            self.predecessor_intent_digest,
            "predecessor",
        )?;
        if self.expected_manifest_hash.is_some() && self.status != CaStatusV1::Enabled {
            return Err(Error::Validation(
                "only an enabled CA may carry an expected manifest hash".into(),
            ));
        }
        if self.rollover_link.is_some()
            && (self.status != CaStatusV1::Terminal
                || self.latest_event_type != HistoryEventTypeV1::Rollover)
        {
            return Err(Error::Validation(
                "rollover link requires a terminal rollover state".into(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(CaStateV1);

/// Exact publication evidence supplied to the deterministic authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationTransactionV1 {
    pub intent: PublicationIntentV1,
    pub exact_manifest_der: Vec<u8>,
    pub intent_signature: Vec<u8>,
    pub ee_certificate_chain: Vec<Vec<u8>>,
}

impl WireValue for PublicationTransactionV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 4)?;
        self.intent.encode_value(encoder)?;
        encoder
            .bytes(&self.exact_manifest_der)
            .map_err(encode_error)?;
        encoder
            .bytes(&self.intent_signature)
            .map_err(encode_error)?;
        encode_array(encoder, self.ee_certificate_chain.len() as u64)?;
        for certificate in &self.ee_certificate_chain {
            encoder.bytes(certificate).map_err(encode_error)?;
        }
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 4, "PublicationTransactionV1")?;
        let intent = PublicationIntentV1::decode_value(decoder)?;
        let exact_manifest_der = decoder.bytes().map_err(decode_error)?.to_vec();
        let intent_signature = decoder.bytes().map_err(decode_error)?.to_vec();
        let chain_len = decoder.array().map_err(decode_error)?.ok_or_else(|| {
            Error::Validation("EE certificate chain must be definite-length".into())
        })?;
        let chain_len = usize::try_from(chain_len)
            .map_err(|_| Error::Validation("EE certificate chain length overflows".into()))?;
        if chain_len > MAX_EE_CERTIFICATE_CHAIN_ITEMS {
            return Err(Error::Validation(
                "EE certificate chain has too many items".into(),
            ));
        }
        let mut ee_certificate_chain = Vec::with_capacity(chain_len);
        for _ in 0..chain_len {
            ee_certificate_chain.push(decoder.bytes().map_err(decode_error)?.to_vec());
        }
        Ok(Self {
            intent,
            exact_manifest_der,
            intent_signature,
            ee_certificate_chain,
        })
    }

    fn validate_value(&self) -> Result<()> {
        self.intent.validate()?;
        if self.exact_manifest_der.is_empty()
            || self.exact_manifest_der.len() > MAX_EXACT_MANIFEST_BYTES
        {
            return Err(Error::Validation(
                "exact manifest length is outside limits".into(),
            ));
        }
        if self.intent_signature.is_empty()
            || self.intent_signature.len() > MAX_PUBLICATION_SIGNATURE_BYTES
        {
            return Err(Error::Validation(
                "publication signature length is outside limits".into(),
            ));
        }
        if self.ee_certificate_chain.is_empty()
            || self.ee_certificate_chain.len() > MAX_EE_CERTIFICATE_CHAIN_ITEMS
            || self.ee_certificate_chain.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_EE_CERTIFICATE_BYTES
            })
        {
            return Err(Error::Validation(
                "EE certificate chain is outside limits".into(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(PublicationTransactionV1);

/// Administrative event and its detached authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlTransactionV1 {
    pub event: ControlEventV1,
    pub authorization: Ed25519AuthorizationV1,
}

impl WireValue for ControlTransactionV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 2)?;
        self.event.encode_value(encoder)?;
        self.authorization.encode_value(encoder)
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 2, "ControlTransactionV1")?;
        Ok(Self {
            event: ControlEventV1::decode_value(decoder)?,
            authorization: Ed25519AuthorizationV1::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        self.event.validate()?;
        self.authorization.validate()
    }
}

impl_wire_object!(ControlTransactionV1);

/// The only two transaction classes accepted by the M4 state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTransactionV1 {
    Publication(PublicationTransactionV1),
    Control(ControlTransactionV1),
}

impl StateTransactionV1 {
    /// Returns the CA instance used for ordering/idempotency.
    #[must_use]
    pub const fn ca_id(&self) -> Hash32 {
        match self {
            Self::Publication(transaction) => transaction.intent.ca_id,
            Self::Control(transaction) => transaction.event.ca_id,
        }
    }

    /// Returns the caller-generated idempotency nonce.
    #[must_use]
    pub const fn nonce(&self) -> Nonce16 {
        match self {
            Self::Publication(transaction) => transaction.intent.nonce,
            Self::Control(transaction) => transaction.event.nonce,
        }
    }

    /// Returns the transaction network identifier.
    #[must_use]
    pub fn network_id(&self) -> &NetworkId {
        match self {
            Self::Publication(transaction) => &transaction.intent.network_id,
            Self::Control(transaction) => &transaction.event.network_id,
        }
    }
}

impl WireValue for StateTransactionV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 2)?;
        match self {
            Self::Publication(transaction) => {
                encoder.u8(1).map_err(encode_error)?;
                transaction.encode_value(encoder)
            }
            Self::Control(transaction) => {
                encoder.u8(2).map_err(encode_error)?;
                transaction.encode_value(encoder)
            }
        }
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 2, "StateTransactionV1")?;
        match decoder.u8().map_err(decode_error)? {
            1 => PublicationTransactionV1::decode_value(decoder).map(Self::Publication),
            2 => ControlTransactionV1::decode_value(decoder).map(Self::Control),
            code => Err(Error::Validation(format!(
                "unknown state transaction type {code}"
            ))),
        }
    }

    fn validate_value(&self) -> Result<()> {
        match self {
            Self::Publication(transaction) => transaction.validate(),
            Self::Control(transaction) => transaction.validate(),
        }
    }
}

impl_wire_object!(StateTransactionV1);

/// Persisted deterministic result used for idempotent replay and `AppHash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionResultV1 {
    pub protocol_version: u16,
    pub transaction_id: Hash32,
    pub app_height: u64,
    pub transaction_index: u32,
    pub code: TransactionResultCodeV1,
    pub ca_id: Hash32,
    pub history_index: Option<u64>,
    pub ca_version: Option<u64>,
    pub admission_epoch: Option<u64>,
}

impl WireValue for TransactionResultV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 9)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.transaction_id.encode_value(encoder)?;
        encoder.u64(self.app_height).map_err(encode_error)?;
        encoder.u32(self.transaction_index).map_err(encode_error)?;
        encoder.u16(self.code as u16).map_err(encode_error)?;
        self.ca_id.encode_value(encoder)?;
        encode_optional_u64(encoder, self.history_index)?;
        encode_optional_u64(encoder, self.ca_version)?;
        encode_optional_u64(encoder, self.admission_epoch)
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 9, "TransactionResultV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            transaction_id: Hash32::decode_value(decoder)?,
            app_height: decoder.u64().map_err(decode_error)?,
            transaction_index: decoder.u32().map_err(decode_error)?,
            code: TransactionResultCodeV1::from_code(decoder.u16().map_err(decode_error)?)?,
            ca_id: Hash32::decode_value(decoder)?,
            history_index: decode_optional_u64(decoder)?,
            ca_version: decode_optional_u64(decoder)?,
            admission_epoch: decode_optional_u64(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 || self.app_height == 0 {
            return Err(Error::Validation(
                "transaction result requires protocol version one and positive height".into(),
            ));
        }
        let all_present = self.history_index.is_some()
            && self.ca_version.is_some()
            && self.admission_epoch.is_some();
        let all_absent = self.history_index.is_none()
            && self.ca_version.is_none()
            && self.admission_epoch.is_none();
        if (self.code.is_admitted() && !all_present)
            || (!self.code.is_admitted() && !all_absent)
            || self.ca_version == Some(0)
        {
            return Err(Error::Validation(
                "admitted result metadata must be all present; rejected metadata all absent".into(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(TransactionResultV1);

/// Immutable consensus-critical M4 configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateConfigV1 {
    pub protocol_version: u16,
    pub network_id: NetworkId,
    pub genesis_time: TimestampV1,
    pub epoch_profile: EpochProfileV1,
    pub validator_config_hash: Hash32,
    pub governance_config_hash: Hash32,
    pub key_epoch: u64,
    pub max_epoch_catchup: u16,
}

impl WireValue for StateConfigV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 8)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        self.genesis_time.encode_value(encoder)?;
        encoder.u8(self.epoch_profile as u8).map_err(encode_error)?;
        self.validator_config_hash.encode_value(encoder)?;
        self.governance_config_hash.encode_value(encoder)?;
        encoder.u64(self.key_epoch).map_err(encode_error)?;
        encoder.u16(self.max_epoch_catchup).map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 8, "StateConfigV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            genesis_time: TimestampV1::decode_value(decoder)?,
            epoch_profile: EpochProfileV1::from_code(decoder.u8().map_err(decode_error)?)?,
            validator_config_hash: Hash32::decode_value(decoder)?,
            governance_config_hash: Hash32::decode_value(decoder)?,
            key_epoch: decoder.u64().map_err(decode_error)?,
            max_epoch_catchup: decoder.u16().map_err(decode_error)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 || self.max_epoch_catchup == 0 {
            return Err(Error::Validation(
                "state config requires version one and non-zero catch-up bound".into(),
            ));
        }
        self.network_id.validate()?;
        self.genesis_time.validate()?;
        if self.genesis_time.seconds < 0 {
            return Err(Error::Validation(
                "genesis time must not precede Unix epoch".into(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(StateConfigV1);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PublicationEventTypeV1, PublicationSignatureAlgorithmV1};

    fn hash(byte: u8) -> Hash32 {
        Hash32::new([byte; 32])
    }

    #[test]
    fn publication_transaction_round_trips_canonically() {
        let transaction = PublicationTransactionV1 {
            intent: PublicationIntentV1 {
                protocol_version: 1,
                network_id: NetworkId::new("m4-test").expect("valid network"),
                event_type: PublicationEventTypeV1::Publish,
                ca_id: hash(1),
                manifest_number: 7,
                manifest_hash: hash(2),
                previous_manifest_hash: None,
                nonce: Nonce16::new([3; 16]),
                signature_algorithm: PublicationSignatureAlgorithmV1::Ed25519,
            },
            exact_manifest_der: vec![0x30, 0x00],
            intent_signature: vec![4; 64],
            ee_certificate_chain: vec![vec![0x30, 0x00]],
        };
        let bytes = transaction.to_canonical_cbor().expect("encode");
        assert_eq!(
            PublicationTransactionV1::from_canonical_cbor(&bytes).expect("decode"),
            transaction
        );
    }

    #[test]
    fn latest_manifest_tuple_is_all_or_nothing() {
        let value = LatestValueV1 {
            protocol_version: 1,
            network_id: NetworkId::new("m4-test").expect("valid network"),
            ca_id: hash(1),
            record_digest: hash(2),
            version: 1,
            event_type: HistoryEventTypeV1::Enable,
            effective_manifest_number: Some(1),
            effective_manifest_hash: None,
            effective_intent_digest: None,
            admission_epoch: 0,
            status: CaStatusV1::Enabled,
            rollover_link: None,
        };
        assert!(value.validate().is_err());
    }
}
