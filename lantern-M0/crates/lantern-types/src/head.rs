use minicbor::{Decoder, Encoder};

use crate::{
    Error, Hash32, NetworkId, PROTOCOL_VERSION_V1, Result, TimestampV1, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{
        decode_error, decode_optional_fixed, decode_optional_u64, encode_array, encode_error,
        encode_optional_bytes, encode_optional_u64, expect_array,
    },
};

/// The head body authenticated by a `CometBFT` AppHash/Commit chain.
///
/// `HeadID` is the domain-separated hash of this object alone. A QC is a
/// certificate over the binding and is deliberately not part of the ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadBodyV1 {
    /// Wire protocol version; must be one.
    pub protocol_version: u16,
    /// Lantern/Comet chain identifier.
    pub network_id: NetworkId,
    /// Public epoch number.
    pub epoch: u64,
    /// Inclusive epoch start.
    pub epoch_start: TimestampV1,
    /// Exclusive epoch end.
    pub epoch_end: TimestampV1,
    /// Consensus time at which the epoch was closed.
    pub issued_at: TimestampV1,
    /// Authenticated root of the latest-state map.
    pub latest_root: Hash32,
    /// Authenticated root of the append-only history.
    pub history_root: Hash32,
    /// Previous `HeadID`; absent only for epoch zero.
    pub previous_head_id: Option<Hash32>,
    /// Hash of the ordered transactions admitted in this epoch.
    pub bundle_hash: Hash32,
    /// Total history leaf count.
    pub history_length: u64,
    /// Number of latest-map entries.
    pub latest_entry_count: u64,
    /// Governance-authorized validator configuration epoch.
    pub key_epoch: u64,
}

impl WireValue for HeadBodyV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 13)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        encoder.u64(self.epoch).map_err(encode_error)?;
        self.epoch_start.encode_value(encoder)?;
        self.epoch_end.encode_value(encoder)?;
        self.issued_at.encode_value(encoder)?;
        encoder
            .bytes(self.latest_root.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.history_root.as_bytes())
            .map_err(encode_error)?;
        encode_optional_bytes(
            encoder,
            self.previous_head_id.as_ref().map(Hash32::as_bytes),
        )?;
        encoder
            .bytes(self.bundle_hash.as_bytes())
            .map_err(encode_error)?;
        encoder.u64(self.history_length).map_err(encode_error)?;
        encoder.u64(self.latest_entry_count).map_err(encode_error)?;
        encoder.u64(self.key_epoch).map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 13, "HeadBodyV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            epoch: decoder.u64().map_err(decode_error)?,
            epoch_start: TimestampV1::decode_value(decoder)?,
            epoch_end: TimestampV1::decode_value(decoder)?,
            issued_at: TimestampV1::decode_value(decoder)?,
            latest_root: Hash32::decode_value(decoder)?,
            history_root: Hash32::decode_value(decoder)?,
            previous_head_id: decode_optional_fixed(decoder, "previous head ID")?.map(Hash32::new),
            bundle_hash: Hash32::decode_value(decoder)?,
            history_length: decoder.u64().map_err(decode_error)?,
            latest_entry_count: decoder.u64().map_err(decode_error)?,
            key_epoch: decoder.u64().map_err(decode_error)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(format!(
                "head protocol version is {}, expected {PROTOCOL_VERSION_V1}",
                self.protocol_version
            )));
        }
        self.network_id.validate()?;
        self.epoch_start.validate()?;
        self.epoch_end.validate()?;
        self.issued_at.validate()?;
        if self.epoch_start >= self.epoch_end {
            return Err(Error::Validation(
                "epoch start must be earlier than epoch end".to_owned(),
            ));
        }
        if self.issued_at < self.epoch_end {
            return Err(Error::Validation(
                "issuedAt must not be earlier than epoch end".to_owned(),
            ));
        }
        if (self.epoch == 0) != self.previous_head_id.is_none() {
            return Err(Error::Validation(
                "only epoch zero may omit previous HeadID".to_owned(),
            ));
        }
        if self.latest_entry_count > self.history_length {
            return Err(Error::Validation(
                "latest entry count exceeds history length".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(HeadBodyV1);

/// Application-state commitment returned after executing a block. A header at
/// the next height carries its hash and thereby binds a closed `HeadBodyV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppStateCommitmentV1 {
    /// Wire protocol version; must be one.
    pub protocol_version: u16,
    /// Lantern/Comet chain identifier.
    pub network_id: NetworkId,
    /// Height whose execution produced this state.
    pub app_height: u64,
    /// Current latest-state root, including pending current-epoch updates.
    pub pending_latest_root: Hash32,
    /// Current history root, including pending current-epoch updates.
    pub pending_history_root: Hash32,
    /// Current total history length.
    pub history_length: u64,
    /// Current latest-map entry count.
    pub latest_entry_count: u64,
    /// Most recently closed epoch, if any.
    pub last_closed_epoch: Option<u64>,
    /// `HeadID` for `last_closed_epoch`, if any.
    pub closed_head_id: Option<Hash32>,
    /// Active/next validator configuration state commitment.
    pub validator_config_hash: Hash32,
    /// CA administrative-key registry commitment.
    pub ca_admin_registry_hash: Hash32,
    /// Governance configuration commitment.
    pub governance_config_hash: Hash32,
    /// Deterministic accumulator over transaction results.
    pub transaction_results_hash: Hash32,
    /// Hash of protocol schemas and consensus-critical configuration.
    pub schema_config_hash: Hash32,
}

impl WireValue for AppStateCommitmentV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 14)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        encoder.u64(self.app_height).map_err(encode_error)?;
        encoder
            .bytes(self.pending_latest_root.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.pending_history_root.as_bytes())
            .map_err(encode_error)?;
        encoder.u64(self.history_length).map_err(encode_error)?;
        encoder.u64(self.latest_entry_count).map_err(encode_error)?;
        encode_optional_u64(encoder, self.last_closed_epoch)?;
        encode_optional_bytes(encoder, self.closed_head_id.as_ref().map(Hash32::as_bytes))?;
        encoder
            .bytes(self.validator_config_hash.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.ca_admin_registry_hash.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.governance_config_hash.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.transaction_results_hash.as_bytes())
            .map_err(encode_error)?;
        encoder
            .bytes(self.schema_config_hash.as_bytes())
            .map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 14, "AppStateCommitmentV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            app_height: decoder.u64().map_err(decode_error)?,
            pending_latest_root: Hash32::decode_value(decoder)?,
            pending_history_root: Hash32::decode_value(decoder)?,
            history_length: decoder.u64().map_err(decode_error)?,
            latest_entry_count: decoder.u64().map_err(decode_error)?,
            last_closed_epoch: decode_optional_u64(decoder)?,
            closed_head_id: decode_optional_fixed(decoder, "closed head ID")?.map(Hash32::new),
            validator_config_hash: Hash32::decode_value(decoder)?,
            ca_admin_registry_hash: Hash32::decode_value(decoder)?,
            governance_config_hash: Hash32::decode_value(decoder)?,
            transaction_results_hash: Hash32::decode_value(decoder)?,
            schema_config_hash: Hash32::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(format!(
                "app-state protocol version is {}, expected {PROTOCOL_VERSION_V1}",
                self.protocol_version
            )));
        }
        self.network_id.validate()?;
        if self.app_height == 0 {
            return Err(Error::Validation(
                "app-state commitment height must be non-zero".to_owned(),
            ));
        }
        if self.latest_entry_count > self.history_length {
            return Err(Error::Validation(
                "latest entry count exceeds history length".to_owned(),
            ));
        }
        if self.last_closed_epoch.is_some() != self.closed_head_id.is_some() {
            return Err(Error::Validation(
                "closed epoch and closed HeadID must either both exist or both be absent"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(AppStateCommitmentV1);
