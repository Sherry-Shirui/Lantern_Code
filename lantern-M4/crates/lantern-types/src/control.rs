use minicbor::{Decoder, Encoder};

use crate::{
    Ed25519PublicKey, Error, Hash32, NetworkId, Nonce16, PROTOCOL_VERSION_V1, Result, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{
        decode_error, decode_optional_fixed, encode_array, encode_error, encode_optional_bytes,
        expect_array,
    },
};

/// Typed administrative transition. Every variant has a distinct wire code
/// and fixed field count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlActionV1 {
    /// Enables a CA before its first repository publication and binds the first
    /// manifest expected from the adjacent EE-signed intent.
    Enable {
        initial_manifest_hash: Hash32,
        initial_admin_key: Ed25519PublicKey,
    },
    /// Marks a CA as legacy/disabled without deleting its history.
    Disable { reason_code: u16 },
    /// Cancels the current latest successor and restores its authenticated
    /// predecessor as the effective manifest without deleting either record.
    Cancel {
        target_version: u64,
        target_manifest_hash: Hash32,
        restore_manifest_hash: Hash32,
        reason_code: u16,
    },
    /// Terminalizes the old CA instance and links a newly authorized instance.
    Rollover {
        successor_ca_id: Hash32,
        successor_admin_key: Ed25519PublicKey,
    },
    /// Permanently terminalizes this CA instance.
    Terminal { reason_code: u16 },
}

impl WireValue for ControlActionV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        match self {
            Self::Enable {
                initial_manifest_hash,
                initial_admin_key,
            } => {
                encode_array(encoder, 3)?;
                encoder.u8(1).map_err(encode_error)?;
                encoder
                    .bytes(initial_manifest_hash.as_bytes())
                    .map_err(encode_error)?;
                encoder
                    .bytes(initial_admin_key.as_bytes())
                    .map_err(encode_error)?;
            }
            Self::Disable { reason_code } => {
                encode_array(encoder, 2)?;
                encoder.u8(2).map_err(encode_error)?;
                encoder.u16(*reason_code).map_err(encode_error)?;
            }
            Self::Cancel {
                target_version,
                target_manifest_hash,
                restore_manifest_hash,
                reason_code,
            } => {
                encode_array(encoder, 5)?;
                encoder.u8(3).map_err(encode_error)?;
                encoder.u64(*target_version).map_err(encode_error)?;
                encoder
                    .bytes(target_manifest_hash.as_bytes())
                    .map_err(encode_error)?;
                encoder
                    .bytes(restore_manifest_hash.as_bytes())
                    .map_err(encode_error)?;
                encoder.u16(*reason_code).map_err(encode_error)?;
            }
            Self::Rollover {
                successor_ca_id,
                successor_admin_key,
            } => {
                encode_array(encoder, 3)?;
                encoder.u8(4).map_err(encode_error)?;
                encoder
                    .bytes(successor_ca_id.as_bytes())
                    .map_err(encode_error)?;
                encoder
                    .bytes(successor_admin_key.as_bytes())
                    .map_err(encode_error)?;
            }
            Self::Terminal { reason_code } => {
                encode_array(encoder, 2)?;
                encoder.u8(5).map_err(encode_error)?;
                encoder.u16(*reason_code).map_err(encode_error)?;
            }
        }
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        let length = decoder.array().map_err(decode_error)?.ok_or_else(|| {
            Error::Validation("control action must be definite-length".to_owned())
        })?;
        let code = decoder.u8().map_err(decode_error)?;
        match (code, length) {
            (1, 3) => Ok(Self::Enable {
                initial_manifest_hash: Hash32::decode_value(decoder)?,
                initial_admin_key: Ed25519PublicKey::decode_value(decoder)?,
            }),
            (2, 2) => Ok(Self::Disable {
                reason_code: decoder.u16().map_err(decode_error)?,
            }),
            (3, 5) => Ok(Self::Cancel {
                target_version: decoder.u64().map_err(decode_error)?,
                target_manifest_hash: Hash32::decode_value(decoder)?,
                restore_manifest_hash: Hash32::decode_value(decoder)?,
                reason_code: decoder.u16().map_err(decode_error)?,
            }),
            (4, 3) => Ok(Self::Rollover {
                successor_ca_id: Hash32::decode_value(decoder)?,
                successor_admin_key: Ed25519PublicKey::decode_value(decoder)?,
            }),
            (5, 2) => Ok(Self::Terminal {
                reason_code: decoder.u16().map_err(decode_error)?,
            }),
            _ => Err(Error::Validation(format!(
                "unknown control action code/length combination {code}/{length}"
            ))),
        }
    }

    fn validate_value(&self) -> Result<()> {
        match self {
            Self::Enable { .. } | Self::Rollover { .. } => Ok(()),
            Self::Disable { reason_code } | Self::Terminal { reason_code } => {
                if *reason_code == 0 {
                    Err(Error::Validation(
                        "disable/terminal reason code must be non-zero".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
            Self::Cancel {
                target_version,
                target_manifest_hash,
                restore_manifest_hash,
                reason_code,
            } => {
                if *target_version == 0 {
                    return Err(Error::Validation(
                        "cancel target version must be non-zero".to_owned(),
                    ));
                }
                if target_manifest_hash == restore_manifest_hash {
                    return Err(Error::Validation(
                        "cancel target and restored manifest hashes must differ".to_owned(),
                    ));
                }
                if *reason_code == 0 {
                    return Err(Error::Validation(
                        "cancel reason code must be non-zero".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

impl_wire_object!(ControlActionV1);

/// A CA administrative event signed by a pre-registered Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEventV1 {
    /// Wire protocol version; must be one.
    pub protocol_version: u16,
    /// Lantern/Comet chain identifier.
    pub network_id: NetworkId,
    /// CA instance affected by this event.
    pub ca_id: Hash32,
    /// Strictly positive per-CA administrative sequence.
    pub admin_sequence: u64,
    /// Previous authenticated state hash; absent only for first enable.
    pub previous_state_hash: Option<Hash32>,
    /// Replay/idempotency nonce.
    pub nonce: Nonce16,
    /// Typed transition.
    pub action: ControlActionV1,
}

impl WireValue for ControlEventV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 7)?;
        encoder.u16(self.protocol_version).map_err(encode_error)?;
        self.network_id.encode_value(encoder)?;
        encoder.bytes(self.ca_id.as_bytes()).map_err(encode_error)?;
        encoder.u64(self.admin_sequence).map_err(encode_error)?;
        encode_optional_bytes(
            encoder,
            self.previous_state_hash.as_ref().map(Hash32::as_bytes),
        )?;
        encoder.bytes(self.nonce.as_bytes()).map_err(encode_error)?;
        self.action.encode_value(encoder)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 7, "ControlEventV1")?;
        Ok(Self {
            protocol_version: decoder.u16().map_err(decode_error)?,
            network_id: NetworkId::decode_value(decoder)?,
            ca_id: Hash32::decode_value(decoder)?,
            admin_sequence: decoder.u64().map_err(decode_error)?,
            previous_state_hash: decode_optional_fixed(decoder, "previous state hash")?
                .map(Hash32::new),
            nonce: Nonce16::decode_value(decoder)?,
            action: ControlActionV1::decode_value(decoder)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(Error::Validation(format!(
                "control event protocol version is {}, expected {PROTOCOL_VERSION_V1}",
                self.protocol_version
            )));
        }
        self.network_id.validate()?;
        if self.admin_sequence == 0 {
            return Err(Error::Validation(
                "admin sequence must be non-zero".to_owned(),
            ));
        }
        self.action.validate()?;
        match &self.action {
            ControlActionV1::Enable { .. } if self.admin_sequence == 1 => {
                if self.previous_state_hash.is_some() {
                    return Err(Error::Validation(
                        "initial enable must not claim a previous state".to_owned(),
                    ));
                }
            }
            ControlActionV1::Rollover {
                successor_ca_id, ..
            } if successor_ca_id == &self.ca_id => {
                return Err(Error::Validation(
                    "rollover successor CA_ID must differ from current CA_ID".to_owned(),
                ));
            }
            _ if self.previous_state_hash.is_none() => {
                return Err(Error::Validation(
                    "only initial enable may omit previous state hash".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

impl_wire_object!(ControlEventV1);
