use crate::{Error, Result};

const PREAMBLE: &[u8] = b"LANTERN\0";

/// Closed set of protocol-v1 hash and signature domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainV1 {
    /// Stable CA identifier.
    CaId,
    /// One-time manifest EE publication intent.
    Intent,
    /// CA administrative control event.
    Control,
    /// Latest-state map key.
    LatestKey,
    /// Latest-state map leaf.
    LatestLeaf,
    /// Append-only history leaf.
    HistoryLeaf,
    /// Append-only history internal node.
    HistoryNode,
    /// Canonical compact history record digest.
    HistoryRecord,
    /// Canonical per-CA state digest.
    CaState,
    /// Canonical state-machine transaction identifier.
    StateTransaction,
    /// Deterministic transaction-result accumulator.
    TransactionResults,
    /// Ordered admitted-transaction bundle accumulator.
    EpochBundle,
    /// CA administrative-key registry accumulator.
    AdminRegistry,
    /// Consensus-critical schema and configuration identifier.
    SchemaConfig,
    /// Quorum-certified head body identifier.
    HeadBody,
    /// ABCI application-state commitment.
    AppState,
    /// Validator configuration identifier.
    ValidatorConfig,
    /// Governance-authorized validator update.
    Governance,
    /// Ed25519 key identifier.
    Ed25519KeyId,
}

impl DomainV1 {
    /// Returns the exact ASCII domain label frozen by protocol v1.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaId => "lantern/v1/ca-id",
            Self::Intent => "lantern/v1/intent",
            Self::Control => "lantern/v1/control",
            Self::LatestKey => "lantern/v1/latest-key",
            Self::LatestLeaf => "lantern/v1/latest-leaf",
            Self::HistoryLeaf => "lantern/v1/history-leaf",
            Self::HistoryNode => "lantern/v1/history-node",
            Self::HistoryRecord => "lantern/v1/history-record",
            Self::CaState => "lantern/v1/ca-state",
            Self::StateTransaction => "lantern/v1/state-transaction",
            Self::TransactionResults => "lantern/v1/transaction-results",
            Self::EpochBundle => "lantern/v1/epoch-bundle",
            Self::AdminRegistry => "lantern/v1/admin-registry",
            Self::SchemaConfig => "lantern/v1/schema-config",
            Self::HeadBody => "lantern/v1/head-body",
            Self::AppState => "lantern/v1/app-state",
            Self::ValidatorConfig => "lantern/v1/validator-config",
            Self::Governance => "lantern/v1/governance",
            Self::Ed25519KeyId => "lantern/v1/ed25519-key-id",
        }
    }
}

/// Creates the exact length-delimited preimage used by Lantern v1 hashes and
/// signatures: `"LANTERN\\0" || u16be(domain_len) || domain ||
/// u64be(payload_len) || payload`.
///
/// # Errors
///
/// Returns an error if a length cannot be represented or the allocation size
/// overflows.
pub fn domain_separated_message(domain: DomainV1, payload: &[u8]) -> Result<Vec<u8>> {
    let domain = domain.as_str();
    let domain_length = u16::try_from(domain.len())
        .map_err(|_| Error::Validation("domain name is longer than u16".to_owned()))?;
    let payload_length = u64::try_from(payload.len())
        .map_err(|_| Error::Validation("payload is longer than u64".to_owned()))?;

    let capacity = PREAMBLE
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(domain.len()))
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or_else(|| Error::Validation("framed message length overflow".to_owned()))?;

    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(PREAMBLE);
    message.extend_from_slice(&domain_length.to_be_bytes());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(&payload_length.to_be_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

/// Length-prefixes a list of byte strings for use as a domain payload.
pub(crate) fn framed_parts(parts: &[&[u8]]) -> Result<Vec<u8>> {
    let part_count = u32::try_from(parts.len())
        .map_err(|_| Error::Validation("too many framed parts".to_owned()))?;
    let mut output = Vec::new();
    output.extend_from_slice(&part_count.to_be_bytes());
    for part in parts {
        let length = u64::try_from(part.len())
            .map_err(|_| Error::Validation("framed part is longer than u64".to_owned()))?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(part);
    }
    Ok(output)
}
