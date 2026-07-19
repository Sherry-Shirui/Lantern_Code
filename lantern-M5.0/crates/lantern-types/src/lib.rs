#![forbid(unsafe_code)]
#![doc = "Canonical Lantern v1 wire objects and cryptographic bindings."]

mod cbor;
mod control;
mod domain;
mod error;
mod hash;
mod head;
mod intent;
mod primitive;
mod signature;
mod state;
mod validator;

pub use cbor::{MAX_WIRE_OBJECT_BYTES, WireObject};
pub use control::{ControlActionV1, ControlEventV1};
pub use domain::{DomainV1, domain_separated_message};
pub use error::{Error, Result};
pub use hash::{
    app_hash, ca_id, ca_state_hash, control_event_id, ed25519_key_id, hash_with_domain, head_id,
    history_record_digest, intent_id, manifest_hash, sha256, state_config_hash,
    state_transaction_id, ta_key_digest, transaction_result_digest, validator_config_hash,
    validator_update_id,
};
pub use head::{AppStateCommitmentV1, HeadBodyV1};
pub use intent::{PublicationEventTypeV1, PublicationIntentV1, PublicationSignatureAlgorithmV1};
pub use primitive::{
    Ed25519PublicKey, Ed25519Signature, Hash32, NetworkId, Nonce16, TimestampV1, ValidatorAddress,
};
pub use signature::{
    Ed25519AuthorizationV1, control_signing_message, publication_signing_message,
    sign_control_event, verify_control_event,
};
pub use state::{
    CaStateV1, CaStatusV1, ControlTransactionV1, EpochProfileV1, HistoryEventTypeV1,
    HistoryRecordV1, LatestValueV1, MAX_EE_CERTIFICATE_BYTES, MAX_EE_CERTIFICATE_CHAIN_ITEMS,
    MAX_EXACT_MANIFEST_BYTES, MAX_PUBLICATION_SIGNATURE_BYTES, PublicationTransactionV1,
    StateConfigV1, StateTransactionV1, TransactionResultCodeV1, TransactionResultV1,
};
pub use validator::{
    GovernanceSignatureV1, UnsignedValidatorUpdateV1, ValidatorConfigV1, ValidatorInfoV1,
    ValidatorUpdateV1, governance_signing_message, sign_validator_update, verify_validator_update,
};

/// The only protocol version accepted by this M0 implementation.
pub const PROTOCOL_VERSION_V1: u16 = 1;
