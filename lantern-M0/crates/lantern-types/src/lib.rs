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
mod validator;

pub use cbor::{MAX_WIRE_OBJECT_BYTES, WireObject};
pub use control::{ControlActionV1, ControlEventV1};
pub use domain::{DomainV1, domain_separated_message};
pub use error::{Error, Result};
pub use hash::{
    app_hash, ca_id, control_event_id, ed25519_key_id, hash_with_domain, head_id, intent_id,
    manifest_hash, sha256, ta_key_digest, validator_config_hash, validator_update_id,
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
pub use validator::{
    GovernanceSignatureV1, UnsignedValidatorUpdateV1, ValidatorConfigV1, ValidatorInfoV1,
    ValidatorUpdateV1, governance_signing_message, sign_validator_update, verify_validator_update,
};

/// The only protocol version accepted by this M0 implementation.
pub const PROTOCOL_VERSION_V1: u16 = 1;
