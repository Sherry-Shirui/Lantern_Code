use thiserror::Error;

/// Errors returned while validating, encoding, hashing, or authenticating a
/// Lantern wire object.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The object exceeds the global defensive decoding limit.
    #[error("wire object is too large: {actual} bytes (limit {limit})")]
    ObjectTooLarge { actual: usize, limit: usize },

    /// CBOR encoding failed.
    #[error("CBOR encoding failed: {0}")]
    CborEncode(String),

    /// CBOR decoding failed.
    #[error("CBOR decoding failed: {0}")]
    CborDecode(String),

    /// The input contained bytes after the single expected object.
    #[error("trailing bytes after canonical CBOR object")]
    TrailingData,

    /// The input decoded, but was not the unique deterministic encoding.
    #[error("CBOR input is not the deterministic Lantern encoding")]
    NonCanonical,

    /// A decoded or constructed value violated a protocol invariant.
    #[error("validation failed: {0}")]
    Validation(String),

    /// A hexadecimal string had the wrong form or size.
    #[error("invalid hexadecimal value: {0}")]
    InvalidHex(String),

    /// A signature or its claimed key identifier did not verify.
    #[error("Ed25519 authorization failed")]
    InvalidSignature,
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, Error>;
