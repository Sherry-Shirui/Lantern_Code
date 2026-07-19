use std::{fmt, str::FromStr};

use minicbor::{Decoder, Encoder};

use crate::{
    Error, Result, WireObject,
    cbor::{WireValue, impl_wire_object},
    cbor::{decode_error, decode_fixed, encode_array, encode_error, expect_array},
};

macro_rules! fixed_bytes_type {
    ($(#[$meta:meta])* $name:ident, $length:expr, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Creates a fixed-length value from bytes.
            #[must_use]
            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            /// Returns the underlying bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            /// Returns lower-case hexadecimal without a prefix.
            #[must_use]
            pub fn to_hex(self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&hex::encode(self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(value: [u8; $length]) -> Self {
                Self::new(value)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                let decoded = hex::decode(value)
                    .map_err(|error| Error::InvalidHex(error.to_string()))?;
                let bytes = decoded.try_into().map_err(|decoded: Vec<u8>| {
                    Error::InvalidHex(format!(
                        "{} has {} bytes, expected {}",
                        $label,
                        decoded.len(),
                        $length
                    ))
                })?;
                Ok(Self::new(bytes))
            }
        }

        impl WireValue for $name {
            fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
                encoder.bytes(&self.0).map_err(encode_error)?;
                Ok(())
            }

            fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
                decode_fixed(decoder, $label).map(Self::new)
            }

            fn validate_value(&self) -> Result<()> {
                Ok(())
            }
        }

        impl_wire_object!($name);
    };
}

fixed_bytes_type!(
    /// A 32-byte SHA-256 digest.
    Hash32,
    32,
    "hash"
);
fixed_bytes_type!(
    /// A 16-byte caller-generated replay/idempotency nonce.
    Nonce16,
    16,
    "nonce"
);
fixed_bytes_type!(
    /// A CometBFT-style 20-byte validator address.
    ValidatorAddress,
    20,
    "validator address"
);
fixed_bytes_type!(
    /// A raw 32-byte Ed25519 public key.
    Ed25519PublicKey,
    32,
    "Ed25519 public key"
);
fixed_bytes_type!(
    /// A raw 64-byte Ed25519 signature.
    Ed25519Signature,
    64,
    "Ed25519 signature"
);

/// A validated Lantern/Comet chain identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId(String);

impl NetworkId {
    /// Creates a network ID. Accepted characters are ASCII letters, digits,
    /// `.`, `_`, and `-`; length must be 1 through 49 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, overlong, or non-canonical identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = Self(value.into());
        value.validate()?;
        Ok(value)
    }

    /// Returns the network identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NetworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("NetworkId").field(&self.0).finish()
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl WireValue for NetworkId {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encoder.str(&self.0).map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder
            .str()
            .map(|value| Self(value.to_owned()))
            .map_err(decode_error)
    }

    fn validate_value(&self) -> Result<()> {
        let length = self.0.len();
        if !(1..=49).contains(&length) {
            return Err(Error::Validation(
                "network ID length must be between 1 and 49 bytes".to_owned(),
            ));
        }
        if !self
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(Error::Validation(
                "network ID contains a forbidden character".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(NetworkId);

/// A canonical UTC timestamp matching protobuf seconds/nanoseconds precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampV1 {
    /// Seconds since the Unix epoch.
    pub seconds: i64,
    /// Nanoseconds within the second; always less than 1,000,000,000.
    pub nanos: u32,
}

impl TimestampV1 {
    /// Constructs and validates a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when `nanos` is at least 1,000,000,000.
    pub fn new(seconds: i64, nanos: u32) -> Result<Self> {
        let value = Self { seconds, nanos };
        value.validate()?;
        Ok(value)
    }
}

impl WireValue for TimestampV1 {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()> {
        encode_array(encoder, 2)?;
        encoder.i64(self.seconds).map_err(encode_error)?;
        encoder.u32(self.nanos).map_err(encode_error)?;
        Ok(())
    }

    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self> {
        expect_array(decoder, 2, "TimestampV1")?;
        Ok(Self {
            seconds: decoder.i64().map_err(decode_error)?,
            nanos: decoder.u32().map_err(decode_error)?,
        })
    }

    fn validate_value(&self) -> Result<()> {
        if self.nanos >= 1_000_000_000 {
            return Err(Error::Validation(
                "timestamp nanos must be below 1,000,000,000".to_owned(),
            ));
        }
        Ok(())
    }
}

impl_wire_object!(TimestampV1);
