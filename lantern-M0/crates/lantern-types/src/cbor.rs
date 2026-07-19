use minicbor::{Decoder, Encoder};

use crate::{Error, Result};

/// Hard upper bound applied before decoding any single Lantern wire object.
pub const MAX_WIRE_OBJECT_BYTES: usize = 1024 * 1024;

pub(crate) trait WireValue: Sized {
    fn encode_value(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<()>;
    fn decode_value(decoder: &mut Decoder<'_>) -> Result<Self>;
    fn validate_value(&self) -> Result<()>;
}

/// A Lantern object with a unique deterministic CBOR representation.
///
/// Implementations use fixed-length arrays and validate semantic invariants.
/// `from_canonical_cbor` decodes, validates, re-encodes, and byte-compares the
/// result, which rejects alternate integer widths, indefinite containers,
/// trailing data, and every other non-canonical representation accepted by a
/// permissive CBOR parser. The unchecked codec is sealed inside this crate so
/// downstream consumers cannot accidentally bypass canonicality enforcement.
pub trait WireObject: Sized {
    /// Validates all semantic invariants of the object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] when an invariant is violated.
    fn validate(&self) -> Result<()>;

    /// Returns the unique deterministic CBOR bytes for this object.
    ///
    /// # Errors
    ///
    /// Returns an encoding, validation, or size-limit error.
    fn to_canonical_cbor(&self) -> Result<Vec<u8>>;

    /// Parses exactly one deterministic CBOR object and rejects alternative
    /// encodings of the same semantic value.
    ///
    /// # Errors
    ///
    /// Returns a decoding, canonicality, validation, trailing-data, or
    /// size-limit error.
    fn from_canonical_cbor(input: &[u8]) -> Result<Self>;
}

pub(crate) fn validate_object<T: WireValue>(value: &T) -> Result<()> {
    value.validate_value()
}

pub(crate) fn encode_object<T: WireValue>(value: &T) -> Result<Vec<u8>> {
    value.validate_value()?;
    let mut encoder = Encoder::new(Vec::new());
    value.encode_value(&mut encoder)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_WIRE_OBJECT_BYTES {
        return Err(Error::ObjectTooLarge {
            actual: bytes.len(),
            limit: MAX_WIRE_OBJECT_BYTES,
        });
    }
    Ok(bytes)
}

pub(crate) fn decode_object<T: WireValue>(input: &[u8]) -> Result<T> {
    if input.len() > MAX_WIRE_OBJECT_BYTES {
        return Err(Error::ObjectTooLarge {
            actual: input.len(),
            limit: MAX_WIRE_OBJECT_BYTES,
        });
    }

    let mut decoder = Decoder::new(input);
    let value = T::decode_value(&mut decoder)?;
    if decoder.position() != input.len() {
        return Err(Error::TrailingData);
    }
    value.validate_value()?;
    if encode_object(&value)?.as_slice() != input {
        return Err(Error::NonCanonical);
    }
    Ok(value)
}

macro_rules! impl_wire_object {
    ($type:ty) => {
        impl $crate::cbor::WireObject for $type {
            fn validate(&self) -> $crate::Result<()> {
                $crate::cbor::validate_object(self)
            }

            fn to_canonical_cbor(&self) -> $crate::Result<Vec<u8>> {
                $crate::cbor::encode_object(self)
            }

            fn from_canonical_cbor(input: &[u8]) -> $crate::Result<Self> {
                $crate::cbor::decode_object(input)
            }
        }
    };
}

pub(crate) use impl_wire_object;

pub(crate) fn encode_error<E: std::fmt::Display>(error: E) -> Error {
    Error::CborEncode(error.to_string())
}

pub(crate) fn decode_error<E: std::fmt::Display>(error: E) -> Error {
    Error::CborDecode(error.to_string())
}

pub(crate) fn encode_array(encoder: &mut Encoder<Vec<u8>>, length: u64) -> Result<()> {
    encoder.array(length).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn expect_array(
    decoder: &mut Decoder<'_>,
    expected: u64,
    name: &'static str,
) -> Result<()> {
    let actual = decoder.array().map_err(decode_error)?;
    match actual {
        Some(length) if length == expected => Ok(()),
        Some(length) => Err(Error::Validation(format!(
            "{name} array length is {length}, expected {expected}"
        ))),
        None => Err(Error::Validation(format!(
            "{name} must use a definite-length array"
        ))),
    }
}

pub(crate) fn encode_optional_bytes<const N: usize>(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<&[u8; N]>,
) -> Result<()> {
    if let Some(bytes) = value {
        encoder.bytes(bytes).map_err(encode_error)?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    Ok(())
}

pub(crate) fn decode_optional_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<Option<[u8; N]>> {
    if decoder.datatype().map_err(decode_error)? == minicbor::data::Type::Null {
        decoder.null().map_err(decode_error)?;
        return Ok(None);
    }
    decode_fixed(decoder, field).map(Some)
}

pub(crate) fn decode_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<[u8; N]> {
    let bytes = decoder.bytes().map_err(decode_error)?;
    bytes
        .try_into()
        .map_err(|_| Error::Validation(format!("{field} has length {}, expected {N}", bytes.len())))
}

pub(crate) fn encode_optional_u64(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<u64>,
) -> Result<()> {
    if let Some(value) = value {
        encoder.u64(value).map_err(encode_error)?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    Ok(())
}

pub(crate) fn decode_optional_u64(decoder: &mut Decoder<'_>) -> Result<Option<u64>> {
    if decoder.datatype().map_err(decode_error)? == minicbor::data::Type::Null {
        decoder.null().map_err(decode_error)?;
        Ok(None)
    } else {
        decoder.u64().map(Some).map_err(decode_error)
    }
}
