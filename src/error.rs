use thiserror::Error;

use data_encoding::DecodeError as DataEncodingDecodeError;
use std::{net::AddrParseError, num::ParseIntError, str::Utf8Error};

/// Result for encoding
pub type EncodeResult<T> = Result<T, EncodeError>;

/// Result for decoding
pub type DecodeResult<T> = Result<T, DecodeError>;

/// This enum represent all decode errors.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// This error occurs if the base64 string could not be decoded.
    #[error("error parsing base 64")]
    Base64Error(#[from] DataEncodingDecodeError),
    /// This error occurs if there is not enough bytes.
    #[error("ran out of bytes to parse")]
    NotEnoughBytes,
    /// This error occurs if there is too many bytes.
    #[error("input too large")]
    TooManyBytes,
    /// This error occurs if a string could not be decoded.
    #[error("string could not be decoded with utf-8")]
    Utf8Error(#[from] Utf8Error),
    /// This error occurs if the address could not be decoded.
    #[error("failed to parse address")]
    AddrParseError(#[from] AddrParseError),
    /// This error occurs if an address is missing.
    #[error("address missing")]
    MissingAddr,
    /// This error occurs if the length of an array has not the expected value.
    #[error("length of array not what was expected")]
    Len,
    /// This error occurs if the a integer could not be parsed.
    /// For example when a port decoded.
    #[error("failed to parse int value")]
    ParseIntError(#[from] ParseIntError),
    /// This error occurs if the regex `DNS_STAMP_REGEX` is not matched.
    #[error("input is invalid {cause:?}")]
    InvalidInput {
        /// cause of the invalid input
        cause: String,
    },
    /// This error occurs if the type is unknown.
    #[error("unknown type")]
    UnknownType(u8),
}

/// This enum represent all encode errors.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// This error occurs if there is too many bytes to encode.
    #[error("input too large")]
    TooManyBytes,
    /// This error occurs if the array is empty.
    #[error("array is empty")]
    EmptyArray,
}
