use data_encoding::DecodeError as DataEncodingDecodeError;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::str::Utf8Error;

pub type EncodeResult<T> = Result<T, EncodeError>;

pub type DecodeResult<T> = Result<T, DecodeError>;

/// This enum represent all decode errors.
#[derive(Debug)]
pub enum DecodeError {
    /// This error occurs if the base64 string could not be decoded.
    Base64Error(DataEncodingDecodeError),
    /// This error occurs if there is not enough bytes.
    NotEnoughBytes,
    /// This error occurs if there is too many bytes.
    TooManyBytes,
    /// This error occurs if the type is unknown.
    UnknownType,
    /// This error occurs if a string could not be decoded.
    Utf8Error(Utf8Error),
    /// This error occurs if the address could not be decoded.
    AddrParseError(AddrParseError),
    /// This error occurs if the length of an array has not the expected value.
    Len,
    /// This error occurs if the a integer could not be parsed.
    /// For example when a port decoded.
    ParseIntError(ParseIntError),
    /// This error occurs if the regex `DNS_STAMP_REGEX` is not matched.
    Regex,
}

impl From<DataEncodingDecodeError> for DecodeError {
    fn from(data_encoding_decode_error: DataEncodingDecodeError) -> Self {
        DecodeError::Base64Error(data_encoding_decode_error)
    }
}

impl From<Utf8Error> for DecodeError {
    fn from(utf8_error: Utf8Error) -> Self {
        DecodeError::Utf8Error(utf8_error)
    }
}

impl From<AddrParseError> for DecodeError {
    fn from(addr_parse_error: AddrParseError) -> Self {
        DecodeError::AddrParseError(addr_parse_error)
    }
}

impl From<ParseIntError> for DecodeError {
    fn from(parse_int_error: ParseIntError) -> Self {
        DecodeError::ParseIntError(parse_int_error)
    }
}

/// This enum represent all encode errors.
#[derive(Debug)]
pub enum EncodeError {
    /// This error occurs if there is too many bytes to encode.
    TooManyBytes,
    /// This error occurs if the array is empty.
    EmptyArray,
}
