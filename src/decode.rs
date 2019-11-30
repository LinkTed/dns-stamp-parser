//! This module contains all decode functions for this crate.
use std::mem::size_of;
use std::convert::TryInto;
use std::num::ParseIntError;
use std::str::{from_utf8, Utf8Error};
use std::net::{SocketAddr, IpAddr, AddrParseError};
use regex::Regex;
use num_traits::FromPrimitive;
use crate::{DnsStampDecodeError, Addr, DnsStampType, Props};


/// Decode a `u8` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u8`.
fn decode_u8(buf: &[u8], offset: &mut usize) -> Result<u8, DnsStampDecodeError> {
    let start = *offset;
    *offset += size_of::<u8>();

    if let Some(buf) = buf.get(start..*offset) {
        Ok(buf[0])
    } else {
        Err(DnsStampDecodeError::TooShort)
    }
}

/// Decode a `u64` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u64`.
fn decode_uint64(buf: &[u8], offset: &mut usize) -> Result<u64, DnsStampDecodeError> {
    let start = *offset;
    *offset += size_of::<u64>();

    if let Some(buf) = buf.get(start..*offset) {
        Ok(u64::from_le_bytes(buf.try_into().unwrap()))
    } else {
        Err(DnsStampDecodeError::TooShort)
    }
}

/// Decode a `u8`slice from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `u8` slice.
/// See [`LP()`].
///
/// [`LP()`]: https://dnscrypt.info/stamps-specifications#common-definitions
fn decode_lp<'a>(buf: &'a [u8], offset: &mut usize) -> Result<&'a [u8], DnsStampDecodeError> {
    let len = decode_u8(buf, offset)?;
    let start = *offset;
    *offset += len as usize;

    if let Some(buf) = buf.get(start..*offset) {
        Ok(buf)
    } else {
        Err(DnsStampDecodeError::TooShort)
    }
}

/// Decode a `str` slice from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
pub fn decode_str<'a>(buf: &'a [u8], offset: &mut usize) -> Result<&'a str, DnsStampDecodeError> {
    let bytes = decode_lp(buf, offset)?;

    let str = from_utf8(bytes)?;
    Ok(str)
}

/// Decode a 'str' and convert it to a `std::net::IpAddr` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `str`.
pub fn decode_ip_addr(buf: &[u8], offset: &mut usize) -> Result<IpAddr, DnsStampDecodeError> {
    let string = decode_str(buf, offset)?;

    let ip_addr = string.parse()?;
    Ok(ip_addr)
}

/// Convert a `str` to a `std::net::SocketAddr`.
/// If the `str` contains only a address then use `default_port` as a port.
fn str_to_socket_addr(string: &str, default_port: u16) -> Result<SocketAddr, DnsStampDecodeError> {
    match string.parse() {
        Ok(result) => {
            Ok(result)
        },
        Err(e) => {
            if let Ok(result) = format!("{}:{}", string, default_port).parse() {
                return Ok(result)
            }
            Err(DnsStampDecodeError::from(e))
        }
    }
}


/// Decode a `str` and convert it to a `std::net::SocketAddr` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
/// If the `str` contains only a address then use `default_port` as a port.
pub fn decode_socket_addr(buf: &[u8], offset: &mut usize, default_port: u16) -> Result<SocketAddr, DnsStampDecodeError> {
    let string = decode_str(buf, offset)?;

    str_to_socket_addr(string, default_port)
}

/// Decode a `str` and convert it to a `crate::Addr` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
/// If the `str` is empty then it return `None`.
/// If the `str` contains only a port then it return `Some(crate::Addr::Port`.
/// If the `str` contains a address and a port then it return `Some(crate::Addr::SocketAddr)`.
pub fn decode_addr(buf: &[u8], offset: &mut usize, default_port: u16) -> Result<Option<Addr>, DnsStampDecodeError> {
    let string = decode_str(buf, offset)?;
    if string == "" {
        return Ok(None)
    }

    lazy_static! {
        static ref PORT_REGEX: Regex = Regex::new("^:(\\d+)$").unwrap();
    }

    if let Some(c) = PORT_REGEX.captures(&string) {
        if let Some(port) = c.get(1) {
            let port = port.as_str().parse()?;
            return Ok(Some(Addr::Port(port)))
        }
    }

    let socket_addr = str_to_socket_addr(string, default_port)?;
    Ok(Some(Addr::SocketAddr(socket_addr)))
}

/// Decode a `std::vec::Vec<u8>` slice from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `std::vec::Vec<&[u8]>`.
/// See [`VLP()`].
///
/// [`VLP()`]:  https://dnscrypt.info/stamps-specifications#common-definitions
fn decode_vlp<'a>(buf: &'a [u8], offset: &mut usize) -> Result<Vec<&'a [u8]>, DnsStampDecodeError> {
    let mut vector = Vec::new();
    loop {
        let mut last = false;
        let mut len = decode_u8(buf, offset)?;
        if len & 0x80 == 0x80 {
            len ^= 0x80;
        } else {
            last = true;
        }
        let start = *offset;
        *offset += len as usize;

        if let Some(buf) = buf.get(start..*offset) {
            vector.push(buf);
        } else {
            return Err(DnsStampDecodeError::TooShort)
        }

        if last {
            return Ok(vector);
        }
    }
}

/// Decode an array of `u8` of the size of `32` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the array of `u8` of the size of `32`.
fn u8_array_u8_32_array(array: &[u8]) -> Result<[u8;32], DnsStampDecodeError> {
    if array.len() != 32 {
        return Err(DnsStampDecodeError::Len)
    }
    Ok(array.try_into().unwrap())
}

/// Decode a `std::vec::Vec<[u8;32]>` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of a `std::vec::Vec<[u8;32]>.
pub fn decode_hashi(buf: &[u8], offset: &mut usize) -> Result<Vec<[u8;32]>, DnsStampDecodeError> {
    let mut hashi = Vec::new();
    for hash in decode_vlp(buf, offset)? {
        if hash.len() != 0 {
            hashi.push(u8_array_u8_32_array(hash)?);
        }
    }

    Ok(hashi)
}

/// Decode a `std::vec::Vec<std::net::IpAddr>` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `std::vec::Vec<std::net::IpAddr>`.
pub fn decode_bootstrap_ipi(buf: &[u8], offset: &mut usize) -> Result<Vec<IpAddr>, DnsStampDecodeError> {
    let mut bootstrap_ipi = Vec::new();
    for ip in decode_vlp(buf, offset)? {
        bootstrap_ipi.push(from_utf8(ip)?.parse()?);
    }
    Ok(bootstrap_ipi)
}

/// Decode an array of `u8` of the size of `32` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the array of `u8` of the size of `32`.
pub fn decode_pk(buf: &[u8], offset: &mut usize) -> Result<[u8;32], DnsStampDecodeError> {
    let pk = decode_lp(buf, offset)?;
    u8_array_u8_32_array(pk)
}

/// Decode a `crate::DnsStampType` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::DnsStampType`.
pub fn decode_type(buf: &[u8], offset: &mut usize) -> Result<DnsStampType, DnsStampDecodeError> {
    let type_ = decode_u8(buf, offset)?;
    match DnsStampType::from_u8(type_) {
        Some(type_) => {
            Ok(type_)
        }
        None => {
            Err(DnsStampDecodeError::UnknownType)
        }
    }
}

/// Decode a `crate::Props` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::Props`.
pub fn decode_props(buf: &[u8], offset: &mut usize) -> Result<Props, DnsStampDecodeError> {
    let props = decode_uint64(buf, offset)?;
    Ok(Props::from_bits_truncate(props))
}

impl From<Utf8Error> for DnsStampDecodeError {
    fn from(utf8_error: Utf8Error) -> Self {
        DnsStampDecodeError::Utf8Error(utf8_error)
    }
}

impl From<AddrParseError> for DnsStampDecodeError {
    fn from(addr_parse_error: AddrParseError) -> Self {
        DnsStampDecodeError::AddrParseError(addr_parse_error)
    }
}

impl From<ParseIntError> for DnsStampDecodeError {
    fn from(parse_int_error: ParseIntError) -> Self {
        DnsStampDecodeError::ParseIntError(parse_int_error)
    }
}
