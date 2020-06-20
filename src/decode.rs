//! This module contains all decode functions for this crate.
use crate::{Addr, DecodeError, DecodeResult, DnsStamp, DnsStampType, Props};
use data_encoding::BASE64URL_NOPAD;
use num_traits::FromPrimitive;
use regex::Regex;
use std::convert::TryInto;
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr};
use std::str::from_utf8;

/// Decode a `u8` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u8`.
fn decode_u8(buf: &[u8], offset: &mut usize) -> DecodeResult<u8> {
    let start = *offset;
    *offset += size_of::<u8>();

    if let Some(buf) = buf.get(start..*offset) {
        Ok(buf[0])
    } else {
        Err(DecodeError::NotEnoughBytes)
    }
}

/// Decode a `u64` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u64`.
fn decode_uint64(buf: &[u8], offset: &mut usize) -> DecodeResult<u64> {
    let start = *offset;
    *offset += size_of::<u64>();

    if let Some(buf) = buf.get(start..*offset) {
        Ok(u64::from_le_bytes(buf.try_into().unwrap()))
    } else {
        Err(DecodeError::NotEnoughBytes)
    }
}

/// Decode a `u8`slice from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `u8` slice.
/// See [`LP()`].
///
/// [`LP()`]: https://dnscrypt.info/stamps-specifications#common-definitions
fn decode_lp<'a>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<&'a [u8]> {
    let len = decode_u8(buf, offset)?;
    let start = *offset;
    *offset += len as usize;

    if let Some(buf) = buf.get(start..*offset) {
        Ok(buf)
    } else {
        Err(DecodeError::NotEnoughBytes)
    }
}

/// Decode a `str` slice from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
fn decode_str<'a>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<&'a str> {
    let bytes = decode_lp(buf, offset)?;

    let str = from_utf8(bytes)?;
    Ok(str)
}

/// Decode a 'str' and convert it to a `std::net::IpAddr` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `str`.
fn decode_ip_addr(buf: &[u8], offset: &mut usize) -> DecodeResult<IpAddr> {
    let string = decode_str(buf, offset)?;

    let ip_addr = string.parse()?;
    Ok(ip_addr)
}

/// Convert a `str` to a `std::net::SocketAddr`.
/// If the `str` contains only a address then use `default_port` as a port.
fn str_to_socket_addr(string: &str, default_port: u16) -> DecodeResult<SocketAddr> {
    match string.parse() {
        Ok(result) => Ok(result),
        Err(e) => {
            if let Ok(result) = format!("{}:{}", string, default_port).parse() {
                Ok(result)
            } else {
                Err(DecodeError::from(e))
            }
        }
    }
}

/// Decode a `str` and convert it to a `std::net::SocketAddr` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
/// If the `str` contains only a address then use `default_port` as a port.
fn decode_socket_addr(
    buf: &[u8],
    offset: &mut usize,
    default_port: u16,
) -> DecodeResult<SocketAddr> {
    let string = decode_str(buf, offset)?;

    str_to_socket_addr(string, default_port)
}

/// Decode a `str` and convert it to a `crate::Addr` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
/// If the `str` is empty then it return `None`.
/// If the `str` contains only a port then it return `Some(crate::Addr::Port)`.
/// If the `str` contains a address and a port then it return `Some(crate::Addr::SocketAddr)`.
fn decode_addr(buf: &[u8], offset: &mut usize, default_port: u16) -> DecodeResult<Option<Addr>> {
    let string = decode_str(buf, offset)?;
    if string.is_empty() {
        return Ok(None);
    }

    lazy_static! {
        static ref PORT_REGEX: Regex = Regex::new("^:(\\d+)$").unwrap();
    }

    if let Some(c) = PORT_REGEX.captures(&string) {
        if let Some(port) = c.get(1) {
            let port = port.as_str().parse()?;
            return Ok(Some(Addr::Port(port)));
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
fn decode_vlp<'a>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<Vec<&'a [u8]>> {
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
            return Err(DecodeError::NotEnoughBytes);
        }

        if last {
            return Ok(vector);
        }
    }
}

/// Decode an array of `u8` of the size of `32` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the array of `u8` of the size of `32`.
fn u8_array_u8_32_array(array: &[u8]) -> DecodeResult<[u8; 32]> {
    if array.len() != 32 {
        return Err(DecodeError::Len);
    }
    Ok(array.try_into().unwrap())
}

/// Decode a `std::vec::Vec<[u8;32]>` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of a `std::vec::Vec<[u8;32]>.
fn decode_hashi(buf: &[u8], offset: &mut usize) -> DecodeResult<Vec<[u8; 32]>> {
    let mut hashi = Vec::new();
    for hash in decode_vlp(buf, offset)? {
        if !hash.is_empty() {
            hashi.push(u8_array_u8_32_array(hash)?);
        }
    }

    Ok(hashi)
}

/// Decode a `std::vec::Vec<std::net::IpAddr>` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `std::vec::Vec<std::net::IpAddr>`.
fn decode_bootstrap_ipi(buf: &[u8], offset: &mut usize) -> DecodeResult<Vec<IpAddr>> {
    let mut bootstrap_ipi = Vec::new();
    for ip in decode_vlp(buf, offset)? {
        bootstrap_ipi.push(from_utf8(ip)?.parse()?);
    }
    Ok(bootstrap_ipi)
}

/// Decode an array of `u8` of the size of `32` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the array of `u8` of the size of `32`.
fn decode_pk(buf: &[u8], offset: &mut usize) -> DecodeResult<[u8; 32]> {
    let pk = decode_lp(buf, offset)?;
    u8_array_u8_32_array(pk)
}

/// Decode a `crate::DnsStampType` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::DnsStampType`.
fn decode_type(buf: &[u8], offset: &mut usize) -> DecodeResult<DnsStampType> {
    let type_ = decode_u8(buf, offset)?;
    if let Some(type_) = DnsStampType::from_u8(type_) {
        Ok(type_)
    } else {
        Err(DecodeError::UnknownType)
    }
}

/// Decode a `crate::Props` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::Props`.
fn decode_props(buf: &[u8], offset: &mut usize) -> DecodeResult<Props> {
    let props = decode_uint64(buf, offset)?;
    Ok(Props::from_bits_truncate(props))
}

impl DnsStamp {
    /// Decode a `crate::DnsStamp` from a `&str`.
    pub fn decode(stamp: &str) -> DecodeResult<DnsStamp> {
        lazy_static! {
            static ref DNS_STAMP_REGEX: Regex = Regex::new("^sdns://([A-Za-z0-9_-]+)$").unwrap();
        }

        if let Some(c) = DNS_STAMP_REGEX.captures(&stamp) {
            // Get the decoded base64 part.
            if let Some(base64) = c.get(1) {
                let bytes = BASE64URL_NOPAD.decode(base64.as_str().as_bytes())?;
                let mut offset: usize = 0;
                let type_ = decode_type(&bytes, &mut offset)?;
                let props = decode_props(&bytes, &mut offset)?;
                let dns_stamp = match type_ {
                    DnsStampType::DnsCrypt => {
                        let addr = decode_socket_addr(&bytes, &mut offset, 443)?;
                        let pk = decode_pk(&bytes, &mut offset)?;
                        let provider_name = decode_str(&bytes, &mut offset)?.to_string();
                        DnsStamp::DnsCrypt(props, addr, pk, provider_name)
                    }
                    DnsStampType::DnsOverHttps => {
                        let addr = decode_addr(&bytes, &mut offset, 443)?;
                        let hashi = decode_hashi(&bytes, &mut offset)?;
                        let hostname = decode_str(&bytes, &mut offset)?.to_string();
                        let path = decode_str(&bytes, &mut offset)?.to_string();
                        let bootstrap_ipi = if bytes.len() == offset {
                            Vec::new()
                        } else {
                            decode_bootstrap_ipi(&bytes, &mut offset)?
                        };
                        DnsStamp::DnsOverHttps(props, addr, hashi, hostname, path, bootstrap_ipi)
                    }
                    DnsStampType::DnsOverTls => {
                        let addr = decode_addr(&bytes, &mut offset, 443)?;
                        let hashi = decode_hashi(&bytes, &mut offset)?;
                        let hostname = decode_str(&bytes, &mut offset)?.to_string();
                        let bootstrap_ipi = if bytes.len() == offset {
                            None
                        } else {
                            Some(decode_ip_addr(&bytes, &mut offset)?)
                        };
                        DnsStamp::DnsOverTls(props, addr, hashi, hostname, bootstrap_ipi)
                    }
                    DnsStampType::DnsPlain => {
                        let addr = decode_ip_addr(&bytes, &mut offset)?;
                        DnsStamp::DnsPlain(props, addr)
                    }
                };
                if bytes.len() == offset {
                    Ok(dns_stamp)
                } else {
                    Err(DecodeError::TooManyBytes)
                }
            } else {
                Err(DecodeError::Regex)
            }
        } else {
            Err(DecodeError::Regex)
        }
    }
}
