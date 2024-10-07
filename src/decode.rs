//! This module contains all decode functions for this crate.
use crate::{
    Addr, AnonymizedDnsCryptRelay, DecodeError, DecodeResult, DnsCrypt, DnsOverHttps, DnsOverTls,
    DnsPlain, DnsStamp, DnsStampType, ObliviousDoHTarget, Props,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::{self, from_utf8},
};

/// Decode a `u8` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u8`.
fn decode<'a, T>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<&'a [u8]> {
    let start = *offset;
    *offset += size_of::<T>();

    buf.get(start..*offset).ok_or(DecodeError::NotEnoughBytes)
}

/// Decode a `u64` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u64`.
fn decode_u64(buf: &[u8], offset: &mut usize) -> DecodeResult<u64> {
    let bytes = decode::<u64>(buf, offset)?
        .try_into()
        .expect("slice has incorrect length");
    Ok(u64::from_le_bytes(bytes))
}

/// Decode a `u8` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u8`.
fn decode_u8(buf: &[u8], offset: &mut usize) -> DecodeResult<u8> {
    Ok(decode::<u8>(buf, offset)?[0])
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

    buf.get(start..*offset).ok_or(DecodeError::NotEnoughBytes)
}

/// Decode a `str` slice from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
fn decode_str<'a>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<&'a str> {
    let bytes = decode_lp(buf, offset)?;
    Ok(str::from_utf8(bytes)?)
}

/// Convert a `str` to a `std::net::IpAddr`.
fn str_to_ip_addr(string: &str) -> DecodeResult<IpAddr> {
    // Check if the addr is IPv6
    if let Some(string) = string.strip_prefix('[') {
        if let Some(string) = string.strip_suffix(']') {
            let ipv6_addr = string.parse::<Ipv6Addr>()?;
            Ok(IpAddr::V6(ipv6_addr))
        } else {
            Err(DecodeError::AddrParseIpv6ClosingBracket)
        }
    } else {
        let ipv4_addr = string.parse::<Ipv4Addr>()?;
        Ok(IpAddr::V4(ipv4_addr))
    }
}

/// Decode a 'str' and convert it to a `std::net::IpAddr` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `str`.
fn decode_ip_addr(buf: &[u8], offset: &mut usize) -> DecodeResult<IpAddr> {
    let string = decode_str(buf, offset)?;
    str_to_ip_addr(string)
}

/// Convert a `str` to a `std::net::SocketAddr`.
/// If the `str` contains only a address then use `default_port` as a port.
fn str_to_socket_addr(string: &str, default_port: u16) -> DecodeResult<SocketAddr> {
    match string.parse() {
        Ok(result) => Ok(result),
        Err(_) => Ok(format!("{}:{}", string, default_port).parse()?),
    }
}

/// Decode a `str` and convert it to a `std::net::SocketAddr` from a `u8` slice at a specific
/// `offset`.
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

/// Convert a `str` to a `crate::Addr`.
/// If the `str` contains only a address then use `default_port` as a port.
fn str_to_addr(string: &str, default_port: u16) -> DecodeResult<Addr> {
    match string.strip_prefix(':') {
        Some(port) => Ok(Addr::Port(port.parse()?)),
        None => Ok(Addr::SocketAddr(str_to_socket_addr(string, default_port)?)),
    }
}

/// Decode a `str` and convert it to a `Option<crate::Addr>` from a `u8` slice at a specific
/// `offset`.
/// Increase the `offset` by the size of the `str`.
/// If the `str` is empty then it return `None`.
/// If the `str` contains only a port then it return `Some(crate::Addr::Port)`.
/// If the `str` contains a address and a port then it return `Some(crate::Addr::SocketAddr)`.
fn decode_option_addr(
    buf: &[u8],
    offset: &mut usize,
    default_port: u16,
) -> DecodeResult<Option<Addr>> {
    let string = decode_str(buf, offset)?;
    if string.is_empty() {
        Ok(None)
    } else {
        let addr = str_to_addr(string, default_port)?;
        Ok(Some(addr))
    }
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

/// Decode an array of `u8` of the size of `32` from a `u8` slice
fn slice_to_32_bytes(array: &[u8]) -> DecodeResult<[u8; 32]> {
    array.try_into().map_err(|_| DecodeError::Len)
}

/// Decode a `std::vec::Vec<[u8;32]>` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of a `std::vec::Vec<[u8;32]>.
fn decode_hashi(buf: &[u8], offset: &mut usize) -> DecodeResult<Vec<[u8; 32]>> {
    decode_vlp(buf, offset)?
        .into_iter()
        .filter_map(|hash| {
            if !hash.is_empty() {
                Some(slice_to_32_bytes(hash))
            } else {
                None
            }
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Decode a `std::vec::Vec<std::net::IpAddr>` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `std::vec::Vec<std::net::IpAddr>`.
fn decode_bootstrap_ipi(buf: &[u8], offset: &mut usize) -> DecodeResult<Vec<IpAddr>> {
    let ips = decode_vlp(buf, offset)?;
    let mut bootstrap_ipi = Vec::with_capacity(ips.len());
    for ip in ips {
        bootstrap_ipi.push(str_to_ip_addr(from_utf8(ip)?)?);
    }
    Ok(bootstrap_ipi)
}

/// Decode an array of `u8` of the size of `32` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the array of `u8` of the size of `32`.
fn decode_pk(buf: &[u8], offset: &mut usize) -> DecodeResult<[u8; 32]> {
    slice_to_32_bytes(decode_lp(buf, offset)?)
}

/// Decode a `crate::DnsStampType` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::DnsStampType`.
fn decode_type(buf: &[u8], offset: &mut usize) -> DecodeResult<DnsStampType> {
    let type_ = decode_u8(buf, offset)?;
    DnsStampType::try_from(type_).map_err(|_| DecodeError::UnknownType(type_))
}

/// Decode a `crate::Props` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::Props`.
fn decode_props(buf: &[u8], offset: &mut usize) -> DecodeResult<Props> {
    let props = decode_u64(buf, offset)?;
    Ok(Props::from_bits_truncate(props))
}

/// Decode a Base64 encoded `&str` with a prefix `"sdns://"` to `std::vec::Vec<u8>`.
fn decode_base64(stamp: &str) -> DecodeResult<Vec<u8>> {
    if let Some(base64) = stamp.strip_prefix("sdns://") {
        Ok(BASE64_URL_SAFE_NO_PAD.decode(base64)?)
    } else {
        Err(DecodeError::InvalidInput {
            cause: "sdns:// prefix not present".to_string(),
        })
    }
}

/// Decode a `crate::DnsPlain` from a `u8` slice at s specific `offset`.
/// Increase the `offset`
fn decode_dns_plain(buf: &[u8], offset: &mut usize) -> DecodeResult<DnsPlain> {
    let props = decode_props(buf, offset)?;
    let addr = decode_ip_addr(buf, offset)?;
    let dns_plain = DnsPlain { props, addr };
    Ok(dns_plain)
}

/// Decode a `crate::DnsCrypt` from a `u8` slice at s specific `offset`.
/// Increase the `offset`
fn decode_dns_crypt(buf: &[u8], offset: &mut usize) -> DecodeResult<DnsCrypt> {
    let props = decode_props(buf, offset)?;
    let addr = decode_socket_addr(buf, offset, 443)?;
    let pk = decode_pk(buf, offset)?;
    let provider_name = decode_str(buf, offset)?.to_string();
    let dns_crypt = DnsCrypt {
        props,
        addr,
        pk,
        provider_name,
    };
    Ok(dns_crypt)
}

/// Decode a `crate::DnsOverHttps` from a `u8` slice at s specific `offset`.
/// Increase the `offset`
fn decode_dns_over_https(buf: &[u8], offset: &mut usize) -> DecodeResult<DnsOverHttps> {
    let props = decode_props(buf, offset)?;
    let addr = decode_option_addr(buf, offset, 443)?;
    let hashi = decode_hashi(buf, offset)?;
    let hostname = decode_str(buf, offset)?.to_string();
    let path = decode_str(buf, offset)?.to_string();
    let bootstrap_ipi = if buf.len() == *offset {
        Vec::new()
    } else {
        decode_bootstrap_ipi(buf, offset)?
    };
    let dns_over_https = DnsOverHttps {
        props,
        addr,
        hashi,
        hostname,
        path,
        bootstrap_ipi,
    };
    Ok(dns_over_https)
}

/// Decode a `crate::DnsOverTls` from a `u8` slice at s specific `offset`.
/// Increase the `offset`
fn decode_dns_over_tls(buf: &[u8], offset: &mut usize) -> DecodeResult<DnsOverTls> {
    let props = decode_props(buf, offset)?;
    let addr = decode_option_addr(buf, offset, 443)?;
    let hashi = decode_hashi(buf, offset)?;
    let hostname = decode_str(buf, offset)?.to_string();
    let bootstrap_ipi = if buf.len() == *offset {
        Vec::new()
    } else {
        decode_bootstrap_ipi(buf, offset)?
    };
    let dns_over_tls = DnsOverTls {
        props,
        addr,
        hashi,
        hostname,
        bootstrap_ipi,
    };
    Ok(dns_over_tls)
}

/// Decode a `crate::ObliviousDoHTarget` from a `u8` slice at s specific `offset`.
/// Increase the `offset`
fn decode_oblivious_doh_target(buf: &[u8], offset: &mut usize) -> DecodeResult<ObliviousDoHTarget> {
    let props = decode_props(buf, offset)?;
    let hostname = decode_str(buf, offset)?.to_string();
    let path = decode_str(buf, offset)?.to_string();
    let oblivious_doh_target = ObliviousDoHTarget {
        props,
        hostname,
        path,
    };
    Ok(oblivious_doh_target)
}

/// Decode a `crate::AnonymizedDnsCryptRelay` from a `u8` slice at s specific `offset`.
/// Increase the `offset`
fn decode_anonymized_dns_crypt_relay(
    buf: &[u8],
    offset: &mut usize,
) -> DecodeResult<AnonymizedDnsCryptRelay> {
    let addr = decode_socket_addr(buf, offset, 443)?;
    let anonymized_dns_crypt_relay = AnonymizedDnsCryptRelay { addr };
    Ok(anonymized_dns_crypt_relay)
}

impl DnsStamp {
    /// Decode a `crate::DnsStamp` from a `&str`.
    pub fn decode(stamp: &str) -> DecodeResult<DnsStamp> {
        let bytes = decode_base64(stamp)?;
        let mut offset: usize = 0;
        let stamp_type = decode_type(&bytes, &mut offset)?;

        let dns_stamp = match stamp_type {
            DnsStampType::Plain => DnsStamp::DnsPlain(decode_dns_plain(&bytes, &mut offset)?),
            DnsStampType::DnsCrypt => DnsStamp::DnsCrypt(decode_dns_crypt(&bytes, &mut offset)?),
            DnsStampType::DnsOverHttps => {
                DnsStamp::DnsOverHttps(decode_dns_over_https(&bytes, &mut offset)?)
            }
            DnsStampType::DnsOverTls => {
                DnsStamp::DnsOverTls(decode_dns_over_tls(&bytes, &mut offset)?)
            }
            DnsStampType::DnsOverQuic => {
                DnsStamp::DnsOverQuic(decode_dns_over_tls(&bytes, &mut offset)?)
            }
            DnsStampType::ObliviousDoHTarget => {
                DnsStamp::ObliviousDoHTarget(decode_oblivious_doh_target(&bytes, &mut offset)?)
            }
            DnsStampType::AnonymizedDnsCryptRelay => DnsStamp::AnonymizedDnsCryptRelay(
                decode_anonymized_dns_crypt_relay(&bytes, &mut offset)?,
            ),
            DnsStampType::ObliviousDoHRelay => {
                DnsStamp::ObliviousDoHRelay(decode_dns_over_https(&bytes, &mut offset)?)
            }
        };
        if bytes.len() == offset {
            Ok(dns_stamp)
        } else {
            Err(DecodeError::TooManyBytes)
        }
    }
}

impl str::FromStr for DnsStamp {
    type Err = DecodeError;
    fn from_str(s: &str) -> DecodeResult<Self> {
        DnsStamp::decode(s)
    }
}
