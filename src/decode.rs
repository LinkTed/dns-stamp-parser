//! This module contains all decode functions for this crate.
use crate::{
    Addr, AnonymizedDnsCryptRelay, DecodeErr, DecodeResult, DnsCrypt, DnsOverTls, DnsPlain,
    DnsStamp, DnsStampType, Props, DOH,
};
use data_encoding::BASE64URL_NOPAD;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
    net::{IpAddr, SocketAddr},
    str::{self, from_utf8},
};

/// Decode a `u8` from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of `u8`.
fn decode<'a, T>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<&'a [u8]> {
    let start = *offset;
    *offset += size_of::<T>();

    buf.get(start..*offset).ok_or(DecodeErr::NotEnoughBytes)
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

    buf.get(start..*offset).ok_or(DecodeErr::NotEnoughBytes)
}

/// Decode a `str` slice from a `u8` slice at a specific `offset`.
/// Increase the `offset` by the size of the `str`.
fn decode_str<'a>(buf: &'a [u8], offset: &mut usize) -> DecodeResult<&'a str> {
    let bytes = decode_lp(buf, offset)?;
    Ok(str::from_utf8(bytes)?)
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
        Err(_) => Ok(format!("{}:{}", string, default_port).parse()?),
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

    match string.find(':') {
        Some(i) if i == 0 => Ok(Some(Addr::Port(string[i..].parse()?))),
        _ => Ok(Some(Addr::SocketAddr(str_to_socket_addr(
            string,
            default_port,
        )?))),
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
            return Err(DecodeErr::NotEnoughBytes);
        }

        if last {
            return Ok(vector);
        }
    }
}

/// Decode an array of `u8` of the size of `32` from a `u8` slice
fn slice_to_32_bytes(array: &[u8]) -> DecodeResult<[u8; 32]> {
    Ok(array.try_into().map_err(|_| DecodeErr::Len)?)
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
    let mut bootstrap_ipi = Vec::new();
    for ip in ips {
        bootstrap_ipi.push(from_utf8(ip)?.parse()?);
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
    DnsStampType::try_from(type_).map_err(|_| DecodeErr::UnknownType(type_))
}

/// Decode a `crate::Props` from a `u8` slice at s specific `offset`.
/// Increase the `offset` by the size of the `crate::Props`.
fn decode_props(buf: &[u8], offset: &mut usize) -> DecodeResult<Props> {
    let props = decode_u64(buf, offset)?;
    Ok(Props::from_bits_truncate(props))
}

impl DnsStamp {
    /// Decode a `crate::DnsStamp` from a `&str`.
    pub fn decode(stamp: &str) -> DecodeResult<DnsStamp> {
        if &stamp[0..7] == "sdns://" {
            let base64 = &stamp[7..];
            let bytes = BASE64URL_NOPAD.decode(base64.as_bytes())?;
            let mut offset: usize = 0;
            let stamp_type = decode_type(&bytes, &mut offset)?;

            let dns_stamp = match stamp_type {
                DnsStampType::DnsCrypt => {
                    let props = decode_props(&bytes, &mut offset)?;
                    let addr = decode_socket_addr(&bytes, &mut offset, 443)?;
                    let pk = decode_pk(&bytes, &mut offset)?;
                    let provider_name = decode_str(&bytes, &mut offset)?.to_string();
                    DnsStamp::DnsCrypt(DnsCrypt {
                        props,
                        addr,
                        pk,
                        provider_name,
                    })
                }
                DnsStampType::DnsOverHttps => {
                    let props = decode_props(&bytes, &mut offset)?;
                    let addr = decode_addr(&bytes, &mut offset, 443)?;
                    let hashi = decode_hashi(&bytes, &mut offset)?;
                    let hostname = decode_str(&bytes, &mut offset)?.to_string();
                    let path = decode_str(&bytes, &mut offset)?.to_string();
                    let bootstrap_ipi = if bytes.len() == offset {
                        Vec::new()
                    } else {
                        decode_bootstrap_ipi(&bytes, &mut offset)?
                    };
                    DnsStamp::DnsOverHttps(DOH {
                        props,
                        addr,
                        hashi,
                        hostname,
                        path,
                        bootstrap_ipi,
                    })
                }
                DnsStampType::DnsOverTls => {
                    let props = decode_props(&bytes, &mut offset)?;
                    let addr = decode_addr(&bytes, &mut offset, 443)?;
                    let hashi = decode_hashi(&bytes, &mut offset)?;
                    let hostname = decode_str(&bytes, &mut offset)?.to_string();
                    let bootstrap_ipi = if bytes.len() == offset {
                        Vec::new()
                    } else {
                        decode_bootstrap_ipi(&bytes, &mut offset)?
                    };
                    DnsStamp::DnsOverTls(DnsOverTls {
                        props,
                        addr,
                        hashi,
                        hostname,
                        bootstrap_ipi,
                    })
                }
                DnsStampType::Plain => {
                    let props = decode_props(&bytes, &mut offset)?;
                    let addr = decode_ip_addr(&bytes, &mut offset)?;
                    DnsStamp::DnsPlain(DnsPlain { props, addr })
                }
                DnsStampType::AnonymizedDnsCryptRelay => decode_addr(&bytes, &mut offset, 443)?
                    .map(|addr| DnsStamp::AnonymizedDnsCryptRelay(AnonymizedDnsCryptRelay { addr }))
                    .ok_or(DecodeErr::MissingAddr)?,
            };
            if bytes.len() == offset {
                Ok(dns_stamp)
            } else {
                Err(DecodeErr::TooManyBytes)
            }
        } else {
            Err(DecodeErr::InvalidInput {
                cause: "sdns:// prefix not present".to_string(),
            })
        }
    }
}

impl str::FromStr for DnsStamp {
    type Err = DecodeErr;
    fn from_str(s: &str) -> DecodeResult<Self> {
        DnsStamp::decode(s)
    }
}
