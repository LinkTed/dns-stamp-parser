//! Provides a library to encode and decode [DNS stamp].
//!
//! [DNS stamp]: https://dnscrypt.info/stamps-specifications
#[macro_use(lazy_static)]
extern crate lazy_static;
#[macro_use(bitflags)]
extern crate bitflags;
#[macro_use(FromPrimitive, ToPrimitive)]
extern crate num_derive;
use std::str::Utf8Error;
use std::num::ParseIntError;
use std::net::{SocketAddr, IpAddr, AddrParseError};
use regex::Regex;
use data_encoding::{BASE64URL_NOPAD, DecodeError};


mod decode;
use crate::decode::{decode_socket_addr, decode_str, decode_addr, decode_hashi, decode_bootstrap_ipi, decode_ip_addr, decode_pk, decode_type, decode_props};
mod encode;
use crate::encode::{encode_type, encode_props, encode_socket_addr, encode_addr, encode_ip_addr, encode_pk, encode_string, encode_hashi, encode_bootstrap_ipi};


/// This enum represent all decode errors.
#[derive(Debug)]
pub enum DnsStampDecodeError {
    /// This error occurs if the base64 string could not be decoded.
    Base64Error(DecodeError),
    /// This error occurs if the array does not have.
    TooShort,
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
    Regex
}

/// This enum represent all encode errors.
#[derive(Debug)]
pub enum DnsStampEncodeError {
    /// This error occurs if not all bytes of the array was parsed.
    TooMuch,
    /// This error occurs if the array is empty.
    EmptyArray,
}

bitflags! {
    /// Represent the [`props`].
    ///
    /// [`props`]: https://dnscrypt.info/stamps-specifications#dnscrypt-stamps
    pub struct Props: u64 {
        /// If this flag is present then the server supports [DNSSEC].
        ///
        /// [DNSSEC]: https://tools.ietf.org/html/rfc3833
        const DNSSEC = 0x01;
        /// If this flag is present then the server does not keep logs
        const NO_LOGS = 0x02;
        /// If this flag is present then the server does not intentionally block domains
        const NO_FILTER = 0x04;
    }
}

/// This enum represent an address.
/// An address in DNS Stamp can have port or a IP-Address and port.
#[derive(Debug, PartialEq, Eq)]
pub enum Addr {
    SocketAddr(SocketAddr),
    Port(u16)
}

/// This enum represent all DNS Stamp type.
#[derive(Debug, Clone, FromPrimitive, ToPrimitive)]
pub enum DnsStampType {
    /// See [DNSCrypt stamps].
    ///
    /// [DNSCrypt stamps]: https://dnscrypt.info/stamps-specifications#dnscrypt-stamps
    DnsCrypt = 0x01,
    /// See [DNS-over-HTTPS stamps].
    ///
    /// [DNS-over-HTTPS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-https-stamps
    DnsOverHttps = 0x02,
    /// See [DNS-over-TLS stamps].
    ///
    /// [DNS-over-TLS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-tls-stamps
    DnsOverTls = 0x03,
    /// See [Plain DNS stamps].
    ///
    /// [Plain DNS stamps]: https://dnscrypt.info/stamps-specifications#plain-dns-stamps
    DnsPlain = 0x00
}

/// This enum represent a [DNS Stamp].
///
/// [DNS Stamp]: https://dnscrypt.info/stamps-specifications/
#[derive(Debug, PartialEq, Eq)]
pub enum DnsStamp {
    /// See [DNSCrypt stamps].
    ///
    /// [DNSCrypt stamps]: https://dnscrypt.info/stamps-specifications#dnscrypt-stamps
    DnsCrypt(Props, SocketAddr, [u8;32], String),
    /// See [DNS-over-HTTPS stamps].
    ///
    /// [DNS-over-HTTPS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-https-stamps
    DnsOverHttps(Props, Option<Addr>, Vec<[u8;32]>, String, String, Vec<IpAddr>),
    /// See [DNS-over-TLS stamps].
    ///
    /// [DNS-over-TLS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-tls-stamps
    DnsOverTls(Props, Option<Addr>, Vec<[u8;32]>, String, Option<IpAddr>),
    /// See [Plain DNS stamps].
    ///
    /// [Plain DNS stamps]: https://dnscrypt.info/stamps-specifications#plain-dns-stamps
    DnsPlain(Props, IpAddr)
}

impl DnsStamp {
    /// Decode a `crate::DnsStamp` from a `&str`.
    pub fn decode(stamp: &str) -> Result<DnsStamp, DnsStampDecodeError> {
        lazy_static! {
            static ref DNS_STAMP_REGEX: Regex = Regex::new("^sdns://([A-Za-z0-9_-]+)$").unwrap();
        }

        if let Some(c) = DNS_STAMP_REGEX.captures(&stamp) {
            // Get the decoded base64 part.
            if let Some(base64) = c.get(1) {
                return match BASE64URL_NOPAD.decode(base64.as_str().as_bytes()) {
                    Ok(result) => {
                        let mut offset: usize = 0;
                        let type_ = decode_type(&result, &mut offset)?;
                        let props = decode_props(&result, &mut offset)?;
                        match type_ {
                            DnsStampType::DnsCrypt => {
                                let addr = decode_socket_addr(&result, &mut offset, 443)?;
                                let pk = decode_pk(&result, &mut offset)?;
                                let provider_name = decode_str(&result, &mut offset)?.to_string();
                                Ok(DnsStamp::DnsCrypt(props, addr, pk, provider_name))
                            },
                            DnsStampType::DnsOverHttps => {
                                let addr = decode_addr(&result, &mut offset, 443)?;
                                let hashi = decode_hashi(&result, &mut offset)?;
                                let hostname = decode_str(&result, &mut offset)?.to_string();
                                let path = decode_str(&result, &mut offset)?.to_string();
                                let bootstrap_ipi = if result.len() == offset {
                                    Vec::new()
                                } else {
                                    decode_bootstrap_ipi(&result, &mut offset)?
                                };
                                Ok(DnsStamp::DnsOverHttps(props, addr, hashi, hostname, path, bootstrap_ipi))
                            },
                            DnsStampType::DnsOverTls => {
                                let addr = decode_addr(&result, &mut offset, 443)?;
                                let hashi = decode_hashi(&result, &mut offset)?;
                                let hostname = decode_str(&result, &mut offset)?.to_string();
                                let bootstrap_ipi = if result.len() == offset {
                                    None
                                } else {
                                    Some(decode_ip_addr(&result, &mut offset)?)
                                };
                                Ok(DnsStamp::DnsOverTls(props, addr, hashi, hostname, bootstrap_ipi))
                            },
                            DnsStampType::DnsPlain => {
                                let addr = decode_ip_addr(&result, &mut offset)?;
                                Ok(DnsStamp::DnsPlain(props, addr))
                            }
                        }
                    }
                    Err(e) => {
                        Err(DnsStampDecodeError::Base64Error(e))
                    }
                };
            }
        }

        Err(DnsStampDecodeError::Regex)
    }

    /// Encode a `crate::DnsStamp` to a `std::string::String`.
    pub fn encode(&self) -> Result<String, DnsStampEncodeError> {
        let mut buffer = Vec::new();
        match self {
            DnsStamp::DnsCrypt(props, addr, pk, provider_name) => {
                encode_type(&mut buffer, DnsStampType::DnsCrypt);
                encode_props(&mut buffer, props);
                encode_socket_addr(&mut buffer, addr, 443)?;
                encode_pk(&mut buffer, pk)?;
                encode_string(&mut buffer, provider_name)?;
            }
            DnsStamp::DnsOverHttps(props, addr, hashi, hostname, path, bootstrap_ipi) => {
                encode_type(&mut buffer, DnsStampType::DnsOverHttps);
                encode_props(&mut buffer, props);
                encode_addr(&mut buffer, addr, 443)?;
                encode_hashi(&mut buffer, hashi)?;
                encode_string(&mut buffer, hostname)?;
                encode_string(&mut buffer, path)?;
                if bootstrap_ipi.len() != 0 {
                    encode_bootstrap_ipi(&mut buffer, bootstrap_ipi)?;
                }
            }
            DnsStamp::DnsOverTls(props, addr, hashi, hostname, bootstrap_ipi) => {
                encode_type(&mut buffer, DnsStampType::DnsOverTls);
                encode_props(&mut buffer, props);
                encode_addr(&mut buffer, addr, 443)?;
                encode_hashi(&mut buffer, hashi)?;
                encode_string(&mut buffer, hostname)?;
                if let Some(bootstrap_ipi) = bootstrap_ipi {
                    encode_ip_addr(&mut buffer, bootstrap_ipi)?;
                }
            }
            DnsStamp::DnsPlain(props, addr) => {
                encode_type(&mut buffer, DnsStampType::DnsPlain);
                encode_props(&mut buffer, props);
                encode_ip_addr(&mut buffer, addr)?;
            }
        }
        Ok(format!("sdns://{}",  BASE64URL_NOPAD.encode(&buffer)))
    }
}
