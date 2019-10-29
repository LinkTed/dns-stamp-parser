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


#[derive(Debug)]
pub enum DnsStampDecodeError {
    DecodeError(DecodeError),
    TooShort,
    UnknownType,
    Utf8Error(Utf8Error),
    AddrParseError(AddrParseError),
    Len,
    ParseIntError(ParseIntError),
    Regex
}

#[derive(Debug)]
pub enum DnsStampEncodeError {
    TooMuch,
    EmptyArray,
}

bitflags! {
    pub struct Props: u64 {
        const DNSSEC = 0x01;
        const NO_LOGS = 0x02;
        const NO_FILTER = 0x04;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Addr {
    SocketAddr(SocketAddr),
    Port(u16)
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive)]
pub enum DnsStampType {
    DnsCrypt = 0x01,
    DnsOverHttps = 0x02,
    DnsOverTls = 0x03,
    DnsPlain = 0x00
}

#[derive(Debug, PartialEq, Eq)]
pub enum DnsStamp {
    DnsCrypt(Props, SocketAddr, [u8;32], String),
    DnsOverHttps(Props, Option<Addr>, Vec<[u8;32]>, String, String, Vec<IpAddr>),
    DnsOverTls(Props, Option<Addr>, Vec<[u8;32]>, String, Option<IpAddr>),
    DnsPlain(Props, IpAddr)
}

impl DnsStamp {
    pub fn decode(stamp: &str) -> Result<DnsStamp, DnsStampDecodeError> {
        lazy_static! {
            static ref DNS_STAMP_REGEX: Regex = Regex::new("^sdns://([A-Za-z0-9_-]+)$").unwrap();
        }

        if let Some(c) = DNS_STAMP_REGEX.captures(&stamp) {
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
                        Err(DnsStampDecodeError::DecodeError(e))
                    }
                };
            }
        }

        Err(DnsStampDecodeError::Regex)
    }

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
