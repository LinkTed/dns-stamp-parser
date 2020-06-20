//! This module contains all encode functions for the crate.
use crate::{Addr, DnsStamp, DnsStampType, EncodeError, EncodeResult, Props};
use data_encoding::BASE64URL_NOPAD;
use num_traits::ToPrimitive;
use std::net::{IpAddr, SocketAddr};

/// Encode a `crate::DnsStampType` into a `std::vec::Vec<u8>`.
fn encode_type(buffer: &mut Vec<u8>, dns_stamp_type: DnsStampType) {
    buffer.push(dns_stamp_type.to_u8().unwrap());
}

/// Encode a `DnsStampType` into a `std::vec::Vec<u8>`.
fn encode_props(buffer: &mut Vec<u8>, props: &Props) {
    let bytes = props.bits().to_le_bytes();
    buffer.extend(bytes.iter());
}

/// Encode a `u8` slice into a `std::vec::Vec<u8>`.
fn encode_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) -> EncodeResult<()> {
    let len = bytes.len();
    if len <= std::u8::MAX as usize {
        buffer.push(len as u8);
        buffer.extend(bytes);
        Ok(())
    } else {
        Err(EncodeError::TooManyBytes)
    }
}

/// Encode a `&str` as utf-8 into a `std::vec::Vec<u8>`.
fn encode_string(buffer: &mut Vec<u8>, string: &str) -> EncodeResult<()> {
    encode_bytes(buffer, string.as_bytes())
}

/// Convert a `crate::IpAddr` to a `String`.
fn ip_addr_string(ip_addr: &IpAddr) -> String {
    let mut string = ip_addr.to_string();
    if ip_addr.is_ipv6() {
        string = format!("[{}]", string);
    }
    string
}

/// Encode a `std::net::SocketAddr` into a `std::vec::Vec<u8>`.
/// If the `socket_addr` hat the same `default_port`
/// then encode only the `std::net::IpAddr`.
fn encode_socket_addr(
    buffer: &mut Vec<u8>,
    socket_addr: &SocketAddr,
    default_port: u16,
) -> EncodeResult<()> {
    let string = if socket_addr.port() == default_port {
        let ip_addr = socket_addr.ip();
        ip_addr_string(&ip_addr)
    } else {
        socket_addr.to_string()
    };

    encode_string(buffer, &string)
}

/// Encode a `crate::Addr` into a `std::vec::Vec<u8>`.
/// If the `addr` is `None` then encode only the `default_port`.
fn encode_addr(buffer: &mut Vec<u8>, addr: &Option<Addr>, default_port: u16) -> EncodeResult<()> {
    if let Some(addr) = addr {
        match addr {
            Addr::SocketAddr(socket_addr) => encode_socket_addr(buffer, socket_addr, default_port),
            Addr::Port(port) => {
                if *port == default_port {
                    encode_string(buffer, "")
                } else {
                    let string = format!(":{}", *port);
                    encode_string(buffer, &string)
                }
            }
        }
    } else {
        encode_string(buffer, "")
    }
}

/// Encode a `std::net::IpAddr` into a `std::vec::Vec<u8>`.
fn encode_ip_addr(buffer: &mut Vec<u8>, ip_addr: &IpAddr) -> EncodeResult<()> {
    let string = ip_addr_string(ip_addr);

    encode_string(buffer, &string)
}

/// Encode a `[u8;32]` into a `std::vec::Vec<u8>`.
fn encode_pk(buffer: &mut Vec<u8>, pk: &[u8; 32]) -> EncodeResult<()> {
    encode_bytes(buffer, &pk[..])
}

/// Encode a `std::vec::Vec<u8>` into a `std::vec::Vec<u8>`.
/// See [`VLP()`].
///
/// [`VLP()`]:  https://dnscrypt.info/stamps-specifications#common-definitions
fn encode_vlp(buffer: &mut Vec<u8>, vlp: &[&[u8]]) -> EncodeResult<()> {
    if vlp.is_empty() {
        encode_bytes(buffer, &[])
    } else {
        let len = vlp.len();
        if let Some(array) = vlp.get(..(len - 1)) {
            for bytes in array {
                let len = bytes.len();
                if len <= 0x80 {
                    buffer.push((len ^ 0x80) as u8);
                    buffer.extend(*bytes);
                } else {
                    return Err(EncodeError::TooManyBytes);
                }
            }
        }
        if let Some(bytes) = vlp.get(len - 1) {
            encode_bytes(buffer, *bytes)
        } else {
            Err(EncodeError::EmptyArray)
        }
    }
}

/// Encode a `std::vec::Vec<[u8;32]>` into a `std::vec::Vec<u8>`.
fn encode_hashi(buffer: &mut Vec<u8>, hashi: &[[u8; 32]]) -> EncodeResult<()> {
    let mut vlp = Vec::new();
    for hash in hashi {
        vlp.push(&hash[..]);
    }
    encode_vlp(buffer, &vlp)
}

/// Encode a `std::vec::Vec<std::net::IpAddr>` into a `std::vec::Vec<u8>`.
fn encode_bootstrap_ipi(buffer: &mut Vec<u8>, bootstrap_ipi: &[IpAddr]) -> EncodeResult<()> {
    let mut bootstrap_ipi_string = Vec::new();
    for ip_addr in bootstrap_ipi {
        bootstrap_ipi_string.push(ip_addr.to_string());
    }

    let mut vlp = Vec::new();
    for string in &bootstrap_ipi_string {
        vlp.push(string.as_bytes());
    }
    encode_vlp(buffer, &vlp)
}

impl DnsStamp {
    /// Encode a `crate::DnsStamp` to a `std::string::String`.
    pub fn encode(&self) -> EncodeResult<String> {
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
                if !bootstrap_ipi.is_empty() {
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
        Ok(format!("sdns://{}", BASE64URL_NOPAD.encode(&buffer)))
    }
}
