//! This module contains all encode functions for the crate.
use std::net::{SocketAddr, IpAddr};
use num_traits::ToPrimitive;
use crate::{DnsStampType, Props, DnsStampEncodeError, Addr};


/// Encode a `crate::DnsStampType` into a `std::vec::Vec<u8>`.
pub fn encode_type(buffer: &mut Vec<u8>, dns_stamp_type: DnsStampType) {
    buffer.push(dns_stamp_type.to_u8().unwrap());
}

/// Encode a `DnsStampType` into a `std::vec::Vec<u8>`.
pub fn encode_props(buffer: &mut Vec<u8>, props: &Props) {
    let bytes = props.bits().to_le_bytes();
    buffer.extend(bytes.iter());
}

/// Encode a `u8` slice into a `std::vec::Vec<u8>`.
fn encode_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) ->  Result<(), DnsStampEncodeError> {
    let len = bytes.len();
    if len <= std::u8::MAX as usize {
        buffer.push(len as u8);
        buffer.extend(bytes);
        Ok(())
    } else {
        Err(DnsStampEncodeError::TooMuch)
    }
}

/// Encode a `&str` as utf-8 into a `std::vec::Vec<u8>`.
pub fn encode_string(buffer: &mut Vec<u8>, string: &str) -> Result<(), DnsStampEncodeError> {
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
pub fn encode_socket_addr(buffer: &mut Vec<u8>, socket_addr: &SocketAddr, default_port: u16) -> Result<(), DnsStampEncodeError> {
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
pub fn encode_addr(buffer: &mut Vec<u8>, addr: &Option<Addr>, default_port: u16) -> Result<(), DnsStampEncodeError> {
    match addr {
        Some(addr) => {
            match addr {
                Addr::SocketAddr(socket_addr) => {
                    encode_socket_addr(buffer, socket_addr, default_port)
                }
                Addr::Port(port) => {
                    if *port == default_port {
                        encode_string(buffer, "")
                    } else {
                        let string = format!(":{}", *port);
                        encode_string(buffer, &string)
                    }
                }
            }
        }
        None => {
            encode_string(buffer, "")
        }
    }
}

/// Encode a `std::net::IpAddr` into a `std::vec::Vec<u8>`.
pub fn encode_ip_addr(buffer: &mut Vec<u8>, ip_addr: &IpAddr) -> Result<(), DnsStampEncodeError> {
    let string = ip_addr_string(ip_addr);

    encode_string(buffer, &string)
}

/// Encode a `[u8;32]` into a `std::vec::Vec<u8>`.
pub fn encode_pk(buffer: &mut Vec<u8>, pk: &[u8;32]) -> Result<(), DnsStampEncodeError> {
    encode_bytes(buffer, &pk[..])
}

/// Encode a `std::vec::Vec<u8>` into a `std::vec::Vec<u8>`.
/// See [`VLP()`].
///
/// [`VLP()`]:  https://dnscrypt.info/stamps-specifications#common-definitions
fn encode_vlp(buffer: &mut Vec<u8>, vlp: &Vec<&[u8]>) -> Result<(), DnsStampEncodeError> {
    let len = vlp.len();
    if len == 0 {
        return encode_bytes(buffer, &[])
    }
    if let Some(array) = vlp.get(..(len - 1)) {
        for bytes in array {
            let len = bytes.len();
            if len <= 0x80 {
                buffer.push((len ^ 0x80) as u8);
                buffer.extend(*bytes);
            } else {
                return Err(DnsStampEncodeError::TooMuch)
            }
        }
    }
    match vlp.get(len - 1) {
        Some(bytes) => {
            encode_bytes(buffer, *bytes)
        }
        None => {
            Err(DnsStampEncodeError::EmptyArray)
        }
    }
}

/// Encode a `std::vec::Vec<[u8;32]>` into a `std::vec::Vec<u8>`.
pub fn encode_hashi(buffer: &mut Vec<u8>, hashi: &Vec<[u8;32]>) -> Result<(), DnsStampEncodeError> {
    let mut vlp = Vec::new();
    for hash in hashi {
        vlp.push(&hash[..]);
    }
    encode_vlp(buffer, &vlp)
}

/// Encode a `std::vec::Vec<std::net::IpAddr>` into a `std::vec::Vec<u8>`.
pub fn encode_bootstrap_ipi(buffer: &mut Vec<u8>, bootstrap_ipi: &Vec<IpAddr>) -> Result<(), DnsStampEncodeError> {
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
