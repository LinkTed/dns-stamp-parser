//! This module contains all encode functions for the crate.
use crate::{
    Addr, AnonymizedDnsCryptRelay, DnsCrypt, DnsOverHttps, DnsOverTls, DnsPlain, DnsStamp,
    DnsStampType, EncodeError, EncodeResult, Props,
};
use base64::{encode_config, URL_SAFE_NO_PAD};
use std::net::{IpAddr, SocketAddr};

/// Encode a `crate::DnsStampType` into a `std::vec::Vec<u8>`.
fn encode_type(buffer: &mut Vec<u8>, dns_stamp_type: DnsStampType) {
    buffer.push(dns_stamp_type as u8);
}

/// Encode a `DnsStampType` into a `std::vec::Vec<u8>`.
fn encode_props(buffer: &mut Vec<u8>, props: &Props) {
    let bytes = props.bits().to_le_bytes();
    buffer.extend(bytes.iter());
}

/// Encode a `u8` slice into a `std::vec::Vec<u8>`.
fn encode_bytes(buffer: &mut Vec<u8>, bytes: impl AsRef<[u8]>) -> EncodeResult<()> {
    let bytes = bytes.as_ref();
    let len = bytes.len();
    if len <= std::u8::MAX as usize {
        buffer.push(len as u8);
        buffer.extend(bytes);
        Ok(())
    } else {
        Err(EncodeError::TooManyBytes)
    }
}

/// Convert a `std::net::IpAddr` to a `String`.
fn ip_addr_to_string(ip_addr: &IpAddr) -> String {
    let mut string = ip_addr.to_string();
    if ip_addr.is_ipv6() {
        string = format!("[{}]", string);
    }
    string
}

/// Convert a `std::net::SocketAddr` to a `String`.
fn socket_addr_to_string(socket_addr: &SocketAddr, default_port: u16) -> String {
    if let SocketAddr::V6(socket_addr_v6) = socket_addr {
        if socket_addr_v6.scope_id() == 0 && socket_addr.port() == default_port {
            ip_addr_to_string(&socket_addr.ip())
        } else {
            socket_addr.to_string()
        }
    } else {
        if socket_addr.port() == default_port {
            ip_addr_to_string(&socket_addr.ip())
        } else {
            socket_addr.to_string()
        }
    }
}

/// Encode a `std::net::SocketAddr` into a `std::vec::Vec<u8>`.
/// If the `socket_addr` hat the same `default_port`
/// then encode only the `std::net::IpAddr`.
fn encode_socket_addr(
    buffer: &mut Vec<u8>,
    socket_addr: &SocketAddr,
    default_port: u16,
) -> EncodeResult<()> {
    let string = socket_addr_to_string(socket_addr, default_port);
    encode_bytes(buffer, &string)
}

/// Convert a `crate::Addr` to a `String`.
fn addr_to_string(addr: &Addr, default_port: u16) -> String {
    match addr {
        Addr::SocketAddr(socket_addr) => socket_addr_to_string(socket_addr, default_port),
        Addr::Port(port) => format!(":{}", port),
    }
}

/// Convert a `std::option::Option<crate::Addr>` to a `String`.
fn option_addr_to_string(addr: Option<&Addr>, default_port: u16) -> String {
    match addr {
        Some(addr) => addr_to_string(addr, default_port),
        None => "".to_string(),
    }
}

/// Encode a `crate::Addr` into a `std::vec::Vec<u8>`.
/// If the `addr` is `None` then encode only the `default_port`.
fn encode_option_addr(
    buffer: &mut Vec<u8>,
    addr: Option<&Addr>,
    default_port: u16,
) -> EncodeResult<()> {
    let string = option_addr_to_string(addr, default_port);
    encode_bytes(buffer, string)
}

/// Encode a `std::net::IpAddr` into a `std::vec::Vec<u8>`.
fn encode_ip_addr(buffer: &mut Vec<u8>, ip_addr: &IpAddr) -> EncodeResult<()> {
    let string = ip_addr_to_string(ip_addr);
    encode_bytes(buffer, &string)
}

/// Encode a `[u8;32]` into a `std::vec::Vec<u8>`.
fn encode_pk(buffer: &mut Vec<u8>, pk: &[u8; 32]) -> EncodeResult<()> {
    encode_bytes(buffer, &pk[..])
}

/// Encode a `std::vec::Vec<u8>` into a `std::vec::Vec<u8>`.
/// See [`VLP()`].
///
/// [`VLP()`]:  https://dnscrypt.info/stamps-specifications#common-definitions
fn encode_vlp<T: AsRef<[u8]>>(buffer: &mut Vec<u8>, vlp: &[T]) -> EncodeResult<()> {
    if vlp.is_empty() {
        encode_bytes(buffer, &[])
    } else {
        let len = vlp.len();
        if let Some(array) = vlp.get(..(len - 1)) {
            for bytes in array {
                let bytes = bytes.as_ref();
                let len = bytes.len();
                if len <= 0x80 {
                    buffer.push((len ^ 0x80) as u8);
                    buffer.extend(bytes);
                } else {
                    return Err(EncodeError::TooManyBytes);
                }
            }
        }
        if let Some(bytes) = vlp.get(len - 1) {
            encode_bytes(buffer, bytes)
        } else {
            Err(EncodeError::EmptyArray)
        }
    }
}

/// Encode a `std::vec::Vec<[u8;32]>` into a `std::vec::Vec<u8>`.
fn encode_hashi(buffer: &mut Vec<u8>, hashi: &[[u8; 32]]) -> EncodeResult<()> {
    encode_vlp(buffer, hashi)
}

/// Encode a `std::vec::Vec<std::net::IpAddr>` into a `std::vec::Vec<u8>`.
fn encode_bootstrap_ipi(buffer: &mut Vec<u8>, bootstrap_ipi: &[IpAddr]) -> EncodeResult<()> {
    encode_vlp(
        buffer,
        &bootstrap_ipi
            .iter()
            .map(|ip| ip_addr_to_string(ip))
            .collect::<Vec<_>>(),
    )
}

/// Encode `[u8]` slice with Base64 and prepand `"sdns://"`.
fn encode_base64(buffer: &[u8]) -> String {
    format!("sdns://{}", encode_config(buffer, URL_SAFE_NO_PAD))
}

impl DnsStamp {
    /// Encode a `crate::DnsStamp` to a `std::string::String`.
    pub fn encode(&self) -> EncodeResult<String> {
        let mut buffer = Vec::new();
        match self {
            DnsStamp::DnsCrypt(DnsCrypt {
                props,
                addr,
                pk,
                provider_name,
            }) => {
                encode_type(&mut buffer, DnsStampType::DnsCrypt);
                encode_props(&mut buffer, props);
                encode_socket_addr(&mut buffer, addr, 443)?;
                encode_pk(&mut buffer, pk)?;
                encode_bytes(&mut buffer, provider_name)?;
            }
            DnsStamp::DnsOverHttps(DnsOverHttps {
                props,
                addr,
                hashi,
                hostname,
                path,
                bootstrap_ipi,
            }) => {
                encode_type(&mut buffer, DnsStampType::DnsOverHttps);
                encode_props(&mut buffer, props);
                encode_option_addr(&mut buffer, addr.as_ref(), 443)?;
                encode_hashi(&mut buffer, hashi)?;
                encode_bytes(&mut buffer, hostname)?;
                encode_bytes(&mut buffer, path)?;
                if !bootstrap_ipi.is_empty() {
                    encode_bootstrap_ipi(&mut buffer, bootstrap_ipi)?;
                }
            }
            DnsStamp::DnsOverTls(DnsOverTls {
                props,
                addr,
                hashi,
                hostname,
                bootstrap_ipi,
            }) => {
                encode_type(&mut buffer, DnsStampType::DnsOverTls);
                encode_props(&mut buffer, props);
                encode_option_addr(&mut buffer, addr.as_ref(), 443)?;
                encode_hashi(&mut buffer, hashi)?;
                encode_bytes(&mut buffer, hostname)?;
                if !bootstrap_ipi.is_empty() {
                    encode_bootstrap_ipi(&mut buffer, bootstrap_ipi)?;
                }
            }
            DnsStamp::DnsPlain(DnsPlain { props, addr }) => {
                encode_type(&mut buffer, DnsStampType::Plain);
                encode_props(&mut buffer, props);
                encode_ip_addr(&mut buffer, addr)?;
            }
            DnsStamp::AnonymizedDnsCryptRelay(AnonymizedDnsCryptRelay { addr }) => {
                encode_type(&mut buffer, DnsStampType::AnonymizedDnsCryptRelay);
                encode_socket_addr(&mut buffer, addr, 443)?;
            }
        }

        Ok(encode_base64(&buffer))
    }
}
