//! This module contains all encode functions for the crate.
use crate::{
    Addr, AnonymizedDnsCryptRelay, DnsCrypt, DnsOverHttps, DnsOverTls, DnsPlain, DnsStamp,
    DnsStampType, EncodeError, EncodeResult, ObliviousDoHTarget, Props,
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
    match socket_addr {
        SocketAddr::V6(socket_addr_v6) => {
            if socket_addr_v6.scope_id() == 0 && socket_addr.port() == default_port {
                ip_addr_to_string(&socket_addr.ip())
            } else {
                socket_addr.to_string()
            }
        }
        SocketAddr::V4(socket_addr_v4) => {
            if socket_addr_v4.port() == default_port {
                ip_addr_to_string(&socket_addr.ip())
            } else {
                socket_addr_v4.to_string()
            }
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

/// Encode a `crate::DnsPlain` into a `std::vec::Vec<u8>` as `crate::DnsStampType::Plain`.
fn encode_dns_plain(buffer: &mut Vec<u8>, dns_plain: &DnsPlain) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::Plain);
    encode_props(buffer, &dns_plain.props);
    encode_ip_addr(buffer, &dns_plain.addr)?;
    Ok(())
}

/// Encode a `crate::DnsCrypt` into a `std::vec::Vec<u8>` as `crate::DnsStampType::DnsCrypt`.
fn encode_dns_crypt(buffer: &mut Vec<u8>, dns_crypt: &DnsCrypt) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::DnsCrypt);
    encode_props(buffer, &dns_crypt.props);
    encode_socket_addr(buffer, &dns_crypt.addr, 443)?;
    encode_pk(buffer, &dns_crypt.pk)?;
    encode_bytes(buffer, &dns_crypt.provider_name)?;
    Ok(())
}

/// Encode a `crate::DnsCrypt` into a `std::vec::Vec<u8>`.
fn encode_dns_over_https_data(
    buffer: &mut Vec<u8>,
    dns_over_https: &DnsOverHttps,
) -> EncodeResult<()> {
    encode_props(buffer, &dns_over_https.props);
    encode_option_addr(buffer, dns_over_https.addr.as_ref(), 443)?;
    encode_hashi(buffer, &dns_over_https.hashi)?;
    encode_bytes(buffer, &dns_over_https.hostname)?;
    encode_bytes(buffer, &dns_over_https.path)?;
    if !dns_over_https.bootstrap_ipi.is_empty() {
        encode_bootstrap_ipi(buffer, &dns_over_https.bootstrap_ipi)?;
    }
    Ok(())
}

/// Encode a `crate::DnsOverHttps` into a `std::vec::Vec<u8>`
/// as `crate::DnsStampType::DnsOverHttps`.
fn encode_dns_over_https(buffer: &mut Vec<u8>, dns_over_https: &DnsOverHttps) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::DnsOverHttps);
    encode_dns_over_https_data(buffer, dns_over_https)
}

/// Encode a `crate::DnsOverHttps` into a `std::vec::Vec<u8>`
/// as `crate::DnsStampType::ObliviousDoHRelay`.
fn encode_oblivious_doh_relay(
    buffer: &mut Vec<u8>,
    dns_over_https: &DnsOverHttps,
) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::ObliviousDoHRelay);
    encode_dns_over_https_data(buffer, dns_over_https)
}

/// Encode a `crate::DnsOverTls` into a `std::vec::Vec<u8>`.
fn encode_dns_over_tls_data(buffer: &mut Vec<u8>, dns_over_tls: &DnsOverTls) -> EncodeResult<()> {
    encode_props(buffer, &dns_over_tls.props);
    encode_option_addr(buffer, dns_over_tls.addr.as_ref(), 443)?;
    encode_hashi(buffer, &dns_over_tls.hashi)?;
    encode_bytes(buffer, &dns_over_tls.hostname)?;
    if !dns_over_tls.bootstrap_ipi.is_empty() {
        encode_bootstrap_ipi(buffer, &dns_over_tls.bootstrap_ipi)?;
    }
    Ok(())
}

/// Encode a `crate::DnsOverTls` into a `std::vec::Vec<u8>` as `crate::DnsStampType::DnsOverTls`.
fn encode_dns_over_tls(buffer: &mut Vec<u8>, dns_over_tls: &DnsOverTls) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::DnsOverTls);
    encode_dns_over_tls_data(buffer, dns_over_tls)?;
    Ok(())
}

/// Encode a `crate::DnsOverTls` into a `std::vec::Vec<u8>` as `crate::DnsStampType::DnsOverQuic`.
fn encode_dns_over_quic(buffer: &mut Vec<u8>, dns_over_tls: &DnsOverTls) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::DnsOverQuic);
    encode_dns_over_tls_data(buffer, dns_over_tls)?;
    Ok(())
}

/// Encode a `crate::ObliviousDoHTarget` into a `std::vec::Vec<u8>`
/// as `crate::DnsStampType::ObliviousDoHTarget`.
fn encode_oblivious_doh_target(
    buffer: &mut Vec<u8>,
    oblivious_doh_target: &ObliviousDoHTarget,
) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::ObliviousDoHTarget);
    encode_props(buffer, &oblivious_doh_target.props);
    encode_bytes(buffer, &oblivious_doh_target.hostname)?;
    encode_bytes(buffer, &oblivious_doh_target.path)?;
    Ok(())
}

/// Encode a `crate::AnonymizedDnsCryptRelay` into a `std::vec::Vec<u8>`
/// as `crate::DnsStampType::AnonymizedDnsCryptRelay`.
fn encode_anonymized_dns_crypt_relay(
    buffer: &mut Vec<u8>,
    anonymized_dns_crypt_relay: &AnonymizedDnsCryptRelay,
) -> EncodeResult<()> {
    encode_type(buffer, DnsStampType::AnonymizedDnsCryptRelay);
    encode_socket_addr(buffer, &anonymized_dns_crypt_relay.addr, 443)?;
    Ok(())
}

impl DnsStamp {
    /// Encode a `crate::DnsStamp` to a `std::string::String`.
    pub fn encode(&self) -> EncodeResult<String> {
        let mut buffer = Vec::new();
        match self {
            DnsStamp::DnsPlain(dns_plain) => encode_dns_plain(&mut buffer, dns_plain)?,
            DnsStamp::DnsCrypt(dns_crypt) => encode_dns_crypt(&mut buffer, dns_crypt)?,
            DnsStamp::DnsOverHttps(dns_over_https) => {
                encode_dns_over_https(&mut buffer, dns_over_https)?
            }
            DnsStamp::DnsOverTls(dns_over_tls) => encode_dns_over_tls(&mut buffer, dns_over_tls)?,
            DnsStamp::DnsOverQuic(dns_over_quic) => {
                encode_dns_over_quic(&mut buffer, dns_over_quic)?
            }
            DnsStamp::ObliviousDoHTarget(oblivious_doh_target) => {
                encode_oblivious_doh_target(&mut buffer, oblivious_doh_target)?
            }
            DnsStamp::AnonymizedDnsCryptRelay(anonymized_dns_crypt_relay) => {
                encode_anonymized_dns_crypt_relay(&mut buffer, anonymized_dns_crypt_relay)?;
            }
            DnsStamp::ObliviousDoHRelay(oblivious_doh_relay) => {
                encode_oblivious_doh_relay(&mut buffer, oblivious_doh_relay)?;
            }
        }

        Ok(encode_base64(&buffer))
    }
}
