//! Provides a library to encode and decode [DNS stamp].
//!
//! [DNS stamp]: https://dnscrypt.info/stamps-specifications
#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub,
    non_snake_case,
    non_upper_case_globals
)]
#![allow(clippy::cognitive_complexity)]
#![deny(broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
mod decode;
mod encode;
mod error;

pub use crate::error::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use bitflags::bitflags;
use std::{
    convert::TryFrom,
    io,
    net::{IpAddr, SocketAddr},
};

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
#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub enum Addr {
    /// a SocketAddr
    SocketAddr(SocketAddr),
    /// port number represented as a u16
    Port(u16),
}

/// This enum represent all DNS Stamp type.
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
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
    Plain = 0x00,
    /// See [Plain DNS stamps].
    ///
    /// [Plain DNS stamps]: https://dnscrypt.info/stamps-specifications#anonymized-dnscrypt-relay-stamps
    AnonymizedDnsCryptRelay = 0x81,
}

impl TryFrom<u8> for DnsStampType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(DnsStampType::DnsCrypt),
            0x02 => Ok(DnsStampType::DnsOverHttps),
            0x03 => Ok(DnsStampType::DnsOverTls),
            0x00 => Ok(DnsStampType::Plain),
            0x81 => Ok(DnsStampType::AnonymizedDnsCryptRelay),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns stamp type not found",
            )),
        }
    }
}

/// This enum represent a [DNS Stamp].
///
/// [DNS Stamp]: https://dnscrypt.info/stamps-specifications/
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsStamp {
    /// See [DNSCrypt stamps].
    ///
    /// [DNSCrypt stamps]: https://dnscrypt.info/stamps-specifications#dnscrypt-stamps
    DnsCrypt(DnsCrypt),
    /// See [DNS-over-HTTPS stamps].
    ///
    /// [DNS-over-HTTPS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-https-stamps
    DnsOverHttps(DnsOverHttps),
    /// See [DNS-over-TLS stamps].
    ///
    /// [DNS-over-TLS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-tls-stamps
    DnsOverTls(DnsOverTls),
    /// See [Plain DNS stamps].
    ///
    /// [Plain DNS stamps]: https://dnscrypt.info/stamps-specifications#plain-dns-stamps
    DnsPlain(DnsPlain),
    /// See [Plain DNS stamps].
    ///
    /// [Plain DNS stamps]: https://dnscrypt.info/stamps-specifications#anonymized-dnscrypt-relay-stamps
    AnonymizedDnsCryptRelay(AnonymizedDnsCryptRelay),
}

/// Dnscrypt configuration parsed from dnsstamp
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCrypt {
    /// server properties
    props: Props,
    /// addr is the IP address, as a string, with a port number if the server
    /// is not accessible over the standard port for the protocol (443).
    addr: SocketAddr,
    /// pk is the DNSCrypt provider’s Ed25519 public key, as 32 raw bytes.
    pk: [u8; 32],
    /// providerName is the DNSCrypt provider name.
    provider_name: String,
}

/// DoH configuration parsed from a dnsstamp
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOverHttps {
    /// server properties
    pub props: Props,
    /// addr is the IP address of the server. It can be an empty string,
    /// or just a port number, represented with a preceding colon (:443).
    /// In that case, the host name will be resolved to an IP address using another resolver.
    pub addr: Option<Addr>,
    /// hashi is the SHA256 digest of one of the TBS certificate found in the validation chain,
    /// typically the certificate used to sign the resolver’s certificate. Multiple hashes can
    /// be provided for seamless rotations.
    pub hashi: Vec<[u8; 32]>,
    /// hostname is the server host name which will also be used as a SNI name.
    /// If the host name contains characters outside the URL-permitted range,
    /// these characters should be sent as-is, without any extra encoding
    /// (neither URL-encoded nor punycode).
    pub hostname: String,
    /// path is the absolute URI path, such as /dns-query.
    pub path: String,
    /// bootstrap_ipi are IP addresses of recommended resolvers accessible over standard DNS
    /// in order to resolve hostname. This is optional, and clients can ignore this information.
    pub bootstrap_ipi: Vec<IpAddr>,
}

/// Dns over TLS configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOverTls {
    /// server properties
    pub props: Props,
    /// addr is the IP address of the server. It can be an empty string,
    /// or just a port number, represented with a preceding colon (:443).
    /// In that case, the host name will be resolved to an IP address using another resolver.
    pub addr: Option<Addr>,
    /// hashi is the SHA256 digest of one of the TBS certificate found in the validation chain,
    /// typically the certificate used to sign the resolver’s certificate. Multiple hashes can
    /// be provided for seamless rotations.
    pub hashi: Vec<[u8; 32]>,
    /// hostname is the server host name which will also be used as a SNI name.
    /// If the host name contains characters outside the URL-permitted range,
    /// these characters should be sent as-is, without any extra encoding
    /// (neither URL-encoded nor punycode).
    pub hostname: String,
    /// bootstrap_ipi are IP addresses of recommended resolvers accessible over standard DNS
    /// in order to resolve hostname. This is optional, and clients can ignore this information.
    pub bootstrap_ipi: Vec<IpAddr>,
}

/// Plain dns configuration parsed from a dnsstamp
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPlain {
    /// server properties
    pub props: Props,
    /// addr is the IP address of the server.
    /// IPv6 strings must be included in square brackets: `[fe80::6d6d:f72c:3ad:60b8]`.
    /// Scopes are permitted.
    pub addr: IpAddr,
}

/// Anonymized dnscrypt relay configuration parsed from a dnsstamp
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymizedDnsCryptRelay {
    /// 0x81 is the protocol identifier for a DNSCrypt relay.
    /// addr is the IP address and port, as a string.
    /// IPv6 strings must be included in square brackets: `[fe80::6d6d:f72c:3ad:60b8]:443`.
    pub addr: SocketAddr,
}

impl DnsOverHttps {
    /// get hostname for DOH config
    pub fn hostname(&self) -> String {
        hostname(self.addr, &self.hostname)
    }

    /// get hostname based on the bootstrap information
    #[cfg(feature = "resolve")]
    pub fn bootstrap_hostname(&self) -> io::Result<String> {
        bootstrap_hostname(self.addr, &self.hostname, &self.bootstrap_ipi)
    }
}

impl DnsOverTls {
    /// get hostname from config
    pub fn hostname(&self) -> String {
        hostname(self.addr, &self.hostname)
    }

    /// get hostname based on the bootstrap information
    #[cfg(feature = "resolve")]
    pub fn bootstrap_hostname(&self) -> io::Result<String> {
        bootstrap_hostname(self.addr, &self.hostname, &self.bootstrap_ipi)
    }
}

#[inline]
fn hostname(addr: Option<Addr>, host: &str) -> String {
    match addr {
        None => format!("{}:443", host),
        Some(Addr::Port(port)) => format!("{}:{}", host, port),
        Some(Addr::SocketAddr(addr)) => addr.to_string(),
    }
}

#[cfg(feature = "resolve")]
#[inline]
fn bootstrap_hostname(addr: Option<Addr>, host: &str, bootstrap: &[IpAddr]) -> io::Result<String> {
    use trust_dns_resolver::config::*;
    use trust_dns_resolver::Resolver;

    if !bootstrap.is_empty() {
        let mut config = ResolverConfig::new();
        for ip in bootstrap {
            let socket_addr = SocketAddr::new(*ip, 53);
            config.add_name_server(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
            });
        }

        let resolver = Resolver::new(config, ResolverOpts::default()).unwrap();

        let resp = resolver.lookup_ip(host)?;

        Ok(resp
            .iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "address not found"))?
            .to_string())
    } else {
        Ok(hostname(addr, host))
    }
}
