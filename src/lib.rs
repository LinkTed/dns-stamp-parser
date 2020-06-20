//! Provides a library to encode and decode [DNS stamp].
//!
//! [DNS stamp]: https://dnscrypt.info/stamps-specifications
#[macro_use(lazy_static)]
extern crate lazy_static;
#[macro_use(bitflags)]
extern crate bitflags;
#[macro_use(FromPrimitive, ToPrimitive)]
extern crate num_derive;

mod decode;
mod encode;
mod error;

pub use crate::error::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use std::net::{IpAddr, SocketAddr};

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
    Port(u16),
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
    DnsPlain = 0x00,
}

/// This enum represent a [DNS Stamp].
///
/// [DNS Stamp]: https://dnscrypt.info/stamps-specifications/
#[derive(Debug, PartialEq, Eq)]
pub enum DnsStamp {
    /// See [DNSCrypt stamps].
    ///
    /// [DNSCrypt stamps]: https://dnscrypt.info/stamps-specifications#dnscrypt-stamps
    DnsCrypt(Props, SocketAddr, [u8; 32], String),
    /// See [DNS-over-HTTPS stamps].
    ///
    /// [DNS-over-HTTPS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-https-stamps
    DnsOverHttps(
        Props,
        Option<Addr>,
        Vec<[u8; 32]>,
        String,
        String,
        Vec<IpAddr>,
    ),
    /// See [DNS-over-TLS stamps].
    ///
    /// [DNS-over-TLS stamps]: https://dnscrypt.info/stamps-specifications#dns-over-tls-stamps
    DnsOverTls(Props, Option<Addr>, Vec<[u8; 32]>, String, Option<IpAddr>),
    /// See [Plain DNS stamps].
    ///
    /// [Plain DNS stamps]: https://dnscrypt.info/stamps-specifications#plain-dns-stamps
    DnsPlain(Props, IpAddr),
}
