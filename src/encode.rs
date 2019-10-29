use std::net::{SocketAddr, IpAddr};
use num_traits::ToPrimitive;
use crate::{DnsStampType, Props, DnsStampEncodeError, Addr};


pub fn encode_type(buffer: &mut Vec<u8>, dns_stamp_type: DnsStampType) {
    buffer.push(dns_stamp_type.to_u8().unwrap());
}

pub fn encode_props(buffer: &mut Vec<u8>, props: &Props) {
    let bytes = props.bits().to_le_bytes();
    buffer.extend(bytes.iter());
}

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

pub fn encode_string(buffer: &mut Vec<u8>, string: &str) -> Result<(), DnsStampEncodeError> {
    encode_bytes(buffer, string.as_bytes())
}

fn ip_addr_string(ip_addr: &IpAddr) -> String {
    let mut string = ip_addr.to_string();
    if ip_addr.is_ipv6() {
        string = format!("[{}]", string);
    }
    string
}

pub fn encode_socket_addr(buffer: &mut Vec<u8>, socket_addr: &SocketAddr, default_port: u16) -> Result<(), DnsStampEncodeError> {
    let string = if socket_addr.port() == default_port {
        let ip_addr = socket_addr.ip();
        ip_addr_string(&ip_addr)
    } else {
        socket_addr.to_string()
    };

    encode_string(buffer, &string)
}

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

pub fn encode_ip_addr(buffer: &mut Vec<u8>, ip_addr: &IpAddr) -> Result<(), DnsStampEncodeError> {
    let string = ip_addr_string(ip_addr);

    encode_string(buffer, &string)
}

pub fn encode_pk(buffer: &mut Vec<u8>, pk: &[u8;32]) -> Result<(), DnsStampEncodeError> {
    encode_bytes(buffer, &pk[..])
}

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

pub fn encode_hashi(buffer: &mut Vec<u8>, hashi: &Vec<[u8;32]>) -> Result<(), DnsStampEncodeError> {
    let mut vlp = Vec::new();
    for hash in hashi {
        vlp.push(&hash[..]);
    }
    encode_vlp(buffer, &vlp)
}

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
