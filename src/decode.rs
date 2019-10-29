use std::mem::size_of;
use std::convert::TryInto;
use std::net::{SocketAddr, IpAddr};
use regex::Regex;
use num_traits::FromPrimitive;
use crate::{DnsStampDecodeError, Addr, DnsStampType, Props};


fn decode_u8(buf: &[u8], offset: &mut usize) -> Result<u8, DnsStampDecodeError> {
    let start = *offset;
    *offset += size_of::<u8>();

    if let Some(buf) = buf.get(start..*offset) {
        Ok(buf[0])
    } else {
        Err(DnsStampDecodeError::TooShort)
    }
}

fn decode_uint64(buf: &[u8], offset: &mut usize) -> Result<u64, DnsStampDecodeError> {
    let start = *offset;
    *offset += size_of::<u64>();

    if let Some(buf) = buf.get(start..*offset) {
        Ok(u64::from_le_bytes(buf.try_into().unwrap()))
    } else {
        Err(DnsStampDecodeError::TooShort)
    }
}

fn decode_lp<'a>(buf: &'a [u8], offset: &mut usize) -> Result<&'a [u8], DnsStampDecodeError> {
    let len = decode_u8(buf, offset)?;
    let start = *offset;
    *offset += len as usize;

    if let Some(buf) = buf.get(start..*offset) {
        Ok(buf)
    } else {
        Err(DnsStampDecodeError::TooShort)
    }
}

fn u8_array_to_str(bytes: &[u8]) -> Result<&str, DnsStampDecodeError> {
    match std::str::from_utf8(bytes) {
        Ok(string) => {
            Ok(string)
        }
        Err(e) => {
            Err(DnsStampDecodeError::Utf8Error(e))
        }
    }
}

pub fn decode_str<'a>(buf: &'a [u8], offset: &mut usize) -> Result<&'a str, DnsStampDecodeError> {
    let bytes = decode_lp(buf, offset)?;

    u8_array_to_str(bytes)
}

fn str_to_ip_addr(string: &str) -> Result<IpAddr, DnsStampDecodeError> {
    match string.parse() {
        Ok(result) => {
            Ok(result)
        },
        Err(e) => {
            Err(DnsStampDecodeError::AddrParseError(e))
        }
    }
}

pub fn decode_ip_addr(buf: &[u8], offset: &mut usize) -> Result<IpAddr, DnsStampDecodeError> {
    let string = decode_str(buf, offset)?;

    str_to_ip_addr(string)
}

fn str_to_socket_addr(string: &str, default_port: u16) -> Result<SocketAddr, DnsStampDecodeError> {
    match string.parse() {
        Ok(result) => {
            Ok(result)
        },
        Err(e) => {
            if let Ok(result) = format!("{}:{}", string, default_port).parse() {
                return Ok(result)
            }
            Err(DnsStampDecodeError::AddrParseError(e))
        }
    }
}

pub fn decode_socket_addr(buf: &[u8], offset: &mut usize, default_port: u16) -> Result<SocketAddr, DnsStampDecodeError> {
    let string = decode_str(buf, offset)?;

    str_to_socket_addr(string, default_port)
}

pub fn decode_addr(buf: &[u8], offset: &mut usize, default_port: u16) -> Result<Option<Addr>, DnsStampDecodeError> {
    let string = decode_str(buf, offset)?;
    if string == "" {
        return Ok(None)
    }

    lazy_static! {
        static ref PORT_REGEX: Regex = Regex::new("^:(\\d+)$").unwrap();
    }

    if let Some(c) = PORT_REGEX.captures(&string) {
        if let Some(port) = c.get(1) {
            match port.as_str().parse() {
                Ok(port) => {
                    return Ok(Some(Addr::Port(port)))
                }
                Err(e) => {
                    return Err(DnsStampDecodeError::ParseIntError(e))
                }
            }
        }
    }

    let socket_addr = str_to_socket_addr(string, default_port)?;
    Ok(Some(Addr::SocketAddr(socket_addr)))
}

fn decode_vlp<'a>(buf: &'a [u8], offset: &mut usize) -> Result<Vec<&'a [u8]>, DnsStampDecodeError> {
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
            return Err(DnsStampDecodeError::TooShort)
        }

        if last {
            return Ok(vector);
        }
    }
}

fn u8_array_u8_32_array(array: &[u8]) -> Result<[u8;32], DnsStampDecodeError> {
    if array.len() != 32 {
        return Err(DnsStampDecodeError::Len)
    }
    Ok(array.try_into().unwrap())
}

pub fn decode_hashi(buf: &[u8], offset: &mut usize) -> Result<Vec<[u8;32]>, DnsStampDecodeError> {
    let mut hashi = Vec::new();
    for hash in decode_vlp(buf, offset)? {
        if hash.len() != 0 {
            hashi.push(u8_array_u8_32_array(hash)?);
        }
    }

    Ok(hashi)
}

pub fn decode_bootstrap_ipi(buf: &[u8], offset: &mut usize) -> Result<Vec<IpAddr>, DnsStampDecodeError> {
    let mut bootstrap_ipi = Vec::new();
    for ip in decode_vlp(buf, offset)? {
        bootstrap_ipi.push(str_to_ip_addr(u8_array_to_str(ip)?)?);
    }
    Ok(bootstrap_ipi)
}

pub fn decode_pk(buf: &[u8], offset: &mut usize) -> Result<[u8;32], DnsStampDecodeError> {
    let pk = decode_lp(buf, offset)?;
    u8_array_u8_32_array(pk)
}

pub fn decode_type(buf: &[u8], offset: &mut usize) -> Result<DnsStampType, DnsStampDecodeError> {
    let type_ = decode_u8(buf, offset)?;
    match DnsStampType::from_u8(type_) {
        Some(type_) => {
            Ok(type_)
        }
        None => {
            Err(DnsStampDecodeError::UnknownType)
        }
    }
}

pub fn decode_props(buf: &[u8], offset: &mut usize) -> Result<Props, DnsStampDecodeError> {
    let props = decode_uint64(buf, offset)?;
    Ok(Props::from_bits_truncate(props))
}
