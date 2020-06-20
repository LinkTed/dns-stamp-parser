use data_encoding::{DecodeError as DataEncodingDecodeError, DecodeKind};
use dns_stamp_parser::{DecodeError, DnsStamp};

#[test]
fn regex_1() {
    let stamp = "sdns://";
    assert_eq!(DnsStamp::decode(stamp), Err(DecodeError::Regex))
}

#[test]
fn regex_2() {
    let stamp = "sdns://>";
    assert_eq!(DnsStamp::decode(stamp), Err(DecodeError::Regex))
}

#[test]
fn base64() {
    let stamp = "sdns://A";
    assert_eq!(
        DnsStamp::decode(stamp),
        Err(DecodeError::Base64Error(DataEncodingDecodeError {
            position: 0,
            kind: DecodeKind::Length
        }))
    )
}

#[test]
fn decode_type() {
    let stamp = "sdns://DzA";
    assert_eq!(DnsStamp::decode(stamp), Err(DecodeError::UnknownType(15)))
}

#[test]
fn decode_uint64() {
    let stamp = "sdns://AA";
    assert_eq!(DnsStamp::decode(stamp), Err(DecodeError::NotEnoughBytes))
}
