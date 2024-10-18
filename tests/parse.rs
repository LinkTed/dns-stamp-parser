use base64::DecodeError as Base64Error;
use dns_stamp_parser::{DecodeError, DnsStamp};

#[test]
fn parse_fail_one() {
    let stamp = "sdns://";

    assert_eq!(DnsStamp::decode(stamp), Err(DecodeError::NotEnoughBytes))
}

#[test]
fn parse_fail_two() {
    let stamp = "sdns://>";

    assert_eq!(
        stamp.parse::<DnsStamp>(),
        Err(DecodeError::Base64Error(Base64Error::InvalidByte(0, 62)))
    )
}

#[test]
fn parse_fail_three() {
    let stamp = "sdns://A";
    assert_eq!(
        stamp.parse::<DnsStamp>(),
        Err(DecodeError::Base64Error(Base64Error::InvalidLength(1)))
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

// Self generated dns-stamp via https://dnscrypt.info/stamps.
static DNS_STAMPS: [&str; 4] = [
    "sdns://AwcAAAAAAAAACTEyNy4wLjAuMQAObG9jYWxob3N0OjgwODA",
    "sdns://BAcAAAAAAAAACTEyNy4wLjAuMQAObG9jYWxob3N0OjgwODA",
    "sdns://BAcAAAAAAAAACTEyNy4wLjAuMQAJbG9jYWxob3N0",
    "sdns://BQcAAAAAAAAACWxvY2FsaG9zdAovZG5zLXF1ZXJ5",
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
#[test]
fn decode_encode_decode() {
    for stamp_1 in DNS_STAMPS.iter() {
        let dns_stamp_1 = DnsStamp::decode(stamp_1).unwrap();
        let stamp_2 = dns_stamp_1.encode().unwrap();
        let dns_stamp_2 = DnsStamp::decode(&stamp_2).unwrap();
        assert_eq!(dns_stamp_1, dns_stamp_2);
    }
}
