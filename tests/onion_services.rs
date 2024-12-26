use dns_stamp_parser::DnsStamp;

// The list is from https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/onion-services.md
static DNS_STAMPS: [&str; 1] = [
    "sdns://AgcAAAAAAAAAACC0WWFtenR5met-s8i0oiShMtYstulWSybPBq-zBUEMNT5kbnM0dG9ycG5sZnMyaWZ1ejJzMnlmM2ZjN3JkbXNiaG02cnc3NWV1ajM1cGFjNmFwMjV6Z3FhZC5vbmlvbgovZG5zLXF1ZXJ5"
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
///
/// [list]: https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/onion-services.md
#[test]
fn parental_control() {
    for stamp_1 in DNS_STAMPS.iter() {
        let dns_stamp_1 = DnsStamp::decode(stamp_1).unwrap();
        let stamp_2 = dns_stamp_1.encode().unwrap();
        let dns_stamp_2 = DnsStamp::decode(&stamp_2).unwrap();
        assert_eq!(dns_stamp_1, dns_stamp_2);
    }
}
