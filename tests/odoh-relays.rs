use dns_stamp_parser::DnsStamp;

// The list is from https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md
static DNS_STAMPS: [&str; 4] = [
    "sdns://hQcAAAAAAAAADDg5LjM4LjEzMS4zOAAYb2RvaC1ubC5hbGVrYmVyZy5uZXQ6NDQzBi9wcm94eQ",
    "sdns://hQcAAAAAAAAAAAAab2RvaC1yZWxheS5lZGdlY29tcHV0ZS5hcHABLw",
    "sdns://hQcAAAAAAAAADjIxMy4xOTYuMTkxLjk2ABhpYmtzdHVybS5zeW5vbG9neS5tZTo0NDMGL3Byb3h5",
    "sdns://hQcAAAAAAAAADTQ1LjE1My4xODcuOTYAGG9kb2gtc2UuYWxla2JlcmcubmV0OjQ0MwYvcHJveHk",
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
///
/// [list]: https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md
#[test]
fn relays() {
    for stamp_1 in DNS_STAMPS.iter() {
        let dns_stamp_1 = DnsStamp::decode(stamp_1).unwrap();
        let stamp_2 = dns_stamp_1.encode().unwrap();
        let dns_stamp_2 = DnsStamp::decode(&stamp_2).unwrap();
        assert_eq!(dns_stamp_1, dns_stamp_2);
    }
}
