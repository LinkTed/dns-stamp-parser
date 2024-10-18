use dns_stamp_parser::DnsStamp;

static DNS_STAMPS: [&str; 2] = [
    "sdns://AAcAAAAAAAAABVs6OjFd",
    "sdns://AAcAAAAAAAAACTEyNy4wLjAuMQ",
];

#[test]
fn ip_addrs() {
    for stamp_1 in DNS_STAMPS.iter() {
        let dns_stamp_1 = DnsStamp::decode(stamp_1).unwrap();
        let stamp_2 = dns_stamp_1.encode().unwrap();
        let dns_stamp_2 = DnsStamp::decode(&stamp_2).unwrap();
        assert_eq!(dns_stamp_1, dns_stamp_2);
    }
}
