use dns_stamp_parser::DnsStamp;

static DNS_STAMPS: [&str; 2] = [
    "sdns://AAcAAAAAAAAABVs6OjFd",
    "sdns://AAcAAAAAAAAACTEyNy4wLjAuMQ",
];

#[test]
fn ip_addrs() {
    for stamp_1 in DNS_STAMPS.iter() {
        match DnsStamp::decode(stamp_1) {
            Ok(dns_stamp_1) => match dns_stamp_1.encode() {
                Ok(stamp_2) => match DnsStamp::decode(&stamp_2) {
                    Ok(dns_stamp_2) => {
                        if dns_stamp_1 != dns_stamp_2 {
                            panic!("Not equal: {} {}", stamp_1, stamp_2);
                        }
                    }
                    Err(e) => {
                        panic!("Decode 2: {:?}: {} {}", e, stamp_1, stamp_2);
                    }
                },
                Err(e) => {
                    panic!("Encode 1: {:?}: {}", e, stamp_1);
                }
            },
            Err(e) => {
                panic!("Decode 1: {:?}: {}", e, stamp_1);
            }
        }
    }
}
