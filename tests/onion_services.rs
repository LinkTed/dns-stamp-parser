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
