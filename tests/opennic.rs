use dns_stamp_parser::DnsStamp;

// The list is from https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/opennic.md
static DNS_STAMPS: [&str; 7] = [
    "sdns://AQcAAAAAAAAADTE1MS44MC4yMjIuNzkgqdYyOk8lgAkmGXUVAs4jHh922d53bIfGu7KKDv_bDk4gMi5kbnNjcnlwdC1jZXJ0Lm9wZW5uaWMuaTJwZC54eXo",
    "sdns://AQcAAAAAAAAAEDc4LjQ3LjI0My4zOjEwNTMgN4CAbUDR-b3uJJMVzfCdL9ivVV7s8wRhifLRPWBfSmQdMi5kbnNjcnlwdC1jZXJ0Lm5zMS5maXNjaGUuaW8",
    "sdns://AQYAAAAAAAAADTE0Mi40LjIwNC4xMTEgHBl5MxvoI8zPCJp5BpN-XDQQKlasf2Jw4EYlsu3bBOMfMi5kbnNjcnlwdC1jZXJ0Lm5zMy5jYS5sdWdncy5jbw",
    "sdns://AQYAAAAAAAAADDE0Mi40LjIwNS40NyC8v7fgUME9okIsALCxrJrWSMXCZLy2FwuIPXGKyG66CR8yLmRuc2NyeXB0LWNlcnQubnM0LmNhLmx1Z2dzLmNv",
    "sdns://AQcAAAAAAAAADDQ1Ljc2LjExMy4zMSAIVGh4i6eKXqlF6o9Fg92cgD2WcDvKQJ7v_Wq4XrQsVhsyLmRuc2NyeXB0LWNlcnQuZG5zLnNlYnkuaW8",
    "sdns://AgcAAAAAAAAADDQ1Ljc2LjExMy4zMaA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OCAyhv9lpl-vMghe6hOIw3OLp-N4c8kGzOPEootMwqWJiBBkb2guc2VieS5pbzo4NDQzCi9kbnMtcXVlcnk",
    "sdns://AgcAAAAAAAAADTEzOS45OS4yMjIuNzKgPhoaD2xT8-l6SS1XCEtbmAcFnuBXqxUFh2_YP9o9uDggMob_ZaZfrzIIXuoTiMNzi6fjeHPJBszjxKKLTMKliYgRZG9oLTIuc2VieS5pbzo0NDMKL2Rucy1xdWVyeQ",
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
///
/// [list]: https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/opennic.md
#[test]
fn opennic() {
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
