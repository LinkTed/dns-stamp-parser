use dns_stamp_parser::DnsStamp;
// The list is from https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/public-resolvers.md
static DNS_STAMPS: [&'static str;15] = [
    "sdns://AgcAAAAAAAAAACA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBRpYmtzdHVybS5zeW5vbG9neS5tZQovZG5zLXF1ZXJ5",
    "sdns://AQcAAAAAAAAAEDg1LjUuOTMuMjMwOjg0NDMgwc9XUACwW8JsYh9ez5qiVgrOvwB-vss6f_SyDeC0Oe4YMi5kbnNjcnlwdC1jZXJ0Lmlia3N0dXJt",
    "sdns://AQcAAAAAAAAALlsyYTAyOjEyMDU6NTA1NTpkZTYwOmIyNmU6YmZmZjpmZTFkOmUxOWJdOjg0NDMgwc9XUACwW8JsYh9ez5qiVgrOvwB-vss6f_SyDeC0Oe4YMi5kbnNjcnlwdC1jZXJ0Lmlia3N0dXJt",
    "sdns://AQcAAAAAAAAAETE1MS44MC4yMjIuNzk6NDQzIKnWMjpPJYAJJhl1FQLOIx4fdtned2yHxruyig7_2w5OIDIuZG5zY3J5cHQtY2VydC5vcGVubmljLmkycGQueHl6",
    "sdns://AQcAAAAAAAAAG1syMDAxOjQ3MDoxZjE1OmI4MDo6NTNdOjQ0MyCp1jI6TyWACSYZdRUCziMeH3bZ3ndsh8a7sooO_9sOTiAyLmRuc2NyeXB0LWNlcnQub3Blbm5pYy5pMnBkLnh5eg",
    "sdns://AQYAAAAAAAAAETUuMTg5LjE3MC4xOTY6NDY1IFQ1LFVAO4Luk8QH_cI0RJcNmlbvIr_P-eyQnM0yJDJrKDIuZG5zY3J5cHQtY2VydC5uczE2LmRlLmRucy5vcGVubmljLmdsdWU",
    "sdns://AQYAAAAAAAAADTE0Mi40LjIwNC4xMTEgHBl5MxvoI8zPCJp5BpN-XDQQKlasf2Jw4EYlsu3bBOMfMi5kbnNjcnlwdC1jZXJ0Lm5zMy5jYS5sdWdncy5jbw",
    "sdns://AQYAAAAAAAAAIVsyNjA3OjUzMDA6MTIwOmE4YToxNDI6NDoyMDQ6MTExXSAcGXkzG-gjzM8ImnkGk35cNBAqVqx_YnDgRiWy7dsE4x8yLmRuc2NyeXB0LWNlcnQubnMzLmNhLmx1Z2dzLmNv",
    "sdns://AQYAAAAAAAAAEDE0Mi40LjIwNS40Nzo0NDMgvL-34FDBPaJCLACwsaya1kjFwmS8thcLiD1xishuugkfMi5kbnNjcnlwdC1jZXJ0Lm5zNC5jYS5sdWdncy5jbw",
    "sdns://AQYAAAAAAAAAJFsyNjA3OjUzMDA6MTIwOmE4YToxNDI6NDoyMDU6NDddOjQ0MyC8v7fgUME9okIsALCxrJrWSMXCZLy2FwuIPXGKyG66CR8yLmRuc2NyeXB0LWNlcnQubnM0LmNhLmx1Z2dzLmNv",
    "sdns://AQYAAAAAAAAAETE0Mi40LjIwNC4xMTE6NDQzIBwZeTMb6CPMzwiaeQaTflw0ECpWrH9icOBGJbLt2wTjHzIuZG5zY3J5cHQtY2VydC5uczMuY2EubHVnZ3MuY28",
    "sdns://AQcAAAAAAAAADDQ1Ljc2LjExMy4zMSAIVGh4i6eKXqlF6o9Fg92cgD2WcDvKQJ7v_Wq4XrQsVhsyLmRuc2NyeXB0LWNlcnQuZG5zLnNlYnkuaW8",
    "sdns://AgcAAAAAAAAADDQ1Ljc2LjExMy4zMSA-GhoPbFPz6XpJLVcIS1uYBwWe4FerFQWHb9g_2j24OBBkb2guc2VieS5pbzo4NDQzCi9kbnMtcXVlcnk",
    "sdns://AQcAAAAAAAAADTEzOS45OS4yMjIuNzIgCwVoTw0L4dgal5LC1FbZUtHtLR_rVuV6rVnxO95e4GUbMi5kbnNjcnlwdC1jZXJ0LmRucy5zZWJ5Lmlv",
    "sdns://AgcAAAAAAAAADTEzOS45OS4yMjIuNzIgPhoaD2xT8-l6SS1XCEtbmAcFnuBXqxUFh2_YP9o9uDgRZG9oLTIuc2VieS5pbzo0NDMKL2Rucy1xdWVyeQ",
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
///
/// [list]: https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/opennic.md
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
