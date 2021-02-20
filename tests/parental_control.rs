use dns_stamp_parser::DnsStamp;

// The list is from https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/parental-control.md
static DNS_STAMPS: [&str; 21] = [
    "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
    "sdns://AgEAAAAAAAAAACA_4zhjTgUQYz3kU8o1CxXOwzmz3Li6nyot0k0QqDj-6x1mYW1pbHkuY2FuYWRpYW5zaGllbGQuY2lyYS5jYQovZG5zLXF1ZXJ5",
    "sdns://AQEAAAAAAAAADjIwOC42Ny4yMjAuMTIzILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
    "sdns://AgAAAAAAAAAADDE0Ni4xMTIuNDEuMyBUDrXp92r0ml9Aq9cu3mXf2w_ugmc61w74ZllxOxR-Vxxkb2guZmFtaWx5c2hpZWxkLm9wZW5kbnMuY29tCi9kbnMtcXVlcnk",
    "sdns://AQMAAAAAAAAAEzE4NS4yMjguMTY4LjEwOjg0NDMgvKwy-tVDaRcfCDLWB1AnwyCM7vDo6Z-UGNx3YGXUjykRY2xlYW5icm93c2luZy5vcmc",
    "sdns://AQMAAAAAAAAAFVsyYTBkOjJhMDA6MTo6MV06ODQ0MyC8rDL61UNpFx8IMtYHUCfDIIzu8Ojpn5QY3HdgZdSPKRFjbGVhbmJyb3dzaW5nLm9yZw",
    "sdns://AQMAAAAAAAAAFDE4NS4yMjguMTY4LjE2ODo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn",
    "sdns://AQMAAAAAAAAAFFsyYTBkOjJhMDA6MTo6XTo4NDQzILysMvrVQ2kXHwgy1gdQJ8MgjO7w6OmflBjcd2Bl1I8pEWNsZWFuYnJvd3Npbmcub3Jn",
    "sdns://AgMAAAAAAAAABzEuMC4wLjMAGWZhbWlseS5jbG91ZGZsYXJlLWRucy5jb20KL2Rucy1xdWVyeQ",
    "sdns://AgMAAAAAAAAAFlsyNjA2OjQ3MDA6NDcwMDo6MTExM10AGWZhbWlseS5jbG91ZGZsYXJlLWRucy5jb20KL2Rucy1xdWVyeQ",
    "sdns://AgMAAAAAAAAAFlsyNjA2OjQ3MDA6NDcwMDo6MTAwM10AGWZhbWlseS5jbG91ZGZsYXJlLWRucy5jb20KL2Rucy1xdWVyeQ",
    "sdns://AQIAAAAAAAAADDc4LjQ3LjY0LjE2MSATJeLOABXNSYcSJIoqR5_iUYz87Y4OecMLB84aEAKPrRBkbnNmb3JmYW1pbHkuY29t",
    "sdns://AgIAAAAAAAAADTk1LjIxNy4yMTMuOTSgPhoaD2xT8-l6SS1XCEtbmAcFnuBXqxUFh2_YP9o9uDggMob_ZaZfrzIIXuoTiMNzi6fjeHPJBszjxKKLTMKliYgYZG5zLWRvaC5kbnNmb3JmYW1pbHkuY29tCi9kbnMtcXVlcnk",
    "sdns://AgIAAAAAAAAADTk1LjIxNy4yMTMuOTQgMob_ZaZfrzIIXuoTiMNzi6fjeHPJBszjxKKLTMKliYgnZG5zLWRvaC1uby1zYWZlLXNlYXJjaC5kbnNmb3JmYW1pbHkuY29tCi9kbnMtcXVlcnk",
    "sdns://AQIAAAAAAAAADzEzNS4xODEuMTkzLjIyMiBHFKrWl_Swzwd8Mcwa8ZhdLGFgC94SpKo_g57e_49DthBkbnNmb3JmYW1pbHkuY29t",
    "sdns://AQIAAAAAAAAAF1syYTAxOjRmODoxYzE3OjRkZjg6OjFdIGN4CrSY4fb2hK8voFJL3GKiM7xQNwkKGH4b0k7LmMPxEGRuc2ZvcmZhbWlseS5jb20",
    "sdns://AgMAAAAAAAAAAAAVZG9oLmNsZWFuYnJvd3Npbmcub3JnEi9kb2gvYWR1bHQtZmlsdGVyLw",
    "sdns://AgMAAAAAAAAAAAAVZG9oLmNsZWFuYnJvd3Npbmcub3JnEy9kb2gvZmFtaWx5LWZpbHRlci8",
    "sdns://AQMAAAAAAAAADjEwNC4xOTcuMjguMTIxICcgf9USBOg2e0g0AF35_9HTC74qnDNjnm7b-K7ZHUDYIDIuZG5zY3J5cHQtY2VydC5zYWZlc3VyZmVyLmNvLm56",
    "sdns://AQMAAAAAAAAADzEwNC4xNTUuMjM3LjIyNSAnIH_VEgToNntINABd-f_R0wu-KpwzY55u2_iu2R1A2CAyLmRuc2NyeXB0LWNlcnQuc2FmZXN1cmZlci5jby5ueg",
    "sdns://AQMAAAAAAAAADzE2My4xNzIuMTgwLjEyNSDfYnO_x1IZKotaObwMhaw_-WRF1zZE9mJygl01WPGh_x8yLmRuc2NyeXB0LWNlcnQuc2Z3LnNjYWxld2F5LWZy",
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
///
/// [list]: https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/parental-control.md
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
