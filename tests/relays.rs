use dns_stamp_parser::DnsStamp;

// The list is from https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/public-resolvers.md
static DNS_STAMPS: [&str; 40] = [
    "sdns://gRE1MS4xNTguMTY2Ljk3OjQ0Mw",
    "sdns://gRpbMjAwMTpiYzg6MTgyNDo3Mzg6OjFdOjQ0Mw",
    "sdns://gRE1MS4xNS4xMjQuMjA4OjQ0Mw",
    "sdns://gRMxNjIuMjIxLjIwNy4yMjg6NDQz",
    "sdns://gRA4NC4xNi4yNDAuNDM6NDQz",
    "sdns://gREyMTIuMTI5LjQ2LjMyOjQ0Mw",
    "sdns://gRExOTUuMTU0LjQwLjQ4OjQ0Mw",
    "sdns://gRMxNzguMTc1LjEzOS4yMTE6NDQz",
    "sdns://gRExODUuMTA3LjgwLjg0OjQ0Mw",
    "sdns://gRIyMTMuMTYzLjY0LjIwODo0NDM",
    "sdns://gRExMDkuNzEuNDIuMjI4OjQ0Mw",
    "sdns://gRMxMjguMTI3LjEwNC4xMDg6NDQz",
    "sdns://gRAyNy4yNTUuNzcuNTY6NDQz",
    "sdns://gRAyMy4xOS42Ny4xMTY6NDQz",
    "sdns://gRE2NC40Mi4xODEuMjI3OjQ0Mw",
    "sdns://gRIxNTUuMjU0LjI5LjExMzo0NDM",
    "sdns://gRAzNy4xMjAuMTQ3LjI6NDQz",
    "sdns://gRExMDQuMjU1LjE3NS4yOjQ0Mw",
    "sdns://gREyMDkuNTguMTQ3LjM2OjQ0Mw",
    "sdns://gRIxMzkuNTkuMjAwLjExNjo0NDM",
    "sdns://gR5bMmEwMzpiMGMwOjE6ZTA6OjJlMzplMDAxXTo0NDM",
    "sdns://gQw2Ni44NS4zMC4xMTU",
    "sdns://gQ0yMy4xMTEuNzQuMjA1",
    "sdns://gRA4NS41LjkzLjIzMDo4NDQz",
    "sdns://gS5bMmEwMjoxMjA1OjUwNTU6ZGU2MDpiMjZlOmJmZmY6ZmUxZDplMTliXTo4NDQz",
    "sdns://gRIxMDQuMjM4LjE1My40Njo0NDM",
    "sdns://gRIxMzcuNzQuMjIzLjIzNDo0NDM",
    "sdns://gRIyMDkuMjUwLjI0MS4yNTo0NDM",
    "sdns://gStbMmEwNTpmNDgwOjE0MDA6NDM2OjU0MDA6MmZmOmZlYjg6OGQxY106NDQz",
    "sdns://gRIxMzkuOTkuMjIyLjcyOjg0NDM",
    "sdns://gRMxNjMuMTcyLjE4MC4xMjU6NDQz",
    "sdns://gRE1MS4xNS4xMjIuMjUwOjQ0Mw",
    "sdns://gRpbMjAwMTpiYzg6MTgyMDo1MGQ6OjFdOjQ0Mw",
    "sdns://gQ81MS4xNS42Mi42NTo0NDM",
    "sdns://gRtbMjAwMTpiYzg6MTgyNDoxNzBmOjoxXTo0NDM",
    "sdns://gRE0NS4xNTMuMTg3Ljk2OjQ0Mw",
    "sdns://gRMxNzQuMTM4LjI5LjE3NToxNDQz",
    "sdns://gSBbMjQwMDo2MTgwOjA6ZDA6OjVmNzM6NDAwMV06MTQ0Mw",
    "sdns://gRMxMDQuMjM4LjE4Ni4xOTI6NDQz",
    "sdns://gSxbMjAwMToxOWYwOjc0MDI6MTU3NDo1NDAwOjJmZjpmZTY2OjJjZmZdOjQ0Mw",
];

/// Test all DNS Stamp from the [list] by decode and encode and decode it again.
///
/// [list]: https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/relays.md
#[test]
fn relays() {
    for stamp_1 in DNS_STAMPS.iter() {
        let dns_stamp_1 = DnsStamp::decode(stamp_1).unwrap();
        let stamp_2 = dns_stamp_1.encode().unwrap();
        let dns_stamp_2 = DnsStamp::decode(&stamp_2).unwrap();
        assert_eq!(dns_stamp_1, dns_stamp_2);
    }
}
