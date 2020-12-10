use dns_stamp_parser::{Addr, DnsOverHttps, DnsStamp, Props};

fn main() {
    let props = Props::DNSSEC;
    let addr = Some(Addr::SocketAddr("217.169.20.22:443".parse().unwrap()));
    let hostname = "dns.aa.net.uk".to_string();
    let path = "/dns-query".to_string();
    let dns_stamp = DnsStamp::DnsOverHttps(DnsOverHttps {
        props,
        addr,
        hashi: Vec::new(),
        hostname,
        path,
        bootstrap_ipi: Vec::new(),
    });
    println!("{}", dns_stamp.encode().unwrap());
}
