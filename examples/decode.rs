use dns_stamp_parser::{DnsStamp, Props};

fn main() {
    let stamp = "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjIgPhoaD2xT8-l6SS1XCEtbmAcFnuBXqxUFh2_YP9o9uDgNZG5zLmFhLm5ldC51awovZG5zLXF1ZXJ5";
    let dns_stamp = DnsStamp::decode(stamp).unwrap();
    if let DnsStamp::DnsOverHttps(props, addr, hashi, hostname, path, _bootstrap_ipi) = dns_stamp {
        println!("DNSSEC: {}", props.contains(Props::DNSSEC));
        println!("No logs: {}", props.contains(Props::NO_LOGS));
        println!("No filter: {}", props.contains(Props::NO_FILTER));

        match addr {
            Some(addr) => {
                println!("IP Address: {:?}", addr);
            }
            None => {
                println!("No Address")
            }
        }

        print!("Hashes: ");
        for hash in hashi {
            print!("{:?},", hash);
        }
        println!();

        println!("Hostname: {}", hostname);

        println!("Path: {}", path);
    }
}