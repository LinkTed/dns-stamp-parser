# dns-stamp-parser
A library to encode and decode [DNS stamp](https://dnscrypt.info/stamps-specifications).
[![Build status](https://travis-ci.org/LinkTed/dns-stamp-parser.svg?branch=master)](https://travis-ci.org/LinkTed/dns-stamp-parser)
[![Latest version](https://img.shields.io/crates/v/dns-stamp-parser.svg)](https://crates.io/crates/dns-stamp-parser)
[![License](https://img.shields.io/crates/l/dns-stamp-parser.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Usage
Add this to your `Cargo.toml`:
```toml
[dependencies]
dns-stamp-parser = "1.0"
```

## Example
```rust
use dns_stamp_parser::DnsStamp;

fn example() {
    let stamp = "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjIgPhoaD2xT8-l6SS1XCEtbmAcFnuBXqxUFh2_YP9o9uDgNZG5zLmFhLm5ldC51awovZG5zLXF1ZXJ5";
    let dns_stamp = DnsStamp::decode(stamp).unwrap();
    println!("{}", dns_stamp.encode().unwrap());
}
```
