#[macro_use]
extern crate honggfuzz;
use base64::{encode_config, URL_SAFE_NO_PAD};
use dns_stamp_parser::DnsStamp;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            let stamp_1_str = format!("sdns://{}", encode_config(data, URL_SAFE_NO_PAD));
            if let Ok(stamp_1) = DnsStamp::decode(&stamp_1_str) {
                match stamp_1.encode() {
                    Ok(stamp_2_str) => match DnsStamp::decode(&stamp_2_str) {
                        Ok(stamp_2) => {
                            if stamp_1 != stamp_2 {
                                panic!(
                                    "Not equal: {:?} != {:?}: {} != {}",
                                    stamp_1, stamp_2, stamp_1_str, stamp_2_str
                                );
                            }
                        }
                        Err(e) => panic!("Decode: {:?}: {}", e, stamp_2_str),
                    },
                    Err(e) => panic!("Encode: {:?}: {}", e, stamp_1_str),
                }
            }
        });
    }
}
