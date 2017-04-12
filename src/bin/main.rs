extern crate traceroute;

use std::env;

fn main() {
    let mut args = env::args();
    let ip = args.nth(1).unwrap() + ":0";
    println!("traceroute to {}", ip);

    for result in traceroute::traceroute(&ip).unwrap() {
    	match result {
    		Ok(res) => println!(" {}\t{}\t{}", res.ttl, res.host,
    			(res.rtt.as_secs() as f32) + ((res.rtt.subsec_nanos() as f32) / 1e6)),
    		Err(e) => panic!("{:?}", e)
    	}
    }
}
