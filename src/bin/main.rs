extern crate traceroute;

use std::{env,process};
use std::io::{self, Write};

fn main() {
    let ip = env::args().nth(1).unwrap_or_else(|| {
        writeln!(io::stderr(), "[!] Usage: traceroute <host>").unwrap();
        process::exit(1);
    }) + ":0";

    println!("traceroute to {}", ip);

    for result in traceroute::traceroute(&ip).unwrap() {
    	match result {
    		Ok(res) => println!(" {}\t{}\t{}", res.ttl, res.host,
    			(res.rtt.as_secs() as f32) + ((res.rtt.subsec_nanos() as f32) / 1e6)),
    		Err(e) => panic!("{:?}", e)
    	}
    }
}
