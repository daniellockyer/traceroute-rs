extern crate traceroute;

use std::env;

fn main() {
    let mut args = env::args();
    let ip = args.nth(1).unwrap() + ":0";
    for result_ip in traceroute::traceroute(&ip).unwrap() {
        println!("{:?}", result_ip);
    }
}