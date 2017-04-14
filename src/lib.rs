extern crate libc;
extern crate socket;
extern crate pnet;

use std::iter::Iterator;
use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{Packet,PrimitiveValues};
use libc::{suseconds_t, time_t, timeval};
use socket::{AF_INET, IP_TTL, IPPROTO_IP, SOCK_RAW, SOL_SOCKET, Socket};

pub struct TraceResult {
    addr: SocketAddr,
    ttl: u8,
    ident: u16,
    seq_num: u16,
    done: bool,
    timeout: Duration,
}

#[derive(Debug)]
pub struct TraceHop {
    /// The Time-To-Live value used to find this hop
    pub ttl: u8,
    /// The address of the node in the hop
    pub host: SocketAddr,
    /// The round trip time to the hop
    pub rtt: Duration,
}

/// Performs a traceroute, waiting at each request for around one second before failing
pub fn traceroute<T: ToSocketAddrs>(address: &T) -> io::Result<TraceResult> {
    traceroute_with_timeout(address, Duration::from_secs(1))
}

/// Performs a traceroute, waiting at each request for around until timeout elapses before failing
pub fn traceroute_with_timeout<T: ToSocketAddrs>(address: &T, timeout: Duration) -> io::Result<TraceResult> {
    if timeout.as_secs() == 0 {
        return Err(Error::new(ErrorKind::InvalidInput, "Timeout too small"));
    }

    let mut addr_iter = address.to_socket_addrs()?;
    match addr_iter.next() {
        None => Err(Error::new(ErrorKind::InvalidInput, "Could not interpret address")),
        Some(addr) => Ok(TraceResult {
            addr: addr,
            ttl: 0,
            ident: (unsafe { libc::getpid() as u16 } & 0xffff) | 0x8000,
            seq_num: 0,
            done: false,
            timeout: timeout,
        })
    }
}

impl Iterator for TraceResult {
    type Item = io::Result<TraceHop>;

    fn next(&mut self) -> Option<io::Result<TraceHop>> {
        if self.done {
            return None;
        }

        let res = self.find_next_hop();
        if res.is_err() {
            self.done = true;
        }
        Some(res)
    }
}

impl TraceResult {
    fn find_next_hop(&mut self) -> io::Result<TraceHop> {
        let socket = Socket::new(AF_INET, SOCK_RAW, 1)?;
        loop {
            let mut vec: Vec<u8> = vec![
                8u8, 0u8,
                0u8, 0u8,
                (self.ident >> 8) as u8, (self.ident & 0xff) as u8,
                (self.seq_num >> 8) as u8, (self.seq_num & 0xff) as u8
            ];

            let mut sum = 0u16;
            for word in vec.chunks(2) {
                let mut part = (word[0] as u16) << 8;
                if word.len() > 1 {
                    part += word[1] as u16;
                }
                sum = sum.wrapping_add(part);
            }
            sum = !sum;
            vec[2] = (sum >> 8) as u8;
            vec[3] = (sum & 0xff) as u8;

            self.seq_num += 1;
            self.ttl += 1;

            socket.setsockopt(IPPROTO_IP, IP_TTL, self.ttl)?;
            socket.setsockopt(SOL_SOCKET, 20, compute_timeout(self.timeout))?; // SO_RCVTIMEO = 20

            let wrote = socket.sendto(&vec, 0, &self.addr)?;
            assert_eq!(wrote, vec.len());

            let start_time = Instant::now();

            // After deadline passes, restart the loop to advance the TTL and resend.
            while Instant::now() < start_time + self.timeout {
                let (sender, data) = match socket.recvfrom(4096, 0) {
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                    Ok((s, d)) => (s, d),
                };

                let reply = Ipv4Packet::new(&data).unwrap();
                let reply_icmp = IcmpPacket::new(reply.payload()).unwrap();

                let icmp_type = reply_icmp.get_icmp_type().to_primitive_values().0;

                if icmp_type == 11 && self.ttl == 255 { // TimeExceeded
                    self.done = true;
                    return Err(Error::new(ErrorKind::TimedOut, "Too many hops"));
                }

                let payload = reply_icmp.payload();

                if payload[(payload.len()-4) .. payload.len()] == vec[4..8] {
                    let hop = TraceHop {
                        ttl: self.ttl,
                        host: sender,
                        rtt: Instant::now() - start_time,
                    };

                    if icmp_type == 0 { // EchoReply
                        self.done = true;
                    }
                    return Ok(hop);
                }
            }
        }
    }
}

fn compute_timeout(timeout: Duration) -> timeval {
    timeval {
        tv_sec: (timeout.as_secs()) as time_t,
        tv_usec: (timeout.subsec_nanos()) as suseconds_t,
    }
}