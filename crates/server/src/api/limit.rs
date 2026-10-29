//! Token buckets for the client API (E10.3): failed authentications per client address, and
//! requests per device key. In memory, so the limits hold per server process.
//!
//! The client address is the peer's, unless the peer is a trusted proxy (`serve
//! --trusted-proxy`, loopback by default: Caddy on the same box): then it is the right-most
//! address in `X-Forwarded-For` that is not a trusted proxy, so a client cannot pick its
//! bucket by sending its own header.
//!
//! ponytail: single node only. Move the buckets to the database if Citadel ever runs more
//! than one process.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An address range: `10.0.0.0/8`, `::1/128`, or one address (`127.0.0.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr(IpAddr, u8);

impl Cidr {
    /// `127.0.0.0/8` and `::1`: a proxy on the same host.
    pub const LOOPBACK: [Self; 2] = [
        Self(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
        Self(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    ];

    pub fn contains(self, ip: IpAddr) -> bool {
        let bits = |n: u128, width: u32| match u32::from(self.1) {
            0 => 0,
            p => n >> (width - p),
        };
        match (self.0, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                bits(u32::from(net).into(), 32) == bits(u32::from(ip).into(), 32)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => bits(net.into(), 128) == bits(ip.into(), 128),
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not an address or a range like 10.0.0.0/8");
        let (ip, len) = s.split_once('/').map_or((s, None), |(a, l)| (a, Some(l)));
        let ip: IpAddr = ip.parse().map_err(|_| bad())?;
        let ip = ip.to_canonical();
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = len.map_or(Ok(max), |l| l.parse().map_err(|_| bad()))?;
        (len <= max).then_some(Self(ip, len)).ok_or_else(bad)
    }
}

/// The client's address: `peer`'s own, unless `peer` is in `trusted`; then the right-most
/// `X-Forwarded-For` entry (across all of them, in order) that is not, stopping at one that
/// does not parse.
pub fn client_ip<'a>(
    peer: IpAddr,
    forwarded_for: impl DoubleEndedIterator<Item = &'a str>,
    trusted: &[Cidr],
) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    let mut client = peer.to_canonical();
    if !is_trusted(client) {
        return client;
    }
    let hops: Vec<&str> = forwarded_for.flat_map(|h| h.split(',')).collect();
    for hop in hops.into_iter().rev() {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            break;
        };
        client = ip.to_canonical();
        if !is_trusted(client) {
            break;
        }
    }
    client
}

/// Buckets of `burst` tokens each, refilled at `per_sec`, by key.
pub struct Limiter {
    pub burst: f64,
    pub per_sec: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

/// Keys kept before full buckets are dropped; a full bucket is the same as no bucket.
const MAX_KEYS: usize = 4096;

impl Limiter {
    pub fn new(burst: u32, per_sec: f64) -> Self {
        Self {
            burst: f64::from(burst),
            per_sec,
            buckets: Mutex::default(),
        }
    }

    fn refill(&self, (tokens, at): (f64, Instant), now: Instant) -> f64 {
        let secs = now.saturating_duration_since(at).as_secs_f64();
        (tokens + secs * self.per_sec).min(self.burst)
    }

    /// Whether `key` has a token at `now`, without taking one; else how long until it has.
    pub fn check(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let buckets = self.buckets.lock().unwrap();
        let tokens = buckets
            .get(key)
            .map_or(self.burst, |b| self.refill(*b, now));
        self.wait(tokens)
    }

    /// Takes a token from `key`'s bucket at `now`; else how long until one is there.
    pub fn take(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() >= MAX_KEYS {
            buckets.retain(|_, b| self.refill(*b, now) < self.burst);
        }
        let bucket = buckets.entry(key.to_owned()).or_insert((self.burst, now));
        let tokens = self.refill(*bucket, now);
        self.wait(tokens)?;
        *bucket = (tokens - 1.0, now);
        Ok(())
    }

    fn wait(&self, tokens: f64) -> Result<(), Duration> {
        if tokens >= 1.0 {
            return Ok(());
        }
        Err(Duration::from_secs_f64(
            (1.0 - tokens) / self.per_sec.max(f64::MIN_POSITIVE),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_client_is_the_peer_unless_a_trusted_proxy_forwards_it() {
        let trusted = Cidr::LOOPBACK;
        // Direct: the peer, whatever it sends.
        assert_eq!(
            client_ip(ip("203.0.113.9"), [].into_iter(), &trusted),
            ip("203.0.113.9")
        );
        let spoofed = ["1.2.3.4"].into_iter();
        assert_eq!(
            client_ip(ip("203.0.113.9"), spoofed, &trusted),
            ip("203.0.113.9")
        );
        // Through the proxy: the right-most untrusted entry, not a client-sent one left of it.
        let xff = ["1.2.3.4, 198.51.100.7"].into_iter();
        assert_eq!(
            client_ip(ip("127.0.0.1"), xff, &trusted),
            ip("198.51.100.7")
        );
        let two = ["1.2.3.4", "198.51.100.7, 127.0.0.2"].into_iter();
        assert_eq!(
            client_ip(ip("127.0.0.1"), two, &trusted),
            ip("198.51.100.7")
        );
        // No header, or a broken one: the proxy itself.
        assert_eq!(client_ip(ip("::1"), [].into_iter(), &trusted), ip("::1"));
        let junk = ["1.2.3.4, unknown"].into_iter();
        assert_eq!(client_ip(ip("127.0.0.1"), junk, &trusted), ip("127.0.0.1"));
        // A wider trust list skips more hops; an IPv4-mapped peer is its IPv4 address.
        let cf: Vec<Cidr> = ["127.0.0.1", "173.245.48.0/20"]
            .map(|c| c.parse().unwrap())
            .into();
        let xff = ["198.51.100.7, 173.245.48.1"].into_iter();
        assert_eq!(
            client_ip(ip("::ffff:127.0.0.1"), xff, &cf),
            ip("198.51.100.7")
        );
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("0.0.0.0/0".parse::<Cidr>().unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn empties_then_refills_per_key() {
        let l = Limiter::new(2, 1.0);
        let t = Instant::now();
        assert!(l.take("a", t).is_ok());
        assert!(l.take("a", t).is_ok());
        let wait = l.take("a", t).unwrap_err();
        assert!(wait <= Duration::from_secs(1) && wait > Duration::ZERO);
        assert!(l.check("a", t).is_err());
        assert!(l.take("b", t).is_ok(), "buckets are per key");
        assert!(l.take("a", t + Duration::from_secs(1)).is_ok());
        assert!(l.check("a", t + Duration::from_secs(1)).is_err());
    }
}
