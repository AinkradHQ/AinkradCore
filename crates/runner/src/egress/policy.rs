//! The egress allow policy of a filtered agent sandbox (E8a-01).
//!
//! The operator lists destinations in the runner's config: CIDRs for IP literals (and a local
//! model), and exact host names that only the egress proxy resolves. Every address a connection
//! would use, literal or resolved, is checked here; the proxy dials the address it checked.
//!
//! Order of checks for one address: the cloud metadata addresses are never reachable; the
//! address must be in an allowed CIDR, or have come from a listed name; the reserved ranges
//! (loopback, link-local, private, ULA, multicast, NAT64, ...) are subtracted unless an allowed
//! CIDR that lies inside that range names the address. So `0.0.0.0/0` opens the public internet
//! and nothing reserved, while a local model needs its own single-host CIDR.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_ENTRIES: usize = 256;
const MAX_PORTS: usize = 16;

/// An address range. The address is kept masked to its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// The address as a number, and the width of its family.
fn bits(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    }
}

/// The leading `prefix` bits of `value`, as a number.
fn head(value: u128, width: u8, prefix: u8) -> u128 {
    value
        .checked_shr(u32::from(width.saturating_sub(prefix)))
        .unwrap_or(0)
}

impl Cidr {
    fn new(addr: IpAddr, prefix: u8) -> Option<Cidr> {
        let (value, width) = bits(addr);
        if prefix > width {
            return None;
        }
        let masked = head(value, width, prefix)
            .checked_shl(u32::from(width - prefix))
            .unwrap_or(0);
        let addr = match addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::try_from(masked).ok()?)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(masked)),
        };
        Some(Cidr { addr, prefix })
    }

    fn v4(a: [u8; 4], prefix: u8) -> Cidr {
        Cidr::new(IpAddr::V4(Ipv4Addr::from(a)), prefix).expect("a valid built-in range")
    }

    fn v6(a: [u16; 8], prefix: u8) -> Cidr {
        Cidr::new(IpAddr::V6(Ipv6Addr::from(a)), prefix).expect("a valid built-in range")
    }

    /// `a.b.c.d/n`, `x::y/n`, or a bare address (a single host). An IPv4-mapped IPv6 range is
    /// refused: write the IPv4 form, which is what the proxy checks after normalising.
    pub fn parse(text: &str) -> Option<Cidr> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        if matches!(addr, IpAddr::V6(a) if a.to_ipv4_mapped().is_some()) {
            return None;
        }
        let width = bits(addr).1;
        let prefix = match prefix {
            None => width,
            Some(p) if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse().ok()?
            }
            Some(_) => return None,
        };
        Cidr::new(addr, prefix)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (value, width) = bits(ip);
        let (net, net_width) = bits(self.addr);
        width == net_width && head(value, width, self.prefix) == head(net, width, self.prefix)
    }

    /// Every address of `self` is in `outer`.
    fn within(&self, outer: &Cidr) -> bool {
        self.prefix >= outer.prefix && outer.contains(self.addr)
    }
}

/// Why a destination was refused. Never carries the destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    Port,
    NotListed,
    Metadata,
    Reserved,
}

/// The cloud metadata services: no allow entry reaches them.
fn metadata() -> [Cidr; 4] {
    [
        Cidr::v4([169, 254, 169, 254], 32),
        Cidr::v4([168, 63, 129, 16], 32),
        Cidr::v4([100, 100, 100, 200], 32),
        Cidr::v6([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254], 128),
    ]
}

/// Ranges that are not the public internet. Denied unless an allowed CIDR inside one names the
/// address. IPv4-mapped IPv6 is converted to IPv4 before any check, so it is not listed.
fn reserved() -> Vec<Cidr> {
    vec![
        Cidr::v4([0, 0, 0, 0], 8),
        Cidr::v4([10, 0, 0, 0], 8),
        Cidr::v4([100, 64, 0, 0], 10),
        Cidr::v4([127, 0, 0, 0], 8),
        Cidr::v4([169, 254, 0, 0], 16),
        Cidr::v4([172, 16, 0, 0], 12),
        Cidr::v4([192, 0, 0, 0], 24),
        Cidr::v4([192, 0, 2, 0], 24),
        Cidr::v4([192, 168, 0, 0], 16),
        Cidr::v4([198, 18, 0, 0], 15),
        Cidr::v4([198, 51, 100, 0], 24),
        Cidr::v4([203, 0, 113, 0], 24),
        Cidr::v4([224, 0, 0, 0], 4),
        Cidr::v4([240, 0, 0, 0], 4),
        // ::/96 holds the unspecified and loopback addresses and the deprecated IPv4-compatible form.
        Cidr::v6([0, 0, 0, 0, 0, 0, 0, 0], 96),
        Cidr::v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96),
        Cidr::v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
        Cidr::v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
        Cidr::v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 32),
        Cidr::v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        Cidr::v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
        Cidr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
        Cidr::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
        Cidr::v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
    ]
}

/// An IPv4-mapped IPv6 address is its IPv4 address; every check runs on that.
pub fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// A host name the operator may list: lower-case labels of letters, digits and hyphens, the last
/// one starting with a letter (so no numeric form a resolver could read as an address).
pub fn host_name(text: &str) -> Option<String> {
    let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let ok = !name.is_empty()
        && name.len() <= 253
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && labels
            .last()
            .is_some_and(|l| l.as_bytes()[0].is_ascii_alphabetic());
    ok.then_some(name)
}

#[derive(Clone, Debug)]
pub struct Policy {
    cidrs: Vec<Cidr>,
    hosts: BTreeSet<String>,
    ports: Vec<u16>,
    reserved: Vec<Cidr>,
}

fn items(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').map(str::trim).filter(|s| !s.is_empty())
}

impl Policy {
    /// From the three comma-separated lists. Errors name the list and the entry number, never the
    /// entry. An empty `ports` is `443`.
    pub fn parse(cidrs: &str, hosts: &str, ports: &str) -> Result<Policy, String> {
        let mut parsed = Policy {
            cidrs: vec![],
            hosts: BTreeSet::new(),
            ports: vec![],
            reserved: reserved(),
        };
        for (n, entry) in items(cidrs).enumerate() {
            let cidr = Cidr::parse(entry).ok_or_else(|| {
                format!("AINKRAD_AGENT_EGRESS_ALLOW entry {} is not a CIDR", n + 1)
            })?;
            parsed.cidrs.push(cidr);
        }
        for (n, entry) in items(hosts).enumerate() {
            let name = host_name(entry).ok_or_else(|| {
                format!(
                    "AINKRAD_AGENT_EGRESS_HOSTS entry {} is not a host name",
                    n + 1
                )
            })?;
            parsed.hosts.insert(name);
        }
        for (n, entry) in items(ports).enumerate() {
            let port = entry
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0 && entry.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| {
                    format!("AINKRAD_AGENT_EGRESS_PORTS entry {} is not a port", n + 1)
                })?;
            parsed.ports.push(port);
        }
        if parsed.cidrs.len() > MAX_ENTRIES
            || parsed.hosts.len() > MAX_ENTRIES
            || parsed.ports.len() > MAX_PORTS
        {
            return Err("the egress allow lists are too long".into());
        }
        if parsed.ports.is_empty() {
            parsed.ports.push(443);
        }
        Ok(parsed)
    }

    /// The runner's own policy (`AINKRAD_AGENT_EGRESS_*`).
    pub fn from_env() -> Result<Policy, String> {
        let get = |k: &str| std::env::var(k).unwrap_or_default();
        Policy::parse(
            &get("AINKRAD_AGENT_EGRESS_ALLOW"),
            &get("AINKRAD_AGENT_EGRESS_HOSTS"),
            &get("AINKRAD_AGENT_EGRESS_PORTS"),
        )
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (self.cidrs.len(), self.hosts.len(), self.ports.len())
    }

    pub fn port_ok(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    /// `name` is exactly a listed host name (already lower-case, no trailing dot).
    pub fn host_listed(&self, name: &str) -> bool {
        self.hosts.contains(name)
    }

    /// The address to dial for `ip`, or why not. `named`: the address came from resolving a
    /// listed name, so it needs no CIDR (but is still subject to the reserved ranges).
    pub fn check_ip(&self, ip: IpAddr, named: bool) -> Result<IpAddr, Deny> {
        let ip = normalise(ip);
        if metadata().iter().any(|m| m.contains(ip)) {
            return Err(Deny::Metadata);
        }
        let allowed = self.cidrs.iter().any(|c| c.contains(ip));
        if !allowed && !named {
            return Err(Deny::NotListed);
        }
        for range in self.reserved.iter().filter(|r| r.contains(ip)) {
            let named_inside = self.cidrs.iter().any(|c| c.contains(ip) && c.within(range));
            if !named_inside {
                return Err(Deny::Reserved);
            }
        }
        Ok(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn public() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }
    fn policy(cidrs: &str, hosts: &str) -> Policy {
        Policy::parse(cidrs, hosts, "").unwrap()
    }

    #[test]
    fn cidrs_parse_and_match() {
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        assert!(c.contains(ip("10.200.0.1")) && !c.contains(ip("11.0.0.1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(public()));
        assert!(!Cidr::parse("0.0.0.0/0").unwrap().contains(ip("::1")));
        assert!(Cidr::parse("::/0").unwrap().contains(ip("2606:4700::1")));
        assert!(Cidr::parse("127.0.0.1").unwrap().contains(ip("127.0.0.1")));
        for bad in [
            "",
            "1.2.3.4/33",
            "::/129",
            "1.2.3/24",
            "a/8",
            "1.2.3.4/",
            "1.2.3.4/+8",
            "::ffff:1.2.3.4/128",
            "example.test",
        ] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn nothing_is_allowed_by_default_and_the_internet_is_not_reserved_space() {
        assert_eq!(
            policy("", "").check_ip(public(), false),
            Err(Deny::NotListed)
        );
        assert_eq!(
            policy("0.0.0.0/0", "").check_ip(public(), false),
            Ok(public())
        );
    }

    #[test]
    fn a_broad_allow_never_opens_reserved_space() {
        let p = policy("0.0.0.0/0,::/0", "");
        for r in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "::",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::808:808",
            "2002:7f00:1::",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ] {
            assert_eq!(p.check_ip(ip(r), false), Err(Deny::Reserved), "{r}");
        }
        let cgnat = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let multicast = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
        let broadcast = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        for r in [cgnat, multicast, broadcast] {
            assert_eq!(p.check_ip(r, false), Err(Deny::Reserved), "{r}");
        }
    }

    #[test]
    fn a_cidr_inside_a_reserved_range_names_just_that_space() {
        let p = policy("127.0.0.2/32,10.9.0.0/16", "");
        assert_eq!(p.check_ip(ip("127.0.0.2"), false), Ok(ip("127.0.0.2")));
        assert_eq!(p.check_ip(ip("127.0.0.1"), false), Err(Deny::NotListed));
        assert_eq!(p.check_ip(ip("10.9.4.4"), false), Ok(ip("10.9.4.4")));
        assert_eq!(p.check_ip(ip("10.8.4.4"), false), Err(Deny::NotListed));
        // A listed name that resolves into reserved space is still refused unless a CIDR names it.
        assert_eq!(p.check_ip(ip("10.8.4.4"), true), Err(Deny::Reserved));
        assert_eq!(p.check_ip(ip("10.9.4.4"), true), Ok(ip("10.9.4.4")));
    }

    #[test]
    fn the_metadata_addresses_are_unreachable_whatever_is_allowed() {
        let p = policy(
            "0.0.0.0/0,169.254.0.0/16,169.254.169.254/32,::/0,fd00:ec2::/32",
            "meta.test",
        );
        let azure = IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16));
        let alibaba = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200));
        for m in [
            ip("169.254.169.254"),
            ip("fd00:ec2::254"),
            ip("::ffff:169.254.169.254"),
            azure,
            alibaba,
        ] {
            assert_eq!(p.check_ip(m, false), Err(Deny::Metadata), "{m}");
            assert_eq!(p.check_ip(m, true), Err(Deny::Metadata), "{m}");
        }
    }

    #[test]
    fn mapped_addresses_are_checked_as_ipv4() {
        let p = policy("0.0.0.0/0", "");
        assert_eq!(
            p.check_ip(ip("::ffff:127.0.0.1"), false),
            Err(Deny::Reserved)
        );
        assert_eq!(
            p.check_ip(ip("::ffff:10.0.0.1"), false),
            Err(Deny::Reserved)
        );
        assert_eq!(
            p.check_ip(IpAddr::V6(public().to_canonical_v6()), false),
            Ok(public())
        );
        // The IPv4 form of an allowed host is what an allowed mapped address matches.
        assert_eq!(
            policy("127.0.0.2/32", "").check_ip(ip("::ffff:127.0.0.2"), false),
            Ok(ip("127.0.0.2"))
        );
    }

    trait V6 {
        fn to_canonical_v6(self) -> Ipv6Addr;
    }
    impl V6 for IpAddr {
        fn to_canonical_v6(self) -> Ipv6Addr {
            match self {
                IpAddr::V4(a) => a.to_ipv6_mapped(),
                IpAddr::V6(a) => a,
            }
        }
    }

    #[test]
    fn host_names_and_ports_are_validated_and_errors_do_not_echo_entries() {
        assert_eq!(host_name("API.Model.Test."), Some("api.model.test".into()));
        let label = "a".repeat(64);
        for bad in [
            "",
            ".",
            "a..b",
            "-a.test",
            "a-.test",
            "*.test",
            "a_b.test",
            "1.2.3.4",
            "0x7f.1",
            "a.0x1",
            "h\u{e9}.test",
            "a b.test",
            "a@b.test",
            label.as_str(),
        ] {
            assert!(host_name(bad).is_none(), "{bad}");
        }
        let long = format!("{}.test", "a.".repeat(130));
        assert!(host_name(&long).is_none());
        let e = Policy::parse("not-a-cidr-secret", "", "").unwrap_err();
        assert!(!e.contains("secret") && e.contains("entry 1"), "{e}");
        let e = Policy::parse("", "api.model.test,1.2.3.4", "").unwrap_err();
        assert!(e.contains("HOSTS") && e.contains("entry 2"), "{e}");
        assert!(Policy::parse("", "", "0").is_err());
        assert!(Policy::parse("", "", "70000").is_err());
        assert!(Policy::parse("", "", "443,8443").unwrap().port_ok(8443));
        assert!(policy("", "").port_ok(443) && !policy("", "").port_ok(80));
        // A name in the CIDR list, and a CIDR in the host list, are both errors.
        assert!(Policy::parse("api.model.test", "", "").is_err());
        assert!(Policy::parse("", "10.0.0.0/8", "").is_err());
        assert!(Policy::parse(&"10.0.0.1,".repeat(300), "", "").is_err());
    }

    #[test]
    fn hosts_match_exactly() {
        let p = policy("", "api.model.test");
        assert!(p.host_listed("api.model.test"));
        for n in [
            "model.test",
            "x.api.model.test",
            "api.model.test.evil.test",
            "API.model.test",
        ] {
            assert!(!p.host_listed(n), "{n}");
        }
    }
}
