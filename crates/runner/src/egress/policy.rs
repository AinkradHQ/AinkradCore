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

    /// A single-host entry for exactly `ip`.
    fn is_exact(&self, ip: IpAddr) -> bool {
        self.addr == ip && self.prefix == bits(ip).1
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
    /// One of this host's own interface addresses.
    HostAddress,
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
        Cidr::v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
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
    /// The host's own interface addresses: never a destination, whatever the CIDRs say.
    own: Vec<IpAddr>,
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
            own: vec![],
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

    /// Adds the host's own interface addresses (`host_addresses`): a host with a public address on an
    /// interface would otherwise let `0.0.0.0/0` reach its own services.
    pub fn with_host_addresses(mut self, addrs: impl IntoIterator<Item = IpAddr>) -> Policy {
        self.own = addrs.into_iter().map(normalise).collect();
        self
    }

    /// The address to dial for `ip`, or why not. `named`: the address came from resolving a
    /// listed name, so it needs no CIDR (but is still subject to the reserved ranges).
    pub fn check_ip(&self, ip: IpAddr, named: bool) -> Result<IpAddr, Deny> {
        let ip = normalise(ip);
        self.never(ip)?;
        let allowed = self.cidrs.iter().any(|c| c.contains(ip));
        if !allowed && !named {
            return Err(Deny::NotListed);
        }
        self.gate(ip)?;
        // An IPv4 address carried inside a NAT64 or 6to4 address is the real destination of a
        // translated connection: it gets the same checks.
        if let Some(inner) = embedded_v4(ip) {
            self.never(inner)?;
            self.gate(inner)?;
        }
        Ok(ip)
    }

    /// Addresses that need more than a covering CIDR. The metadata addresses are never reachable.
    /// A host address (an interface address of this machine, any of 127.0.0.0/8, ::1) is reachable
    /// only through an EXACT single-host entry (/32 or /128) naming it: a local model's own entry.
    /// A broader CIDR that happens to contain one does not open it. The reserved ranges still
    /// apply afterwards (`gate`), so that entry must also sit inside a reserved range it names.
    fn never(&self, ip: IpAddr) -> Result<(), Deny> {
        if metadata().iter().any(|m| m.contains(ip)) {
            return Err(Deny::Metadata);
        }
        let host = self.own.contains(&ip)
            || match ip {
                IpAddr::V4(a) => a.is_loopback(),
                IpAddr::V6(a) => a.is_loopback(),
            };
        if host && !self.cidrs.iter().any(|c| c.is_exact(ip)) {
            return Err(Deny::HostAddress);
        }
        Ok(())
    }

    /// Reserved ranges are subtracted unless a CIDR inside that range names the address.
    fn gate(&self, ip: IpAddr) -> Result<(), Deny> {
        for range in self.reserved.iter().filter(|r| r.contains(ip)) {
            let named_inside = self.cidrs.iter().any(|c| c.contains(ip) && c.within(range));
            if !named_inside {
                return Err(Deny::Reserved);
            }
        }
        Ok(())
    }
}

/// The IPv4 address inside a NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address.
fn embedded_v4(ip: IpAddr) -> Option<IpAddr> {
    let IpAddr::V6(a) = ip else { return None };
    let s = a.segments();
    let octets = if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        [s[6].to_be_bytes(), s[7].to_be_bytes()]
    } else if s[0] == 0x2002 {
        [s[1].to_be_bytes(), s[2].to_be_bytes()]
    } else {
        return None;
    };
    let [[a, b], [c, d]] = octets;
    Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

/// The host's own interface addresses, from `/proc` (no unsafe, no extra tool), read once when the
/// runner starts: an interface added later (docker0, a VPN) is not covered. A table that cannot be
/// read, or that does not even list the loopback address, is an error: a runner that cannot list
/// its addresses does not start filtering.
pub fn host_addresses() -> Result<Vec<IpAddr>, String> {
    if !cfg!(target_os = "linux") {
        return Ok(vec![]);
    }
    let v4 = std::fs::read_to_string("/proc/net/fib_trie")
        .map_err(|_| "cannot list the host's IPv4 addresses".to_owned())?;
    let mut all = parse_fib_trie(&v4);
    // IPv6 may be switched off, which removes the file.
    if let Ok(v6) = std::fs::read_to_string("/proc/net/if_inet6") {
        all.extend(parse_if_inet6(&v6));
    }
    all.sort();
    all.dedup();
    if !all.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)) {
        return Err("the host's IPv4 address table is empty or unreadable".to_owned());
    }
    Ok(all)
}

/// `/proc/net/fib_trie`: an address line (`|-- a.b.c.d`) followed by `/32 host LOCAL`.
fn parse_fib_trie(text: &str) -> Vec<IpAddr> {
    let mut last = None;
    let mut out = vec![];
    for line in text.lines().map(str::trim) {
        if let Some(addr) = line.strip_prefix("|-- ") {
            last = addr.parse::<Ipv4Addr>().ok();
        } else if line.starts_with("/32 host LOCAL") {
            out.extend(last.map(IpAddr::V4));
        }
    }
    out
}

/// `/proc/net/if_inet6`: the address as 32 hex digits, first on each line.
fn parse_if_inet6(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let hex = l.split_whitespace().next().filter(|h| h.len() == 32)?;
            u128::from_str_radix(hex, 16)
                .ok()
                .map(|v| IpAddr::V6(Ipv6Addr::from(v)))
        })
        .collect()
}

#[cfg(test)]
mod tests;
