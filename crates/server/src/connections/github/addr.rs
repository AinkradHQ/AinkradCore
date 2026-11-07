//! Where an upstream may be (C2): the public-address rule every lookup answer must pass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is somewhere an upstream may be: not this host, not a private, shared, link-local
/// (cloud metadata), documentation, multicast, reserved or translation range.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(a),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => public_v4(v4),
            None => public_v6(a),
        },
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    !(a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o0 == 0
        || o0 >= 240
        || (o0 == 100 && (o1 & 0xc0) == 64)
        || (o0 == 192 && o1 == 0 && o2 == 0)
        || (o0 == 198 && (o1 & 0xfe) == 18)
        || (o0 == 192 && o1 == 88 && o2 == 99))
}

fn public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    !(a.is_loopback()
        || a.is_unspecified()
        || a.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || s[..6] == [0; 6]
        // ::ffff:0:0:0/96, IPv4-translated (SIIT).
        || (s[..4] == [0; 4] && s[4] == 0xffff && s[5] == 0)
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || s[0] == 0x2002
        || (s[0] == 0x0064 && s[1] == 0xff9b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_pass() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        for ip in [
            v4(127, 0, 0, 1),
            v4(10, 0, 0, 1),
            v4(192, 168, 1, 1),
            v4(172, 16, 0, 1),
            v4(169, 254, 169, 254),
            v4(100, 64, 0, 1),
            v4(0, 0, 0, 0),
            v4(224, 0, 0, 1),
            v4(240, 0, 0, 1),
            v4(198, 18, 0, 1),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fd00::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
            IpAddr::V6("64:ff9b::7f00:1".parse().unwrap()),
            IpAddr::V6("64:ff9b:1::1".parse().unwrap()),
            IpAddr::V6("::7f00:1".parse().unwrap()),
            IpAddr::V6("::8c52:7005".parse().unwrap()),
            IpAddr::V6("2001:0:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()),
            IpAddr::V6("fec0::1".parse().unwrap()),
            v4(192, 88, 99, 1),
            IpAddr::V6("::ffff:0:7f00:1".parse().unwrap()),
            IpAddr::V6("::ffff:0:8c52:7005".parse().unwrap()),
        ] {
            assert!(!public(ip), "{ip}");
        }
        assert!(public(v4(140, 82, 112, 5)));
        assert!(public(IpAddr::V6("2606:50c0:8000::1".parse().unwrap())));
    }
}
