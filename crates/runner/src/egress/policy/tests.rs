use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
/// An address in routable space. The documentation ranges cannot stand in for it: the policy
/// reserves them, so they are never allowed. Built, not written, and not a real service.
fn public() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))
}
fn policy(cidrs: &str, hosts: &str) -> Policy {
    Policy::parse(cidrs, hosts, "").unwrap()
}

#[test]
fn cidrs_parse_and_match() {
    let c = Cidr::parse("10.1.2.3/8").unwrap();
    assert!(c.contains(ip("10.200.0.1")) && !c.contains(ip("172.16.0.1")));
    assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(public()));
    assert!(!Cidr::parse("0.0.0.0/0").unwrap().contains(ip("::1")));
    assert!(Cidr::parse("::/0").unwrap().contains(ip("2a0f:ffff::1")));
    assert!(Cidr::parse("127.0.0.1").unwrap().contains(ip("127.0.0.1")));
    for bad in [
        "",
        "203.0.113.4/33",
        "::/129",
        "1.2.3/24",
        "a/8",
        "203.0.113.4/",
        "203.0.113.4/+8",
        "::ffff:203.0.113.4/128",
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
        "2001:0:c000:221:8000:1234:3fff:fdd2",
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
        "203.0.113.4",
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
    let e = Policy::parse("", "api.model.test,203.0.113.4", "").unwrap_err();
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

#[test]
fn an_ipv4_inside_nat64_or_6to4_gets_the_ipv4_checks() {
    // The operator opened the translation prefixes on purpose; what they carry is still checked.
    let p = policy("64:ff9b::/96,2002::/16", "");
    assert_eq!(
        p.check_ip(ip("64:ff9b::a9fe:a9fe"), false),
        Err(Deny::Metadata)
    );
    assert_eq!(
        p.check_ip(ip("2002:a9fe:a9fe::"), false),
        Err(Deny::Metadata)
    );
    assert_eq!(
        p.check_ip(ip("64:ff9b::7f00:1"), false),
        Err(Deny::Reserved)
    );
    assert_eq!(p.check_ip(ip("64:ff9b::a00:1"), false), Err(Deny::Reserved));
    assert_eq!(
        p.check_ip(ip("2002:c0a8:101::"), false),
        Err(Deny::Reserved)
    );
    assert!(
        p.check_ip(ip("64:ff9b::b00:1"), false).is_ok(),
        "a routable embedded address"
    );
    assert!(p.check_ip(ip("2002:b00:1::"), false).is_ok());
    // A v4 CIDR inside the reserved range names it, and then the translated form is allowed too.
    let p = policy("64:ff9b::/96,10.9.0.0/16", "");
    assert!(p.check_ip(ip("64:ff9b::a09:1"), false).is_ok());
    assert_eq!(p.check_ip(ip("64:ff9b::a08:1"), false), Err(Deny::Reserved));
}

#[test]
fn the_hosts_own_addresses_are_never_destinations() {
    let v4 = |d| IpAddr::V4(Ipv4Addr::new(11, 0, 0, d));
    let mapped = |d| IpAddr::V6(Ipv4Addr::new(11, 0, 0, d).to_ipv6_mapped());
    let own = [v4(1), ip("2a0f:ffff::7"), mapped(2)];
    let p = policy("0.0.0.0/0,::/0", "").with_host_addresses(own);
    for a in [v4(1), ip("2a0f:ffff::7"), v4(2), mapped(1)] {
        assert_eq!(p.check_ip(a, false), Err(Deny::HostAddress), "{a}");
        assert_eq!(p.check_ip(a, true), Err(Deny::HostAddress), "{a}");
    }
    assert!(p.check_ip(v4(3), false).is_ok());
}

#[test]
fn the_proc_tables_parse_into_addresses() {
    let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     +-- 10.0.0.0/24 2 0 2\n        |-- 10.0.0.4\n           /32 host LOCAL\n        |-- 10.0.0.255\n           /32 link BROADCAST\n     |-- 127.0.0.1\n        /32 host LOCAL\nLocal:\n     |-- 127.0.0.1\n        /32 host LOCAL\n";
    assert_eq!(
        parse_fib_trie(trie),
        [ip("10.0.0.4"), ip("127.0.0.1"), ip("127.0.0.1")]
    );
    let inet6 = "fe80000000000000000000000000abcd 02 40 20 80 eth0\n00000000000000000000000000000001 01 80 10 80 lo\nshort 01\n";
    assert_eq!(parse_if_inet6(inet6), [ip("fe80::abcd"), ip("::1")]);
    assert_eq!(parse_fib_trie("garbage"), Vec::<IpAddr>::new());
    // On the real host (Linux) the call works and lists loopback.
    if cfg!(target_os = "linux") {
        assert!(host_addresses().unwrap().contains(&ip("127.0.0.1")));
    }
}

#[test]
fn a_host_address_needs_an_exact_entry_and_a_covering_cidr_does_not_open_it() {
    let v4 = |d| IpAddr::V4(Ipv4Addr::new(11, 0, 0, d));
    let own = [v4(1), ip("127.0.0.1")];
    // The local model: an exact single-host entry opens exactly that address.
    let p = policy("127.0.0.1/32", "").with_host_addresses(own);
    assert_eq!(p.check_ip(ip("127.0.0.1"), false), Ok(ip("127.0.0.1")));
    assert_eq!(p.check_ip(ip("127.0.0.1"), true), Ok(ip("127.0.0.1")));
    // ... and not its neighbour, which is a host address too (all of 127.0.0.0/8 is).
    assert_eq!(p.check_ip(ip("127.0.0.2"), false), Err(Deny::HostAddress));
    assert_eq!(p.check_ip(ip("::1"), false), Err(Deny::HostAddress));
    // Nothing allowed: 127.0.0.2 is refused as a host address, not slipped through.
    let none = policy("", "").with_host_addresses(own);
    assert_eq!(none.check_ip(ip("127.0.0.2"), true), Err(Deny::HostAddress));
    // A CIDR that merely contains a host address does not open it, however broad.
    let around = format!("{}/24", v4(0));
    for wide in ["127.0.0.0/8", "127.0.0.0/24", "0.0.0.0/0", around.as_str()] {
        let p = policy(wide, "").with_host_addresses(own);
        for a in [v4(1), ip("127.0.0.1"), ip("127.0.0.2")] {
            assert_eq!(p.check_ip(a, false), Err(Deny::HostAddress), "{wide} {a}");
        }
    }
    // A public host address with its exact entry works (not a reserved range, so no gate).
    let p = policy(&format!("{}/32", v4(1)), "").with_host_addresses(own);
    assert_eq!(p.check_ip(v4(1), false), Ok(v4(1)));
    assert_eq!(p.check_ip(v4(2), false), Err(Deny::NotListed));
    // The IPv6 loopback with its exact entry.
    let p = policy("::1/128", "");
    assert_eq!(p.check_ip(ip("::1"), false), Ok(ip("::1")));
}

#[test]
fn an_exact_entry_never_overrides_the_metadata_or_the_reserved_ranges() {
    let own = [ip("169.254.169.254"), ip("10.1.2.3")];
    let p = policy(
        "169.254.169.254/32,fd00:ec2::254/128,10.1.2.3/32,fe80::1/128",
        "",
    )
    .with_host_addresses(own);
    assert_eq!(
        p.check_ip(ip("169.254.169.254"), false),
        Err(Deny::Metadata)
    );
    assert_eq!(p.check_ip(ip("fd00:ec2::254"), true), Err(Deny::Metadata));
    // An exact entry names that single address inside a reserved range, which is the local-model
    // rule; a CIDR that is the whole range or wider does not.
    assert_eq!(p.check_ip(ip("10.1.2.3"), false), Ok(ip("10.1.2.3")));
    let wide = policy("0.0.0.0/0,::/0", "").with_host_addresses(own);
    assert_eq!(wide.check_ip(ip("10.1.2.3"), false), Err(Deny::HostAddress));
    assert_eq!(wide.check_ip(ip("10.1.2.4"), false), Err(Deny::Reserved));
}
