//! The Host router's pure parts: which names are project hosts, the header filter, host-only
//! cookies and the primary port.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue};
use serde_json::json;

use super::*;

#[test]
fn only_one_unreserved_label_under_the_domain_is_a_project_host() {
    let l = |n| label(n, "ainkrad.io", "core.ainkrad.io");
    assert_eq!(l("shop.ainkrad.io").as_deref(), Some("shop"));
    assert_eq!(l("SHOP.Ainkrad.IO.").as_deref(), Some("shop"));
    assert_eq!(l("my-shop-web.ainkrad.io").as_deref(), Some("my-shop-web"));
    for not in [
        "core.ainkrad.io",
        "signin.ainkrad.io",
        "www.ainkrad.io",
        "api.ainkrad.io",
        "ainkrad.io",
        ".ainkrad.io",
        "a.b.ainkrad.io",
        "shopainkrad.io",
        "shop.ainkrad.io.evil.test",
        "shop_x.ainkrad.io",
        "localhost",
    ] {
        assert_eq!(l(not), None, "{not}");
    }
    // The Core's host is never one, even when it would be a label under the domain.
    assert_eq!(
        label("ops.ainkrad.io", "ainkrad.io", "ops.ainkrad.io"),
        None
    );
}

#[test]
fn hop_by_hop_proxy_and_core_headers_are_not_forwarded() {
    let mut h = HeaderMap::new();
    for (n, v) in [
        ("connection", "close, x-named"),
        ("x-named", "1"),
        ("keep-alive", "5"),
        ("te", "trailers"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "h2c"),
        ("proxy-authorization", "Basic x"),
        ("host", "core.ainkrad.io"),
        ("forwarded", "for=1.2.3.4"),
        ("x-forwarded-for", "1.2.3.4"),
        ("x-real-ip", "1.2.3.4"),
        ("x-ainkrad-session", "s_1"),
        ("accept", "text/html"),
        ("cookie", "app=1"),
    ] {
        h.append(n, HeaderValue::from_static(v));
    }
    let out = forwardable(&h, false);
    let mut names: Vec<_> = out.keys().map(|k| k.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["accept", "cookie"]);
}

#[test]
fn a_project_cookie_stays_on_its_own_host() {
    assert_eq!(host_only("a=1; Domain=.ainkrad.io; Path=/"), "a=1; Path=/");
    assert_eq!(host_only("a=1;domain=ainkrad.io;Secure"), "a=1;Secure");
    // A cookie whose NAME starts with "domain" is kept.
    assert_eq!(host_only("domainy=1; HttpOnly"), "domainy=1; HttpOnly");
    assert_eq!(host_only("a=1"), "a=1");
}

#[test]
fn ports_come_off_a_host_but_not_off_anything_else() {
    assert_eq!(strip_port("shop.ainkrad.io:443"), "shop.ainkrad.io");
    assert_eq!(strip_port("shop.ainkrad.io"), "shop.ainkrad.io");
    assert_eq!(strip_port("shop.ainkrad.io:"), "shop.ainkrad.io:");
}

#[test]
fn the_primary_port_is_webs_else_the_first_exposed_by_name() {
    let spec = |v| crate::store::run_specs::spec::parse(&v).unwrap();
    let both = spec(json!({"services": {
        "api": {"image": "node:22", "ports": [{"port": 4000, "expose": true}]},
        "web": {"image": "node:22", "ports": [{"port": 9, "expose": false},
                                              {"port": 3000, "expose": true}]},
        "db": {"image": "postgres:17", "ports": [{"port": 5432}]}}}));
    assert_eq!(target(&both, None), Some(("web".into(), 3000)));
    assert_eq!(target(&both, Some("api")), Some(("api".into(), 4000)));
    assert_eq!(target(&both, Some("db")), None);
    assert_eq!(target(&both, Some("nope")), None);
    let no_web = spec(json!({"services": {
        "b": {"image": "node:22", "ports": [{"port": 2, "expose": true}]},
        "a": {"image": "node:22", "ports": [{"port": 1, "expose": true}]}}}));
    assert_eq!(target(&no_web, None), Some(("a".into(), 1)));
    let none = spec(json!({"services": {"db": {"image": "postgres:17"}}}));
    assert_eq!(target(&none, None), None);
}

#[test]
fn client_claims_pass_only_from_the_edge() {
    let mut h = HeaderMap::new();
    for (n, v) in [
        ("cf-connecting-ip", "6.6.6.6"),
        ("cf-ipcountry", "XX"),
        ("true-client-ip", "6.6.6.6"),
        ("x-client-ip", "6.6.6.6"),
        ("client-ip", "6.6.6.6"),
        ("accept", "text/html"),
    ] {
        h.append(n, HeaderValue::from_static(v));
    }
    let names = |m: HeaderMap| {
        let mut n: Vec<String> = m.keys().map(|k| k.to_string()).collect();
        n.sort_unstable();
        n
    };
    assert_eq!(names(forwardable(&h, false)), ["accept"]);
    assert_eq!(names(forwardable(&h, true)).len(), 6);
}

#[test]
fn the_client_is_cf_connecting_ip_only_from_a_cloudflare_peer() {
    let edge = edge(&[]);
    let req = |peer: &str, cf: Option<&str>| {
        let mut b = axum::http::Request::get("/");
        if let Some(cf) = cf {
            b = b.header("cf-connecting-ip", cf);
        }
        let mut r = b.body(Body::empty()).unwrap();
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 443)));
        r
    };
    let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
    // Direct: the peer, whatever it claims.
    assert_eq!(
        client_ip(&req("203.0.113.9", Some("6.6.6.6")), &edge),
        (ip("203.0.113.9"), false)
    );
    // Through Cloudflare: its header; the edge itself when it sends none or junk.
    assert_eq!(
        client_ip(&req("104.16.0.1", Some("198.51.100.4")), &edge),
        (ip("198.51.100.4"), true)
    );
    assert_eq!(
        client_ip(&req("2606:4700::1", Some("2001:db8::7")), &edge),
        (ip("2001:db8::7"), true)
    );
    assert_eq!(
        client_ip(&req("104.16.0.1", Some("nope")), &edge),
        (ip("104.16.0.1"), true)
    );
    assert_eq!(
        client_ip(&req("104.16.0.1", None), &edge),
        (ip("104.16.0.1"), true)
    );
    // `--trusted-proxy` widens the edge (a local tunnel).
    let local = super::edge(&crate::api::limit::Cidr::LOOPBACK);
    assert_eq!(
        client_ip(&req("127.0.0.1", Some("198.51.100.4")), &local),
        (ip("198.51.100.4"), true)
    );
    // No peer (an in-process call): no client address.
    let bare = axum::http::Request::get("/").body(Body::empty()).unwrap();
    assert_eq!(client_ip(&bare, &edge), (None, false));
}

#[test]
fn a_held_place_comes_back_on_drop_and_empty_keys_go() {
    let counts: Counts<i64> = Counts::default();
    let a: Vec<_> = (0..2).map(|_| hold(&counts, 1, 2).unwrap()).collect();
    assert!(hold(&counts, 1, 2).is_none(), "the cap holds");
    let other = hold(&counts, 2, 2).unwrap();
    drop(a);
    assert!(hold(&counts, 1, 2).is_some(), "given back");
    drop(other);
    assert!(counts.lock().unwrap().is_empty(), "no key is kept at 0");
}
