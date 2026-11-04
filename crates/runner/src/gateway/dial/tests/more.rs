//! The rest of the dialer tests; shares the fixtures of the parent module.

use super::*;

type Case<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

#[tokio::test]
async fn a_certificate_for_another_name_or_another_ca_is_refused() {
    // Valid chain, wrong name.
    let f = serve("other.example.test", OK).await;
    let (d, _) = dialer(&f, Script::of(vec![public()]), vec![]);
    assert_eq!(get(&d, HOST).await, Err(DialError::Tls));
    // Right name, a CA the dialer does not trust.
    let f = serve(HOST, OK).await;
    let to = Arc::new(ToLocal {
        server: f.addr,
        asked: Mutex::new(vec![]),
        fail: vec![],
    });
    let d = Dialer::with(
        Script::of(vec![public()]),
        vec![],
        to,
        rustls::RootCertStore::empty(),
    );
    assert_eq!(get(&d, HOST).await, Err(DialError::Tls));
}

#[tokio::test]
async fn a_redirect_is_returned_not_followed_and_its_location_is_dropped() {
    let f = serve(
        HOST,
        "HTTP/1.1 302 Found\r\nLocation: https://metadata.example.test/\r\ncontent-type: text/plain\r\n\r\n",
    )
    .await;
    let (d, to) = dialer(&f, Script::of(vec![public()]), vec![]);
    let reply = get(&d, HOST).await.unwrap();
    assert_eq!(reply.status, 302);
    assert!(reply.headers.iter().all(|h| h.0 != "location"));
    assert_eq!(to.asked.lock().unwrap().len(), 1);
    assert_eq!(f.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn resolver_failures_and_empty_answers_are_a_resolve_error() {
    let f = serve(HOST, OK).await;
    for script in [
        Script::new(vec![Err(io::Error::other("nxdomain"))]),
        Script::of(vec![]),
    ] {
        let (d, to) = dialer(&f, script, vec![]);
        assert_eq!(get(&d, HOST).await, Err(DialError::Resolve));
        assert!(to.asked.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_request_that_could_smuggle_a_header_or_override_the_framing_is_not_sent() {
    let f = serve(HOST, OK).await;
    let script = Script::of(vec![public()]);
    let (d, to) = dialer(&f, script.clone(), vec![]);
    let cases: Vec<Case> = vec![
        ("POST", "/x", &[("x-a", "v\r\nHost: evil.test")]),
        ("POST", "/x", &[("x-a\r\nb", "v")]),
        ("POST", "/x", &[("Host", "evil.test")]),
        ("POST", "/x", &[("Content-Length", "0")]),
        ("POST", "/x", &[("Transfer-Encoding", "chunked")]),
        ("POST", "/x y", &[]),
        ("POST", "x", &[]),
        ("CONNECT", "/x", &[]),
        ("POST", "/x", &[("Expect", "100-continue")]),
        ("POST", "/x", &[("TE", "trailers")]),
        ("POST", "/x", &[("Upgrade", "websocket")]),
        ("POST", "/x", &[("Trailer", "x")]),
        ("POST", "/x", &[("Keep-Alive", "timeout=5")]),
    ];
    for (method, path, headers) in cases {
        let got = d.request(HOST, method, path, headers, b"", 16).await;
        assert_eq!(
            got,
            Err(DialError::BadRequest),
            "{method} {path} {headers:?}"
        );
    }
    assert!(to.asked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_body_is_bounded_and_a_broken_head_is_an_upstream_error() {
    let f = serve(HOST, "HTTP/1.1 200 OK\r\n\r\n0123456789").await;
    let (d, _) = dialer(&f, Script::of(vec![public()]), vec![]);
    let reply = d.request(HOST, "GET", "/x", &[], b"", 4).await.unwrap();
    assert_eq!(reply.body, b"0123");
    assert!(reply.truncated);
    let f = serve(HOST, "garbage\r\n\r\n").await;
    let (d, _) = dialer(&f, Script::of(vec![public()]), vec![]);
    assert_eq!(
        d.request(HOST, "GET", "/x", &[], b"", 4).await,
        Err(DialError::Upstream)
    );
}

#[test]
fn the_strict_policy_has_no_operator_input_and_allows_only_the_public_internet_on_443() {
    let p = Policy::strict();
    assert!(p.port_ok(443) && !p.port_ok(8443) && !p.port_ok(80));
    assert_eq!(p.counts(), (0, 0, 1));
    assert!(p.check_ip(public(), true).is_ok());
    // Control: an operator's CIDR does open 10.0.0.1 for the egress proxy; the strict policy
    // is built without any list, so the same address stays refused.
    let operator = Policy::parse("10.0.0.0/8", "", "").unwrap();
    assert!(operator.check_ip(ip4(10, 0, 0, 1), true).is_ok());
    for ip in [ip4(10, 0, 0, 1), ip4(127, 0, 0, 1), ip4(169, 254, 169, 254)] {
        assert!(p.check_ip(ip, true).is_err());
    }
}
