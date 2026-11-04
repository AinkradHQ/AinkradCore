//! The dialer against a fake resolver and an in-process TLS server under a throwaway CA. Public
//! addresses are built, not written (the documentation ranges are reserved, hence refused).

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::egress::Answers;

const HOST: &str = "api.example.test";

pub(crate) fn public() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))
}

fn other_public() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(11, 0, 0, 2))
}

/// Answers from a script, one entry per lookup; the last repeats. Counts the lookups.
pub(crate) struct Script {
    answers: Mutex<VecDeque<io::Result<Vec<IpAddr>>>>,
    lookups: AtomicUsize,
}

impl Script {
    pub(crate) fn new(answers: Vec<io::Result<Vec<IpAddr>>>) -> Arc<Script> {
        Arc::new(Script {
            answers: Mutex::new(answers.into()),
            lookups: AtomicUsize::new(0),
        })
    }

    pub(crate) fn of(ips: Vec<IpAddr>) -> Arc<Script> {
        Script::new(vec![Ok(ips)])
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl Resolve for Script {
    fn resolve<'a>(&'a self, _: &'a str) -> Answers<'a> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let mut q = self.answers.lock().unwrap();
        let next = if q.len() > 1 {
            q.pop_front()
        } else {
            q.front().map(copy)
        };
        Box::pin(async move { next.unwrap() })
    }
}

fn copy(r: &io::Result<Vec<IpAddr>>) -> io::Result<Vec<IpAddr>> {
    match r {
        Ok(v) => Ok(v.clone()),
        Err(e) => Err(io::Error::new(e.kind(), "again")),
    }
}

/// Connects every dial to the local server, and records the address it was asked for: what the
/// dialer pinned. Addresses in `fail` refuse.
pub(crate) struct ToLocal {
    pub(crate) server: SocketAddr,
    pub(crate) asked: Mutex<Vec<SocketAddr>>,
    pub(crate) fail: Vec<IpAddr>,
}

impl Connect for ToLocal {
    fn connect(&self, addr: SocketAddr) -> Connecting<'_> {
        self.asked.lock().unwrap().push(addr);
        Box::pin(async move {
            if self.fail.contains(&addr.ip()) {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            TcpStream::connect(self.server).await
        })
    }
}

pub(crate) struct Ca {
    cert: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    pub(crate) fn new() -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = CertificateDer::from(params.self_signed(&key).unwrap().der().to_vec());
        Ca {
            cert,
            issuer: Issuer::new(params, key),
        }
    }

    pub(crate) fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.clone()).unwrap();
        roots
    }

    pub(crate) fn server_config(&self, name: &str) -> Arc<rustls::ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], der)
            .unwrap(),
        )
    }
}

/// A TLS server that answers every connection with `reply` and keeps the request it read.
struct Fixture {
    ca: Ca,
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
}

/// How the server ends a connection after its reply.
#[derive(Clone, Copy)]
enum End {
    /// A TLS `close_notify`, then close: a clean end of data.
    Notify,
    /// Drop the socket without `close_notify`: a truncation an attacker or a fault can cause.
    Abrupt,
    /// Keep the connection open and silent.
    Stall,
}

async fn serve(cert_name: &str, reply: &'static str) -> Fixture {
    serve_as(cert_name, reply, End::Notify).await
}

async fn serve_as(cert_name: &str, reply: &'static str, end: End) -> Fixture {
    let ca = Ca::new();
    let acceptor = TlsAcceptor::from(ca.server_config(cert_name));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&got).into_owned());
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.flush().await;
                match end {
                    End::Notify => {
                        let _ = tls.shutdown().await;
                    }
                    End::Abrupt => drop(tls),
                    End::Stall => tokio::time::sleep(Duration::from_secs(60)).await,
                }
            });
        }
    });
    Fixture { ca, addr, seen }
}

const OK: &str = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nSet-Cookie: a=b\r\n\
    X-Ratelimit-Remaining: 9\r\nanthropic-organization-id: org\r\nretry-after: 3\r\n\
    Content-Length: 2\r\n\r\n{}";

fn dialer(f: &Fixture, resolver: Arc<Script>, own: Vec<IpAddr>) -> (Dialer, Arc<ToLocal>) {
    let to = Arc::new(ToLocal {
        server: f.addr,
        asked: Mutex::new(vec![]),
        fail: vec![],
    });
    (Dialer::with(resolver, own, to.clone(), f.ca.roots()), to)
}

async fn get(d: &Dialer, host: &str) -> Result<Reply, DialError> {
    d.request(
        host,
        "POST",
        "/v1/messages",
        &[("x-api-key", "k")],
        b"{}",
        1024,
    )
    .await
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn only_a_plain_dns_name_is_a_host() {
    assert_eq!(strict_host("API.Example.test"), Ok(HOST.to_owned()));
    for bad in [
        "",
        "127.0.0.1",
        "127.1",
        "0x7f000001",
        "0x7f.0.0.1",
        "2130706433",
        "017700000001",
        "0177.0.0.1",
        "localhost",
        "intranet",
        "api",
        "unnamed.11.0.0.1.",
        "api.example.test.",
        "localhost.",
        "[::1]",
        "::1",
        "api.example.test:443",
        "user@api.example.test",
        "a b.test",
        "-a.test",
        "a..test",
        "api_x.test",
        "api.example.test/x",
        "xn--",
    ] {
        assert_eq!(strict_host(bad), Err(DialError::BadHost), "{bad:?}");
    }
}

#[tokio::test]
async fn a_bad_host_never_reaches_the_resolver_or_the_network() {
    let f = serve(HOST, OK).await;
    let script = Script::of(vec![public()]);
    let (d, to) = dialer(&f, script.clone(), vec![]);
    for bad in [
        "127.0.0.1",
        "0x7f000001",
        "2130706433",
        "017700000001",
        "api.example.test.",
    ] {
        assert_eq!(get(&d, bad).await, Err(DialError::BadHost));
    }
    assert_eq!(script.lookups(), 0);
    assert!(to.asked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_refused_address_class_is_refused_and_nothing_is_dialled() {
    let f = serve(HOST, OK).await;
    let refused = [
        // loopback, private, link-local, metadata, unspecified, multicast, shared, reserved
        ip4(127, 0, 0, 1),
        ip4(127, 255, 255, 254),
        ip4(10, 0, 0, 1),
        ip4(172, 16, 5, 5),
        ip4(192, 168, 1, 1),
        ip4(169, 254, 1, 1),
        ip4(169, 254, 169, 254),
        ip4(168, 63, 129, 16),
        ip4(100, 100, 100, 200),
        ip4(100, 64, 0, 1),
        ip4(0, 0, 0, 0),
        ip4(224, 0, 0, 1),
        ip4(255, 255, 255, 255),
        ip4(240, 0, 0, 1),
        ip4(203, 0, 113, 9),
        ip4(198, 51, 100, 9),
        ip4(192, 0, 2, 9),
        // IPv6: loopback, unspecified, ULA, link-local, site-local, multicast, metadata, doc
        v6("::1"),
        v6("::"),
        v6("fd00::1"),
        v6("fc00::1"),
        v6("fe80::1"),
        v6("fec0::1"),
        v6("ff02::1"),
        v6("fd00:ec2::254"),
        v6("2001:db8::1"),
        // IPv4 inside IPv6: mapped, NAT64, 6to4, IPv4-compatible
        v6("::ffff:127.0.0.1"),
        v6("::ffff:10.0.0.1"),
        v6("::ffff:169.254.169.254"),
        v6("::ffff:7f00:1"),
        v6("64:ff9b::7f00:1"),
        v6("64:ff9b::a9fe:a9fe"),
        v6("2002:7f00:1::"),
        v6("2002:a9fe:a9fe::1"),
        v6("::127.0.0.1"),
        // Teredo, benchmarking, IETF protocol assignments, and the special ranges of the strict policy.
        v6("2001:0:4136:e378:8000:63bf:3fff:fdd2"),
        ip4(198, 18, 0, 1),
        ip4(198, 19, 255, 255),
        ip4(192, 0, 0, 8),
        ip4(192, 88, 99, 1),
        v6("2001:2::1"),
        v6("2001:10::1"),
        v6("2001:20::1"),
        v6("3fff::1"),
        v6("5f00::1"),
        v6("::ffff:0:7f00:1"),
        v6("::2:1"),
    ];
    for ip in refused {
        let script = Script::of(vec![ip]);
        let (d, to) = dialer(&f, script, vec![]);
        let got = get(&d, HOST).await;
        assert!(matches!(got, Err(DialError::Refused(_))), "{ip}: {got:?}");
        assert!(to.asked.lock().unwrap().is_empty(), "{ip} was dialled");
    }
}

#[tokio::test]
async fn a_mixed_answer_is_refused_whole_in_either_order() {
    let f = serve(HOST, OK).await;
    for answers in [
        vec![public(), ip4(127, 0, 0, 1)],
        vec![ip4(10, 0, 0, 1), public()],
        vec![public(), other_public(), v6("::ffff:169.254.169.254")],
    ] {
        let (d, to) = dialer(&f, Script::of(answers), vec![]);
        assert!(matches!(get(&d, HOST).await, Err(DialError::Refused(_))));
        assert!(to.asked.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn this_hosts_own_addresses_are_refused() {
    let f = serve(HOST, OK).await;
    let (d, to) = dialer(&f, Script::of(vec![public()]), vec![public()]);
    assert_eq!(
        get(&d, HOST).await,
        Err(DialError::Refused(Deny::HostAddress))
    );
    assert!(to.asked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_public_answer_is_dialled_at_the_checked_address_on_443_and_verified() {
    let f = serve(HOST, OK).await;
    let script = Script::of(vec![public(), public(), other_public()]);
    let (d, to) = dialer(&f, script.clone(), vec![]);
    let reply = get(&d, HOST).await.unwrap();
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"{}");
    assert_eq!(script.lookups(), 1);
    assert_eq!(*to.asked.lock().unwrap(), [SocketAddr::new(public(), 443)]);
    // Only the allow-listed headers: no cookie, no organisation id.
    let names: Vec<&str> = reply.headers.iter().map(|h| h.0.as_str()).collect();
    assert_eq!(
        names,
        ["content-type", "x-ratelimit-remaining", "retry-after"]
    );
    // The request was built fresh and closes the connection.
    let req = f.seen.lock().unwrap()[0].clone();
    assert!(
        req.starts_with("POST /v1/messages HTTP/1.1\r\nHost: api.example.test\r\n"),
        "{req}"
    );
    for line in [
        "x-api-key: k",
        "Connection: close",
        "Accept-Encoding: identity",
        "Content-Length: 2",
    ] {
        assert!(req.contains(line), "{line} in {req}");
    }
}

#[tokio::test]
async fn the_next_checked_address_is_tried_when_the_first_does_not_answer() {
    let f = serve(HOST, OK).await;
    let to = Arc::new(ToLocal {
        server: f.addr,
        asked: Mutex::new(vec![]),
        fail: vec![public()],
    });
    let d = Dialer::with(
        Script::of(vec![public(), other_public()]),
        vec![],
        to.clone(),
        f.ca.roots(),
    );
    assert_eq!(get(&d, HOST).await.unwrap().status, 200);
    let asked: Vec<IpAddr> = to.asked.lock().unwrap().iter().map(|a| a.ip()).collect();
    assert_eq!(asked, [public(), other_public()]);
    // Nothing answers: unreachable, still only checked addresses.
    let none = Arc::new(ToLocal {
        server: f.addr,
        asked: Mutex::new(vec![]),
        fail: vec![public(), other_public()],
    });
    let d = Dialer::with(
        Script::of(vec![public(), other_public()]),
        vec![],
        none,
        f.ca.roots(),
    );
    assert_eq!(get(&d, HOST).await, Err(DialError::Unreachable));
}

#[tokio::test]
async fn rebinding_between_two_requests_is_caught_because_each_request_resolves_and_checks() {
    let f = serve(HOST, OK).await;
    // First lookup public, the next ones loopback (what a rebinding server answers).
    let script = Script::new(vec![Ok(vec![public()]), Ok(vec![ip4(127, 0, 0, 1)])]);
    let (d, to) = dialer(&f, script.clone(), vec![]);
    assert_eq!(get(&d, HOST).await.unwrap().status, 200);
    assert!(matches!(get(&d, HOST).await, Err(DialError::Refused(_))));
    assert!(matches!(get(&d, HOST).await, Err(DialError::Refused(_))));
    assert_eq!(script.lookups(), 3);
    // Only the address that passed was ever dialled, and once.
    assert_eq!(*to.asked.lock().unwrap(), [SocketAddr::new(public(), 443)]);
}

mod framing;
mod more;
