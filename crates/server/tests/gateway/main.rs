//! The gateway (E1-06): one matrix runs the same assertions over the three listener modes —
//! a Unix socket, loopback, and public TLS with a stored certificate (the ACME order itself
//! is `pebble.rs`, behind an environment variable) — plus what only public has: TLS 1.3 only
//! and HTTP/2. `renewal` swaps certificates under a held connection; `drain` stops a server
//! with requests in flight.

mod common;
mod drain;
mod limits;
mod pebble;
mod renewal;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::api::router;
use ainkrad_core_server::gateway::{Gateway, Limits, Listen, acme::Acme};
use common::{Ca, Fx, Io, get, tls};
use tokio::sync::watch;

/// A gateway serving the whole API in a background task.
pub struct Running {
    pub closing: Arc<watch::Sender<bool>>,
    pub served: tokio::task::JoinHandle<std::io::Result<()>>,
    pub host: String,
    pub target: Target,
    pub certs: Option<Arc<ainkrad_core_server::gateway::tls::Certs>>,
}

pub enum Target {
    Unix(PathBuf),
    Tcp(u16),
    Tls(u16),
}

impl Running {
    pub async fn connect(&self, ca: &Ca) -> Box<dyn Io> {
        match &self.target {
            Target::Unix(path) => Box::new(tokio::net::UnixStream::connect(path).await.unwrap()),
            Target::Tcp(port) => Box::new(
                tokio::net::TcpStream::connect(("127.0.0.1", *port))
                    .await
                    .unwrap(),
            ),
            Target::Tls(port) => Box::new(tls(ca, *port).await.unwrap()),
        }
    }

    pub async fn stop(self) {
        self.closing.send_replace(true);
        let served = tokio::time::timeout(Duration::from_secs(10), self.served).await;
        served.expect("drains in time").unwrap().unwrap();
    }
}

/// An ACME config for `localhost` that never needs its directory while the stored
/// certificate is young.
pub fn acme(fx: &Fx) -> Acme {
    Acme {
        hostname: "localhost".to_owned(),
        contact: "ops@example.test".to_owned(),
        directory: "https://127.0.0.1:1/directory".to_owned(),
        http01: false,
        ca_root: None,
        dir: fx.dir.join("tls"),
    }
}

/// Starts `mode` (`unix`, `loopback`, `public`) on `fx`'s database. Public gets a 90-day
/// certificate from `ca`, stored as ACME would store it.
pub async fn start(fx: &Fx, mode: &str, ca: &Ca) -> Running {
    let listen = match mode {
        "unix" => Listen::Unix(format!("/tmp/ak-{}-{mode}.sock", std::process::id()).into()),
        "loopback" => Listen::Tcp("127.0.0.1:0".to_owned()),
        "public" => {
            let acme = acme(fx);
            let (chain, key) = ca.leaf(90);
            acme.store_cert(&chain, &key).unwrap();
            Listen::Public {
                port: 0,
                http01: None,
                acme,
            }
        }
        _ => unreachable!(),
    };
    let gateway = Gateway::bind(listen.clone(), Limits::default())
        .await
        .unwrap();
    let port = gateway.local_addr().map(|a| a.port());
    let (host, target) = match (&listen, port) {
        (Listen::Unix(path), _) => ("localhost".to_owned(), Target::Unix(path.clone())),
        (Listen::Tcp(_), Some(p)) => (format!("127.0.0.1:{p}"), Target::Tcp(p)),
        (Listen::Public { .. }, Some(p)) => (format!("localhost:{p}"), Target::Tls(p)),
        _ => unreachable!(),
    };
    let app = fx.app(&host);
    let closing = Arc::clone(&app.closing);
    let certs = gateway.certs();
    let served =
        tokio::spawn(gateway.serve(router(app), Arc::clone(&closing), Duration::from_secs(5)));
    Running {
        closing,
        served,
        host,
        target,
        certs,
    }
}

#[tokio::test]
async fn every_mode_serves_the_same_surface() {
    let ca = Ca::new();
    for mode in ["unix", "loopback", "public"] {
        let fx = Fx::new(&format!("matrix-{mode}")).await;
        let running = start(&fx, mode, &ca).await;
        let host = running.host.clone();
        let mut io = running.connect(&ca).await;
        // One kept-alive connection through the whole surface.
        assert_eq!(
            get(&mut io, "/healthz", &host, None).await,
            (200, "ok".into()),
            "{mode}"
        );
        let (status, body) = get(&mut io, "/handshake", &host, None).await;
        assert_eq!(status, 200, "{mode}: {body}");
        assert!(body.contains("\"api_minor\""), "{mode}: {body}");
        for path in ["/api/v1/me", "/nope", "/.well-known/acme-challenge/x"] {
            let (status, body) = get(&mut io, path, &host, None).await;
            assert_eq!(status, 401, "{mode} {path}: {body}");
        }
        let (status, body) = get(&mut io, "/api/v1/me", &host, Some(&fx.key)).await;
        assert_eq!(status, 200, "{mode}: {body}");
        assert!(body.contains("\"mac\""), "{mode}: {body}");
        let (status, _) = get(&mut io, "/handshake", "rebound.example", None).await;
        assert_eq!(status, 403, "{mode}: the Host check holds");

        if let Target::Unix(path) = &running.target {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the socket is the user's only");
        }
        if mode == "public" {
            use std::os::unix::fs::PermissionsExt;
            for file in ["cert.pem", "key.pem"] {
                let meta = std::fs::metadata(fx.dir.join("tls").join(file)).unwrap();
                assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{file}");
            }
            let meta = std::fs::metadata(fx.dir.join("tls")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }
        drop(io);
        running.stop().await;
    }
}

#[tokio::test]
async fn public_is_tls_1_3_only_and_speaks_http_2() {
    let ca = Ca::new();
    let fx = Fx::new("tls").await;
    let running = start(&fx, "public", &ca).await;
    let Target::Tls(port) = running.target else {
        unreachable!()
    };
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    // A TLS 1.2-only client is refused at the handshake.
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let old = ca.client(&[&rustls::version::TLS12], &[b"http/1.1"]);
    let refused = old.connect(name.clone(), tcp).await;
    assert!(refused.is_err(), "TLS 1.2 must be refused");

    // HTTP/2 over TLS 1.3.
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let h2 = ca.client(&[&rustls::version::TLS13], &[b"h2"]);
    let stream = h2.connect(name, tcp).await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        stream.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let req = hyper::Request::get(format!("https://{}/healthz", running.host))
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .unwrap();
    let res = send.send_request(req).await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.version(), hyper::Version::HTTP_2);
    running.stop().await;
}
