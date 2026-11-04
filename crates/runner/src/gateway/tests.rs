//! The gateway against a fake upstream: an in-process TLS server under a throwaway CA, a fake
//! resolver, and the real unix socket. Keys are built from a shape prefix and a filler, never
//! written whole, and no public address is written (the dialer tests' built ones are reused).

mod auth;
mod framing;
mod stream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{Ceiling, GatewayGrant, ModelPrice, Rate, Upstream, UserKeyDef, Wire};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use super::dial::Dialer;
use super::dial::tests::{Ca, Script, ToLocal, public};
use super::{Config, Gateway, Key, socket_in, start};

pub(super) const MODEL: &str = "model-a";

/// What the fake upstream does after it has read a request.
#[derive(Clone)]
pub(super) enum Step {
    Send(Vec<u8>),
    /// Waits for the test to open the gate.
    Wait(Arc<Notify>),
    /// Drops the connection with no `close_notify`.
    Abrupt,
    /// A clean TLS close.
    Close,
}

pub(super) struct Seen {
    pub head: String,
    pub body: Vec<u8>,
}

pub(super) struct Up {
    pub ca: Ca,
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Up {
    pub(super) fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// The request head the upstream got, lower-cased, for header assertions.
    pub(super) fn head(&self, i: usize) -> String {
        self.seen.lock().unwrap()[i].head.clone()
    }
}

/// An upstream whose certificate is for `cert_name`, running `script` on every connection.
pub(super) async fn upstream(cert_name: &str, script: Vec<Step>) -> Up {
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
            let (acceptor, log, script) = (acceptor.clone(), log.clone(), script.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut got = Vec::new();
                let mut buf = [0u8; 8192];
                let end = loop {
                    if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match tls.read(&mut buf).await {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                };
                let head = String::from_utf8_lossy(&got[..end]).into_owned();
                let want = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while got.len() < end + want {
                    match tls.read(&mut buf).await {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                log.lock().unwrap().push(Seen {
                    head,
                    body: got[end..end + want].to_vec(),
                });
                for step in script {
                    match step {
                        Step::Send(b) => {
                            let _ = tls.write_all(&b).await;
                            let _ = tls.flush().await;
                        }
                        Step::Wait(n) => n.notified().await,
                        Step::Abrupt => return drop(tls),
                        Step::Close => {
                            let _ = tls.shutdown().await;
                            return;
                        }
                    }
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    Up { ca, addr, seen }
}

/// A filler in the shape the key rule accepts: `prefix` + 24 characters.
pub(super) fn key_of(prefix: &str) -> String {
    format!("{prefix}{}", "k9".repeat(12))
}

pub(super) fn grant(wire: Wire, host: &str, base: &str, provider: &str) -> GatewayGrant {
    let price = |m: &str| ModelPrice {
        model: m.to_owned(),
        input: 1,
        output: 1,
        cache_read: 1,
        cache_write: 1,
    };
    GatewayGrant {
        lease: String::new(),
        account: 1,
        provider: provider.to_owned(),
        user_key: None,
        upstream: Upstream {
            host: host.to_owned(),
            base_path: base.to_owned(),
            wire,
            auth: wire.auth(),
        },
        // `unpriced` is allowed by name and has no price: refused.
        models: vec![MODEL.to_owned(), "unpriced".to_owned()],
        prices: vec![price(MODEL)],
        ceiling: Ceiling {
            tokens: 1_000_000,
            usd_micros: 1_000_000,
        },
        rate: Rate {
            per_minute: 600,
            concurrent: 4,
        },
    }
}

static DIRS: AtomicUsize = AtomicUsize::new(0);

pub(super) struct Rig {
    pub up: Up,
    pub key: String,
    pub sock: PathBuf,
    dir: PathBuf,
    _gw: Gateway,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) struct Opts {
    pub grant: GatewayGrant,
    pub key: String,
    /// The certificate name of the upstream.
    pub cert: String,
    pub script: Vec<Step>,
    pub answers: Vec<std::net::IpAddr>,
    pub limits: Option<(usize, usize)>,
}

impl Opts {
    pub(super) fn anthropic(script: Vec<Step>) -> Opts {
        Opts::of(
            Wire::AnthropicMessages,
            "api.anthropic.com",
            "",
            "anthropic",
            "sk-ant-",
            script,
        )
    }

    pub(super) fn of(
        wire: Wire,
        host: &str,
        base: &str,
        provider: &str,
        prefix: &str,
        script: Vec<Step>,
    ) -> Opts {
        Opts {
            grant: grant(wire, host, base, provider),
            key: key_of(prefix),
            cert: host.to_owned(),
            script,
            answers: vec![public()],
            limits: None,
        }
    }
}

pub(super) async fn rig(o: Opts) -> Rig {
    let up = upstream(&o.cert, o.script).await;
    let to = Arc::new(ToLocal {
        server: up.addr,
        asked: Mutex::new(vec![]),
        fail: vec![],
    });
    let dialer = Arc::new(Dialer::with(
        Script::of(o.answers),
        vec![],
        to,
        up.ca.roots(),
    ));
    let key = Key::new(Zeroizing::new(o.key.clone())).unwrap();
    let mut cfg = Config::new(&o.grant, key, dialer).unwrap();
    if let Some((req, resp)) = o.limits {
        cfg = cfg.with_limits(req, resp);
    }
    let dir = std::env::temp_dir().join(format!(
        "gw-{}-{}",
        std::process::id(),
        DIRS.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = socket_in(&dir);
    let gw = start(&sock, cfg).unwrap();
    Rig {
        up,
        key: o.key,
        sock,
        dir,
        _gw: gw,
    }
}

/// Sends `bytes` and reads until the gateway closes (or 5 seconds).
pub(super) async fn raw(sock: &std::path::Path, bytes: &[u8]) -> Vec<u8> {
    let mut c = UnixStream::connect(sock).await.unwrap();
    let _ = c.write_all(bytes).await; // a refusal may close before the body is all written
    let mut out = Vec::new();
    let _ = timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
    out
}

pub(super) fn status(resp: &[u8]) -> u16 {
    String::from_utf8_lossy(resp)
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// A request: `head_lines` after the request line, a JSON `body` and its `Content-Length`.
pub(super) fn request(line: &str, head_lines: &[&str], body: &str) -> Vec<u8> {
    let mut s = format!("{line}\r\nHost: 127.0.0.1\r\n");
    for l in head_lines {
        s.push_str(l);
        s.push_str("\r\n");
    }
    s.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    s.into_bytes()
}

pub(super) fn body_of(resp: &[u8]) -> String {
    let text = String::from_utf8_lossy(resp);
    text.split_once("\r\n\r\n")
        .map(|x| x.1.to_owned())
        .unwrap_or_default()
}

pub(super) const OK_JSON: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";

pub(super) fn ok_script() -> Vec<Step> {
    vec![Step::Send(OK_JSON.as_bytes().to_vec())]
}

pub(super) fn model_body() -> String {
    format!("{{\"model\":\"{MODEL}\",\"max_tokens\":8}}")
}

pub(super) fn user_def() -> UserKeyDef {
    UserKeyDef {
        prefix: "sk-or-v1-".to_owned(),
        host: "openrouter.example.test".to_owned(),
    }
}
