//! The strict upstream dialer of the auth gateway (KAN-435 G2, spec 4.4).
//!
//! One request, one connection: resolve the host (bounded), check **every** answer against
//! [`Policy::strict`], dial the address that was checked (never a second lookup), verify the TLS
//! certificate against the host name with the bundled roots only, send `Connection: close`, never
//! follow a redirect. A denied answer refuses the request outright: a mixed answer is hostile, so
//! there is no fall-through to a public one. No operator setting reaches this policy.
//!
//! The text check on the host is a convenience; the address check here is the boundary.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;

use crate::egress::policy::{Deny, host_name};
use crate::egress::{Limited, Policy, Resolve};

/// The only port an upstream is dialled on.
pub const UPSTREAM_PORT: u16 = 443;
/// Addresses dialled for one request.
const MAX_DIALS: usize = 4;
const CONNECT: Duration = Duration::from_secs(5);
const HANDSHAKE: Duration = Duration::from_secs(10);
const RESOLVE: Duration = Duration::from_secs(5);
/// The whole request, from the lookup to the last body byte; the per-read idle timeout is in
/// `reply`.
const TOTAL: Duration = Duration::from_secs(120);

/// Why a request was not made, or did not finish. Never carries a name, address or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialError {
    /// The host is not a plain DNS name (an IP in any notation, a trailing dot, a port, ...).
    BadHost,
    /// The lookup failed, timed out, or answered nothing.
    Resolve,
    /// An answer is in a range no upstream may be in (`gateway_refused_address`).
    Refused(Deny),
    /// No checked address accepted a connection.
    Unreachable,
    /// The handshake failed or the certificate is not valid for the host (`tls_failed`).
    Tls,
    /// The request is not one the dialer sends (a header with a line break, ...).
    BadRequest,
    /// The response head is malformed or too large, or the connection broke or stalled.
    Upstream,
    /// The body is longer than the ceiling given to [`Dialer::open`].
    Truncated,
}

pub(crate) type Connecting<'a> = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>;

/// Opens the TCP connection to an address the policy approved. A seam for tests only: the
/// runner's own is [`Tcp`].
pub(crate) trait Connect: Send + Sync {
    fn connect(&self, addr: SocketAddr) -> Connecting<'_>;
}

pub(crate) struct Tcp;

impl Connect for Tcp {
    fn connect(&self, addr: SocketAddr) -> Connecting<'_> {
        Box::pin(async move {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            Ok(tcp)
        })
    }
}

pub use super::body::Body;
use super::reply::open_reply;
pub use super::reply::{Opened, Reply};

/// The stream of an opened response.
pub type Stream = tokio_rustls::client::TlsStream<TcpStream>;

pub struct Dialer {
    resolver: Arc<dyn Resolve>,
    policy: Policy,
    connect: Arc<dyn Connect>,
    tls: Arc<rustls::ClientConfig>,
    total: Duration,
}

/// The bundled roots only: `SSL_CERT_FILE` and the system store are never read (threat T10).
fn client_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

impl Dialer {
    /// The runner's dialer: the host's resolver under the standard limits, `Policy::strict`
    /// plus this host's own interface addresses, the real network, the bundled roots.
    pub fn new(own_addresses: Vec<IpAddr>) -> Dialer {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Dialer::with(
            Arc::new(Limited::system()),
            own_addresses,
            Arc::new(Tcp),
            roots,
        )
    }

    /// Every part chosen: tests give a fake resolver, a connector and their own CA.
    pub(crate) fn with(
        resolver: Arc<dyn Resolve>,
        own_addresses: Vec<IpAddr>,
        connect: Arc<dyn Connect>,
        roots: rustls::RootCertStore,
    ) -> Dialer {
        Dialer {
            resolver,
            policy: Policy::strict().with_host_addresses(own_addresses),
            connect,
            tls: client_config(roots),
            total: TOTAL,
        }
    }

    /// The overall cap of one request, from the lookup to the last body byte.
    pub fn with_total(mut self, total: Duration) -> Dialer {
        self.total = total;
        self
    }

    /// Resolves `host` and returns the addresses to dial: every answer checked, at most
    /// [`MAX_DIALS`]. Any denied answer refuses all of them.
    async fn checked(&self, host: &str) -> Result<Vec<IpAddr>, DialError> {
        let answers = timeout(RESOLVE, self.resolver.resolve(host))
            .await
            .map_err(|_| DialError::Resolve)?
            .map_err(|_| DialError::Resolve)?;
        let mut ok = Vec::new();
        for answer in answers.into_iter().take(crate::egress::MAX_ANSWERS) {
            let ip = self
                .policy
                .check_ip(answer, true)
                .map_err(DialError::Refused)?;
            if !ok.contains(&ip) {
                ok.push(ip);
            }
        }
        ok.truncate(MAX_DIALS);
        if ok.is_empty() {
            return Err(DialError::Resolve);
        }
        Ok(ok)
    }

    /// One request to `host` (port 443): `method path` with `headers` and `body`, sent fresh with
    /// `Host`, `Content-Length`, `Connection: close` and `Accept-Encoding: identity` of the
    /// dialer's own. Returns the status, the allow-listed headers and a body reader that yields at
    /// most `max_body` bytes (then [`DialError::Truncated`]) under the total deadline. A redirect
    /// is returned as it is, never followed.
    pub async fn open(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        max_body: usize,
    ) -> Result<Opened<Stream>, DialError> {
        let name = strict_host(host)?;
        let head = build_head(&name, method, path, headers, body.len())?;
        let deadline = Instant::now() + self.total;
        timeout_at(deadline, async {
            let addrs = self.checked(&name).await?;
            let tcp = self.dial(&addrs).await?;
            let server = ServerName::try_from(name.clone()).map_err(|_| DialError::BadHost)?;
            let mut tls = timeout(
                HANDSHAKE,
                TlsConnector::from(self.tls.clone()).connect(server, tcp),
            )
            .await
            .map_err(|_| DialError::Tls)?
            .map_err(|_| DialError::Tls)?;
            let sent = async {
                tls.write_all(&head).await?;
                tls.write_all(body).await?;
                tls.flush().await
            };
            sent.await.map_err(|_| DialError::Upstream)?;
            open_reply(tls, max_body, deadline).await
        })
        .await
        .map_err(|_| DialError::Upstream)?
    }

    /// [`open`](Self::open), then the whole body in memory: at most `max_body` bytes, and
    /// `truncated` says the upstream sent more.
    pub async fn request(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        max_body: usize,
    ) -> Result<Reply, DialError> {
        let mut opened = self
            .open(host, method, path, headers, body, max_body)
            .await?;
        let (mut out, mut truncated) = (Vec::new(), false);
        loop {
            match opened.body.next().await {
                Ok(Some(piece)) => out.extend_from_slice(&piece),
                Ok(None) => break,
                Err(DialError::Truncated) => {
                    truncated = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Reply {
            status: opened.status,
            headers: opened.headers,
            body: out,
            chunked: opened.chunked,
            truncated,
        })
    }

    /// Dials the first checked address that answers.
    async fn dial(&self, addrs: &[IpAddr]) -> Result<TcpStream, DialError> {
        for ip in addrs {
            let addr = SocketAddr::new(*ip, UPSTREAM_PORT);
            if let Ok(Ok(tcp)) = timeout(CONNECT, self.connect.connect(addr)).await {
                return Ok(tcp);
            }
        }
        Err(DialError::Unreachable)
    }
}

/// A host the dialer takes: a lower-case DNS name of at least two labels whose last label starts
/// with a letter, so no IP in any notation (`127.1`, `0x7f000001`, `2130706433`,
/// `017700000001`) reaches a resolver that would read it as an address, and no single-label
/// name (`localhost`, a search-domain host) either; no trailing dot.
pub fn strict_host(host: &str) -> Result<String, DialError> {
    if host.ends_with('.') || !host.contains('.') {
        return Err(DialError::BadHost);
    }
    host_name(host).ok_or(DialError::BadHost)
}

fn token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && b != b':')
}

fn build_head(
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    len: usize,
) -> Result<Vec<u8>, DialError> {
    let plain = |s: &str| s.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
    if !matches!(method, "GET" | "POST")
        || !path.starts_with('/')
        || path.bytes().any(|b| !b.is_ascii_graphic())
        || !headers.iter().all(|(n, v)| {
            token(n)
                && plain(v)
                && ![
                    "host",
                    "content-length",
                    "connection",
                    "accept-encoding",
                    "transfer-encoding",
                    "expect",
                    "te",
                    "upgrade",
                    "trailer",
                    "keep-alive",
                ]
                .contains(&n.to_ascii_lowercase().as_str())
        })
    {
        return Err(DialError::BadRequest);
    }
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (n, v) in headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {len}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ));
    Ok(head.into_bytes())
}

#[cfg(test)]
pub(crate) mod tests;
