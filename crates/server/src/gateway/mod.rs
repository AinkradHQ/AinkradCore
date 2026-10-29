//! The gateway (E1-06): where requests come in. One hyper accept loop (`conn`) serves every
//! listener mode with the same limits and the same drain:
//!
//! - `unix`: a Unix socket, `0600`, the default for local runs. Only this user can connect.
//! - `loopback`: `127.0.0.1:<port>` (and `serve --bind` for any address, as before).
//! - `public`: TLS 1.3 on :443 with an ACME certificate (`tls`, `acme`), and :80 only when
//!   HTTP-01 is turned on. Opt-in, and refused without a hostname and an ACME contact.
//!
//! Before routing, the pre-auth gate (`preauth`) lets four route prefixes through without a
//! key and refuses everything else unauthenticated.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UnixListener};

pub mod acme;
mod conn;
mod idle;
pub mod preauth;
pub mod tls;

pub use conn::Limits;

/// Where `serve` listens.
#[derive(Debug, Clone)]
pub enum Listen {
    /// A Unix socket at this path, `0600`.
    Unix(PathBuf),
    /// Plain HTTP on this address: `127.0.0.1:<port>` for `loopback`, or `serve --bind`.
    Tcp(String),
    /// TLS on `port` (443) with ACME certificates; HTTP-01 on `http01` (80) when set.
    Public {
        port: u16,
        http01: Option<u16>,
        acme: acme::Acme,
    },
}

impl Listen {
    /// The `Host` clients send by default: `localhost` on a socket, the address on loopback,
    /// the hostname (with a port other than 443) in public.
    pub fn default_host(&self) -> String {
        match self {
            Self::Unix(_) => "localhost".to_owned(),
            Self::Tcp(addr) => addr.clone(),
            Self::Public {
                port: 443, acme, ..
            } => acme.hostname.clone(),
            Self::Public { port, acme, .. } => format!("{}:{port}", acme.hostname),
        }
    }
}

enum Listener {
    /// A socket, and the uid that owns its file (this process's): a peer is the same user when
    /// its credentials say so.
    Unix(UnixListener, u32),
    Tcp(TcpListener),
}

/// A request that came over a Unix socket of this server, and whether its peer runs as the
/// server's own user (`SO_PEERCRED` / `getpeereid` through tokio). Only such a request may
/// claim a bootstrap pairing (handshake spec §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    pub same_user: bool,
}

/// The TLS exporter of the connection a request came over (RFC 8446 §7.5; label
/// `ainkrad_proto::v2::EXPORTER_LABEL`, no context, 32 bytes), for the runner hub's
/// channel-bound proof (handshake spec §13). Present only on the TLS listener. A secret of the
/// session: its `Debug` shows nothing, and it is never logged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Exporter(pub [u8; 32]);

impl std::fmt::Debug for Exporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Exporter(..)")
    }
}

/// Binds a Unix socket at `path`, `0600`, replacing a socket a killed server left there.
fn bind_unix(path: &std::path::Path) -> std::io::Result<Listener> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // A socket left by a killed server; anything else at the path is an error.
    if std::fs::symlink_metadata(path).is_ok_and(|m| {
        use std::os::unix::fs::FileTypeExt;
        m.file_type().is_socket()
    }) {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    // ponytail: the socket has the umask's mode for a moment before this; in a 0700
    // directory nobody else can reach it meanwhile (`make run`'s `state/` is 0755).
    // A bind under a 0077 umask closes the gap, which needs libc (`crates/sys`).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let owner = std::fs::metadata(path)?.uid();
    Ok(Listener::Unix(listener, owner))
}

/// Bound listeners, ready to serve.
pub struct Gateway {
    main: Listener,
    /// The admin socket beside a TCP listener (`with_admin_socket`), for the host's bootstrap.
    admin: Option<Listener>,
    http01: Option<TcpListener>,
    /// The public listener's certificates and how to renew them.
    tls: Option<(Arc<tls::Certs>, acme::Acme)>,
    limits: Limits,
}

impl Gateway {
    /// Binds `listen`. In public mode a stored certificate is loaded before the first accept,
    /// so a restart has no outage; without one, the first order runs once serving starts
    /// (TLS-ALPN-01 needs the listener up).
    pub async fn bind(listen: Listen, limits: Limits) -> std::io::Result<Self> {
        let (main, http01, tls) = match listen {
            Listen::Unix(path) => (bind_unix(&path)?, None, None),
            Listen::Tcp(addr) => (Listener::Tcp(TcpListener::bind(addr).await?), None, None),
            Listen::Public { port, http01, acme } => {
                let certs = Arc::new(tls::Certs::default());
                if let Some(cert) = acme.load_cert() {
                    certs.set(cert);
                }
                // ponytail: IPv4 only, like the host (no AAAA); bind `::` too once IPv6 matters.
                let main = TcpListener::bind(("0.0.0.0", port)).await?;
                let http01 = match http01 {
                    Some(p) => Some(TcpListener::bind(("0.0.0.0", p)).await?),
                    None => None,
                };
                (Listener::Tcp(main), http01, Some((certs, acme)))
            }
        };
        Ok(Self {
            main,
            admin: None,
            http01,
            tls,
            limits,
        })
    }

    /// Also serves the same routes on a Unix socket at `path` (`0600`), so a TCP Core can be
    /// bootstrapped from the host (handshake spec §7.3). A Unix main listener needs none.
    pub fn with_admin_socket(mut self, path: &std::path::Path) -> std::io::Result<Self> {
        self.admin = Some(bind_unix(path)?);
        Ok(self)
    }

    /// The main listener's TCP address (`None` on a socket).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self.main {
            Listener::Tcp(l) => l.local_addr().ok(),
            Listener::Unix(..) => None,
        }
    }

    /// The HTTP-01 listener's address, when there is one.
    pub fn http01_addr(&self) -> Option<SocketAddr> {
        self.http01.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// The public listener's certificates.
    pub fn certs(&self) -> Option<Arc<tls::Certs>> {
        self.tls.as_ref().map(|(c, _)| Arc::clone(c))
    }
}

/// How long requests in flight get to finish once serve is told to stop.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
