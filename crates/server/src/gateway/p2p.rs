//! The iroh listener (E2-19, `Specs/2026-10-29-nat-traversal-decision.md`): an opt-in second
//! listener so a Core behind NAT is reachable, directly (hole punching) or through a
//! self-hosted `iroh-relay`. Off unless `serve --iroh` asks for it.
//!
//! iroh is the pipe and nothing more. Its Ed25519 transport key proves which endpoint the client
//! dialled (the client pins the Core's endpoint id) but grants nothing: every QUIC stream a peer
//! opens carries one HTTP/1.1 connection into the same router as the other listeners, so the
//! pre-auth gate, the Host and Origin rules and the signed device handshake (P-256, spec §4 to
//! §6) apply unchanged. A peer that has not paired reaches `/handshake`, `/pair` and `/healthz`
//! and is refused everywhere else, exactly like a stranger on TCP.
//!
//! Limits, as on the other pre-auth listeners: a handshake deadline, a cap on open connections,
//! on streams per connection and on how fast one address and the whole listener may start
//! connections (checked before any crypto), and the per-request limits of `conn`. The failed
//! authentication buckets (`api::limit`) are keyed by an address derived from the peer's
//! endpoint id, which is never loopback and so never a trusted proxy or a local peer.
//!
//! No relay unless one is configured: n0's public relays and DNS are never used.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ::iroh::endpoint::{Incoming, IncomingAddr, presets};
use ::iroh::{Endpoint, EndpointId, RelayMode, RelayUrl, SecretKey};
use axum::Router;
use hyper_util::server::graceful::GracefulShutdown;
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, watch};

use super::conn::{Limits, Peer, serve_conn};
use crate::api::limit::Limiter;

/// The ALPN of the Core's HTTP-over-iroh protocol: one HTTP/1.1 connection per bidirectional
/// stream.
pub const ALPN: &[u8] = b"ainkrad/http/1";

/// Connections open at once, over all peers.
const MAX_CONNECTIONS: usize = 256;
/// Streams (HTTP connections) open at once on one connection.
const MAX_STREAMS: usize = 8;
/// Streams one connection may open over its whole life; then it reconnects. hyper's drain
/// watchers cannot be cloned, so each connection takes this many up front.
// ponytail: a lifetime cap on streams per connection; a drain-aware stream pool if clients churn them.
const LIFETIME_STREAMS: usize = 16;

/// How the listener is set up.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The transport key: 32 bytes, `0600`, made on first start. Its public half is the endpoint
    /// id clients pin.
    pub key_path: std::path::PathBuf,
    /// The self-hosted relays (`https://…`). None means direct connections only.
    pub relays: Vec<String>,
    /// UDP addresses to bind; none means iroh's default (any port, IPv4 and IPv6).
    pub bind: Vec<SocketAddr>,
}

fn other(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// The transport key at `path`, made (`0600`) when there is none.
pub fn load_or_create_key(path: &Path) -> std::io::Result<SecretKey> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes =
                <[u8; 32]>::try_from(bytes).map_err(|_| other("the iroh key is not 32 bytes"))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?
                .write_all(&key.to_bytes())?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// The endpoint id for the key at `path`: what a client pins.
pub fn endpoint_id(path: &Path) -> std::io::Result<EndpointId> {
    Ok(load_or_create_key(path)?.public())
}

/// A bound iroh endpoint and its limits.
pub struct Listener {
    endpoint: Endpoint,
    conns: Arc<Semaphore>,
    /// New connections per remote address (or relay peer), then over everyone.
    per_remote: Limiter,
    global: Limiter,
}

impl Listener {
    pub async fn bind(config: Config) -> std::io::Result<Self> {
        let key = load_or_create_key(&config.key_path)?;
        let relays = config
            .relays
            .iter()
            .map(|r| {
                r.parse::<RelayUrl>()
                    .map_err(|e| other(format!("relay {r}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mode = if relays.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::custom(relays)
        };
        // `Minimal`: no n0 DNS, no n0 relays.
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(mode);
        for addr in &config.bind {
            builder = builder.bind_addr(*addr).map_err(other)?;
        }
        let endpoint = builder.bind().await.map_err(other)?;
        Ok(Self {
            endpoint,
            conns: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            per_remote: Limiter::new(8, 1.0),
            global: Limiter::new(64, 20.0),
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub(super) async fn close(&self) {
        self.endpoint.close().await;
    }

    /// Accepts until `closing` is set; each connection on its own task.
    pub(super) async fn accept(
        &self,
        app: Router,
        limits: &Arc<Limits>,
        graceful: &GracefulShutdown,
        mut closing: watch::Receiver<bool>,
    ) {
        loop {
            let incoming = tokio::select! {
                i = self.endpoint.accept() => match i { Some(i) => i, None => return },
                () = crate::api::stopping(&mut closing) => return,
            };
            let Some(permit) = self.admit(&incoming) else {
                incoming.refuse();
                continue;
            };
            let mut watchers: Vec<_> = (0..LIFETIME_STREAMS).map(|_| graceful.watcher()).collect();
            let (app, limits) = (app.clone(), Arc::clone(limits));
            let mut closing = closing.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(accepting) = incoming.accept() else {
                    return;
                };
                let shake = tokio::time::timeout(limits.tls_handshake, accepting);
                let Ok(Ok(conn)) = shake.await else { return };
                let peer = Peer::Tcp(Some(derived_addr(conn.remote_id())));
                let streams = Arc::new(Semaphore::new(MAX_STREAMS));
                loop {
                    // A connection with no stream open and none coming is closed, as an idle
                    // HTTP connection is.
                    let next = tokio::time::timeout(limits.idle, conn.accept_bi());
                    let bi = tokio::select! {
                        b = next => b,
                        () = crate::api::stopping(&mut closing) => return,
                    };
                    let (send, recv) = match bi {
                        Ok(Ok(bi)) => bi,
                        Ok(Err(_)) => return,
                        Err(_) if streams.available_permits() == MAX_STREAMS => {
                            conn.close(0u8.into(), b"idle");
                            return;
                        }
                        Err(_) => continue,
                    };
                    let Ok(slot) = Arc::clone(&streams).try_acquire_owned() else {
                        // Too many at once: the stream is dropped, the peer sees it reset.
                        continue;
                    };
                    let Some(w) = watchers.pop() else {
                        conn.close(0u8.into(), b"reconnect");
                        return;
                    };
                    let io = tokio::io::join(recv, send);
                    let (app, limits) = (app.clone(), Arc::clone(&limits));
                    tokio::spawn(async move {
                        serve_conn(io, false, peer, app, &limits, w).await;
                        drop(slot);
                    });
                }
            });
        }
    }

    /// A connection slot and a token from both rate limits, taken before any crypto; none when
    /// the listener is full or the remote is going too fast.
    fn admit(&self, incoming: &Incoming) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let key = match incoming.remote_addr() {
            IncomingAddr::Ip(a) => a.ip().to_string(),
            IncomingAddr::Relay { endpoint_id, .. } => endpoint_id.to_string(),
            _ => "other".to_owned(),
        };
        let now = Instant::now();
        // ponytail: relay peers are keyed by their endpoint id, which costs an attacker nothing to
        // change; the global bucket and the connection cap are what hold then.
        self.per_remote.take(&key, now).ok()?;
        self.global.take("*", now).ok()?;
        Arc::clone(&self.conns).try_acquire_owned().ok()
    }
}

/// The address the rate limits and logs see for a peer: a unique-local IPv6 address from its
/// endpoint id, never loopback.
pub fn derived_addr(id: EndpointId) -> SocketAddr {
    let hash = Sha256::digest(id.as_bytes());
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&hash[..15]);
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derived_address_is_stable_per_key_and_never_loopback() {
        let a = SecretKey::generate().public();
        let b = SecretKey::generate().public();
        assert_eq!(derived_addr(a), derived_addr(a));
        assert_ne!(derived_addr(a), derived_addr(b));
        assert!(!derived_addr(a).ip().is_loopback());
    }

    #[test]
    fn the_key_is_made_once_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("core-iroh-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("iroh.key");
        let first = endpoint_id(&path).unwrap();
        assert_eq!(endpoint_id(&path).unwrap(), first, "stable across starts");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::write(&path, b"short").unwrap();
        assert!(endpoint_id(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
