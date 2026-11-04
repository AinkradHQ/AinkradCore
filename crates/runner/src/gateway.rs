//! The auth gateway (KAN-435), runner side.
//!
//! - G2 ([`dial`]): the strict upstream dialer.
//! - G3 (this module): one unix socket per session that serves the harness's model requests. It
//!   allows only the provider's inference routes and the grant's priced models, strips whatever
//!   auth the agent sends and puts the real key on the request it builds fresh, and streams the
//!   response back with an allow-listed head. The key lives in this process's memory only: it is
//!   never in the environment, a file, a log line, a `Debug` or an error text.
//!
//! Metering, the ceiling and the usage reports are G4; the Core's side is G5; the harness's base
//! URL and placeholder key are G6.

mod body;
pub mod dial;
mod reply;
mod request;
mod route;
mod selftest;
mod serve;
pub mod session;
#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{GatewayGrant, Rate, Upstream, key_host_problem};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use dial::Dialer;
pub use selftest::selftest;

/// The forwarder's port inside the sandbox: the MCP route is `FORWARD_PORT`, the egress proxy
/// `EGRESS_PORT`, this is the next one.
pub const GW_PORT: u16 = crate::egress::EGRESS_PORT + 1;
/// A unix socket path must fit `sun_path`.
const MAX_SOCK_PATH: usize = 100;
/// Open connections one session may hold.
const MAX_CONNS: usize = 64;
/// Consecutive failed accepts after which the gateway gives up.
const ACCEPT_FAILURES: u32 = 12;
/// The largest request body (spec 4.5).
pub const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;
/// The most one response may carry before it is cut (explicitly, never as a clean end).
pub const MAX_RESPONSE_BODY: usize = 256 * 1024 * 1024;
/// A model stream may run long; this caps one request from the lookup to the last byte.
pub const REQUEST_TOTAL: Duration = Duration::from_secs(30 * 60);

/// The real API key. No `Debug` output of the value, wiped when dropped.
pub struct Key(Zeroizing<String>);

impl Key {
    /// A value that can go in a header as it is: visible ASCII, 1 to 4096 bytes.
    pub fn new(value: Zeroizing<String>) -> Result<Key, &'static str> {
        let ok =
            !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_graphic());
        ok.then_some(Key(value))
            .ok_or("the key is not a value that can go in a header")
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// What one session's gateway serves. No `Debug`: it holds the key.
pub struct Config {
    upstream: Upstream,
    key: Key,
    /// The models the session may name: the grant's models that have a price.
    models: Vec<String>,
    rate: Rate,
    max_body: usize,
    max_response: usize,
    dialer: Arc<Dialer>,
}

/// A base path that is empty or `/a/b`: no query, fragment, escape, dot segment or empty segment.
fn base_path_ok(p: &str) -> bool {
    p.is_empty()
        || (p.starts_with('/')
            && !p.ends_with('/')
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
            && p.split('/')
                .skip(1)
                .all(|s| !s.is_empty() && s != "." && s != ".."))
}

impl Config {
    /// The grant, checked as the broker checked it, and the key it redeemed: the key may be sent
    /// to this host (`key_host_problem`), the host is a plain DNS name, the wire's auth is the
    /// grant's, the base path is a plain path, and a model is allowed only when it has a price
    /// (T6: an unpriced model is refused, so a dollar ceiling means something).
    pub fn new(
        grant: &GatewayGrant,
        key: Key,
        dialer: Arc<Dialer>,
    ) -> Result<Config, &'static str> {
        let up = &grant.upstream;
        if dial::strict_host(&up.host).as_deref() != Ok(up.host.as_str()) {
            return Err("the upstream host is not a plain DNS name");
        }
        if up.auth != up.wire.auth() {
            return Err("the upstream's auth is not the wire's");
        }
        if !base_path_ok(&up.base_path) {
            return Err("the upstream's base path is not a plain path");
        }
        let user: Vec<_> = grant
            .user_key
            .iter()
            .map(|u| u.of(&grant.provider))
            .collect();
        if let Some(why) = key_host_problem(key.expose(), &grant.provider, &up.host, &user) {
            return Err(why);
        }
        if grant.rate.per_minute == 0 || grant.rate.concurrent == 0 {
            return Err("the grant allows no requests");
        }
        let models = grant
            .models
            .iter()
            .filter(|m| grant.prices.iter().any(|p| &p.model == *m))
            .cloned()
            .collect();
        Ok(Config {
            upstream: up.clone(),
            key,
            models,
            rate: grant.rate,
            max_body: MAX_REQUEST_BODY,
            max_response: MAX_RESPONSE_BODY,
            dialer,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_limits(mut self, max_body: usize, max_response: usize) -> Config {
        self.max_body = max_body;
        self.max_response = max_response;
        self
    }
}

pub(crate) struct Shared {
    cfg: Config,
    /// Requests in flight.
    inflight: Arc<Semaphore>,
    /// Start times of the requests of the last minute.
    window: Mutex<std::collections::VecDeque<tokio::time::Instant>>,
}

/// Serves the harness until dropped (the session ended or was stopped): the socket is gone and
/// every open connection is aborted.
pub struct Gateway {
    task: JoinHandle<()>,
    sock: PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort(); // the accept task owns the JoinSet; dropping it aborts every request
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// The socket a session's gateway listens on, in its private dir.
pub fn socket_in(dir: &Path) -> PathBuf {
    dir.join("gateway.sock")
}

/// The environment a sandbox needs to reach the gateway at `sock` (slot `AINKRAD_SANDBOX_GW_*`):
/// the socket, the forwarder (this executable) and the port.
pub fn sandbox_env(sock: &Path, exe: &Path) -> Vec<(String, std::ffi::OsString)> {
    vec![
        ("AINKRAD_SANDBOX_GW_SOCK".to_owned(), sock.into()),
        ("AINKRAD_SANDBOX_GW_FWD".to_owned(), exe.into()),
        (
            "AINKRAD_SANDBOX_GW_PORT".to_owned(),
            GW_PORT.to_string().into(),
        ),
    ]
}

/// Listens on `sock` (mode 0600) for the session.
pub fn start(sock: &Path, cfg: Config) -> io::Result<Gateway> {
    if sock.as_os_str().len() > MAX_SOCK_PATH {
        return Err(io::Error::other("the gateway socket path is too long"));
    }
    match std::fs::remove_file(sock) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let shared = Arc::new(Shared {
        inflight: Arc::new(Semaphore::new(cfg.rate.concurrent as usize)),
        window: Mutex::default(),
        cfg,
    });
    let conns = Arc::new(Semaphore::new(MAX_CONNS));
    let task = tokio::spawn(async move {
        let mut set = JoinSet::new();
        let mut failures = 0u32;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let client = match accepted {
                        Ok((client, _)) => { failures = 0; client }
                        Err(_) => {
                            failures += 1;
                            if failures > ACCEPT_FAILURES {
                                tracing::warn!("gateway stopped: accept keeps failing");
                                break;
                            }
                            let pause = Duration::from_millis(10).saturating_mul(1u32 << failures.min(7));
                            tokio::time::sleep(pause.min(Duration::from_secs(1))).await;
                            continue;
                        }
                    };
                    // Over the limit: close at once; nothing is queued.
                    let Ok(permit) = conns.clone().try_acquire_owned() else { continue };
                    let shared = shared.clone();
                    set.spawn(async move {
                        let _held = permit;
                        serve::connection(&shared, client).await;
                    });
                }
                Some(_) = set.join_next(), if !set.is_empty() => {}
            }
        }
    });
    Ok(Gateway {
        task,
        sock: sock.to_owned(),
    })
}
