//! The auth gateway (KAN-435), runner side.
//!
//! - G2 ([`dial`]): the strict upstream dialer.
//! - G3 (this module): one unix socket per session that serves the harness's model requests. It
//!   allows only the provider's inference routes and the grant's priced models, strips whatever
//!   auth the agent sends and puts the real key on the request it builds fresh, and streams the
//!   response back with an allow-listed head. The key lives in this process's memory only: it is
//!   never in the environment, a file, a log line, a `Debug` or an error text.
//!
//! - G4 ([`meter`], [`usage`], [`charge`]): every request is priced from the grant and held
//!   against the session's ceiling before it is sent; its reply is read for usage (buffered or
//!   streamed, whole or cut) and ends in one report on a channel of its own ([`Event`]); the
//!   stream is cut when the ceiling is reached; `agent.limit` moves the ceiling.
//!
//! - G6 ([`wiring`], [`stored`]): what each harness is given to reach the gateway (a base URL and
//!   a placeholder key; Codex's generated `config.toml`), and the Responses requests that read
//!   state the provider holds are refused.
//!
//! The Core's side is G5.

mod body;
mod charge;
pub mod check;
pub mod dial;
pub mod meter;
mod nested;
mod probe;
mod reply;
mod request;
mod route;
mod selftest;
mod serve;
pub mod session;
mod status;
mod stored;
mod stream;
#[cfg(test)]
mod tests;
mod usage;
pub mod wiring;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{
    GatewayGrant, GatewayReport, Rate, Upstream, UserKeyDef, key_host_problem,
};
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use dial::Dialer;
use meter::Meter;
pub use selftest::selftest;

/// What a session's gateway tells the driver, on a channel of its own: the harness cannot write
/// to it, so nothing it prints can become a usage report.
#[derive(Debug)]
pub enum Event {
    /// A request's usage, or an upstream signal. `gw_seq` is the driver's to set.
    Report(GatewayReport),
    /// The gateway stopped serving, and why: the driver says so in the transcript.
    Closed(&'static str),
}

pub type Events = mpsc::UnboundedSender<Event>;

/// The forwarder's port inside the sandbox: the MCP route is `FORWARD_PORT`, the egress proxy
/// `EGRESS_PORT`, this is the next one.
pub const GW_PORT: u16 = crate::egress::EGRESS_PORT + 1;
/// A unix socket path must fit `sun_path`.
pub(crate) const MAX_SOCK_PATH: usize = 100;
/// Open connections one session may hold at most: the concurrency cap plus a little room to say
/// 429, never more than this.
const MAX_CONNS: usize = 64;
/// Connections past the concurrency cap, which are answered and closed.
const SPARE_CONNS: usize = 2;
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
    /// The session's ceiling and spend, and the grant's prices.
    meter: Arc<Meter>,
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

/// Why `key` may not be sent to `up` for `provider` (and `user_key`'s definition): the key may go
/// to this host (`key_host_problem`), the host is a plain DNS name, the wire's auth is the
/// grant's, and the base path is a plain path. One check for a session and for `gateway.test`.
pub(crate) fn upstream_problem(
    provider: &str,
    user_key: Option<&UserKeyDef>,
    up: &Upstream,
    key: &Key,
) -> Option<&'static str> {
    if dial::strict_host(&up.host).as_deref() != Ok(up.host.as_str()) {
        return Some("the upstream host is not a plain DNS name");
    }
    if up.auth != up.wire.auth() {
        return Some("the upstream's auth is not the wire's");
    }
    if !base_path_ok(&up.base_path) {
        return Some("the upstream's base path is not a plain path");
    }
    let user: Vec<_> = user_key.iter().map(|u| u.of(provider)).collect();
    key_host_problem(key.expose(), provider, &up.host, &user)
}

impl Config {
    /// The grant, checked as the broker checked it, and the key it redeemed ([`upstream_problem`]),
    /// and a model is allowed only when it has a price (T6: an unpriced model is refused, so a
    /// dollar ceiling means something).
    pub fn new(
        grant: &GatewayGrant,
        key: Key,
        dialer: Arc<Dialer>,
    ) -> Result<Config, &'static str> {
        let up = &grant.upstream;
        if let Some(why) = upstream_problem(&grant.provider, grant.user_key.as_ref(), up, &key) {
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
            meter: Arc::new(Meter::new(grant.ceiling, grant.prices.clone())),
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
    events: Events,
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
    meter: Arc<Meter>,
}

impl Gateway {
    /// The session's ceiling and spend: `agent.limit` sets it.
    pub fn meter(&self) -> &Arc<Meter> {
        &self.meter
    }
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

/// Listens on `sock` (mode 0600) for the session; what it sees goes to `events`.
pub fn start(sock: &Path, cfg: Config, events: Events) -> io::Result<Gateway> {
    if sock.as_os_str().len() > MAX_SOCK_PATH {
        return Err(io::Error::other("the gateway socket path is too long"));
    }
    match std::fs::remove_file(sock) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let meter = cfg.meter.clone();
    let conns = Arc::new(Semaphore::new(
        (cfg.rate.concurrent as usize + SPARE_CONNS).min(MAX_CONNS),
    ));
    let shared = Arc::new(Shared {
        inflight: Arc::new(Semaphore::new(cfg.rate.concurrent as usize)),
        window: Mutex::default(),
        events,
        cfg,
    });
    let path = sock.to_owned();
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
                                // Said, not silent: the harness would see only refused connections.
                                tracing::warn!("gateway stopped: accept keeps failing");
                                let _ = shared.events.send(Event::Closed("accepting connections kept failing"));
                                let _ = std::fs::remove_file(&path);
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
        meter,
    })
}
