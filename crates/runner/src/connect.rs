//! Where the runner connects, and why it may stop for good.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::{HeaderValue, header};

/// How the runner reaches its server. Has no `Debug`: it holds the key.
pub struct Config {
    /// `wss://citadel.example/runner/v1/connect`; `ws://` only to a loopback host.
    pub url: String,
    pub key: String,
    /// Capabilities it offers, e.g. `linux`, `macos`, `xcode`.
    pub tags: Vec<String>,
    /// Installed harness → version, from `HarnessExecutor::probe` (E3.6).
    pub harnesses: BTreeMap<String, String>,
    /// Its own log file, whose tail the admin may read (1.20); `None`, it keeps none.
    pub log: Option<PathBuf>,
}

/// Why the daemon stopped for good.
#[derive(Debug)]
pub enum Error {
    /// The URL or key cannot be used.
    Config(String),
    /// The server refused this runner (bad key, host or request); retrying cannot help.
    Refused(u16),
    /// Told to stop (`run_until`), and no run was in flight.
    Stopped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(why) => f.write_str(why),
            Self::Refused(status) => write!(f, "server refused the runner (HTTP {status})"),
            Self::Stopped => f.write_str("stopped"),
        }
    }
}

impl std::error::Error for Error {}

fn loopback(host: &str) -> bool {
    let ip = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The upgrade request: checked URL, key in the `Authorization` header (marked sensitive).
pub(crate) fn request(config: &Config) -> Result<Request, Error> {
    let bad = |why: &str| Error::Config(why.to_owned());
    let mut req = config
        .url
        .as_str()
        .into_client_request()
        .map_err(|e| Error::Config(format!("bad server URL: {e}")))?;
    let uri = req.uri();
    match uri.scheme_str() {
        Some("wss") => {}
        Some("ws") if uri.host().is_some_and(loopback) => {}
        Some("ws") => return Err(bad("ws:// is only allowed to a loopback host; use wss://")),
        _ => return Err(bad("the server URL must be wss://")),
    }
    if uri.query().is_some() {
        return Err(bad("the server URL takes no query string"));
    }
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", config.key))
        .map_err(|_| bad("the runner key is not valid header text"))?;
    auth.set_sensitive(true);
    req.headers_mut().insert(header::AUTHORIZATION, auth);
    Ok(req)
}
