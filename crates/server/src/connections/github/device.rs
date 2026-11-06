//! "Sign in with GitHub": the OAuth device flow (C2; design §6). No callback address and no
//! client secret: Core shows a short code, the person types it at github.com, Core polls until
//! GitHub hands over a token.
//!
//! [`start`] returns what the UI shows ([`Prompt`]: no secret in it) and a [`Pending`] Core keeps
//! (the device code, which is the poll key, never printed). [`Pending::poll`] makes one poll and
//! says what happened; it keeps GitHub's interval itself (a call before the interval is up
//! answers [`Step::Wait`] without a request) and takes up `slow_down`. The caller stores a
//! granted token with `store::connections::secret::replace` or at `create`.
//!
//! The client id is the Ainkrad OAuth app's, from Core's settings (`CLIENT_ID_SETTING`); unset,
//! [`start`] refuses with [`DeviceError::NotConfigured`] before any request.

use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::http::{Host, Req, Transport};
use super::outcome::{Outcome, classify};
use crate::connections::material::Material;
use crate::scheduler::iso_of_unix;

/// Where the Ainkrad OAuth app's client id is kept (empty until Ainkrad registers the app).
pub const CLIENT_ID_SETTING: &str = "connections.github.client_id";
/// What the sign-in asks for: a classic OAuth app has no finer scope than `repo` for private
/// repositories. A GitHub App ignores it.
pub const SCOPE: &str = "repo";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MIN_INTERVAL: u64 = 1;
const MAX_INTERVAL: u64 = 300;
const SLOW_DOWN_STEP: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// No client id is set: "Sign in with GitHub" is not set up on this Core.
    NotConfigured,
    /// GitHub refused the client id or the flow (not enabled for the app, a wrong code).
    Rejected,
    /// The reply did not say what a device flow reply says.
    BadReply,
    /// No usable reply; transient unless it is a `bad_request`.
    Net(Outcome),
}

impl DeviceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Rejected => "client_rejected",
            Self::BadReply => "upstream",
            Self::Net(o) => o.code(),
        }
    }

    /// Worth polling again.
    pub fn transient(&self) -> bool {
        matches!(self, Self::Net(o) if o.health().is_some())
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str(
                "Sign in with GitHub is not set up on this Core yet: it has no GitHub client id.",
            ),
            Self::Rejected => f.write_str("GitHub refused the sign-in request from this Core."),
            Self::BadReply => f.write_str("GitHub's reply was not what Core expected."),
            Self::Net(o) => f.write_str(o.message()),
        }
    }
}

impl std::error::Error for DeviceError {}

/// What the screen shows. Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Prompt {
    pub user_code: String,
    /// `https://github.com/login/device`.
    pub verification_uri: String,
    /// Seconds between polls.
    pub interval: u64,
    /// Seconds the code lives.
    pub expires_in: u64,
}

/// A granted sign-in.
#[derive(Debug)]
pub struct Granted {
    pub material: Material,
    /// What GitHub says the token may do (`repo`).
    pub scopes: String,
}

#[derive(Debug)]
pub enum Step {
    /// Nothing yet: ask again in this many seconds.
    Wait {
        secs: u64,
    },
    Granted(Granted),
    /// The code ran out: start again.
    Expired,
    /// The person said no on github.com.
    Denied,
    Failed(DeviceError),
    /// The flow already ended (granted, expired, denied or failed for good): no request was made.
    Closed,
}

/// The flow in progress, held by Core. No `Serialize`; `Debug` hides the code.
pub struct Pending {
    device_code: Zeroizing<String>,
    interval: Duration,
    next_at: Instant,
    expires_at: Instant,
    /// Set when a poll ended the flow: later polls make no request.
    done: bool,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pending(<redacted>)")
    }
}

#[derive(Deserialize, Default)]
struct Reply {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

fn client_id_ok(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn parse(body: &[u8]) -> Reply {
    serde_json::from_slice(body).unwrap_or_default()
}

/// The one thing GitHub may ask a person to open.
fn verification_ok(uri: &str) -> bool {
    uri.starts_with("https://github.com/")
        && !uri.bytes().any(|b| b <= b' ' || b == b'\\' || b == b'@')
}

fn unix_now() -> i64 {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(s.as_secs()).unwrap_or(i64::MAX)
}

/// Asks GitHub for a device code. `now` is the caller's clock (an `Instant`).
pub async fn start(
    t: &Transport,
    client_id: &str,
    now: Instant,
) -> Result<(Prompt, Pending), DeviceError> {
    let client_id = client_id.trim();
    if !client_id_ok(client_id) {
        return Err(DeviceError::NotConfigured);
    }
    let req = Req::form(
        Host::Web,
        "/login/device/code",
        &[("client_id", client_id), ("scope", SCOPE)],
    );
    let resp = t
        .send(&req, None)
        .await
        .map_err(|e| DeviceError::Net(e.into()))?;
    let r = parse(&resp.body);
    if r.error.is_some() && resp.status < 500 {
        return Err(DeviceError::Rejected);
    }
    classify(&resp).map_err(DeviceError::Net)?;
    let (Some(code), Some(user_code), Some(uri), Some(expires_in)) =
        (r.device_code, r.user_code, r.verification_uri, r.expires_in)
    else {
        return Err(DeviceError::BadReply);
    };
    let shown_ok = !user_code.is_empty()
        && user_code.len() <= 32
        && user_code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if code.is_empty() || !shown_ok || !verification_ok(&uri) || expires_in == 0 {
        return Err(DeviceError::BadReply);
    }
    let interval = r.interval.unwrap_or(5).clamp(MIN_INTERVAL, MAX_INTERVAL);
    let expires_in = expires_in.min(3600);
    let pending = Pending {
        device_code: Zeroizing::new(code),
        interval: Duration::from_secs(interval),
        next_at: now + Duration::from_secs(interval),
        expires_at: now + Duration::from_secs(expires_in),
        done: false,
    };
    Ok((
        Prompt {
            user_code,
            verification_uri: uri,
            interval,
            expires_in,
        },
        pending,
    ))
}

impl Pending {
    /// One poll at `now`. Before the interval is up, after the code expired, once the flow has
    /// ended, or with a client id that is not one, no request is made.
    pub async fn poll(&mut self, t: &Transport, client_id: &str, now: Instant) -> Step {
        if self.done {
            return Step::Closed;
        }
        if !client_id_ok(client_id.trim()) {
            return Step::Failed(DeviceError::NotConfigured);
        }
        let step = self.poll_once(t, client_id, now).await;
        self.done = match &step {
            Step::Granted(_) | Step::Expired | Step::Denied => true,
            Step::Failed(e) => !e.transient(),
            Step::Wait { .. } | Step::Closed => false,
        };
        step
    }

    async fn poll_once(&mut self, t: &Transport, client_id: &str, now: Instant) -> Step {
        if now >= self.expires_at {
            return Step::Expired;
        }
        if now < self.next_at {
            let left = self.next_at - now;
            return Step::Wait {
                secs: left.as_secs() + u64::from(left.subsec_nanos() > 0),
            };
        }
        self.next_at = now + self.interval;
        let req = Req::form(
            Host::Web,
            "/login/oauth/access_token",
            &[
                ("client_id", client_id.trim()),
                ("device_code", self.device_code.as_str()),
                ("grant_type", GRANT),
            ],
        );
        let resp = match t.send(&req, None).await {
            Ok(r) => r,
            Err(e) => return Step::Failed(DeviceError::Net(e.into())),
        };
        let r = parse(&resp.body);
        if let Some(token) = r.access_token.as_deref() {
            return self.granted(token, &r);
        }
        match r.error.as_deref() {
            Some("authorization_pending") => Step::Wait {
                secs: self.interval.as_secs(),
            },
            Some("slow_down") => {
                let secs = r
                    .interval
                    .unwrap_or(self.interval.as_secs() + SLOW_DOWN_STEP)
                    .clamp(MIN_INTERVAL, MAX_INTERVAL);
                self.interval = Duration::from_secs(secs);
                self.next_at = now + self.interval;
                Step::Wait { secs }
            }
            Some("expired_token") => Step::Expired,
            Some("access_denied") => Step::Denied,
            Some(_) => Step::Failed(DeviceError::Rejected),
            None => match classify(&resp) {
                Err(o) => Step::Failed(DeviceError::Net(o)),
                Ok(()) => Step::Failed(DeviceError::BadReply),
            },
        }
    }

    fn granted(&self, token: &str, r: &Reply) -> Step {
        // `expires_in` here is the token's own life (an expiring token), not the code's.
        let at = r
            .expires_in
            .filter(|n| *n > 0)
            .map(|n| iso_of_unix(unix_now().saturating_add(i64::try_from(n).unwrap_or(0))));
        match Material::new(token, r.refresh_token.as_deref(), at.as_deref()) {
            Some(material) => Step::Granted(Granted {
                material,
                scopes: r
                    .scope
                    .clone()
                    .unwrap_or_default()
                    .chars()
                    .take(256)
                    .collect(),
            }),
            None => Step::Failed(DeviceError::BadReply),
        }
    }
}
