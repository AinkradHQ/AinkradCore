//! "Sign in with Microsoft": the OAuth 2.0 device authorization grant against Entra ID. No
//! redirect address and no client secret: Core shows a short code, the person types it at
//! Microsoft's own page, Core polls until Microsoft hands over tokens.
//!
//! [`Teams::device_start`] returns what the screen shows (the same [`Prompt`] GitHub's device flow
//! uses: no secret in it) and a [`Pending`] Core keeps (the device code, which is the poll key,
//! never printed). [`Pending::poll`] makes one poll and says what happened; it keeps Microsoft's
//! interval itself (a call before the interval is up makes no request) and takes up `slow_down`.
//!
//! What Core shows is what it checked: the verification address must be https on an exact
//! Microsoft host (never Microsoft's own `message` text), the code a short plain string. The
//! tenant is pinned from the id token of the grant (`tid`), and a grant for the wrong tenant (an
//! app limited to one) or one with no refresh token is refused.

use std::fmt;
use std::time::{Duration, Instant};

use serde_json::Value;
use zeroize::Zeroizing;

use super::Teams;
use super::cred::{id_token_tenant, oauth_material, tenant_id};
use super::http::{CallError, Endpoint};
use super::oauth::{SCOPES, issued};
use crate::connections::github::device::Prompt;
use crate::connections::material::Material;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MIN_INTERVAL: u64 = 1;
const MAX_INTERVAL: u64 = 300;
const SLOW_DOWN_STEP: u64 = 5;
/// Microsoft's codes live 15 minutes; never believed beyond that.
const MAX_LIFE: u64 = 900;
/// The only hosts the screen may send a person to.
const VERIFY_HOSTS: [&str; 4] = [
    "microsoft.com",
    "www.microsoft.com",
    "login.microsoftonline.com",
    "login.microsoft.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// No Microsoft app is configured: "Sign in with Microsoft" is not set up on this Core.
    NotConfigured,
    /// Microsoft refused Core's app or the flow (no such client, public client flows off).
    Rejected,
    /// The reply did not say what a device flow reply says.
    BadReply,
    /// The grant is for a tenant this app is not limited to.
    WrongTenant,
    /// No usable answer.
    Unreachable,
}

impl DeviceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Rejected => "client_rejected",
            Self::BadReply | Self::Unreachable => "upstream",
            Self::WrongTenant => "wrong_tenant",
        }
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => {
                "Sign in with Microsoft is not set up on this Core yet: it has no Microsoft app."
            }
            Self::Rejected => {
                "Microsoft refused the sign-in request from this Core: check the app's client id \
                 and that public client flows are allowed."
            }
            Self::BadReply => "Microsoft's reply was not what Core expected.",
            Self::WrongTenant => {
                "that sign-in is for a different Microsoft tenant than this Core allows"
            }
            Self::Unreachable => "Microsoft could not be reached to start the sign-in.",
        })
    }
}

impl std::error::Error for DeviceError {}

fn verification_ok(uri: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(uri) else {
        return false;
    };
    uri.len() <= 200
        && u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.port().is_none()
        && u.fragment().is_none()
        && u.query().is_none()
        && u.host_str().is_some_and(|h| VERIFY_HOSTS.contains(&h))
        && !uri.bytes().any(|b| b <= b' ' || b == b'\\' || b == b'@')
}

fn user_code_ok(c: &str) -> bool {
    (4..=32).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A granted sign-in.
pub struct Granted {
    pub material: Material,
    /// The tenant (`tid`) the tokens were issued in.
    pub tenant: String,
}

pub enum Step {
    /// Nothing yet: ask again in this many seconds.
    Wait {
        secs: u64,
    },
    /// A transient failure (network, 429, 5xx): ask again.
    Retry,
    Granted(Box<Granted>),
    /// The code ran out: start again.
    Expired,
    /// The person said no.
    Denied,
    Failed(DeviceError),
    /// The flow already ended: no request was made.
    Closed,
}

/// The flow in progress, held by Core. No `Serialize`; `Debug` hides the code.
pub struct Pending {
    device_code: Zeroizing<String>,
    client_id: String,
    tenant: String,
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

fn text(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}

impl Teams {
    /// Asks Entra for a device code. `tenant` is the tenant a re-sign-in must land in (a stored
    /// connection's); otherwise the app's own.
    pub async fn device_start(
        &self,
        tenant: Option<&str>,
        now: Instant,
    ) -> Result<(Prompt, Pending), DeviceError> {
        let app = self.app().ok_or(DeviceError::NotConfigured)?;
        let tenant = tenant
            .filter(|t| tenant_id(t))
            .unwrap_or(app.tenant.as_str())
            .to_owned();
        let form = [("client_id", app.client_id.as_str()), ("scope", SCOPES)];
        let res = self
            .http
            .entra(&tenant, Endpoint::DeviceCode, &form)
            .await
            .map_err(|_| DeviceError::Unreachable)?;
        if !(200..300).contains(&res.status) {
            let said = res.body.get("error").and_then(Value::as_str);
            return Err(match said {
                Some(
                    "invalid_client" | "unauthorized_client" | "invalid_scope" | "invalid_request",
                ) if res.status < 500 => DeviceError::Rejected,
                _ => DeviceError::Unreachable,
            });
        }
        let b = &res.body;
        let (Some(code), Some(user_code), Some(uri), Some(expires_in)) = (
            text(b, "device_code"),
            text(b, "user_code"),
            text(b, "verification_uri"),
            b.get("expires_in").and_then(Value::as_u64),
        ) else {
            return Err(DeviceError::BadReply);
        };
        let code = Zeroizing::new(code);
        if code.is_empty()
            || code.len() > 4096
            || code.bytes().any(|c| c <= b' ')
            || !user_code_ok(&user_code)
            || !verification_ok(&uri)
            || expires_in == 0
        {
            return Err(DeviceError::BadReply);
        }
        let interval = b
            .get("interval")
            .and_then(Value::as_u64)
            .unwrap_or(5)
            .clamp(MIN_INTERVAL, MAX_INTERVAL);
        let expires_in = expires_in.min(MAX_LIFE);
        let pending = Pending {
            device_code: code,
            client_id: app.client_id.clone(),
            tenant,
            interval: Duration::from_secs(interval),
            next_at: now + Duration::from_secs(interval),
            expires_at: now + Duration::from_secs(expires_in),
            done: false,
        };
        let prompt = Prompt {
            user_code,
            verification_uri: uri,
            interval,
            expires_in,
        };
        Ok((prompt, pending))
    }
}

fn transient(e: &CallError) -> bool {
    matches!(
        e,
        CallError::Network
            | CallError::TimedOut
            | CallError::Broken
            | CallError::Upstream(_)
            | CallError::RateLimited { .. }
    )
}

impl Pending {
    /// One poll at `now` (`now_iso` is the clock for the token's expiry). Before the interval is
    /// up, after the code expired and once the flow has ended, no request is made.
    pub async fn poll(&mut self, t: &Teams, now: Instant, now_iso: &str) -> Step {
        if self.done {
            return Step::Closed;
        }
        let step = self.poll_once(t, now, now_iso).await;
        self.done = matches!(
            step,
            Step::Granted(_) | Step::Expired | Step::Denied | Step::Failed(_)
        );
        step
    }

    async fn poll_once(&mut self, t: &Teams, now: Instant, now_iso: &str) -> Step {
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
        let form = [
            ("grant_type", GRANT),
            ("client_id", self.client_id.as_str()),
            ("device_code", self.device_code.as_str()),
        ];
        let res = match t.http.entra(&self.tenant, Endpoint::Token, &form).await {
            Ok(r) => r,
            Err(e) if transient(&e) => return Step::Retry,
            Err(_) => return Step::Failed(DeviceError::Unreachable),
        };
        if (200..300).contains(&res.status) {
            return self.granted(&res.body, now_iso);
        }
        match res.body.get("error").and_then(Value::as_str) {
            Some("authorization_pending") => Step::Wait {
                secs: self.interval.as_secs(),
            },
            Some("slow_down") => {
                let secs =
                    (self.interval.as_secs() + SLOW_DOWN_STEP).clamp(MIN_INTERVAL, MAX_INTERVAL);
                self.interval = Duration::from_secs(secs);
                self.next_at = now + self.interval;
                Step::Wait { secs }
            }
            Some("expired_token") => Step::Expired,
            Some("authorization_declined") => Step::Denied,
            Some(
                "bad_verification_code"
                | "invalid_client"
                | "unauthorized_client"
                | "invalid_scope"
                | "invalid_grant",
            ) if res.status < 500 => Step::Failed(DeviceError::Rejected),
            _ if res.status == 429 || res.status >= 500 => Step::Retry,
            _ => Step::Failed(DeviceError::BadReply),
        }
    }

    fn granted(&self, body: &Value, now_iso: &str) -> Step {
        let bad = Step::Failed(DeviceError::BadReply);
        let Ok(iss) = issued(body, now_iso) else {
            return bad;
        };
        let (Some(refresh), Some(id)) = (iss.refresh.as_ref(), iss.id_token.as_ref()) else {
            return bad;
        };
        let Some(tid) = id_token_tenant(id, &self.client_id) else {
            return bad;
        };
        // An app limited to one tenant takes no grant from another.
        if self.tenant != "organizations" && tid != self.tenant {
            return Step::Failed(DeviceError::WrongTenant);
        }
        match oauth_material(&tid, &iss.access, refresh, &iss.expires_at) {
            Some(material) => Step::Granted(Box::new(Granted {
                material,
                tenant: tid,
            })),
            None => bad,
        }
    }
}
