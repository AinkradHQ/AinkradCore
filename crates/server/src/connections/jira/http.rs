//! One HTTP request to Atlassian, and what its answer means. The client is
//! `ainkrad_providers::guard::Policy`'s: https on 443 to a named allow-listed host only, every
//! resolved address vetted and pinned (no second lookup), no proxy, no redirect, timeouts. The
//! answer is size-capped. Errors are fixed text: never a URL, a header or an upstream message.
//!
//! (The KAN-435 runner `Dialer` is the same idea but lives in `ainkrad-runner`, which this crate
//! only dev-depends on, and has no loopback seam; C2 may share this module in a later refactor.)

use std::fmt;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use ainkrad_providers::guard::Policy;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, RETRY_AFTER};
use reqwest::{Client, Method};
use serde_json::Value;

/// The largest answer read.
pub const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// A `Retry-After` is believed up to a day.
const MAX_RETRY_SECS: u64 = 86_400;

pub const API_HOST: &str = "api.atlassian.com";
pub const AUTH_HOST: &str = "auth.atlassian.com";

/// How a call ended badly. Fixed text, safe to log and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// 401 (after one refresh for OAuth), or a refresh the service refused: a pending auth
    /// failure, which only a test confirms.
    AuthFailed,
    /// 403: the account may not do this. Not a credential verdict.
    Forbidden,
    NotFound,
    /// 429; `retry_after` seconds when the service said.
    RateLimited {
        retry_after: Option<u64>,
    },
    /// 5xx, a redirect or an unreadable answer.
    Upstream(u16),
    /// Another 4xx: the request was not acceptable (a bad field, a missing transition).
    BadRequest(u16),
    /// No connection: the address was refused, the connect or the TLS handshake failed. The only
    /// failure that says the service is unreachable.
    Network,
    /// The answer was longer than we read. Says nothing about the service's health.
    TooLarge,
    /// No answer in time. Says nothing about the service's health (a slow query is not an outage).
    TimedOut,
    /// The exchange broke off some other way (a reset, a malformed frame). No health signal.
    Broken,
    /// Refused here, before or after the call, by the adapter's own rules (bad arguments, the
    /// project limit). Never carries an argument value.
    Refused(String),
    Internal(&'static str),
    /// The token endpoint refused Core's own app (`invalid_client`, `unauthorized_client`): the
    /// Atlassian app registration or its secret is wrong. No connection's credential is at fault,
    /// so there is no per-connection health signal.
    AppConfig,
    /// An OAuth token is expired or refused and this Core has no Atlassian app configured, so it
    /// cannot be renewed: the connection needs the token the app would have renewed.
    OAuthNotConfigured,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => f.write_str("Jira refused the credential"),
            Self::Forbidden => f.write_str("Jira says the account may not do that"),
            Self::NotFound => f.write_str("Jira has no such thing, or the account cannot see it"),
            Self::RateLimited { .. } => f.write_str("Jira is rate limiting this connection"),
            Self::Upstream(s) => write!(f, "Jira answered with an error ({s})"),
            Self::BadRequest(s) => write!(f, "Jira did not accept the request ({s})"),
            Self::Network => f.write_str("Jira could not be reached"),
            Self::TooLarge => f.write_str("Jira's answer was too large to read"),
            Self::TimedOut => f.write_str("Jira did not answer in time"),
            Self::Broken => f.write_str("the exchange with Jira broke off"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Internal(why) => f.write_str(why),
            Self::AppConfig => f.write_str(
                "Atlassian refused this Core's app registration: check the client id and secret",
            ),
            Self::OAuthNotConfigured => f.write_str(
                "Sign in with Atlassian is not set up on this Core, so an expired token cannot be renewed",
            ),
        }
    }
}

impl std::error::Error for CallError {}

impl CallError {
    /// The signal this is for connection health (`store::connections::health::Signal::Upstream`):
    /// status and Retry-After. `None` for what says nothing about the connection (403, 404,
    /// bad requests, our own refusals).
    pub fn health(&self) -> Option<(UpstreamStatus, Option<u64>)> {
        match self {
            Self::AuthFailed => Some((UpstreamStatus::AuthFailed, None)),
            Self::RateLimited { retry_after } => Some((UpstreamStatus::RateLimited, *retry_after)),
            // Only Jira's own 5xx. A redirect, an unmapped status or an unreadable body can be
            // provoked through what an agent names, and the connection is shared.
            Self::Upstream(s) if (500..600).contains(s) => {
                Some((UpstreamStatus::ServerError, None))
            }
            Self::Network => Some((UpstreamStatus::Unreachable, None)),
            Self::OAuthNotConfigured => Some((UpstreamStatus::AuthFailed, None)),
            _ => None,
        }
    }

    /// A short plain identifier for `record_use`'s `code`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AuthFailed => "auth_failed",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "rate_limited",
            Self::Upstream(_) => "upstream",
            Self::BadRequest(_) => "bad_request",
            Self::Network => "network",
            Self::TooLarge => "too_large",
            Self::TimedOut => "timed_out",
            Self::Broken => "broken",
            Self::Refused(_) => "refused",
            Self::Internal(_) => "internal",
            Self::AppConfig => "app_config",
            Self::OAuthNotConfigured => "oauth_not_configured",
        }
    }
}

/// What a failed `send` or a failed read of the body means.
fn net(e: &reqwest::Error) -> CallError {
    if e.is_timeout() {
        CallError::TimedOut
    } else if e.is_connect() {
        CallError::Network
    } else {
        CallError::Broken
    }
}

/// The error of a non-2xx status.
pub fn classify(status: u16, retry_after: Option<u64>) -> CallError {
    match status {
        401 => CallError::AuthFailed,
        403 => CallError::Forbidden,
        404 => CallError::NotFound,
        429 => CallError::RateLimited { retry_after },
        s if s >= 500 || (300..400).contains(&s) => CallError::Upstream(s),
        s => CallError::BadRequest(s),
    }
}

pub struct Resp {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub body: Value,
}

impl Resp {
    pub fn into_ok(self) -> Result<Value, CallError> {
        if (200..300).contains(&self.status) {
            Ok(self.body)
        } else {
            Err(classify(self.status, self.retry_after))
        }
    }
}

/// The client and the places it may go.
#[derive(Clone)]
pub struct Http {
    fixed: (Policy, Client),
    /// Production: a token-auth site gets a client of its own, allowing that one host.
    per_site: bool,
    pub api: String,
    pub auth: String,
    site: Option<String>,
    timeout: Duration,
}

impl Http {
    pub fn production() -> Self {
        let policy = Policy::new([API_HOST.to_owned(), AUTH_HOST.to_owned()]);
        let client = policy.client();
        Self {
            fixed: (policy, client),
            per_site: true,
            api: format!("https://{API_HOST}"),
            auth: format!("https://{AUTH_HOST}"),
            site: None,
            timeout: Duration::from_secs(20),
        }
    }

    /// Tests: everything goes to one plain-http loopback origin.
    #[cfg(test)]
    pub fn loopback(addr: std::net::SocketAddr) -> Self {
        let policy = Policy::new([]).with_test_origin(addr);
        let client = policy.client();
        let origin = format!("http://{addr}");
        Self {
            fixed: (policy, client),
            per_site: false,
            api: origin.clone(),
            auth: origin.clone(),
            site: Some(origin),
            timeout: Duration::from_secs(20),
        }
    }

    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// `https://<host>` for a token-auth site.
    pub fn site_base(&self, host: &str) -> String {
        self.site
            .clone()
            .unwrap_or_else(|| format!("https://{host}"))
    }

    /// One request. `site` is the token-auth host the URL is on, if it is. Transport failures
    /// are [`CallError::Network`]; any status is an `Ok(Resp)`.
    pub async fn send(
        &self,
        site: Option<&str>,
        method: Method,
        url: &str,
        auth: Option<HeaderValue>,
        json: Option<&Value>,
    ) -> Result<Resp, CallError> {
        let (policy, client) = match site {
            Some(host) if self.per_site => {
                let policy = Policy::new([host.to_owned()]);
                let client = policy.client();
                (policy, client)
            }
            _ => self.fixed.clone(),
        };
        policy.check_url(url).map_err(|_| {
            CallError::Refused("the address is not one Jira may be called at".into())
        })?;
        let mut req = client
            .request(method, url)
            .header(ACCEPT, "application/json")
            .timeout(self.timeout);
        if let Some(a) = auth {
            req = req.header(AUTHORIZATION, a);
        }
        if let Some(j) = json {
            req = req.json(j);
        }
        let mut res = req.send().await.map_err(|e| net(&e))?;
        let status = res.status().as_u16();
        let retry_after = res
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|s| s.min(MAX_RETRY_SECS));
        if res
            .content_length()
            .is_some_and(|n| n > MAX_ANSWER_BYTES as u64)
        {
            return Err(CallError::TooLarge);
        }
        let mut raw = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|e| net(&e))? {
            if raw.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(CallError::TooLarge);
            }
            raw.extend_from_slice(&chunk);
        }
        let body = if raw.iter().all(u8::is_ascii_whitespace) {
            Value::Null
        } else {
            match serde_json::from_slice(&raw) {
                Ok(v) => v,
                Err(_) if !(200..300).contains(&status) => Value::Null,
                Err(_) => return Err(CallError::Upstream(status)),
            }
        };
        Ok(Resp {
            status,
            retry_after,
            body,
        })
    }
}
