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
    /// No answer: refused address, connection, TLS, timeout or an over-size answer.
    Network,
    /// Refused here, before or after the call, by the adapter's own rules (bad arguments, the
    /// project limit). Never carries an argument value.
    Refused(String),
    Internal(&'static str),
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
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Internal(why) => f.write_str(why),
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
            Self::Upstream(_) => Some((UpstreamStatus::ServerError, None)),
            Self::Network => Some((UpstreamStatus::Unreachable, None)),
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
            Self::Refused(_) => "refused",
            Self::Internal(_) => "internal",
        }
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
pub struct Http {
    fixed: (Policy, Client),
    /// Production: a token-auth site gets a client of its own, allowing that one host.
    per_site: bool,
    pub api: String,
    pub auth: String,
    site: Option<String>,
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
        }
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
            .timeout(Duration::from_secs(20));
        if let Some(a) = auth {
            req = req.header(AUTHORIZATION, a);
        }
        if let Some(j) = json {
            req = req.json(j);
        }
        let mut res = req.send().await.map_err(|_| CallError::Network)?;
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
            return Err(CallError::Network);
        }
        let mut raw = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|_| CallError::Network)? {
            if raw.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(CallError::Network);
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
