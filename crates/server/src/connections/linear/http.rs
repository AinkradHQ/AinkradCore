//! One request to Linear, and what its answer means. The client is
//! `ainkrad_providers::guard::Policy`'s: https on 443 to exactly `api.linear.app`, every resolved
//! address vetted and pinned, no proxy, no redirect, timeouts, a size-capped answer. `linear.app`
//! is only in the descriptor, for the authorize address Core builds and never fetches: the policy
//! refuses it, so no bearer can be sent there. Errors are fixed text: never a URL, a header or an
//! upstream message.
//!
//! **GraphQL.** A 200 can carry an `errors` array: that is a failure, whatever `data` holds. An
//! error is classified by its `extensions.code` first and the HTTP status second, never by its
//! message. Only what is about the credential or the service reaches health (`CallError::health`).

use std::fmt;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use ainkrad_providers::guard::Policy;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use reqwest::{Client, Method};
use serde_json::{Value, json};

/// The largest answer read.
pub const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// A `Retry-After` is believed up to a day.
const MAX_RETRY_SECS: u64 = 86_400;

pub const API_HOST: &str = "api.linear.app";
pub const AUTH_HOST: &str = "linear.app";

/// How a call ended badly. Fixed text, safe to log and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// 401 or an `AUTHENTICATION_ERROR` (after one refresh for OAuth), or a refresh the service
    /// refused: a pending auth failure, which only a test confirms.
    AuthFailed,
    /// 403 or `FORBIDDEN`: the account may not do this. Not a credential verdict.
    Forbidden,
    NotFound,
    /// 429 or `RATELIMITED`; `retry_after` seconds when the service said.
    RateLimited {
        retry_after: Option<u64>,
    },
    /// 5xx, a redirect or an unreadable answer.
    Upstream(u16),
    /// Another error: the request was not acceptable (bad input, a complexity refusal).
    BadRequest(u16),
    /// No connection: the connect or the TLS handshake failed.
    Network,
    /// The answer was longer than we read. Says nothing about the service's health.
    TooLarge,
    /// No answer in time. Says nothing about the service's health.
    TimedOut,
    /// The exchange broke off some other way. No health signal.
    Broken,
    /// Refused here, before or after the call, by the adapter's own rules (bad arguments, the
    /// team limit). Never carries an argument value.
    Refused(String),
    Internal(&'static str),
    /// The token endpoint refused Core's own app (`invalid_client`, `unauthorized_client`): the
    /// Linear app registration or its secret is wrong. No connection's credential is at fault.
    AppConfig,
    /// An OAuth token is expired or refused and this Core has no Linear app configured.
    OAuthNotConfigured,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => f.write_str("Linear refused the credential"),
            Self::Forbidden => f.write_str("Linear says the account may not do that"),
            Self::NotFound => f.write_str("Linear has no such thing, or the account cannot see it"),
            Self::RateLimited { .. } => f.write_str("Linear is rate limiting this connection"),
            Self::Upstream(s) => write!(f, "Linear answered with an error ({s})"),
            Self::BadRequest(s) => write!(f, "Linear did not accept the request ({s})"),
            Self::Network => f.write_str("Linear could not be reached"),
            Self::TooLarge => f.write_str("Linear's answer was too large to read"),
            Self::TimedOut => f.write_str("Linear did not answer in time"),
            Self::Broken => f.write_str("the exchange with Linear broke off"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Internal(why) => f.write_str(why),
            Self::AppConfig => f.write_str(
                "Linear refused this Core's app registration: check the client id and secret",
            ),
            Self::OAuthNotConfigured => f.write_str(
                "Sign in with Linear is not set up on this Core, so an expired token cannot be renewed",
            ),
        }
    }
}

impl std::error::Error for CallError {}

impl CallError {
    /// The signal this is for connection health (`store::connections::health::Signal::Upstream`):
    /// status and Retry-After. `None` for what says nothing about the connection (403, not found,
    /// bad requests, our own refusals, a redirect, an oversized or late answer).
    pub fn health(&self) -> Option<(UpstreamStatus, Option<u64>)> {
        match self {
            Self::AuthFailed => Some((UpstreamStatus::AuthFailed, None)),
            Self::RateLimited { retry_after } => Some((UpstreamStatus::RateLimited, *retry_after)),
            // Only Linear's own 5xx. A redirect, an unmapped status or an unreadable body can be
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

/// The error of a non-2xx status with no better word from the body.
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

/// Lower is worse: when an answer holds several errors, the worst decides.
fn severity(e: &CallError) -> u8 {
    match e {
        CallError::AuthFailed => 0,
        CallError::RateLimited { .. } => 1,
        CallError::Forbidden => 2,
        CallError::NotFound => 3,
        _ => 4,
    }
}

/// The meaning of one GraphQL error's `extensions.code` (case and separators ignored); `None`
/// for a code this adapter has no word for. Never the message.
fn of_code(code: &str, retry_after: Option<u64>) -> Option<CallError> {
    let c: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    match c.as_str() {
        "AUTHENTICATIONERROR" | "UNAUTHENTICATED" => Some(CallError::AuthFailed),
        "RATELIMITED" | "RATELIMIT" => Some(CallError::RateLimited { retry_after }),
        "FORBIDDEN" => Some(CallError::Forbidden),
        "NOTFOUND" | "ENTITYNOTFOUND" => Some(CallError::NotFound),
        _ => None,
    }
}

pub struct Resp {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub body: Value,
}

impl Resp {
    /// The `data` of a GraphQL answer, or the error it comes to. A body with `errors` is a failure
    /// even at 200 (partial `data` is dropped); a body with no `data` object is unreadable.
    pub fn into_data(self) -> Result<Value, CallError> {
        let Self {
            status,
            retry_after,
            body,
        } = self;
        if status >= 500 || (300..400).contains(&status) {
            return Err(CallError::Upstream(status));
        }
        let errors = body.get("errors").filter(|e| !e.is_null());
        if let Some(errors) = errors {
            let list = errors.as_array().map(Vec::as_slice).unwrap_or_default();
            let worst = list
                .iter()
                .filter_map(|e| {
                    let ext = e.get("extensions")?;
                    // Linear names an error by `code` (`RATELIMITED`) and by `type` ("ratelimited").
                    let word = |k: &str| ext.get(k).and_then(Value::as_str);
                    let by = |k: &str| word(k).and_then(|c| of_code(c, retry_after));
                    by("code").or_else(|| by("type"))
                })
                .min_by_key(severity);
            return Err(worst.unwrap_or_else(|| {
                if (200..300).contains(&status) {
                    CallError::BadRequest(status)
                } else {
                    classify(status, retry_after)
                }
            }));
        }
        if !(200..300).contains(&status) {
            return Err(classify(status, retry_after));
        }
        match body.get("data") {
            Some(d) if d.is_object() => Ok(d.clone()),
            _ => Err(CallError::Upstream(status)),
        }
    }
}

/// The client and the places it may go.
#[derive(Clone)]
pub struct Http {
    policy: Policy,
    client: Client,
    /// The origin API calls go to, and the one the authorize address and token endpoint use.
    pub api: String,
    pub auth: String,
    timeout: Duration,
}

impl Http {
    pub fn production() -> Self {
        let policy = Policy::new([API_HOST.to_owned()]);
        let client = policy.client();
        Self {
            policy,
            client,
            api: format!("https://{API_HOST}"),
            auth: format!("https://{AUTH_HOST}"),
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
            policy,
            client,
            api: origin.clone(),
            auth: origin,
            timeout: Duration::from_secs(20),
        }
    }

    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether `url` may be called at all (the policy's allow-list).
    #[cfg(test)]
    pub fn allows(&self, url: &str) -> bool {
        self.policy.check_url(url).is_ok()
    }

    /// One GraphQL operation: a fixed document and its variables. `query` is always one of
    /// `docs`' constants, never text a caller wrote.
    pub async fn graphql(
        &self,
        auth: HeaderValue,
        query: &'static str,
        name: &'static str,
        variables: &Value,
    ) -> Result<Resp, CallError> {
        let url = format!("{}/graphql", self.api);
        let body = json!({"query": query, "operationName": name, "variables": variables});
        self.send(Method::POST, &url, Some(auth), Some(Body::Json(&body)))
            .await
    }

    /// POSTs the token endpoint (`application/x-www-form-urlencoded`, which is what Linear takes).
    pub async fn token(&self, pairs: &[(&str, &str)]) -> Result<Resp, CallError> {
        let url = format!("{}/oauth/token", self.api);
        let mut enc = reqwest::Url::parse("http://form.invalid/")
            .map_err(|_| CallError::Internal("the form could not be made"))?;
        enc.query_pairs_mut().extend_pairs(pairs);
        let form = enc.query().unwrap_or_default().to_owned();
        self.send(Method::POST, &url, None, Some(Body::Form(form)))
            .await
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        auth: Option<HeaderValue>,
        body: Option<Body<'_>>,
    ) -> Result<Resp, CallError> {
        self.policy.check_url(url).map_err(|_| {
            CallError::Refused("the address is not one Linear may be called at".into())
        })?;
        let mut req = self
            .client
            .request(method, url)
            .header(ACCEPT, "application/json")
            .timeout(self.timeout);
        if let Some(a) = auth {
            req = req.header(AUTHORIZATION, a);
        }
        req = match body {
            Some(Body::Json(j)) => req.json(j),
            Some(Body::Form(f)) => req
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(f),
            None => req,
        };
        let mut res = req.send().await.map_err(|e| net(&e))?;
        let status = res.status().as_u16();
        let header = |name: &str| res.headers().get(name).and_then(|v| v.to_str().ok());
        // `Retry-After` is seconds; the reset header is UTC epoch MILLISECONDS.
        let reset_in = header("x-ratelimit-requests-reset")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|ms| (ms / 1000).saturating_sub(now_secs()));
        let retry_after = header(RETRY_AFTER.as_str())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .or(reset_in)
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

enum Body<'a> {
    Json(&'a Value),
    Form(String),
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
