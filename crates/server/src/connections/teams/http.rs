//! One request to Microsoft, and what its answer means. The client is
//! `ainkrad_providers::guard::Policy`'s: https on 443 to exactly `graph.microsoft.com` and
//! `login.microsoftonline.com`, every resolved address vetted and pinned, no proxy, no redirect,
//! timeouts, a size-capped answer. Errors are fixed text: never a URL, a header or Microsoft's own
//! message.
//!
//! **Graph** (`https://graph.microsoft.com/v1.0/...`): the path is built from fixed segments and
//! validated ids only (each pushed as ONE path segment), the query is `$top` and `$skiptoken` and
//! nothing a caller wrote, and the token is only in `Authorization`. An error is classified by its
//! `error.code` and the status, never by anything else it says; only what is about the credential
//! or the service reaches health ([`CallError::health`]).
//!
//! **Entra** (`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/...`): the device code and
//! token endpoints, a form POST with NO `Authorization` header. The tenant is `organizations` or a
//! GUID, checked here again before it becomes a path segment.

use std::fmt;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use ainkrad_providers::guard::Policy;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use reqwest::{Client, Method};
use serde_json::Value;

use super::cred::guid;

/// The largest answer read.
pub const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// A `Retry-After` is believed up to an hour.
pub const MAX_RETRY_SECS: u64 = 3_600;

pub const API_HOST: &str = "graph.microsoft.com";
pub const AUTH_HOST: &str = "login.microsoftonline.com";

/// How a call ended badly. Fixed text, safe to log and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// 401 or `InvalidAuthenticationToken` (after one renewal), or a refresh Entra refused with
    /// `invalid_grant`: a pending auth failure, which only a test confirms.
    AuthFailed,
    /// The account may not do this (403, `Forbidden`, `accessDenied`). Not a credential verdict.
    Forbidden,
    /// 404, `ResourceNotFound`, `ChannelNotFound`: no such thing, or not visible.
    NotFound,
    /// 429 or `TooManyRequests`; `retry_after` seconds when Microsoft said.
    RateLimited {
        retry_after: Option<u64>,
    },
    /// 5xx, a redirect, an unreadable answer.
    Upstream(u16),
    /// Another 4xx: the request was not acceptable.
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
    /// channel limit). Never carries an argument value.
    Refused(String),
    Internal(&'static str),
    /// Entra refused Core's own app (`invalid_client`, `unauthorized_client`, `invalid_scope`: no
    /// such app, public client flows off, a scope not on the app). No connection is at fault.
    AppConfig,
    /// Entra wants the person (`interaction_required`, `consent_required`, `login_required`: MFA,
    /// a Conditional Access step-up, consent withdrawn). The token cannot be renewed without them;
    /// it is no verdict on the credential (a later renewal may pass).
    InteractionRequired,
    /// The token is expired or refused and this Core has no Microsoft app configured.
    OAuthNotConfigured,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => f.write_str("Microsoft refused the credential"),
            Self::Forbidden => f.write_str("Microsoft says the account may not do that"),
            Self::NotFound => f.write_str("Microsoft has no such thing, or the account cannot see it"),
            Self::RateLimited { .. } => f.write_str("Microsoft is rate limiting this connection"),
            Self::Upstream(s) => write!(f, "Microsoft answered with an error ({s})"),
            Self::BadRequest(s) => write!(f, "Microsoft did not accept the request ({s})"),
            Self::Network => f.write_str("Microsoft could not be reached"),
            Self::TooLarge => f.write_str("Microsoft's answer was too large to read"),
            Self::TimedOut => f.write_str("Microsoft did not answer in time"),
            Self::Broken => f.write_str("the exchange with Microsoft broke off"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Internal(why) => f.write_str(why),
            Self::AppConfig => f.write_str(
                "Microsoft refused this Core's app registration: check the client id, the tenant, \
                 the allowed scopes and that public client flows are on",
            ),
            Self::InteractionRequired => f.write_str(
                "Microsoft needs the person to sign in again (multi-factor, a policy or consent)",
            ),
            Self::OAuthNotConfigured => f.write_str(
                "Sign in with Microsoft is not set up on this Core, so an expired token cannot be renewed",
            ),
        }
    }
}

impl std::error::Error for CallError {}

impl CallError {
    /// The signal this is for connection health (`Signal::Upstream`): status and Retry-After.
    /// `None` for what says nothing about the connection (a missing or forbidden channel, bad
    /// requests, our own refusals, a redirect, an oversized or late answer, a missing app).
    pub fn health(&self) -> Option<(UpstreamStatus, Option<u64>)> {
        match self {
            Self::AuthFailed => Some((UpstreamStatus::AuthFailed, None)),
            Self::RateLimited { retry_after } => Some((UpstreamStatus::RateLimited, *retry_after)),
            // Only Microsoft's own 5xx. A redirect, an unmapped status or an unreadable body can
            // be provoked through what an agent names, and the connection is shared.
            Self::Upstream(s) if (500..600).contains(s) => {
                Some((UpstreamStatus::ServerError, None))
            }
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
            Self::TooLarge => "too_large",
            Self::TimedOut => "timed_out",
            Self::Broken => "broken",
            Self::Refused(_) => "refused",
            Self::Internal(_) => "internal",
            Self::AppConfig => "app_config",
            Self::InteractionRequired => "interaction_required",
            Self::OAuthNotConfigured => "not_configured",
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

/// The meaning of one Graph `error.code`; `None` for a code this adapter has no word for (the
/// status decides). Never the message.
fn of_code(code: &str, retry_after: Option<u64>) -> Option<CallError> {
    Some(match code {
        "InvalidAuthenticationToken" | "Unauthorized" | "AuthenticationError" => {
            CallError::AuthFailed
        }
        "TooManyRequests"
        | "ApplicationThrottled"
        | "activityLimitReached"
        | "throttledRequest" => CallError::RateLimited { retry_after },
        "Forbidden"
        | "accessDenied"
        | "ErrorAccessDenied"
        | "Authorization_RequestDenied"
        | "AccessDenied" => CallError::Forbidden,
        "NotFound"
        | "ResourceNotFound"
        | "Request_ResourceNotFound"
        | "ChannelNotFound"
        | "ItemNotFound"
        | "itemNotFound"
        | "TeamNotFound" => CallError::NotFound,
        _ => return None,
    })
}

pub struct Resp {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub body: Value,
}

impl Resp {
    /// The body of a 2xx answer, or the error it comes to.
    pub fn into_ok(self) -> Result<Value, CallError> {
        let Self {
            status,
            retry_after,
            body,
        } = self;
        if (200..300).contains(&status) {
            return Ok(body);
        }
        if status >= 500 || (300..400).contains(&status) {
            return Err(CallError::Upstream(status));
        }
        if status == 429 {
            return Err(CallError::RateLimited { retry_after });
        }
        let code = body
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str);
        Err(code
            .and_then(|c| of_code(c, retry_after))
            .unwrap_or_else(|| classify(status, retry_after)))
    }
}

/// One Graph request: fixed segments after `/v1.0`, ids already validated by the caller.
pub struct Req {
    pub method: Method,
    pub path: Vec<String>,
    /// The pre-encoded query (`$top=20&$skiptoken=...`), built by the adapter, never a caller's.
    pub query: Option<String>,
    pub body: Option<Value>,
}

/// An Entra endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    DeviceCode,
    Token,
}

impl Endpoint {
    const fn name(self) -> &'static str {
        match self {
            Self::DeviceCode => "devicecode",
            Self::Token => "token",
        }
    }
}

/// `organizations` or a GUID: what may be a tenant path segment.
pub fn tenant_segment(t: &str) -> bool {
    t == "organizations" || guid(t)
}

/// The client and the places it may go.
#[derive(Clone)]
pub struct Http {
    policy: Policy,
    client: Client,
    /// The origin Graph calls go to.
    pub api: String,
    /// The origin the Entra endpoints are on.
    pub auth: String,
    timeout: Duration,
}

impl Http {
    pub fn production() -> Self {
        let policy = Policy::new([API_HOST.to_owned(), AUTH_HOST.to_owned()]);
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

    fn refused() -> CallError {
        CallError::Refused("the address is not one Microsoft may be called at".into())
    }

    /// One Graph call. The token travels only in `auth`.
    pub async fn graph(&self, auth: HeaderValue, req: &Req) -> Result<Resp, CallError> {
        let mut url = reqwest::Url::parse(&self.api).map_err(|_| Self::refused())?;
        {
            let mut seg = url
                .path_segments_mut()
                .map_err(|()| CallError::Internal("the address could not be made"))?;
            seg.pop_if_empty().push("v1.0");
            for s in &req.path {
                seg.push(s);
            }
        }
        url.set_query(req.query.as_deref());
        self.policy
            .check_url(url.as_str())
            .map_err(|_| Self::refused())?;
        let mut r = self
            .client
            .request(req.method.clone(), url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, auth)
            .timeout(self.timeout);
        if let Some(b) = &req.body {
            r = r.json(b);
        }
        self.read(r).await
    }

    /// A form POST to an Entra endpoint of `tenant`, with no `Authorization` header.
    pub async fn entra(
        &self,
        tenant: &str,
        endpoint: Endpoint,
        form: &[(&str, &str)],
    ) -> Result<Resp, CallError> {
        if !tenant_segment(tenant) {
            return Err(Self::refused());
        }
        let mut url = reqwest::Url::parse(&self.auth).map_err(|_| Self::refused())?;
        url.path_segments_mut()
            .map_err(|()| CallError::Internal("the address could not be made"))?
            .pop_if_empty()
            .extend([tenant, "oauth2", "v2.0", endpoint.name()]);
        self.policy
            .check_url(url.as_str())
            .map_err(|_| Self::refused())?;
        let mut enc = reqwest::Url::parse("http://form.invalid/")
            .map_err(|_| CallError::Internal("the form could not be made"))?;
        enc.query_pairs_mut().extend_pairs(form);
        let body = enc.query().unwrap_or_default().to_owned();
        let r = self
            .client
            .post(url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .timeout(self.timeout)
            .body(body);
        self.read(r).await
    }

    async fn read(&self, r: reqwest::RequestBuilder) -> Result<Resp, CallError> {
        let mut res = r.send().await.map_err(|e| net(&e))?;
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
