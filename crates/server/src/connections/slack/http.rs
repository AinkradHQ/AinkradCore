//! One request to Slack, and what its answer means. The client is
//! `ainkrad_providers::guard::Policy`'s: https on 443 to exactly `slack.com`, every resolved
//! address vetted and pinned, no proxy, no redirect, timeouts, a size-capped answer. Errors are
//! fixed text: never a URL, a header or an upstream message.
//!
//! **Web API.** Every call is a form POST to `https://slack.com/api/<method>` where the method is
//! one of [`Method`]'s constants (never text a caller wrote), with the token in an `Authorization`
//! header (never in the form or the address). Slack answers HTTP 200 with `ok:false` and an
//! `error` code for almost everything: that is a failure and its other fields are dropped. An
//! error is classified by its `error` code first and the HTTP status second, never by anything
//! else it says. Only what is about the credential or the service reaches health
//! ([`CallError::health`]).

use std::fmt;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use ainkrad_providers::guard::Policy;
use reqwest::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use serde_json::Value;

/// The largest answer read.
pub const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// A `Retry-After` is believed up to an hour: Slack's waits are seconds to minutes.
pub const MAX_RETRY_SECS: u64 = 3_600;

/// The one host: the Web API, `oauth.v2.access`, and the authorize address Core builds (which it
/// never fetches).
pub const HOST: &str = "slack.com";

/// The Web API methods this adapter calls: the whole set, fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    AuthTest,
    ConversationsInfo,
    ConversationsHistory,
    ConversationsReplies,
    ConversationsList,
    UsersInfo,
    ChatPostMessage,
    ReactionsAdd,
    OauthV2Access,
}

impl Method {
    /// The whole set, for the tests that hold the fake to it.
    #[cfg(test)]
    pub const ALL: [Method; 9] = [
        Self::AuthTest,
        Self::ConversationsInfo,
        Self::ConversationsHistory,
        Self::ConversationsReplies,
        Self::ConversationsList,
        Self::UsersInfo,
        Self::ChatPostMessage,
        Self::ReactionsAdd,
        Self::OauthV2Access,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthTest => "auth.test",
            Self::ConversationsInfo => "conversations.info",
            Self::ConversationsHistory => "conversations.history",
            Self::ConversationsReplies => "conversations.replies",
            Self::ConversationsList => "conversations.list",
            Self::UsersInfo => "users.info",
            Self::ChatPostMessage => "chat.postMessage",
            Self::ReactionsAdd => "reactions.add",
            Self::OauthV2Access => "oauth.v2.access",
        }
    }
}

/// How a call ended badly. Fixed text, safe to log and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// `invalid_auth`, `account_inactive`, `token_revoked`, `token_expired`, `not_authed` or a 401
    /// (after one renewal for a rotating token): a pending auth failure, which only a test confirms.
    AuthFailed,
    /// The token may not do this (`missing_scope`, `not_in_channel`, `is_archived`, ...). Not a
    /// credential verdict.
    Forbidden,
    /// `channel_not_found`, `thread_not_found`, `message_not_found`, `user_not_found`.
    NotFound,
    /// 429 or `ratelimited`; `retry_after` seconds when Slack said.
    RateLimited {
        retry_after: Option<u64>,
    },
    /// `rate_limited` and `message_limit_exceeded`: too many messages to a channel, or a workspace
    /// over its free limits. What an agent can provoke by posting: no health signal.
    Throttled,
    /// This family of calls is cooling on this connection (Slack said 429 or `ratelimited` to a
    /// method an agent drives): refused here with no request, no health signal, for `wait_secs`.
    Cooling {
        wait_secs: u64,
    },
    /// A rotating token was renewed but cannot be stored below `secrets.mode` 2: the connection is
    /// suspended until a person raises the mode and signs in again. No health signal.
    NeedsMode2,
    /// 5xx, a redirect, an unreadable answer, or a transient `internal_error`.
    Upstream(u16),
    /// Another `ok:false`, or a 4xx: the request was not acceptable.
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
    /// `oauth.v2.access` refused Core's own app (`invalid_client_id`, `bad_client_secret`): the
    /// registration or its secret is wrong. No connection's credential is at fault.
    AppConfig,
    /// A rotating token is expired or refused and this Core has no Slack app configured.
    OAuthNotConfigured,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => f.write_str("Slack refused the credential"),
            Self::Forbidden => f.write_str("Slack says the app may not do that"),
            Self::NotFound => f.write_str("Slack has no such thing, or the app cannot see it"),
            Self::RateLimited { .. } => f.write_str("Slack is rate limiting this connection"),
            Self::Throttled => f.write_str("Slack says too many messages were sent; wait"),
            Self::Cooling { wait_secs } => write!(
                f,
                "Slack is rate limiting this kind of call; it can be asked again in {wait_secs} seconds"
            ),
            Self::NeedsMode2 => f.write_str(
                "Slack rotated this connection's token and secrets.mode 2 is needed to store the \
                 new one: raise it, then sign in again",
            ),
            Self::Upstream(s) => write!(f, "Slack answered with an error ({s})"),
            Self::BadRequest(s) => write!(f, "Slack did not accept the request ({s})"),
            Self::Network => f.write_str("Slack could not be reached"),
            Self::TooLarge => f.write_str("Slack's answer was too large to read"),
            Self::TimedOut => f.write_str("Slack did not answer in time"),
            Self::Broken => f.write_str("the exchange with Slack broke off"),
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Internal(why) => f.write_str(why),
            Self::AppConfig => f.write_str(
                "Slack refused this Core's app registration: check the client id and secret",
            ),
            Self::OAuthNotConfigured => f.write_str(
                "Sign in with Slack is not set up on this Core, so an expired token cannot be renewed",
            ),
        }
    }
}

impl std::error::Error for CallError {}

impl CallError {
    /// The signal this is for connection health (`store::connections::health::Signal::Upstream`):
    /// status and Retry-After. `None` for what says nothing about the connection (a missing
    /// channel, a forbidden one, bad requests, our own refusals, a redirect, an oversized or late
    /// answer, a posting flood, a transient 200 error).
    pub fn health(&self) -> Option<(UpstreamStatus, Option<u64>)> {
        match self {
            Self::AuthFailed => Some((UpstreamStatus::AuthFailed, None)),
            Self::RateLimited { retry_after } => Some((UpstreamStatus::RateLimited, *retry_after)),
            // Only Slack's own 5xx. A redirect, an unmapped status or an unreadable body can be
            // provoked through what an agent names, and the connection is shared.
            Self::Upstream(s) if (500..600).contains(s) => {
                Some((UpstreamStatus::ServerError, None))
            }
            Self::Network => Some((UpstreamStatus::Unreachable, None)),
            // No app configured says nothing about any connection's credential: removing or
            // half-editing the app config must not suspend every sign-in connection.
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
            Self::Throttled => "throttled",
            Self::Cooling { .. } => "rate_limited",
            Self::NeedsMode2 => "needs_mode_2",
            Self::Upstream(_) => "upstream",
            Self::BadRequest(_) => "bad_request",
            Self::Network => "network",
            Self::TooLarge => "too_large",
            Self::TimedOut => "timed_out",
            Self::Broken => "broken",
            Self::Refused(_) => "refused",
            Self::Internal(_) => "internal",
            Self::AppConfig => "app_config",
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

/// The meaning of one `error` code; `None` for a code this adapter has no word for (it is a plain
/// bad request, never a health signal). Never the message.
fn of_code(code: &str, status: u16, retry_after: Option<u64>) -> CallError {
    match code {
        "invalid_auth" | "account_inactive" | "token_revoked" | "token_expired" | "not_authed" => {
            CallError::AuthFailed
        }
        "ratelimited" => CallError::RateLimited { retry_after },
        "rate_limited" | "message_limit_exceeded" => CallError::Throttled,
        "channel_not_found" | "thread_not_found" | "message_not_found" | "user_not_found"
        | "users_not_found" | "user_not_visible" => CallError::NotFound,
        "missing_scope"
        | "no_permission"
        | "access_denied"
        | "not_in_channel"
        | "is_archived"
        | "team_access_not_granted"
        | "app_access_restricted"
        | "not_allowed_token_type"
        | "accesslimited"
        | "ekm_access_denied"
        | "cannot_reply_to_message"
        | "channel_is_limited_access"
        | "enterprise_is_restricted"
        | "two_factor_setup_required"
        | "org_login_required"
        | "team_added_to_org"
        | "thread_locked"
        | "not_reactable"
        | "no_access" => CallError::Forbidden,
        c if c.starts_with("restricted_action") => CallError::Forbidden,
        "internal_error" | "fatal_error" | "service_unavailable" | "request_timeout" => {
            CallError::Upstream(status)
        }
        _ => CallError::BadRequest(status),
    }
}

pub struct Resp {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub body: Value,
}

impl Resp {
    /// The body of an `ok:true` answer, or the error it comes to. `ok:false` is a failure even at
    /// 200 (whatever else the body holds is dropped); a body with no `ok` is unreadable.
    pub fn into_ok(self) -> Result<Value, CallError> {
        let Self {
            status,
            retry_after,
            body,
        } = self;
        if status >= 500 || (300..400).contains(&status) {
            return Err(CallError::Upstream(status));
        }
        if status == 429 {
            return Err(CallError::RateLimited { retry_after });
        }
        match body.get("ok").and_then(Value::as_bool) {
            Some(true) if (200..300).contains(&status) => Ok(body),
            Some(false) => {
                let said = body.get("error").and_then(Value::as_str);
                Err(said.map_or_else(
                    || classify(status, retry_after),
                    |c| of_code(c, status, retry_after),
                ))
            }
            _ if !(200..300).contains(&status) => Err(classify(status, retry_after)),
            _ => Err(CallError::Upstream(status)),
        }
    }
}

/// The client and the places it may go.
#[derive(Clone)]
pub struct Http {
    policy: Policy,
    client: Client,
    /// The origin API calls go to, and the one the authorize address uses.
    pub api: String,
    timeout: Duration,
}

impl Http {
    pub fn production() -> Self {
        let policy = Policy::new([HOST.to_owned()]);
        let client = policy.client();
        Self {
            policy,
            client,
            api: format!("https://{HOST}"),
            timeout: Duration::from_secs(20),
        }
    }

    /// Tests: everything goes to one plain-http loopback origin.
    #[cfg(test)]
    pub fn loopback(addr: std::net::SocketAddr) -> Self {
        let policy = Policy::new([]).with_test_origin(addr);
        let client = policy.client();
        Self {
            policy,
            client,
            api: format!("http://{addr}"),
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

    /// One Web API call: `method` is a constant, `form` holds the values the adapter built from
    /// validated arguments. The token travels only in `auth`.
    pub async fn call(
        &self,
        auth: Option<HeaderValue>,
        method: Method,
        form: &[(&str, &str)],
    ) -> Result<Resp, CallError> {
        let url = format!("{}/api/{}", self.api, method.name());
        self.policy.check_url(&url).map_err(|_| {
            CallError::Refused("the address is not one Slack may be called at".into())
        })?;
        let mut enc = reqwest::Url::parse("http://form.invalid/")
            .map_err(|_| CallError::Internal("the form could not be made"))?;
        enc.query_pairs_mut().extend_pairs(form);
        let body = enc.query().unwrap_or_default().to_owned();
        let mut req = self
            .client
            .post(&url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .timeout(self.timeout)
            .body(body);
        if let Some(a) = auth {
            req = req.header(AUTHORIZATION, a);
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
