//! What a failed turn means for its run: the provider dropped it and the same session should
//! resume (E15.4), or another (harness, model) of the agent's fallback chain should take over
//! (E15.3), or neither. Each adapter's failure `code` is its harness's own
//! error class, with the provider's HTTP status after a `:` where it reports one:
//!
//! - Claude: the `result` subtype, plus `api_error_status` (`error_during_execution:429`;
//!   `529` is Anthropic's `overloaded_error`, and a lost connection reads "API Error:
//!   Connection error."). Its
//!   usage-limit text is "Claude AI usage limit reached" / "… limit reached ∙ resets …"; an
//!   unknown or inaccessible model is "There's an issue with the selected model (…). It may not
//!   exist or you may not have access to it." (Claude Code 2.1.x).
//! - Codex: `codexErrorInfo`'s variant (app-server schema 0.154.0): `usageLimitExceeded` is
//!   the plan's quota; `httpConnectionFailed`, `responseStreamConnectionFailed`,
//!   `responseStreamDisconnected`, `internalServerError` and `responseTooManyFailedAttempts`
//!   are the provider dropping the turn; `unauthorized`, `badRequest`, `contextWindowExceeded`
//!   are permanent, except `unauthorized`, which is `Auth`.
//! - OpenCode: the `session.error` name, plus `data.statusCode` for an `APIError`
//!   (`APIError:429`); `ProviderAuthError` is `Auth`.
//! - agy: the result status (`error`); only its text says more (Google's
//!   `RESOURCE_EXHAUSTED`, `NOT_FOUND` for a model, `UNAVAILABLE` / `DEADLINE_EXCEEDED`).
//! - Every harness: a process that ends mid-turn without a result (`harness_exit`) is a reset
//!   stream; the runner resumes its session. One that ends after Citadel refused a request it
//!   does not know (a newer CLI's control request or JSON-RPC method) is `protocol`.
//!
//! The text is matched case-insensitively as a last resort, for every harness.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The model does not exist or this account may not use it.
    ModelUnavailable,
    /// Too many requests right now.
    RateLimited,
    /// The account's plan or credit is used up.
    Quota,
    /// The provider refused the account's credentials (401/403, an invalid or expired key or
    /// token). Another account may work; the same one will not.
    Auth,
    /// The provider dropped the turn (network, 5xx, overloaded, a reset stream): resume the
    /// same session (E15.4).
    Transient,
    /// The account dropped the run too often: its turns go to the next entry (E15.4).
    Unhealthy,
    /// The harness speaks a protocol its adapter does not know (a newer CLI): the next entry
    /// of the chain, another harness, may not.
    Protocol,
    /// Anything else: retrying elsewhere would fail the same way.
    Permanent,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModelUnavailable => "model_unavailable",
            Self::RateLimited => "rate_limited",
            Self::Quota => "quota",
            Self::Auth => "auth",
            Self::Transient => "transient",
            Self::Unhealthy => "unhealthy",
            Self::Protocol => "protocol",
            Self::Permanent => "permanent",
        }
    }

    /// Whether the next entry of the agent's fallback chain should take the run.
    pub fn falls_back(self) -> bool {
        !matches!(self, Self::Permanent | Self::Transient)
    }
}

const QUOTA: &[&str] = &[
    "usage limit",
    "limit reached",
    "hit your limit",
    "quota",
    "credit balance",
    "billing",
    "key limit exceeded",
];
const RATE: &[&str] = &[
    "rate limit",
    "rate_limit",
    "ratelimit",
    "too many requests",
    "resource_exhausted",
];
const AUTH: &[&str] = &[
    "unauthorized",
    "authentication_error",
    "authentication failed",
    "invalid api key",
    "invalid x-api-key",
    "invalid_api_key",
    "incorrect api key",
    "oauth token has expired",
    "oauth token expired",
    "token has expired",
    "please run /login",
    "permission_denied",
];
/// A 403 or a permission error that is the project's or API's setup, not the credentials.
const SETUP: &[&str] = &[
    "has not been used in project",
    "has not been enabled",
    "api is not enabled",
    "service_disabled",
];
const MODEL: &[&str] = &[
    "not found",
    "not_found",
    "does not exist",
    "may not exist",
    "not available",
    "unknown model",
    "invalid model",
    "not supported",
];

const TRANSIENT: &[&str] = &[
    "overloaded",
    "connection error",
    "connection reset",
    "connection refused",
    "econnreset",
    "socket hang up",
    "fetch failed",
    "network",
    "timed out",
    "stream disconnected",
    "stream error",
    "internal server error",
    "bad gateway",
    "service unavailable",
    "unavailable",
    "deadline_exceeded",
];

/// An adapter's code for a turn its harness ended over a request the adapter does not know.
pub const PROTOCOL: &str = "protocol";

/// The runner's code for a run whose provider dropped it more often than it resumes.
pub const DROPPED: &str = "provider_dropped";

/// The class of a failed turn, from the adapter's `code` and the harness's `reason`.
pub fn classify(code: &str, reason: &str) -> ErrorClass {
    let (name, status) = match code.rsplit_once(':') {
        Some((name, status)) => (name, status.parse::<u16>().ok()),
        None => (code, None),
    };
    let text = reason.to_lowercase();
    let says = |words: &[&str]| words.iter().any(|w| text.contains(w));
    match (name, status) {
        (DROPPED, _) => return ErrorClass::Unhealthy,
        (PROTOCOL, _) => return ErrorClass::Protocol,
        ("harness_exit", _) => return ErrorClass::Transient,
        ("usageLimitExceeded", _) => return ErrorClass::Quota,
        (
            "httpConnectionFailed"
            | "responseStreamConnectionFailed"
            | "responseStreamDisconnected"
            | "internalServerError"
            | "responseTooManyFailedAttempts",
            _,
        ) => return ErrorClass::Transient,
        ("unauthorized" | "ProviderAuthError", _) => return ErrorClass::Auth,
        ("badRequest" | "contextWindowExceeded", _) => return ErrorClass::Permanent,
        (_, Some(429)) if says(QUOTA) => return ErrorClass::Quota,
        (_, Some(429)) => return ErrorClass::RateLimited,
        (_, Some(404)) => return ErrorClass::ModelUnavailable,
        // A key's own spending limit is a quota, whatever status carries it.
        (_, Some(401 | 403)) if says(QUOTA) => return ErrorClass::Quota,
        // A 403 about a model is the model's access, not the credentials.
        (_, Some(403)) if text.contains("model") && says(MODEL) => {
            return ErrorClass::ModelUnavailable;
        }
        // A project or API that is not set up fails the same way for every account.
        (_, Some(403)) if says(SETUP) => return ErrorClass::Permanent,
        (_, Some(401 | 403)) => return ErrorClass::Auth,
        (_, Some(500 | 502 | 503 | 504 | 529)) => return ErrorClass::Transient,
        _ => {}
    }
    if says(QUOTA) {
        ErrorClass::Quota
    } else if says(RATE) {
        ErrorClass::RateLimited
    } else if text.contains("model") && says(MODEL) {
        ErrorClass::ModelUnavailable
    } else if says(AUTH) && !says(SETUP) {
        ErrorClass::Auth
    } else if says(TRANSIENT) {
        ErrorClass::Transient
    } else {
        ErrorClass::Permanent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ErrorClass::*;

    #[test]
    fn documented_failures_classify() {
        let cases = [
            // Claude
            (
                "error_during_execution:429",
                "API Error: 429 rate_limit_error",
                RateLimited,
            ),
            ("success", "Claude AI usage limit reached|1792681200", Quota),
            (
                "error_during_execution",
                "5-hour limit reached ∙ resets 3pm",
                Quota,
            ),
            (
                "error_during_execution:404",
                "There's an issue with the selected model (claude-opus-9). It may not exist \
                 or you may not have access to it.",
                ModelUnavailable,
            ),
            (
                "error_during_execution",
                "[ede_diagnostic] result_type=user",
                Permanent,
            ),
            // Codex
            ("usageLimitExceeded", "You've hit your usage limit.", Quota),
            ("unauthorized", "401 Unauthorized", Auth),
            ("other", "model gpt-9 does not exist", ModelUnavailable),
            // OpenCode
            ("APIError:429", "Too Many Requests", RateLimited),
            ("ProviderAuthError", "key expired", Auth),
            ("APIError:404", "Not Found", ModelUnavailable),
            // agy
            (
                "error",
                "RESOURCE_EXHAUSTED: Resource has been exhausted",
                RateLimited,
            ),
            (
                "error",
                "NOT_FOUND: model gemini-9 is not found",
                ModelUnavailable,
            ),
            // Dropped turns, recorded or documented shapes.
            (
                "error_during_execution:529",
                r#"API Error: 529 {"type":"error","error":{"type":"overloaded_error"}}"#,
                Transient,
            ),
            ("success", "API Error: Connection error.", Transient),
            (
                "success:500",
                "API Error: 500 Internal server error",
                Transient,
            ),
            (
                "responseStreamDisconnected",
                "stream disconnected before completion",
                Transient,
            ),
            ("APIError:503", "Service Unavailable", Transient),
            (
                "error",
                "UNAVAILABLE: The service is currently unavailable.",
                Transient,
            ),
            ("harness_exit", "claude ended without a result", Transient),
            ("provider_dropped", "dropped 3 times", Unhealthy),
        ];
        for (code, reason, want) in cases {
            assert_eq!(classify(code, reason), want, "{code}: {reason}");
        }
        assert!(Quota.falls_back() && Unhealthy.falls_back() && Protocol.falls_back());
        assert!(Auth.falls_back() && Auth.as_str() == "auth");
        assert_eq!(classify(PROTOCOL, "exited after a 429"), Protocol);
        assert!(!Permanent.falls_back() && !Transient.falls_back());
    }

    /// 401/403/429/5xx as status codes and as bare text, whatever the harness.
    #[test]
    fn status_and_text_variants_of_auth_rate_and_server_errors() {
        let cases = [
            (
                "error_during_execution:401",
                "API Error: 401 authentication_error",
                Auth,
            ),
            ("error_during_execution:401", "", Auth),
            ("success:403", "API Error: 403 forbidden", Auth),
            ("APIError:403", "Forbidden", Auth),
            (
                "APIError:403",
                "model gpt-9 is not available to you",
                ModelUnavailable,
            ),
            ("success", "Invalid API key · Please run /login", Auth),
            (
                "success",
                "OAuth token has expired. Please obtain a new token",
                Auth,
            ),
            (
                "error",
                "PERMISSION_DENIED: the caller does not have permission",
                Auth,
            ),
            ("error", "Incorrect API key provided: sk-...", Auth),
            (
                "error_during_execution:429",
                "Too Many Requests",
                RateLimited,
            ),
            ("error_during_execution:429", "5-hour limit reached", Quota),
            ("success", "rate_limit_error: slow down", RateLimited),
            ("success:500", "boom", Transient),
            ("success:502", "Bad Gateway", Transient),
            ("success:503", "Service Unavailable", Transient),
            ("success:504", "", Transient),
            ("success:529", "overloaded_error", Transient),
            ("success", "Internal server error", Transient),
        ];
        for (code, reason, want) in cases {
            assert_eq!(classify(code, reason), want, "{code}: {reason}");
        }
    }

    #[test]
    fn a_key_limit_is_quota_and_a_setup_error_is_not_auth() {
        assert_eq!(
            classify("APIError:403", "Key limit exceeded (monthly)"),
            Quota
        );
        assert_eq!(
            classify("APIError:401", "billing hard limit reached"),
            Quota
        );
        for (code, reason) in [
            (
                "error",
                "PERMISSION_DENIED: Gemini API has not been used in project 123 before",
            ),
            (
                "error:403",
                "PERMISSION_DENIED: the API has not been enabled for this project",
            ),
            (
                "APIError:403",
                "Cloud Resource Manager API has not been used in project x",
            ),
            ("error", "SERVICE_DISABLED: PERMISSION_DENIED"),
        ] {
            assert_eq!(classify(code, reason), Permanent, "{code}: {reason}");
        }
        assert_eq!(classify("error", "PERMISSION_DENIED: no access"), Auth);
    }

    /// Quota and rate words win over an auth word in the same text, and a 4xx number inside
    /// ordinary text is no status: only the adapter's `code` carries one.
    #[test]
    fn auth_is_never_guessed_from_a_number_or_beaten_by_a_limit() {
        assert_eq!(
            classify("success", "usage limit reached, unauthorized"),
            Quota
        );
        assert_eq!(classify("success", "rate limit; forbidden"), RateLimited);
        assert_eq!(
            classify("error", "wrote 401 lines and 403 tests"),
            Permanent
        );
        assert_eq!(classify("error", "exit 401"), Permanent);
    }
}
