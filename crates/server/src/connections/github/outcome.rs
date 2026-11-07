//! How a GitHub reply ends, as plain codes (C2). Nothing GitHub said is kept: a class, a
//! cooldown, a fixed sentence.
//!
//! - `401` is an auth failure (pending: C1's health confirms it with a test before disabling).
//! - `429`, and a `403` that carries `Retry-After`, an empty `x-ratelimit-remaining` or says "rate
//!   limit" (the secondary limit), is a cooldown with the reset GitHub gave.
//! - Any other `403` is `forbidden`: the credential works but may not do this. A `404` is
//!   `not_found`: GitHub answers 404 for a private repository the credential cannot see, so the
//!   two are not told apart (and a missing repository is not told from a hidden one).
//! - `5xx` is the upstream's trouble; a redirect or anything else unexpected is the same class.

use ainkrad_proto::v2::UpstreamStatus;

use super::http::{NetError, Rate, Resp};
use crate::scheduler::iso_of_unix;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    AuthFailed,
    RateLimited {
        retry_after: Option<u64>,
        /// When the window resets, as stored time.
        reset_at: Option<String>,
    },
    Forbidden,
    NotFound,
    /// GitHub refused the input (`400`, `422`, `409`, ...).
    Invalid,
    /// The number is a pull request, and the operation is for issues.
    IsPullRequest,
    /// The number is an issue, and the operation is for pull requests.
    NotPullRequest,
    ServerError,
    Unexpected,
    Net(NetError),
}

impl Outcome {
    /// The plain code (what an API or a tool result says).
    pub fn code(&self) -> &'static str {
        match self {
            Self::AuthFailed => "auth_failed",
            Self::RateLimited { .. } => "rate_limited",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Invalid => "invalid",
            Self::IsPullRequest => "is_pull_request",
            Self::NotPullRequest => "not_pull_request",
            Self::ServerError | Self::Unexpected => "upstream",
            Self::Net(NetError::Refused) => "refused_address",
            Self::Net(NetError::BadRequest) => "bad_request",
            Self::Net(_) => "unreachable",
        }
    }

    /// A sentence fit for a person.
    pub fn message(&self) -> &'static str {
        match self {
            Self::AuthFailed => {
                "GitHub did not accept the connection's sign-in. Test it, and sign in again if it fails."
            }
            Self::RateLimited { .. } => {
                "GitHub is rate limiting this connection; it will be used again when the limit resets."
            }
            Self::Forbidden => "The connection is not allowed to do that on GitHub.",
            Self::NotFound => "GitHub says this does not exist, or the connection cannot see it.",
            Self::Invalid => "GitHub refused the request as it was written.",
            Self::IsPullRequest => {
                "That number is a pull request; use the pull request operations."
            }
            Self::NotPullRequest => "That number is an issue, not a pull request.",
            Self::ServerError | Self::Unexpected => "GitHub had a problem. Try again shortly.",
            Self::Net(NetError::TooLarge) => "GitHub's answer was too large to read.",
            Self::Net(NetError::Refused) => "GitHub resolved to an address Core will not use.",
            Self::Net(NetError::BadRequest) => "That request is not one Core sends to GitHub.",
            Self::Net(_) => "GitHub could not be reached.",
        }
    }

    /// The class to tell the connection's health (`Signal::Upstream`), or `None` when the call
    /// says nothing about the credential or the service (a 404, a refused input).
    pub fn health(&self) -> Option<UpstreamStatus> {
        match self {
            Self::AuthFailed => Some(UpstreamStatus::AuthFailed),
            Self::RateLimited { .. } => Some(UpstreamStatus::RateLimited),
            // Only GitHub's own 5xx. A redirect, a 451, a 413 or an unmapped status can be
            // provoked by an agent through the repository it names (a renamed, transferred or
            // blocked repo, a huge issue), and the connection is shared: it must not count.
            Self::ServerError => Some(UpstreamStatus::ServerError),
            Self::Net(NetError::Refused) => Some(UpstreamStatus::RefusedAddress),
            Self::Net(NetError::Unreachable | NetError::Timeout) => {
                Some(UpstreamStatus::Unreachable)
            }
            Self::Forbidden
            | Self::NotFound
            | Self::Invalid
            | Self::IsPullRequest
            | Self::NotPullRequest
            | Self::Unexpected
            | Self::Net(NetError::TooLarge | NetError::BadRequest) => None,
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Outcome {}

impl From<NetError> for Outcome {
    fn from(e: NetError) -> Self {
        Self::Net(e)
    }
}

fn limited(rate: &Rate) -> Outcome {
    Outcome::RateLimited {
        retry_after: rate.retry_after,
        reset_at: rate.reset.filter(|r| *r > 0).map(iso_of_unix),
    }
}

/// `Ok` for a 2xx; the outcome of any other reply.
pub fn classify(r: &Resp) -> Result<(), Outcome> {
    match r.status {
        200..=299 => Ok(()),
        401 => Err(Outcome::AuthFailed),
        429 => Err(limited(&r.rate)),
        403 => {
            let head = &r.body[..r.body.len().min(2048)];
            let says = String::from_utf8_lossy(head).to_ascii_lowercase();
            if r.rate.retry_after.is_some()
                || r.rate.remaining == Some(0)
                || says.contains("rate limit")
            {
                Err(limited(&r.rate))
            } else {
                Err(Outcome::Forbidden)
            }
        }
        404 | 410 => Err(Outcome::NotFound),
        400 | 405 | 409 | 422 => Err(Outcome::Invalid),
        500..=599 => Err(Outcome::ServerError),
        _ => Err(Outcome::Unexpected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, rate: Rate, body: &str) -> Resp {
        Resp {
            status,
            rate,
            scopes: None,
            body: zeroize::Zeroizing::new(body.as_bytes().to_vec()),
        }
    }

    #[test]
    fn statuses_map_to_plain_codes() {
        let r = Rate::default();
        let code = |s, body| classify(&resp(s, r, body)).unwrap_err().code();
        assert!(classify(&resp(201, r, "")).is_ok());
        assert_eq!(code(401, ""), "auth_failed");
        assert_eq!(code(404, ""), "not_found");
        assert_eq!(
            code(403, r#"{"message":"Resource not accessible"}"#),
            "forbidden"
        );
        assert_eq!(
            code(
                403,
                r#"{"message":"You have exceeded a secondary rate limit"}"#
            ),
            "rate_limited"
        );
        assert_eq!(code(429, ""), "rate_limited");
        assert_eq!(code(422, ""), "invalid");
        assert_eq!(code(502, ""), "upstream");
        assert_eq!(code(302, ""), "upstream");
    }

    #[test]
    fn a_cooldown_carries_retry_after_and_reset() {
        let rate = Rate {
            remaining: Some(0),
            reset: Some(1_800_000_000),
            retry_after: Some(60),
            ..Rate::default()
        };
        let e = classify(&resp(403, rate, "")).unwrap_err();
        assert_eq!(
            e,
            Outcome::RateLimited {
                retry_after: Some(60),
                reset_at: Some(iso_of_unix(1_800_000_000)),
            }
        );
        assert_eq!(e.health(), Some(UpstreamStatus::RateLimited));
        assert_eq!(Outcome::NotFound.health(), None);
        assert_eq!(
            Outcome::AuthFailed.health(),
            Some(UpstreamStatus::AuthFailed)
        );
    }
}
