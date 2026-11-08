//! How a call that did not return data ends: a plain code, a fixed sentence, and the health class
//! of the end (if it says anything about the connection). Nothing an upstream said is kept.

use super::health::Feed;
use crate::connections::github::Outcome;
use crate::connections::jira::CallError;
use crate::connections::linear::CallError as LinearError;
use crate::connections::teams::CallError as TeamsError;
use crate::store::secrets::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub code: String,
    pub message: String,
    /// `refused` (the broker said no before any upstream call) or `error` (the call was made).
    pub result: &'static str,
    pub feed: Option<Feed>,
}

/// A sentence that came from our own code but may quote what the caller wrote: no control
/// characters, at most 160 characters.
pub fn tidy(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(160).collect()
}

pub fn refuse(code: &str, message: &str) -> Fail {
    Fail {
        code: code.to_owned(),
        message: tidy(message),
        result: "refused",
        feed: None,
    }
}

/// A store refusal (`resolve`, `secret::open`) as a call's refusal; a database error is `internal`.
pub fn of_store(e: Error) -> Fail {
    match e {
        Error::Refused { code, message } => refuse(code, &message),
        Error::Db(e) => {
            tracing::error!(error = %e, "the connection broker could not read the store");
            refuse("internal", "the connection broker failed")
        }
    }
}

impl Fail {
    fn upstream(code: &str, message: &str, feed: Option<Feed>) -> Self {
        Self {
            code: code.to_owned(),
            message: tidy(message),
            result: "error",
            feed,
        }
    }

    pub fn of_github(o: &Outcome) -> Self {
        let feed = match o {
            Outcome::RateLimited {
                retry_after,
                reset_at,
            } => o.health().map(|status| Feed {
                status,
                retry_after: *retry_after,
                reset_at: reset_at.clone(),
            }),
            other => other.health().map(Feed::of),
        };
        Self::upstream(o.code(), o.message(), feed)
    }

    pub fn of_teams(e: &TeamsError) -> Self {
        let feed = e.health().map(|(status, retry_after)| Feed {
            status,
            retry_after,
            reset_at: None,
        });
        // No app configured is our own state, not the service's answer: a plain refusal.
        let ours = matches!(e, TeamsError::Refused(_) | TeamsError::OAuthNotConfigured);
        let result = if ours { "refused" } else { "error" };
        Self {
            result,
            ..Self::upstream(e.code(), &e.to_string(), feed)
        }
    }

    pub fn of_linear(e: &LinearError) -> Self {
        let feed = e.health().map(|(status, retry_after)| Feed {
            status,
            retry_after,
            reset_at: None,
        });
        // No app configured is our own state, not the service's answer: a plain refusal.
        let ours = matches!(e, LinearError::Refused(_) | LinearError::OAuthNotConfigured);
        let result = if ours { "refused" } else { "error" };
        Self {
            result,
            ..Self::upstream(e.code(), &e.to_string(), feed)
        }
    }

    pub fn of_jira(e: &CallError) -> Self {
        let feed = e.health().map(|(status, retry_after)| Feed {
            status,
            retry_after,
            reset_at: None,
        });
        // A refusal by the adapter's own rules, or no app configured (our own state), is a
        // refusal, not an upstream error.
        let result = if matches!(e, CallError::Refused(_) | CallError::OAuthNotConfigured) {
            "refused"
        } else {
            "error"
        };
        Self {
            result,
            ..Self::upstream(e.code(), &e.to_string(), feed)
        }
    }
}
