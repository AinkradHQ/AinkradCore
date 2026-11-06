//! What becomes of an attempt that is over: the §8.1 decision table, as one pure function of the
//! row the Core stored. Nothing here reads a clock or the runner, so the decision is the same on a
//! restart as it was at the end (a half-done move is finished the way it was begun).

use serde_json::Value;

use super::View;

/// The `ErrorClass::as_str` values that move a run on (`falls_back()` of the harness crate, the
/// server does not depend on it): the account or the model cannot go on, another may.
pub const FALLS_BACK: [&str; 6] = [
    "model_unavailable",
    "rate_limited",
    "quota",
    "auth",
    "unhealthy",
    "protocol",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Start a new attempt, because of this class.
    Move(String),
    /// The run ends with this attempt, for this reason.
    End(&'static str),
}

/// The budget a gateway stop names (`gateway::exhausted` writes `budget exhausted: <kind> <subject>
/// (<period>, <key>)` itself, so this reads the Core's own text, never a runner's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStop {
    Account(i64),
    Pool(i64),
}

pub fn budget_stop(why: &str) -> Option<BudgetStop> {
    let rest = why.strip_prefix("budget exhausted: ")?;
    let (kind, rest) = rest.split_once(' ')?;
    let subject: i64 = rest.split(' ').next()?.parse().ok()?;
    match kind {
        "account" => Some(BudgetStop::Account(subject)),
        "pool" => Some(BudgetStop::Pool(subject)),
        _ => None,
    }
}

/// §8.1, row by row.
pub fn decide(v: &View) -> Decision {
    use Decision::{End, Move};
    // A module's session, a session that names its account itself and one that never got an
    // account have no chain to walk.
    if v.module || v.chain.is_none() || v.account.is_none() {
        return End("the session has no chain to move along");
    }
    let outcome = v.outcome.clone().unwrap_or(Value::Null);
    let kind = outcome["kind"].as_str().unwrap_or("");
    // A runner that never came back is not an account failure, and the run stays on its runner (4).
    if v.state == "lost" {
        return End("the runner was lost");
    }
    // It finished, or its own limits ended it: no account is to blame (1). Checked before the
    // move the Core ordered, so a stop that raced a real finish never starts a second attempt.
    if matches!(kind, "succeeded" | "token_cap" | "stalled") {
        return End("the attempt finished");
    }
    // The move was decided, and written before the stop that ended it was sent (0).
    if let Some(class) = &v.class {
        return Move(class.clone());
    }
    // A budget stop (2): an account or pool budget moves the run, a session limit or ceiling ends it.
    if let Some(why) = &v.gw_stop {
        return match budget_stop(why) {
            Some(_) => Move("budget_pool".to_owned()),
            None => End("the session reached its own limit"),
        };
    }
    match kind {
        // A person's cancel or kill, or the runner's own stop (1).
        "cancelled" => End("it was cancelled"),
        "failed" => failed(v, &outcome),
        _ => End("the attempt ended without a class that moves a run"),
    }
}

/// A failed end (3). The class comes from the gateway's own reports when the attempt had a
/// gateway, and from the harness's fingerprint when it had none (a subscription, or no report).
fn failed(v: &View, outcome: &Value) -> Decision {
    use Decision::{End, Move};
    if v.gateway
        && let Some(up) = v.upstream.as_deref()
    {
        return match up {
            "rate_limited" => Move("rate_limited".to_owned()),
            "quota" => Move("quota".to_owned()),
            "auth_failed" => Move("auth".to_owned()),
            "server_error" | "unreachable" | "tls_failed" => Move("upstream_errors".to_owned()),
            // `ok` says the task failed, not the account; `refused_address` is a configuration
            // error that every attempt on the account would meet the same way.
            _ => End("the gateway saw no account failure"),
        };
    }
    match outcome["fingerprint"].as_str() {
        Some(class) if FALLS_BACK.contains(&class) => Move(class.to_owned()),
        _ => End("the failure is the task's, not the account's"),
    }
}
