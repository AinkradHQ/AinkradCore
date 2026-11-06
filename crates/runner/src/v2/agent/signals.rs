//! What the harness tells the Core about its account, beyond the transcript (KAN-436 S2): the
//! class a failed run ended in, and the plan-limit snapshot. Both are read from the harness's own
//! structured output, never from the text an agent wrote, and neither is a gateway report: the
//! gateway has its own channel (`gw.rs`) that only the gateway task writes.
//!
//! - A failed turn's `<harness>:<code>` fingerprint becomes its `classify` class (`quota`,
//!   `rate_limited`, `auth`, ...), so the Core sees why a session ended. Text only ever picks the
//!   class, and a limit word beats an auth word, so forged text cannot make a failure look more
//!   like an auth one than it is. A fingerprint that is a step of the runner's own (`sandbox`,
//!   `secrets`, ...) is left as it is.
//! - `plan_limit` takes a `rate_limit` entry, which the adapter makes from the harness's
//!   `rate_limit_event`. Any other entry, an assistant's text or a tool's output that merely looks
//!   like one included, is no snapshot.

use ainkrad_harness::classify;
use ainkrad_proto::runner::Outcome;
use ainkrad_proto::v2::{PlanLimit, PlanWindow};
use serde_json::Value;

/// A harness reports a handful of windows; more is not a plan.
const MAX_WINDOWS: usize = 8;
const MAX_WORD: usize = 64;

/// The snapshot in a transcript entry body, when it is the adapter's `rate_limit` event.
pub(super) fn plan_limit(body: &Value) -> Option<PlanLimit> {
    if body["type"] != "rate_limit" {
        return None;
    }
    let status: String = body["status"].as_str()?.chars().take(MAX_WORD).collect();
    let windows = body["windows"]
        .as_array()?
        .iter()
        .filter_map(|w| {
            Some(PlanWindow {
                name: w["name"].as_str()?.chars().take(MAX_WORD).collect(),
                utilization: w["utilization"].as_f64().filter(|u| u.is_finite())?,
                resets_at: w["resets_at"].as_i64(),
            })
        })
        .take(MAX_WINDOWS)
        .collect();
    Some(PlanLimit { status, windows })
}

/// A failed outcome of `harness` carries its class as the fingerprint.
pub(super) fn stamp(outcome: &mut Outcome, harness: &str) {
    let Outcome::Failed {
        reason,
        fingerprint: Some(f),
    } = outcome
    else {
        return;
    };
    let class = match f.split_once(':') {
        Some((h, code)) if h == harness => classify(code, reason),
        None if f == "harness_exit" => classify(f, reason),
        _ => return,
    };
    *f = class.as_str().to_owned();
}

#[cfg(test)]
mod tests;
