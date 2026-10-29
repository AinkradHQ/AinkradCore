//! The loop breaker's pure parts (E2.7, decision #15): the failure fingerprint and the
//! thresholds. Same failure N times in a row → stop retrying, escalate.

use super::RunState;

/// Runs in a row on one agent and issue ending with the same fingerprint before the breaker
/// stops retrying and escalates the issue: the default of `breaker.loop_threshold` (E15.17).
pub const LOOP_BREAKER_THRESHOLD: usize = 3;

/// Issue breakers one agent may trip within `AGENT_BREAKER_WINDOW_SECS` before it is paused:
/// the defaults of `breaker.agent_trips` and `breaker.agent_window_secs`.
pub const AGENT_BREAKER_TRIPS: i64 = 3;

pub const AGENT_BREAKER_WINDOW_SECS: i64 = 3600;

/// Longest fingerprint kept, in chars; a reason can be a whole log tail.
const MAX_FINGERPRINT_CHARS: usize = 200;

/// The stable identity of a failure: `<state>:<detail>`, where `detail` is the runner's own
/// fingerprint (error class + step) or else the terminal reason. Volatile parts are
/// replaced so the same failure matches across runs: a word holding a path becomes
/// `<path>`; numbers, `0x…` values and lowercase hex ids (UUIDs, SHAs) become `#`; digit
/// runs in a word that starts with a digit (`10ms`, timestamps) become `#`. Words that
/// start with a letter keep their digits, so error codes like `E0308` stay distinct.
pub fn failure_fingerprint(state: RunState, detail: &str) -> String {
    let words: Vec<String> = detail.split_whitespace().map(word).collect();
    format!("{}:{}", state.as_str(), words.join(" "))
        .chars()
        .take(MAX_FINGERPRINT_CHARS)
        .collect()
}

fn word(w: &str) -> String {
    if w.contains('/') || w.contains('\\') {
        return "<path>".to_owned();
    }
    let mut out = String::new();
    let mut rest = w;
    while let Some(c) = rest.chars().next() {
        let len = if c.is_ascii_alphanumeric() {
            rest.find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(rest.len())
        } else {
            c.len_utf8()
        };
        let (seg, tail) = rest.split_at(len);
        out.push_str(&segment(seg));
        rest = tail;
    }
    out
}

fn segment(s: &str) -> String {
    let b = s.as_bytes();
    if !b.iter().any(u8::is_ascii_digit) {
        return s.to_owned();
    }
    let hex = b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    if hex || s.starts_with("0x") || s.starts_with("0X") {
        return "#".to_owned();
    }
    if !b[0].is_ascii_digit() {
        return s.to_owned();
    }
    let mut out = String::new();
    for c in s.chars() {
        if !c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('#') {
            out.push('#');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(detail: &str) -> String {
        failure_fingerprint(RunState::Failed, detail)
    }

    #[test]
    fn volatile_parts_do_not_change_the_fingerprint() {
        let pairs = [
            (
                "error[E0308]: mismatched types at src/lib.rs:41:5",
                "error[E0308]: mismatched types at /tmp/wt-9/src/main.rs:7:12",
            ),
            (
                "worktree 550e8400-e29b-41d4-a716-446655440000 locked",
                "worktree 123e4567-e89b-12d3-a456-4266141740ab locked",
            ),
            (
                "timed out after 3000ms at 2026-10-21T10:00:00.000Z",
                "timed out after 120ms at 2026-10-22T23:59:59.999Z",
            ),
            (
                "commit 9fceb02 rejected (exit 1)",
                "commit 4b825dc rejected (exit 128)",
            ),
            ("segfault at 0x7ffd5c3e", "segfault at 0xDEADBEEF"),
        ];
        for (a, b) in pairs {
            assert_eq!(fp(a), fp(b), "{a} / {b}");
        }
        assert_eq!(
            fp("error[E0308]: mismatched types at src/lib.rs:41:5"),
            "failed:error[E0308]: mismatched types at <path>"
        );
        assert_eq!(fp("  tests   red "), "failed:tests red");
    }

    #[test]
    fn different_failures_stay_different() {
        assert_ne!(fp("error[E0308]: x"), fp("error[E0599]: x"));
        assert_ne!(fp("build failed"), fp("tests failed"));
        assert_ne!(
            failure_fingerprint(RunState::Failed, "timed_out"),
            failure_fingerprint(RunState::TimedOut, "timed_out")
        );
    }

    #[test]
    fn long_details_are_capped() {
        let long = "x".repeat(10_000);
        assert_eq!(fp(&long).chars().count(), MAX_FINGERPRINT_CHARS);
        // Never splits a multi-byte char.
        assert_eq!(fp(&"é".repeat(500)).chars().count(), MAX_FINGERPRINT_CHARS);
    }
}
