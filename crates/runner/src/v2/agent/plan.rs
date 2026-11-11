//! `plan.check` (N36): does a Claude subscription's token work? The Core leases the token; the
//! runner starts an ordinary session on it (claude, the prompt `ok`, the sandbox and egress
//! filter every subscription session needs, so [`sub::early`] judges it too), waits for its end,
//! forgets the session and answers one word. Nothing the CLI printed leaves the runner.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use ainkrad_proto::runner::{Isolation, Outcome, Policy};
use ainkrad_proto::v2::{
    AgentStart, AgentState, ErrorCode, PlanCheck, PlanChecked, SUBSCRIPTION_HARNESS,
    SUBSCRIPTION_VAR, SecretGrant, StreamError,
};

use super::{AgentDriver, refuse};

/// The check's whole life; the host kills the sandbox at the same deadline.
const WAIT: Duration = Duration::from_secs(90);
/// The cheapest model on a plan: the check spends a few tokens of its quota.
const MODEL: &str = "haiku";

impl AgentDriver {
    /// Runs the check for `req`'s lease.
    pub async fn plan_check(self: &Arc<Self>, req: PlanCheck) -> Result<PlanChecked, StreamError> {
        let at = Instant::now();
        let done = |result: &str| PlanChecked {
            result: result.to_owned(),
            latency_ms: u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        if !self.sandbox.tier().satisfies(Isolation::Process) {
            return Ok(done("sandbox_unavailable"));
        }
        if !self.sandbox.capabilities().contains(&"egress-filter") {
            return Ok(done("egress_not_proven"));
        }
        let session = {
            let mut n = self.next_run.lock().unwrap();
            *n += 1;
            format!("as_pc{}", *n)
        };
        let start = AgentStart {
            session: session.clone(),
            harness: SUBSCRIPTION_HARNESS.to_owned(),
            model: Some(MODEL.to_owned()),
            prompt: Some("ok".to_owned()),
            workspace: None,
            policy: Policy {
                min_isolation: Some(Isolation::Process),
                wall_secs: Some(u32::try_from(WAIT.as_secs()).unwrap_or(90)),
                ..Policy::default()
            },
            resume: None,
            secrets: vec![SecretGrant {
                lease: req.lease,
                var: SUBSCRIPTION_VAR.to_owned(),
            }],
            gateway: None,
            epoch: 0,
        };
        match self.start(start) {
            Ok(_) => {}
            Err(e) if e.code == ErrorCode::Busy => return Ok(done("runner_busy")),
            Err(e) => return Err(refuse(e.code, e.message)),
        }
        let end = Instant::now() + WAIT;
        let outcome = loop {
            let woken = self.changed.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            {
                let all = self.sessions.lock().unwrap();
                match all.get(&session) {
                    Some(l) if l.meta.state != AgentState::Running => break l.meta.outcome.clone(),
                    Some(_) => {}
                    None => break None,
                }
            }
            if tokio::time::timeout_at(end, woken).await.is_err() {
                let run = self.sessions.lock().unwrap().get(&session).map(|l| l.run);
                if let Some(run) = run {
                    self.kill(&session, run);
                }
                self.forget(&session);
                return Ok(done("timeout"));
            }
        };
        self.forget(&session);
        Ok(done(word(outcome)))
    }

    /// Drops the check's session and its transcript: it was never the Core's.
    fn forget(&self, session: &str) {
        self.sessions.lock().unwrap().remove(session);
        let _ = std::fs::remove_dir_all(self.config.dir.join(session));
    }
}

/// The one word for how the session ended: the class the runner stamped on a failure.
fn word(outcome: Option<Outcome>) -> &'static str {
    match outcome {
        Some(Outcome::Succeeded) => "ok",
        Some(Outcome::Failed { fingerprint, .. }) => match fingerprint.as_deref() {
            Some("auth") => "token_expired",
            Some("quota" | "rate_limited") => "limit_reached",
            Some("transient" | "provider_dropped") => "unreachable",
            _ => "failed",
        },
        _ => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_class_becomes_one_word() {
        let failed = |f: Option<&str>| Outcome::Failed {
            reason: "x".to_owned(),
            fingerprint: f.map(str::to_owned),
        };
        assert_eq!(word(Some(Outcome::Succeeded)), "ok");
        assert_eq!(word(Some(failed(Some("auth")))), "token_expired");
        assert_eq!(word(Some(failed(Some("quota")))), "limit_reached");
        assert_eq!(word(Some(failed(Some("rate_limited")))), "limit_reached");
        assert_eq!(word(Some(failed(Some("transient")))), "unreachable");
        assert_eq!(word(Some(failed(Some("harness_start")))), "failed");
        assert_eq!(word(Some(failed(None))), "failed");
        assert_eq!(word(None), "failed");
    }
}
