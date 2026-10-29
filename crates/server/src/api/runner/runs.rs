//! A connection's run messages: transcript chunks, usage, heartbeats, worktree pruning, and a
//! run's start and end.

use ainkrad_core::gov::AccountId;
use ainkrad_core::org::ModelRoute;
use ainkrad_proto::runner::RepoDiff;

use super::*;
use crate::store::exec::{Fallback, record_disk, record_progress, switch_route};
use crate::store::forge::push_reported;
use crate::store::gov::{apply_signal, record_drop};

impl Session {
    /// Stores a transcript chunk; a `Cancel` when this runner does not hold the run.
    pub(super) async fn chunk(
        &self,
        run: i64,
        seq: u64,
        payload: &serde_json::Value,
    ) -> Option<ServerMessage> {
        let size = payload.to_string().len();
        if size > MAX_CHUNK {
            return Some(error(format!(
                "chunk {seq} of run {run} is {size} bytes; the most is {MAX_CHUNK}"
            )));
        }
        let (pool, now, by) = (&self.app.pool, self.now(), self.runner.id);
        match append_run_event(pool, RunId(run), by, seq, payload, &now).await {
            Ok(stored) => {
                // The harness's plan limits (E15.2) reach its account's status.
                if let Err(e) = apply_signal(pool, RunId(run), payload, &now).await {
                    tracing::error!(run, error = %e, "applying a rate-limit report failed");
                }
                // A branch push's outcome reaches its issue and PR request (#103), once.
                if stored && let Err(e) = push_reported(pool, RunId(run), payload, &now).await {
                    tracing::error!(run, error = %e, "recording a push outcome failed");
                }
                None
            }
            Err(ChunkError::NotHolder) => Some(cancel(run, "not this runner's run")),
            Err(e) => Some(error(e.to_string())),
        }
    }

    /// Records the run's token totals in the cost ledger.
    pub(super) async fn usage(&self, run: i64, seq: u64, t: Tokens) -> Option<ServerMessage> {
        let current = match self.own(run).await {
            Ok(r) => r,
            Err(reply) => return Some(*reply),
        };
        let int = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        let totals = Usage {
            input_tokens: int(t.input),
            output_tokens: int(t.output),
            cache_tokens: int(t.cache_read + t.cache_write),
            cost_usd_micros: t.cost_usd_micros.map(int),
        };
        match record_run_usage(&self.app.pool, &current, seq, &totals, &self.now()).await {
            Ok(_) => None,
            Err(e) => Some(error(e.to_string())),
        }
    }

    /// Moves the run to the next entry of its chain (E15.3); an `Error` when refused.
    pub(super) async fn fallback(
        &self,
        run: i64,
        harness: &str,
        model: String,
        account: Option<i64>,
        class: &str,
        reason: &str,
    ) -> Option<ServerMessage> {
        if let Err(reply) = self.own(run).await {
            return Some(*reply);
        }
        let Ok(harness) = harness.parse::<Harness>() else {
            return Some(error(format!("unknown harness {harness:?}")));
        };
        if !self.harnesses.contains(&harness) {
            return Some(error(format!("{} is not offered here", harness.as_str())));
        }
        let to = ModelRoute { harness, model };
        let fallback = Fallback {
            to: &to,
            account: account.map(AccountId),
            class,
            reason,
        };
        let (pool, now) = (&self.app.pool, self.now());
        match switch_route(pool, RunId(run), &fallback, self.actor(), &now).await {
            Ok(moved) => {
                tracing::info!(
                    run,
                    harness = moved.harness.as_str(),
                    class,
                    "run fell back"
                );
                None
            }
            Err(e) => Some(error(format!("fallback of run {run} refused: {e}"))),
        }
    }

    /// Counts a provider drop of the run's turn against its account (E15.4).
    pub(super) async fn dropped(&self, run: i64, reason: &str) -> Option<ServerMessage> {
        if let Err(reply) = self.own(run).await {
            return Some(*reply);
        }
        let (pool, now) = (&self.app.pool, self.now());
        match record_drop(pool, RunId(run), reason, self.actor(), &now).await {
            Ok(()) => None,
            Err(e) => Some(error(e.to_string())),
        }
    }

    /// The worktrees among `held` whose issues are closed or gone, for the runner to remove.
    pub(super) async fn prune(&self, held: &[i64]) -> Option<ServerMessage> {
        if held.is_empty() {
            return None;
        }
        match closed_issues(&self.app.pool, held).await {
            Ok(issues) if issues.is_empty() => None,
            Ok(issues) => Some(ServerMessage::Prune { issues }),
            Err(e) => {
                tracing::error!(error = %e, "reading closed issues failed");
                None
            }
        }
    }

    /// Renews the lease on `run`, stretched for the host's `load` (AIN-55); a `Cancel` when
    /// this runner no longer holds it.
    pub(super) async fn heartbeat(
        &self,
        run: i64,
        load: Option<HostLoad>,
    ) -> Option<ServerMessage> {
        let now = self.now();
        match renew_lease_loaded(&self.app.pool, RunId(run), self.runner.id, &now, load).await {
            Ok(_) => None,
            Err(LeaseError::Db(e)) => Some(error(e.to_string())),
            Err(e) => Some(cancel(run, e)),
        }
    }

    /// Records the run's progress (E15.7). One for a run that has ended or is not this
    /// runner's is ignored: the heartbeat, not progress, decides who holds a run.
    pub(super) async fn progress(
        &self,
        run: i64,
        diff: Option<u32>,
        repos: &[RepoDiff],
    ) -> Option<ServerMessage> {
        let (pool, now, by) = (&self.app.pool, self.now(), self.runner.id);
        match record_progress(pool, RunId(run), by, diff, repos, &now).await {
            Ok(_) => None,
            Err(e) => Some(error(e.to_string())),
        }
    }

    /// Stores the runner's disk report (E15.9).
    pub(super) async fn disk(&self, report: &DiskReport) -> Option<ServerMessage> {
        let (pool, now) = (&self.app.pool, self.now());
        match record_disk(pool, self.runner.id, report, &now).await {
            Ok(true) => {
                tracing::warn!(
                    runner = self.runner.id.0,
                    used = report.used_bytes,
                    cap = report.cap_bytes,
                    "runner disk full: nothing left to evict"
                );
                None
            }
            Ok(false) => None,
            Err(e) => Some(error(e.to_string())),
        }
    }

    /// The run, if this runner claimed it.
    pub(super) async fn own(&self, run: i64) -> Result<Run, Box<ServerMessage>> {
        match get_run(&self.app.pool, RunId(run)).await {
            Ok(Some(r)) if r.runner_id == Some(self.runner.id) => Ok(r),
            Ok(_) => Err(Box::new(cancel(run, "not this runner's run"))),
            Err(e) => Err(Box::new(error(e.to_string()))),
        }
    }

    /// Starts a claimed run and sends its token. A run already running (the runner lost the
    /// first `Token` to a dropped connection) gets a fresh token instead.
    pub(super) async fn started(&mut self, run: i64, session: Option<String>) -> ServerMessage {
        let current = match self.own(run).await {
            Ok(r) => r,
            Err(reply) => return *reply,
        };
        let (pool, now) = (&self.app.pool, self.now());
        let token = match current.state {
            RunState::Claimed => start_run(pool, current.id, self.actor(), session, &now)
                .await
                .map(|(_, token)| token)
                .map_err(|e| e.to_string()),
            RunState::Running => rotate_run_token(pool, current.id, self.actor(), &now)
                .await
                .map_err(|e| e.to_string()),
            state => return cancel(run, format!("run is {}", state.as_str())),
        };
        match token {
            Ok(token) => {
                self.redactor.known("run_token", token.expose());
                ServerMessage::Token {
                    run,
                    token: RunToken::new(token.expose().to_owned()),
                }
            }
            Err(why) => cancel(run, why),
        }
    }

    /// Ends the run with the runner's outcome; a failed run is retried per policy.
    pub(super) async fn ended(&self, run: i64, outcome: Outcome) -> ServerMessage {
        if let Err(reply) = self.own(run).await {
            return *reply;
        }
        let event = match outcome {
            Outcome::Succeeded => RunEvent::Succeed,
            Outcome::Failed {
                reason,
                fingerprint,
            } => RunEvent::Fail {
                reason,
                fingerprint,
            },
            Outcome::Cancelled { reason } => RunEvent::Cancel { reason },
            Outcome::TokenCap => RunEvent::TokenCap,
            Outcome::Stalled => RunEvent::Stall,
        };
        let (pool, now) = (&self.app.pool, self.now());
        match transition_run(pool, RunId(run), self.actor(), &event, &now).await {
            Ok(ended) => {
                tracing::info!(run, state = ended.state.as_str(), "run ended");
                if ended.state == RunState::Failed
                    && let Err(e) = schedule_retry(pool, ended.id, &now).await
                {
                    tracing::error!(run, error = %e, "scheduling the retry failed");
                }
                ServerMessage::Ack { run }
            }
            Err(TransitionError::Db(e)) => error(e.to_string()),
            Err(e) => cancel(run, e),
        }
    }
}
