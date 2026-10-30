//! One harness turn worked to the run's outcome (`HarnessExecutor::work`), resumed when the
//! provider drops it (E15.4), and the helpers the executor shares.

use std::time::{Duration, Instant};

use ainkrad_harness::{
    DROPPED, Decision, ErrorClass, Harness, HarnessEvent, Meter, PROTOCOL, Spec, TurnOutcome,
    Usage, classify, tokens, weighted_tokens,
};
use ainkrad_proto::runner::{Outcome, RepoDiff, TokenCaps, Tokens};
use serde_json::json;
use tokio::sync::mpsc;

use super::HarnessExecutor;
use super::tools::Tools;
use super::watch::Watch;
use crate::{Job, Report};

impl HarnessExecutor {
    /// Works one turn of `prompt` through harness `H` to the run's outcome.
    ///
    /// Token cap (E3.8): the run's tokens are counted from its events (`Meter`) and
    /// reported every `usage_every`, and once more at the end. When a turn's tokens so far
    /// reach its caps (`reached`), the harness is interrupted and stopped and the run ends
    /// `TokenCap`. A turn's closing `Usage` is not checked: the turn is over, and its work stands.
    ///
    /// Provider drops (E15.4): a turn the provider dropped (a transient failure, `classify`,
    /// or a harness that stopped mid-turn after it had begun) is not the run's end: the same
    /// session is resumed after a backoff (`resume_backoff`, doubling up to `resume_backoff_max`;
    /// the server's settings when it sends them) and told to go on,
    /// inside this run. Each drop is reported (`Report::Dropped`) for the account's count. After
    /// `max_resumes` resumes the run gives up on the entry (`DROPPED`), and its fallback chain
    /// takes over (E15.3). A permanent failure ends the run at once.
    pub(super) async fn work<H: Harness>(
        &self,
        job: &Job,
        spec: Spec,
        reports: mpsc::Sender<Report>,
        meter: &mut Meter,
    ) -> Outcome {
        let name = &job.harness;
        let caps = job.caps(self.default_token_cap);
        let limits = self.limits(job);
        if caps.least() == 0 {
            return Outcome::TokenCap;
        }
        // A new session, unless the server named one to continue (E15.5); on a warm server
        // of this agent's when one is idle (E15.6).
        let isolated = spec.env.iter().any(|(n, _)| n == "AINKRAD_SANDBOX");
        let warm =
            !isolated && H::LONG_LIVED && limits.warm_max > 0 && job.resume_session.is_none();
        // A server kept warm outlives this run's worktree: it works from the work root (E15.9).
        let spec = Spec {
            process_dir: warm.then(|| self.work_root.clone()),
            ..spec
        };
        let key = warm.then(|| super::warm::key(job, &spec));
        let started = match (&job.resume_session, &key) {
            (Some(id), _) => H::resume(&spec, id).await,
            (None, Some(key)) => self.warm_start::<H>(job, key, &spec, &reports).await,
            (None, None) => H::start(&spec).await,
        };
        let mut harness = match started {
            Ok(harness) => Some(harness),
            Err(e) => return failed(format!("starting {name}: {e}"), "harness_start"),
        };
        let mut prompting = match &job.resume_session {
            Some(_) => CONTINUE.to_owned(),
            None => prompt(job),
        };
        let session = job.resume_session.clone().or(spec.session_id.clone());
        let (mut session, mut drops, mut reported) = (session, 0, Instant::now());
        let mut watch = Watch::new(limits.stall_after, spec.cwd.clone());
        let outcome = loop {
            let Some(h) = harness.as_mut() else {
                unreachable!("a harness runs until the loop ends");
            };
            // A broken pipe means the child already exited: the turn's events say how, with
            // its stderr tail (`with_stderr`), so the result does not depend on timing.
            match h.send(&prompting).await {
                Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
                    break failed(format!("prompting {name}: {e}"), "harness_io");
                }
                _ => {}
            }
            let turn = Turn {
                job,
                spec: &spec,
                reports: &reports,
                caps,
                approval_timeout: limits.approval_timeout,
                tool_output: limits.tool_output,
            };
            let why = match self
                .attempt(&turn, h, meter, &mut watch, &mut reported, &mut session)
                .await
            {
                Attempt::Done(Outcome::Succeeded) => match self.inbox(job.run).take_message() {
                    // The admin's message is the next turn (1.19); the run goes on.
                    Some((id, text)) => {
                        let event = json!({"type": "user_message", "id": id, "text": text});
                        let _ = reports.send(Report::Event(event)).await;
                        prompting = text;
                        continue;
                    }
                    None => break Outcome::Succeeded,
                },
                Attempt::Done(outcome) => break outcome,
                Attempt::Dropped(why) => why,
            };
            if let Some(h) = harness.take() {
                h.stop().await;
            }
            meter.close_turn();
            drops += 1;
            tracing::warn!(run = job.run, drops, %why, "the provider dropped the turn");
            let event = json!({"type": "provider_dropped", "drop": drops, "reason": why});
            let _ = reports.send(Report::Event(event)).await;
            let _ = reports
                .send(Report::Dropped {
                    reason: why.clone(),
                })
                .await;
            if drops > limits.max_resumes {
                let why = format!("the provider dropped the turn {drops} times; last: {why}");
                break failed(why, &format!("{name}:{DROPPED}"));
            }
            let doublings = (drops - 1).min(5);
            let wait = limits.resume_backoff * (1 << doublings);
            tokio::time::sleep(wait.min(limits.resume_backoff_max)).await;
            let resumed = match &session {
                Some(id) => H::resume(&spec, id).await,
                None => H::start(&spec).await,
            };
            match resumed {
                Ok(h) => harness = Some(h),
                Err(e) => break failed(format!("resuming {name}: {e}"), "harness_start"),
            }
            if session.is_some() {
                prompting = RESUME.to_owned();
            }
        };
        match (harness, key) {
            // A server whose run went well serves the next one (E15.6).
            (Some(h), Some(key)) if outcome == Outcome::Succeeded => {
                self.warm.keep(key, h, limits.warm_max as usize).await;
            }
            (Some(h), _) => drop(h.stop().await),
            (None, _) => {}
        }
        // The run's last diff, for its issue's `done` checks (E15.7) and its repos' sizes (1.18).
        if let Some(repos) = self.diff_stats(job).await {
            let diff_files = Some(repos.iter().map(|d| d.files).sum());
            let _ = reports.send(Report::Progress { diff_files, repos }).await;
        }
        // A turn that never closed (a dropped connection) still counts what was seen of it.
        meter.close_turn();
        let _ = reports.send(Report::Usage(wire(meter))).await;
        outcome
    }

    /// A new session on this agent's idle server under `key`, else a new process.
    async fn warm_start<H: Harness>(
        &self,
        job: &Job,
        key: &str,
        spec: &Spec,
        reports: &mpsc::Sender<Report>,
    ) -> std::io::Result<H> {
        let Some(mut h) = self.warm.take::<H>(key) else {
            return H::start(spec).await;
        };
        match h.renew(spec).await {
            Ok(()) => {
                tracing::info!(run = job.run, harness = %job.harness, "reusing a warm harness");
                let event = json!({"type": "harness_reused"});
                let _ = reports.send(Report::Event(event)).await;
                Ok(h)
            }
            Err(e) => {
                tracing::warn!(run = job.run, error = %e, "a warm harness failed; starting anew");
                h.stop().await;
                H::start(spec).await
            }
        }
    }

    /// One harness process's events, to the turn's end, the provider dropping it, or a stall
    /// (`watch`, E15.7): no progress for the stall limit interrupts it and ends the run
    /// `Stalled`.
    async fn attempt<H: Harness>(
        &self,
        turn: &Turn<'_>,
        harness: &mut H,
        meter: &mut Meter,
        watch: &mut Watch,
        reported: &mut Instant,
        session: &mut Option<String>,
    ) -> Attempt {
        let Turn {
            job,
            spec,
            reports,
            caps,
            approval_timeout,
            ..
        } = *turn;
        let name = &job.harness;
        let emit = |report: Report| {
            let reports = reports.clone();
            async move {
                let _ = reports.send(report).await;
            }
        };
        // Whether this process got going: one that dies before saying anything did not start,
        // which no resume fixes.
        let mut began = false;
        let mut tools = Tools::default();
        let inbox = self.inbox(job.run);
        loop {
            // A pause waits for the tool call in flight to end (1.19, decision #34).
            if inbox.paused() && tools.0.is_empty() {
                return self.pause(job, harness).await;
            }
            // The pending `next` lives across looks at the working dir, so none of its
            // output is lost; it is dropped only on a stall or a pause, and the harness with it.
            let next = {
                let next = harness.next();
                tokio::pin!(next);
                loop {
                    tokio::select! {
                        event = &mut next => break Next::Event(event),
                        () = tokio::time::sleep_until(watch.next_check()) => {
                            if self.look(watch, job, reports).await {
                                break Next::Stalled;
                            }
                        }
                        () = inbox.arrived.notified() => {
                            if inbox.paused() && tools.0.is_empty() {
                                break Next::Paused;
                            }
                        }
                    }
                }
            };
            let next = match next {
                Next::Event(next) => next,
                Next::Stalled => return self.stall(job, harness).await,
                Next::Paused => return self.pause(job, harness).await,
            };
            let Some(event) = next else {
                let why = with_stderr(format!("{name} ended without a result"), &*harness);
                return dropped_or(began, why);
            };
            // The Citadel MCP tools and CLI are scoped by the run token: a harness asking for
            // one is answered at once, with no approval in the transcript.
            if let HarnessEvent::ApprovalRequested { id, tool, input } = &event
                && super::policy::citadel_call(tool, input)
            {
                began = true;
                if let Err(e) = harness.approve(id, Decision::Allow).await {
                    tracing::warn!(run = job.run, error = %e, "answering an approval failed");
                }
                continue;
            }
            emit(Report::Event(match &event {
                HarnessEvent::ToolResult { .. } => tools.result(&event, turn.tool_output),
                _ => {
                    tools.started(&event);
                    serde_json::to_value(&event).expect("events serialise")
                }
            }))
            .await;
            began |= !matches!(event, HarnessEvent::Exited { .. });
            let counted = meter.see(&event);
            if watch.see(&event, tokens(&meter.total())) {
                let tool = matches!(event, HarnessEvent::ToolUse { .. });
                self.progressed(watch, job, reports, tool).await;
            }
            // A harness that never goes quiet is looked at too: chatter is no progress.
            if tokio::time::Instant::now() >= watch.next_check()
                && self.look(watch, job, reports).await
            {
                return self.stall(job, harness).await;
            }
            if counted {
                let total = meter.total();
                if matches!(event, HarnessEvent::UsageSoFar(_)) && reached(&caps, &total) {
                    tracing::warn!(
                        run = job.run,
                        spent = tokens(&total),
                        ?caps,
                        "token cap reached; stopping"
                    );
                    let _ = harness.interrupt().await;
                    return Attempt::Done(Outcome::TokenCap);
                }
                if reported.elapsed() >= self.usage_every {
                    emit(Report::Usage(wire(meter))).await;
                    *reported = Instant::now();
                }
            }
            match event {
                HarnessEvent::SessionStarted { id } => *session = Some(id),
                HarnessEvent::ApprovalRequested { id, tool, input } => {
                    let decision =
                        match self.decide(&inbox.policy(&job.policy), &tool, &input, &spec.cwd) {
                            Ok(()) => Decision::Allow,
                            Err(why) => {
                                emit(Report::Event(
                                    json!({"type": "approval_escalated", "id": id,
                                        "tool": tool, "reason": why}),
                                ))
                                .await;
                                self.escalate(&id, &tool, &input, reports, approval_timeout)
                                    .await
                            }
                        };
                    let (approved, reason) = match &decision {
                        Decision::Allow => (true, None),
                        Decision::Deny { reason } => (false, Some(reason)),
                    };
                    emit(Report::Event(json!({"type": "approval_decided", "id": id,
                                "tool": tool, "approved": approved, "reason": reason})))
                    .await;
                    if let Err(e) = harness.approve(&id, decision).await {
                        tracing::warn!(run = job.run, error = %e, "answering an approval failed");
                    }
                    // Waiting on a reviewer is not the agent stalling.
                    watch.progress();
                }
                HarnessEvent::TurnEnded { outcome } => {
                    return Attempt::Done(match outcome {
                        TurnOutcome::Success => Outcome::Succeeded,
                        TurnOutcome::Interrupted => Outcome::Cancelled {
                            reason: "interrupted".to_owned(),
                        },
                        TurnOutcome::Failed { reason, code } => {
                            if classify(&code, &reason) == ErrorClass::Transient {
                                return Attempt::Dropped(reason);
                            }
                            // A newer CLI the adapter does not understand: say which.
                            let reason = if code == PROTOCOL {
                                let versions = self.versions.lock().expect("versions");
                                let version = versions.get(name.as_str());
                                let version = version.map_or("(version unknown)", String::as_str);
                                format!("{name} {version}: {reason}")
                            } else {
                                reason
                            };
                            failed(reason, &format!("{name}:{code}"))
                        }
                    });
                }
                HarnessEvent::Exited { code } => {
                    let why = with_stderr(format!("{name} exited with {code:?}"), &*harness);
                    return dropped_or(began, why);
                }
                _ => {}
            }
        }
    }
}

impl HarnessExecutor {
    /// Looks at the run's working dir (a change is progress): `true` when the run is stalled.
    async fn look(&self, watch: &mut Watch, job: &Job, reports: &mpsc::Sender<Report>) -> bool {
        if watch.files_changed().await {
            self.progressed(watch, job, reports, true).await;
        }
        watch.stalled()
    }

    /// Reports progress when due; `measure` re-reads the worktree's diff first.
    async fn progressed(
        &self,
        watch: &mut Watch,
        job: &Job,
        reports: &mpsc::Sender<Report>,
        measure: bool,
    ) {
        let (diff, repos) = match measure {
            true => {
                let repos = self.diff_stats(job).await;
                let files = repos.as_ref().map(|r| r.iter().map(|d| d.files).sum());
                (files, repos.unwrap_or_default())
            }
            false => (watch.diff(), vec![]),
        };
        if watch.report(diff) {
            let diff_files = diff;
            let _ = reports.send(Report::Progress { diff_files, repos }).await;
        }
    }

    /// Stops a paused run's turn (1.19): interrupted, then stopped by the caller; the run ends
    /// `Cancelled`.
    async fn pause<H: Harness>(&self, job: &Job, harness: &mut H) -> Attempt {
        tracing::info!(run = job.run, "paused by the admin; stopping the turn");
        let _ = harness.interrupt().await;
        Attempt::Done(Outcome::Cancelled {
            reason: PAUSED.to_owned(),
        })
    }

    /// Stops a stalled run's turn: the harness is interrupted, then stopped by the caller.
    async fn stall<H: Harness>(&self, job: &Job, harness: &mut H) -> Attempt {
        tracing::warn!(run = job.run, "no progress for the stall limit; stopping");
        let _ = harness.interrupt().await;
        Attempt::Done(Outcome::Stalled)
    }

    /// Each of the job's worktrees against its base; `None` without a worktree.
    pub(super) async fn diff_stats(&self, job: &Job) -> Option<Vec<RepoDiff>> {
        let (Some(_), Some(issue)) = (&job.workspace, job.issue) else {
            return None;
        };
        self.workspaces.diff_stats(issue, &job.trees()).await.ok()
    }
}

/// What one turn works with.
#[derive(Clone, Copy)]
struct Turn<'a> {
    job: &'a Job,
    spec: &'a Spec,
    reports: &'a mpsc::Sender<Report>,
    caps: TokenCaps,
    approval_timeout: Duration,
    /// The most of a tool's output its `tool_result` event carries.
    tool_output: usize,
}

/// What woke a turn's wait for the harness.
enum Next {
    Event(Option<HarnessEvent>),
    Stalled,
    Paused,
}

/// How one harness process's turn ended.
enum Attempt {
    Done(Outcome),
    /// The provider dropped it, for this reason.
    Dropped(String),
}

/// A process gone mid-turn: a reset stream once it had begun, else a failed start.
fn dropped_or(began: bool, why: String) -> Attempt {
    match began {
        true => Attempt::Dropped(why),
        false => Attempt::Done(failed(why, "harness_exit")),
    }
}

/// Why a paused run ended (1.19).
pub(crate) const PAUSED: &str = "paused by admin";

/// What a session continued from an unfinished run is told (E15.5).
const CONTINUE: &str = "Your previous run on this task ended before it finished. Continue the \
                        task from where you left off; do not redo work already done.";

/// What a resumed session is told.
const RESUME: &str = "The connection to the model provider dropped in the middle of your turn. \
                      Continue the task from where you left off; do not redo work already done.";

/// Whether `total` reaches one of `caps`: the budgets' cap in full, or `run.token_cap` with cache
/// reads and writes weighted (1.27).
pub(super) fn reached(caps: &TokenCaps, total: &Usage) -> bool {
    caps.exact.is_some_and(|exact| tokens(total) >= exact)
        || weighted_tokens(total, caps.cache_weight_divisor) >= caps.run
}

fn wire(meter: &Meter) -> Tokens {
    let u = meter.total();
    Tokens {
        input: u.input,
        output: u.output,
        cache_read: u.cache_read,
        cache_write: u.cache_write,
        cost_usd_micros: meter
            .cost_usd()
            .filter(|c| c.is_finite() && *c >= 0.0)
            .map(|c| (c * 1e6).round() as u64),
    }
}

/// The turn's prompt: the server's (1.22), else only which issue; the rest comes through the
/// Citadel MCP tools.
fn prompt(job: &Job) -> String {
    if let Some(prompt) = &job.prompt {
        return prompt.clone();
    }
    match &job.issue_key {
        Some(key) => {
            format!("You are working on {key}. Use the citadel MCP tools to read it and report.")
        }
        None => format!(
            "You are working Citadel run {}. Use the citadel MCP tools to read your context \
             and report.",
            job.run
        ),
    }
}

/// `why`, with the harness's stderr tail when it has one. The run's task redacts it.
fn with_stderr(why: String, harness: &impl Harness) -> String {
    match harness.stderr_tail() {
        tail if tail.is_empty() => why,
        tail => format!("{why}; stderr: {tail}"),
    }
}

pub(super) fn failed(reason: String, fingerprint: &str) -> Outcome {
    Outcome::Failed {
        reason,
        fingerprint: Some(fingerprint.to_owned()),
    }
}
