//! One runner connection (E3.1): the protocol in `ainkrad_proto::runner` driven against the
//! engine. Runs are claimed by `dispatch_next`, started by `start_run` (which mints the run
//! token) when the runner reports its harness up, kept alive by `renew_lease`, and ended by
//! `transition_run`. A dropped connection only marks the runner offline: its leases run on,
//! so a runner that reconnects within the lease grace (`lease.grace_secs`) re-claims its runs
//! with its `Hello`, and one that does not loses them to the reaper (`runner_lost`, then a
//! retry).
//!
//! Harness versions (E3.6): `Hello` lists the runner's installed harnesses and versions,
//! judged by `ainkrad_harness::compat` under the runner's settings (`harness_policy`). A
//! supported version, or an untested newer one, is offered work; the latter is logged, and
//! noted in the Runners API (`Runner.harness_status`). A refused one (too old, known bad,
//! unreadable, above its cap, or untested while `harness.allow_untested_newer` is 0) makes the
//! runner `unhealthy`, with every refusal in `health_reason`, and is not offered. The runner
//! still gets work for its other harnesses: one stale harness does not idle the others. A
//! harness missing from `Hello` is simply not offered and is no health problem.
//!
//! Workspaces (E3.7): an `Assign` for an issue whose project has a repo carries the issue's
//! worktree (`citadel/<KEY>-<n>` off the default branch). Each `Ready` lists the issues the
//! runner holds worktrees for; those closed or gone come back in a `Prune`. Cleanup is the
//! runner's GC on that list, so a runner offline when an issue closes still cleans up later.
//!
//! Dispatch (E15.6): a `Ready` is answered at once when a run is due; otherwise the connection
//! waits for the store's wake signal (a new wake, an ended run) and dispatches the moment it
//! fires, with a slow fallback poll (`dispatch.fallback_poll_ms`) for wakes that came due or
//! were written by another process.
//!
//! Token caps (E3.8): `Assign` carries the run's cap, `run_token_cap` of the budgets that
//! apply, at most the `run.token_cap` setting of its project (E15.17), and its `limits` from
//! the other settings (`approval.deadline.permission_escalation`, `runner.*`). `RunUsage` totals go into the cost ledger as they
//! arrive (`record_run_usage`), so spend shows mid-run.
//!
//! Fallbacks (E15.3): `Assign` carries the rest of the agent's (harness, model) chain this
//! runner offers, each with its account; `RunFallback` moves the run along it
//! (`switch_route`), refused for anything outside the chain or an account the run's company
//! may not use.
//!
//! Provider drops (E15.4): `ProviderDrop` counts a drop against the run's account
//! (`record_drop`), which turns unhealthy after too many.
//!
//! Permissions (E3.10): `Assign` carries the issue's project policy (the default asks).
//! `ApprovalRequest` opens a `permission_escalation` approval (`escalate`, once per run and
//! request) that this connection then polls; once decided, `Approval` carries the answer and
//! the reviewer's reply back. A runner that reconnects resends its open requests, so a
//! decision made while it was away still reaches it.
//!
//! Progress (E15.7): `Progress` stamps the run's `last_progress_at` and its worktree's diff
//! (`record_progress`); `Assign.limits` carries `run.stall_after_secs`, past which the runner
//! stops a run that made none and ends it `Stalled`, which escalates its issue.
//!
//! Disk (E15.9): `Welcome` carries the runner's disk and warm-process settings (`runner.*`,
//! `workspace.idle_secs`, read for the runner, decision #57); its reports (`Hello`, `Disk`)
//! are stored by `record_disk`, which audits `runner.disk_full` when one turns full.
//!
//! Transcripts (E3.9): `RunEvent` chunks are stored by `append_run_event`, only from the
//! runner holding the run's lease, once per `seq`. The runner redacts them before sending;
//! the server redacts them again before anything is logged or written (defence in depth),
//! with the runner's key, every run token it sent on this connection, and the key shapes of
//! `ainkrad_proto::redact`. Failure and cancel reasons go through the same redaction.
//!
//! Artifacts (E15.12): a file an agent publishes by path is read by the runner holding its run's
//! lease; the connection hands it the pending reads each poll (`ReadFile`, protocol 1.17) and
//! leaves each answer (`FileRead`) for the waiting MCP call (`files`).
//!
//! Controls (1.19, decision #34): each poll, the admin's controls of this runner's runs go out:
//! `Pause`, `Message`, and a stop as `Cancel` (`controls`). An older runner gets only the stop;
//! its runs finish, and their messages become comments.
//!
//! Runner state (1.20): `Hello` and `Status` carry its `RunnerInfo` (slots, uptime, logins,
//! last sleep), stored with its harness versions; the admin's log requests go out as `ReadLog`
//! and its Power Nap preference in `Welcome` and `Prefs` (`state`). A drained runner is
//! dispatched nothing.
//!
//! Every message is logged at debug level through `Debug`, where a run token is redacted,
//! and only after that redaction.

use std::collections::{BTreeMap, HashMap};

use citadel_core::audit::AuditActor;
use citadel_core::exec::{Run, RunEvent, RunId, RunState, Runner, RunnerId, RunnerStatus, Usage};
use citadel_core::org::Harness;
use citadel_core::settings::{Key, Scope};
use ainkrad_harness::compat;
use ainkrad_proto::redact::Redactor;
use ainkrad_proto::runner::{
    DiskReport, HostLoad, Outcome, PROTOCOL_VERSION, RunToken, RunnerLimits, RunnerMessage,
    ServerMessage, Tokens, protocol_major,
};
use axum::extract::ws::{Message, WebSocket};

use super::App;
use crate::store::exec::{
    ChunkError, LeaseError, TransitionError, append_run_event, get_run, get_runner,
    record_platform, record_run_usage, renew_lease_loaded, rotate_run_token, schedule_retry,
    start_run, transition_run, update_runner,
};
use crate::store::work::closed_issues;

mod approvals;
mod controls;
mod dispatch;
mod files;
mod runs;
mod state;
use approvals::Waiting;
pub use state::{LogTails, ProbeFail, Probes};

struct Session {
    app: App,
    runner: Runner,
    /// Set by an accepted `Hello`; nothing else is served before it.
    hello: bool,
    /// The harnesses `Hello` reported at a supported version: the only ones dispatched.
    harnesses: Vec<Harness>,
    /// `Ready`s not yet answered with an `Assign`.
    wanted: u32,
    /// Close after sending the replies.
    closing: bool,
    /// The runner's key and the run tokens sent on this connection, plus key shapes.
    redactor: Redactor,
    /// Escalations opened on this connection, polled until decided.
    waiting: Vec<Waiting>,
    /// The runner answers `ReadFile` (protocol 1.17, E15.12).
    reads_files: bool,
    /// The runner takes `Pause` and `Message` (protocol 1.19).
    takes_controls: bool,
    /// The runner takes `ReadLog` and `Prefs` (protocol 1.20).
    speaks_1_20: bool,
    /// The Power Nap preference last sent to it.
    power_nap_sent: Option<bool>,
    /// The runner takes `PolicyUpdate` (protocol 1.24).
    speaks_1_24: bool,
    /// The runner takes `Probe` (protocol 1.25).
    speaks_1_25: bool,
    /// The policy last sent for each of its live runs.
    policies_sent: HashMap<i64, ainkrad_proto::runner::Policy>,
}

/// The largest transcript chunk stored, as JSON text.
const MAX_CHUNK: usize = 256 * 1024;

pub(super) async fn session(app: App, runner: Runner, key: String, mut socket: WebSocket) {
    let id = runner.id;
    let n = app.connected(id);
    tracing::info!(runner = id.0, "runner connected");
    let mut poll = tokio::time::interval(app.poll);
    let mut fallback = tokio::time::interval(app.dispatch_poll);
    fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut wakes = crate::store::exec::wake_signal();
    let mut s = Session {
        app,
        runner,
        hello: false,
        harnesses: vec![],
        wanted: 0,
        closing: false,
        redactor: Redactor::new(),
        waiting: vec![],
        reads_files: false,
        takes_controls: false,
        speaks_1_20: false,
        power_nap_sent: None,
        speaks_1_24: false,
        speaks_1_25: false,
        policies_sent: HashMap::new(),
    };
    let mut reads = tokio::time::interval(s.app.poll);
    s.redactor.known("runner_key", &key);
    let mut closing = s.app.closing.subscribe();
    loop {
        let replies = tokio::select! {
            // The server is stopping: a clean close, so the runner reconnects to the next one
            // and keeps its lease.
            () = crate::api::stopping(&mut closing) => {
                let bye = axum::extract::ws::CloseFrame { code: 1012, reason: "server restarting".into() };
                let _ = socket.send(Message::Close(Some(bye))).await;
                break;
            }
            frame = socket.recv() => match frame {
                Some(Ok(Message::Text(text))) => match serde_json::from_str(&text) {
                    Ok(msg) => s.handle(msg).await,
                    Err(e) => vec![error(format!("bad message: {e}"))],
                },
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => continue,
            },
            _ = poll.tick(), if !s.waiting.is_empty() => s.decided().await,
            // Files agents published by path, for this runner to read (E15.12), and the admin's
            // controls of its runs (1.19).
            _ = reads.tick(), if s.hello => {
                let mut out = s.reads().await;
                out.extend(s.controls().await);
                out.extend(s.asks().await);
                out.extend(s.policy_updates().await);
                out
            }
            // A new wake or an ended run (E15.6), else the slow fallback poll.
            Ok(()) = wakes.changed(), if s.wanted > 0 => s.dispatch().await.into_iter().collect(),
            _ = fallback.tick(), if s.wanted > 0 => s.dispatch().await.into_iter().collect(),
        };
        let mut sent = true;
        for reply in replies {
            tracing::debug!(runner = id.0, msg = ?reply, "to runner");
            let text = serde_json::to_string(&reply).expect("messages serialise");
            sent = sent && socket.send(Message::Text(text.into())).await.is_ok();
        }
        if !sent || s.closing {
            break;
        }
    }
    tracing::info!(runner = id.0, "runner disconnected");
    if s.app.disconnected(id, n) {
        s.set_status(RunnerStatus::Offline, None, None).await;
    }
}

/// The harness version policy of `runner` (E3.6): `harness.allow_untested_newer` and each
/// `harness.<name>.max_version`, the defaults when a setting cannot be read.
pub(crate) async fn harness_policy(pool: &sqlx::SqlitePool, runner: RunnerId) -> compat::Policy {
    let at = Scope::Runner(runner);
    let read = async |key: Key| {
        crate::store::settings::value(pool, key, at)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(key = key.name(), error = %e, "reading a setting failed");
                key.default()
            })
    };
    let mut policy = compat::Policy {
        refuse_untested_newer: read(Key::AllowUntestedNewer).await == 0,
        ..Default::default()
    };
    for c in compat::COMPAT {
        let Some(key) = Key::max_version(c.harness) else {
            continue;
        };
        if let Some(cap) = compat::Version::from_setting(read(key).await) {
            policy.max_version.insert(c.harness.to_owned(), cap);
        }
    }
    policy
}

/// The harnesses a runner may be given work for, why each other one it reported is refused,
/// and the notes on untested versions it may run.
fn judge(
    reported: &BTreeMap<String, String>,
    policy: &compat::Policy,
) -> (Vec<Harness>, Vec<String>, Vec<String>) {
    let (mut offered, mut refused, mut notes) = (vec![], vec![], vec![]);
    for (name, version) in reported {
        let verdict = compat::check(name, Some(version), policy);
        if verdict.offered() {
            offered.extend(name.parse::<Harness>().ok());
        }
        match verdict.reason {
            Some(why) if verdict.refused => refused.push(why),
            Some(note) => notes.push(note),
            None => {}
        }
    }
    (offered, refused, notes)
}

fn error(message: String) -> ServerMessage {
    ServerMessage::Error { message }
}

fn cancel(run: i64, reason: impl ToString) -> ServerMessage {
    ServerMessage::Cancel {
        run,
        reason: reason.to_string(),
    }
}

impl Session {
    fn now(&self) -> String {
        self.app.clock.now()
    }

    fn actor(&self) -> AuditActor {
        AuditActor::Runner(self.runner.id)
    }

    /// Setting `key` at `at` (E15.17); its default when it cannot be read.
    async fn setting(&self, key: Key, at: Scope) -> i64 {
        crate::store::settings::value(&self.app.pool, key, at)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(key = key.name(), error = %e, "reading a setting failed");
                key.default()
            })
    }

    /// Redacts what a runner may have leaked: transcript chunks and outcome reasons.
    fn redact(&self, msg: &mut RunnerMessage) {
        match msg {
            RunnerMessage::RunEvent { payload, .. }
            | RunnerMessage::ApprovalRequest { input: payload, .. } => self.redactor.json(payload),
            RunnerMessage::RunFallback { reason, .. }
            | RunnerMessage::ProviderDrop { reason, .. } => *reason = self.redactor.text(reason),
            RunnerMessage::RunEnded {
                outcome: Outcome::Failed { reason, .. } | Outcome::Cancelled { reason },
                ..
            } => *reason = self.redactor.text(reason),
            _ => {}
        }
    }

    async fn handle(&mut self, mut msg: RunnerMessage) -> Vec<ServerMessage> {
        self.redact(&mut msg);
        match &msg {
            RunnerMessage::FileRead {
                request, content, ..
            } => {
                let bytes = content.as_ref().map(String::len);
                tracing::debug!(
                    runner = self.runner.id.0,
                    request,
                    ?bytes,
                    "file from runner"
                );
            }
            RunnerMessage::LogTail { request, lines, .. } => {
                let lines = lines.len();
                tracing::debug!(runner = self.runner.id.0, request, lines, "log from runner");
            }
            msg => tracing::debug!(runner = self.runner.id.0, ?msg, "from runner"),
        }
        match msg {
            RunnerMessage::Hello {
                protocol,
                runner_version,
                tags,
                harnesses,
                runs,
                disk,
                info,
                os,
                arch,
            } => {
                if self.hello {
                    return vec![error("hello was already said".to_owned())];
                }
                if protocol_major(&protocol) != protocol_major(PROTOCOL_VERSION) {
                    self.closing = true;
                    let speaks = PROTOCOL_VERSION;
                    return vec![error(format!(
                        "unsupported protocol {protocol}; this server speaks {speaks}"
                    ))];
                }
                tracing::info!(runner = self.runner.id.0, %runner_version, ?tags, ?harnesses, "hello");
                self.hello = true;
                let minor = protocol
                    .split_once('.')
                    .and_then(|(_, m)| m.parse::<u32>().ok());
                self.reads_files = minor.is_some_and(|m| m >= 17);
                self.takes_controls = minor.is_some_and(|m| m >= 19);
                self.speaks_1_20 = minor.is_some_and(|m| m >= 20);
                self.speaks_1_24 = minor.is_some_and(|m| m >= 24);
                self.speaks_1_25 = minor.is_some_and(|m| m >= 25);
                let platform = (os.as_deref(), arch.as_deref());
                let recorded =
                    record_platform(&self.app.pool, self.runner.id, platform.0, platform.1);
                if let Err(e) = recorded.await {
                    tracing::error!(error = %e, "recording the runner's platform failed");
                }
                let info = info.map(|i| *i).unwrap_or_default();
                self.info(&info, Some(&harnesses)).await;
                self.runner.tags = tags;
                let policy = harness_policy(&self.app.pool, self.runner.id).await;
                let (offered, refused, notes) = judge(&harnesses, &policy);
                self.harnesses = offered;
                let status = if refused.is_empty() {
                    RunnerStatus::Online
                } else {
                    let why = refused.join("; ");
                    tracing::warn!(runner = self.runner.id.0, %why, "runner unhealthy");
                    RunnerStatus::Unhealthy
                };
                for note in &notes {
                    tracing::info!(runner = self.runner.id.0, %note, "untested harness version");
                }
                let reason = (!refused.is_empty()).then(|| refused.join("; "));
                self.set_status(status, reason, Some(self.now())).await;
                // Awake again: a wake the admin asked for is done.
                if let Err(e) =
                    crate::store::exec::runner_woke(&self.app.pool, self.runner.id).await
                {
                    tracing::error!(error = %e, "clearing the runner's wake request failed");
                }
                // The runner heartbeats at a third of its own lease TTL (E15.17).
                let at = Scope::Runner(self.runner.id);
                let lease_ttl_secs = self.setting(Key::LeaseTtlSecs, at).await;
                let limits = RunnerLimits {
                    disk_cap_bytes: self.setting(Key::DiskCapBytes, at).await as u64,
                    disk_evict_percent: self.setting(Key::DiskEvictPercent, at).await as u32,
                    workspace_idle_secs: self.setting(Key::WorkspaceIdleSecs, at).await as u64,
                    warm_idle_secs: self.setting(Key::WarmIdleSecs, at).await as u64,
                };
                let power_nap = match get_runner(&self.app.pool, self.runner.id).await {
                    Ok(Some(r)) => r.power_nap,
                    _ => None,
                };
                self.power_nap_sent = power_nap;
                let mut replies = vec![ServerMessage::Welcome {
                    runner: self.runner.id.0,
                    lease_ttl_secs,
                    limits: Some(limits),
                    power_nap,
                }];
                if let Some(report) = disk {
                    replies.extend(self.disk(&report).await);
                }
                for run in runs {
                    // A run re-announced in `Hello` renews its lease on the plain TTL.
                    replies.extend(self.heartbeat(run, None).await);
                }
                replies
            }
            _ if !self.hello => {
                self.closing = true;
                vec![error("say hello first".to_owned())]
            }
            RunnerMessage::Ready { workspaces } => {
                self.wanted += 1;
                let mut replies: Vec<ServerMessage> =
                    self.prune(&workspaces).await.into_iter().collect();
                replies.extend(self.dispatch().await);
                replies
            }
            RunnerMessage::Heartbeat { run, load } => {
                self.heartbeat(run, load).await.into_iter().collect()
            }
            RunnerMessage::Disk { report } => self.disk(&report).await.into_iter().collect(),
            RunnerMessage::Status { info } => {
                self.info(&info, None).await;
                vec![]
            }
            RunnerMessage::LogTail {
                request,
                lines,
                error,
            } => {
                self.log_tail(request, lines, error);
                vec![]
            }
            RunnerMessage::Probed {
                request,
                harnesses,
                info,
                os,
                arch,
                error,
            } => {
                let platform = (os.as_deref(), arch.as_deref());
                self.probed(request, harnesses, &info, platform, error)
                    .await;
                vec![]
            }
            RunnerMessage::Progress {
                run,
                diff_files,
                repos,
            } => self
                .progress(run, diff_files, &repos)
                .await
                .into_iter()
                .collect(),
            RunnerMessage::RunStarted { run, session } => vec![self.started(run, session).await],
            RunnerMessage::RunEvent { run, seq, payload } => {
                self.chunk(run, seq, &payload).await.into_iter().collect()
            }
            RunnerMessage::RunEnded { run, outcome } => vec![self.ended(run, outcome).await],
            RunnerMessage::RunUsage { run, seq, usage } => {
                self.usage(run, seq, usage).await.into_iter().collect()
            }
            RunnerMessage::RunFallback {
                run,
                harness,
                model,
                account,
                class,
                reason,
            } => self
                .fallback(run, &harness, model, account, &class, &reason)
                .await
                .into_iter()
                .collect(),
            RunnerMessage::ProviderDrop { run, reason } => {
                self.dropped(run, &reason).await.into_iter().collect()
            }
            RunnerMessage::ApprovalRequest {
                run,
                id,
                tool,
                input,
                timeout_secs,
            } => self
                .escalate(run, id, &tool, &input, timeout_secs)
                .await
                .into_iter()
                .collect(),
            RunnerMessage::FileRead {
                request,
                content,
                error,
            } => self.file_read(request, content, error).await,
        }
    }

    /// Writes the runner's status and health reason (set exactly when `Unhealthy`), its
    /// advertised tags, and `last_seen_at` when given.
    async fn set_status(
        &mut self,
        status: RunnerStatus,
        reason: Option<String>,
        seen: Option<String>,
    ) {
        let pool = &self.app.pool;
        let stored = match get_runner(pool, self.runner.id).await {
            Ok(Some(stored)) => stored,
            Ok(None) => return,
            Err(e) => return tracing::error!(error = %e, "reading runner failed"),
        };
        self.runner.status = status;
        self.runner.health_reason = reason;
        self.runner.last_seen_at = seen.or(stored.last_seen_at);
        if let Err(e) = update_runner(pool, &self.runner).await {
            tracing::error!(error = %e, "updating runner failed");
        }
    }
}
