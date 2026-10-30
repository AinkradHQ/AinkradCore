//! The `agent` driver (E2-08): harness sessions owned by the runner, keyed by the Core's
//! session id (`ainkrad_proto::v2::agent`), outliving every connection.
//!
//! - **Harness.** Any [`Executor`](crate::Executor): `HarnessExecutor` drives the real
//!   harnesses (and gates their versions, meters their tokens, escalates their tool calls);
//!   `FakeExecutor` stands in. A session is one `Executor::run`.
//! - **Capacity** (E2-08.1): at most `capacity` sessions run at once, and at most a harness's
//!   `slots` of them; one more is `busy`. Reads and the other ops are commands, counted by the
//!   hub against `streams`, never against the sessions.
//! - **Transcript** (E2-08.3): every entry gets the session's next `seq` and is redacted before
//!   it is kept (in memory, and appended to `<dir>/<session>/transcript.jsonl`). An `agent.read`
//!   acknowledges what the Core holds; entries it acknowledged are dropped. Past `max_entries`
//!   unacknowledged, the oldest go and the next read starts with an explicit `gap` entry.
//! - **Secrets** (E2-07.2/.3, `secrets`): the runner redeems each lease of an `agent.start`
//!   itself, delivers the value to that session's harness only (env on its processes, a 0600
//!   file, or an askpass helper), and teaches the session's redactor the value before the
//!   harness starts. Delivered files go when the session ends, is killed, or (after a crash)
//!   when the next driver starts.
//! - **Restart** (E2-08.5): a new driver reloads every session from `dir`. One that was running
//!   went with the old process: it is `interrupted`, its transcript kept for the Core to read,
//!   and an `agent.start` naming it again resumes it (`resume`, the harness's own session).
//! - **Isolation** is E2-09: [`Sandbox`] is the seam; the default confines nothing.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::runner::{Outcome, RunToken, Tokens, Workspace};
use ainkrad_proto::v2::{
    AGENT_DRIVER, AGENT_OPS, AgentDecide, AgentEvents, AgentRead, AgentStart, AgentState,
    AgentStop, DriverInfo, ErrorCode, StreamError, TranscriptEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc};

use crate::{Answer, Control, Executor, Job, Report};

pub mod secrets;
use secrets::{Delivered, Redeem};

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The longest an `agent.read` waits, whatever the Core asks.
pub const MAX_WAIT: Duration = Duration::from_secs(25);

/// Entries one `agent.read` answers with at most (the rest on the next).
const READ_BATCH: usize = 256;
const MAX_ENTRY_BYTES: usize = 256 * 1024;
const MAX_BATCH_BYTES: usize = 1024 * 1024;
const MAX_TRANSCRIPT_BYTES: u64 = 16 * 1024 * 1024;

/// How the driver is set up.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Sessions' transcripts and state: `<dir>/<session>/`.
    pub dir: PathBuf,
    /// Delivered secrets, `<secrets_dir>/<session>/`, 0700. Emptied when the driver starts.
    pub secrets_dir: PathBuf,
    /// Sessions at once.
    pub capacity: u32,
    /// Per harness, sessions at once; a harness not listed is refused. Empty: any harness.
    pub slots: BTreeMap<String, u32>,
    /// Unacknowledged entries kept per session before the oldest go (a `gap`).
    pub max_entries: usize,
    /// After a cancel, how long the harness has before it is killed.
    pub stop_grace: Duration,
}

impl AgentConfig {
    pub fn new(dir: PathBuf, secrets_dir: PathBuf) -> Self {
        Self {
            dir,
            secrets_dir,
            capacity: 2,
            slots: BTreeMap::new(),
            max_entries: 10_000,
            stop_grace: Duration::from_secs(30),
        }
    }
}

/// The isolation seam (E2-09): called with a session's start and the variables its harness
/// gets, before the harness starts; refusing fails the session. E2-09 brings Landlock and
/// Seatbelt here (and threads them to `ainkrad_harness::proc::command`).
pub trait Sandbox: Send + Sync {
    /// Shown in logs and the session's `started` entry.
    fn name(&self) -> &'static str;
    fn prepare(&self, start: &AgentStart, env: &mut Vec<(String, String)>) -> Result<(), String>;
}

/// The default: the harness runs as the runner's user, unconfined (the E2 landmine E2-09 fixes).
pub struct Unconfined;

impl Sandbox for Unconfined {
    fn name(&self) -> &'static str {
        "none"
    }
    fn prepare(&self, _: &AgentStart, _: &mut Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
}

/// [`Executor`] as an object, so the driver is one type whatever drives the harness.
trait Harness: Send + Sync {
    fn secrets(&self) -> Fut<'_, Vec<(String, String)>>;
    fn start<'a>(&'a self, job: &'a Job) -> Fut<'a, Result<Option<String>, String>>;
    fn run<'a>(&'a self, job: &'a Job, reports: mpsc::Sender<Report>) -> Fut<'a, Outcome>;
    fn run_secrets(&self, job: &Job) -> Vec<(String, String)>;
    fn control(&self, run: i64, control: Control);
    fn session_env(&self, run: i64, env: Option<Vec<(String, String)>>);
    fn prepare_agent_workspace<'a>(
        &'a self,
        session: &'a str,
        workspace: &'a Workspace,
    ) -> Fut<'a, Result<PathBuf, String>>;
    fn cleanup_agent_workspace<'a>(&'a self, session: &'a str) -> Fut<'a, ()>;
}

impl<E: Executor> Harness for E {
    fn secrets(&self) -> Fut<'_, Vec<(String, String)>> {
        Box::pin(Executor::secrets(self))
    }
    fn start<'a>(&'a self, job: &'a Job) -> Fut<'a, Result<Option<String>, String>> {
        Box::pin(Executor::start(self, job))
    }
    fn run<'a>(&'a self, job: &'a Job, reports: mpsc::Sender<Report>) -> Fut<'a, Outcome> {
        // The run token is Citadel's MCP credential (E2-13 brings it back); none here.
        Box::pin(Executor::run(
            self,
            job,
            RunToken::new(String::new()),
            reports,
        ))
    }
    fn run_secrets(&self, job: &Job) -> Vec<(String, String)> {
        Executor::run_secrets(self, job)
    }
    fn control(&self, run: i64, control: Control) {
        Executor::control(self, run, control);
    }
    fn session_env(&self, run: i64, env: Option<Vec<(String, String)>>) {
        Executor::session_env(self, run, env);
    }
    fn prepare_agent_workspace<'a>(
        &'a self,
        session: &'a str,
        workspace: &'a Workspace,
    ) -> Fut<'a, Result<PathBuf, String>> {
        Box::pin(Executor::prepare_agent_workspace(self, session, workspace))
    }
    fn cleanup_agent_workspace<'a>(&'a self, session: &'a str) -> Fut<'a, ()> {
        Box::pin(Executor::cleanup_agent_workspace(self, session))
    }
}

/// What survives the process, in `<dir>/<session>/meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    harness: String,
    state: AgentState,
    last_seq: u64,
    /// The newest `seq` the Core holds.
    acked: u64,
    #[serde(default)]
    harness_session: Option<String>,
    #[serde(default)]
    usage: Option<Tokens>,
    #[serde(default)]
    outcome: Option<Outcome>,
}

struct Live {
    meta: Meta,
    run: i64,
    /// Unacknowledged entries, oldest first.
    entries: VecDeque<TranscriptEntry>,
    /// The session's redactor: the harness's secrets, its account's, and its leased values.
    redactor: Redactor,
    /// Tool calls waiting on a decision, by request id.
    approvals: HashMap<String, crate::Reply>,
    /// The task working it, while it runs.
    task: Option<tokio::task::AbortHandle>,
}

pub struct AgentDriver {
    config: AgentConfig,
    harness: Arc<dyn Harness>,
    redeem: Option<Redeem>,
    sandbox: Arc<dyn Sandbox>,
    sessions: Mutex<HashMap<String, Live>>,
    /// Woken on every new entry or state change, for reads.
    changed: Notify,
    next_run: Mutex<i64>,
}

fn refuse(code: ErrorCode, why: impl Into<String>) -> StreamError {
    StreamError::new(code, why)
}

use ainkrad_proto::v2::valid_session_id as valid_session;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl AgentDriver {
    /// The driver over `config.dir`: delivered secrets a crashed process left are removed
    /// first, then every session is reloaded (running ones as `interrupted`).
    pub fn new<E: Executor>(config: AgentConfig, executor: E) -> std::io::Result<Self> {
        secrets::sweep(&config.secrets_dir)?;
        secrets::private_dir(&config.dir)?;
        let sessions = reload(&config);
        Ok(Self {
            config,
            harness: Arc::new(executor),
            redeem: None,
            sandbox: Arc::new(Unconfined),
            sessions: Mutex::new(sessions),
            changed: Notify::new(),
            // Unique across runner processes: a harness names its scratch dirs `run-<id>`, and a
            // run after a restart must never land in a dead session's.
            next_run: Mutex::new(now_ms()),
        })
    }

    /// How leases are redeemed (`secrets::http_redeem`); without it a start with secrets fails.
    pub fn with_redeem(mut self, redeem: Redeem) -> Self {
        self.redeem = Some(redeem);
        self
    }

    pub fn with_sandbox(mut self, sandbox: Arc<dyn Sandbox>) -> Self {
        self.sandbox = sandbox;
        self
    }

    pub fn info(&self) -> DriverInfo {
        DriverInfo {
            name: AGENT_DRIVER.to_owned(),
            commands: AGENT_OPS.iter().map(|o| (*o).to_owned()).collect(),
            capacity: self.config.capacity,
            slots: self.config.slots.clone(),
            // A read per session, and room for starts, messages, decisions and stops.
            streams: Some(self.config.capacity.saturating_mul(2).saturating_add(8)),
        }
    }

    /// The session's state and entries after `after`, waiting up to `wait_ms` for one.
    pub async fn read(&self, req: &AgentRead) -> Result<AgentEvents, StreamError> {
        let wait = Duration::from_millis(req.wait_ms.unwrap_or(0)).min(MAX_WAIT);
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.changed.notified();
            {
                let mut all = self.sessions.lock().unwrap();
                let live = all.get_mut(&req.session).ok_or_else(no_session)?;
                ack(&self.config, &req.session, live, req.after);
                let events = events(&req.session, live, req.after);
                if !events.entries.is_empty() || events.state != AgentState::Running {
                    return Ok(events);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Ok(events);
                }
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    /// Starts `req`'s session, or answers with the one it already holds (a resent start).
    pub fn start(self: &Arc<Self>, req: AgentStart) -> Result<AgentEvents, StreamError> {
        if !valid_session(&req.session) {
            return Err(refuse(ErrorCode::InvalidArgs, "a session id is as_…"));
        }
        if req.secrets.iter().any(|s| !secrets::valid_var(&s.var)) {
            return Err(refuse(
                ErrorCode::InvalidArgs,
                "a secret's var is [A-Z_][A-Z0-9_]*, and not one the runner sets itself",
            ));
        }
        let slots = &self.config.slots;
        if !slots.is_empty() && !slots.contains_key(&req.harness) {
            return Err(refuse(
                ErrorCode::InvalidArgs,
                "this runner offers no slot for that harness",
            ));
        }
        let mut all = self.sessions.lock().unwrap();
        if let Some(live) = all.get(&req.session)
            && live.meta.state != AgentState::Interrupted
        {
            return Ok(events(&req.session, live, live.meta.last_seq));
        }
        let running: Vec<&Live> = all
            .values()
            .filter(|l| l.meta.state == AgentState::Running)
            .collect();
        let of_harness = running
            .iter()
            .filter(|l| l.meta.harness == req.harness)
            .count();
        if running.len() >= self.config.capacity as usize
            || slots
                .get(&req.harness)
                .is_some_and(|n| of_harness >= *n as usize)
        {
            return Err(refuse(
                ErrorCode::Busy,
                "the agent driver is at its capacity",
            ));
        }
        let run = {
            let mut next = self.next_run.lock().unwrap();
            *next += 1;
            *next
        };
        let resumed = all.contains_key(&req.session);
        let live = all.entry(req.session.clone()).or_insert_with(|| Live {
            meta: Meta {
                harness: req.harness.clone(),
                state: AgentState::Running,
                last_seq: 0,
                acked: 0,
                harness_session: None,
                usage: None,
                outcome: None,
            },
            run,
            entries: VecDeque::new(),
            redactor: Redactor::new(),
            approvals: HashMap::new(),
            task: None,
        });
        live.meta.state = AgentState::Running;
        live.meta.outcome = None;
        live.run = run;
        save_meta(&self.config, &req.session, &live.meta);
        let me = Arc::clone(self);
        let session = req.session.clone();
        let task = tokio::spawn(async move { me.work(req, run, resumed).await });
        live.task = Some(task.abort_handle());
        let answer = events(&session, live, live.meta.last_seq);
        drop(all);
        self.changed.notify_waiters();
        Ok(answer)
    }

    /// Redeems and delivers the session's secrets, starts the harness and works it to its end.
    async fn work(self: Arc<Self>, req: AgentStart, run: i64, resumed: bool) {
        let session = req.session.clone();
        let job = Job {
            run,
            agent: 0,
            issue: None,
            harness: req.harness.clone(),
            model: req.model.clone().unwrap_or_default(),
            context_ref: session.clone(),
            workspace: req.workspace.clone(),
            token_cap: None,
            token_caps: None,
            policy: req.policy.clone(),
            issue_key: None,
            instructions: None,
            account: None,
            fallbacks: vec![],
            limits: None,
            resume_session: req.resume.clone(),
            prompt: req.prompt.clone(),
            repos: vec![],
        };
        if let Some(workspace) = req.workspace.as_ref()
            && let Err(why) = self
                .harness
                .prepare_agent_workspace(&session, workspace)
                .await
        {
            return self.end(&session, failed(why, "workspace"));
        }
        let workspace_prepared = req.workspace.is_some();
        let mut redactor = Redactor::new();
        for (name, value) in self.harness.secrets().await {
            redactor.known(&name, &value);
        }
        // Held to the end of this task: dropping it (the end, a kill's abort) removes the files.
        let delivered = match self.deliver(&req, &mut redactor).await {
            Ok(d) => d,
            Err(why) => {
                if workspace_prepared {
                    self.harness.cleanup_agent_workspace(&session).await;
                }
                return self.end(&session, failed(why, "secrets"));
            }
        };
        let mut env = delivered.env.clone();
        if let Err(why) = self.sandbox.prepare(&req, &mut env) {
            if workspace_prepared {
                self.harness.cleanup_agent_workspace(&session).await;
            }
            return self.end(&session, failed(why, "sandbox"));
        }
        self.harness.session_env(run, Some(env));
        let started = match self.harness.start(&job).await {
            Ok(id) => id,
            Err(why) => {
                self.harness.session_env(run, None);
                if workspace_prepared {
                    self.harness.cleanup_agent_workspace(&session).await;
                }
                let why = redactor.text(&why);
                return self.end(&session, failed(why, "start"));
            }
        };
        for (name, value) in self.harness.run_secrets(&job) {
            redactor.known(&name, &value);
        }
        let entry = json!({"type": "started", "harness": req.harness, "resumed": resumed,
                           "sandbox": self.sandbox.name()});
        self.with(&session, |live, cfg, s| {
            live.redactor = redactor;
            if started.is_some() {
                live.meta.harness_session = started;
            }
            push(cfg, s, live, entry);
        });
        let (tx, mut rx) = mpsc::channel(64);
        let outcome = {
            let run = self.harness.run(&job, tx);
            tokio::pin!(run);
            loop {
                tokio::select! {
                    Some(r) = rx.recv() => self.report(&session, r),
                    outcome = &mut run => break outcome,
                }
            }
        };
        while let Ok(r) = rx.try_recv() {
            self.report(&session, r);
        }
        self.harness.session_env(run, None);
        self.harness.cleanup_agent_workspace(&session).await;
        drop(delivered);
        self.end(&session, outcome);
    }

    /// Redeems each lease and delivers it to the session's private dir; the redactor learns
    /// every value first.
    async fn deliver(
        &self,
        req: &AgentStart,
        redactor: &mut Redactor,
    ) -> Result<Delivered, String> {
        let mut leased = Vec::with_capacity(req.secrets.len());
        if !req.secrets.is_empty() {
            let redeem = self
                .redeem
                .as_ref()
                .ok_or("this runner cannot redeem secrets")?;
            for grant in &req.secrets {
                let secret = redeem(grant.lease.clone()).await?;
                redactor.known(&secret.name, &secret.value);
                leased.push((grant.var.clone(), secret));
            }
        }
        secrets::deliver(&self.config.secrets_dir, &req.session, leased)
            .map_err(|e| format!("delivering the session's secrets: {e}"))
    }

    /// Runs `f` on the session, if it is still held.
    fn with(&self, session: &str, f: impl FnOnce(&mut Live, &AgentConfig, &str)) {
        if let Some(live) = self.sessions.lock().unwrap().get_mut(session) {
            f(live, &self.config, session);
        }
        self.changed.notify_waiters();
    }

    fn report(&self, session: &str, report: Report) {
        self.with(session, |live, cfg, s| {
            let body = match report {
                Report::Event(v) => {
                    if v["type"] == "session_started"
                        && let Some(id) = v["id"].as_str()
                    {
                        live.meta.harness_session = Some(id.to_owned());
                    }
                    v
                }
                Report::Usage(t) => {
                    live.meta.usage = Some(t);
                    return;
                }
                Report::Fallback {
                    harness,
                    model,
                    class,
                    reason,
                    ..
                } => json!({"type": "fallback", "harness": harness, "model": model,
                            "class": class, "reason": reason}),
                Report::Dropped { reason } => json!({"type": "dropped", "reason": reason}),
                Report::Progress { .. } => return,
                Report::Approval {
                    id,
                    tool,
                    input,
                    timeout_secs,
                    reply,
                } => {
                    live.approvals.insert(id.clone(), reply);
                    json!({"type": "approval_request", "id": id, "tool": tool, "input": input,
                           "timeout_secs": timeout_secs})
                }
            };
            push(cfg, s, live, body);
        });
    }

    /// The session ended with `outcome`: its last entry, its state saved.
    fn end(&self, session: &str, outcome: Outcome) {
        self.with(session, |live, cfg, s| {
            let mut outcome = outcome;
            if let Outcome::Failed { reason, .. } | Outcome::Cancelled { reason } = &mut outcome {
                *reason = live.redactor.text(reason);
            }
            live.task = None;
            live.approvals.clear();
            push(cfg, s, live, json!({"type": "ended", "outcome": outcome}));
            live.meta.state = AgentState::Ended;
            live.meta.outcome = Some(outcome);
            save_meta(cfg, s, &live.meta);
        });
    }

    pub fn send(&self, session: &str, text: String) -> Result<AgentEvents, StreamError> {
        self.running(session, |live, cfg| {
            let id = i64::try_from(live.meta.last_seq).unwrap_or(i64::MAX);
            let entry = json!({"type": "message", "text": text});
            self.harness
                .control(live.run, Control::Message { id, text });
            push(cfg, session, live, entry);
            Ok(())
        })
    }

    pub fn decide(&self, req: AgentDecide) -> Result<AgentEvents, StreamError> {
        self.running(&req.session, |live, cfg| {
            let reply = live
                .approvals
                .remove(&req.request)
                .ok_or_else(|| refuse(ErrorCode::InvalidArgs, "no such tool request waiting"))?;
            reply.send(Answer {
                approved: req.approved,
                reply: req.reply.clone(),
            });
            let entry = json!({"type": "approval_decided", "id": req.request,
                               "approved": req.approved});
            push(cfg, &req.session, live, entry);
            Ok(())
        })
    }

    /// Cancels the session (its tool call in flight finishes, then it ends; killed after
    /// `stop_grace`), or kills it now.
    pub fn stop(self: &Arc<Self>, req: AgentStop) -> Result<AgentEvents, StreamError> {
        let run = {
            let all = self.sessions.lock().unwrap();
            let live = all.get(&req.session).ok_or_else(no_session)?;
            if live.meta.state != AgentState::Running {
                return Ok(events(&req.session, live, live.meta.last_seq));
            }
            live.run
        };
        if req.kill {
            self.kill(&req.session, run);
        } else {
            self.harness.control(run, Control::Pause);
            let (me, session) = (Arc::clone(self), req.session.clone());
            tokio::spawn(async move {
                tokio::time::sleep(me.config.stop_grace).await;
                me.kill(&session, run);
            });
        }
        let all = self.sessions.lock().unwrap();
        let live = all.get(&req.session).ok_or_else(no_session)?;
        Ok(events(&req.session, live, live.meta.last_seq))
    }

    /// Aborts run `run` of the session (its harness is killed with it, and its secret files
    /// removed): ended as cancelled. A later run of the session is left alone.
    fn kill(self: &Arc<Self>, session: &str, run: i64) {
        let task = {
            let mut all = self.sessions.lock().unwrap();
            match all.get_mut(session) {
                Some(l) if l.run == run && l.meta.state == AgentState::Running => l.task.take(),
                _ => return,
            }
        };
        if let Some(task) = task {
            task.abort();
        }
        self.harness.session_env(run, None);
        let me = Arc::clone(self);
        let cleanup_session = session.to_owned();
        tokio::spawn(async move {
            me.harness.cleanup_agent_workspace(&cleanup_session).await;
        });
        self.end(
            session,
            Outcome::Cancelled {
                reason: "killed".to_owned(),
            },
        );
    }

    fn running(
        &self,
        session: &str,
        f: impl FnOnce(&mut Live, &AgentConfig) -> Result<(), StreamError>,
    ) -> Result<AgentEvents, StreamError> {
        let answer = {
            let mut all = self.sessions.lock().unwrap();
            let live = all.get_mut(session).ok_or_else(no_session)?;
            if live.meta.state != AgentState::Running {
                return Err(refuse(ErrorCode::InvalidArgs, "the session is not running"));
            }
            f(live, &self.config)?;
            events(session, live, live.meta.last_seq)
        };
        self.changed.notify_waiters();
        Ok(answer)
    }

    /// The sessions it holds and their state, for tests and logs.
    pub fn states(&self) -> BTreeMap<String, AgentState> {
        let all = self.sessions.lock().unwrap();
        all.iter().map(|(k, l)| (k.clone(), l.meta.state)).collect()
    }
}

fn no_session() -> StreamError {
    refuse(ErrorCode::InvalidArgs, ainkrad_proto::v2::NO_SESSION)
}

fn failed(reason: String, step: &str) -> Outcome {
    Outcome::Failed {
        reason,
        fingerprint: Some(step.to_owned()),
    }
}

/// Appends `body` (redacted) as the session's next entry, on disk too.
fn push(cfg: &AgentConfig, session: &str, live: &mut Live, mut body: Value) {
    live.redactor.json(&mut body);
    if body.to_string().len() > MAX_ENTRY_BYTES {
        body = json!({"type": "truncated"});
    }
    live.meta.last_seq += 1;
    let entry = TranscriptEntry {
        seq: live.meta.last_seq,
        at: now_ms(),
        body,
    };
    let path = cfg.dir.join(session).join("transcript.jsonl");
    let line = serde_json::to_string(&entry).expect("an entry serializes") + "\n";
    let written = std::fs::metadata(&path)
        .ok()
        .filter(|m| m.len() >= MAX_TRANSCRIPT_BYTES)
        .map_or_else(
            || secrets::private_file(&path, true).and_then(|mut f| f.write_all(line.as_bytes())),
            |_| Ok(()),
        );
    if let Err(e) = written {
        tracing::error!(session, error = %e, "appending to a transcript failed");
    }
    live.entries.push_back(entry);
    if live.entries.len() > cfg.max_entries {
        live.entries.pop_front();
    }
}

/// The Core holds up to `after`: what it holds is dropped here (and noted on disk).
fn ack(cfg: &AgentConfig, session: &str, live: &mut Live, after: u64) {
    let after = after.min(live.meta.last_seq);
    if after <= live.meta.acked {
        return;
    }
    while live.entries.front().is_some_and(|e| e.seq <= after) {
        live.entries.pop_front();
    }
    live.meta.acked = after;
    save_meta(cfg, session, &live.meta);
    // Everything delivered and nothing more to come: the transcript file goes, the state stays.
    if live.meta.state == AgentState::Ended && after == live.meta.last_seq {
        let _ = std::fs::remove_file(cfg.dir.join(session).join("transcript.jsonl"));
    }
}

/// The session's answer with its entries after `after`; a `gap` entry first when entries the
/// Core never read were dropped.
fn events(session: &str, live: &Live, after: u64) -> AgentEvents {
    let mut entries = Vec::new();
    let first = live
        .entries
        .front()
        .map_or(live.meta.last_seq + 1, |e| e.seq);
    if after + 1 < first && after < live.meta.last_seq {
        entries.push(TranscriptEntry {
            seq: first - 1,
            at: now_ms(),
            body: json!({"type": "gap", "from": after + 1, "to": first - 1}),
        });
    }
    let mut bytes: usize = 0;
    for entry in live
        .entries
        .iter()
        .filter(|e| e.seq > after)
        .take(READ_BATCH)
    {
        let size = serde_json::to_vec(entry).map_or(0, |v| v.len());
        if !entries.is_empty() && bytes.saturating_add(size) > MAX_BATCH_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        entries.push(entry.clone());
    }
    AgentEvents {
        session: session.to_owned(),
        state: live.meta.state,
        last_seq: live.meta.last_seq,
        entries,
        harness_session: live.meta.harness_session.clone(),
        usage: live.meta.usage,
        outcome: live.meta.outcome.clone(),
    }
}

fn save_meta(cfg: &AgentConfig, session: &str, meta: &Meta) {
    let dir = cfg.dir.join(session);
    let saved = secrets::private_dir(&dir).and_then(|()| {
        let tmp = dir.join("meta.json.tmp");
        let mut f = secrets::private_file(&tmp, false)?;
        f.write_all(&serde_json::to_vec(meta).expect("meta serializes"))?;
        f.sync_all()?;
        std::fs::rename(tmp, dir.join("meta.json"))
    });
    if let Err(e) = saved {
        tracing::error!(session, error = %e, "saving a session's state failed");
    }
}

/// Every session under `cfg.dir`, with its unacknowledged entries; one that was running is now
/// `interrupted` (its harness went with the process that ran it).
fn reload(cfg: &AgentConfig) -> HashMap<String, Live> {
    let mut out = HashMap::new();
    let Ok(dirs) = std::fs::read_dir(&cfg.dir) else {
        return out;
    };
    for d in dirs.flatten() {
        let session = d.file_name().to_string_lossy().into_owned();
        if !valid_session(&session) {
            continue;
        }
        let Some(mut meta) = std::fs::read(d.path().join("meta.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
        else {
            continue;
        };
        let text = std::fs::read_to_string(d.path().join("transcript.jsonl")).unwrap_or_default();
        let mut entries: VecDeque<TranscriptEntry> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<TranscriptEntry>(l).ok())
            .filter(|e| e.seq > meta.acked)
            .collect();
        while entries.len() > cfg.max_entries {
            entries.pop_front();
        }
        if let Some(last) = entries.back() {
            meta.last_seq = meta.last_seq.max(last.seq);
        }
        let mut live = Live {
            meta,
            run: 0,
            entries,
            redactor: Redactor::new(),
            approvals: HashMap::new(),
            task: None,
        };
        if live.meta.state == AgentState::Running {
            tracing::warn!(
                session,
                "a session's harness went with the last runner process"
            );
            live.meta.state = AgentState::Interrupted;
            push(
                cfg,
                &session,
                &mut live,
                json!({"type": "interrupted", "reason": "the runner restarted"}),
            );
            save_meta(cfg, &session, &live.meta);
        }
        out.insert(session, live);
    }
    out
}

#[cfg(test)]
mod tests;
