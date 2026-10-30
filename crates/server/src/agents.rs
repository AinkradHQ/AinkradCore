//! The agent-session service (E2-08, P2.7): the platform primitive Citadel's issue runs and the
//! interactive chats sit on. A session is a harness on a runner (`ainkrad_proto::v2::agent`),
//! held by the runner's agent driver; the Core keeps its row and its transcript
//! (`store::agents`) and supervises it.
//!
//! - **One supervisor per live session**, started at create and, for every session not over,
//!   when the Core starts (`resume_all`). It long-polls the runner (`agent.read` from the
//!   stored `last_seq`), stores what comes back once, and carries on. So a lost answer, a runner
//!   reconnect or a Core restart costs a re-read, never a gap or a duplicate (E2-08.3).
//! - **Re-claim** (E2-08.5): while its runner is away the session waits for it; when it comes
//!   back the next read re-claims it. A runner that restarted reports the session
//!   `interrupted` (its harness went with it): the supervisor stores the rest of the transcript,
//!   then starts it again with the harness's own session id (`resume`) and fresh leases. A
//!   runner away past `lost_after`, or one that no longer knows the session, loses it.
//! - **Leases** (E2-07.2) are granted by the Core at each start, for the session's runner only,
//!   and travel only in the `agent.start` command: never in a response, an event or a row.
//! - **Capacity** (E2-08.1): a create is refused `runner_busy` when the runner's `agent`
//!   driver, or the harness's slot on it, is full (the runner refuses it too).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::v2::{
    AGENT_DRIVER, AgentEvents, AgentRead, AgentStart, AgentState, Body, Command, ErrorCode, Reply,
    SecretGrant, StreamError,
};
use serde_json::{Value, json};

use crate::api::App;
use crate::store::agents::{self as store, Session};

/// How the supervisors pace themselves.
#[derive(Debug, Clone)]
pub struct AgentsConfig {
    /// How long one `agent.read` waits on the runner.
    pub read_wait: Duration,
    /// Between attempts while the runner is away or busy.
    pub retry: Duration,
    /// A runner away this long loses its sessions.
    pub lost_after: Duration,
    /// How long a command other than a read waits for its answer.
    pub answer: Duration,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            read_wait: Duration::from_secs(20),
            retry: Duration::from_secs(2),
            lost_after: Duration::from_secs(3600),
            answer: Duration::from_secs(15),
        }
    }
}

/// The sessions supervised in this process.
#[derive(Default)]
pub struct Agents {
    pub config: AgentsConfig,
    supervised: Mutex<HashSet<String>>,
}

/// Why the service refused, as the API maps it.
#[derive(Debug)]
pub enum Refusal {
    Runner(StreamError),
    Secrets(crate::store::secrets::Error),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for Refusal {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<crate::store::secrets::Error> for Refusal {
    fn from(e: crate::store::secrets::Error) -> Self {
        Self::Secrets(e)
    }
}

impl From<StreamError> for Refusal {
    fn from(e: StreamError) -> Self {
        Self::Runner(e)
    }
}

fn busy(why: &str) -> Refusal {
    Refusal::Runner(StreamError::new(ErrorCode::Busy, why))
}

/// Whether the runner can take one more `harness` session now: online, offering `agent`, under
/// its capacity and the harness's slot (counting the sessions the Core holds on it).
pub async fn admit(app: &App, runner: &str, harness: &str) -> Result<(), Refusal> {
    let live = app.hub.runners();
    let Some(r) = live.get(runner).filter(|r| r.online) else {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::Offline,
            "the runner is not connected",
        )));
    };
    let Some(d) = r.drivers.iter().find(|d| d.name == AGENT_DRIVER) else {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::UnsupportedCommand,
            "the runner offers no agent sessions",
        )));
    };
    if !d.slots.is_empty() && !d.slots.contains_key(harness) {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::InvalidArgs,
            "the runner offers no slot for that harness",
        )));
    }
    let held = store::on_runner(&app.pool, runner).await?;
    let of_harness = held.iter().filter(|h| *h == harness).count();
    if held.len() >= d.capacity as usize
        || d.slots
            .get(harness)
            .is_some_and(|n| of_harness >= *n as usize)
    {
        return Err(busy("the runner's agent sessions are at their capacity"));
    }
    Ok(())
}

/// Leases each of the session's secrets to its runner for one start.
async fn leases(app: &App, s: &Session) -> Result<Vec<SecretGrant>, Refusal> {
    let mut out = Vec::with_capacity(s.secrets.len());
    for secret in &s.secrets {
        let (lease, _) = crate::store::secrets::lease(
            &app.pool,
            &secret.name,
            &s.runner,
            None,
            &s.created_by,
            AuditActor::System,
            &app.clock.now(),
            app.clock.unix(),
        )
        .await?;
        out.push(SecretGrant {
            lease,
            var: secret.var.clone(),
        });
    }
    Ok(out)
}

/// The `agent.start` of `s`, continuing the harness's own session when `resume`.
fn start_command(s: &Session, secrets: Vec<SecretGrant>, resume: bool) -> Command {
    Command::AgentStart(AgentStart {
        session: s.id.clone(),
        harness: s.harness.clone(),
        model: s.model.clone(),
        prompt: s.prompt.clone(),
        workspace: s
            .workspace
            .clone()
            .and_then(|w| serde_json::from_value(w).ok()),
        policy: serde_json::from_value(s.policy.clone()).unwrap_or_default(),
        resume: resume.then(|| s.harness_session.clone()).flatten(),
        secrets,
    })
}

/// Sends `command` to the session's runner and waits (at most `wait`) for its answer.
pub async fn ask(
    app: &App,
    runner: &str,
    command: Command,
    wait: Duration,
) -> Result<AgentEvents, StreamError> {
    let sent = app.hub.dispatch(runner, command)?;
    let answer = tokio::time::timeout(wait, sent.outcome())
        .await
        .map_err(|_| StreamError::new(ErrorCode::Lost, "the runner did not answer in time"))??;
    match answer {
        Body::Result(
            Reply::AgentStart(ev)
            | Reply::AgentRead(ev)
            | Reply::AgentSend(ev)
            | Reply::AgentDecide(ev)
            | Reply::AgentStop(ev),
        ) => Ok(ev),
        other => Err(StreamError::new(
            ErrorCode::BadFrame,
            format!("an answer of another op: {:?}", other_kind(&other)),
        )),
    }
}

fn other_kind(b: &Body) -> &'static str {
    match b {
        Body::Result(_) => "result",
        Body::Error(_) => "error",
        _ => "frame",
    }
}

/// Starts (or resumes) `s` on its runner with fresh leases; its state moves to `running`.
/// A refusal that retrying cannot fix ends the session as failed.
async fn launch(app: &App, s: &Session, resume: bool) -> Result<(), Refusal> {
    // No lease for a runner that cannot redeem it now: they would only pile up to the cap.
    if !app.hub.online(&s.runner) {
        let why = "the runner is not connected";
        return Err(Refusal::Runner(StreamError::new(ErrorCode::Offline, why)));
    }
    let secrets = match leases(app, s).await {
        Ok(l) => l,
        Err(e) => {
            fail(app, s, &format!("leasing its secrets: {}", describe(&e))).await;
            return Err(e);
        }
    };
    let wait = app.agents.config.answer;
    match ask(app, &s.runner, start_command(s, secrets, resume), wait).await {
        Ok(ev) => {
            let why = if resume { "resumed" } else { "started" };
            store::set_state(&app.pool, &s.id, "running", why, resume, &app.clock.now()).await?;
            store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
            Ok(())
        }
        Err(e) if matches!(e.code, ErrorCode::Busy | ErrorCode::InvalidArgs) => {
            fail(app, s, &e.message).await;
            Err(e.into())
        }
        Err(e) => Err(e.into()),
    }
}

/// Ends `s` as failed with `why` (no value or lease is ever in it).
async fn fail(app: &App, s: &Session, why: &str) {
    let outcome = json!({"kind": "failed", "reason": why, "fingerprint": "core"});
    if let Err(e) = store::end(&app.pool, &s.id, "ended", &outcome, &app.clock.now()).await {
        tracing::error!(session = s.id, error = %e, "ending a session failed");
    }
}

pub fn describe(r: &Refusal) -> String {
    match r {
        Refusal::Runner(e) => e.message.clone(),
        Refusal::Secrets(e) => e.to_string(),
        Refusal::Db(e) => e.to_string(),
    }
}

/// Starts a just-created session and supervises it. A runner away (or an answer lost) leaves
/// it `starting`, for the supervisor; any other refusal has ended it, and is returned.
pub async fn start(app: &App, s: &Session) -> Result<(), Refusal> {
    let first = launch(app, s, false).await;
    match &first {
        Err(Refusal::Runner(e)) if matches!(e.code, ErrorCode::Offline | ErrorCode::Lost) => {
            supervise(app, &s.id);
            Ok(())
        }
        Err(_) => first,
        Ok(()) => {
            supervise(app, &s.id);
            Ok(())
        }
    }
}

/// Starts supervising `id`, unless this process already does.
pub fn supervise(app: &App, id: &str) {
    if !app.agents.supervised.lock().unwrap().insert(id.to_owned()) {
        return;
    }
    let (app, id) = (app.clone(), id.to_owned());
    tokio::spawn(async move {
        let mut closing = app.closing.subscribe();
        tokio::select! {
            () = run(&app, &id) => {}
            () = crate::api::stopping(&mut closing) => {}
        }
        app.agents.supervised.lock().unwrap().remove(&id);
    });
}

/// Supervises every session not over: what a starting Core does (a Core restart re-claims).
pub async fn resume_all(app: &App) -> Result<usize, sqlx::Error> {
    let live = store::live(&app.pool).await?;
    for s in &live {
        supervise(app, &s.id);
    }
    Ok(live.len())
}

/// A session's supervisor, until it is over.
async fn run(app: &App, id: &str) {
    let cfg = app.agents.config.clone();
    let mut away: Option<tokio::time::Instant> = None;
    loop {
        let s = match store::get(&app.pool, id).await {
            Ok(Some(s)) if s.live() => s,
            Ok(_) => return,
            Err(e) => {
                tracing::error!(session = id, error = %e, "reading a session failed");
                tokio::time::sleep(cfg.retry).await;
                continue;
            }
        };
        let step = match s.state.as_str() {
            "starting" => launch(app, &s, false).await.map(drop),
            "interrupted" => launch(app, &s, true).await.map(drop),
            _ => read(app, &s, &cfg).await,
        };
        match step {
            Ok(()) => away = None,
            Err(Refusal::Runner(e)) if matches!(e.code, ErrorCode::Offline | ErrorCode::Lost) => {
                let since = *away.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= cfg.lost_after {
                    let outcome = json!({"kind": "lost", "reason": "the runner never came back"});
                    let _ = store::end(&app.pool, id, "lost", &outcome, &app.clock.now()).await;
                    return;
                }
                tokio::time::sleep(cfg.retry).await;
            }
            Err(e) => {
                tracing::warn!(session = id, why = describe(&e), "supervising a session");
                tokio::time::sleep(cfg.retry).await;
            }
        }
    }
}

/// One long poll: stores what came; an `interrupted` or `ended` runner state, once every entry
/// is stored, moves the session.
async fn read(app: &App, s: &Session, cfg: &AgentsConfig) -> Result<(), Refusal> {
    let after = u64::try_from(s.last_seq).unwrap_or(0);
    let wait = u64::try_from(cfg.read_wait.as_millis()).unwrap_or(u64::MAX);
    let req = Command::AgentRead(AgentRead {
        session: s.id.clone(),
        after,
        wait_ms: Some(wait),
    });
    let ev = match ask(app, &s.runner, req, cfg.read_wait + cfg.answer).await {
        Ok(ev) => ev,
        Err(e)
            if e.code == ErrorCode::InvalidArgs && e.message == ainkrad_proto::v2::NO_SESSION =>
        {
            // The runner no longer knows it (its state was wiped): nothing will come back.
            let outcome = json!({"kind": "lost", "reason": e.message});
            store::end(&app.pool, &s.id, "lost", &outcome, &app.clock.now()).await?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let held = store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    if held >= store::MAX_TRANSCRIPT && held < ev.last_seq {
        // Nothing more is stored: the session is stopped, not read forever.
        let stop = Command::AgentStop(ainkrad_proto::v2::AgentStop {
            session: s.id.clone(),
            kill: true,
        });
        let _ = ask(app, &s.runner, stop, cfg.answer).await;
        let why = format!("the transcript reached {} entries", store::MAX_TRANSCRIPT);
        fail(app, s, &why).await;
        return Ok(());
    }
    if held < ev.last_seq {
        return Ok(()); // more to read first
    }
    match ev.state {
        AgentState::Ended => {
            let outcome = ev
                .outcome
                .as_ref()
                .and_then(|o| serde_json::to_value(o).ok())
                .unwrap_or(Value::Null);
            store::end(&app.pool, &s.id, "ended", &outcome, &app.clock.now()).await?;
            // The runner may drop its copy: the Core holds all of it.
            let ack = Command::AgentRead(AgentRead {
                session: s.id.clone(),
                after: held,
                wait_ms: None,
            });
            let _ = ask(app, &s.runner, ack, cfg.answer).await;
        }
        AgentState::Interrupted => {
            let why = "the runner restarted";
            store::set_state(
                &app.pool,
                &s.id,
                "interrupted",
                why,
                false,
                &app.clock.now(),
            )
            .await?;
        }
        AgentState::Running | AgentState::Unknown => {}
    }
    Ok(())
}

/// The supervised session ids, for tests.
pub fn supervised(app: &App) -> Vec<String> {
    let all = app.agents.supervised.lock().unwrap();
    let mut v: Vec<String> = all.iter().cloned().collect();
    v.sort();
    v
}

impl Agents {
    pub fn new(config: AgentsConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            supervised: Mutex::default(),
        })
    }
}
