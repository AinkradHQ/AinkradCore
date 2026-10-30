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

mod launch;
use launch::launch;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::v2::{
    AGENT_DRIVER, AgentEvents, AgentRead, AgentStart, AgentState, Body, Command, ErrorCode, Reply,
    SecretGrant, StreamError,
};
use serde_json::{Value, json};

use crate::api::App;
use crate::api::v1::Caller;
use crate::hub::Elevated;
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
    elevated: Mutex<HashMap<String, Elevated>>,
    leases: Mutex<HashMap<String, (i64, Vec<SecretGrant>)>>,
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

/// Sends `command` to the session's runner and waits (at most `wait`) for its answer.
pub async fn ask(
    app: &App,
    runner: &str,
    command: Command,
    wait: Duration,
    proof: Option<Elevated>,
) -> Result<AgentEvents, StreamError> {
    let sent = if command.op() == ainkrad_proto::v2::OP_AGENT_READ {
        app.hub.dispatch_agent_read(runner, command)?
    } else {
        app.hub.dispatch_elevated(
            runner,
            command,
            proof.ok_or_else(|| {
                StreamError::new(ErrorCode::InvalidArgs, "agent elevation missing")
            })?,
        )?
    };
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

/// Called only by the already-gated create route. The proof is retained for the supervisor's
/// reconnect/start path: resuming the same session continues the original elevated create.
pub fn authorize_create(app: &App, caller: &Caller, session: &str) {
    debug_assert!(caller.device.scopes.iter().any(|s| s == "agent"));
    app.agents
        .elevated
        .lock()
        .unwrap()
        .insert(session.to_owned(), app.hub.agent_elevation(caller));
}

#[cfg(feature = "test-support")]
pub fn authorize_for_tests(app: &App, session: &str) {
    app.agents
        .elevated
        .lock()
        .unwrap()
        .insert(session.to_owned(), Elevated::for_tests());
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
        app.agents
            .elevated
            .lock()
            .unwrap()
            .insert(s.id.clone(), app.hub.continue_agent_elevation());
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
                let since = *away.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= cfg.lost_after {
                    fail(app, &s, "bounded agent retries exhausted").await;
                    app.agents.leases.lock().unwrap().remove(id);
                    return;
                }
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
    let ev = match ask(app, &s.runner, req, cfg.read_wait + cfg.answer, None).await {
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
        let proof = app.agents.elevated.lock().unwrap().get(&s.id).copied();
        let why = format!("the transcript reached {} entries", store::MAX_TRANSCRIPT);
        match ask(app, &s.runner, stop, cfg.answer, proof).await {
            Ok(_) => fail(app, s, &why).await,
            Err(e) => {
                let outcome = json!({
                    "kind": "lost",
                    "reason": format!("kill pending after transcript ceiling: {}", e.message)
                });
                let _ = store::end(&app.pool, &s.id, "lost", &outcome, &app.clock.now()).await;
            }
        }
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
            let _ = ask(app, &s.runner, ack, cfg.answer, None).await;
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
            elevated: Mutex::default(),
            leases: Mutex::default(),
        })
    }
}
