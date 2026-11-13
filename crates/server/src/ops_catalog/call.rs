//! `ainkrad.call {op, args, run?, key?, repeat?, wait_ms?}` (E2, E6, E6.5): runs one allow-listed operation for an
//! AI session through the existing client router, in process. A `write` runs inside the session's
//! scopes at most once per key; a `risky` one also waits for a person (see `run`).
//!
//! **The principal.** A session has no device key. Its call acts as its CREATOR device, read from
//! the store on EVERY call, with scopes = that device's current scopes minus `admin` (never
//! granted), and only for an operation whose scope is among them. The router itself carries no
//! scope check (the signed-request gate in front of it does), so this module repeats the gate's
//! scope and step-up rules and never skips them: signature verification is untouched, a session
//! simply never reaches it. A revoked creator, an ended session or a scope taken away refuses the
//! very next call.
//!
//! **Audit.** The call runs under `ai_session` origin with the session's chain root; each call
//! that was allowed to run writes one `code_mode.call` row (op, risk, outcome, time, a hash of
//! the arguments; never an argument or result body). A call refused before it ran is audited once
//! per refusal code per session per window, like the broker's rate floods.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core::ids::UserId;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::{ConnTool, ToolCall, ToolResult};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Op, Risk};
use crate::api::App;
use crate::store::audit::origin;
use crate::store::connections::access;

pub const CALL: &str = "ainkrad.call";

/// The tool entry the runner's script engine and CLI call (E3); not listed to the harness itself.
pub fn call_tool() -> ConnTool {
    ConnTool {
        name: CALL.to_owned(),
        description: "Run one Ainkrad operation found with ainkrad.search.".to_owned(),
        write: false,
        input_schema: Some(json!({
            "type": "object",
            "properties": {
                "op": {"type": "string", "maxLength": 64},
                "args": {"type": "object"},
                "run": {"type": "string", "maxLength": 64},
                "key": {"type": "string", "maxLength": 64},
                "repeat": {"type": "boolean"},
                "wait_ms": {"type": "integer", "minimum": 0}
            },
            "required": ["op"],
            "additionalProperties": false
        })),
    }
}

/// What the dispatcher remembers between calls, in memory (a restart starts every window empty).
#[derive(Default)]
pub struct CallState {
    /// Call times per session, for the per-minute rate.
    pub(crate) rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// `(session, run)` -> (first call, calls so far).
    pub(crate) runs: Mutex<HashMap<(String, String), (Instant, usize)>>,
    /// Calls running now, per session.
    pub(crate) inflight: Mutex<HashMap<String, usize>>,
    /// Risky calls parked for a person, by request id; the decision wakes them (E6.2).
    pub(crate) waiting: Mutex<HashMap<String, std::sync::Arc<tokio::sync::Notify>>>,
    /// Writes running now, `(session, key hash)`: tells a retry "busy" from "outcome unknown".
    pub(crate) idem: Mutex<std::collections::HashSet<(String, String)>>,
}

pub(super) struct Flight<'a>(&'a CallState, String);

impl<'a> Flight<'a> {
    /// A place already taken in `inflight`, given back when this is dropped.
    pub fn new(state: &'a CallState, session: &str) -> Self {
        Self(state, session.to_owned())
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut m = self.0.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

pub(super) struct Limits {
    pub per_min: usize,
    pub run_calls: usize,
    pub run_wall: Duration,
    pub call_wall: Duration,
    pub concurrent: usize,
    pub max_args: usize,
    pub max_result: usize,
    pub approval: Duration,
    pub idem_window: i64,
}

impl Limits {
    pub async fn read(app: &App) -> Result<Self, sqlx::Error> {
        let v = |k| async move { crate::store::settings::value(&app.pool, k, Scope::Server).await };
        let n = |x: i64| usize::try_from(x).unwrap_or(0);
        let s = |x: i64| Duration::from_secs(u64::try_from(x).unwrap_or(0));
        Ok(Self {
            per_min: n(v(Key::CodeModeCallsPerMin).await?),
            run_calls: n(v(Key::CodeModeMaxRunCalls).await?),
            run_wall: s(v(Key::CodeModeRunSecs).await?),
            call_wall: s(v(Key::CodeModeCallSecs).await?),
            concurrent: n(v(Key::CodeModeConcurrent).await?),
            max_args: n(v(Key::CodeModeMaxArgsBytes).await?),
            max_result: n(v(Key::CodeModeMaxResultBytes).await?),
            approval: s(v(Key::CodeModeApprovalSecs).await?),
            idem_window: v(Key::CodeModeIdemSecs).await?,
        })
    }
}

/// How a call ended: what the session gets, and what the audit row says.
pub(super) struct Done {
    pub op: Option<(String, Risk)>,
    pub outcome: Result<Value, (String, String)>,
    /// Refused before it ran: audited once per window, not per call.
    pub denied: bool,
    /// The Core-held approval of a risky call: its request id, and who allowed it once decided.
    pub approval: Option<Value>,
    /// The first result of a write sent again, not a new run.
    pub replayed: bool,
}

pub(super) fn deny(code: &'static str, msg: impl Into<String>, op: Option<&Op>) -> Done {
    Done {
        op: op.map(|o| (o.id.clone(), o.risk)),
        outcome: Err((code.to_owned(), msg.into())),
        denied: true,
        approval: None,
        replayed: false,
    }
}

fn refuse(id: String, code: &str, message: &str) -> ToolResult {
    ToolResult {
        approval: None,
        id,
        ok: false,
        result: None,
        code: Some(code.to_owned()),
        message: Some(message.to_owned()),
    }
}

/// A run id or key: `[A-Za-z0-9_.-]`, 1..=64.
pub(super) fn plain_id(v: &Value) -> Result<Option<&str>, ()> {
    match v {
        Value::Null => Ok(None),
        Value::String(s)
            if (1..=64).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) =>
        {
            Ok(Some(s))
        }
        _ => Err(()),
    }
}

/// The `ainkrad.call` of `runner` for `session`.
pub async fn call_call(app: &App, runner: &str, session: &str, call: &ToolCall) -> ToolResult {
    let id = call.id.clone();
    let acc = match access::load(&app.pool, session).await {
        Ok(Some(a)) if a.live && a.runner == runner => a,
        Ok(_) => return refuse(id, "unknown_session", "no live session of yours"),
        Err(_) => return refuse(id, "unavailable", "try again"),
    };
    let origin = {
        let Ok(mut conn) = app.pool.acquire().await else {
            return refuse(id, "unavailable", "try again");
        };
        crate::store::agents::session_origin(&mut conn, Ok(session)).await
    };
    let Some(origin) = origin else {
        return refuse(id, "unknown_session", "no live session of yours");
    };
    let started = Instant::now();
    let done = origin::scope(
        origin.clone(),
        super::run::run(app, (runner, session), call),
    )
    .await;
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let code = done.outcome.as_ref().err().map(|e| e.0.as_str());
    let audit = !done.denied
        || app.auth.refusals.note(
            &format!("code_mode {session} {}", code.unwrap_or("")),
            app.clock.unix(),
        );
    if audit {
        let (op, risk) = done.op.clone().unzip();
        let project = super::session_project(&app.pool, session).await;
        let details = json!({"session": session, "project": project, "op": op, "risk": risk.map(Risk::as_str),
            "outcome": if code.is_none() { "ok" } else if done.denied { "denied" } else { "error" },
            "code": code, "ms": ms, "approval": done.approval, "replayed": done.replayed,
            "args_sha256": hex(&Sha256::digest(call.args.to_string().as_bytes()))});
        let event = NewAuditEvent {
            actor: AuditActor::User(UserId(acc.user)),
            action: "code_mode.call".to_owned(),
            entity: None,
            details: details.to_string(),
        };
        let written = async {
            let mut tx = crate::store::begin_write(&app.pool).await?;
            crate::store::audit::append_as(&mut tx, &event, origin).await?;
            tx.commit().await
        };
        if let Err(e) = written.await {
            tracing::error!(error = %e, "auditing a code mode call failed");
            return refuse(id, "unavailable", "try again");
        }
    }
    // The script is told which of its calls waited for a person (E6.5), never who answered.
    let approval = done
        .approval
        .as_ref()
        .and_then(|a| a["request"].as_str())
        .map(str::to_owned);
    let mut r = match done.outcome {
        Ok(result) => ToolResult {
            approval: None,
            id,
            ok: true,
            result: Some(result),
            code: None,
            message: None,
        },
        Err((code, message)) => refuse(id, &code, &message),
    };
    r.approval = approval;
    r
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The script run's call and time budget (`run_id` None: no run, no budget).
pub(super) fn budget(
    state: &CallState,
    lim: &Limits,
    session: &str,
    run_id: Option<&str>,
    op: Option<&Op>,
) -> Result<(), Done> {
    let Some(run_id) = run_id else { return Ok(()) };
    let mut runs = state.runs.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if runs.len() > 1024 {
        runs.retain(|_, (t, _)| now.duration_since(*t) < lim.run_wall);
    }
    let r = runs
        .entry((session.to_owned(), run_id.to_owned()))
        .or_insert((now, 0));
    if now.duration_since(r.0) > lim.run_wall {
        return Err(deny("run_timeout", "this script ran out of time", op));
    }
    if r.1 >= lim.run_calls {
        return Err(deny(
            "too_many_calls",
            "this script made too many calls",
            op,
        ));
    }
    r.1 += 1;
    Ok(())
}

/// One in-flight slot of `session`, or `busy`.
pub(super) fn flight<'a>(
    state: &'a CallState,
    lim: &Limits,
    session: &str,
    op: Option<&Op>,
) -> Result<Flight<'a>, Done> {
    let mut m = state.inflight.lock().unwrap_or_else(|e| e.into_inner());
    let n = m.entry(session.to_owned()).or_default();
    if *n >= lim.concurrent {
        return Err(deny("busy", "too many calls running; wait for one", op));
    }
    *n += 1;
    Ok(Flight::new(state, session))
}

/// A `connections.<kind>.<op>` call (E5), through the broker.
pub(super) async fn connection(
    app: &App,
    runner: &str,
    session: &str,
    call: &ToolCall,
    op_id: &str,
    run_id: Option<&str>,
    lim: &Limits,
) -> Done {
    use super::conn::{Ran, run as conn_run};
    let state = &app.code_mode;
    if let Err(d) = budget(state, lim, session, run_id, None) {
        return d;
    }
    let _flight = match flight(state, lim, session, None) {
        Ok(f) => f,
        Err(d) => return d,
    };
    let now = app.clock.now();
    let env = crate::connections::broker::Env {
        pool: &app.pool,
        sealer: app.secrets.as_ref(),
        now: &now,
    };
    let sent = tokio::time::timeout(
        lim.call_wall,
        conn_run(
            &app.connections,
            &env,
            runner,
            session,
            op_id,
            &call.args["args"],
            call,
        ),
    )
    .await;
    match sent {
        Err(_) => deny("timeout", "the operation took too long", None),
        Ok(Err(_)) => deny("unavailable", "try again", None),
        Ok(Ok(Ran::Unknown)) => deny("unknown_op", "no such operation; use ainkrad.search", None),
        Ok(Ok(Ran::NotRead(op))) => deny(
            "not_available",
            "this operation cannot be called yet",
            Some(&op),
        ),
        Ok(Ok(Ran::Done(op, r))) => Done {
            op: Some((op.id, op.risk)),
            outcome: match (r.ok, r.result) {
                (true, Some(v)) => Ok(super::run::cap(v, lim.max_result)),
                _ => Err((
                    r.code.unwrap_or_else(|| "refused".to_owned()),
                    r.message.unwrap_or_default(),
                )),
            },
            denied: false,
            approval: None,
            replayed: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_and_key_ids_are_short_and_plain() {
        assert_eq!(plain_id(&json!("run-1.a_b")), Ok(Some("run-1.a_b")));
        assert_eq!(plain_id(&Value::Null), Ok(None));
        for bad in [
            json!(""),
            json!("a b"),
            json!("../x"),
            json!("x".repeat(65)),
            json!(5),
        ] {
            assert!(plain_id(&bad).is_err(), "{bad}");
        }
    }
}
