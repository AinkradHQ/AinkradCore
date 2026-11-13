//! `ainkrad.call {op, args, run?, key?}` (E2): runs one allow-listed, read-only operation for an
//! AI session through the existing client router, in process.
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
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::{Op, Risk, args, session_principal};
use crate::api::App;
use crate::api::v1::{Caller, Client};
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
                "key": {"type": "string", "maxLength": 64}
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
}

struct Flight<'a>(&'a CallState, String);

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

struct Limits {
    per_min: usize,
    run_calls: usize,
    run_wall: Duration,
    call_wall: Duration,
    concurrent: usize,
    max_args: usize,
    max_result: usize,
}

impl Limits {
    async fn read(app: &App) -> Result<Self, sqlx::Error> {
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
        })
    }
}

/// How a call ended: what the session gets, and what the audit row says.
struct Done {
    op: Option<(String, Risk)>,
    outcome: Result<Value, (&'static str, String)>,
    /// Refused before it ran: audited once per window, not per call.
    denied: bool,
}

fn deny(code: &'static str, msg: impl Into<String>, op: Option<&Op>) -> Done {
    Done {
        op: op.map(|o| (o.id.clone(), o.risk)),
        outcome: Err((code, msg.into())),
        denied: true,
    }
}

fn refuse(id: String, code: &str, message: &str) -> ToolResult {
    ToolResult {
        id,
        ok: false,
        result: None,
        code: Some(code.to_owned()),
        message: Some(message.to_owned()),
    }
}

/// A run id or key: `[A-Za-z0-9_.-]`, 1..=64.
fn plain_id(v: &Value) -> Result<Option<&str>, ()> {
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
    let done = origin::scope(origin.clone(), run(app, session, call)).await;
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let code = done.outcome.as_ref().err().map(|e| e.0);
    let audit = !done.denied
        || app.auth.refusals.note(
            &format!("code_mode {session} {}", code.unwrap_or("")),
            app.clock.unix(),
        );
    if audit {
        let (op, risk) = done.op.clone().unzip();
        let details = json!({"session": session, "op": op, "risk": risk.map(Risk::as_str),
            "outcome": if code.is_none() { "ok" } else if done.denied { "denied" } else { "error" },
            "code": code, "ms": ms,
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
    match done.outcome {
        Ok(result) => ToolResult {
            id,
            ok: true,
            result: Some(result),
            code: None,
            message: None,
        },
        Err((code, message)) => refuse(id, code, &message),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn run(app: &App, session: &str, call: &ToolCall) -> Done {
    let Ok(lim) = Limits::read(app).await else {
        return deny("unavailable", "try again", None);
    };
    let state = &app.code_mode;
    // 1. The session's rate: every call counts, refused or not.
    {
        let mut all = state.rate.lock().unwrap_or_else(|e| e.into_inner());
        let w = all.entry(session.to_owned()).or_default();
        let now = Instant::now();
        w.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if w.len() >= lim.per_min {
            return deny("rate_limited", "too many calls this minute", None);
        }
        w.push(now);
    }
    // 2. Shape and size.
    if call.args.to_string().len() > lim.max_args {
        return deny("args_too_large", "arguments too large", None);
    }
    let a = &call.args;
    let (Some(op_id), Ok(run_id), Ok(_key)) =
        (a["op"].as_str(), plain_id(&a["run"]), plain_id(&a["key"]))
    else {
        return deny(
            "bad_args",
            "op is a string; run and key are short plain ids",
            None,
        );
    };
    if a.as_object().is_some_and(|m| {
        m.keys()
            .any(|k| !["op", "args", "run", "key"].contains(&k.as_str()))
    }) {
        return deny("bad_args", "unknown field", None);
    }
    // 3. The operation: in the catalogue, read-only in this epic.
    let Some(op) = app.catalogue().ops.get(op_id) else {
        return deny("unknown_op", "no such operation; use ainkrad.search", None);
    };
    if op.risk != Risk::Read || op.method != "GET" {
        return deny(
            "not_available",
            "this operation cannot be called yet",
            Some(op),
        );
    }
    // 4. The principal, now: the creator's current scopes, never admin; the op's scope among them.
    let principal = match session_principal(&app.pool, session).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return deny(
                "creator_revoked",
                "this session may no longer call operations",
                Some(op),
            );
        }
        Err(_) => return deny("unavailable", "try again", Some(op)),
    };
    let method = Method::GET;
    let gate_scope = crate::api::v1::scopes::required(&method, &op.path, &app.modules);
    if gate_scope != Some(op.scope.as_str()) || !principal.scopes.contains(&op.scope) {
        return deny(
            "forbidden_scope",
            "this session's scopes do not allow that",
            Some(op),
        );
    }
    if crate::api::v1::scopes::destructive(&method, &op.path, &app.modules) {
        return deny(
            "not_available",
            "this operation cannot be called yet",
            Some(op),
        );
    }
    // 5. The arguments, before anything runs.
    let target = match args::target(op, &a["args"]) {
        Ok(t) => t,
        Err(why) => return deny("bad_args", why, Some(op)),
    };
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let path = target.split('?').next().unwrap_or("");
    let names_ok = query.split('&').filter(|p| !p.is_empty()).all(|p| {
        let n = p.split('=').next().unwrap_or(p);
        crate::api::v1::QUERY.contains(&n)
    }) || crate::api::v1::scopes::module_query_ok(&app.modules, path, query);
    if !names_ok {
        return deny("bad_args", "a query parameter is not allowed", Some(op));
    }
    // 6. The script run's budget.
    if let Some(run_id) = run_id {
        let mut runs = state.runs.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if runs.len() > 1024 {
            runs.retain(|_, (t, _)| now.duration_since(*t) < lim.run_wall);
        }
        let r = runs
            .entry((session.to_owned(), run_id.to_owned()))
            .or_insert((now, 0));
        if now.duration_since(r.0) > lim.run_wall {
            return deny("run_timeout", "this script ran out of time", Some(op));
        }
        if r.1 >= lim.run_calls {
            return deny(
                "too_many_calls",
                "this script made too many calls",
                Some(op),
            );
        }
        r.1 += 1;
    }
    // 7. Concurrency.
    let _flight = {
        let mut m = state.inflight.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(session.to_owned()).or_default();
        if *n >= lim.concurrent {
            return deny("busy", "too many calls running; wait for one", Some(op));
        }
        *n += 1;
        Flight(state, session.to_owned())
    };
    // 8. Through the router as the principal.
    let request = Request::builder()
        .method(method)
        .uri(&target)
        .header(header::HOST, &app.host)
        .extension(Caller {
            device: principal.device,
            session: format!("code_mode:{session}"),
        })
        .extension(Client("code_mode".to_owned()))
        .body(Body::empty());
    let Ok(request) = request else {
        return deny("bad_args", "not a valid target", Some(op));
    };
    let sent = tokio::time::timeout(
        lim.call_wall,
        crate::api::v1::router(app.clone()).oneshot(request),
    )
    .await;
    let op_ref = Some((op.id.clone(), op.risk));
    let fail = |code, msg: &str| Done {
        op: op_ref.clone(),
        outcome: Err((code, msg.to_owned())),
        denied: false,
    };
    let Ok(Ok(response)) = sent else {
        return fail("timeout", "the operation took too long");
    };
    let status = response.status();
    let Ok(bytes) = to_bytes(response.into_body(), 4 << 20).await else {
        return fail("result_too_large", "the result is too large to return");
    };
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status.is_success() {
        return Done {
            op: op_ref,
            outcome: Ok(cap(body, lim.max_result)),
            denied: false,
        };
    }
    let (code, msg) = refusal(status, &body);
    fail(code, &msg)
}

/// A stable refusal code for an API status, with the API's own code appended when it is a plain one.
fn refusal(status: StatusCode, body: &Value) -> (&'static str, String) {
    let code = match status.as_u16() {
        400 | 422 => "bad_args",
        401 | 403 => "forbidden_scope",
        404 => "not_found",
        409 => "conflict",
        429 => "rate_limited",
        500.. => "upstream_error",
        _ => "refused",
    };
    let api = body["code"]
        .as_str()
        .filter(|c| c.len() <= 48 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    (
        code,
        api.map_or_else(
            || format!("refused ({})", status.as_u16()),
            |c| format!("refused: {c}"),
        ),
    )
}

/// `v` as is, or a marker with the full size and a prefix when its JSON text is over `max`.
fn cap(v: Value, max: usize) -> Value {
    let text = v.to_string();
    if text.len() <= max {
        return v;
    }
    let mut cut = max.saturating_sub(256);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    json!({"truncated": true, "size": text.len(), "preview": &text[..cut]})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_over_the_cap_is_cut_and_marked_with_its_full_size() {
        let big = json!({"text": "é".repeat(5_000)});
        let size = big.to_string().len();
        let cut = cap(big, 1_024);
        assert_eq!(cut["truncated"], true);
        assert_eq!(cut["size"], size);
        assert!(cut.to_string().len() <= 2_048);
        let small = json!({"a": 1});
        assert_eq!(cap(small.clone(), 1_024), small);
    }

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
