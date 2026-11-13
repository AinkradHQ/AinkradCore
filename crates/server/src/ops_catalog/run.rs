//! The checks and the execution of one `ainkrad.call` (E2, E6). Order, each step refusing with a
//! plain code before the next: rate, shape, the operation and its risk class, the principal's
//! scopes, the arguments, the script's budget; then for a write the idempotency claim, for a
//! risky one the person's approval and the scope check AGAIN, then concurrency and the router.
//!
//! Risk classes: `read` is a GET. `write` is reversible and inside the Core: it runs within the
//! session's scopes. `risky` is destructive or reaches outside the Core (a connection write, a
//! delete): it never reaches the handler without an approval a person gave through
//! `decideAgentApproval` (scope `approve`, live step-up, checked by the gate), single use and bound
//! to the call's arguments. A route that needs a step-up itself is reachable only as `risky`: the
//! approver's step-up stands for it, since a session has none.

use std::time::{Duration, Instant};

use ainkrad_proto::v2::ToolCall;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::approval::{self, Outcome, Waiting};
use super::call::{Done, Limits, deny, plain_id};
use super::idem::{self, Begin, Live};
use super::{Op, Risk, args, session_principal};
use crate::api::App;
use crate::api::v1::{Caller, Client};

/// A flag: absent or null is false.
fn flag(v: &Value) -> Result<bool, ()> {
    match v {
        Value::Null => Ok(false),
        Value::Bool(b) => Ok(*b),
        _ => Err(()),
    }
}

pub(super) async fn run(app: &App, (runner, session): (&str, &str), call: &ToolCall) -> Done {
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
    let (Some(op_id), Ok(run_id), Ok(key), Ok(repeat)) = (
        a["op"].as_str(),
        plain_id(&a["run"]),
        plain_id(&a["key"]),
        flag(&a["repeat"]),
    ) else {
        return deny(
            "bad_args",
            "op is a string; run and key are short plain ids; repeat is true or false",
            None,
        );
    };
    if a.as_object().is_some_and(|m| {
        m.keys()
            .any(|k| !["op", "args", "run", "key", "repeat"].contains(&k.as_str()))
    }) {
        return deny("bad_args", "unknown field", None);
    }
    // 3a. A connection operation (E5): the session's grants and the broker decide, not the scopes.
    if op_id.starts_with(super::conn::PREFIX) {
        return super::call::connection(app, runner, session, call, op_id, run_id, &lim).await;
    }
    // 3. The operation: in the catalogue, its method agreeing with its class.
    let Some(op) = app.catalogue().ops.get(op_id) else {
        return deny("unknown_op", "no such operation; use ainkrad.search", None);
    };
    let Ok(method) = Method::from_bytes(op.method.as_bytes()) else {
        return deny("not_available", "this operation cannot be called", Some(op));
    };
    if (op.risk == Risk::Read) != (method == Method::GET) || !super::exposed(&op.path) {
        return deny("not_available", "this operation cannot be called", Some(op));
    }
    // 4. The principal, now: the creator's current scopes, never admin; the op's scope among them.
    if let Err(d) = authorize(app, session, op, &method).await {
        return d;
    }
    // 5. The arguments, before anything runs.
    let (target, body) = match args::request(op, &a["args"]) {
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
    let req = Req {
        runner,
        session,
        run_id,
        target,
        body,
    };
    if op.risk == Risk::Read {
        return send(app, op, &req, &lim, &method).await;
    }
    // 7. A write: claimed once per key (a retried script never writes twice).
    let hash = idem::key_hash(session, &op.id, &a["args"], key);
    let began = idem::begin(
        &app.pool,
        state,
        (session, &hash, &op.id),
        (app.clock.unix(), lim.idem_window),
        repeat,
    )
    .await;
    match began {
        Ok(Begin::Fresh) => {}
        Ok(Begin::Replay(first)) => {
            return Done {
                op: Some((op.id.clone(), op.risk)),
                outcome: Ok(json!({"replayed": true, "result": first})),
                denied: false,
                approval: None,
                replayed: true,
            };
        }
        Ok(Begin::Busy) => return deny("busy", "this write is running now", Some(op)),
        Ok(Begin::Unknown) => {
            return deny(
                "outcome_unknown",
                "an earlier try of this write did not finish and may have taken effect; \
                 repeat:true sends it again",
                Some(op),
            );
        }
        Ok(Begin::Conflict) => {
            return deny(
                "key_reused",
                "that key was used for another operation",
                Some(op),
            );
        }
        Err(_) => return deny("unavailable", "try again", Some(op)),
    }
    let _live = Live::new(state, session, &hash);
    let mut done = guarded(app, op, &req, &lim, (&method, &hash, &a["args"])).await;
    // The claim stays only for a write that took effect, or whose effect is unknown (a timeout).
    match &done.outcome {
        Ok(v) => {
            if idem::finish(&app.pool, session, &hash, v).await.is_err() {
                tracing::error!(session, "recording a write's result failed");
            }
        }
        Err((code, _)) if code == "timeout" => {}
        Err(_) => idem::forget(&app.pool, session, &hash).await,
    }
    done.replayed = false;
    done
}

/// The call's request, once it is checked.
struct Req<'a> {
    runner: &'a str,
    session: &'a str,
    run_id: Option<&'a str>,
    target: String,
    body: Option<Vec<u8>>,
}

/// The principal of `session` as it is NOW, its scopes holding the op's, and its route allowed to
/// it: a route that needs a step-up only as `risky` (the approver's stands for it).
async fn authorize(app: &App, session: &str, op: &Op, method: &Method) -> Result<(), Done> {
    let principal = match session_principal(&app.pool, session).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(deny(
                "creator_revoked",
                "this session may no longer call operations",
                Some(op),
            ));
        }
        Err(_) => return Err(deny("unavailable", "try again", Some(op))),
    };
    let gate_scope = crate::api::v1::scopes::required(method, &op.path, &app.modules);
    if gate_scope != Some(op.scope.as_str()) || !principal.scopes.contains(&op.scope) {
        return Err(deny(
            "forbidden_scope",
            "this session's scopes do not allow that",
            Some(op),
        ));
    }
    if op.risk != Risk::Risky && crate::api::v1::scopes::destructive(method, &op.path, &app.modules)
    {
        return Err(deny(
            "not_available",
            "this operation cannot be called without an approval",
            Some(op),
        ));
    }
    Ok(())
}

/// A risky write waits for its approval, a plain one goes on.
async fn guarded(
    app: &App,
    op: &Op,
    req: &Req<'_>,
    lim: &Limits,
    (method, hash, args): (&Method, &str, &Value),
) -> Done {
    if op.risk != Risk::Risky {
        return send(app, op, req, lim, method).await;
    }
    let reason = if crate::api::v1::scopes::destructive(method, &op.path, &app.modules) {
        "It can change or remove things that are hard to get back."
    } else {
        "It acts outside the Core."
    };
    let id = approval::new_id();
    let waiting = Waiting::new(&app.code_mode, &id);
    let ttl = i64::try_from(lim.approval.as_secs()).unwrap_or(0);
    let made = approval::create(
        app,
        (&id, req.session),
        (&op.id, &op.summary, args, reason),
        hash,
        ttl,
    )
    .await;
    if made.is_err() {
        return deny("unavailable", "try again", Some(op));
    }
    let asked = Instant::now();
    let outcome = approval::wait(app, &waiting, (&id, req.session, req.runner), lim.approval).await;
    drop(waiting);
    // The wait is not the script's time: its run window moves by as much.
    if let Some(run_id) = req.run_id {
        let mut runs = app.code_mode.runs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = runs.get_mut(&(req.session.to_owned(), run_id.to_owned())) {
            r.0 += asked.elapsed();
        }
    }
    let marked = |by: Option<&str>| Some(json!({"request": id, "by": by}));
    let refused = |code: &'static str, msg: &str, by: Option<&str>| Done {
        op: Some((op.id.clone(), op.risk)),
        outcome: Err((code.to_owned(), msg.to_owned())),
        // A person's answer (or silence) is always audited, not once per window.
        denied: false,
        approval: marked(by),
        replayed: false,
    };
    let by = match outcome {
        Ok(Outcome::Approved(by)) => by,
        Ok(Outcome::Denied) => return refused("approval_denied", "a person denied this", None),
        Ok(Outcome::Timeout) => {
            return refused("approval_timeout", "nobody answered in time", None);
        }
        Ok(Outcome::Ended) => return refused("session_ended", "the session ended", None),
        Err(_) => return deny("unavailable", "try again", Some(op)),
    };
    // At execution time, not at queue time: the scope may have been taken away while it waited.
    if let Err(mut d) = authorize(app, req.session, op, method).await {
        d.approval = marked(Some(&by));
        d.denied = false;
        return d;
    }
    match approval::consume(&app.pool, &id, req.session, hash).await {
        Ok(true) => {}
        _ => {
            return refused(
                "approval_used",
                "this approval was already spent",
                Some(&by),
            );
        }
    }
    let mut done = send(app, op, req, lim, method).await;
    done.approval = marked(Some(&by));
    done
}

/// Concurrency, then the router as the principal.
async fn send(app: &App, op: &Op, req: &Req<'_>, lim: &Limits, method: &Method) -> Done {
    let state = &app.code_mode;
    let session = req.session;
    let flight = {
        let mut m = state.inflight.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(session.to_owned()).or_default();
        if *n >= lim.concurrent {
            return deny("busy", "too many calls running; wait for one", Some(op));
        }
        *n += 1;
        super::call::Flight::new(state, session)
    };
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
    let mut request = Request::builder()
        .method(method.clone())
        .uri(&req.target)
        .header(header::HOST, &app.host)
        .extension(Caller {
            device: principal.device,
            session: format!("code_mode:{session}"),
        })
        .extension(Client("code_mode".to_owned()));
    if req.body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request.body(Body::from(req.body.clone().unwrap_or_default()));
    let Ok(request) = request else {
        return deny("bad_args", "not a valid target", Some(op));
    };
    let sent = tokio::time::timeout(
        lim.call_wall,
        crate::api::v1::router(app.clone()).oneshot(request),
    )
    .await;
    drop(flight);
    let fail = |code: &str, msg: &str| Done {
        op: Some((op.id.clone(), op.risk)),
        outcome: Err((code.to_owned(), msg.to_owned())),
        denied: false,
        approval: None,
        replayed: false,
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
            op: Some((op.id.clone(), op.risk)),
            outcome: Ok(cap(body, lim.max_result)),
            denied: false,
            approval: None,
            replayed: false,
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
pub(super) fn cap(v: Value, max: usize) -> Value {
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
    fn a_flag_is_true_false_or_absent() {
        assert_eq!(flag(&Value::Null), Ok(false));
        assert_eq!(flag(&json!(true)), Ok(true));
        assert!(flag(&json!("yes")).is_err());
    }
}
