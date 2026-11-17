//! The Leyline gate (Y4-01, plan T10): the ONE check every action that reaches a host passes.
//!
//! Security model.
//! - `authorize` / `authorize_many` are the only way to obtain an [`Authorized`]; its fields are
//!   private, so dispatch code that takes an `Authorized` cannot be written without going through
//!   here (see the `compile_fail` test below). A new route cannot skip the check.
//! - Who asks is a [`Principal`]: a person (a paired device, already checked by the request gate),
//!   an AI session (re-read from the Core on every call: live, creator not revoked), or
//!   `system:health` (probes only). Nothing a caller sends picks its principal.
//! - What a host allows an AI is its `ai_rule`, read from the store at the moment of the call:
//!   `read_only` = only pre-set commands flagged read-only, health, file list/read; `ask` = every
//!   action waits for a person through the Core's own approval (`ops_catalog::approval`, `cm_...`,
//!   decided with a live step-up); `allowed` = runs, audited. An unknown rule reads as `read_only`.
//! - Trust of a host key and Mac-direct are never available to an AI session or to health, and
//!   there is no action, and no op, that touches key material.
//! - One approval = one execution: it is bound to a hash of the operation, the hosts and the
//!   command, and spent (`consume`) before an `Authorized` exists. Denied, expired, ended, lost or
//!   already-spent approvals never run anything. A fleet with any `ask` host asks once for the run.
//! - Every call leaves a `leyline_runs` row, per-host rows and audit rows (origin = the principal).
//!   The command text is never in an audit row (a hash only); in the run row it is redacted + cut.
//!
//! ```compile_fail,E0451
//! // An `Authorized` cannot be made outside the gate.
//! let _ = leyline_module::gate::Authorized {
//!     run: String::new(),
//!     host: String::new(),
//!     principal: leyline_module::gate::Principal::Health,
//! };
//! ```

use std::time::Duration;

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, BY};
use ainkrad_core_server::ops_catalog::approval::{self, Outcome, Waiting};
use ainkrad_core_server::ops_catalog::session_principal;
use ainkrad_core_server::store::connections::access;
use ainkrad_core_server::store::{audit, begin_write, redact, settings};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

use crate::hosts::find;
pub use crate::policy::{Action, Principal};
use crate::policy::{Rule, Verdict, verdict};
use crate::valid::new_id;

/// Most hosts one fleet call may name.
const MAX_HOSTS: usize = 100;
/// Longest ad-hoc command kept on a run row.
const KEPT: usize = 2000;

/// Proof that the gate allowed this action on this host: one execution, then it is spent.
#[derive(Debug)]
pub struct Authorized {
    run: String,
    host: String,
    principal: Principal,
}

impl Authorized {
    pub fn run_id(&self) -> &str {
        &self.run
    }
    pub fn host_id(&self) -> &str {
        &self.host
    }
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
}

/// What a fleet call came to.
#[derive(Debug)]
pub struct Gated {
    pub run: String,
    pub authorized: Vec<Authorized>,
    /// Host id and a fixed reason.
    pub refused: Vec<(String, &'static str)>,
}

fn refuse(why: &'static str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "gate_refused", why)
}

/// One host. Any refusal (policy, session, or the person's "no") is an error.
///
/// # Errors
///
/// 404/409 for the host, 403 `gate_refused`, or a store failure.
pub async fn authorize(
    app: &App,
    who: &Principal,
    host: &str,
    action: &Action,
) -> Result<Authorized, ApiError> {
    let mut g = authorize_many(app, who, &[host], action).await?;
    match (g.authorized.pop(), g.refused.pop()) {
        (Some(a), _) => Ok(a),
        (None, Some((_, why))) => Err(refuse(why)),
        (None, None) => Err(refuse("not allowed")),
    }
}

/// Several hosts, one run, at most one approval (for every `ask` host together).
///
/// # Errors
///
/// An unknown or ambiguous host fails the whole call before anything is written; a store failure.
pub async fn authorize_many(
    app: &App,
    who: &Principal,
    hosts: &[&str],
    action: &Action,
) -> Result<Gated, ApiError> {
    if hosts.is_empty() || hosts.len() > MAX_HOSTS {
        return Err(ApiError::bad_request("name between 1 and 100 hosts"));
    }
    // The hosts, as they are NOW (id, label, rule).
    let mut found: Vec<(String, String, Rule)> = Vec::new();
    {
        let mut conn = app.pool.acquire().await?;
        for ident in hosts {
            let id = find(&mut conn, ident).await?;
            if found.iter().all(|h| h.0 != id) {
                found.push(host_row(&mut conn, id).await?);
            }
        }
    }
    // An AI session must be live with a usable creator; the runner it waits on is its own.
    let session_runner = match who {
        Principal::Session(s) => {
            let live = match access::load(&app.pool, s).await? {
                Some(a) if a.live => Some(a.runner),
                _ => None,
            };
            if session_principal(&app.pool, s).await?.is_none() {
                None
            } else {
                live
            }
        }
        _ => None,
    };
    let mut verdicts: Vec<Verdict> = found
        .iter()
        .map(|(.., rule)| {
            if matches!(who, Principal::Session(_)) && session_runner.is_none() {
                Verdict::Deny("this session may no longer act")
            } else {
                verdict(who, *rule, action)
            }
        })
        .collect();
    let asks = verdicts.contains(&Verdict::Ask);
    let run = new_id("lr_");
    let hash = op_hash(action, &found);
    write_run(app, who, &run, action, &found, &verdicts, &hash).await?;

    let mut approval_id = None;
    if asks {
        let (Principal::Session(session), Some(runner)) = (who, &session_runner) else {
            unreachable!("only an AI session is asked about");
        };
        let id = approval::new_id();
        let outcome = ask(
            app,
            (&id, session, runner),
            action,
            &found,
            &verdicts,
            &hash,
        )
        .await?;
        let by = match &outcome {
            Outcome::Approved(by) => Some(by.clone()),
            _ => None,
        };
        // One approval, one execution: spent before anything is authorized.
        let spent = by.is_some() && approval::consume(&app.pool, &id, session, &hash).await?;
        let why = match (&outcome, spent) {
            (Outcome::Approved(_), true) => None,
            (Outcome::Approved(_), false) => Some("approval already used"),
            (Outcome::Denied, _) => Some("the person said no"),
            (Outcome::Timeout, _) => Some("nobody answered in time"),
            (Outcome::Ended, _) => Some("the session ended while it waited"),
        };
        for v in &mut verdicts {
            if *v == Verdict::Ask {
                *v = why.map_or(Verdict::Allow, Verdict::Deny);
            }
        }
        let mut tx = begin_write(&app.pool).await?;
        let details = json!({"run": run, "approval": id, "approved": why.is_none(),
            "by": by, "outcome": why.unwrap_or("approved")});
        note(&mut tx, who, "leyline.run.approval", &details).await?;
        tx.commit().await?;
        approval_id = Some(id);
    }
    settle(app, who, &run, &found, &verdicts, approval_id.as_deref()).await
}

async fn host_row(
    conn: &mut SqliteConnection,
    id: String,
) -> Result<(String, String, Rule), ApiError> {
    let (name, rule): (String, String) =
        sqlx::query_as("SELECT name, ai_rule FROM leyline_hosts WHERE id = ?")
            .bind(&id)
            .fetch_one(conn)
            .await?;
    Ok((id, name, Rule::of(&rule)))
}

/// Binds an approval to exactly this operation, these hosts and this command.
fn op_hash(action: &Action, hosts: &[(String, String, Rule)]) -> String {
    let mut ids: Vec<&str> = hosts.iter().map(|h| h.0.as_str()).collect();
    ids.sort_unstable();
    let doc = json!({"op": action.op(), "detail": action.detail(), "hosts": ids});
    Sha256::digest(doc.to_string().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn note(
    conn: &mut SqliteConnection,
    who: &Principal,
    action: &str,
    details: &Value,
) -> Result<(), ApiError> {
    let row = NewAuditEvent {
        actor: BY,
        action: action.to_owned(),
        entity: None,
        details: details.to_string(),
    };
    audit::append_as(conn, &row, who.origin())
        .await
        .map_err(|e| ApiError::from(sqlx::Error::Protocol(e.to_string())))?;
    Ok(())
}

/// The run and its host rows, before anything waits: a refused or parked call leaves a trace too.
async fn write_run(
    app: &App,
    who: &Principal,
    run: &str,
    action: &Action,
    hosts: &[(String, String, Rule)],
    verdicts: &[Verdict],
    hash: &str,
) -> Result<(), ApiError> {
    let ask = verdicts.contains(&Verdict::Ask);
    let any = verdicts.contains(&Verdict::Allow);
    let state = if ask {
        "waiting_approval"
    } else if any {
        "running"
    } else {
        "denied"
    };
    let (command_id, adhoc) = match action {
        Action::Preset { id, .. } => (Some(id.clone()), None),
        Action::Exec(c) => (None, Some(cut(&redact::text(c)))),
        _ => (None, None),
    };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "INSERT INTO leyline_runs (id, command_id, adhoc, action, principal, state) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(run)
    .bind(command_id)
    .bind(adhoc)
    .bind(action.op())
    .bind(who.label())
    .bind(state)
    .execute(&mut *tx)
    .await?;
    for ((id, ..), v) in hosts.iter().zip(verdicts) {
        let s = match v {
            Verdict::Allow => "queued",
            Verdict::Ask => "needs_approval",
            Verdict::Deny(_) => "refused",
        };
        sqlx::query("INSERT INTO leyline_run_hosts (run_id, host_id, state) VALUES (?, ?, ?)")
            .bind(run)
            .bind(id)
            .bind(s)
            .execute(&mut *tx)
            .await?;
    }
    let ids: Vec<&str> = hosts.iter().map(|h| h.0.as_str()).collect();
    let details = json!({"run": run, "op": action.op(), "principal": who.label(), "hosts": ids,
        "command_sha256": hash});
    note(&mut tx, who, "leyline.run.requested", &details).await?;
    tx.commit().await?;
    Ok(())
}

fn cut(s: &str) -> String {
    s.chars().take(KEPT).collect()
}

/// Parks the approval of the `ask` hosts and waits for the person.
async fn ask(
    app: &App,
    (id, session, runner): (&str, &str, &str),
    action: &Action,
    hosts: &[(String, String, Rule)],
    verdicts: &[Verdict],
    hash: &str,
) -> Result<Outcome, ApiError> {
    let names: Vec<&str> = hosts
        .iter()
        .zip(verdicts)
        .filter(|(_, v)| **v == Verdict::Ask)
        .map(|(h, _)| h.1.as_str())
        .collect();
    let args = json!({"hosts": names, "detail": action.detail()});
    let summary = format!("Run {} on {} host(s).", action.op(), names.len());
    let secs = settings::value(&app.pool, Key::CodeModeApprovalSecs, Scope::Server)
        .await
        .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
    let ttl = u64::try_from(secs).unwrap_or(0);
    let waiting = Waiting::new(&app.code_mode, id);
    approval::create(
        app,
        (id, session),
        (
            action.op(),
            &summary,
            &args,
            "It reaches a host: it runs only if you allow it, once.",
        ),
        hash,
        i64::try_from(ttl).unwrap_or(0),
    )
    .await?;
    let out = approval::wait(
        app,
        &waiting,
        (id, session, runner),
        Duration::from_secs(ttl),
    )
    .await?;
    Ok(out)
}

/// Final states, the `Authorized` values, the audit row.
async fn settle(
    app: &App,
    who: &Principal,
    run: &str,
    hosts: &[(String, String, Rule)],
    verdicts: &[Verdict],
    approval_id: Option<&str>,
) -> Result<Gated, ApiError> {
    let mut authorized = Vec::new();
    let mut refused = Vec::new();
    let mut tx = begin_write(&app.pool).await?;
    for ((id, ..), v) in hosts.iter().zip(verdicts) {
        match v {
            Verdict::Allow => authorized.push(Authorized {
                run: run.to_owned(),
                host: id.clone(),
                principal: who.clone(),
            }),
            Verdict::Deny(why) => refused.push((id.clone(), *why)),
            Verdict::Ask => unreachable!("every ask is decided before settling"),
        }
    }
    for (id, _) in &refused {
        sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'refused' WHERE run_id = ? AND host_id = ?",
        )
        .bind(run)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    for a in &authorized {
        sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'queued' WHERE run_id = ? AND host_id = ? AND state = 'needs_approval'",
        )
        .bind(run)
        .bind(&a.host)
        .execute(&mut *tx)
        .await?;
    }
    let state = if authorized.is_empty() {
        "denied"
    } else {
        "running"
    };
    sqlx::query(
        "UPDATE leyline_runs SET state = ?, approval = ?, \
         ended_at = CASE WHEN ? = 'denied' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END WHERE id = ?",
    )
    .bind(state)
    .bind(approval_id)
    .bind(state)
    .bind(run)
    .execute(&mut *tx)
    .await?;
    let reasons: Vec<Value> = refused
        .iter()
        .map(|(h, w)| json!({"host": h, "why": w}))
        .collect();
    if !refused.is_empty() {
        note(
            &mut tx,
            who,
            "leyline.run.refused",
            &json!({"run": run, "refused": reasons}),
        )
        .await?;
    }
    if !authorized.is_empty() {
        let ids: Vec<&str> = authorized.iter().map(|a| a.host.as_str()).collect();
        note(
            &mut tx,
            who,
            "leyline.run.allowed",
            &json!({"run": run, "hosts": ids, "approval": approval_id}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Gated {
        run: run.to_owned(),
        authorized,
        refused,
    })
}

/// The host's execution ended: spends the `Authorized`, and closes the run with its last host.
///
/// # Errors
///
/// A store failure.
pub async fn finish(app: &App, done: Authorized, ok: bool) -> Result<(), ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE leyline_run_hosts SET state = ? WHERE run_id = ? AND host_id = ? AND state = 'queued'",
    )
    .bind(if ok { "ok" } else { "failed" })
    .bind(&done.run)
    .bind(&done.host)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE leyline_runs SET state = 'done', ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE id = ? AND state = 'running' AND NOT EXISTS \
         (SELECT 1 FROM leyline_run_hosts WHERE run_id = ? AND state IN ('queued', 'running', 'needs_approval'))",
    )
    .bind(&done.run)
    .bind(&done.run)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
