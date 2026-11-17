//! The Leyline gate (Y4-01, plan T10): the ONE check every action that reaches a host passes.
//!
//! Security model.
//! - `authorize` / `authorize_many` are the only way to obtain an [`Authorized`]; its fields are
//!   private, so dispatch code that takes an `Authorized` cannot be written without going through
//!   here (see the `compile_fail` test below). A new route cannot skip the check.
//! - Who asks is a [`Principal`], built only by [`Principal::of`] from the authenticated request
//!   (a `code_mode:` session is an AI session, else the person behind the device) or, for the
//!   health prober, inside this module. An AI session is re-read from the Core on every call
//!   (live, creator not revoked). Nothing a caller sends picks its principal.
//! - What a host allows an AI is its `ai_rule`, read from the store at the moment of the call:
//!   `read_only` = only pre-set commands flagged read-only, health, file list/read; `ask` = every
//!   action waits for a person through the Core's own approval (`ops_catalog` approval, `cm_...`,
//!   decided with a live step-up); `allowed` = runs, audited. An unknown rule reads as `read_only`.
//! - Trust of a host key and Mac-direct are never available to an AI session or to health, and
//!   there is no action, and no op, that touches key material.
//! - One approval = one execution: it is bound to a hash of the operation, the command and, per
//!   host, its rule and its whole connection tuple (address, port, user, key, jump chain, runner).
//!   After the person answers the hosts are read again and the hash recomputed: a host that
//!   changed or went away while the call waited refuses the call. The approval is spent
//!   (`consume`) before an `Authorized` exists. Denied, expired, ended, lost, already-spent or
//!   stale approvals never run anything. A fleet with any `ask` host asks once for the run.
//! - The approval card is shown whole or not at all: a command, path or host list the card would
//!   have to cut or redact is refused before anything is parked.
//! - An `Authorized` carries the action and its hash: dispatch takes the command from it, never
//!   from the caller again. A run left waiting (error, cancelled call) is marked `cancelled`.
//! - Every call leaves a `leyline_runs` row, per-host rows and audit rows (origin = the principal).
//!   The command text is never in an audit row (a hash only); in the run row it is redacted + cut.
//!
//! ```compile_fail,E0451
//! // An `Authorized` cannot be made outside the gate.
//! let _ = leyline_module::gate::Authorized {
//!     run: String::new(),
//!     host: String::new(),
//!     action: leyline_module::gate::Action::Terminal,
//!     op_sha256: String::new(),
//!     principal: leyline_module::gate::Principal::health(),
//! };
//! ```

use std::time::Duration;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::ops_catalog::{
    Outcome, Waiting, consume_approval, create_approval, new_approval_id, session_principal,
    void_approval, wait_approval,
};
use ainkrad_core_server::store::connections::access;
use ainkrad_core_server::store::{begin_write, settings};
use axum::http::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};

use crate::hosts::find;
pub use crate::policy::{Action, Principal};
use crate::policy::{Rule, Verdict, Who, verdict};
use crate::valid::new_id;

#[path = "runs.rs"]
mod runs;
pub use runs::finish;
use runs::{Parked, cancel, note, redacted, settle, write_run};

/// Most hosts one fleet call may name.
const MAX_HOSTS: usize = 100;
/// Longest detail kept on a run row.
const KEPT: usize = 2000;
/// What an approval card shows whole: one text, and all of it together.
const CARD_TEXT: usize = 200;
const CARD_ALL: usize = 2000;

/// Proof that the gate allowed this action on this host: one execution, then it is spent.
#[derive(Debug)]
pub struct Authorized {
    run: String,
    host: String,
    action: Action,
    /// The hash the gate decided (and, if asked, the person approved) on.
    op_sha256: String,
    principal: Principal,
}

impl Authorized {
    pub fn action(&self) -> &Action {
        &self.action
    }
    pub fn op_sha256(&self) -> &str {
        &self.op_sha256
    }
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
    // The hosts, as they are NOW.
    let mut found: Vec<H> = Vec::new();
    {
        let mut conn = app.pool.acquire().await?;
        for ident in hosts {
            let id = find(&mut conn, ident).await?;
            if found.iter().all(|h| h.id != id) {
                found.push(host_row(&mut conn, &id).await?.ok_or_else(gone)?);
            }
        }
    }
    // An AI session must be live with a usable creator; the runner it waits on is its own.
    let session_runner = match &who.0 {
        Who::Session(s) => {
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
    let is_ai = matches!(who.0, Who::Session(_));
    let verdicts: Vec<Verdict> = found
        .iter()
        .map(|h| {
            if is_ai && session_runner.is_none() {
                Verdict::Deny("this session may no longer act")
            } else {
                verdict(who, h.rule, action)
            }
        })
        .collect();
    let run = new_id("lr_");
    let hash = op_hash(action, &found);
    write_run(app, who, &run, action, &found, &verdicts, &hash).await?;
    // From here a run that never settles is cancelled, not left waiting forever.
    let mut guard = Parked {
        pool: app.pool.clone(),
        run: run.clone(),
        armed: true,
    };
    let called = Call {
        who,
        run: &run,
        action,
        hash,
        runner: session_runner,
    };
    match park_and_settle(app, &called, &found, verdicts).await {
        Ok(g) => {
            guard.armed = false;
            Ok(g)
        }
        Err(e) => {
            cancel(&app.pool, &run).await;
            guard.armed = false;
            Err(e)
        }
    }
}

/// What one gated call is, once its hosts are read.
struct Call<'a> {
    who: &'a Principal,
    run: &'a str,
    action: &'a Action,
    hash: String,
    /// The runner an AI session waits on.
    runner: Option<String>,
}

/// A host as the gate read it: its rule and the tuple a connection is made with.
#[derive(Clone)]
struct H {
    id: String,
    name: String,
    rule: Rule,
    /// Rule, address, port, user, key, jump chain, runner: any change is a different host.
    tuple: String,
}

fn gone() -> ApiError {
    ApiError::not_found("no such host")
}

async fn host_row(conn: &mut SqliteConnection, id: &str) -> Result<Option<H>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT name, ai_rule, address, port, username, key_id, jump_chain, via_runner \
         FROM leyline_hosts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?
    else {
        return Ok(None);
    };
    let rule: String = r.try_get("ai_rule")?;
    let tuple = json!([
        rule,
        r.try_get::<String, _>("address")?,
        r.try_get::<i64, _>("port")?,
        r.try_get::<String, _>("username")?,
        r.try_get::<Option<String>, _>("key_id")?,
        r.try_get::<String, _>("jump_chain")?,
        r.try_get::<Option<String>, _>("via_runner")?,
    ])
    .to_string();
    Ok(Some(H {
        id: id.to_owned(),
        name: r.try_get("name")?,
        rule: Rule::of(&rule),
        tuple,
    }))
}

/// Parks the approval of the `ask` hosts (if any), then settles the run.
async fn park_and_settle(
    app: &App,
    c: &Call<'_>,
    found: &[H],
    mut verdicts: Vec<Verdict>,
) -> Result<Gated, ApiError> {
    let mut hash = c.hash.clone();
    let mut approval_id = None;
    if verdicts.contains(&Verdict::Ask) {
        let (Who::Session(session), Some(runner)) = (&c.who.0, &c.runner) else {
            unreachable!("only an AI session is asked about");
        };
        let id = new_approval_id();
        let outcome = ask(
            app,
            (&id, session, runner),
            c.action,
            found,
            &verdicts,
            &c.hash,
        )
        .await?;
        // The hosts as they are after the wait: a changed or deleted one voids the approval.
        let mut now = Vec::new();
        {
            let mut conn = app.pool.acquire().await?;
            for h in found {
                now.push(host_row(&mut conn, &h.id).await?);
            }
        }
        let same: Vec<bool> = found
            .iter()
            .zip(&now)
            .map(|(o, n)| n.as_ref().is_some_and(|n| n.tuple == o.tuple))
            .collect();
        let all_same = same.iter().all(|s| *s);
        let fresh: Vec<H> = now.into_iter().flatten().collect();
        let fresh_hash = op_hash(c.action, &fresh);
        let by = match &outcome {
            Outcome::Approved(by) => Some(by.clone()),
            _ => None,
        };
        // One approval, one execution: spent, for exactly what is there now, before anything runs.
        let spent = by.is_some() && consume_approval(&app.pool, &id, session, &fresh_hash).await?;
        if by.is_some() && !spent {
            // Approved for something that is no longer there: never spendable later.
            void_approval(&app.pool, &id, session).await?;
        }
        let why = match (&outcome, spent) {
            (Outcome::Approved(_), true) => None,
            (Outcome::Approved(_), false) if !all_same => Some("a host changed while it waited"),
            (Outcome::Approved(_), false) => Some("approval already used"),
            (Outcome::Denied, _) => Some("the person said no"),
            (Outcome::Timeout, _) => Some("nobody answered in time"),
            (Outcome::Ended, _) => Some("the session ended while it waited"),
        };
        for (v, same) in verdicts.iter_mut().zip(&same) {
            if *v == Verdict::Ask {
                *v = why.map_or(Verdict::Allow, Verdict::Deny);
            } else if *v == Verdict::Allow && !same {
                *v = Verdict::Deny("a host changed while it waited");
            }
        }
        if why.is_none() {
            hash = fresh_hash;
        }
        let mut tx = begin_write(&app.pool).await?;
        let details = json!({"run": c.run, "approval": id, "approved": why.is_none(),
            "by": by, "outcome": why.unwrap_or("approved")});
        note(&mut tx, c.who, "leyline.run.approval", &details).await?;
        tx.commit().await?;
        approval_id = Some(id);
    }
    settle(app, c, &hash, found, &verdicts, approval_id.as_deref()).await
}

/// Binds an approval to exactly this operation and command, and to each host's rule and whole
/// connection tuple.
fn op_hash(action: &Action, hosts: &[H]) -> String {
    let mut hs: Vec<(&str, &str)> = hosts
        .iter()
        .map(|h| (h.id.as_str(), h.tuple.as_str()))
        .collect();
    hs.sort_unstable();
    let doc = json!({"op": action.op(), "action": format!("{action:?}"), "hosts": hs});
    Sha256::digest(doc.to_string().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A text the card can show exactly as it is: short and with nothing to redact.
fn shows_whole(s: &str) -> bool {
    s.chars().count() <= CARD_TEXT && redacted(s) == s
}

/// Parks the approval of the `ask` hosts and waits for the person.
async fn ask(
    app: &App,
    (id, session, runner): (&str, &str, &str),
    action: &Action,
    hosts: &[H],
    verdicts: &[Verdict],
    hash: &str,
) -> Result<Outcome, ApiError> {
    let names: Vec<&str> = hosts
        .iter()
        .zip(verdicts)
        .filter(|(_, v)| **v == Verdict::Ask)
        .map(|(h, _)| h.name.as_str())
        .collect();
    let args = json!({"hosts": names, "detail": action.detail()});
    // The person approves what the card shows: never a cut or redacted version of it.
    if !shows_whole(action.detail())
        || !names.iter().all(|n| shows_whole(n))
        || args.to_string().len() > CARD_ALL
    {
        return Err(refuse("too long to show for approval"));
    }
    let summary = format!("Run {} on {} host(s).", action.op(), names.len());
    let secs = settings::value(&app.pool, Key::CodeModeApprovalSecs, Scope::Server)
        .await
        .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
    let ttl = u64::try_from(secs).unwrap_or(0);
    let waiting = Waiting::new(&app.code_mode, id);
    create_approval(
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
    let out = wait_approval(
        app,
        &waiting,
        (id, session, runner),
        Duration::from_secs(ttl),
    )
    .await?;
    Ok(out)
}
