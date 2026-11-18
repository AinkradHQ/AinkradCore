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
//!   have to cut is refused ("too long to show for approval"), and so is one that holds a secret
//!   written out ("contains a secret"). A `$NAME` or `${NAME}` value is shown as written; `$(...)` is not (its text can hold the secret).
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
//!     steps: Vec::new(),
//!     tuple: String::new(),
//! };
//! ```

use std::time::Duration;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::ops_catalog::{
    Outcome, Waiting, approval_left, consume_approval, create_approval, new_approval_id,
    session_principal, void_approval, wait_approval,
};
use ainkrad_core_server::store::connections::access;
use ainkrad_core_server::store::{begin_write, gov, settings};
use ainkrad_proto::v2::MAX_SSH_HOPS;
use axum::http::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};

use crate::commands::{Cmd, Scope as CmdScope, load_cmd};
use crate::hosts::find;
pub use crate::policy::{Action, Principal};
use crate::policy::{Rule, Verdict, Who, verdict};
use crate::valid::new_id;

#[path = "runs.rs"]
mod runs;
pub use runs::finish;
use runs::{Abandon, Parked, note, redacted, settle, write_run};
pub(crate) use runs::{cancel, literal_secret};

/// `s` with secret shapes masked: what a stored text goes through.
pub(crate) fn redact_text(s: &str) -> String {
    redacted(s)
}

/// Most hosts one fleet call may name.
const NOT_FOR_HOST: &str = "the command is not for that host";
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
    /// The pre-set command's steps as the gate decided (and a person approved) them.
    steps: Vec<String>,
    /// The host's rule and connection as the gate read them; `still_valid` compares it.
    tuple: String,
}

impl Authorized {
    /// A pre-set command's steps, as decided: dispatch runs these, never a fresh read of the store.
    pub fn steps(&self) -> &[String] {
        &self.steps
    }
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

/// One machine on the path: what a connection to it is made with.
#[derive(Clone)]
pub(crate) struct Stop {
    /// The leyline host id (its row), as `host` is the address to dial.
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) key_id: Option<String>,
    pub(crate) secret: Option<String>,
    pub(crate) pinned: Vec<String>,
}

/// The target, its jump hosts in order, and the runner that connects (the host's `via_runner`, else
/// the Core machine's built-in one): read once, together with the host's rule.
#[derive(Clone)]
pub(crate) struct Link {
    pub(crate) target: Stop,
    pub(crate) hops: Vec<Stop>,
    pub(crate) runner: String,
}

/// Dispatch calls this right before each thing it sends: the gate's decision still holds. The host
/// must still exist with the same rule and connection (address, port, user, key, every jump hop's
/// connection, runner) it had when the gate decided (`op_sha256` was made over exactly that), the
/// run must still be running, a person must still be an active device and an AI session must still
/// be live. Fixed answers, nothing echoed.
///
/// # Errors
///
/// 403 `gate_refused` when anything changed, or a store failure.
pub async fn still_valid(app: &App, a: &Authorized) -> Result<(), ApiError> {
    check(app, a).await.map(|_| ())
}

/// [`still_valid`], and the very connection data it compared: dispatch connects with THIS read,
/// never a second one made after the check.
pub(crate) async fn checked(app: &App, a: &Authorized) -> Result<Link, ApiError> {
    check(app, a).await?.map_err(refuse)
}

/// What still holds, and the connection read with it (which may itself be unusable: no runner, a
/// bad jump chain; that only matters to a caller that connects).
async fn check(app: &App, a: &Authorized) -> Result<Result<Link, &'static str>, ApiError> {
    let host = {
        let mut conn = app.pool.acquire().await?;
        host_row(&mut conn, &a.host).await?
    };
    let link = match host {
        None => return Err(refuse("the host is gone")),
        Some(h) if h.tuple != a.tuple => return Err(refuse("the host changed")),
        Some(h) => h.link,
    };
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM leyline_runs WHERE id = ?")
        .bind(&a.run)
        .fetch_optional(&app.pool)
        .await?;
    if state.as_deref() != Some("running") {
        return Err(refuse("the run is no longer running"));
    }
    match &a.principal.0 {
        Who::Session(s) => {
            let live = access::load(&app.pool, s).await?.is_some_and(|x| x.live);
            if !live || session_principal(&app.pool, s).await?.is_none() {
                return Err(refuse("this session may no longer act"));
            }
        }
        Who::Person(d) => {
            let usable = gov::get_device(&app.pool, d)
                .await
                .map_err(|e| ApiError::from(sqlx::Error::Protocol(e.to_string())))?
                .is_some_and(|d| d.usable());
            if !usable {
                return Err(refuse("this device may no longer act"));
            }
        }
        Who::Health => {}
    }
    Ok(link)
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

/// One host. A `confirm` command is refused (409 `confirm_required`) here: a caller that has the
/// request's `confirm` uses [`authorize_confirmed`]. Any refusal (policy, session, or the person's "no") is an error.
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
    authorize_confirmed(app, who, host, action, false).await
}

/// [`authorize`] for a caller that took `confirm` from its request: a pre-set command flagged
/// `confirm` is refused (409 `confirm_required`) unless `confirmed`, judged on the command the gate
/// itself reads, so an edit between the caller's check and the gate cannot slip past.
///
/// # Errors
///
/// As [`authorize`], and 409 `confirm_required`.
pub async fn authorize_confirmed(
    app: &App,
    who: &Principal,
    host: &str,
    action: &Action,
    confirmed: bool,
) -> Result<Authorized, ApiError> {
    let mut g = gate_many(app, who, &[host], action, confirmed, None).await?;
    match (g.authorized.pop(), g.refused.pop()) {
        (Some(a), _) => Ok(a),
        (None, Some((_, why))) if why == NOT_FOR_HOST => Err(ApiError::conflict(why)),
        (None, Some((_, why))) => Err(refuse(why)),
        (None, None) => Err(refuse("not allowed")),
    }
}

/// Several hosts, one run, at most one approval (for every `ask` host together). As with
/// [`authorize`], a `confirm` command is refused: it is never confirmed unless a caller says so.
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
    gate_many(app, who, hosts, action, false, None).await
}

/// How a fleet call picked its hosts: the ids named directly, and the label of what picked the
/// rest (`group edge`, `tag web`, `project 12 (role production)`).
#[derive(Clone)]
pub(crate) struct Fleet {
    pub(crate) named: Vec<String>,
    pub(crate) label: String,
}

/// `fleet` (a call whose hosts a group, tag or project picked): the approval card lists every host
/// named directly by name, and shows the picked ones as a count plus the label. Ceiling: the person
/// approves "N hosts of <label>", not each of their names; the approval is still bound by hash to
/// exactly the hosts (and their connections) read here, so a host added or changed while it waits
/// voids it.
pub(crate) async fn gate_many(
    app: &App,
    who: &Principal,
    hosts: &[&str],
    action: &Action,
    confirmed: bool,
    fleet: Option<&Fleet>,
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
    // A pre-set command is read here, by the gate: its flag and steps are never an input.
    let cmd = match action {
        Action::Preset(id) => {
            let mut conn = app.pool.acquire().await?;
            Some(
                load_cmd(&mut conn, id)
                    .await?
                    .ok_or_else(|| ApiError::not_found("no such command"))?,
            )
        }
        _ => None,
    };
    if cmd.as_ref().is_some_and(|c| c.confirm) && !confirmed {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "confirm_required",
            "this command must be confirmed: send confirm true",
        ));
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
    let mut verdicts: Vec<Verdict> = Vec::new();
    for h in &found {
        let v = if is_ai && session_runner.is_none() {
            Verdict::Deny("this session may no longer act")
        } else if !for_host(app, cmd.as_ref(), &h.id).await? {
            Verdict::Deny(NOT_FOR_HOST)
        } else {
            match verdict(
                who,
                h.rule,
                action,
                cmd.as_ref().is_some_and(|c| c.read_only),
            ) {
                // A command that wants confirming is not run by an AI on its own, even where
                // the host allows it.
                Verdict::Allow if is_ai && cmd.as_ref().is_some_and(|c| c.confirm) => Verdict::Ask,
                v => v,
            }
        };
        verdicts.push(v);
    }
    let run = new_id("lr_");
    let hash = op_hash(action, cmd.as_ref(), &found);
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
        cmd,
        fleet: fleet.cloned(),
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
    /// The pre-set command, as read when the call began.
    cmd: Option<Cmd>,
    /// A fleet call's picked hosts, shown on the card as a count and a label.
    fleet: Option<Fleet>,
}

/// A host as the gate read it: its rule and the tuple a connection is made with.
#[derive(Clone)]
struct H {
    id: String,
    name: String,
    rule: Rule,
    /// Rule, address, port, user, key, runner and every jump hop's connection: any change is a
    /// different host.
    tuple: String,
    /// The connection as read in the same query round as `tuple`.
    link: Result<Link, &'static str>,
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
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let rule: String = r.try_get("ai_rule")?;
    let (jump_chain, via): (String, Option<String>) =
        (r.try_get("jump_chain")?, r.try_get("via_runner")?);
    let link = link(conn, id, &jump_chain, via.as_deref()).await;
    let path = match &link {
        Ok(l) => json!({
            "runner": l.runner,
            "stops": l.hops.iter().chain([&l.target]).map(|s| json!([s.host, s.port, s.user, s.key_id])).collect::<Vec<_>>(),
        }),
        Err(e) => json!(e),
    };
    // The hops' own connections count even when the path cannot be built (no runner yet): a hop that
    // changes is a different host either way.
    let mut hops = Vec::new();
    for id in serde_json::from_str::<Vec<String>>(&jump_chain).unwrap_or_default() {
        let h =
            sqlx::query("SELECT address, port, username, key_id FROM leyline_hosts WHERE id = ?")
                .bind(&id)
                .fetch_optional(&mut *conn)
                .await?;
        hops.push(match h {
            Some(h) => json!([
                id,
                h.try_get::<String, _>("address")?,
                h.try_get::<i64, _>("port")?,
                h.try_get::<String, _>("username")?,
                h.try_get::<Option<String>, _>("key_id")?
            ]),
            None => json!([id]),
        });
    }
    let tuple = json!([
        hops,
        rule,
        r.try_get::<String, _>("address")?,
        r.try_get::<i64, _>("port")?,
        r.try_get::<String, _>("username")?,
        r.try_get::<Option<String>, _>("key_id")?,
        jump_chain,
        via,
        path,
    ])
    .to_string();
    Ok(Some(H {
        id: id.to_owned(),
        name: r.try_get("name")?,
        rule: Rule::of(&rule),
        tuple,
        link,
    }))
}

const NO: &str = "the host cannot be read";

/// The path to `host`: each hop's connection (and key secret and pinned keys), and the runner.
async fn link(
    conn: &mut SqliteConnection,
    host: &str,
    jump_chain: &str,
    via: Option<&str>,
) -> Result<Link, &'static str> {
    let jumps: Vec<String> = serde_json::from_str(jump_chain).map_err(|_| NO)?;
    if jumps.len() > MAX_SSH_HOPS {
        return Err("too many jump hosts");
    }
    let runner = match via {
        Some(r) => r.to_owned(),
        None => sqlx::query_scalar(
            "SELECT p.device_id FROM core_pairings p JOIN core_devices d ON d.id = p.device_id \
             WHERE p.kind = 'runner' AND p.sas = ? AND d.status = 'active' AND d.revoked_at IS NULL ORDER BY p.device_id LIMIT 1",
        )
        .bind(ainkrad_core_server::store::gov::LOCAL_ENROL_SAS)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| NO)?
        .ok_or("the Core has no built-in runner")?,
    };
    let mut stops = Vec::new();
    for id in jumps.iter().map(String::as_str).chain([host]) {
        let h = sqlx::query(
            "SELECT h.address, h.port, h.username, h.key_id, k.secret FROM leyline_hosts h \
             LEFT JOIN leyline_keys k ON k.id = h.key_id WHERE h.id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| NO)?
        .ok_or(NO)?;
        let pinned: Vec<String> = sqlx::query_scalar(
            "SELECT fingerprint FROM leyline_host_keys WHERE host_id = ? AND state = 'trusted'",
        )
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| NO)?;
        stops.push(Stop {
            id: id.to_owned(),
            host: h.try_get("address").map_err(|_| NO)?,
            port: u16::try_from(h.try_get::<i64, _>("port").map_err(|_| NO)?).map_err(|_| NO)?,
            user: h.try_get("username").map_err(|_| NO)?,
            key_id: h.try_get("key_id").map_err(|_| NO)?,
            secret: h.try_get("secret").map_err(|_| NO)?,
            pinned,
        });
    }
    let target = stops.pop().ok_or(NO)?;
    Ok(Link {
        target,
        hops: stops,
        runner,
    })
}

/// Whether the pre-set command (if any) is for the host `host` (an id): its scope, checked here so
/// a single run and a fleet run (Y4-03) both pass through it.
async fn for_host(app: &App, cmd: Option<&Cmd>, host: &str) -> Result<bool, sqlx::Error> {
    let Some(c) = cmd else {
        return Ok(true);
    };
    let mut conn = app.pool.acquire().await?;
    in_scope(&mut conn, &c.scope, host).await
}

/// Whether `host` (an id) is one of the hosts `scope` names.
async fn in_scope(
    conn: &mut SqliteConnection,
    scope: &Option<CmdScope>,
    host: &str,
) -> Result<bool, sqlx::Error> {
    let Some(s) = scope else {
        return Ok(true);
    };
    let sql = match s.kind.as_str() {
        "host" => "SELECT ?2 = ?1",
        "group" => {
            "SELECT EXISTS (SELECT 1 FROM leyline_hosts WHERE id = ?1 AND group_name = ?2 COLLATE NOCASE)"
        }
        "tag" => {
            "SELECT EXISTS (SELECT 1 FROM leyline_hosts, json_each(tags) WHERE leyline_hosts.id = ?1 AND value = ?2)"
        }
        _ => {
            "SELECT EXISTS (SELECT 1 FROM leyline_project_hosts WHERE host_id = ?1 AND project = ?2 \
             AND (?3 IS NULL OR role = ?3))"
        }
    };
    sqlx::query_scalar(sql)
        .bind(host)
        .bind(&s.value)
        .bind(&s.role)
        .fetch_one(conn)
        .await
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
        // The call dropped (the caller gave up) while the approval is open: it is voided.
        let mut open = Abandon {
            pool: app.pool.clone(),
            id: id.clone(),
            session: session.clone(),
            armed: true,
        };
        // The run knows its approval while it waits, so a cancel can void it.
        sqlx::query("UPDATE leyline_runs SET approval = ? WHERE id = ?")
            .bind(&id)
            .bind(c.run)
            .execute(&app.pool)
            .await?;
        let outcome = ask(
            app,
            (&id, session, runner),
            c.action,
            found,
            &verdicts,
            &c.hash,
            c.cmd.as_ref(),
            c.fleet.as_ref(),
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
        // The command as it is after the wait: an edited or deleted one voids the approval.
        let cmd_now = match c.action {
            Action::Preset(id) => {
                let mut conn = app.pool.acquire().await?;
                load_cmd(&mut conn, id).await?
            }
            _ => None,
        };
        let cmd_same = cmd_now == c.cmd;
        let fresh_hash = op_hash(c.action, cmd_now.as_ref(), &fresh);
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
        open.armed = false;
        let why = match (&outcome, spent) {
            (Outcome::Approved(_), true) => None,
            (Outcome::Approved(_), false) if !cmd_same => {
                Some("the command changed while it waited")
            }
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
            } else if *v == Verdict::Allow && !cmd_same {
                *v = Verdict::Deny("the command changed while it waited");
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
fn op_hash(action: &Action, cmd: Option<&Cmd>, hosts: &[H]) -> String {
    let mut hs: Vec<(&str, &str)> = hosts
        .iter()
        .map(|h| (h.id.as_str(), h.tuple.as_str()))
        .collect();
    hs.sort_unstable();
    let cmd = cmd.map(|c| json!([c.id, c.name, c.read_only, c.confirm, c.steps, c.scope]));
    let doc = json!({"op": action.op(), "action": format!("{action:?}"), "cmd": cmd, "hosts": hs});
    Sha256::digest(doc.to_string().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A control character or a bidi override: text a card or an exec line must not carry, because the
/// person would read something other than what runs (U+202A-202E, U+2066-2069).
pub(crate) fn hides(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
}

/// A text the card can show exactly as it is: short (a `$NAME` or `${NAME}` value is shown as
/// written; a secret written out is not) and with nothing in it that hides or rewrites what the
/// person reads.
pub(crate) fn shows_whole(s: &str) -> bool {
    s.chars().count() <= CARD_TEXT && !hides(s)
}

/// Parks the approval of the `ask` hosts and waits for the person.
#[allow(clippy::too_many_arguments)] // one call site; a struct would only rename them
async fn ask(
    app: &App,
    (id, session, runner): (&str, &str, &str),
    action: &Action,
    hosts: &[H],
    verdicts: &[Verdict],
    hash: &str,
    cmd: Option<&Cmd>,
    fleet: Option<&Fleet>,
) -> Result<Outcome, ApiError> {
    let asked: Vec<&H> = hosts
        .iter()
        .zip(verdicts)
        .filter(|(_, v)| **v == Verdict::Ask)
        .map(|(h, _)| h)
        .collect();
    // Hosts named directly are always listed by name; only picked ones fold into a count.
    let is_named = |h: &H| fleet.is_none_or(|f| f.named.contains(&h.id));
    let names: Vec<&str> = asked
        .iter()
        .filter(|h| is_named(h))
        .map(|h| h.name.as_str())
        .collect();
    let picked = asked.len() - names.len();
    let label = fleet.filter(|_| picked > 0).map(|f| f.label.as_str());
    // A pre-set command is shown by name with every step, whole.
    let (detail, steps) = cmd.map_or((action.detail(), &[][..]), |c| {
        (c.name.as_str(), &c.steps[..])
    });
    let args = match label {
        Some(l) => json!({"hosts": names, "picked": picked, "picked_by": l,
            "detail": detail, "steps": steps}),
        None => json!({"hosts": names, "detail": detail, "steps": steps}),
    };
    // The person approves what the card shows: never a cut or redacted version of it.
    let texts: Vec<&str> = [detail]
        .into_iter()
        .chain(steps.iter().map(String::as_str))
        .chain(names.iter().copied())
        .chain(label)
        .collect();
    if texts.iter().any(|t| literal_secret(t)) {
        return Err(refuse("the command contains a secret"));
    }
    if texts.iter().any(|t| !shows_whole(t)) || args.to_string().len() > CARD_ALL {
        return Err(refuse("too long to show for approval"));
    }
    let summary = match label {
        Some(l) => format!(
            "Run {} on {} host(s), {picked} picked by {l}.",
            action.op(),
            asked.len()
        ),
        None => format!("Run {} on {} host(s).", action.op(), asked.len()),
    };
    let secs = settings::value(&app.pool, Key::CodeModeApprovalSecs, Scope::Server)
        .await
        .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
    // Never held past what the caller still waits (a Code Mode call's `wait_ms`).
    let mut ttl = u64::try_from(secs).unwrap_or(0);
    if let Some(left) = approval_left() {
        ttl = ttl.min(left.as_secs());
    }
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

#[cfg(test)]
mod hides_tests {
    use super::*;

    #[test]
    fn control_and_bidi_text_is_never_shown_whole() {
        for bad in [
            "ls\nrm -rf /",
            "ls\r",
            "a\u{1b}[2J",
            "a\tb",
            "a\0b",
            "ls \u{202E}gnp.txt",
            "a\u{202A}b",
            "a\u{2066}b",
            "a\u{2069}b",
        ] {
            assert!(hides(bad), "{bad:?}");
            assert!(!shows_whole(bad), "{bad:?}");
        }
        for fine in ["uptime", "ls -la /var/log", "echo é世界", "echo \u{200B}x"] {
            assert!(!hides(fine), "{fine:?}");
            assert!(shows_whole(fine), "{fine:?}");
        }
        assert!(!shows_whole(&"x".repeat(CARD_TEXT + 1)));
    }
}
