//! Host terminals (Y3-01): `POST /hosts/{host}/terminals` opens an interactive SSH terminal on a
//! host through the runner the host is reached by, as an ordinary Core terminal (the app attaches
//! through the existing terminals WebSocket, unchanged).
//!
//! Security model.
//! - The gate first: `gate::authorize(Terminal)` runs before any lease, runner lookup or dispatch;
//!   its refusal ends the request. What reaches a runner exists only because the gate returned an
//!   `Authorized`, which is finished (ok or failed) when the open is over.
//! - The Core sends no key: each hop of the chain (jump hosts, then the target) gets a secret lease
//!   the runner redeems itself. A host or hop with no key is refused (the runner needs a key to
//!   start the connection).
//! - Each hop is pinned to the fingerprints a person trusted (`hostkeys`); none pinned means the
//!   runner stops at the host key and the fingerprint is stored for a person to compare. The
//!   fingerprint comes only from the runner's structured exit report (`TerminalExit::host_key`,
//!   written by `ssh-pty` itself over a private descriptor, set only when no shell ever started and
//!   `ssh-pty` made a reserved exit code 70 or 71). The terminal's output is never parsed: a remote
//!   shell controls it, and its own exit status 70 to 72 is made 1 by `ssh-pty`.
//! - Every Core refusal (scope, size, caps, runner, a key on every hop) comes before the first
//!   lease; a lease granted for an open that then fails is revoked.
//! - An ssh terminal goes only to a runner that lists `pty.ssh`: an older one would open a LOCAL
//!   shell. Checked here before any lease is made, and by the hub on every dispatch.
//! - The session row ends with the terminal (exit, host-key refusal, or the runner lost).
//! - A host with recording on gets its output (never its input) written by `record`, set up here
//!   before the terminal's id leaves the Core.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{
    ApiError, ApiResult, BY, Caller, Ended, TerminalSize, check_ssh_open, open_ssh,
};
use ainkrad_core_server::store::gov::LOCAL_ENROL_SAS;
use ainkrad_core_server::store::{audit, begin_write, events, secrets};
use ainkrad_proto::v2::{
    FEATURE_PTY_SSH, SSH_PTY_EXIT_AUTH_FAILED, SSH_PTY_EXIT_FAILED, SSH_PTY_EXIT_HOST_KEY_CHANGED,
    SSH_PTY_EXIT_HOST_KEY_UNKNOWN, SshHop, SshTerminal,
};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::gate::{self, Action, Authorized, Principal};
use crate::hostkeys;
use crate::hosts::{In, find};
use crate::valid::new_id;

#[derive(Deserialize, ToSchema)]
pub struct NewSession {
    pub rows: u16,
    pub cols: u16,
}

/// A host terminal: attach to `terminal` through the Core's terminals WebSocket.
#[derive(Serialize, ToSchema)]
pub struct SessionView {
    /// `ls_` and 16 hex characters.
    pub id: String,
    pub host_id: String,
    /// The Core terminal's id (`t_...`).
    pub terminal: String,
    pub runner: String,
    pub started_at: String,
    /// The session is being recorded (a person sees this as a visible Recording indicator).
    pub recording: bool,
}

fn refuse(code: &'static str, why: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code, why)
}

/// The runner a host is reached by: its own, else the Core machine's built-in one.
async fn runner_of(conn: &mut SqliteConnection, via: Option<String>) -> Result<String, ApiError> {
    if let Some(r) = via {
        return Ok(r);
    }
    sqlx::query_scalar(
        "SELECT p.device_id FROM core_pairings p JOIN core_devices d ON d.id = p.device_id \
         WHERE p.kind = 'runner' AND p.sas = ? AND d.status = 'active' AND d.revoked_at IS NULL LIMIT 1",
    )
    .bind(LOCAL_ENROL_SAS)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| refuse("no_runner", "the host has no runner to reach it by"))
}

/// One machine on the path as stored: where, who, which key, and the fingerprints pinned.
struct Stop {
    address: String,
    port: u16,
    user: String,
    secret: String,
    pinned: Vec<String>,
}

/// Reads one machine of the path; no lease yet. A host with no key is refused here.
async fn stop(app: &App, host: &str) -> Result<Stop, ApiError> {
    let mut conn = app.pool.acquire().await?;
    let r = sqlx::query(
        "SELECT h.address, h.port, h.username, k.secret FROM leyline_hosts h \
         LEFT JOIN leyline_keys k ON k.id = h.key_id WHERE h.id = ?",
    )
    .bind(host)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| ApiError::not_found("no such host"))?;
    let secret: Option<String> = r.try_get("secret")?;
    let secret = secret
        .ok_or_else(|| refuse("host_needs_key", "every host on the path needs an ssh key"))?;
    let pinned = hostkeys::trusted(&mut conn, host).await?;
    Ok(Stop {
        address: r.try_get("address")?,
        port: u16::try_from(r.try_get::<i64, _>("port")?).unwrap_or(22),
        user: r.try_get("username")?,
        secret,
        pinned,
    })
}

/// The lease for one stop, redeemable by `runner` only.
async fn hop(app: &App, me: &Caller, runner: &str, s: Stop) -> Result<SshHop, ApiError> {
    let (lease, _) = secrets::lease(
        &app.pool,
        &s.secret,
        runner,
        None,
        &me.device.id,
        BY,
        &app.clock.now(),
        app.clock.unix(),
    )
    .await?;
    Ok(SshHop {
        host: s.address,
        port: s.port,
        user: s.user,
        pinned_keys: s.pinned,
        lease,
    })
}

/// Drops leases that were granted and will not be redeemed (best effort: an unredeemed lease also
/// expires on its own).
async fn revoke(app: &App, leases: &[String]) {
    for l in leases {
        let _ = secrets::revoke_lease(&app.pool, l).await;
    }
}

/// Everything `open` needs, checked and leased. `chain` is the jump hosts then the target. Every
/// refusal the Core can know of comes before the first lease: terminal scope, size, caps, the
/// runner, and a key on every hop. A lease that fails part-way revokes the ones already granted.
async fn prepare(
    app: &App,
    me: &Caller,
    id: &str,
    size: TerminalSize,
) -> Result<(String, SshTerminal, Vec<String>), ApiError> {
    let (via, jumps): (Option<String>, String) = {
        let mut conn = app.pool.acquire().await?;
        sqlx::query_as("SELECT via_runner, jump_chain FROM leyline_hosts WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?
    };
    let runner = {
        let mut conn = app.pool.acquire().await?;
        runner_of(&mut conn, via).await?
    };
    // A runner that cannot do this would open a local shell, and a lease for it would be spent
    // for nothing.
    let can = app.hub.runners().get(&runner).is_some_and(|r| {
        r.online
            && r.drivers
                .iter()
                .any(|d| d.commands.iter().any(|c| c == FEATURE_PTY_SSH))
    });
    if !can {
        return Err(refuse(
            "runner_cannot_ssh",
            "the runner is offline or too old to open ssh terminals",
        ));
    }
    check_ssh_open(app, me, &runner, size).await?;
    let mut chain: Vec<String> = serde_json::from_str(&jumps).unwrap_or_default();
    chain.push(id.to_owned());
    let mut stops = Vec::new();
    for h in &chain {
        stops.push(stop(app, h).await?);
    }
    let mut hops = Vec::new();
    for s in stops {
        match hop(app, me, &runner, s).await {
            Ok(h) => hops.push(h),
            Err(e) => {
                let leased: Vec<String> = hops.iter().map(|h| h.lease.clone()).collect();
                revoke(app, &leased).await;
                return Err(e);
            }
        }
    }
    let target = hops.pop().expect("the chain ends with the host");
    Ok((runner, SshTerminal { target, hops }, chain))
}

#[utoipa::path(post, path = "/hosts/{host}/terminals", operation_id = "leylineOpenTerminal", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = NewSession,
    responses((status = 200, description = "The terminal is open on the host's runner: attach to `terminal` through the terminals WebSocket. 403 `gate_refused`; 409 `runner_cannot_ssh` (offline, or a runner without `pty.ssh`), `host_needs_key`, `no_runner`. A host key that is not pinned ends the terminal at once with its fingerprint stored (`GET /hosts/{host}/host-keys`)", body = SessionView)))]
pub(crate) async fn open(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<NewSession>,
) -> ApiResult<SessionView> {
    let size = TerminalSize {
        rows: req.rows,
        cols: req.cols,
    };
    let id = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, &host).await?
    };
    let auth = gate::authorize(&app, &Principal::of(&me), &id, &Action::Terminal).await?;
    let done = start(&app, &me, size, &auth).await;
    finish(&app, auth, done.is_ok()).await?;
    Ok(Json(done?))
}

async fn finish(app: &App, auth: Authorized, ok: bool) -> Result<(), ApiError> {
    gate::finish(app, auth, ok).await
}

/// Dispatch takes the gate's proof: it cannot be written without one.
async fn start(
    app: &App,
    me: &Caller,
    size: TerminalSize,
    auth: &Authorized,
) -> Result<SessionView, ApiError> {
    let (id, run, who) = (auth.host_id(), auth.run_id(), auth.principal().label());
    let (runner, ssh, chain) = prepare(app, me, id, size).await?;
    let leased: Vec<String> = (ssh.hops.iter().chain([&ssh.target]))
        .map(|h| h.lease.clone())
        .collect();
    let (t, ended) = match open_ssh(app, me, &runner, ssh, size).await {
        Ok(opened) => opened,
        Err(e) => {
            revoke(app, &leased).await;
            return Err(e);
        }
    };
    let session = new_id("ls_");
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "INSERT INTO leyline_sessions (id, host_id, terminal, runner, principal, run_id) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&session)
    .bind(id)
    .bind(&t.id)
    .bind(&runner)
    .bind(&who)
    .bind(run)
    .execute(&mut *tx)
    .await?;
    note(&mut tx, "opened", &session, id).await?;
    let started: String =
        sqlx::query_scalar("SELECT started_at FROM leyline_sessions WHERE id = ?")
            .bind(&session)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    // Before the monitor below can end the session: a tap set after the end would never be removed.
    let recording = crate::record::begin(app, &session, id, &t.id, size).await;
    if recording {
        let mut c = app.pool.acquire().await?;
        events::append(
            &mut c,
            "leyline.session",
            &json!({"op": "recording", "id": session, "host": id, "recording": true}),
        )
        .await?;
    }
    let (a, s, terminal) = (app.clone(), session.clone(), t.id.clone());
    tokio::spawn(async move {
        // The monitor went without telling us how it ended: the runner (or the Core's hold on it)
        // is lost, which is what the session records.
        let end = ended.await.unwrap_or(Ended {
            lost: true,
            ..Ended::default()
        });
        let closed = conclude(&a, &s, &chain, end).await;
        // The recording ends with the terminal: dropping the tap lets its writer finish the file.
        a.terminals.untap(&terminal);
        if closed.is_err() {
            tracing::warn!("a leyline session could not be closed out");
        }
    });
    Ok(SessionView {
        id: session,
        host_id: id.to_owned(),
        terminal: t.id,
        runner,
        started_at: started,
        recording,
    })
}

async fn note(
    conn: &mut SqliteConnection,
    op: &str,
    session: &str,
    host: &str,
) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.session.{op}"),
        entity: None,
        details: json!({"session": session, "host": host}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(
        conn,
        "leyline.session",
        &json!({"op": op, "id": session, "host": host}),
    )
    .await?;
    Ok(())
}

/// The session ends with its terminal; a host-key refusal also leaves the key for a person.
async fn conclude(app: &App, session: &str, chain: &[String], end: Ended) -> Result<(), ApiError> {
    let reason = match (end.lost, end.exit_code) {
        (true, _) => "runner_lost",
        (_, Some(SSH_PTY_EXIT_HOST_KEY_UNKNOWN)) => "host_key_unknown",
        (_, Some(SSH_PTY_EXIT_HOST_KEY_CHANGED)) => "host_key_changed",
        (_, Some(SSH_PTY_EXIT_AUTH_FAILED)) => "auth_failed",
        (_, Some(SSH_PTY_EXIT_FAILED)) => "failed",
        _ => "exited",
    };
    // The runner's structured report, only for the reserved codes `ssh-pty` alone can exit with.
    // The hop is a host too: its key belongs to that host, not to the target.
    if matches!(reason, "host_key_unknown" | "host_key_changed")
        && let Some(k) = &end.host_key
        && hostkeys::fingerprint_ok(&k.fingerprint)
        && let Some(host) = chain.get(usize::from(k.hop))
    {
        hostkeys::saw(app, host, &k.fingerprint, reason == "host_key_changed").await?;
    }
    let mut tx = begin_write(&app.pool).await?;
    let host: String = sqlx::query_scalar(
        "UPDATE leyline_sessions SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), end_reason = ?, exit_code = ? \
         WHERE id = ? AND ended_at IS NULL RETURNING host_id",
    )
    .bind(reason)
    .bind(end.exit_code)
    .bind(session)
    .fetch_one(&mut *tx)
    .await?;
    note(&mut tx, "ended", session, &host).await?;
    tx.commit().await?;
    Ok(())
}

/// At Core start: a session row still open belongs to a terminal whose monitor died with the
/// previous process, so nobody will ever end it. Closed as `runner_lost`.
pub(crate) async fn close_orphans(app: &App) -> Result<(), ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "UPDATE leyline_sessions SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), end_reason = 'runner_lost' \
         WHERE ended_at IS NULL RETURNING id, host_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (id, host) in &rows {
        note(&mut tx, "ended", id, host).await?;
    }
    tx.commit().await?;
    Ok(())
}
