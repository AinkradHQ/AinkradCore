//! Mac-direct (Y6-01, plan T7): `POST /hosts/{host}/direct` leases a host's key (and its jump hops')
//! to the person's Mac runner, which holds it in an ssh-agent bound to those hosts, so `ssh`,
//! `scp` and editors on the Mac work; `POST /hosts/{host}/direct/revoke` ends it.
//!
//! Security model.
//! - The gate first: `gate::authorize(Direct)` runs before any lease or dispatch. It is a person-only
//!   action (an AI session or the prober is refused there), and the create route is a step-up route.
//!   What reaches a runner exists only because the gate returned an `Authorized`, which is finished
//!   (ok or failed) when the call is over.
//! - The key never reaches the Core's API or the App. The Core sends the runner one single-use lease
//!   per machine on the path, minted for that runner only: the key is opened here
//!   (`secrets::open_for_module`, audited `secret.used`) and held in the Core's memory under a lease
//!   id (`Agents::stash`) until the runner redeems it or the load is over. The key's stored runner
//!   list is NOT changed, so no other lease path (the admin `POST /secrets/.../leases`, an AI
//!   Session's `secrets:`) can reach the Mac runner, and no other lease of the key is dropped. The
//!   runner holds the keys in memory and signs only inside an ssh session bound to the host key
//!   pinned for that key's own machine, for that machine's user (see the runner's `ssh/agent.rs`:
//!   every sign request is checked there).
//! - The agent ops have one way out of the Core, an `SshAgentLine` the hub hands out once; this
//!   file takes it and keeps it private (`line`).
//! - Nothing is leased for a path with an unpinned machine: a person trusts host keys first, so the
//!   agent always has pins to bind to.
//! - One open lease per host (a unique index). It ends on revoke, on its TTL (a Core timer that
//!   outlives restarts, and the runner's own deadline), or when the runner loses the Core for 5
//!   minutes. A revoke whose runner cannot be reached still ends the row and says so
//!   (`runner_reached: false`, stored); the Core sends the drop again whenever that runner is online,
//!   until it answers or the lease's own deadline has passed (`redrop`).
//! - Rows and audit carry ids, the runner, times and the signature count: never a key, a lease or a
//!   fingerprint of a key. Runner failures are answered with fixed texts.

use std::sync::Mutex;
use std::time::Duration;

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::agents::Ephemeral;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::hub::{Dispatched, RunnerState, SshAgentLine};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::{audit, begin_write, events, secrets};
use ainkrad_proto::v2::{
    AgentKey, Body, ErrorCode, OP_SSH_AGENT_DROP, OP_SSH_AGENT_LOAD, Reply, SSH_AGENT_MAX_TTL_SECS,
    SshAgentCommand, SshAgentDrop, SshAgentLoad, StreamError,
};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::gate::{self, Action, Authorized, Principal};
use crate::hosts::{In, find};
use crate::ready::{ready, sane};
use crate::terminal::{Stop, refuse, stop};
use crate::valid::{self, new_id};

const DEFAULT_TTL: u32 = 3600;
const MIN_TTL: u32 = 60;
/// How long the runner has to answer a load (it redeems leases first) or a drop.
const LOAD_WAIT: Duration = Duration::from_secs(45);
const DROP_WAIT: Duration = Duration::from_secs(10);
/// How long a minted key lease waits for the runner (it redeems at once, inside `LOAD_WAIT`).
const MINT_SECS: i64 = 60;
/// How often ended leases the runner never heard of are looked at again.
const REDROP_EVERY: Duration = Duration::from_secs(5);
/// The Mac's clock may run behind the Core's: a late drop is still sent this long past a deadline.
const SKEW_SECS: i64 = 300;

#[derive(Deserialize, ToSchema)]
pub struct NewDirect {
    /// The runner on the person's Mac (`d_...`). Absent: the one online macOS runner that offers the
    /// agent; none or several is a 409 that says so.
    pub runner: Option<String>,
    /// 60 to 43200 seconds; default 3600.
    pub ttl_secs: Option<u32>,
}

/// A Mac-direct lease: the agent is listening.
#[derive(Serialize, ToSchema)]
pub struct DirectView {
    /// `ld_` and 16 hex characters.
    pub id: String,
    pub host_id: String,
    pub runner: String,
    /// The agent socket (`SSH_AUTH_SOCK`), on the runner's machine.
    pub socket: String,
    /// Run this in a terminal on that machine: it reaches the host, and only the host.
    pub ready: String,
    pub started_at: String,
    pub expires_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct DirectEnded {
    pub id: String,
    /// Signatures the agent made; 0 when the runner could not be asked.
    pub signatures: i64,
    /// The runner answered the drop. When false it ends by its own deadline.
    pub runner_reached: bool,
}

fn wrong(code: &'static str, why: &'static str) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, code, why)
}

/// What a runner failure is called to the caller: fixed texts, never the runner's own.
fn runner_err(e: &StreamError) -> ApiError {
    match e.code {
        ErrorCode::SshAuthFailed => {
            wrong("runner_failed", "the runner could not redeem a key lease")
        }
        ErrorCode::Offline | ErrorCode::Lost => {
            wrong("runner_offline", "the runner is not reachable")
        }
        ErrorCode::Busy => wrong("runner_busy", "the runner is busy or has too many agents"),
        ErrorCode::UnsupportedCommand => {
            wrong("runner_cannot_agent", "the runner does not offer the agent")
        }
        _ => wrong("runner_failed", "the runner could not start the agent"),
    }
}

/// The hub's one agent line, taken on first use (one per hub; a test process has several).
static LINES: Mutex<Vec<SshAgentLine>> = Mutex::new(Vec::new());

fn line_send(app: &App, runner: &str, cmd: SshAgentCommand) -> Result<Dispatched, ApiError> {
    let mut lines = LINES.lock().unwrap();
    lines.retain(|l| !l.is_dead());
    if !lines.iter().any(|l| l.serves(&app.hub)) {
        // Someone else took this hub's line: fail closed.
        let taken = app.hub.take_ssh_agent_line().ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "the agent line is not this module's",
            )
        })?;
        lines.push(taken);
    }
    let line = lines.iter().find(|l| l.serves(&app.hub));
    line.expect("pushed above")
        .dispatch(runner, cmd)
        .map_err(|e| runner_err(&e))
}

async fn call(
    app: &App,
    runner: &str,
    cmd: SshAgentCommand,
    wait: Duration,
) -> Result<Body, ApiError> {
    let sent = line_send(app, runner, cmd)?;
    match tokio::time::timeout(wait, sent.outcome()).await {
        Ok(done) => done.map_err(|e| runner_err(&e)),
        Err(_) => Err(wrong("runner_timeout", "the runner did not answer in time")),
    }
}

fn offers(r: &RunnerState) -> bool {
    r.online
        && r.drivers.iter().any(|d| {
            [OP_SSH_AGENT_LOAD, OP_SSH_AGENT_DROP]
                .iter()
                .all(|op| d.commands.iter().any(|c| c == op))
        })
}

/// The runner that holds the agent: the one named, or the only online Mac runner that offers it.
fn pick_runner(app: &App, want: Option<String>) -> Result<String, ApiError> {
    let runners = app.hub.runners();
    if let Some(id) = want {
        if !valid::runner(&id) || !runners.get(&id).is_some_and(offers) {
            return Err(refuse(
                "runner_cannot_agent",
                "that runner is offline or does not offer the agent",
            ));
        }
        return Ok(id);
    }
    let macs: Vec<&String> = runners
        .iter()
        .filter(|(_, r)| offers(r) && r.os.as_deref() == Some("macos"))
        .map(|(id, _)| id)
        .collect();
    match macs.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(refuse(
            "no_mac_runner",
            "no online Mac runner offers the agent",
        )),
        _ => Err(refuse(
            "pick_a_runner",
            "name the runner: several Macs are online",
        )),
    }
}

#[utoipa::path(post, path = "/hosts/{host}/direct", operation_id = "leylineLeaseDirect", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = NewDirect,
    responses((status = 200, description = "The agent listens on the runner's machine; run `ready` there. A step-up route; person only (403 `gate_refused` for an AI session). 409 `host_needs_key`, `host_not_trusted` (a machine on the path has no pinned host key), `already_leased`, `no_mac_runner`, `pick_a_runner`, `runner_cannot_agent`; 502 `runner_*`", body = DirectView)))]
pub(crate) async fn lease(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<NewDirect>,
) -> ApiResult<DirectView> {
    let id = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, &host).await?
    };
    let auth = gate::authorize(&app, &Principal::of(&me), &id, &Action::Direct).await?;
    let done = start(&app, &auth, req).await;
    gate::finish(&app, auth, done.is_ok()).await?;
    Ok(Json(done?))
}

async fn start(app: &App, auth: &Authorized, req: NewDirect) -> Result<DirectView, ApiError> {
    let host = auth.host_id();
    let ttl = req.ttl_secs.unwrap_or(DEFAULT_TTL);
    if !(MIN_TTL..=SSH_AGENT_MAX_TTL_SECS).contains(&ttl) {
        return Err(ApiError::bad_request("ttl_secs is 60 to 43200"));
    }
    let jumps: String = {
        let mut conn = app.pool.acquire().await?;
        sqlx::query_scalar("SELECT jump_chain FROM leyline_hosts WHERE id = ?")
            .bind(host)
            .fetch_one(&mut *conn)
            .await?
    };
    let mut chain: Vec<String> = serde_json::from_str(&jumps).unwrap_or_default();
    chain.push(host.to_owned());
    let mut stops = Vec::new();
    for h in &chain {
        let s = stop(app, h).await?;
        if s.pinned.is_empty() {
            return Err(refuse(
                "host_not_trusted",
                "every machine on the path needs a trusted host key first",
            ));
        }
        stops.push(s);
    }
    let runner = pick_runner(app, req.runner)?;
    let id = new_id("ld_");
    let expires = app.clock.unix() + i64::from(ttl);
    let started = open_row(app, &id, host, &runner, auth, expires).await?;
    let loaded = load(app, &id, &runner, ttl, &stops).await;
    let loaded = match loaded {
        Ok(l) => l,
        Err(e) => {
            // The runner may or may not have started it: a drop makes sure it did not.
            let _ = end(app, &id, "failed").await;
            return Err(e);
        }
    };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("UPDATE leyline_direct SET socket = ? WHERE id = ?")
        .bind(&loaded.socket)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    note(
        &mut tx,
        "leased",
        &id,
        host,
        json!({"runner": runner, "ttl_secs": ttl}),
    )
    .await?;
    tx.commit().await?;
    watch(app.clone(), id.clone(), expires);
    Ok(DirectView {
        ready: ready(&loaded.config, &stops),
        id,
        host_id: host.to_owned(),
        runner,
        socket: loaded.socket,
        started_at: started,
        expires_at: iso_of_unix(expires),
    })
}

/// The row that makes the lease exist (and the key list of the runner follow it), or 409.
async fn open_row(
    app: &App,
    id: &str,
    host: &str,
    runner: &str,
    auth: &Authorized,
    expires: i64,
) -> Result<String, ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    let inserted = sqlx::query_scalar::<_, String>(
        "INSERT INTO leyline_direct (id, host_id, runner, principal, run_id, expires_at, expires_unix) \
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING started_at",
    )
    .bind(id)
    .bind(host)
    .bind(runner)
    .bind(auth.principal().label())
    .bind(auth.run_id())
    .bind(iso_of_unix(expires))
    .bind(expires)
    .fetch_one(&mut *tx)
    .await;
    let started = match inserted {
        Ok(s) => s,
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => {
            return Err(refuse(
                "already_leased",
                "this host already has an open Mac-direct lease; revoke it first",
            ));
        }
        Err(e) => return Err(e.into()),
    };
    tx.commit().await?;
    Ok(started)
}

/// Mints one single-use lease of each key for the runner (the keys' stored scope unchanged) and has
/// the runner load the agent.
async fn load(
    app: &App,
    id: &str,
    runner: &str,
    ttl: u32,
    stops: &[Stop],
) -> Result<ainkrad_proto::v2::SshAgentLoaded, ApiError> {
    let mut keys = Vec::new();
    let mut leased: Vec<String> = Vec::new();
    for s in stops {
        match mint(app, &s.secret, runner).await {
            Ok(lease) => {
                leased.push(lease.clone());
                keys.push(AgentKey {
                    lease,
                    pinned_keys: s.pinned.clone(),
                    user: s.user.clone(),
                });
            }
            Err(e) => {
                revoke(app, runner, &leased);
                return Err(e);
            }
        }
    }
    let cmd = SshAgentCommand::Load(SshAgentLoad {
        id: id.to_owned(),
        ttl_secs: ttl,
        keys,
    });
    let answer = call(app, runner, cmd, LOAD_WAIT).await;
    // Whatever happened, a lease the runner did not redeem is of no use to anyone.
    revoke(app, runner, &leased);
    match answer? {
        Body::Result(Reply::SshAgentLoad(l)) if sane(&l.socket) && sane(&l.config) => Ok(l),
        _ => Err(wrong(
            "runner_failed",
            "the runner answered the agent oddly",
        )),
    }
}

/// Opens key `secret` (a `leyline.` name: `open_for_module` opens nothing else) and holds its
/// OpenSSH text for `runner` under a fresh lease id, redeemable once, for `MINT_SECS`.
async fn mint(app: &App, secret: &str, runner: &str) -> Result<String, ApiError> {
    let sealer = app.secrets.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "secrets_unavailable",
            "this Core has no master key loaded",
        )
    })?;
    let b64 = secrets::open_for_module(&app.pool, sealer, crate::MODULE, secret, "direct").await?;
    // A key's value is its OpenSSH text in base64 (`file` kind); the runner takes text as it is.
    let raw = Zeroizing::new(
        STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| wrong("runner_failed", "a stored key is unusable"))?,
    );
    let text = Zeroizing::new(
        std::str::from_utf8(&raw)
            .map_err(|_| wrong("runner_failed", "a stored key is unusable"))?
            .to_owned(),
    );
    let lease = new_id("l_");
    let now = app.clock.unix();
    let held = Ephemeral {
        runner: runner.to_owned(),
        var: secret.to_owned(),
        value: text,
        expires: now + MINT_SECS,
    };
    if !app.agents.stash(&lease, held, now) {
        return Err(wrong(
            "runner_busy",
            "too many credentials await redemption",
        ));
    }
    Ok(lease)
}

/// Takes back every minted lease the runner did not redeem.
fn revoke(app: &App, runner: &str, leases: &[String]) {
    for l in leases {
        let _ = app.agents.take_ephemeral(l, runner, i64::MIN);
    }
}

#[utoipa::path(post, path = "/hosts/{host}/direct/revoke", operation_id = "leylineRevokeDirect", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")),
    responses((status = 200, description = "The agent is dropped on the runner (the keys are wiped and every connection closes within seconds) and the lease ends. 404 when the host has no open lease", body = DirectEnded)))]
pub(crate) async fn revoke_route(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
) -> ApiResult<DirectEnded> {
    let id = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, &host).await?
    };
    let auth = gate::authorize(&app, &Principal::of(&me), &id, &Action::Direct).await?;
    let done = revoke_host(&app, auth.host_id()).await;
    gate::finish(&app, auth, done.is_ok()).await?;
    Ok(Json(done?))
}

async fn revoke_host(app: &App, host: &str) -> Result<DirectEnded, ApiError> {
    let none = || ApiError::not_found("this host has no open Mac-direct lease");
    let id: String =
        sqlx::query_scalar("SELECT id FROM leyline_direct WHERE host_id = ? AND ended_at IS NULL")
            .bind(host)
            .fetch_optional(&app.pool)
            .await?
            .ok_or_else(none)?;
    end(app, &id, "revoked").await?.ok_or_else(none)
}

/// Ends lease `id` once (a revoke and the timer racing: the first wins), drops the agent, records
/// the count and gives the runner back its place in the key lists. `None`: already over.
async fn end(app: &App, id: &str, reason: &'static str) -> Result<Option<DirectEnded>, ApiError> {
    let claimed: Option<(String, String)> = sqlx::query_as(
        "UPDATE leyline_direct SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), end_reason = ? \
         WHERE id = ? AND ended_at IS NULL RETURNING host_id, runner",
    )
    .bind(reason)
    .bind(id)
    .fetch_optional(&app.pool)
    .await?;
    let Some((host, runner)) = claimed else {
        return Ok(None);
    };
    let dropping = SshAgentCommand::Drop(SshAgentDrop { id: id.to_owned() });
    let (signatures, reached) = match call(app, &runner, dropping, DROP_WAIT).await {
        Ok(Body::Result(Reply::SshAgentDrop(d))) => {
            (i64::try_from(d.signatures).unwrap_or(i64::MAX), true)
        }
        _ => (0, false),
    };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("UPDATE leyline_direct SET signatures = ?, runner_reached = ? WHERE id = ?")
        .bind(signatures)
        .bind(reached)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let op = match reason {
        "revoked" => "revoked",
        "expired" => "expired",
        _ => "failed",
    };
    let extra = json!({"runner": runner, "signatures": signatures, "runner_reached": reached});
    note(&mut tx, op, id, &host, extra).await?;
    tx.commit().await?;
    Ok(Some(DirectEnded {
        id: id.to_owned(),
        signatures,
        runner_reached: reached,
    }))
}

async fn note(
    conn: &mut SqliteConnection,
    op: &str,
    id: &str,
    host: &str,
    extra: Value,
) -> Result<(), sqlx::Error> {
    let mut details = json!({"direct": id, "host": host});
    if let (Some(d), Some(e)) = (details.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.direct.{op}"),
        entity: None,
        details: details.to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(
        conn,
        "leyline.direct",
        &json!({"op": op, "id": id, "host": host}),
    )
    .await?;
    Ok(())
}

/// Ends lease `id` when its time comes. It looks again at least once a minute, so a lease that
/// ended some other way (a revoke) stops its watcher, and a changed clock is followed.
fn watch(app: App, id: String, expires: i64) {
    tokio::spawn(async move {
        loop {
            let left = expires - app.clock.unix();
            if left <= 0 {
                break;
            }
            let nap = u64::try_from(left.min(60)).unwrap_or(1);
            tokio::time::sleep(Duration::from_secs(nap)).await;
            let open: Result<Option<i64>, _> = sqlx::query_scalar(
                "SELECT 1 FROM leyline_direct WHERE id = ? AND ended_at IS NULL",
            )
            .bind(&id)
            .fetch_optional(&app.pool)
            .await;
            if matches!(open, Ok(None)) {
                return;
            }
        }
        if end(&app, &id, "expired").await.is_err() {
            tracing::warn!("a leyline direct lease could not be ended at its time");
        }
    });
}

/// At Core start: leases still open belong to agents that run on without us; each is watched again.
pub(crate) async fn resume(app: &App) -> Result<(), ApiError> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT id, expires_unix FROM leyline_direct WHERE ended_at IS NULL")
            .fetch_all(&app.pool)
            .await?;
    for (id, expires) in rows {
        watch(app.clone(), id, expires);
    }
    let app = app.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REDROP_EVERY).await;
            if redrop(&app).await.is_err() {
                tracing::warn!("leyline direct drops could not be sent again");
            }
        }
    });
    Ok(())
}

/// Sends the drop again for every ended lease whose runner never answered it, now that the runner
/// is online (it said hello again, or the link came back). A lease past its own deadline is left:
/// the runner's wall-clock deadline has ended that agent already. Returns how many were reached.
pub(crate) async fn redrop(app: &App) -> Result<usize, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, runner FROM leyline_direct \
         WHERE ended_at IS NOT NULL AND runner_reached = 0 AND expires_unix > ?",
    )
    .bind(app.clock.unix() - SKEW_SECS)
    .fetch_all(&app.pool)
    .await?;
    let mut reached = 0;
    for (id, runner) in rows {
        if !app.hub.online(&runner) {
            continue;
        }
        let dropping = SshAgentCommand::Drop(SshAgentDrop { id: id.clone() });
        let Ok(Body::Result(Reply::SshAgentDrop(d))) =
            call(app, &runner, dropping, DROP_WAIT).await
        else {
            continue;
        };
        let signatures = i64::try_from(d.signatures).unwrap_or(i64::MAX);
        let mut tx = begin_write(&app.pool).await?;
        sqlx::query(
            "UPDATE leyline_direct SET runner_reached = 1, \
             signatures = max(coalesce(signatures, 0), ?) WHERE id = ?",
        )
        .bind(signatures)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
        let host: String = sqlx::query_scalar("SELECT host_id FROM leyline_direct WHERE id = ?")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?;
        let extra = json!({"runner": runner, "signatures": signatures, "runner_reached": true});
        note(&mut tx, "dropped", &id, &host, extra).await?;
        tx.commit().await?;
        reached += 1;
    }
    Ok(reached)
}
