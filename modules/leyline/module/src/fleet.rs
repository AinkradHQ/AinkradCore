//! Fleet runs (Y4-03): one pre-set command on many hosts, each host gated and run on its own.
//!
//! Security model (security-flagged).
//! - ONE call to `gate::authorize_many` decides the whole fleet: one run, at most one approval for
//!   every `ask` host together, and one `Authorized` per allowed host. Nothing here decides or
//!   widens access: a host without an `Authorized` never runs. Targets only choose WHICH hosts the
//!   gate is asked about; the gate alone applies the command's scope, rule and confirm semantics,
//!   and a host it refuses is stored `refused` with its reason.
//! - Every host's steps run through `exec::run`, which calls `gate::still_valid` before each step
//!   and sends only through `dispatch_ssh_exec`. This file sends nothing itself.
//! - Cancel reaches no host: it ends the run (so `still_valid` refuses every later step), skips
//!   queued hosts and stops waiting on running ones. It needs the same device scope as a run.
//! - Results are per host (`leyline_run_hosts`), output redacted and capped by `exec`; a reason is a
//!   fixed sentence. Events and audit rows carry ids and states only.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::SqliteConnection;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use utoipa::ToSchema;

use crate::commands::{find_cmd, load_view};
use crate::exec::{self, Cancel, stopped};
use crate::gate::{Action, Authorized, Principal, authorize_many, finish};
use crate::hosts::{In, find};

/// Hosts running at once; the rest of the fleet waits for a slot.
const CONCURRENCY: usize = 8;
/// Most hosts one fleet names (the gate's own limit).
const MAX_HOSTS: usize = 100;
const ROLES: &[&str] = &["production", "staging", "development", "other"];

/// Fleets in flight, by run id: the sender that stops them.
static LIVE: LazyLock<Mutex<HashMap<String, watch::Sender<bool>>>> = LazyLock::new(Mutex::default);

#[derive(Deserialize, ToSchema)]
pub struct FleetRequest {
    /// Command id, else its unique name.
    pub command: String,
    /// Host ids or labels.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Every host in this group.
    pub group: Option<String>,
    /// Every host with this tag.
    pub tag: Option<String>,
    /// Every host attached to this Core project (id), optionally only with `role`.
    pub project: Option<String>,
    pub role: Option<String>,
    /// Must be `true` when the command's `confirm` flag is set.
    pub confirm: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct FleetStarted {
    /// The run's id (`lr_...`); read it with `GET /runs/{run}`, one result per host.
    pub run: String,
    /// `running`, or `denied` when no host may run it (the reasons are on the run).
    pub state: String,
    /// Hosts past the gate.
    pub started: usize,
    /// Hosts the gate refused, each stored with a reason.
    pub refused: usize,
}

#[derive(Serialize, ToSchema)]
pub struct Cancelled {
    pub run: String,
}

/// Every host the request names, once, in the order named.
async fn targets(conn: &mut SqliteConnection, r: &FleetRequest) -> Result<Vec<String>, ApiError> {
    if r.hosts.len() > MAX_HOSTS {
        return Err(ApiError::bad_request("name at most 100 hosts"));
    }
    if r.role.is_some() && r.project.is_none()
        || r.role.as_deref().is_some_and(|x| !ROLES.contains(&x))
    {
        return Err(ApiError::bad_request(
            "role is production, staging, development or other, and needs a project",
        ));
    }
    let mut ids: Vec<String> = Vec::new();
    for h in &r.hosts {
        ids.push(find(conn, &h.chars().take(256).collect::<String>()).await?);
    }
    let by = [
        (
            "SELECT id FROM leyline_hosts WHERE group_name = ?1 COLLATE NOCASE AND ?2 IS ?2 ORDER BY name",
            r.group.as_ref(),
        ),
        (
            "SELECT leyline_hosts.id FROM leyline_hosts, json_each(tags) WHERE value = ?1 AND ?2 IS ?2 ORDER BY name",
            r.tag.as_ref(),
        ),
        (
            "SELECT host_id FROM leyline_project_hosts WHERE project = ?1 AND (?2 IS NULL OR role = ?2) ORDER BY host_id",
            r.project.as_ref(),
        ),
    ];
    for (sql, value) in by {
        if let Some(v) = value {
            let found: Vec<String> = sqlx::query_scalar(sql)
                .bind(v.chars().take(256).collect::<String>())
                .bind(&r.role)
                .fetch_all(&mut *conn)
                .await?;
            ids.extend(found);
        }
    }
    let mut seen = HashSet::new();
    ids.retain(|i| seen.insert(i.clone()));
    if ids.is_empty() {
        return Err(ApiError::bad_request(
            "name hosts, or a group, tag or project that has some",
        ));
    }
    if ids.len() > MAX_HOSTS {
        return Err(ApiError::bad_request("that is more than 100 hosts"));
    }
    Ok(ids)
}

#[utoipa::path(post, path = "/fleet/runs", operation_id = "leylineStartFleetRun", tag = "leyline",
    request_body = FleetRequest,
    responses((status = 200, description = "Past the gate once for the whole fleet: each allowed host runs the steps in the background (8 at a time), the others are `refused` with a reason; read the run for one result per host. 409 when the command needs `confirm`", body = FleetStarted)))]
pub(crate) async fn start(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<FleetRequest>,
) -> ApiResult<FleetStarted> {
    let (cmd, ids) = {
        let mut conn = app.pool.acquire().await?;
        let id = find_cmd(&mut conn, &req.command).await?;
        let cmd = load_view(&mut conn, &id).await?;
        if cmd.confirm && req.confirm != Some(true) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "confirm_required",
                "this command must be confirmed: send confirm true",
            ));
        }
        (cmd, targets(&mut conn, &req).await?)
    };
    let hosts: Vec<&str> = ids.iter().map(String::as_str).collect();
    let gated = authorize_many(&app, &Principal::of(&me), &hosts, &Action::Preset(cmd.id)).await?;
    let (started, refused) = (gated.authorized.len(), gated.refused.len());
    if started > 0 {
        let (tx, rx) = watch::channel(false);
        LIVE.lock().unwrap().insert(gated.run.clone(), tx);
        tokio::spawn(drive(app.clone(), gated.run.clone(), gated.authorized, rx));
    }
    Ok(Json(FleetStarted {
        run: gated.run,
        state: if started > 0 { "running" } else { "denied" }.to_owned(),
        started,
        refused,
    }))
}

#[utoipa::path(post, path = "/runs/{run}/cancel", operation_id = "leylineCancelRun", tag = "leyline",
    params(("run" = String, Path, description = "The run's id")),
    responses((status = 200, description = "The run is cancelled: queued hosts are skipped, running hosts stop at once from the Core's side. 404 no such run, 409 it is not running", body = Cancelled)))]
pub(crate) async fn cancel(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(run): Path<String>,
) -> ApiResult<Cancelled> {
    let run: String = run.chars().take(64).collect();
    let mut tx = begin_write(&app.pool).await?;
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM leyline_runs WHERE id = ?")
        .bind(&run)
        .fetch_optional(&mut *tx)
        .await?;
    match state.as_deref() {
        None => return Err(ApiError::not_found("no such run")),
        Some("running") => {}
        Some(_) => return Err(ApiError::conflict("the run is not running")),
    }
    sqlx::query(
        "UPDATE leyline_runs SET state = 'cancelled', ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(&run)
    .execute(&mut *tx)
    .await?;
    let row = NewAuditEvent {
        actor: BY,
        action: "leyline.run.cancelled".to_owned(),
        entity: None,
        details: json!({"run": run}).to_string(),
    };
    audit::append_as(&mut tx, &row, Principal::of(&me).origin())
        .await
        .map_err(|e| ApiError::from(sqlx::Error::Protocol(e.to_string())))?;
    events::append(
        &mut tx,
        "leyline.run",
        &json!({"run": run, "state": "cancelled"}),
    )
    .await?;
    tx.commit().await?;
    // Now `still_valid` refuses every later step; this also ends the wait on a step in flight.
    if let Some(s) = LIVE.lock().unwrap().get(&run) {
        let _ = s.send(true);
    }
    Ok(Json(Cancelled { run }))
}

/// Runs every authorised host, `CONCURRENCY` at a time, then tells the world the run ended.
async fn drive(app: App, run: String, fleet: Vec<Authorized>, stop: Cancel) {
    let cancel = Some(stop);
    let work = {
        let (app, cancel) = (app.clone(), cancel.clone());
        move |auth: Authorized, got: bool| host(app.clone(), auth, cancel.clone(), got)
    };
    spread(fleet, CONCURRENCY, &cancel, work).await;
    LIVE.lock().unwrap().remove(&run);
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM leyline_runs WHERE id = ?")
        .bind(&run)
        .fetch_optional(&app.pool)
        .await
        .unwrap_or(None);
    announce(&app, json!({"run": run, "state": state})).await;
}

/// Calls `work(item, true)` for every item with at most `limit` at once; an item still waiting for
/// a slot when `cancel` fires gets `work(item, false)` instead. Returns when all are done.
async fn spread<T, F, Fut>(items: Vec<T>, limit: usize, cancel: &Option<Cancel>, work: F)
where
    T: Send + 'static,
    F: Fn(T, bool) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (slots, work) = (Arc::new(Semaphore::new(limit)), Arc::new(work));
    let mut set = JoinSet::new();
    for item in items {
        let (slots, work, cancel) = (slots.clone(), work.clone(), cancel.clone());
        set.spawn(async move {
            let permit = tokio::select! {
                biased;
                () = stopped(&cancel) => None,
                p = slots.acquire_owned() => p.ok(),
            };
            work(item, permit.is_some()).await;
            drop(permit);
        });
    }
    while set.join_next().await.is_some() {}
}

/// One host: mark it running, run its steps through the gate's checks, report its result.
async fn host(app: App, auth: Authorized, cancel: Option<Cancel>, got_slot: bool) {
    let (run, host) = (auth.run_id().to_owned(), auth.host_id().to_owned());
    let started = got_slot
        && sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'running' WHERE run_id = ? AND host_id = ? AND state = 'queued'",
        )
        .bind(&run)
        .bind(&host)
        .execute(&app.pool)
        .await
        .is_ok_and(|r| r.rows_affected() == 1);
    if started {
        announce(&app, json!({"run": run, "host": host, "state": "running"})).await;
        exec::run(app.clone(), auth, cancel).await;
    } else {
        let _ = sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'skipped', reason = 'cancelled' WHERE run_id = ? AND host_id = ? AND state = 'queued'",
        )
        .bind(&run)
        .bind(&host)
        .execute(&app.pool)
        .await;
        // Spends the `Authorized` and lets the run close if this was its last host.
        if let Err(e) = finish(&app, auth, false).await {
            tracing::error!(error = %e.message, "closing a skipped fleet host failed");
        }
    }
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM leyline_run_hosts WHERE run_id = ? AND host_id = ?")
            .bind(&run)
            .bind(&host)
            .fetch_optional(&app.pool)
            .await
            .unwrap_or(None);
    announce(&app, json!({"run": run, "host": host, "state": state})).await;
}

/// Live progress: a `leyline.run` event (ids and states only).
async fn announce(app: &App, payload: Value) {
    let sent = async {
        let mut tx = begin_write(&app.pool).await?;
        events::append(&mut tx, "leyline.run", &payload).await?;
        tx.commit().await
    };
    if let Err(e) = sent.await {
        tracing::error!(error = %e, "announcing a leyline run failed");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    /// 20 hosts, one stuck: the other 19 still finish, never more than 8 run at once, and the
    /// stuck one ends the moment it is let go.
    #[tokio::test]
    async fn one_slow_host_does_not_block_the_others() {
        let n = || Arc::new(AtomicUsize::new(0));
        let (live, peak, done) = (n(), n(), n());
        let release = Arc::new(Notify::new());
        let work = {
            let (live, peak, done, release) =
                (live.clone(), peak.clone(), done.clone(), release.clone());
            move |i: usize, got: bool| {
                let (live, peak, done, release) =
                    (live.clone(), peak.clone(), done.clone(), release.clone());
                async move {
                    assert!(got);
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    if i == 0 {
                        release.notified().await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        done.fetch_add(1, Ordering::SeqCst);
                    }
                    live.fetch_sub(1, Ordering::SeqCst);
                }
            }
        };
        let all = tokio::spawn(async move { spread((0..20).collect(), 8, &None, work).await });
        let waited = tokio::time::timeout(Duration::from_secs(5), async {
            while done.load(Ordering::SeqCst) < 19 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "the 19 others were blocked by the slow one");
        assert!(
            peak.load(Ordering::SeqCst) <= 8,
            "{}",
            peak.load(Ordering::SeqCst)
        );
        release.notify_one();
        all.await.unwrap();
    }

    /// A stop while hosts wait for a slot hands each of them `false`: none of them runs.
    #[tokio::test]
    async fn a_stop_skips_the_hosts_still_waiting() {
        let (tx, rx) = watch::channel(false);
        tx.send(true).unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        let work = move |_: usize, got: bool| {
            let r = r.clone();
            async move {
                if got {
                    r.fetch_add(1, Ordering::SeqCst);
                }
            }
        };
        spread((0..5).collect(), 2, &Some(rx), work).await;
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }
}
