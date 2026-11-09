//! Runners from the app (E11.9, protocol 1.20), mirroring `citadel-server runner add|revoke`:
//! every runner with what it reports of itself (harness versions, slots, uptime, logins per
//! harness and account, its last sleep), register one (its key shown once), drain and undrain,
//! remove, the tail of its own log (read from it while it is connected, redacted), and the
//! admin's Power Nap preference for it. Runners belong to no company (the admin's own).

use std::collections::BTreeMap;
use std::time::Duration;

use citadel_core::exec::{self as core, NewRunner, RunnerId, RunnerStatus as CoreStatus};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::{RunnerStatus, Timestamp, opt_ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::api::runner::{ProbeFail, harness_policy};
use crate::store::exec::{self, DeleteRunnerError, RunnerState};
use crate::store::{gov, settings};
use citadel_core::settings::{Key, Scope};
use ainkrad_harness::compat;

/// Where a harness or account logs in on the runner's host, and whether it is.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerLogin {
    /// Under the runner's config root (`claude`, `accounts/claude-a`), or
    /// `credentials/<file>` for an account's token file.
    pub dir: String,
    /// The harness, when the dir is a harness's own.
    pub harness: Option<String>,
    /// `logged_in`, `logged_out`, or `unknown` (the login lives in the keychain) — open.
    pub state: String,
    /// The accounts that log in there.
    pub account_ids: Vec<i64>,
}

/// One harness the runner can drive, judged against Citadel's tested versions (E3.6).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerHarness {
    pub name: String,
    /// What it reported; absent when not installed.
    pub version: Option<String>,
    /// `supported` (a tested version), `untested_newer` (newer than tested; runs unless the
    /// settings refuse it), `too_old`, `known_bad`, `missing`, `unreadable` or
    /// `unknown_harness` — open.
    pub status: String,
    /// Whether runs are dispatched to it.
    pub offered: bool,
    /// The newest version Citadel's adapter was tested against.
    pub tested_up_to: Option<String>,
    /// Why it is refused, or the note on an untested version.
    pub reason: Option<String>,
}

/// Every known harness, then any other `reported` one, judged under `policy`.
fn harness_status(
    reported: &BTreeMap<String, String>,
    policy: &compat::Policy,
) -> Vec<RunnerHarness> {
    let known = compat::COMPAT.iter().map(|c| c.harness.to_owned());
    let others = reported
        .keys()
        .filter(|h| compat::compat(h).is_none())
        .cloned();
    known
        .chain(others)
        .map(|name| {
            let version = reported.get(&name).cloned();
            let v = compat::check(&name, version.as_deref(), policy);
            RunnerHarness {
                status: v.status.as_str().to_owned(),
                offered: v.offered(),
                tested_up_to: v.tested_up_to.map(str::to_owned),
                reason: v.reason,
                name,
                version,
            }
        })
        .collect()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Runner {
    pub id: i64,
    pub name: String,
    pub tags: Vec<String>,
    pub status: RunnerStatus,
    pub last_seen_at: Option<Timestamp>,
    /// Why it is unhealthy, when it is.
    pub health_reason: Option<String>,
    /// When the admin asked to wake it (`wakeRunner`); absent once it connects.
    pub wake_requested_at: Option<Timestamp>,
    /// `now` or `when_back`, with `wake_requested_at`.
    pub wake_mode: Option<String>,
    /// Harness → version, from its last hello.
    pub harnesses: BTreeMap<String, String>,
    /// Every harness with how its reported version stands against the tested ones (API
    /// minor 10), under the runner's current settings.
    pub harness_status: Vec<RunnerHarness>,
    /// Runs it works at once, as it reported.
    pub slots: Option<u32>,
    /// Seconds it had been up at `reported_at`; absent while it is offline.
    pub uptime_secs: Option<u64>,
    /// When it last reported its state (runner protocol 1.20).
    pub reported_at: Option<Timestamp>,
    pub logins: Vec<RunnerLogin>,
    /// An offline Mac: most likely asleep (the "Wake my Mac" case).
    pub asleep: bool,
    /// How long its machine last slept, as it reported after waking.
    pub last_slept_secs: Option<u64>,
    /// When the admin drained it: it takes no new run; its runs finish.
    pub drained_at: Option<Timestamp>,
    /// The admin's Power Nap preference for it; absent, none set.
    pub power_nap: Option<bool>,
    /// The preference the runner says it holds.
    pub power_nap_applied: Option<bool>,
    /// Its operating system as it said in its hello (runner protocol 1.25; API minor 17), as
    /// Rust names it: `macos`, `linux`, `windows`. Absent until it says (an older runner never
    /// does).
    pub os: Option<String>,
    /// Its CPU architecture, as Rust names it: `aarch64`, `x86_64`.
    pub arch: Option<String>,
}

/// The runner with its reported state; `accounts` name who logs in where.
pub fn view(
    r: core::Runner,
    state: Option<&RunnerState>,
    accounts: &[citadel_core::gov::Account],
    policy: &compat::Policy,
) -> Runner {
    let info = state.and_then(|s| s.info.as_ref());
    let online = r.status != CoreStatus::Offline;
    let logins = info.map_or_else(Vec::new, |i| {
        i.logins
            .iter()
            .map(|l| RunnerLogin {
                dir: l.dir.clone(),
                harness: l.harness.clone(),
                state: l.state.clone(),
                account_ids: accounts
                    .iter()
                    .filter(|a| {
                        a.config_dir == l.dir
                            || a.credential_ref
                                .as_ref()
                                .is_some_and(|c| format!("credentials/{c}") == l.dir)
                    })
                    .map(|a| a.id.0)
                    .collect(),
            })
            .collect()
    });
    Runner {
        // ponytail: a sleeping Mac and a stopped one look the same from here (both dropped
        // the socket); a goodbye message from a stopping runner would tell them apart.
        asleep: !online && r.tags.iter().any(|t| t == "macos"),
        harness_status: harness_status(state.map_or(&BTreeMap::new(), |s| &s.harnesses), policy),
        harnesses: state.map(|s| s.harnesses.clone()).unwrap_or_default(),
        slots: info.map(|i| i.slots),
        uptime_secs: info.filter(|_| online).map(|i| i.uptime_secs),
        reported_at: opt_ts(state.and_then(|s| s.info_at.as_deref())),
        logins,
        last_slept_secs: info.and_then(|i| i.slept_secs),
        drained_at: opt_ts(r.drained_at.as_deref()),
        power_nap: r.power_nap,
        power_nap_applied: info.and_then(|i| i.power_nap),
        os: state.and_then(|s| s.os.clone()),
        arch: state.and_then(|s| s.arch.clone()),
        id: r.id.0,
        name: r.name,
        tags: r.tags,
        status: r.status.into(),
        last_seen_at: opt_ts(r.last_seen_at.as_deref()),
        health_reason: r.health_reason,
        wake_requested_at: opt_ts(r.wake_requested_at.as_deref()),
        wake_mode: r.wake_mode,
    }
}

/// `r` as the app shows it.
pub async fn shown(app: &App, r: core::Runner) -> Result<Runner, ApiError> {
    let states = exec::runner_states(&app.pool).await?;
    let accounts = gov::list_accounts(&app.pool).await?;
    let state = states.get(&r.id.0);
    let policy = harness_policy(&app.pool, r.id).await;
    Ok(view(r, state, &accounts, &policy))
}

async fn found(app: &App, id: i64) -> Result<core::Runner, ApiError> {
    exec::get_runner(&app.pool, RunnerId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no runner {id}")))
}

#[utoipa::path(get, path = "/api/v1/runners", operation_id = "listRunners", tag = "org",
    responses((status = 200, description = "Every runner, its health and what it reports of \
        itself", body = Vec<Runner>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Runner>> {
    let states = exec::runner_states(&app.pool).await?;
    let accounts = gov::list_accounts(&app.pool).await?;
    let mut shown = vec![];
    for r in exec::list_runners(&app.pool).await? {
        let state = states.get(&r.id.0);
        let policy = harness_policy(&app.pool, r.id).await;
        shown.push(view(r, state, &accounts, &policy));
    }
    Ok(Json(shown))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewRunnerBody {
    /// Unique; 1–64 characters.
    pub name: String,
    /// Capabilities it offers, e.g. `macos`, `xcode`; it may send its own when it connects.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A registered runner and its key: shown only now, never stored (only its hash is).
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisteredRunner {
    pub runner: Runner,
    pub key: String,
}

#[utoipa::path(post, path = "/api/v1/runners", operation_id = "registerRunner", tag = "org",
    request_body = NewRunnerBody,
    responses((status = 200, description = "The new runner, offline, and its key, shown only \
        now (audited as `runner.registered`)", body = RegisteredRunner)))]
pub async fn register(
    State(app): State<App>,
    Json(b): Json<NewRunnerBody>,
) -> ApiResult<RegisteredRunner> {
    let name = b.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::bad_request("a runner's name is 1-64 characters"));
    }
    let new = NewRunner {
        name: name.clone(),
        tags: b.tags,
    };
    let (r, key) = match exec::add_runner(&app.pool, &new, BY).await {
        Ok(added) => added,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::conflict(format!("runner name {name:?} is taken")));
        }
        Err(e) => return Err(e.into()),
    };
    Ok(Json(RegisteredRunner {
        runner: shown(&app, r).await?,
        key,
    }))
}

async fn drain(app: App, id: i64, on: bool) -> ApiResult<Runner> {
    let now = app.clock.now();
    let r = exec::drain_runner(&app.pool, RunnerId(id), on, BY, &now)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no runner {id}")))?;
    Ok(Json(shown(&app, r).await?))
}

#[utoipa::path(post, path = "/api/v1/runners/{id}/drain", operation_id = "drainRunner",
    tag = "org", params(("id" = i64, Path, description = "Runner id")),
    responses((status = 200, description = "The runner, drained: it takes no new run and its \
        runs finish (audited as `runner.drained`)", body = Runner)))]
pub async fn drain_runner(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Runner> {
    drain(app, id, true).await
}

#[utoipa::path(delete, path = "/api/v1/runners/{id}/drain", operation_id = "undrainRunner",
    tag = "org", params(("id" = i64, Path, description = "Runner id")),
    responses((status = 200, description = "The runner, taking runs again (audited as \
        `runner.undrained`)", body = Runner)))]
pub async fn undrain_runner(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Runner> {
    drain(app, id, false).await
}

/// A runner that was removed.
#[derive(Debug, Serialize, ToSchema)]
pub struct RemovedRunner {
    pub id: i64,
}

#[utoipa::path(delete, path = "/api/v1/runners/{id}", operation_id = "removeRunner", tag = "org",
    params(("id" = i64, Path, description = "Runner id")),
    responses((status = 200, description = "The runner is gone and its key no longer connects \
        (audited as `runner.removed`); 409 while it holds live runs (drain it, let them end)",
        body = RemovedRunner)))]
pub async fn remove(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<RemovedRunner> {
    match exec::remove_runner(&app.pool, RunnerId(id), Some(BY)).await {
        Ok(true) => Ok(Json(RemovedRunner { id })),
        Ok(false) => Err(ApiError::not_found(format!("no runner {id}"))),
        Err(DeleteRunnerError::LiveRuns(runs)) => {
            let ids: Vec<String> = runs.iter().map(|r| r.0.to_string()).collect();
            Err(ApiError::conflict(format!(
                "runner {id} holds live runs ({}); drain it and let them end",
                ids.join(", ")
            )))
        }
        Err(DeleteRunnerError::Db(e)) => Err(e.into()),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    /// Lines from the end; default and most: `runner.log_tail_max_lines`.
    pub limit: Option<u32>,
}

/// The end of a runner's own log, redacted by the runner and again by the server.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerLog {
    pub runner_id: i64,
    pub lines: Vec<String>,
}

#[utoipa::path(get, path = "/api/v1/runners/{id}/logs", operation_id = "getRunnerLogs",
    tag = "org", params(("id" = i64, Path, description = "Runner id"), LogQuery),
    responses((status = 200, description = "The last lines of its log, read from it now; 409 \
        while it is offline, 502 when it could not read it, 504 when it did not answer within \
        `runner.log_tail_timeout_secs`", body = RunnerLog)))]
pub async fn logs(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<LogQuery>,
) -> ApiResult<RunnerLog> {
    let r = found(&app, id).await?;
    if !app.is_connected(r.id) {
        return Err(ApiError::conflict(format!(
            "runner {id} is offline; its log is read from it while it is connected"
        )));
    }
    let max = settings::value(&app.pool, Key::RunnerLogTailMaxLines, Scope::Server).await?;
    let wait = settings::value(&app.pool, Key::RunnerLogTailTimeoutSecs, Scope::Server).await?;
    let lines = q.limit.unwrap_or(max as u32).clamp(1, max as u32);
    let (request, answer) = app.log_tails.ask(r.id, lines);
    match tokio::time::timeout(Duration::from_secs(wait as u64), answer).await {
        Ok(Ok(Ok(lines))) => Ok(Json(RunnerLog {
            runner_id: id,
            lines,
        })),
        Ok(Ok(Err(why))) => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "runner_error",
            format!("runner {id} could not read its log: {why}"),
        )),
        Ok(Err(_)) | Err(_) => {
            app.log_tails.forget(request);
            Err(ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "runner_timeout",
                format!("runner {id} did not send its log in {wait} s"),
            ))
        }
    }
}

#[utoipa::path(post, path = "/api/v1/runners/{id}/probe", operation_id = "probeRunner",
    tag = "org", params(("id" = i64, Path, description = "Runner id")),
    responses(
        (status = 200, description = "The runner after it looked at itself now (API minor 17): \
            its harness versions and how they stand, its logins and its platform are fresh",
            body = Runner),
        (status = 409, description = "It is offline, or its protocol is older than 1.25 \
            (\"runner too old\")", body = super::types::ErrorBody),
        (status = 502, description = "It could not look", body = super::types::ErrorBody),
        (status = 504, description = "It did not answer within `runner.log_tail_timeout_secs`",
            body = super::types::ErrorBody)))]
pub async fn probe(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Runner> {
    let r = found(&app, id).await?;
    if !app.is_connected(r.id) {
        return Err(ApiError::conflict(format!(
            "runner {id} is offline; it is probed while it is connected"
        )));
    }
    let wait = settings::value(&app.pool, Key::RunnerLogTailTimeoutSecs, Scope::Server).await?;
    let (request, answer) = app.probes.ask(r.id);
    match tokio::time::timeout(Duration::from_secs(wait as u64), answer).await {
        Ok(Ok(Ok(()))) => shown(&app, found(&app, id).await?).await.map(Json),
        Ok(Ok(Err(ProbeFail::TooOld))) => Err(ApiError::conflict(format!(
            "runner {id} is too old to probe (it needs runner protocol 1.25); update it"
        ))),
        Ok(Ok(Err(ProbeFail::Failed(why)))) => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "runner_error",
            format!("runner {id} could not probe itself: {why}"),
        )),
        Ok(Err(_)) | Err(_) => {
            app.probes.forget(request);
            Err(ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "runner_timeout",
                format!("runner {id} did not answer the probe in {wait} s"),
            ))
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PowerNapBody {
    pub enabled: bool,
}

#[utoipa::path(put, path = "/api/v1/runners/{id}/power-nap", operation_id = "setRunnerPowerNap",
    tag = "org", params(("id" = i64, Path, description = "Runner id")), request_body = PowerNapBody,
    responses((status = 200, description = "The runner with the admin's Power Nap preference, \
        stored (audited as `runner.power_nap`) and pushed to it while it is connected; \
        `power_nap_applied` shows once it holds it", body = Runner)))]
pub async fn set_power_nap(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<PowerNapBody>,
) -> ApiResult<Runner> {
    let r = exec::set_power_nap(&app.pool, RunnerId(id), b.enabled, BY)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no runner {id}")))?;
    Ok(Json(shown(&app, r).await?))
}
