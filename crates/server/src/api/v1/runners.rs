//! Runners (E1-11.6): every paired runner with its live state from the hub (`crate::hub`), and
//! the no-op command end to end (`ainkradctl run noop`). A runner's presence also goes out as
//! the `runner.connected`, `runner.disconnected` and `runner.degraded` events.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_proto::v2::{ErrorCode, StreamError};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::hub::RunnerState;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::gov;

/// The audit action of a command sent through the API.
pub const COMMAND: &str = "runner.command";

/// How long `noop` waits for its answer (under the gateway's request deadline).
const NOOP_WAIT: Duration = Duration::from_secs(20);

/// A driver a runner offers, as it advertised it.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerDriver {
    /// `exec` now; `pty`, `harness` later.
    pub name: Option<String>,
    /// The command ops it takes: `noop`, `exec.run`.
    pub commands: Option<Vec<String>>,
    /// How many of its commands run at once (`agent`: sessions).
    pub capacity: Option<u32>,
    /// `agent`: how many sessions each harness may run at once (E2-08.1); absent, no split.
    pub slots: Option<std::collections::BTreeMap<String, u32>>,
}

/// A paired runner and its live state.
#[derive(Debug, Serialize, ToSchema)]
pub struct Runner {
    /// The runner's device id, `d_…`.
    pub id: String,
    pub name: String,
    /// Connected to this Core now.
    pub online: Option<bool>,
    /// Connected but silent past two heartbeats.
    pub degraded: Option<bool>,
    /// Its last frame or request; null if never seen.
    pub last_seen: Option<Timestamp>,
    /// What it last advertised (empty until it first connected since the Core started).
    pub drivers: Option<Vec<RunnerDriver>>,
    /// Commands it takes at once.
    pub capacity: Option<u32>,
    /// Commands in flight.
    pub load: Option<u32>,
    /// The host's load as its runner last reported it (E2-15.2), if it has.
    pub host_load: Option<RunnerHostLoad>,
    /// Its `ainkrad-runner` version, once connected.
    pub version: Option<String>,
    /// The CPU architecture it reported (`aarch64`, `x86_64`), once connected.
    pub arch: Option<String>,
    /// The isolation it offers now (E8a-09): absent until it reports, and then no tier can be
    /// assumed.
    pub isolation: Option<RunnerIsolation>,
    /// `linux` or `macos`, once connected.
    pub os: Option<String>,
    /// The system as a person names it, `Ubuntu 26.04`, as the runner reported it.
    pub os_pretty: Option<String>,
    /// The user the runner process runs as, and whether that is root.
    pub runs_as: Option<RunnerRunsAs>,
    /// `process` when the runner offers a process sandbox for agents, else `none`; absent when it
    /// did not report (agents off).
    pub sandbox: Option<String>,
    /// When its current connection began; absent when it is offline.
    pub connected_since: Option<Timestamp>,
    /// This Core's own version is newer than the runner's `version`. Absent until it connected.
    pub update_available: Option<bool>,
    /// Whether it can serve the accounts' kinds of key, with the reason when it cannot.
    pub accounts: Option<RunnerAccounts>,
    /// Sessions and terminals running now, and how many it takes.
    pub slots: Option<RunnerSlots>,
    /// Tools it found on its host, name to version (`claude` to `2.1.318`, `git`, `node`, `python`,
    /// `go`, `rust`, `docker`, `codex`); a tool that is not installed is not listed.
    pub tools: Option<std::collections::BTreeMap<String, String>>,
    /// Harnesses with a login of their own on its host (`claude`, `codex`, ...); a plain session
    /// of one is not refused as `no_account`. Absent until a runner of this version connected.
    pub own_logins: Option<Vec<String>>,
    /// The runner `runner-enroll-local` made on the Core's own machine (the installer's).
    pub built_in: Option<bool>,
    /// What the runner offers now: terminals, agents, agent capacity (`PUT /runners/{id}/policy`
    /// sets it). Absent until a runner of this version connected.
    pub policy: Option<super::runner_control::RunnerPolicyBody>,
}

/// Who the runner process is.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerRunsAs {
    pub user: Option<String>,
    pub root: Option<bool>,
}

/// What a runner can do for accounts: each answer, and why not when it is `false`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerAccounts {
    /// API-key accounts through the auth gateway.
    pub gateway: bool,
    pub gateway_reason: Option<String>,
    /// A subscription's token handed to a session as an environment variable (needs the sandbox
    /// and a proven egress filter).
    pub subscription_env: bool,
    pub subscription_env_reason: Option<String>,
    /// Sessions' network is filtered by an allow list.
    pub egress_filter: bool,
    pub egress_filter_reason: Option<String>,
}

/// A runner's work, split by kind.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerSlots {
    /// Agent sessions starting, running or interrupted on it.
    pub agents_used: u32,
    /// How many agent sessions it takes at once; absent when agents are off or it is unknown.
    pub agents_capacity: Option<u32>,
    /// Terminals created or running on it.
    pub terminals_used: u32,
    /// How many terminals it takes at once; absent when terminals are off or it is unknown.
    pub terminals_capacity: Option<u32>,
}

/// Per runner, what the Core's tables say: live sessions, live terminals, and the built-in mark.
#[derive(Default)]
struct Counts {
    agents: HashMap<String, u32>,
    terminals: HashMap<String, u32>,
    built_in: HashSet<String>,
}

async fn counts(app: &App) -> Result<Counts, sqlx::Error> {
    let by_runner = |sql: &'static str| async move {
        let rows: Vec<(String, i64)> = sqlx::query_as(sql).fetch_all(&app.pool).await?;
        Ok::<_, sqlx::Error>(
            rows.into_iter()
                .map(|(r, n)| (r, u32::try_from(n).unwrap_or(u32::MAX)))
                .collect::<HashMap<_, _>>(),
        )
    };
    Ok(Counts {
        agents: by_runner(
            "SELECT runner, count(*) FROM core_agent_sessions \
             WHERE state IN ('starting', 'running', 'interrupted') GROUP BY runner",
        )
        .await?,
        terminals: by_runner(
            "SELECT runner, count(*) FROM core_terminals \
             WHERE status IN ('created', 'running') GROUP BY runner",
        )
        .await?,
        built_in: sqlx::query_scalar(
            "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? \
             AND device_id IS NOT NULL",
        )
        .bind(gov::LOCAL_ENROL_SAS)
        .fetch_all(&app.pool)
        .await?
        .into_iter()
        .collect(),
    })
}

/// `a.b.c` as numbers, ignoring a suffix; `None` if it is not one.
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v
        .split(['-', '+'])
        .next()?
        .split('.')
        .map(|p| p.parse().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

fn accounts_of(drivers: &[RunnerDriver], iso: Option<&RunnerIsolation>) -> RunnerAccounts {
    let agent = drivers.iter().find(|d| d.name.as_deref() == Some("agent"));
    let has = |cap: &str| agent.is_some_and(|d| d.commands.iter().flatten().any(|c| c == cap));
    let why = |on: bool, what: &str| {
        (!on).then(|| match agent {
            None => "agents are off on this runner (start it with --enable-agents)".to_owned(),
            Some(_) => format!("{what} did not pass its start-up check on this runner"),
        })
    };
    let (gateway, filter) = (has("gateway"), has("egress-filter"));
    let sandboxed = iso
        .and_then(|i| i.tiers.as_ref())
        .is_some_and(|t| t.iter().any(|t| t != "none"));
    let sub = filter && sandboxed;
    RunnerAccounts {
        gateway,
        gateway_reason: why(gateway, "the auth gateway"),
        subscription_env: sub,
        subscription_env_reason: match (sub, filter) {
            (true, _) => None,
            (false, true) => Some("this runner has no process sandbox".to_owned()),
            (false, false) => why(false, "the egress filter"),
        },
        egress_filter: filter,
        egress_filter_reason: why(filter, "the egress filter"),
    }
}

/// The isolation tiers a runner offers and the state of its `/dev/kvm` (E8a-09).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerIsolation {
    /// Tiers offered now, by name: `none`, `process`, `microvm`.
    pub tiers: Option<Vec<String>>,
    /// `not_applicable`, `absent`, `usable` or `unusable`.
    pub kvm: Option<String>,
}

fn of(d: gov::Device, live: Option<&RunnerState>, x: &Extra) -> Runner {
    let used = d.last_used_at.as_deref().and_then(unix_secs);
    let seen = live.map(|s| s.last_seen).into_iter().chain(used).max();
    let n = |v: usize| Some(u32::try_from(v).unwrap_or(u32::MAX));
    let drivers: Vec<RunnerDriver> = live
        .map(|s| s.drivers.clone())
        .unwrap_or_default()
        .into_iter()
        .map(|d| RunnerDriver {
            name: Some(d.name),
            commands: Some(d.commands),
            capacity: Some(d.capacity),
            slots: (!d.slots.is_empty()).then_some(d.slots),
        })
        .collect();
    let capacity_of = |name: &str| {
        drivers
            .iter()
            .find(|d| d.name.as_deref() == Some(name))
            .and_then(|d| d.capacity)
    };
    let isolation = live
        .and_then(|s| s.isolation.as_ref())
        .map(|i| RunnerIsolation {
            tiers: Some(i.tiers.clone()),
            kvm: serde_json::to_value(i.kvm)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned)),
        });
    let version = live.map(|s| s.version.clone()).filter(|v| !v.is_empty());
    let facts = x.facts.as_ref();
    Runner {
        slots: Some(RunnerSlots {
            agents_used: x.agents,
            agents_capacity: capacity_of("agent"),
            terminals_used: x.terminals,
            terminals_capacity: capacity_of("pty"),
        }),
        accounts: live.map(|_| accounts_of(&drivers, isolation.as_ref())),
        sandbox: isolation.as_ref().and_then(|i| i.tiers.as_ref()).map(|t| {
            if t.iter().any(|t| t != "none") {
                "process"
            } else {
                "none"
            }
            .to_owned()
        }),
        os: live.and_then(|s| s.os.clone()),
        os_pretty: facts.and_then(|f| f.os_pretty.clone()),
        runs_as: facts.map(|f| RunnerRunsAs {
            user: f.user.clone(),
            root: f.root,
        }),
        tools: facts.map(|f| f.tools.clone()),
        own_logins: facts.map(|f| f.own_logins.clone()),
        connected_since: x
            .since
            .filter(|_| live.is_some_and(|s| s.online))
            .map(|t| ts(&iso_of_unix(t))),
        update_available: version
            .as_deref()
            .and_then(semver)
            .zip(semver(env!("CARGO_PKG_VERSION")))
            .map(|(runner, core)| core > runner),
        built_in: Some(x.built_in),
        policy: facts.and_then(|f| f.policy).map(Into::into),
        id: d.id,
        name: d.name,
        online: Some(live.is_some_and(|s| s.online)),
        degraded: Some(live.is_some_and(|s| s.degraded)),
        last_seen: seen.map(|t| ts(&iso_of_unix(t))),
        drivers: Some(drivers),
        capacity: live.and_then(|s| n(s.capacity)),
        load: n(live.map_or(0, |s| s.load)),
        host_load: live.and_then(|s| s.host_load).map(|l| RunnerHostLoad {
            avg1: l.avg1,
            cores: l.cores,
        }),
        version,
        arch: live.and_then(|s| s.arch.clone()),
        isolation,
    }
}

/// What `of` takes besides the device and its live state.
#[derive(Default)]
struct Extra {
    facts: Option<ainkrad_proto::v2::RunnerFacts>,
    since: Option<i64>,
    agents: u32,
    terminals: u32,
    built_in: bool,
}

fn extra(
    id: &str,
    hub: &HashMap<String, (Option<ainkrad_proto::v2::RunnerFacts>, i64)>,
    c: &Counts,
) -> Extra {
    let (facts, since) = hub.get(id).cloned().unzip();
    Extra {
        facts: facts.flatten(),
        since,
        agents: c.agents.get(id).copied().unwrap_or(0),
        terminals: c.terminals.get(id).copied().unwrap_or(0),
        built_in: c.built_in.contains(id),
    }
}

/// A runner device that may connect: approved and not revoked (a pending, rejected or expired
/// claimant is not a runner yet).
fn listed(d: &gov::Device) -> bool {
    d.kind == "runner" && d.usable()
}

/// The host's load as last reported by a runner (E2-15.2), if any.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerHostLoad {
    /// The one-minute load average.
    pub avg1: f64,
    /// How many CPUs the runner sees.
    pub cores: u32,
}

#[utoipa::path(get, path = "/api/v1/runners", operation_id = "listRunners", tag = "runners",
    responses((status = 200, description = "Every paired runner that is active (approved, not \
        revoked), with its live state", body = Vec<Runner>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Runner>> {
    let live = app.hub.runners();
    let hub = app.hub.facts();
    let c = counts(&app).await?;
    let devices = gov::list_devices(&app.pool).await?;
    Ok(Json(
        devices
            .into_iter()
            .filter(listed)
            .map(|d| {
                let s = live.get(&d.id);
                let x = extra(&d.id, &hub, &c);
                of(d, s, &x)
            })
            .collect(),
    ))
}

pub(super) async fn one(app: &App, id: &str) -> Result<gov::Device, ApiError> {
    let found = match is_id(id, "d_") {
        true => gov::get_device(&app.pool, id).await?,
        false => None,
    };
    found
        .filter(listed)
        .ok_or_else(|| ApiError::not_found("no such runner"))
}

#[utoipa::path(get, path = "/api/v1/runners/{id}", operation_id = "getRunner", tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    responses((status = 200, description = "One runner and its live state", body = Runner)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Runner> {
    let d = one(&app, &id).await?;
    let live = app.hub.runners();
    let x = extra(&id, &app.hub.facts(), &counts(&app).await?);
    Ok(Json(of(d, live.get(&id), &x)))
}

/// The no-op's answer.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoopResult {
    /// The runner answered.
    pub ok: Option<bool>,
    /// From dispatch to answer.
    pub duration_ms: Option<u64>,
}

/// A failed command as an API error.
pub(super) fn failed(e: &StreamError) -> ApiError {
    let (status, code) = match e.code {
        ErrorCode::Offline => (StatusCode::CONFLICT, "runner_offline"),
        ErrorCode::UnsupportedCommand => (StatusCode::CONFLICT, "unsupported_command"),
        ErrorCode::Busy => (StatusCode::SERVICE_UNAVAILABLE, "runner_busy"),
        ErrorCode::Lost => (StatusCode::GATEWAY_TIMEOUT, "runner_lost"),
        _ => (StatusCode::BAD_GATEWAY, "runner_failed"),
    };
    ApiError::new(status, code, e.message.clone())
}

#[utoipa::path(post, path = "/api/v1/runners/{id}/noop", operation_id = "runNoop",
    tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    responses((status = 200, description = "The runner ran the no-op command (audited as \
        `runner.command`, once per caller, runner and outcome in a window). 409 `runner_offline` or `unsupported_command`, 503 `runner_busy`, \
        504 `runner_lost` or `runner_timeout`, 502 `runner_failed`", body = NoopResult)))]
pub async fn noop(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<NoopResult> {
    let d = one(&app, &id).await?;
    let started = Instant::now();
    let outcome = match tokio::time::timeout(NOOP_WAIT, app.hub.noop(&id)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(failed(&e)),
        Err(_) => Err(ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "runner_timeout",
            "the runner did not answer in time",
        )),
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    // The first call per caller, runner and outcome in a window is audited; the repeats are
    // counted in memory (`auth::refusals`, bounded), so a device that can call this at its
    // request rate cannot grow the permanent audit log (security review RH4).
    let key = format!("{COMMAND}:noop:{}:{id}:{}", me.device.id, outcome.is_ok());
    if !app.auth.refusals.note(&key, app.clock.unix()) {
        outcome?;
        return Ok(Json(NoopResult {
            ok: Some(true),
            duration_ms: Some(duration_ms),
        }));
    }
    let event = NewAuditEvent {
        actor: BY,
        action: COMMAND.to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: d.seq,
        }),
        details: json!({
            "runner": id,
            "op": "noop",
            "by_device": me.device.id,
            "ok": outcome.is_ok(),
            "duration_ms": duration_ms,
        })
        .to_string(),
    };
    crate::store::audit::append_one(&app.pool, &event).await?;
    outcome?;
    Ok(Json(NoopResult {
        ok: Some(true),
        duration_ms: Some(duration_ms),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(cmds: &[&str]) -> RunnerDriver {
        RunnerDriver {
            name: Some("agent".to_owned()),
            commands: Some(cmds.iter().map(|c| (*c).to_owned()).collect()),
            capacity: Some(2),
            slots: None,
        }
    }

    fn tiers(t: &[&str]) -> RunnerIsolation {
        RunnerIsolation {
            tiers: Some(t.iter().map(|c| (*c).to_owned()).collect()),
            kvm: None,
        }
    }

    #[test]
    fn versions_compare_by_number_not_text() {
        assert!(semver("0.10.0") > semver("0.9.9"));
        assert_eq!(semver("0.2.2-rc1"), Some((0, 2, 2)));
        assert_eq!(semver("nightly"), None);
    }

    #[test]
    fn accounts_say_why_not() {
        let off = accounts_of(&[], None);
        assert!(!off.gateway && !off.subscription_env && !off.egress_filter);
        assert!(off.gateway_reason.unwrap().contains("--enable-agents"));
        // Agents on, a sandbox, no proven egress filter: no subscription either.
        let a = accounts_of(&[agent(&["gateway"])], Some(&tiers(&["none", "process"])));
        assert!(a.gateway && !a.egress_filter && !a.subscription_env);
        assert!(a.subscription_env_reason.unwrap().contains("egress filter"));
        // Filter but no sandbox.
        let a = accounts_of(&[agent(&["egress-filter"])], Some(&tiers(&["none"])));
        assert!(a.egress_filter && !a.subscription_env);
        assert!(a.subscription_env_reason.unwrap().contains("sandbox"));
        // Everything.
        let a = accounts_of(
            &[agent(&["gateway", "egress-filter"])],
            Some(&tiers(&["none", "process"])),
        );
        assert!(a.gateway && a.egress_filter && a.subscription_env);
        assert!(a.gateway_reason.is_none() && a.subscription_env_reason.is_none());
    }
}
