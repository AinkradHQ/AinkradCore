//! Project runs, orchestrated (Core 0.9, P5-03; store `store::runs`, runner side P5-02).
//!
//! Security model: nothing here starts a container on its own. `run.start` goes out only with the
//! `Elevated` proof of the admin route that asked (`POST /projects/{id}/run/start|restart`, a
//! step-up); stop, status and reconcile are the Core's own housekeeping and can only remove
//! containers the runner lists under a run label. Secrets leave as single-use leases, never as
//! values. A project has one live run (409 on a second start); a start that fails stops what it
//! started before it is marked failed.
//!
//! The runner is reached through [`Link`], so the state machine is tested without a runner.

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use ainkrad_core::audit::{AuditActor, AuditOrigin, OriginKind};
use ainkrad_proto::v2::{
    Body, Command, DRIVER_RUN, ErrorCode, Reply, RunCheckout, RunInfo, RunLimits, RunList,
    RunPhase, RunSecret, RunStart, RunStatusReq, RunStop,
};

use crate::api::App;
use crate::hub::{Elevated, Hub, RunHousekeeping};
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::audit::origin;
use crate::store::projects::{self, Who};
use crate::store::run_specs::{self, spec};
use crate::store::runs::{self, End, Run};
use crate::store::secrets::{self, Error};

/// A `run.start` that does not answer in this long is a failed start (image pulls and builds are
/// slow, so it is generous).
pub const START_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// `run.stop` is `podman stop -t 10` per container.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(2 * 60);
pub const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// A runner offline this long (unix seconds) has lost its runs.
pub const RUNNER_LOST_AFTER: i64 = 10 * 60;
const PIDS: u32 = 512;

/// When this process began running orchestration (forced by `sweep_loop`), for L4.
static BOOT: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
/// Runs whose `drive_start` is in this process right now: `reconcile` leaves their `starting`
/// alone, so a healthy start is not promoted (and then stopped) from under its own driver.
static DRIVING: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);

struct Driving(String);

impl Driving {
    fn new(run: &str) -> Self {
        DRIVING.lock().unwrap().insert(run.to_owned());
        Self(run.to_owned())
    }
}

impl Drop for Driving {
    fn drop(&mut self) {
        DRIVING.lock().unwrap().remove(&self.0);
    }
}

fn driving(run: &str) -> bool {
    DRIVING.lock().unwrap().contains(run)
}

pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub enum LinkError {
    /// The runner is not connected.
    Offline,
    Failed(String),
}

/// Whether a runner is connected and when it was last heard from (unix seconds).
#[derive(Debug, Clone, Copy)]
pub struct Presence {
    pub online: bool,
    pub last_seen: i64,
}

/// The runner side of a run, as the orchestrator needs it.
pub trait Link: Send + Sync {
    /// Runners that are online and able to run projects (`run_caps`), by id.
    fn runners(&self) -> Vec<String>;
    /// `None` for a runner the Core has not met since it started.
    fn presence(&self, runner: &str) -> Option<Presence>;
    /// Seconds this Core has been orchestrating (a runner never met since is only lost after
    /// the grace has passed on the Core's own clock).
    fn uptime_secs(&self) -> i64;
    fn start<'a>(
        &'a self,
        runner: &'a str,
        req: RunStart,
        proof: Elevated,
    ) -> Fut<'a, Result<RunInfo, LinkError>>;
    fn stop<'a>(&'a self, runner: &'a str, run: &'a str) -> Fut<'a, Result<RunInfo, LinkError>>;
    fn status<'a>(&'a self, runner: &'a str) -> Fut<'a, Result<RunList, LinkError>>;
    /// The checkouts of `repos` for a run, prepared on the runner.
    fn checkouts<'a>(
        &'a self,
        runner: &'a str,
        run: &'a str,
        repos: &'a [String],
    ) -> Fut<'a, Result<Vec<RunCheckout>, String>>;
}

/// The runner hub as a [`Link`].
pub struct HubLink(pub Arc<Hub>);

impl HubLink {
    async fn call(
        &self,
        runner: &str,
        command: Command,
        proof: Elevated,
        wait: Duration,
    ) -> Result<Reply, LinkError> {
        let sent = self.0.dispatch_elevated(runner, command, proof);
        Self::answer(sent, wait).await
    }

    async fn housekeeping(
        &self,
        runner: &str,
        op: RunHousekeeping,
        wait: Duration,
    ) -> Result<Reply, LinkError> {
        Self::answer(self.0.dispatch_run_housekeeping(runner, op), wait).await
    }

    async fn answer(
        sent: Result<crate::hub::Dispatched, ainkrad_proto::v2::StreamError>,
        wait: Duration,
    ) -> Result<Reply, LinkError> {
        let failed = |m: String| LinkError::Failed(m);
        let sent = sent.map_err(|e| match e.code {
            ErrorCode::Offline => LinkError::Offline,
            _ => failed(e.message),
        })?;
        match tokio::time::timeout(wait, sent.outcome()).await {
            Err(_) => Err(failed("the runner did not answer in time".into())),
            Ok(Err(e)) => Err(failed(e.message)),
            Ok(Ok(Body::Result(r))) => Ok(r),
            Ok(Ok(_)) => Err(failed("the runner answered with something else".into())),
        }
    }
}

impl Link for HubLink {
    fn runners(&self) -> Vec<String> {
        let states = self.0.runners();
        let mut out: Vec<String> = self
            .0
            .facts()
            .into_iter()
            .filter(|(id, (facts, _))| {
                facts
                    .as_ref()
                    .is_some_and(|f| f.run_caps.is_some() && f.policy.is_some_and(|p| p.runs))
                    && states
                        .get(id)
                        .is_some_and(|s| s.online && s.drivers.iter().any(|d| d.name == DRIVER_RUN))
            })
            .map(|(id, _)| id)
            .collect();
        out.sort();
        out
    }

    fn presence(&self, runner: &str) -> Option<Presence> {
        self.0.runners().get(runner).map(|s| Presence {
            online: s.online,
            last_seen: s.last_seen,
        })
    }

    fn uptime_secs(&self) -> i64 {
        i64::try_from(BOOT.elapsed().as_secs()).unwrap_or(i64::MAX)
    }

    fn start<'a>(
        &'a self,
        runner: &'a str,
        req: RunStart,
        proof: Elevated,
    ) -> Fut<'a, Result<RunInfo, LinkError>> {
        Box::pin(async move {
            match self
                .call(runner, Command::RunStart(req), proof, START_TIMEOUT)
                .await?
            {
                Reply::RunStart(i) => Ok(i),
                _ => Err(LinkError::Failed("not a run.start answer".into())),
            }
        })
    }

    fn stop<'a>(&'a self, runner: &'a str, run: &'a str) -> Fut<'a, Result<RunInfo, LinkError>> {
        Box::pin(async move {
            let op = RunHousekeeping::Stop(RunStop {
                run: run.to_owned(),
            });
            match self.housekeeping(runner, op, STOP_TIMEOUT).await? {
                Reply::RunStop(i) => Ok(i),
                _ => Err(LinkError::Failed("not a run.stop answer".into())),
            }
        })
    }

    fn status<'a>(&'a self, runner: &'a str) -> Fut<'a, Result<RunList, LinkError>> {
        Box::pin(async move {
            let op = RunHousekeeping::Status(RunStatusReq { run: None });
            match self.housekeeping(runner, op, STOP_TIMEOUT).await? {
                Reply::RunStatus(l) => Ok(l),
                _ => Err(LinkError::Failed("not a run.status answer".into())),
            }
        })
    }

    fn checkouts<'a>(
        &'a self,
        _runner: &'a str,
        _run: &'a str,
        _repos: &'a [String],
    ) -> Fut<'a, Result<Vec<RunCheckout>, String>> {
        // ponytail: no runner op clones a project's repos for a run yet (P3-02 clones for AI
        // sessions only), so a spec that mounts or builds from a repo cannot start. Add the op
        // (clone from the Core copy under a lease, answer the dirs) and fill this in.
        Box::pin(async {
            Err(
                "run checkouts are not available yet: the runner cannot prepare project repos"
                    .into(),
            )
        })
    }
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

fn system(now: &str) -> Who<'_> {
    Who {
        by_device: "system",
        actor: AuditActor::System,
        now,
    }
}

/// What `begin_start` hands to `drive_start`.
pub struct Pending {
    pub run: Run,
    pub project: projects::Project,
    pub spec: run_specs::SpecVersion,
}

/// The synchronous half of a start: refuses a second live run (409 `conflict`), an archived
/// project (409), no spec (404) and no able runner (409 `no_runner`), places the run on the
/// least loaded runner and records it `starting`. Call [`drive_start`] next.
pub async fn begin_start(
    app: &App,
    link: &dyn Link,
    project_id: i64,
    who: Who<'_>,
) -> Result<Pending, Error> {
    let project = projects::get(&mut *app.pool.acquire().await?, project_id).await?;
    if project.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    if runs::live(&app.pool, project_id).await?.is_some() {
        return refused("conflict", "the project already has a live run");
    }
    let spec = run_specs::latest(&app.pool, project_id).await?;
    let load = runs::load(&app.pool).await?;
    // Prefer a runner every referenced secret may be leased to; load breaks the tie.
    let mut scopes = Vec::new();
    for name in spec::secret_refs(&spec.spec) {
        if let Ok(stored) = project_secret(&app.pool, &project, &name).await {
            scopes.push(secrets::effective_runners(&app.pool, &stored).await?);
        }
    }
    let Some(runner) = link.runners().into_iter().min_by_key(|r| {
        let out = scopes.iter().filter(|s| !s.contains(r)).count();
        (out, load.get(r).copied().unwrap_or(0))
    }) else {
        return refused(
            "no_runner",
            "no online runner can run projects (it needs Podman, rootless setup and cgroup limits)",
        );
    };
    let id = crate::auth::crypto::random_id("r_");
    let run = runs::begin(&app.pool, &id, project_id, spec.version, &runner, who).await?;
    Ok(Pending { run, project, spec })
}

/// The slow half of a start: checkouts, secret leases, `run.start`. Whatever goes wrong, what
/// the runner started is stopped (the #297 review) before the run is marked `failed`
/// (`start_failed`); a run stopped meanwhile is stopped again, since its `run.start` may have
/// finished after the stop.
pub async fn drive_start(app: &App, link: &dyn Link, p: Pending, proof: Elevated) {
    let run = p.run.id.clone();
    let runner = p.run.runner.clone();
    let _driving = Driving::new(&run);
    let mut leases = Vec::new();
    let outcome = try_start(app, link, &p, proof, &mut leases).await;
    let now = app.clock.now();
    match outcome {
        Ok(()) => match runs::mark_running(&app.pool, &run, &now).await {
            Ok(true) => {}
            // Not `starting` any more: stop only when it is not `running` (a reconcile may have
            // promoted this healthy start; stopping that one would kill it).
            Ok(false) => match runs::get(&app.pool, &run).await {
                Ok(r) if r.state == "running" => {}
                _ => {
                    let _ = link.stop(&runner, &run).await;
                }
            },
            Err(e) => tracing::error!(error = %e, run, "marking a run running failed"),
        },
        Err(why) => fail_start(app, link, &p.run, &why, &leases).await,
    }
}

/// The stored name (`<slug>.<name>`) of the project's secret `name`, looked up by the project's
/// secret group, never by the name alone: a secret of that name outside the group is not found.
pub async fn project_secret(
    pool: &sqlx::SqlitePool,
    project: &projects::Project,
    name: &str,
) -> Result<String, String> {
    let missing = || format!("the secret {name} is not one of this project's");
    let group = project.secret_group.ok_or_else(missing)?;
    let stored = format!("{}.{name}", project.slug);
    let found: Option<String> =
        sqlx::query_scalar("SELECT name FROM core_secrets WHERE group_id = ? AND name = ?")
            .bind(group)
            .bind(&stored)
            .fetch_optional(pool)
            .await
            .map_err(|e| e.to_string())?;
    found.ok_or_else(missing)
}

/// The lease ids made so far go into `leases` so a failed start can drop them.
async fn try_start(
    app: &App,
    link: &dyn Link,
    p: &Pending,
    proof: Elevated,
    leases: &mut Vec<String>,
) -> Result<(), String> {
    let run = &p.run;
    let repos: Vec<String> = spec::repo_refs(&p.spec.spec)
        .into_iter()
        .map(|(_, r)| r.to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let checkouts = match repos.is_empty() {
        true => Vec::new(),
        false => link.checkouts(&run.runner, &run.id, &repos).await?,
    };
    let json = serde_json::to_value(&p.spec.spec).map_err(|e| e.to_string())?;
    let mut req = RunStart {
        run: run.id.clone(),
        project: u64::try_from(p.project.id).map_err(|e| e.to_string())?,
        spec: serde_json::from_value(json).map_err(|e| e.to_string())?,
        limits: RunLimits {
            cpus: p.project.cpu_limit,
            memory_mb: u64::try_from(p.project.mem_limit_mb).unwrap_or(2048),
            pids: PIDS,
        },
        checkouts,
        secrets: Vec::new(),
    };
    // Before any lease: a request that is invalid anyway must not cost one (it does not look at
    // the secrets).
    if let Some(why) = req.problem() {
        return Err(why);
    }
    for name in spec::secret_refs(&p.spec.spec) {
        // Only a member of the project's own group (never a same-named secret outside it).
        let stored = project_secret(&app.pool, &p.project, &name).await?;
        let (lease, _) = secrets::lease(
            &app.pool,
            &stored,
            &run.runner,
            None,
            &run.started_by,
            AuditActor::System,
            &app.clock.now(),
            app.clock.unix(),
        )
        .await
        .map_err(|e| format!("cannot lease the secret {name}: {e}"))?;
        leases.push(lease.clone());
        req.secrets.push(RunSecret { name, lease });
    }
    match link.start(&run.runner, req, proof).await {
        Ok(i) if i.phase == RunPhase::Running => Ok(()),
        Ok(i) => Err(match (i.failed_service, i.reason) {
            (Some(s), Some(r)) => format!("{s}: {r}"),
            (Some(s), None) => format!("the service {s} did not start"),
            (None, Some(r)) => r,
            (None, None) => format!("the run ended up {:?}, not running", i.phase),
        }),
        Err(LinkError::Offline) => Err("the runner went offline".into()),
        Err(LinkError::Failed(m)) => Err(m),
    }
}

/// Stops what a failed start left on the runner, then marks the run `failed`.
/// Its unredeemed leases are dropped, so a failed start leaves none against the runner's cap.
async fn fail_start(app: &App, link: &dyn Link, run: &Run, why: &str, leases: &[String]) {
    let _ = tokio::time::timeout(STOP_TIMEOUT, link.stop(&run.runner, &run.id)).await;
    for lease in leases {
        let _ = crate::store::account_keys::revoke_unused_lease(&app.pool, lease).await;
    }
    let now = app.clock.now();
    let end = End {
        state: "failed",
        reason: Some("start_failed"),
        error: Some(why),
    };
    if let Err(e) = runs::finish(&app.pool, &run.id, end, system(&now)).await {
        tracing::error!(error = %e, run = run.id, "ending a failed start failed");
    }
}

/// Stops the project's live run for `reason` (`user`, `idle` or `replaced`) and waits for it.
/// 404 for no live run. A runner that is gone ends it `runner_lost`; one that refuses leaves it
/// `stopping` (502 `runner_error`) for the sweep to retry.
pub async fn stop(
    app: &App,
    link: &dyn Link,
    project_id: i64,
    reason: &str,
    who: Who<'_>,
) -> Result<Run, Error> {
    projects::get(&mut *app.pool.acquire().await?, project_id).await?;
    let Some(run) = runs::live(&app.pool, project_id).await? else {
        return refused("not_found", "the project has no live run");
    };
    settle_stop(app, link, run, reason, who).await
}

async fn settle_stop(
    app: &App,
    link: &dyn Link,
    run: Run,
    reason: &str,
    who: Who<'_>,
) -> Result<Run, Error> {
    if run.state != "stopping" {
        runs::begin_stop(&app.pool, &run.id, reason).await?;
    }
    let gone = match tokio::time::timeout(STOP_TIMEOUT, link.stop(&run.runner, &run.id)).await {
        Ok(Ok(_)) => None,
        Ok(Err(LinkError::Offline)) => Some("runner_lost"),
        Ok(Err(LinkError::Failed(m))) => return refused("runner_error", m),
        Err(_) => return refused("runner_error", "the runner did not stop the run in time"),
    };
    let end = End {
        state: "stopped",
        reason: gone,
        error: gone.map(|_| "the runner was offline when the run was stopped"),
    };
    runs::finish(&app.pool, &run.id, end, who).await?;
    runs::get(&app.pool, &run.id).await
}

/// Stops the live run (reason `replaced`), if any; the caller then starts the next one.
pub async fn replace(
    app: &App,
    link: &dyn Link,
    project_id: i64,
    who: Who<'_>,
) -> Result<(), Error> {
    match stop(app, link, project_id, "replaced", who).await {
        Ok(_) => Ok(()),
        Err(Error::Refused {
            code: "not_found", ..
        }) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Brings the Core's rows for `runner` in line with what the runner says it holds (from the
/// labels on its containers): called when the runner reconnects and on every sweep.
///
/// - listed `running` and the Core had `starting`: now `running`;
/// - listed `failed`: ended `failed` (`crash`, naming the service) and its containers stopped;
/// - not listed (or listed with no container left) while `running`: the runner lost it, ended
///   `runner_lost`; while `stopping`: simply stopped;
/// - listed and not live in the Core (a run it ended, or never knew): stopped, so nothing runs
///   unaccounted for. A `starting` row not listed yet is left to `drive_start` and its timeout.
pub async fn reconcile(app: &App, link: &dyn Link, runner: &str) {
    let Ok(list) = link.status(runner).await else {
        return;
    };
    let Ok(live) = runs::live_all(&app.pool).await else {
        return;
    };
    let now = app.clock.now();
    let mine: Vec<&Run> = live.iter().filter(|r| r.runner == runner).collect();
    for r in &mine {
        let seen = list.runs.iter().find(|i| i.run == r.id);
        let end = match (seen.map(|i| i.phase), r.state.as_str()) {
            // Only a start nobody is driving (the Core restarted mid-start): a driver in this
            // process promotes its own run when `run.start` answers.
            (Some(RunPhase::Running), "starting") => {
                if !driving(&r.id) {
                    let _ = runs::mark_running(&app.pool, &r.id, &now).await;
                }
                None
            }
            (Some(RunPhase::Failed), _) => {
                let i = seen.expect("matched above");
                let why = format!(
                    "{}: {}",
                    i.failed_service.as_deref().unwrap_or("a service"),
                    i.reason.as_deref().unwrap_or("it is not running")
                );
                let _ = link.stop(runner, &r.id).await;
                Some(("failed", Some("crash"), Some(why)))
            }
            (None | Some(RunPhase::Stopped), "running") => Some((
                "stopped",
                Some("runner_lost"),
                Some("the runner no longer holds the run".to_owned()),
            )),
            (None | Some(RunPhase::Stopped), "stopping") => Some(("stopped", None, None)),
            _ => None,
        };
        if let Some((state, reason, error)) = end {
            let end = End {
                state,
                reason,
                error: error.as_deref(),
            };
            let _ = runs::finish(&app.pool, &r.id, end, system(&now)).await;
        }
    }
    let known: HashSet<&str> = mine.iter().map(|r| r.id.as_str()).collect();
    for i in &list.runs {
        if i.phase != RunPhase::Stopped && !known.contains(i.run.as_str()) {
            let _ = link.stop(runner, &i.run).await;
        }
    }
}

/// One pass: the idle stop (T6), a stop that did not finish, a start that never finished, a
/// runner gone for good, and a reconcile of every runner that holds a live run.
pub async fn sweep(app: &App, link: &dyn Link) {
    let Ok(live) = runs::live_all(&app.pool).await else {
        return;
    };
    let unix = app.clock.unix();
    let now = app.clock.now();
    let idle = AuditOrigin::new(OriginKind::Schedule, Some("project_idle".to_owned()));
    for r in &live {
        let age = |t: &str| unix - unix_secs(t).unwrap_or(unix);
        match r.state.as_str() {
            "running" => {
                let Ok(mut conn) = app.pool.acquire().await else {
                    continue;
                };
                let Ok(p) = projects::get(&mut conn, r.project_id).await else {
                    continue;
                };
                let last = r.last_activity_at.as_deref().unwrap_or(&r.started_at);
                if age(last) >= p.idle_minutes * 60 {
                    let done = origin::scope(
                        idle.clone(),
                        settle_stop(app, link, r.clone(), "idle", system(&now)),
                    )
                    .await;
                    if let Err(e) = done {
                        tracing::warn!(run = r.id, error = %e, "the idle stop failed");
                    }
                }
            }
            "stopping" => {
                let reason = r.stop_reason.clone().unwrap_or_else(|| "user".into());
                let _ = settle_stop(app, link, r.clone(), &reason, system(&now)).await;
            }
            "starting" if age(&r.started_at) >= START_TIMEOUT.as_secs() as i64 + 60 => {
                // A start whose driver is gone (the Core restarted mid-start).
                fail_start(app, link, r, "the start never finished", &[]).await;
            }
            _ => {}
        }
    }
    let runners: BTreeSet<String> = live.iter().map(|r| r.runner.clone()).collect();
    for runner in runners {
        let lost = match link.presence(&runner) {
            Some(Presence { online: true, .. }) => {
                reconcile(app, link, &runner).await;
                false
            }
            Some(Presence { last_seen, .. }) => unix - last_seen > RUNNER_LOST_AFTER,
            // Never met since this Core started: lost once the Core has been up past the grace
            // (a runner that reconnects in that time is reconciled instead).
            None => link.uptime_secs() > RUNNER_LOST_AFTER,
        };
        if lost {
            for r in runs::live_all(&app.pool).await.unwrap_or_default() {
                if r.runner == runner {
                    let end = End {
                        state: "stopped",
                        reason: Some("runner_lost"),
                        error: Some("the runner has been offline too long"),
                    };
                    let _ = runs::finish(&app.pool, &r.id, end, system(&now)).await;
                }
            }
        }
    }
}

/// `sweep` every `SWEEP_EVERY` until the Core stops.
pub async fn sweep_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let mut tick = tokio::time::interval(SWEEP_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    LazyLock::force(&BOOT);
    let link = HubLink(Arc::clone(&app.hub));
    loop {
        tokio::select! {
            () = crate::api::stopping(&mut closing) => return,
            _ = tick.tick() => sweep(&app, &link).await,
        }
    }
}

/// A runner reconnected: settle its runs (spawned by the hub when its hello lists the `run`
/// driver).
pub async fn reconnected(app: &App, runner: &str) {
    reconcile(app, &HubLink(Arc::clone(&app.hub)), runner).await;
}

/// The instant `iso_of_unix` gives back, for the callers that show when the idle stop is due.
pub fn idle_due(run: &Run, idle_minutes: i64) -> Option<String> {
    let last = run.last_activity_at.as_deref().unwrap_or(&run.started_at);
    if run.state != "running" {
        return None;
    }
    Some(iso_of_unix(unix_secs(last)? + idle_minutes * 60))
}
