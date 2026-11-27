//! A run's start progress and its services' CPU and memory history (API 110). Neither needs a
//! new runner: both are the Core's reading of what the runner already reports through the
//! read-only `run.observe` (each service's container state, health, CPU and memory).
//!
//! **Steps.** `run.start` is one long call on the runner, which clones the code, builds every
//! `build` image, then creates and starts each service in order (pulling a missing image as it
//! creates it) and waits for it to run (and pass its health check). While a run is `starting`,
//! `GET /run` asks `run.observe` (3 s at most) which containers exist and reads the steps off them:
//! no container yet is `pull` (or `build`, when the spec builds an image), some services up is
//! `start`, every service running is `health`. A start that failed names its step from the
//! runner's words. A runner that does not answer in time leaves the steps as the spec alone says.
//!
//! **History.** A ring of the last [`SAMPLES`] samples per service of each live run, in this
//! process's memory (gone on a restart, dropped with the run): one sample per [`SAMPLE_EVERY`]
//! from the run sweep, and one from every `GET /run/services` at most each [`MIN_GAP_SECS`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{RunObserveReq, ServiceHealth, ServiceMetrics};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::super::types::{Timestamp, ts};
use super::super::{ApiError, ApiResult};
use super::num;
use super::run_logs::ServicesQuery;
use crate::api::App;
use crate::runs::{HubLink, Link};
use crate::store::run_specs::RunSpec;
use crate::store::runs::{self as store, Run};

/// Samples kept per service.
pub const SAMPLES: usize = 60;
/// The sweep's sampling interval: 60 samples are the last hour.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(60);
/// Samples from viewers are at least this far apart.
pub const MIN_GAP_SECS: i64 = 10;
/// How long `GET /run` waits for the runner while a run starts.
const STEPS_WAIT: Duration = Duration::from_secs(3);

/// One step of a run's start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RunStep {
    /// `pull` (the code, and images as they are needed), `build` (only when the spec builds an
    /// image), `start` (the services, in order), `health` (every service running and healthy).
    pub name: String,
    /// `done`, `active`, `pending` or `failed`.
    pub state: String,
    /// A few words: `2 of 3 services up`, the reason a step failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub detail: Option<String>,
}

fn step(name: &str, state: &str, detail: Option<String>) -> RunStep {
    RunStep {
        name: name.to_owned(),
        state: state.to_owned(),
        detail,
    }
}

/// The step names `spec` goes through.
fn names(spec: &RunSpec) -> Vec<&'static str> {
    let builds = spec.services.values().any(|s| s.build.is_some());
    let mut n = vec!["pull"];
    if builds {
        n.push("build");
    }
    n.extend(["start", "health"]);
    n
}

/// Every step up to `at` done, `at` itself `state` with `detail`, the rest pending.
fn upto(names: &[&str], at: &str, state: &str, detail: Option<String>) -> Vec<RunStep> {
    let i = names.iter().position(|n| *n == at).unwrap_or(0);
    names
        .iter()
        .enumerate()
        .map(|(j, n)| match j.cmp(&i) {
            std::cmp::Ordering::Less => step(n, "done", None),
            std::cmp::Ordering::Equal => step(n, state, detail.clone()),
            std::cmp::Ordering::Greater => step(n, "pending", None),
        })
        .collect()
}

/// The steps of `run` (none for a run that is not starting, running or a failed start), with
/// `seen` the services `run.observe` reported while it starts (`None`: the runner did not say).
pub fn steps(spec: &RunSpec, run: &Run, seen: Option<&[ServiceMetrics]>) -> Option<Vec<RunStep>> {
    let n = names(spec);
    match (run.state.as_str(), run.stop_reason.as_deref()) {
        ("running", _) => Some(n.iter().map(|s| step(s, "done", None)).collect()),
        ("failed", Some("start_failed")) => {
            let why = run.error.clone().unwrap_or_default();
            let at = if why.contains("did not build") {
                "build"
            } else if why.contains("did not turn healthy") {
                "health"
            } else if why.contains("did not start") || why.contains(" is ") {
                "start"
            } else {
                "pull"
            };
            let at = if n.contains(&at) { at } else { "pull" };
            Some(upto(&n, at, "failed", Some(why)))
        }
        ("starting", _) => {
            let total = spec.services.len();
            let seen = seen.unwrap_or_default();
            let up = seen.iter().filter(|s| s.state == "running").count();
            let first = if n.contains(&"build") {
                "build"
            } else {
                "pull"
            };
            Some(if seen.is_empty() {
                upto(&n, first, "active", None)
            } else if up < total {
                let d = format!("{up} of {total} services up");
                upto(&n, "start", "active", Some(d))
            } else {
                let waiting: Vec<&str> = seen
                    .iter()
                    .filter(|s| s.health == ServiceHealth::Starting)
                    .map(|s| s.name.as_str())
                    .collect();
                let d = match waiting.as_slice() {
                    [] => "settling".to_owned(),
                    w => format!("waiting for {}", w.join(", ")),
                };
                upto(&n, "health", "active", Some(d))
            })
        }
        _ => None,
    }
}

/// [`steps`] for the status route: asks the runner only while the run starts.
pub async fn steps_now(app: &App, run: &Run) -> Option<Vec<RunStep>> {
    if !matches!(run.state.as_str(), "starting" | "running" | "failed") {
        return None;
    }
    let spec = crate::store::run_specs::version(&app.pool, run.project_id, run.spec_version)
        .await
        .ok()?;
    let seen = if run.state == "starting" {
        let req = RunObserveReq {
            run: run.id.clone(),
            limit: Some(0),
            ..RunObserveReq::default()
        };
        let link = HubLink(std::sync::Arc::clone(&app.hub));
        match tokio::time::timeout(STEPS_WAIT, link.observe(&run.runner, req)).await {
            Ok(Ok(o)) => Some(o.services),
            _ => None,
        }
    } else {
        None
    };
    steps(&spec.spec, run, seen.as_deref())
}

/// One CPU and memory reading of a service.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct MetricSample {
    pub at: Timestamp,
    /// Percent of one CPU; none while it was not running.
    pub cpu_percent: Option<f64>,
    pub memory_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceHistory {
    pub name: String,
    /// Oldest first, at most 60.
    pub samples: Vec<MetricSample>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunMetrics {
    /// The live run these belong to; none (and no services) when the project is not running.
    pub run: Option<String>,
    /// How many samples a service keeps (60).
    pub samples_max: i64,
    /// Seconds between the Core's own samples (60); a viewer's polls add some in between.
    pub every_secs: i64,
    pub services: Vec<ServiceHistory>,
}

#[derive(Default)]
struct Ring {
    last: i64,
    services: BTreeMap<String, VecDeque<MetricSample>>,
}

// ponytail: one process-wide table, as `run_logs::OPEN`; bounded by live runs x services x 60.
static RINGS: LazyLock<Mutex<HashMap<String, Ring>>> = LazyLock::new(Mutex::default);

/// Keeps a sample of each of `services` for `run`, unless one was kept under `gap` seconds ago.
pub fn record(run: &str, unix: i64, at: &str, services: &[ServiceMetrics], gap: i64) {
    let mut rings = RINGS.lock().unwrap_or_else(|p| p.into_inner());
    let ring = rings.entry(run.to_owned()).or_default();
    if ring.last != 0 && unix - ring.last < gap {
        return;
    }
    ring.last = unix;
    for s in services {
        let q = ring.services.entry(s.name.clone()).or_default();
        if q.len() == SAMPLES {
            q.pop_front();
        }
        q.push_back(MetricSample {
            at: ts(at),
            cpu_percent: s.cpu_percent,
            memory_bytes: i64::try_from(s.memory_bytes).unwrap_or(i64::MAX),
        });
    }
}

fn history(run: &str) -> Vec<ServiceHistory> {
    let rings = RINGS.lock().unwrap_or_else(|p| p.into_inner());
    rings.get(run).map_or_else(Vec::new, |r| {
        r.services
            .iter()
            .map(|(name, q)| ServiceHistory {
                name: name.clone(),
                samples: q.iter().cloned().collect(),
            })
            .collect()
    })
}

/// The sweep's sample of every running run; rings of runs no longer live go.
pub async fn sample_all(app: &App, link: &dyn Link) {
    let Ok(live) = store::live_all(&app.pool).await else {
        return;
    };
    let keep: HashSet<&str> = live.iter().map(|r| r.id.as_str()).collect();
    RINGS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|run, _| keep.contains(run.as_str()));
    for r in live.iter().filter(|r| r.state == "running") {
        let req = RunObserveReq {
            run: r.id.clone(),
            limit: Some(0),
            ..RunObserveReq::default()
        };
        // ponytail: one run after another inside the sweep loop; spawn them if a Core runs many.
        if let Ok(Ok(o)) = tokio::time::timeout(STEPS_WAIT, link.observe(&r.runner, req)).await {
            record(&r.id, app.clock.unix(), &app.clock.now(), &o.services, 0);
        }
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run/metrics",
    operation_id = "getProjectRunMetrics", tag = "projects",
    params(("id" = String, Path, description = "The project's id"), ServicesQuery),
    responses((status = 200, description = "The CPU and memory history of each service of the \
        live run (API 110): the last 60 samples, oldest first, one a minute from the Core and more \
        while someone watches `run/services`; kept in memory, so it starts again after a Core \
        restart. Empty when the project is not running. 404 for no such project",
        body = RunMetrics)))]
pub async fn metrics(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<ServicesQuery>,
) -> ApiResult<RunMetrics> {
    let project = num(&id, "project")?;
    let mut conn = app.pool.acquire().await?;
    crate::store::projects::get(&mut conn, project)
        .await
        .map_err(ApiError::from)?;
    drop(conn);
    let live = store::live_list(&app.pool, project).await?;
    let run = match q.run.as_deref() {
        Some(id) => live.into_iter().find(|r| r.id == id),
        None => store::live(&app.pool, project).await?,
    };
    Ok(Json(RunMetrics {
        services: run.as_ref().map(|r| history(&r.id)).unwrap_or_default(),
        run: run.map(|r| r.id),
        samples_max: SAMPLES as i64,
        every_secs: SAMPLE_EVERY.as_secs() as i64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(v: serde_json::Value) -> RunSpec {
        serde_json::from_value(v).unwrap()
    }

    fn run(state: &str, reason: Option<&str>, error: Option<&str>) -> Run {
        Run {
            id: "r_1".into(),
            project_id: 1,
            spec_version: 1,
            runner: "r1".into(),
            state: state.into(),
            stop_reason: reason.map(str::to_owned),
            error: error.map(str::to_owned),
            started_by: "d".into(),
            started_at: "2026-11-27T10:00:00.000Z".into(),
            stopped_at: None,
            last_activity_at: None,
            config_id: None,
            environment: None,
        }
    }

    fn svc(name: &str, state: &str, health: ServiceHealth) -> ServiceMetrics {
        ServiceMetrics {
            name: name.into(),
            state: state.into(),
            health,
            cpu_percent: Some(1.5),
            memory_bytes: 1024,
            memory_limit_bytes: 0,
            restarts: 0,
        }
    }

    fn states(s: &[RunStep]) -> Vec<(&str, &str)> {
        s.iter()
            .map(|s| (s.name.as_str(), s.state.as_str()))
            .collect()
    }

    #[test]
    fn a_start_reads_its_steps_off_the_containers() {
        let two = spec(json!({"services": {
            "web": {"image": "node:22"}, "db": {"image": "postgres:17"}}}));
        let r = run("starting", None, None);
        let s = steps(&two, &r, None).unwrap();
        assert_eq!(
            states(&s),
            [
                ("pull", "active"),
                ("start", "pending"),
                ("health", "pending")
            ]
        );
        let one_up = [svc("db", "running", ServiceHealth::None)];
        let s = steps(&two, &r, Some(&one_up)).unwrap();
        assert_eq!(s[1].state, "active");
        assert_eq!(s[1].detail.as_deref(), Some("1 of 2 services up"));
        assert_eq!(s[0].state, "done");
        let both = [
            svc("db", "running", ServiceHealth::Healthy),
            svc("web", "running", ServiceHealth::Starting),
        ];
        let s = steps(&two, &r, Some(&both)).unwrap();
        assert_eq!(
            states(&s),
            [("pull", "done"), ("start", "done"), ("health", "active")]
        );
        assert_eq!(s[2].detail.as_deref(), Some("waiting for web"));
        let s = steps(&two, &run("running", None, None), None).unwrap();
        assert!(s.iter().all(|s| s.state == "done"));
        assert_eq!(steps(&two, &run("stopped", Some("user"), None), None), None);
        assert_eq!(steps(&two, &run("failed", Some("crash"), None), None), None);
    }

    #[test]
    fn a_build_is_its_own_step_and_a_failed_start_names_the_step() {
        let built = spec(json!({"services": {
            "web": {"build": {"repo": "app"}}}}));
        let s = steps(&built, &run("starting", None, None), None).unwrap();
        assert_eq!(
            states(&s),
            [
                ("pull", "done"),
                ("build", "active"),
                ("start", "pending"),
                ("health", "pending")
            ]
        );
        for (why, at) in [
            ("web: web did not build: exit 1", "build"),
            ("web: web did not start: no image", "start"),
            ("web is exited (exit code 1)", "start"),
            ("web did not turn healthy in time", "health"),
            ("checking out app: disk full", "pull"),
        ] {
            let s = steps(
                &built,
                &run("failed", Some("start_failed"), Some(why)),
                None,
            )
            .unwrap();
            let failed: Vec<_> = s.iter().filter(|s| s.state == "failed").collect();
            assert_eq!(failed.len(), 1, "{why}");
            assert_eq!(failed[0].name, at, "{why}");
            assert_eq!(failed[0].detail.as_deref(), Some(why));
        }
    }

    #[test]
    fn the_history_keeps_sixty_and_spaces_viewer_samples() {
        let run = "r_hist";
        let s = [svc("web", "running", ServiceHealth::None)];
        for i in 0..70 {
            record(run, 1000 + i * 60, "2026-11-27T10:00:00.000Z", &s, 0);
        }
        assert_eq!(history(run)[0].samples.len(), SAMPLES);
        // A viewer's sample right after the last one is skipped.
        record(
            run,
            1000 + 69 * 60 + 5,
            "2026-11-27T11:00:00.000Z",
            &s,
            MIN_GAP_SECS,
        );
        let h = history(run);
        assert_eq!(h[0].samples.len(), SAMPLES);
        assert_ne!(
            serde_json::to_value(&h[0].samples[SAMPLES - 1].at).unwrap(),
            json!("2026-11-27T11:00:00.000Z")
        );
        RINGS.lock().unwrap().remove(run);
    }
}
