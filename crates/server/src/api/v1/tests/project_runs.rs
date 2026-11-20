//! Project runs (P5-03): one live run per project (409), the idle stop on a faked clock, a
//! reconnecting runner settling the Core's rows, one audit row per start and per stop with its
//! origin, and a failed start stopping what it started. The runner is a fake `Link`.

use std::sync::Mutex;

use ainkrad_core::audit::{AuditActor, AuditOrigin, OriginKind};
use ainkrad_proto::v2::{RunInfo, RunList, RunPhase, RunStart};
use axum::http::Method;
use serde_json::json;

use super::*;
use crate::hub::Elevated;
use crate::runs::{self, Fut, Link, LinkError, Presence};
use crate::store::audit::origin;
use crate::store::projects::{self, Who};
use crate::store::run_specs;
use crate::store::runs as store;
use crate::store::secrets::Error;

const RUNNER: &str = "r1";

pub(super) struct Fake {
    pub(super) runners: Vec<String>,
    /// The phase `run.start` answers with, or an error text.
    pub(super) start: Mutex<Result<RunPhase, String>>,
    /// What `run.status` lists; `None`: the runs it started and has not stopped, running.
    pub(super) listed: Mutex<Option<Vec<RunInfo>>>,
    pub(super) held: Mutex<Vec<String>>,
    pub(super) stops: Mutex<Vec<String>>,
    pub(super) seen: Mutex<Option<Presence>>,
    /// Every `run.start` it got.
    pub(super) started: Mutex<Vec<RunStart>>,
    /// Seconds the Core says it has been up.
    pub(super) uptime: Mutex<i64>,
    /// Runners that cannot clone project repos (`run_caps.can_clone` off).
    pub(super) cannot_clone: Mutex<Vec<String>>,
}

impl Fake {
    pub(super) fn new() -> Self {
        Self {
            uptime: Mutex::new(0),
            cannot_clone: Mutex::default(),
            runners: vec![RUNNER.to_owned()],
            start: Mutex::new(Ok(RunPhase::Running)),
            listed: Mutex::default(),
            held: Mutex::default(),
            stops: Mutex::default(),
            started: Mutex::default(),
            seen: Mutex::new(Some(Presence {
                online: true,
                last_seen: 0,
            })),
        }
    }

    pub(super) fn stops(&self) -> Vec<String> {
        self.stops.lock().unwrap().clone()
    }
}

pub(super) fn info(run: &str, phase: RunPhase) -> RunInfo {
    RunInfo {
        run: run.to_owned(),
        project: 1,
        phase,
        failed_service: None,
        reason: None,
        services: vec![],
    }
}

impl Link for Fake {
    fn runners(&self) -> Vec<String> {
        self.runners.clone()
    }
    fn can_clone(&self, runner: &str) -> bool {
        !self
            .cannot_clone
            .lock()
            .unwrap()
            .iter()
            .any(|r| r == runner)
    }
    fn presence(&self, _: &str) -> Option<Presence> {
        *self.seen.lock().unwrap()
    }
    fn uptime_secs(&self) -> i64 {
        *self.uptime.lock().unwrap()
    }
    fn start<'a>(
        &'a self,
        _: &'a str,
        req: RunStart,
        _: Elevated,
    ) -> Fut<'a, Result<RunInfo, LinkError>> {
        Box::pin(async move {
            self.started.lock().unwrap().push(req.clone());
            match self.start.lock().unwrap().clone() {
                Ok(p) => {
                    if p == RunPhase::Running {
                        self.held.lock().unwrap().push(req.run.clone());
                    }
                    Ok(info(&req.run, p))
                }
                Err(m) => Err(LinkError::Failed(m)),
            }
        })
    }
    fn stop<'a>(&'a self, _: &'a str, run: &'a str) -> Fut<'a, Result<RunInfo, LinkError>> {
        Box::pin(async move {
            self.stops.lock().unwrap().push(run.to_owned());
            self.held.lock().unwrap().retain(|r| r != run);
            Ok(info(run, RunPhase::Stopped))
        })
    }
    fn status<'a>(&'a self, _: &'a str) -> Fut<'a, Result<RunList, LinkError>> {
        Box::pin(async move {
            let runs = match self.listed.lock().unwrap().clone() {
                Some(l) => l,
                None => {
                    let held = self.held.lock().unwrap();
                    held.iter().map(|r| info(r, RunPhase::Running)).collect()
                }
            };
            Ok(RunList { runs })
        })
    }
}

pub(super) fn w(now: &str) -> Who<'_> {
    Who {
        by_device: "d_test",
        actor: AuditActor::System,
        now,
    }
}

/// A project with a one-service spec; returns its id.
pub(super) async fn project(fx: &Fx, slug: &str) -> i64 {
    let now = fx.app.clock.now();
    let p = projects::create(&fx.app.pool, slug, slug, "", "manual", w(&now))
        .await
        .unwrap();
    let spec = json!({"services": {"web": {"image": "node:22",
                      "ports": [{"port": 3000, "expose": true}]}}});
    run_specs::save(&fx.app.pool, p.id, &spec, "manual", w(&now))
        .await
        .unwrap();
    p.id
}

/// Starts the project's run and drives it to the end of its start.
pub(super) async fn start(fx: &Fx, link: &Fake, project: i64) -> Result<String, Error> {
    let now = fx.app.clock.now();
    let pending = runs::begin_start(&fx.app, link, project, w(&now)).await?;
    let id = pending.run.id.clone();
    runs::drive_start(&fx.app, link, pending, Elevated::for_tests()).await;
    Ok(id)
}

pub(super) async fn run(fx: &Fx, id: &str) -> store::Run {
    store::get(&fx.app.pool, id).await.unwrap()
}

pub(super) fn code(e: Error) -> &'static str {
    match e {
        Error::Refused { code, .. } => code,
        Error::Db(e) => panic!("{e}"),
    }
}

pub(super) async fn audit_rows(fx: &Fx) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT action, origin FROM audit_events WHERE action LIKE 'project.run_%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_second_start_is_a_409_and_the_index_is_the_backstop() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id).await.state, "running");
    let now = fx.app.clock.now();
    let again = runs::begin_start(&fx.app, &link, p, w(&now)).await;
    assert_eq!(code(again.err().unwrap()), "conflict");
    // A racing writer that got past the check meets the unique index, also as `conflict`.
    let raced = store::begin(&fx.app.pool, "r_other", p, 1, RUNNER, None, w(&now)).await;
    assert_eq!(code(raced.err().unwrap()), "conflict");
    // Over HTTP: the same 409, before any runner is looked for.
    let r = send(
        &fx.app,
        req(
            Method::POST,
            &format!("/api/v1/projects/{p}/run/start"),
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    // Stopped, it can start again.
    let now = fx.app.clock.now();
    runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    assert!(start(&fx, &link, p).await.is_ok());
}

#[tokio::test]
async fn with_no_able_runner_a_start_is_409_no_runner_and_a_run_never_made_is_404() {
    let fx = fx().await;
    let p = project(&fx, "shop").await;
    let get = |m, u: String| send(&fx.app, req(m, &u, Some(&fx.dev), None));
    let r = get(Method::GET, format!("/api/v1/projects/{p}/run")).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
    // The test app's hub has no runner.
    let r = get(Method::POST, format!("/api/v1/projects/{p}/run/start")).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_runner"))
    );
}

#[tokio::test]
async fn each_start_and_stop_is_one_audit_row_with_its_origin() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let person = AuditOrigin::new(OriginKind::Person, Some("d_test".into()));
    origin::scope(person, async {
        let id = start(&fx, &link, p).await.unwrap();
        let now = fx.app.clock.now();
        let done = runs::stop(&fx.app, &link, p, "user", w(&now))
            .await
            .unwrap();
        assert_eq!(
            (done.id.as_str(), done.state.as_str()),
            (id.as_str(), "stopped")
        );
        assert_eq!(done.stop_reason.as_deref(), Some("user"));
        // Stopping again finds nothing live and writes nothing.
        let again = runs::stop(&fx.app, &link, p, "user", w(&now)).await;
        assert_eq!(code(again.err().unwrap()), "not_found");
    })
    .await;
    assert_eq!(
        audit_rows(&fx).await,
        [
            ("project.run_started".to_owned(), "person".to_owned()),
            ("project.run_stopped".to_owned(), "person".to_owned())
        ]
    );
}

#[tokio::test]
async fn a_project_set_to_never_stop_for_idleness_keeps_running() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    *link.seen.lock().unwrap() = Some(Presence {
        online: true,
        last_seen: fx.app.clock.unix(),
    });
    sqlx::query("UPDATE core_projects SET idle_never = 1 WHERE id = ?")
        .bind(p)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let id = start(&fx, &link, p).await.unwrap();
    fx.clock.advance(24 * 3600);
    runs::sweep(&fx.app, &link).await;
    assert_eq!(run(&fx, &id).await.state, "running");
}

#[tokio::test]
async fn the_idle_stop_fires_after_idle_minutes_on_a_faked_clock() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    *link.seen.lock().unwrap() = Some(Presence {
        online: true,
        last_seen: fx.app.clock.unix(),
    });
    let id = start(&fx, &link, p).await.unwrap();
    fx.clock.advance(29 * 60);
    runs::sweep(&fx.app, &link).await;
    assert_eq!(run(&fx, &id).await.state, "running", "29 of 30 minutes");
    // A viewer on the Run tab pushes it back.
    store::touch(&fx.app.pool, p, &fx.app.clock.now())
        .await
        .unwrap();
    fx.clock.advance(29 * 60);
    runs::sweep(&fx.app, &link).await;
    assert_eq!(
        run(&fx, &id).await.state,
        "running",
        "58 minutes since start, 29 since touch"
    );
    fx.clock.advance(2 * 60);
    runs::sweep(&fx.app, &link).await;
    let r = run(&fx, &id).await;
    assert_eq!(
        (r.state.as_str(), r.stop_reason.as_deref()),
        ("stopped", Some("idle"))
    );
    assert_eq!(link.stops(), std::slice::from_ref(&id));
    runs::sweep(&fx.app, &link).await;
    assert_eq!(link.stops().len(), 1, "stopped once");
    let rows = audit_rows(&fx).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[1],
        ("project.run_stopped".to_owned(), "schedule".to_owned())
    );
}

#[tokio::test]
async fn a_failed_start_stops_what_it_started_and_says_why() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    *link.start.lock().unwrap() = Err("pulling node:22 failed".into());
    let id = start(&fx, &link, p).await.unwrap();
    let r = run(&fx, &id).await;
    assert_eq!(
        (r.state.as_str(), r.stop_reason.as_deref()),
        ("failed", Some("start_failed"))
    );
    assert!(r.error.unwrap().contains("pulling node:22 failed"));
    assert_eq!(
        link.stops(),
        [id],
        "the run is stopped before it is marked failed"
    );
    assert_eq!(
        audit_rows(&fx).await.len(),
        2,
        "one start row, one stop row"
    );
    // The slot is free again, and a start the runner answers `failed` to is cleaned up too.
    *link.start.lock().unwrap() = Ok(RunPhase::Failed);
    let id2 = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id2).await.state, "failed");
    assert_eq!(link.stops().len(), 2);
}

#[tokio::test]
async fn a_reconnecting_runner_settles_the_rows() {
    let fx = fx().await;
    let link = Fake::new();
    let (shop, blog, docs) = (
        project(&fx, "shop").await,
        project(&fx, "blog").await,
        project(&fx, "notes").await,
    );
    let crashed = start(&fx, &link, shop).await.unwrap();
    let vanished = start(&fx, &link, blog).await.unwrap();
    // `docs` is still starting: its start has not answered.
    let now = fx.app.clock.now();
    let pending = runs::begin_start(&fx.app, &link, docs, w(&now))
        .await
        .unwrap();
    let starting = pending.run.id.clone();
    *link.listed.lock().unwrap() = Some(vec![
        RunInfo {
            failed_service: Some("web".into()),
            reason: Some("exited with 1".into()),
            ..info(&crashed, RunPhase::Failed)
        },
        info(&starting, RunPhase::Running),
        info("r_unknown", RunPhase::Running),
    ]);
    runs::reconcile(&fx.app, &link, RUNNER).await;
    let c = run(&fx, &crashed).await;
    assert_eq!(
        (c.state.as_str(), c.stop_reason.as_deref()),
        ("failed", Some("crash"))
    );
    assert!(c.error.unwrap().starts_with("web: exited with 1"));
    let v = run(&fx, &vanished).await;
    assert_eq!(
        (v.state.as_str(), v.stop_reason.as_deref()),
        ("stopped", Some("runner_lost"))
    );
    assert_eq!(run(&fx, &starting).await.state, "running");
    let mut stops = link.stops();
    stops.sort();
    let mut want = vec![crashed, "r_unknown".to_owned()];
    want.sort();
    assert_eq!(
        stops, want,
        "the crashed run's containers and the unaccounted run are stopped"
    );
}

#[tokio::test]
async fn a_runner_offline_for_good_loses_its_runs_and_restart_replaces() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let first = start(&fx, &link, p).await.unwrap();
    // Restart: the old run ends `replaced`, a new one starts.
    let now = fx.app.clock.now();
    runs::replace(&fx.app, &link, p, w(&now)).await.unwrap();
    assert_eq!(
        run(&fx, &first).await.stop_reason.as_deref(),
        Some("replaced")
    );
    let second = start(&fx, &link, p).await.unwrap();
    assert_ne!(first, second);
    // The runner drops off and is not back after the grace.
    *link.seen.lock().unwrap() = Some(Presence {
        online: false,
        last_seen: fx.app.clock.unix(),
    });
    fx.clock.advance(runs::RUNNER_LOST_AFTER + 1);
    runs::sweep(&fx.app, &link).await;
    let r = run(&fx, &second).await;
    assert_eq!(
        (r.state.as_str(), r.stop_reason.as_deref()),
        ("stopped", Some("runner_lost"))
    );
}

#[tokio::test]
async fn a_run_resolves_secrets_by_the_projects_group_only() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let spec = json!({"services": {"web": {"image": "node:22",
                      "env": {"TOKEN": "${secret:api_key}"}}}});
    let now = fx.app.clock.now();
    run_specs::save_unchecked(&fx.app.pool, p, &spec, w(&now))
        .await
        .unwrap();
    let seed = |group: Option<i64>| {
        let (pool, owner, now) = (fx.app.pool.clone(), fx.dev.id.clone(), now.clone());
        async move {
            sqlx::query(
                "INSERT INTO core_secrets (name, owner, delivery, version, key_id, sealed, size, \
                 created_at, updated_at, group_id) \
                 VALUES ('shop.api_key', ?, 'env', 1, '0123456789abcdef', x'00', 1, ?, ?, ?)",
            )
            .bind(owner)
            .bind(&now)
            .bind(&now)
            .bind(group)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    // Same stored name, but outside any group: the project has no group, so it is not found.
    seed(None).await;
    let id = start(&fx, &link, p).await.unwrap();
    let r = run(&fx, &id).await;
    assert_eq!(r.state, "failed");
    assert!(r.error.unwrap().contains("not one of this project's"));
    let mut conn = fx.app.pool.acquire().await.unwrap();
    let project = projects::get(&mut conn, p).await.unwrap();
    drop(conn);
    // The project has its own group since it was created; the secret outside it is still not found.
    let gid = project.secret_group.expect("a project made with a group");
    let grouped = project;
    let e = runs::project_secret(&fx.app.pool, &grouped, "api_key").await;
    assert!(e.is_err(), "ungrouped secret must not resolve");
    sqlx::query("UPDATE core_secrets SET group_id = ? WHERE name = 'shop.api_key'")
        .bind(gid)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        runs::project_secret(&fx.app.pool, &grouped, "api_key")
            .await
            .unwrap(),
        "shop.api_key"
    );
    // Another project's group does not see it.
    let other = projects::Project {
        secret_group: Some(gid + 100),
        ..grouped
    };
    assert!(
        runs::project_secret(&fx.app.pool, &other, "api_key")
            .await
            .is_err()
    );
}
