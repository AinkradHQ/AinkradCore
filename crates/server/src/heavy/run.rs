//! Orchestration of one heavy job (E15-3, spec §5.3): place, lease the files, `sync.push`,
//! `job.run`, `sync.pull` the changes, record the history, tell the app. One task per job.
//!
//! Live jobs sit in a process-wide registry with a replay buffer of their frames (the shim's JSON
//! lines: `state`, `out`, `exit`), so the shim's stream and the app's WebSocket can both follow
//! one. A job that cannot start, or whose runner is lost, ends its stream with no `exit` frame:
//! the shim then runs the command where it was typed, which is the Core.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::ids::UserId;
use ainkrad_proto::v2::{
    Body, Close, Command, Control, JobNeed, JobRun, Os, Reply, RunSecret, SignalReq,
};
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use super::live::{Ctl, registry};
pub use super::live::{Live, cancel, get, lines, signal};
use super::rules::Row;
use super::{cache, history};
use crate::api::App;
use crate::auth::crypto::random_id;
use crate::hardware::place::{PlaceReason, place_job};
use crate::hardware::view;
use crate::workspace::flow;
use crate::workspace::fs::Tree;
use crate::workspace::manifest::Memo;
use crate::workspace::paths::SessionKey;
use crate::workspace::rules as sync_rules;

/// A job's frames stay available this long after it ends.
const KEEP: Duration = Duration::from_secs(300);
/// A cancel is TERM, then KILL after this.
const KILL_AFTER: Duration = Duration::from_secs(10);
/// The `cache` a job names when it runs in a runner's warm cache (the runner picks the folder).
const CACHE: &str = "core";

/// What one command asks.
#[derive(Debug, Clone)]
pub struct Start {
    pub project: i64,
    pub session: Option<String>,
    pub terminal: Option<String>,
    pub run_config: Option<i64>,
    pub argv: Vec<String>,
    pub cwd_rel: String,
    pub env: BTreeMap<String, String>,
    pub row: Row,
    /// `rule`, `history`, `decision` or `config`.
    pub tier: &'static str,
    /// `(variable, stored secret name)`: leased to the device the job lands on, redeemed once there
    /// into the variable (a task run configuration's Secret links).
    pub secrets: Vec<(String, String)>,
    /// The device that started it (the lease audit's `by`).
    pub by: String,
}

#[derive(Debug)]
pub enum Started {
    /// Placed on other hardware: follow it with [`follow`].
    Job { id: String, device_name: String },
    /// Nothing better than where it was typed (`core`, `core_no_fit:…`): run it there.
    Local(String),
}

/// What a job needs of its hardware, from its rule row.
pub fn need_of(row: &Row) -> JobNeed {
    let mac = row.need.iter().any(|n| n == "xcode" || n == "swift");
    JobNeed {
        os: mac.then_some(Os::Macos),
        arch: None,
        toolchains: row
            .need
            .iter()
            .filter(|n| !matches!(n.as_str(), "xcode" | "swift"))
            .cloned()
            .collect(),
        xcode: mac,
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

async fn emit(app: &App, kind: &str, payload: Value) {
    let written = async {
        let mut tx = crate::store::begin_write(&app.pool).await?;
        crate::store::events::append(&mut tx, kind, &payload).await?;
        tx.commit().await
    };
    if let Err(e) = written.await {
        tracing::error!(error = %e, kind, "writing a job event failed");
    }
}

async fn set_state(app: &App, id: &str, state: &str) {
    let r = sqlx::query("UPDATE core_hw_jobs SET state = ? WHERE id = ?")
        .bind(state)
        .bind(id)
        .execute(&app.pool)
        .await;
    if let Err(e) = r {
        tracing::error!(error = %e, "recording a job's state failed");
    }
}

async fn set_running(app: &App, id: &str) {
    let r = sqlx::query("UPDATE core_hw_jobs SET state = 'running', started_at = ? WHERE id = ?")
        .bind(app.clock.now())
        .bind(id)
        .execute(&app.pool)
        .await;
    if let Err(e) = r {
        tracing::error!(error = %e, "recording a job's start failed");
    }
}

/// The folder whose files the job works on: the session's, else the project's main copy.
fn base_of(s: &Start) -> PathBuf {
    let ws = super::workspace();
    match &s.session {
        Some(id) => ws
            .session_dir(&SessionKey {
                id,
                user: UserId(1),
                project: Some(s.project),
            })
            .unwrap_or_default(),
        None => ws
            .project_meta(s.project)
            .parent()
            .map(|p| p.join("main"))
            .unwrap_or_default(),
    }
}

/// Places the job. A job for the Core, started from a shim, is not a job at all (`Local`): the
/// command already is on the Core. A task run configuration runs on the Core's own runner.
pub async fn start(app: &App, s: Start) -> Result<Started, sqlx::Error> {
    let views = view::views(app).await?;
    let placed = place_job(&views, &need_of(&s.row), &s.project.to_string());
    let on_core = matches!(
        placed.reason,
        PlaceReason::Core | PlaceReason::CoreNoFit { .. }
    );
    if on_core && s.run_config.is_none() {
        return Ok(Started::Local(placed.reason.as_str()));
    }
    let Some(device) = views.iter().find(|v| v.device == placed.device) else {
        return Ok(Started::Local("no_hardware".to_owned()));
    };
    let id = random_id("j_");
    let now = app.clock.now();
    sqlx::query(
        "INSERT INTO core_hw_jobs (id, project_id, session_id, terminal_id, run_config_id, argv, \
         cwd_rel, device_id, place_reason, tier, state, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)",
    )
    .bind(&id)
    .bind(s.project)
    .bind(&s.session)
    .bind(&s.terminal)
    .bind(s.run_config)
    .bind(serde_json::to_string(&s.argv).unwrap_or_else(|_| "[]".to_owned()))
    .bind(&s.cwd_rel)
    .bind(&device.device)
    .bind(placed.reason.as_str())
    .bind(s.tier)
    .bind(&now)
    .execute(&app.pool)
    .await?;
    let (tx, _) = broadcast::channel(256);
    let (ctl_tx, ctl) = mpsc::unbounded_channel();
    let live = Arc::new(Live {
        frames: Mutex::default(),
        tx,
        ctl: ctl_tx,
        done: AtomicBool::new(false),
    });
    registry()
        .lock()
        .unwrap()
        .insert(id.clone(), Arc::clone(&live));
    emit(
        app,
        "job.queued",
        json!({"id": id, "project": s.project, "device": device.device}),
    )
    .await;
    let run = Run {
        id: id.clone(),
        device: device.device.clone(),
        mac: device.kind == ainkrad_proto::v2::HwKind::Mac,
        on_core,
        base: base_of(&s),
        s,
    };
    tokio::spawn(drive(app.clone(), live, ctl, run));
    Ok(Started::Job {
        id,
        device_name: device.name.clone(),
    })
}

struct Run {
    id: String,
    device: String,
    mac: bool,
    on_core: bool,
    base: PathBuf,
    s: Start,
}

/// How a job ended.
#[derive(Default)]
struct End {
    /// `ended`, `failed`, `cancelled` or `lost`.
    state: &'static str,
    exit: Option<i32>,
    signal: Option<String>,
    conflicts: u32,
    ms: u64,
    /// The command ran: the shim is told its exit. Otherwise its stream just ends.
    ran: bool,
}

fn failed(why: &str) -> End {
    tracing::warn!(why, "a heavy job did not run");
    End {
        state: "failed",
        ..End::default()
    }
}

async fn drive(app: App, live: Arc<Live>, ctl: mpsc::UnboundedReceiver<Ctl>, run: Run) {
    let end = execute(&app, &live, ctl, &run).await;
    let now = app.clock.now();
    let r = sqlx::query(
        "UPDATE core_hw_jobs SET state = ?, exit_code = ?, signal = ?, conflicts = ?, \
         ended_at = ?, duration_ms = ? WHERE id = ?",
    )
    .bind(end.state)
    .bind(end.exit)
    .bind(&end.signal)
    .bind(i64::from(end.conflicts))
    .bind(&now)
    .bind(i64::try_from(end.ms).unwrap_or(i64::MAX))
    .bind(&run.id)
    .execute(&app.pool)
    .await;
    if let Err(e) = r {
        tracing::error!(error = %e, "recording a job's end failed");
    }
    // Only a clean run says how long the command takes.
    if end.exit == Some(0) {
        let key = history::cmd_key(&run.s.argv);
        let ms = i64::try_from(end.ms).unwrap_or(i64::MAX);
        let _ = history::record(&app.pool, run.s.project, &key, ms, &now).await;
    }
    app.hub.sync.leases.revoke_scope(&run.id);
    emit(
        &app,
        "job.ended",
        json!({"id": run.id, "project": run.s.project, "device": run.device}),
    )
    .await;
    if end.ran {
        let mut exit = json!({"t": "exit", "code": end.exit});
        if let Some(sig) = &end.signal {
            exit["signal"] = json!(sig);
        }
        live.push(exit);
    }
    live.done.store(true, Ordering::SeqCst);
    // A final empty line wakes followers that wait on the channel; the senders close with the Live.
    let id = run.id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(KEEP).await;
        registry().lock().unwrap().remove(&id);
    });
}

async fn execute(
    app: &App,
    live: &Arc<Live>,
    mut ctl: mpsc::UnboundedReceiver<Ctl>,
    run: &Run,
) -> End {
    let ws = super::workspace();
    let mut sync = None;
    if !run.on_core {
        set_state(app, &run.id, "syncing").await;
        live.push(json!({"t": "state", "state": "syncing"}));
        let Ok(tree) = Tree::open(&run.base) else {
            return failed("the project folder cannot be opened");
        };
        let jobs_toml = tokio::fs::read_to_string(ws.jobs_toml(run.s.project))
            .await
            .unwrap_or_default();
        let rules = sync_rules::from_toml(&jobs_toml);
        let lease =
            app.hub
                .sync
                .leases
                .issue(&run.device, run.s.project, &run.id, 3600, unix_now());
        let mut memo = Memo::default();
        let now_ns = unix_now().saturating_mul(1_000_000_000);
        match flow::sync_in(
            &app.hub,
            &run.device,
            run.s.project,
            &lease,
            &tree,
            &rules,
            &mut memo,
            run.mac,
            now_ns,
        )
        .await
        {
            Ok(synced) => sync = Some((tree, rules, lease, memo, synced.m0)),
            Err(e) => return failed(&e.to_string()),
        }
    }
    // The runner keeps a warm cache: the prepare step (a lockfile install) runs on its first sync
    // and again whenever the lockfiles changed since it last ran.
    let lock = sync.as_ref().map(|s| cache::lock_hash(&s.4));
    let first = match &lock {
        Some(l) => !cache::prepared(app, &run.device, run.s.project, l).await,
        None => false,
    };
    let mut secrets = Vec::new();
    for (var, stored) in &run.s.secrets {
        let leased = crate::store::secrets::lease(
            &app.pool,
            stored,
            &run.device,
            None,
            &run.s.by,
            ainkrad_core::audit::AuditActor::System,
            &app.clock.now(),
            app.clock.unix(),
        )
        .await;
        match leased {
            Ok((lease, _)) => secrets.push(RunSecret {
                name: var.clone(),
                lease,
            }),
            Err(e) => return failed(&format!("cannot lease the secret for {var}: {e}")),
        }
    }
    let job = JobRun {
        job: run.id.clone(),
        project: run.s.project,
        cache: if run.on_core {
            String::new()
        } else {
            CACHE.to_owned()
        },
        argv: run.s.argv.clone(),
        cwd_rel: run.s.cwd_rel.clone(),
        env: run.s.env.clone(),
        secrets,
        prepare: run
            .s
            .row
            .prepare
            .clone()
            .filter(|_| first)
            .into_iter()
            .collect(),
        timeout_ms: None,
        need: need_of(&run.s.row),
    };
    let mut d = match app.hub.dispatch_job(&run.device, Command::JobRun(job)) {
        Ok(d) => d,
        Err(e) => return failed(&e.message),
    };
    set_running(app, &run.id).await;
    live.push(json!({"t": "state", "state": "running"}));
    emit(
        app,
        "job.started",
        json!({"id": run.id, "project": run.s.project, "device": run.device}),
    )
    .await;
    let stream = d.stream;
    let mut kill_at: Option<tokio::time::Instant> = None;
    let mut cancelled = false;
    let done = loop {
        tokio::select! {
            body = d.next() => match body {
                Some(Body::Output(o)) => live.push(json!({"t": "out", "fd": 1, "b64": o.data})),
                Some(Body::Result(Reply::JobRun(done))) => break done,
                // The runner went away, or refused: the stream ends with no exit, so the shim runs it here.
                Some(Body::Error(_)) | None => return End { state: "lost", ..End::default() },
                Some(_) => {}
            },
            c = ctl.recv() => match c {
                Some(Ctl::Signal(s)) => {
                    let _ = app.hub.send_terminal(&run.device, stream, Body::Control(Control::Signal(SignalReq { signal: s.to_owned() })));
                }
                Some(Ctl::Cancel) => {
                    cancelled = true;
                    kill_at.get_or_insert(tokio::time::Instant::now() + KILL_AFTER);
                    let _ = app.hub.send_terminal(&run.device, stream, Body::Control(Control::Signal(SignalReq { signal: "TERM".to_owned() })));
                }
                None => {}
            },
            () = async { tokio::time::sleep_until(kill_at.unwrap()).await }, if kill_at.is_some() => {
                let _ = app.hub.send_terminal(&run.device, stream, Body::Control(Control::Signal(SignalReq { signal: "KILL".to_owned() })));
                let _ = app.hub.send_terminal(&run.device, stream, Body::Close(Close::default()));
                kill_at = None;
            }
        }
    };
    let mut end = End {
        state: if cancelled { "cancelled" } else { "ended" },
        exit: done.exit_code,
        signal: done.signal.clone(),
        ms: done.duration_ms,
        ran: true,
        ..End::default()
    };
    // Nothing comes back from a cancelled job; a finished one brings its changes, Core wins.
    if let (Some((tree, rules, lease, mut memo, m0)), false) = (sync, cancelled) {
        let conflicts = ws.conflicts_dir(run.s.project, &run.id);
        let back = match conflicts {
            Some(dir) if std::fs::create_dir_all(&dir).is_ok() => match Tree::open(&dir) {
                Ok(ct) => {
                    let now_ns = unix_now().saturating_mul(1_000_000_000);
                    flow::sync_back(
                        &app.hub,
                        &run.device,
                        run.s.project,
                        &lease,
                        &tree,
                        &ct,
                        &rules,
                        &m0,
                        &mut memo,
                        now_ns,
                    )
                    .await
                }
                Err(e) => Err(e.into()),
            },
            _ => Err(crate::workspace::sync::SyncError::new(
                "workspace_io",
                "no conflicts folder",
            )),
        };
        match back {
            Ok(b) => end.conflicts = u32::try_from(b.conflicts.len()).unwrap_or(u32::MAX),
            Err(e) => {
                tracing::warn!(error = %e, job = run.id, "syncing a job's changes back failed");
                end.state = "failed";
            }
        }
        let ran_prepare = first && run.s.row.prepare.is_some() && done.exit_code == Some(0);
        let prepared = lock.filter(|_| ran_prepare);
        cache::remember(app, &run.device, run.s.project, &done.tree, prepared).await;
    }
    end
}
