//! V6-01, Core half: a pending font or Icon Composer zip goes to a runner's `design.check` and its
//! verdict flips `check_state`; a crash of the helper is a refusal; no runner leaves it pending.
//! The runner here is played by the test through the real hub.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_core_server::store::{connect, migrate};
use ainkrad_proto::v2::{
    Body, Command, DesignChecked, DriverInfo, ErrorCode, OP_DESIGN_CHECK, Reply, RunnerHello,
    StreamError,
};
use design_module::{Design, check_pending};

async fn app(name: &str) -> (App, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("design-checks-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Design::default())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
    let mut app = App::new(pool, Arc::new(SystemClock), "core.test".into(), identity);
    app.modules = Arc::from(modules);
    (app, dir)
}

async fn pending(app: &App, sha: char, kind: &str) -> String {
    let sha = sha.to_string().repeat(64);
    sqlx::query(
        "INSERT INTO design_assets (sha256, kind, name, content_type, size, check_state, data, created_by) \
         VALUES (?, ?, 'f', 'font/ttf', 4, 'pending', x'00010000', 'person:t')",
    )
    .bind(&sha)
    .bind(kind)
    .execute(&app.pool)
    .await
    .unwrap();
    sha
}

async fn state(app: &App, sha: &str) -> String {
    sqlx::query_scalar("SELECT check_state FROM design_assets WHERE sha256 = ?")
        .bind(sha)
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

fn runner(app: &App) -> tokio::sync::mpsc::Receiver<ainkrad_proto::v2::Frame> {
    app.hub.connect_for_tests(
        "dv_runner",
        RunnerHello {
            drivers: vec![DriverInfo {
                name: "design".into(),
                commands: vec![OP_DESIGN_CHECK.into()],
                capacity: 2,
                streams: Some(2),
                ..DriverInfo::default()
            }],
            ..RunnerHello::default()
        },
    )
}

/// Answers each `design.check` the runner receives with `answer(i)`.
fn play(
    app: &App,
    mut rx: tokio::sync::mpsc::Receiver<ainkrad_proto::v2::Frame>,
    answer: fn(usize) -> Body,
) {
    let hub = Arc::clone(&app.hub);
    tokio::spawn(async move {
        let mut i = 0;
        while let Some(f) = rx.recv().await {
            if let Ok(Some(Body::Command(Command::DesignCheck(c)))) = f.body() {
                assert!(!c.kind.is_empty());
                let reply = ainkrad_proto::v2::Frame::new(f.stream_id, 0, answer(i));
                hub.answer_for_tests("dv_runner", reply);
                i += 1;
            }
        }
    });
}

#[tokio::test]
async fn verdicts_flip_the_check_state_and_a_crash_is_a_refusal() {
    let (app, dir) = app("verdicts").await;
    let a = pending(&app, 'a', "font").await;
    let b = pending(&app, 'b', "icon_composer").await;
    let c = pending(&app, 'c', "font").await;
    play(&app, runner(&app), |i| match i {
        0 => Body::Result(Reply::DesignCheck(DesignChecked {
            ok: true,
            reason: None,
        })),
        1 => Body::Result(Reply::DesignCheck(DesignChecked {
            ok: false,
            reason: Some("the file is not a font this renderer can read".into()),
        })),
        _ => Body::Error(StreamError::new(
            ErrorCode::DesignFailed,
            "the design helper failed: it was killed by a signal (a crash).",
        )),
    });
    assert_eq!(check_pending(&app).await.unwrap(), 3);
    assert_eq!(state(&app, &a).await, "ok");
    assert_eq!(state(&app, &b).await, "refused");
    assert_eq!(state(&app, &c).await, "refused");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'design.asset.checked'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 3);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn no_runner_or_a_lost_answer_leaves_it_pending() {
    let (app, dir) = app("pending").await;
    let a = pending(&app, 'a', "font").await;
    assert_eq!(check_pending(&app).await.unwrap(), 0, "no runner");
    assert_eq!(state(&app, &a).await, "pending");
    play(&app, runner(&app), |_| {
        Body::Error(StreamError::new(
            ErrorCode::Busy,
            "design is at capacity (2)",
        ))
    });
    assert_eq!(check_pending(&app).await.unwrap(), 0, "busy");
    assert_eq!(state(&app, &a).await, "pending");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_design_ops_take_the_design_path() {
    let hub = Arc::new(ainkrad_core_server::hub::Hub::new(Default::default()));
    let e = hub
        .dispatch_design(
            "dv_runner",
            Command::ExecRun(ainkrad_proto::v2::ExecRun {
                program: "/bin/sh".into(),
                args: vec![],
                cwd: None,
                env: Default::default(),
                env_pass: vec![],
                limits: Default::default(),
            }),
        )
        .err()
        .unwrap();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    // A design command passes the filter and is then refused only for want of a runner.
    let check = Command::DesignCheck(ainkrad_proto::v2::DesignCheck {
        kind: "font".into(),
        data: String::new(),
    });
    let e = hub.dispatch_design("dv_runner", check).err().unwrap();
    assert_eq!(e.code, ErrorCode::Offline);
}

/// Review M2: a sandbox that did not start (`spawn_failed`) is not a verdict: the asset stays pending.
#[tokio::test]
async fn a_sandbox_that_did_not_start_leaves_it_pending() {
    let (app, dir) = app("spawn").await;
    let a = pending(&app, 'a', "font").await;
    play(&app, runner(&app), |_| {
        Body::Error(StreamError::new(
            ErrorCode::SpawnFailed,
            "the design sandbox did not start: bwrap: Unknown option --disable-userns",
        ))
    });
    assert_eq!(check_pending(&app).await.unwrap(), 0);
    assert_eq!(state(&app, &a).await, "pending");
    std::fs::remove_dir_all(dir).unwrap();
}

/// Round 3: three wall-clock stops refuse an asset; until then it stays pending, and the pick goes
/// by the last attempt so a file that never finishes does not hold the queue.
#[tokio::test]
async fn three_timeouts_refuse_and_the_pick_goes_by_last_attempt() {
    let (app, dir) = app("limits").await;
    let a = pending(&app, 'a', "font").await;
    let b = pending(&app, 'b', "font").await;
    sqlx::query("UPDATE design_assets SET created_at = '2020-01-01T00:00:00Z' WHERE sha256 = ?")
        .bind(&a)
        .execute(&app.pool)
        .await
        .unwrap();
    // Both time out on every run.
    play(&app, runner(&app), |_| {
        Body::Error(StreamError::new(ErrorCode::DesignLimit, "its time limit"))
    });
    let attempts = |sha: String| {
        let pool = app.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT check_attempts FROM design_assets WHERE sha256 = ?",
            )
            .bind(sha)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(check_pending(&app).await.unwrap(), 0);
    assert_eq!(state(&app, &a).await, "pending");
    assert_eq!(attempts(a.clone()).await, 1);
    assert_eq!(attempts(b.clone()).await, 1);
    assert_eq!(check_pending(&app).await.unwrap(), 0);
    assert_eq!(
        check_pending(&app).await.unwrap(),
        2,
        "the third stop refuses both"
    );
    assert_eq!(state(&app, &a).await, "refused");
    assert_eq!(state(&app, &b).await, "refused");
    std::fs::remove_dir_all(dir).unwrap();
}
