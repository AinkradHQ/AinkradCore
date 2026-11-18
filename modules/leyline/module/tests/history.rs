//! Session history, recording, replay and retention (Y3-02) through the Core's real gate and relay
//! types, with a runner the hub drives from the outside. The relay's own call into the tap
//! (`stream`, over a WebSocket) is exercised here by calling the registered tap the way it does.
//! Each test fails if the property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate, settings};
use ainkrad_proto::redact::PLANTED;
use ainkrad_proto::v2::{
    Body, Command, Control, DriverInfo, Frame, Output, PtyOpen, Reply, RunnerHello, Size,
    TerminalExit, TerminalInfo, TerminalState,
};
use axum::body::{Body as Http, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use leyline_module::Leyline;
use serde_json::{Value, json};
use tokio::sync::mpsc::Receiver;
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/leyline/v1";

struct Fx {
    app: App,
    /// Admin, terminal scope, stepped up.
    admin: TestDevice,
    /// Admin and terminal, not stepped up.
    laptop: TestDevice,
    runner: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn enroll(app: &App, name: &str, kind: &str, scopes: &[&str]) -> TestDevice {
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        name,
        kind,
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    dev
}

async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "leyline-history-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Leyline)];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let sealer = SecretBox::new(&[7; 32]);
    let identity = Arc::new(Identity::load_or_create(&dir, &sealer).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    app.secrets = Some(Arc::new(sealer));
    settings::set(
        &app.pool,
        Key::SecretsMode,
        Scope::Server,
        "2",
        BY,
        &app.clock.now(),
    )
    .await
    .unwrap();
    let scopes = ["admin", "read", "terminal"];
    let admin = enroll(&app, "admin", "device", &scopes).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    let laptop = enroll(&app, "laptop", "device", &scopes).await;
    let runner = enroll(&app, "runner-1", "runner", &["runner"]).await;
    Fx {
        app,
        admin,
        laptop,
        runner,
        dir,
    }
}

async fn call(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let uri = format!("{BASE}{path}");
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    for (name, value) in dev.headers(method.as_str(), &uri, bytes.as_bytes()) {
        b = b.header(name, value);
    }
    if !bytes.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Http::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let text = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&text).unwrap_or(Value::Null))
}

fn drivers(pty_ssh: bool) -> Vec<DriverInfo> {
    let ssh: Vec<String> = if pty_ssh {
        vec!["ssh.exec".to_owned(), "pty.ssh".to_owned()]
    } else {
        vec!["ssh.exec".to_owned()]
    };
    vec![
        DriverInfo {
            name: "pty".to_owned(),
            commands: ["pty.open", "pty.attach", "pty.close"]
                .map(str::to_owned)
                .to_vec(),
            capacity: 8,
            ..DriverInfo::default()
        },
        DriverInfo {
            name: "ssh".to_owned(),
            commands: ssh,
            capacity: 4,
            ..DriverInfo::default()
        },
    ]
}

/// The runner goes online with (or without) the ssh pty feature.
fn online(fx: &Fx, pty_ssh: bool) -> Receiver<Frame> {
    fx.app.hub.fake_runner(
        &fx.runner.id,
        RunnerHello {
            drivers: drivers(pty_ssh),
            ..RunnerHello::default()
        },
    )
}

/// A key and a host `name` reached through the runner; `jump` is an optional jump host's id.
async fn host(fx: &Fx, name: &str, jump: Option<&str>) -> String {
    let (s, k) = call(
        fx,
        &fx.admin,
        Method::POST,
        "/keys",
        Some(json!({"name": format!("k-{name}")})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{k}");
    let mut body = json!({"name": name, "address": format!("{name}.example.com"), "username": "deploy",
        "key_id": k["id"], "via_runner": fx.runner.id});
    if let Some(j) = jump {
        body["jump_chain"] = json!([j]);
    }
    let (s, v) = call(fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

async fn scalar(fx: &Fx, sql: &str, bind: &str) -> String {
    let sql = sqlx::AssertSqlSafe(sql.to_owned()); // test-only literals
    sqlx::query_scalar(sql)
        .bind(bind.to_owned())
        .fetch_optional(&fx.app.pool)
        .await
        .unwrap()
        .unwrap_or_default()
}

async fn n(fx: &Fx, table: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")); // test-only literal
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

fn exits(code: i32, terminal: &str) -> Body {
    Body::Result(Reply::PtyOpen(TerminalExit {
        terminal: terminal.to_owned(),
        exit_code: Some(code),
        signal: None,
        host_key: None,
    }))
}

async fn open_terminal(
    fx: &Fx,
    rx: &mut Receiver<Frame>,
    host: &str,
    then: impl FnOnce(&str) -> Vec<Body>,
) -> (StatusCode, Value, Option<PtyOpen>) {
    let body = Some(json!({"rows": 24, "cols": 80}));
    let path = format!("/hosts/{host}/terminals");
    let ask = call(fx, &fx.admin, Method::POST, &path, body);
    let serve = async {
        let f = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .ok()??;
        let terminal = format!("t_{}", f.stream_id);
        let Some(Body::Command(Command::PtyOpen(open))) = f.body().unwrap() else {
            panic!("not a pty.open")
        };
        let info = TerminalInfo {
            terminal: terminal.clone(),
            state: TerminalState::Running,
            size: Size { rows: 24, cols: 80 },
            seq: 0,
            pid: None,
            exit: None,
        };
        let mut seq = 0;
        let frames = std::iter::once(Body::Control(Control::Opened(info))).chain(then(&terminal));
        for b in frames {
            fx.app
                .hub
                .fake_reply(&fx.runner.id, Frame::new(f.stream_id, seq, b));
            seq += 1;
        }
        Some(open)
    };
    let (answer, open) = tokio::join!(ask, serve);
    (answer.0, answer.1, open)
}

/// `call`, but the body as text (the replay is not JSON).
async fn raw(fx: &Fx, dev: &TestDevice, path: &str) -> (StatusCode, String) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .header(header::HOST, HOST);
    for (name, value) in dev.headers("GET", &uri, b"") {
        b = b.header(name, value);
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Http::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let text = to_bytes(res.into_body(), 1 << 24).await.unwrap();
    (status, String::from_utf8_lossy(&text).into_owned())
}

fn printed(text: &str) -> Body {
    Body::Output(Output {
        data: B64.encode(text),
    })
}

async fn recording_for(fx: &Fx, host: &str, record: &str) {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::PUT,
        &format!("/hosts/{host}/recording"),
        Some(json!({"record": record})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["record"], record);
}

/// Opens a terminal on `host` and leaves it running; returns the session id and terminal id.
async fn open_running(fx: &Fx, rx: &mut Receiver<Frame>, host: &str) -> (String, String) {
    let (s, v, _) = open_terminal(fx, rx, host, |_| vec![]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (
        v["id"].as_str().unwrap().to_owned(),
        v["terminal"].as_str().unwrap().to_owned(),
    )
}

/// The runner reports the terminal's exit.
fn end_terminal(fx: &Fx, terminal: &str) {
    let stream: u64 = terminal.trim_start_matches("t_").parse().unwrap();
    fx.app
        .hub
        .fake_reply(&fx.runner.id, Frame::new(stream, 9, exits(0, terminal)));
}

async fn until_recording_ends(fx: &Fx, session: &str) {
    for _ in 0..100 {
        let done = n(
            fx,
            &format!("leyline_recordings WHERE session = '{session}' AND ended_at IS NOT NULL"),
        )
        .await;
        if done == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the recording never ended")
}

fn recordings_dir(fx: &Fx) -> PathBuf {
    fx.dir.join("leyline").join("recordings")
}

#[tokio::test]
async fn recording_off_writes_nothing_and_no_tap_exists() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    let (session, terminal) = open_running(&fx, &mut rx, &h).await;
    assert!(fx.app.terminals.tap_of(&terminal).is_none());
    end_terminal(&fx, &terminal);
    for _ in 0..100 {
        if !scalar(
            &fx,
            "SELECT ended_at FROM leyline_sessions WHERE id = ?",
            &session,
        )
        .await
        .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(n(&fx, "leyline_recordings").await, 0);
    assert_eq!(
        n(&fx, "leyline_recording_key").await,
        0,
        "no key made either"
    );
    assert!(!recordings_dir(&fx).exists(), "no file, no directory");
    // The history still lists the session, as not recorded.
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/hosts/{h}/sessions"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v[0]["id"], session.as_str());
    assert_eq!(v[0]["recorded"], false);
}

#[tokio::test]
async fn turning_recording_on_needs_a_step_up_and_off_does_not() {
    let fx = fx().await;
    let h = host(&fx, "alpha", None).await;
    let path = format!("/hosts/{h}/recording");
    let (s, b) = call(
        &fx,
        &fx.laptop,
        Method::PUT,
        &path,
        Some(json!({"record": "on"})),
    )
    .await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert_eq!(
        scalar(&fx, "SELECT record FROM leyline_hosts WHERE id = ?", &h).await,
        "off"
    );
    recording_for(&fx, &h, "on").await;
    assert_eq!(
        scalar(&fx, "SELECT record FROM leyline_hosts WHERE id = ?", &h).await,
        "on"
    );
    let (s, _) = call(
        &fx,
        &fx.laptop,
        Method::PUT,
        &path,
        Some(json!({"record": "off"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &path,
        Some(json!({"record": "loud"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        n(&fx, "audit_events WHERE action = 'leyline.recording.on'").await,
        1
    );
}

#[tokio::test]
async fn a_recorded_session_is_redacted_output_only_encrypted_and_replayable() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    recording_for(&fx, &h, "on").await;
    let (session, terminal) = open_running(&fx, &mut rx, &h).await;
    let tap = fx
        .app
        .terminals
        .tap_of(&terminal)
        .expect("a tap on a recorded terminal");

    // What the relay hands the tap: runner output with a seeded secret, and a password prompt
    // whose typed answer an echoing remote sends back.
    let (_, secret) = PLANTED[0];
    let frames = [
        format!("deploy@alpha:~$ cat .env\r\nAPI_KEY={secret}\r\n"),
        "deploy@alpha:~$ sudo ls\r\n[sudo] password for deploy: ".to_owned(),
        "hunter2-correct-horse".to_owned(),
        "\r\nbin  etc  home\r\n".to_owned(),
    ];
    let mut at = 0u64;
    for f in &frames {
        tap.output(at, &B64.encode(f));
        at += f.len() as u64;
    }
    // A client attaching afresh is replayed the history: it must not appear twice.
    tap.output(0, &B64.encode(&frames[0]));
    drop(tap);
    end_terminal(&fx, &terminal);
    until_recording_ends(&fx, &session).await;

    // On disk: one file, no plaintext, owner-only.
    let file = recordings_dir(&fx).join(format!("{session}.cast.age"));
    let bytes = std::fs::read(&file).unwrap();
    assert!(
        !bytes.windows(6).any(|w| w == b"deploy"),
        "plaintext on disk"
    );
    assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Replay needs the step-up; the Core decrypts for a stepped-up caller.
    let path = format!("/sessions/{session}/recording");
    let (s, _) = raw(&fx, &fx.laptop, &path).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, cast) = raw(&fx, &fx.admin, &path).await;
    assert_eq!(s, StatusCode::OK, "{cast}");
    let head: Value = serde_json::from_str(cast.lines().next().unwrap()).unwrap();
    assert_eq!(
        (&head["version"], &head["width"], &head["height"]),
        (&json!(2), &json!(80), &json!(24))
    );
    assert!(cast.contains("cat .env"), "{cast}");
    assert!(
        !cast.contains(secret),
        "the seeded secret was written: {cast}"
    );
    assert!(cast.contains("[redacted:"), "{cast}");
    assert!(
        !cast.contains("hunter2") && !cast.contains("horse"),
        "a typed password was written"
    );
    assert!(cast.contains("[sudo] password for deploy: "));
    assert!(cast.contains("bin  etc  home"));
    assert_eq!(
        cast.matches("cat .env").count(),
        1,
        "replayed history was written twice"
    );
    for line in cast.lines().skip(1) {
        let e: Value = serde_json::from_str(line).unwrap();
        assert_eq!(e[1], "o", "an event that is not output: {line}");
    }
    assert_eq!(
        n(
            &fx,
            "audit_events WHERE action = 'leyline.recording.replayed'"
        )
        .await,
        1
    );

    // The session list says so; a pruned or absent one is a 404.
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/hosts/{h}/sessions"),
        None,
    )
    .await;
    assert_eq!(v[0]["recorded"], true);
    assert!(v[0]["recording_bytes"].as_i64().unwrap() > 0);
    let (s, _) = raw(&fx, &fx.admin, "/sessions/ls_0000000000000000/recording").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sessions_list_per_project_follows_the_attached_hosts() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    let other = host(&fx, "beta", None).await;
    let (session, _) = open_running(&fx, &mut rx, &h).await;
    sqlx::query(
        "INSERT INTO leyline_project_hosts (project, host_id, role) VALUES ('7', ?, 'other')",
    )
    .bind(&h)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let (s, v) = call(&fx, &fx.admin, Method::GET, "/projects/7/sessions", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["id"], session.as_str());
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/hosts/{other}/sessions"),
        None,
    )
    .await;
    assert_eq!(v, json!([]));
    let (s, _) = call(&fx, &fx.admin, Method::GET, "/projects/x/sessions", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
