//! Host terminals and host-key trust (Y3-01) through the Core's real gate, with a runner the hub
//! drives from the outside (`Hub::fake_runner`): every frame the Core sends is seen, every frame
//! it gets is chosen. Each test fails if the property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::v1::{BY, Caller};
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::hub::Elevated;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate, settings};
use ainkrad_proto::v2::{
    Body, Command, Control, DriverInfo, ErrorCode, Frame, Output, PtyOpen, Reply, RunnerHello,
    Size, StreamError, TerminalExit, TerminalInfo, TerminalState,
};
use axum::body::{Body as Http, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use leyline_module::Leyline;
use leyline_module::hostkeys;
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
        "leyline-term-{}-{}",
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

fn fp(c: char) -> String {
    format!("SHA256:{}", c.to_string().repeat(43))
}

async fn trust_row(fx: &Fx, host: &str, fingerprint: &str, state: &str) {
    sqlx::query(
        "INSERT INTO leyline_host_keys (host_id, algo, key_b64, fingerprint, state, first_seen) \
         VALUES (?, '', '', ?, ?, '2026-01-01T00:00:00Z')",
    )
    .bind(host)
    .bind(fingerprint)
    .bind(state)
    .execute(&fx.app.pool)
    .await
    .unwrap();
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

fn printed(text: &str) -> Body {
    Body::Output(Output {
        data: B64.encode(text),
    })
}

fn exits(code: i32, terminal: &str) -> Body {
    Body::Result(Reply::PtyOpen(TerminalExit {
        terminal: terminal.to_owned(),
        exit_code: Some(code),
        signal: None,
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

async fn session_ends(fx: &Fx, host: &str) -> String {
    for _ in 0..100 {
        let r = scalar(
            fx,
            "SELECT end_reason FROM leyline_sessions WHERE host_id = ? AND ended_at IS NOT NULL ORDER BY started_at DESC",
            host,
        )
        .await;
        if !r.is_empty() {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the session never ended")
}

#[tokio::test]
async fn a_terminal_goes_through_the_gate_with_a_lease_and_the_pinned_keys() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    trust_row(&fx, &h, &fp('B'), "seen").await; // not pinned until a person says so
    trust_row(&fx, &h, &fp('C'), "replaced").await;
    let (s, v, open) = open_terminal(&fx, &mut rx, &h, |_| vec![]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let ssh = open
        .expect("the runner got an open")
        .ssh
        .expect("an ssh open");
    assert!(ssh.hops.is_empty());
    assert_eq!(ssh.target.host, "alpha.example.com");
    assert_eq!(ssh.target.user, "deploy");
    assert_eq!(
        ssh.target.pinned_keys,
        vec![fp('A')],
        "only the trusted key is pinned"
    );
    assert!(ssh.target.lease.starts_with("l_"), "a lease, never a key");
    // A normal Core terminal the app attaches to, owned by the opener.
    let t = v["terminal"].as_str().unwrap();
    assert_eq!(
        scalar(&fx, "SELECT opened_by FROM core_terminals WHERE id = ?", t).await,
        fx.admin.id
    );
    assert_eq!(
        scalar(&fx, "SELECT runner FROM core_terminals WHERE id = ?", t).await,
        fx.runner.id
    );
    // It went through the gate: one finished terminal run, by this person, and a session row.
    assert_eq!(n(&fx, "leyline_runs").await, 1);
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_runs WHERE action LIKE ?",
            "leylineTerminal"
        )
        .await,
        "done"
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT principal FROM leyline_sessions WHERE id = ?",
            v["id"].as_str().unwrap()
        )
        .await,
        format!("person:{}", fx.admin.id)
    );
    // A terminal needs the step-up, like the Core's own.
    let (s, b) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &format!("/hosts/{h}/terminals"),
        Some(json!({"rows": 24, "cols": 80})),
    )
    .await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
}

#[tokio::test]
async fn a_runner_without_pty_ssh_is_refused_before_any_lease_and_by_the_hub() {
    let fx = fx().await;
    let mut rx = online(&fx, false);
    let h = host(&fx, "alpha", None).await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/hosts/{h}/terminals"),
        Some(json!({"rows": 24, "cols": 80})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("runner_cannot_ssh")),
        "{v}"
    );
    assert!(rx.try_recv().is_err(), "nothing was sent to the runner");
    assert_eq!(n(&fx, "core_secret_leases").await, 0, "no lease was spent");
    assert_eq!(n(&fx, "leyline_sessions").await, 0);
    assert_eq!(n(&fx, "core_terminals").await, 0);
    // The run is not left waiting: the gate's proof was finished as failed.
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_runs WHERE action LIKE ?",
            "leylineTerminal"
        )
        .await,
        "done"
    );
    // Whoever asks, the hub itself will not send an ssh open to such a runner (it would open a
    // local shell); the same open without ssh is fine, and so is ssh to a runner that lists it.
    let open = |ssh| {
        Command::PtyOpen(PtyOpen {
            program: None,
            args: vec![],
            cwd: None,
            session: None,
            env: Default::default(),
            env_pass: vec![],
            size: Size { rows: 24, cols: 80 },
            watch: true,
            scrollback_bytes: None,
            scrollback_budget: None,
            ssh,
        })
    };
    let ssh = || {
        Some(ainkrad_proto::v2::SshTerminal {
            target: ainkrad_proto::v2::SshHop {
                host: "a.example.com".into(),
                port: 22,
                user: "u".into(),
                pinned_keys: vec![],
                lease: "l_x".into(),
            },
            hops: vec![],
        })
    };
    let hub = &fx.app.hub;
    let e = hub
        .dispatch_elevated(&fx.runner.id, open(ssh()), Elevated::for_tests())
        .err()
        .expect("refused");
    assert_eq!(e.code, ErrorCode::UnsupportedCommand);
    assert!(
        hub.dispatch_elevated(&fx.runner.id, open(None), Elevated::for_tests())
            .is_ok()
    );
    let _rx2 = online(&fx, true);
    assert!(
        hub.dispatch_elevated(&fx.runner.id, open(ssh()), Elevated::for_tests())
            .is_ok()
    );
    drop(rx);
}

#[tokio::test]
async fn an_offline_runner_and_a_host_without_a_key_are_refused() {
    let fx = fx().await;
    let h = host(&fx, "alpha", None).await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/hosts/{h}/terminals"),
        Some(json!({"rows": 24, "cols": 80})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("runner_cannot_ssh")),
        "never connected: {v}"
    );
    let _rx = online(&fx, true);
    let (s, keyless) = call(&fx, &fx.admin, Method::POST, "/hosts", Some(json!({"name": "pw", "address": "pw.example.com", "username": "deploy", "via_runner": fx.runner.id}))).await;
    assert_eq!(s, StatusCode::OK, "{keyless}");
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/hosts/{}/terminals", keyless["id"].as_str().unwrap()),
        Some(json!({"rows": 24, "cols": 80})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("host_needs_key")),
        "{v}"
    );
    assert_eq!(n(&fx, "core_secret_leases").await, 0);
}

#[tokio::test]
async fn first_connect_leaves_the_seen_key_and_a_person_trusts_it_once() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    let line = format!("host key unknown: {} (hop 0); not pinned\r\n", fp('K'));
    let (s, v, open) =
        open_terminal(&fx, &mut rx, &h, |t| vec![printed(&line), exits(70, t)]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        open.unwrap().ssh.unwrap().target.pinned_keys.is_empty(),
        "nothing is trusted on first sight"
    );
    assert_eq!(session_ends(&fx, &h).await, "host_key_unknown");
    let (s, keys) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/hosts/{h}/host-keys"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(keys[0]["fingerprint"], json!(fp('K')));
    assert_eq!(keys[0]["state"], json!("seen"));
    assert_eq!(n(&fx, "events WHERE kind = 'leyline.hostkey'").await, 1);
    // A person trusts the key it saw: now pinned; a second trust has nothing waiting.
    let path = format!("/hosts/{h}/host-keys/trust");
    let (s, t) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &path,
        Some(json!({"fingerprint": fp('K')})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "trust needs no step-up: {t}");
    assert_eq!(
        (&t["state"], &t["trusted_by"]),
        (&json!("trusted"), &json!(fx.laptop.id))
    );
    assert_eq!(
        call(
            &fx,
            &fx.laptop,
            Method::POST,
            &path,
            Some(json!({"fingerprint": fp('K')}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // A key nobody saw cannot be trusted by typing it.
    assert_eq!(
        call(
            &fx,
            &fx.laptop,
            Method::POST,
            &path,
            Some(json!({"fingerprint": fp('Z')}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, _, open) = open_terminal(&fx, &mut rx, &h, |_| vec![]).await;
    assert_eq!(open.unwrap().ssh.unwrap().target.pinned_keys, vec![fp('K')]);
}

#[tokio::test]
async fn a_changed_key_alerts_and_only_a_stepped_up_replace_pins_it() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    let line = format!(
        "host key changed: {} (hop 0); not the pinned key\r\n",
        fp('N')
    );
    let (_, _, open) =
        open_terminal(&fx, &mut rx, &h, |t| vec![printed(&line), exits(71, t)]).await;
    assert_eq!(open.unwrap().ssh.unwrap().target.pinned_keys, vec![fp('A')]);
    assert_eq!(session_ends(&fx, &h).await, "host_key_changed");
    assert_eq!(
        n(&fx, "audit_log WHERE action = 'leyline.hostkey.changed'").await,
        1,
        "the alert hook"
    );
    assert_eq!(
        n(
            &fx,
            "events WHERE kind = 'leyline.hostkey' AND payload LIKE '%changed%'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_host_keys WHERE fingerprint = ?",
            &fp('N')
        )
        .await,
        "seen"
    );
    // The old pin stays the pin: trust cannot add to it, and replace needs the step-up.
    let trust = format!("/hosts/{h}/host-keys/trust");
    let (s, b) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &trust,
        Some(json!({"fingerprint": fp('N')})),
    )
    .await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::CONFLICT, &json!("host_key_conflict"))
    );
    let replace = format!("/hosts/{h}/host-keys/replace");
    let (s, b) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &replace,
        Some(json!({"fingerprint": fp('N')})),
    )
    .await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    let (s, b) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &replace,
        Some(json!({"fingerprint": fp('N')})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_host_keys WHERE fingerprint = ?",
            &fp('A')
        )
        .await,
        "replaced"
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_host_keys WHERE fingerprint = ?",
            &fp('N')
        )
        .await,
        "trusted"
    );
}

#[tokio::test]
async fn an_ai_session_cannot_trust_or_replace_a_key() {
    let fx = fx().await;
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    trust_row(&fx, &h, &fp('N'), "seen").await;
    let (h2, k) = (host(&fx, "beta", None).await, fp('M'));
    trust_row(&fx, &h2, &k, "seen").await;
    for session in ["code_mode:as_x", "code_mode:"] {
        let ai = Caller {
            device: ainkrad_core_server::store::gov::get_device(&fx.app.pool, &fx.admin.id)
                .await
                .unwrap()
                .unwrap(),
            session: session.to_owned(),
        };
        for r in [
            hostkeys::trust(&fx.app, &ai, &h2, &k).await,
            hostkeys::replace(&fx.app, &ai, &h, &fp('N')).await,
        ] {
            let e = r.err().expect("an AI is refused");
            assert_eq!(e.status, StatusCode::FORBIDDEN);
        }
    }
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_host_keys WHERE fingerprint = ?",
            &fp('M')
        )
        .await,
        "seen"
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_host_keys WHERE fingerprint = ?",
            &fp('A')
        )
        .await,
        "trusted"
    );
}

#[tokio::test]
async fn losing_the_runner_ends_the_session_row() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    let (s, v, _) = open_terminal(&fx, &mut rx, &h, |_| vec![]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        scalar(
            &fx,
            "SELECT ended_at FROM leyline_sessions WHERE host_id = ?",
            &h
        )
        .await,
        ""
    );
    // The hub reports what it had in flight lost once the runner is gone for good.
    let t = v["terminal"]
        .as_str()
        .unwrap()
        .trim_start_matches("t_")
        .parse::<u64>()
        .unwrap();
    fx.app.hub.fake_reply(
        &fx.runner.id,
        Frame::new(
            t,
            1,
            Body::Error(StreamError::new(ErrorCode::Lost, "the runner went")),
        ),
    );
    assert_eq!(session_ends(&fx, &h).await, "runner_lost");
}

#[tokio::test]
async fn a_jump_hop_is_pinned_and_its_key_is_kept_for_the_hop_not_the_target() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let jump = host(&fx, "jump", None).await;
    let target = host(&fx, "inner", Some(&jump)).await;
    trust_row(&fx, &jump, &fp('J'), "trusted").await;
    let line = format!("host key unknown: {} (hop 1); not pinned\r\n", fp('T'));
    let (s, v, open) = open_terminal(&fx, &mut rx, &target, |t| {
        vec![printed(&line), exits(70, t)]
    })
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let ssh = open.unwrap().ssh.unwrap();
    assert_eq!(ssh.hops.len(), 1);
    assert_eq!(ssh.hops[0].host, "jump.example.com");
    assert_eq!(ssh.hops[0].pinned_keys, vec![fp('J')]);
    assert_ne!(ssh.hops[0].lease, ssh.target.lease, "a lease per hop");
    assert_eq!(session_ends(&fx, &target).await, "host_key_unknown");
    // Hop 1 is the target (hop 0 is the jump host).
    assert_eq!(
        scalar(
            &fx,
            "SELECT host_id FROM leyline_host_keys WHERE fingerprint = ?",
            &fp('T')
        )
        .await,
        target
    );
}
