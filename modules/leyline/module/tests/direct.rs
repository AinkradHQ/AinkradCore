//! Mac-direct leases (Y6-01) through the Core's real gate, with a runner the hub drives from the
//! outside (`Hub::fake_runner`): every frame the Core sends is seen, every frame it gets is chosen.

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
use ainkrad_proto::v2::{
    Body, Command, DriverInfo, ErrorCode, Frame, Reply, RunnerHello, SshAgentDropped,
    SshAgentLoaded, StreamError,
};
use axum::body::{Body as Http, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
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

/// The next frame that is not a `close`: the Core closes the stream of a finished terminal or request, and that
/// must not be mistaken for the command a test waits for.
async fn next_open(
    rx: &mut Receiver<Frame>,
    secs: u64,
) -> Result<Option<Frame>, tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            let f = rx.recv().await?;
            if !matches!(f.body(), Ok(Some(Body::Close(_)))) {
                return Some(f);
            }
        }
    })
    .await
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

/// The runner goes online as a Mac that offers (or not) the agent ops.
fn online(fx: &Fx, agent: bool) -> Receiver<Frame> {
    online_as(fx, &fx.runner.id, agent)
}

fn online_as(fx: &Fx, runner: &str, agent: bool) -> Receiver<Frame> {
    let mut ssh = vec!["ssh.exec".to_owned(), "pty.ssh".to_owned()];
    if agent {
        ssh.extend(["ssh.agent.load", "ssh.agent.drop"].map(str::to_owned));
    }
    fx.app.hub.fake_runner(
        runner,
        RunnerHello {
            drivers: vec![DriverInfo {
                name: "ssh".to_owned(),
                commands: ssh,
                capacity: 4,
                ..DriverInfo::default()
            }],
            os: Some("macos".to_owned()),
            ..RunnerHello::default()
        },
    )
}

/// Takes the next command the Core sends and answers it.
async fn serve(fx: &Fx, rx: &mut Receiver<Frame>, answer: Body) -> Command {
    let f = next_open(rx, 10)
        .await
        .expect("the Core sent nothing")
        .expect("the runner link closed");
    let Some(Body::Command(c)) = f.body().unwrap() else {
        panic!("not a command: {:?}", f.body())
    };
    fx.app
        .hub
        .fake_reply(&fx.runner.id, Frame::new(f.stream_id, 0, answer));
    c
}

fn loaded() -> Body {
    Body::Result(Reply::SshAgentLoad(SshAgentLoaded {
        socket: "/tmp/ainkrad-ssh.x/agent.sock".into(),
        config: "/tmp/ainkrad-ssh.x/ssh_config".into(),
    }))
}

async fn lease(
    fx: &Fx,
    dev: &TestDevice,
    rx: &mut Receiver<Frame>,
    h: &str,
    answer: Body,
) -> (StatusCode, Value, Option<Command>) {
    let path = format!("/hosts/{h}/direct");
    let ask = call(fx, dev, Method::POST, &path, Some(json!({})));
    let (a, c) = tokio::join!(ask, async {
        // Only an answered request has a command to serve: wait briefly for one.
        match next_open(rx, 2).await {
            Ok(Some(f)) => {
                let Some(Body::Command(c)) = f.body().unwrap() else {
                    panic!("not a command: {:?}", f.body())
                };
                fx.app
                    .hub
                    .fake_reply(&fx.runner.id, Frame::new(f.stream_id, 0, answer));
                Some(c)
            }
            _ => None,
        }
    });
    (a.0, a.1, c)
}

#[tokio::test]
async fn a_lease_goes_through_the_gate_with_one_lease_per_machine_and_only_pinned_keys() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let jump = host(&fx, "jump", None).await;
    let h = host(&fx, "alpha", Some(&jump)).await;
    trust_row(&fx, &jump, &fp('J'), "trusted").await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    trust_row(&fx, &h, &fp('B'), "seen").await;
    let (s, v, c) = lease(&fx, &fx.admin, &mut rx, &h, loaded()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let Some(Command::SshAgentLoad(load)) = c else {
        panic!("no agent.load: {c:?}")
    };
    assert!(load.id.starts_with("ld_") && load.ttl_secs == 3600);
    // The jump host's key first, then the target's; each with its own machine's pin only.
    let pins: Vec<_> = load.keys.iter().map(|k| k.pinned_keys.clone()).collect();
    assert_eq!(pins, vec![vec![fp('J')], vec![fp('A')]]);
    assert!(load.keys.iter().all(|k| k.lease.starts_with("l_")));
    // Each key with its own machine's login user.
    assert!(load.keys.iter().all(|k| k.user == "deploy"));
    assert_eq!(
        v["ready"],
        json!(
            "ssh -F '/tmp/ainkrad-ssh.x/ssh_config' -J deploy@jump.example.com:22 -p 22 deploy@alpha.example.com"
        )
    );
    assert_eq!(v["socket"], json!("/tmp/ainkrad-ssh.x/agent.sock"));
    // Through the gate, by this person; audited; the response carries no lease.
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_runs WHERE action LIKE ?",
            "leylineDirect"
        )
        .await,
        "done"
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT principal FROM leyline_direct WHERE id = ?",
            v["id"].as_str().unwrap()
        )
        .await,
        format!("person:{}", fx.admin.id)
    );
    assert_eq!(
        n(&fx, "audit_events WHERE action = 'leyline.direct.leased'").await,
        1
    );
    assert!(!v.to_string().contains("l_"), "a lease in the answer: {v}");
}

#[tokio::test]
async fn a_machine_without_a_pinned_key_a_missing_step_up_or_a_runner_without_the_agent_leases_nothing()
 {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    // Nothing trusted yet.
    let (s, v, c) = lease(&fx, &fx.admin, &mut rx, &h, loaded()).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("host_not_trusted")),
        "{v}"
    );
    assert!(c.is_none());
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    // No step-up.
    let (s, v, c) = lease(&fx, &fx.laptop, &mut rx, &h, loaded()).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert!(c.is_none());
    // A runner that lists no agent ops.
    let mut rx2 = online(&fx, false);
    let (s, v, c) = lease(&fx, &fx.admin, &mut rx2, &h, loaded()).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("no_mac_runner")),
        "{v}"
    );
    assert!(c.is_none());
    assert_eq!(n(&fx, "core_secret_leases").await, 0, "a lease was spent");
    assert_eq!(n(&fx, "leyline_direct").await, 0);
}

#[tokio::test]
async fn one_lease_per_host_and_a_revoke_drops_the_agent_and_records_what_it_did() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    let (s, v, c) = lease(&fx, &fx.admin, &mut rx, &h, loaded()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let Some(Command::SshAgentLoad(load)) = c else {
        panic!("no agent.load")
    };
    let (s, v, c) = lease(&fx, &fx.admin, &mut rx, &h, loaded()).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("already_leased")),
        "{v}"
    );
    assert!(c.is_none());
    let path = format!("/hosts/{h}/direct/revoke");
    let drop_answer = Body::Result(Reply::SshAgentDrop(SshAgentDropped {
        was_live: true,
        signatures: 3,
        refused: 1,
    }));
    let ask = call(&fx, &fx.admin, Method::POST, &path, None);
    let (a, sent) = tokio::join!(ask, serve(&fx, &mut rx, drop_answer));
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    let Command::SshAgentDrop(d) = sent else {
        panic!("not a drop")
    };
    assert_eq!(d.id, load.id);
    assert_eq!(
        (&a.1["signatures"], &a.1["runner_reached"]),
        (&json!(3), &json!(true))
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT end_reason FROM leyline_direct WHERE id = ?",
            &load.id
        )
        .await,
        "revoked"
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT CAST(signatures AS TEXT) FROM leyline_direct WHERE id = ?",
            &load.id
        )
        .await,
        "3"
    );
    assert_eq!(
        n(&fx, "audit_events WHERE action = 'leyline.direct.revoked'").await,
        1
    );
    // Nothing left to revoke; and the host can be leased again.
    let (s, _) = call(&fx, &fx.admin, Method::POST, &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v, _) = lease(&fx, &fx.admin, &mut rx, &h, loaded()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn a_load_the_runner_refuses_leaves_no_open_lease_and_no_lease_behind() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    let refused = Body::Error(StreamError::new(ErrorCode::SshAuthFailed, "secret detail"));
    let path = format!("/hosts/{h}/direct");
    let ask = call(&fx, &fx.admin, Method::POST, &path, Some(json!({})));
    let runner = async {
        serve(&fx, &mut rx, refused).await;
        // The Core makes sure nothing was left running.
        serve(
            &fx,
            &mut rx,
            Body::Result(Reply::SshAgentDrop(SshAgentDropped::default())),
        )
        .await
    };
    let (a, second) = tokio::join!(ask, runner);
    assert_eq!(a.0, StatusCode::BAD_GATEWAY, "{}", a.1);
    assert!(
        !a.1.to_string().contains("secret detail"),
        "the runner's text was echoed"
    );
    assert!(matches!(second, Command::SshAgentDrop(_)));
    assert_eq!(
        scalar(
            &fx,
            "SELECT end_reason FROM leyline_direct WHERE host_id = ?",
            &h
        )
        .await,
        "failed"
    );
    assert_eq!(n(&fx, "core_secret_leases").await, 0);
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_runs WHERE action LIKE ?",
            "leylineDirect"
        )
        .await,
        "done"
    );
}

/// A request of `dev` to a Core route (not the module's).
async fn core_call(fx: &Fx, dev: &TestDevice, path: &str, body: Value) -> (StatusCode, Value) {
    let bytes = body.to_string();
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in dev.headers("POST", path, bytes.as_bytes()) {
        b = b.header(name, value);
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Http::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let text = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&text).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_lease_mints_a_single_use_key_for_the_mac_without_widening_the_key_scope() {
    let fx = fx().await;
    // The Mac is not the host's runner: it is in no key's runner list.
    let mac = enroll(&fx.app, "mac", "runner", &["runner"]).await;
    let mut rx = online_as(&fx, &mac.id, true);
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    let secret = scalar(
        &fx,
        "SELECT k.secret FROM leyline_keys k JOIN leyline_hosts h ON h.key_id = k.id WHERE h.id = ?",
        &h,
    )
    .await;
    let runners_sql = "SELECT runners FROM core_secrets WHERE name = ?";
    let before = scalar(&fx, runners_sql, &secret).await;
    let changes = "audit_events WHERE action = 'secret.runners_changed'";
    let changed_before = n(&fx, changes).await;
    // A lease of the key's own (unredeemed) to the host's runner: a Mac-direct lease must not drop it.
    let (s, own) = core_call(
        &fx,
        &fx.admin,
        &format!("/api/v1/secrets/{secret}/leases"),
        json!({"runner": fx.runner.id}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{own}");
    let path = format!("/hosts/{h}/direct");
    let ask = call(&fx, &fx.admin, Method::POST, &path, Some(json!({})));
    let runner = async {
        let f = next_open(&mut rx, 10)
            .await
            .expect("the Core sent nothing")
            .expect("the link closed");
        let Some(Body::Command(Command::SshAgentLoad(load))) = f.body().unwrap() else {
            panic!("not an agent.load")
        };
        let lease = load.keys[0].lease.clone();
        // The Mac redeems it: the key's OpenSSH text, once.
        let first = core_call(
            &fx,
            &mac,
            "/api/v1/secret-leases/redeem",
            json!({"lease": lease}),
        )
        .await;
        let again = core_call(
            &fx,
            &mac,
            "/api/v1/secret-leases/redeem",
            json!({"lease": lease}),
        )
        .await;
        fx.app
            .hub
            .fake_reply(&mac.id, Frame::new(f.stream_id, 0, loaded()));
        (first, again)
    };
    let ((s, v), (first, again)) = tokio::join!(ask, runner);
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert!(
        first.1["value"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    assert_eq!(again.0, StatusCode::NOT_FOUND, "a second redemption");
    // The stored scope did not move, nothing was audited as a scope change, the other lease lives.
    assert_eq!(scalar(&fx, runners_sql, &secret).await, before);
    assert!(!before.contains(&mac.id));
    assert_eq!(n(&fx, changes).await, changed_before);
    let (s, _) = core_call(
        &fx,
        &fx.runner,
        "/api/v1/secret-leases/redeem",
        json!({"lease": own["lease"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "the host runner's own lease was dropped");
    // And no other lease path reaches the Mac: the admin route refuses it (not in scope).
    let (s, v) = core_call(
        &fx,
        &fx.admin,
        &format!("/api/v1/secrets/{secret}/leases"),
        json!({"runner": mac.id}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn a_drop_the_runner_never_got_is_sent_again_when_it_is_back() {
    let fx = fx().await;
    let mut rx = online(&fx, true);
    let h = host(&fx, "alpha", None).await;
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    let (s, v, c) = lease(&fx, &fx.admin, &mut rx, &h, loaded()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let Some(Command::SshAgentLoad(load)) = c else {
        panic!("no agent.load")
    };
    // The revoke's drop is lost: the row ends, unreached.
    let path = format!("/hosts/{h}/direct/revoke");
    let lost = Body::Error(StreamError::new(ErrorCode::Lost, "gone"));
    let ask = call(&fx, &fx.admin, Method::POST, &path, None);
    let (a, _) = tokio::join!(ask, serve(&fx, &mut rx, lost));
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a.1["runner_reached"], json!(false));
    let reached = "SELECT CAST(runner_reached AS TEXT) FROM leyline_direct WHERE id = ?";
    assert_eq!(scalar(&fx, reached, &load.id).await, "0");
    // The runner says hello again; the Core's watch (every 5 s) sends the drop again.
    let mut rx = online(&fx, true);
    Leyline.attach(&fx.app);
    let answer = Body::Result(Reply::SshAgentDrop(SshAgentDropped {
        was_live: true,
        signatures: 2,
        refused: 0,
    }));
    let Command::SshAgentDrop(d) = serve(&fx, &mut rx, answer).await else {
        panic!("not a drop")
    };
    assert_eq!(d.id, load.id);
    for _ in 0..50 {
        if scalar(&fx, reached, &load.id).await == "1" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(scalar(&fx, reached, &load.id).await, "1");
    assert_eq!(
        n(&fx, "audit_events WHERE action = 'leyline.direct.dropped'").await,
        1
    );
}
