//! Make a host a runner (Y8-01) through the Core's real gate, with a runner the hub drives from the
//! outside (`Hub::fake_runner`): every frame the Core sends is recorded, every answer is chosen.
//! Each test fails if the property it names stops holding.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

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
    Body, Command, Control, DriverInfo, ErrorCode, Frame, Reply, RunnerHello, SftpDone,
    SftpTransferred, Size, StreamError, TerminalInfo, TerminalState,
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
        "leyline-mkrun-{}-{}",
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
    let scopes = ["admin", "read", "terminal", "runner"];
    let admin = enroll(&app, "admin", "device", &scopes).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    admin.unlock(&app.auth, clock.unix() + 3600);
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

fn path(pairing: &str) -> String {
    format!(".ainkrad-invite-{pairing}")
}

/// What the fake runner saw.
#[derive(Default)]
struct Seen {
    /// Every command, as text (what a log of the Core's dispatch could show).
    commands: Vec<String>,
    /// Files written: path, mode, bytes.
    puts: Vec<(String, Option<u32>, Vec<u8>)>,
    removes: Vec<String>,
    opens: usize,
    typed: String,
    /// Fail the next file write.
    fail_put: bool,
}

fn drivers(sftp: bool) -> Vec<DriverInfo> {
    let mut ssh = vec!["ssh.exec".to_owned(), "pty.ssh".to_owned()];
    if sftp {
        ssh.extend(["ssh.sftp.mkdir", "ssh.sftp.write", "ssh.sftp.remove"].map(str::to_owned));
    }
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
            capacity: 8,
            ..DriverInfo::default()
        },
    ]
}

/// The runner goes online and answers like a real one, recording what it is sent.
fn online(fx: &Fx, sftp: bool) -> Arc<Mutex<Seen>> {
    let mut rx: Receiver<Frame> = fx.app.hub.fake_runner(
        &fx.runner.id,
        RunnerHello {
            drivers: drivers(sftp),
            ..RunnerHello::default()
        },
    );
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (app, id, log) = (fx.app.clone(), fx.runner.id.clone(), seen.clone());
    tokio::spawn(async move {
        let mut seq: HashMap<u64, u64> = HashMap::new();
        let mut writing: HashMap<u64, (String, Option<u32>, Vec<u8>)> = HashMap::new();
        let mut attached: Vec<u64> = Vec::new();
        let mut say = |stream: u64, b: Body| {
            let n = seq.entry(stream).or_default();
            app.hub.fake_reply(&id, Frame::new(stream, *n, b));
            *n += 1;
        };
        while let Some(f) = rx.recv().await {
            let Ok(Some(b)) = f.body() else { continue };
            let s = f.stream_id;
            match b {
                Body::Command(c) => {
                    log.lock().unwrap().commands.push(format!("{c:?}"));
                    match c {
                        Command::SshSftpMkdir(_) => {
                            say(s, Body::Result(Reply::SshSftpMkdir(SftpDone {})));
                        }
                        Command::SshSftpRemove(r) => {
                            log.lock().unwrap().removes.push(r.path);
                            say(s, Body::Result(Reply::SshSftpRemove(SftpDone {})));
                        }
                        Command::SshSftpWrite(w) => {
                            if std::mem::take(&mut log.lock().unwrap().fail_put) {
                                let e = StreamError::new(ErrorCode::SftpFailed, "no");
                                say(s, Body::Error(e));
                            } else {
                                writing.insert(s, (w.path, w.mode, Vec::new()));
                            }
                        }
                        Command::PtyOpen(_) => {
                            log.lock().unwrap().opens += 1;
                            let info = TerminalInfo {
                                terminal: format!("t_{s}"),
                                state: TerminalState::Running,
                                size: Size { rows: 24, cols: 80 },
                                seq: 0,
                                pid: None,
                                exit: None,
                            };
                            say(s, Body::Control(Control::Opened(info)));
                        }
                        Command::PtyAttach(a) => {
                            attached.push(s);
                            let info = TerminalInfo {
                                terminal: a.terminal,
                                state: TerminalState::Running,
                                size: Size { rows: 24, cols: 80 },
                                seq: 0,
                                pid: None,
                                exit: None,
                            };
                            say(s, Body::Control(Control::Opened(info)));
                        }
                        _ => {}
                    }
                }
                Body::Output(o) => {
                    let bytes = B64.decode(o.data).unwrap();
                    if let Some(w) = writing.get_mut(&s) {
                        w.2.extend(bytes);
                    } else if attached.contains(&s) {
                        log.lock().unwrap().typed += &String::from_utf8(bytes).unwrap();
                    }
                }
                Body::Control(Control::Eof) => {
                    if let Some(w) = writing.remove(&s) {
                        let n = w.2.len() as u64;
                        log.lock().unwrap().puts.push(w);
                        say(
                            s,
                            Body::Result(Reply::SshSftpWrite(SftpTransferred { bytes: n })),
                        );
                    }
                }
                _ => {}
            }
        }
    });
    seen
}

async fn until(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..300 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never happened: {what}")
}

async fn text(fx: &Fx, sql: &str) -> String {
    let sql = sqlx::AssertSqlSafe(sql.to_owned()); // test-only literals
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn make(fx: &Fx, dev: &TestDevice, host: &str) -> (StatusCode, Value) {
    let path = format!("/hosts/{host}/runner");
    call(
        fx,
        dev,
        Method::POST,
        &path,
        Some(json!({"rows": 24, "cols": 80})),
    )
    .await
}

async fn trusted_host(fx: &Fx, name: &str) -> String {
    let h = host(fx, name, None).await;
    trust_row(fx, &h, &fp('A'), "trusted").await;
    h
}

/// The secret of the invite the runner was sent as a file.
fn secret_of(puts: &[(String, Option<u32>, Vec<u8>)]) -> String {
    let token = String::from_utf8(puts[0].2.clone()).unwrap();
    token.rsplit('.').next().unwrap().to_owned()
}

#[tokio::test]
async fn one_action_installs_and_the_claim_links_the_runner_without_the_invite_leaking() {
    let fx = fx().await;
    let seen = online(&fx, true);
    let h = trusted_host(&fx, "alpha").await;
    let (s, v) = make(&fx, &fx.admin, &h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    until("the line was typed", || {
        !seen.lock().unwrap().typed.is_empty()
    })
    .await;
    let (puts, commands, typed, opens) = {
        let g = seen.lock().unwrap();
        (g.puts.clone(), g.commands.clone(), g.typed.clone(), g.opens)
    };
    // The invite is one 0600 file in the user's cache, whole, and the one place it is.
    assert_eq!(puts.len(), 1);
    let p = v["pairing"].as_str().unwrap().to_owned();
    assert_eq!(
        puts[0].0,
        path(&p),
        "a per-pairing file, straight in the home"
    );
    assert!(
        !commands.iter().any(|c| c.contains("SshSftpMkdir")),
        "no directory is created or trusted"
    );
    assert_eq!(puts[0].1, Some(0o600));
    let secret = secret_of(&puts);
    assert!(secret.len() >= 20, "a real secret");
    // Never in argv, a command the Core sent, the typed line, the answer, an audit row or an event.
    for c in &commands {
        assert!(!c.contains(&secret), "a command carries the invite");
    }
    assert!(!typed.contains(&secret));
    assert!(
        typed.contains("--runner")
            && typed.contains(&path(&p))
            && typed.contains("--proto =https --tlsv1.3")
    );
    assert!(typed.starts_with("sudo sh -c '"), "{typed}");
    assert!(!v.to_string().contains(&secret));
    assert!(
        !text(
            &fx,
            "SELECT coalesce(group_concat(details), '') FROM audit_events"
        )
        .await
        .contains(&secret)
    );
    assert!(
        !text(
            &fx,
            "SELECT coalesce(group_concat(payload), '') FROM events"
        )
        .await
        .contains(&secret)
    );
    // The invite is a live single-use runner invite made by the caller.
    let p = p.as_str();
    assert_eq!(
        scalar(&fx, "SELECT kind FROM core_pairings WHERE id = ?", p).await,
        "runner"
    );
    assert_eq!(
        scalar(&fx, "SELECT status FROM core_pairings WHERE id = ?", p).await,
        "live"
    );
    assert_eq!(
        scalar(&fx, "SELECT created_by FROM core_pairings WHERE id = ?", p).await,
        fx.admin.id
    );
    // A terminal is open on the host for the person to type the sudo password in.
    assert_eq!(opens, 1);
    assert_eq!(v["session"]["host_id"], json!(h));
    // The installer claims the invite: the host is then a paired runner.
    sqlx::query("UPDATE core_pairings SET status = 'approved', device_id = ? WHERE id = ?")
        .bind(&fx.runner.id)
        .bind(p)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    for _ in 0..200 {
        if scalar(
            &fx,
            "SELECT runner_device FROM leyline_hosts WHERE id = ?",
            &h,
        )
        .await
            == fx.runner.id
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        scalar(
            &fx,
            "SELECT runner_device FROM leyline_hosts WHERE id = ?",
            &h
        )
        .await,
        fx.runner.id
    );
    // The claimer's own details are in the audit row and the event for the person to check.
    for sql in [
        "SELECT coalesce(group_concat(details), '') FROM audit_events WHERE action = 'leyline.host.changed'",
        "SELECT coalesce(group_concat(payload), '') FROM events WHERE payload LIKE '%runner_install%'",
    ] {
        let t = text(&fx, sql).await;
        assert!(
            t.contains("\"claimer\"") && t.contains(&fx.runner.id),
            "{t}"
        );
    }
    // Already a runner: no second install, and no second invite.
    let (s, b) = make(&fx, &fx.admin, &h).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::CONFLICT, &json!("already_runner"))
    );
    assert_eq!(n(&fx, "core_pairings WHERE kind = 'runner'").await, 1);
}

#[tokio::test]
async fn an_invite_nobody_claims_is_withdrawn_and_its_file_removed() {
    let fx = fx().await;
    let seen = online(&fx, true);
    let h = trusted_host(&fx, "beta").await;
    let (s, v) = make(&fx, &fx.admin, &h).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let p = v["pairing"].as_str().unwrap().to_owned();
    // The Core's own sweep marks it expired at its end.
    sqlx::query("UPDATE core_pairings SET status = 'expired' WHERE id = ?")
        .bind(&p)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    until("the file was removed", || {
        seen.lock().unwrap().removes.contains(&path(&p))
    })
    .await;
    // Told to the app, linked to nothing, and the person may start again with a new invite.
    for _ in 0..100 {
        let q = "SELECT details FROM audit_events WHERE action = 'leyline.host.changed' AND details LIKE ?";
        if !scalar(&fx, q, "%expired%").await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!scalar(&fx, "SELECT details FROM audit_events WHERE action = 'leyline.host.changed' AND details LIKE ?", "%expired%").await.is_empty());
    assert_eq!(
        scalar(
            &fx,
            "SELECT coalesce(runner_device, '') FROM leyline_hosts WHERE id = ?",
            &h
        )
        .await,
        ""
    );
    let (s, b) = make(&fx, &fx.admin, &h).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let g = seen.lock().unwrap();
    assert_eq!(g.puts.len(), 2, "a new invite, a new file");
    assert_ne!(g.puts[0].0, g.puts[1].0, "each install has its own file");
    assert_eq!(g.removes, [path(&p)], "only its own file was removed");
}

#[tokio::test]
async fn a_failed_upload_withdraws_the_invite_and_opens_no_terminal() {
    let fx = fx().await;
    let seen = online(&fx, true);
    seen.lock().unwrap().fail_put = true;
    let h = trusted_host(&fx, "gamma").await;
    let (s, b) = make(&fx, &fx.admin, &h).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::BAD_GATEWAY, &json!("sftp_failed"))
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT status FROM core_pairings WHERE kind = ?",
            "runner"
        )
        .await,
        "rejected"
    );
    assert_eq!(seen.lock().unwrap().opens, 0);
    assert!(seen.lock().unwrap().puts.is_empty());
    assert_eq!(n(&fx, "leyline_sessions").await, 0);
    // The run is finished as failed, not left running.
    assert_eq!(
        scalar(
            &fx,
            "SELECT state FROM leyline_runs WHERE action = ?",
            "leylineMakeRunner"
        )
        .await,
        "done"
    );
}

#[tokio::test]
async fn refusals_come_before_any_invite() {
    let fx = fx().await;
    let seen = online(&fx, true);
    // No pinned key yet: nothing is trusted on first sight.
    let h = host(&fx, "delta", None).await;
    let (s, b) = make(&fx, &fx.admin, &h).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::CONFLICT, &json!("host_not_trusted"))
    );
    // The app unlock is needed (not a step-up).
    trust_row(&fx, &h, &fp('A'), "trusted").await;
    let (s, b) = make(&fx, &fx.laptop, &h).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("unlock_required"))
    );
    // A device without the runner scope cannot make an invite.
    let tablet = enroll(&fx.app, "tablet", "device", &["admin", "terminal"]).await;
    let session = tablet.session.lock().unwrap().clone().unwrap();
    fx.app
        .auth
        .elevate(&session, &tablet.id, SystemClock.unix() + 3600);
    tablet.unlock(&fx.app.auth, SystemClock.unix() + 3600);
    let (s, b) = make(&fx, &tablet, &h).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
    assert_eq!(n(&fx, "core_pairings WHERE kind = 'runner'").await, 0);
    assert!(
        seen.lock().unwrap().commands.is_empty(),
        "nothing reached the runner"
    );
}

#[tokio::test]
async fn a_runner_that_cannot_copy_files_is_refused_before_any_invite() {
    let fx = fx().await;
    let seen = online(&fx, false);
    let h = trusted_host(&fx, "eps").await;
    let (s, b) = make(&fx, &fx.admin, &h).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::CONFLICT, &json!("runner_cannot_sftp"))
    );
    assert_eq!(n(&fx, "core_pairings WHERE kind = 'runner'").await, 0);
    assert!(seen.lock().unwrap().commands.is_empty());
}
