//! The terminal service end to end (E2-05/06): the real Core API over HTTP and WebSocket, the
//! real runner daemon with its `pty` driver and the real `ainkrad-ptyhost`. A scripted fake
//! cannot hide a handler that never reaches a runner (the review's H1), so nothing here is faked.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::store::gov;
use ainkrad_proto::v2::{Body, Control, Frame, Output, Size, Snapshot};
use ainkrad_runner::v2::client::Client;
use ainkrad_runner::v2::daemon::{Backoff, Daemon};
use ainkrad_runner::v2::key::{Enrolment, Key};
use ainkrad_runner::v2::{PtyConfig, PtyDriver};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use super::runner::{driver, paired, state};
use super::{Core, Io, Ws, quick};

/// A shell that echoes typed lines as `got:<line>`, and prints its size for `size`.
const SCRIPT: &str = "echo ready; while IFS= read -r l; do case \"$l\" in size) stty size;; *) echo \"got:$l\";; esac; done";
const TYPED: &str = "typed-secret-4f2a";
const PLANTED: &str = "planted-env-91bc";

struct Fx {
    core: Core,
    runner: String,
    dir: PathBuf,
    stop: watch::Sender<bool>,
    owner: TestDevice,
    /// The runner's paired state, to start it again.
    st: ainkrad_runner::v2::key::State,
}

impl Drop for Fx {
    /// Kills every terminal host under `dir` by its recorded pid (the shell follows on its
    /// closed pty), pass or fail.
    fn drop(&mut self) {
        self.stop.send_replace(true);
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let rec = std::fs::read_to_string(e.path()).unwrap_or_default();
            if let Some(pid) = serde_json::from_str::<Value>(&rec)
                .ok()
                .and_then(|v| v["pid"].as_u64())
            {
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A runner daemon for the runner paired under `state(name)`, its terminals kept in `dir`;
/// send `true` on the returned channel to stop it. Calling it again is a runner restart: the
/// hosts under `dir` outlive the old daemon and the new hello lists the live ones.
fn spawn_daemon(
    st: &ainkrad_runner::v2::key::State,
    base: &str,
    dir: &std::path::Path,
) -> watch::Sender<bool> {
    let cfg = PtyConfig {
        enabled: true,
        grace: Duration::from_millis(200),
        ..PtyConfig::new(dir.to_owned())
    };
    assert!(
        cfg.host.is_file(),
        "ainkrad-ptyhost is built (cargo test --workspace)"
    );
    let key = Arc::new(Key::load(&st.key()).unwrap());
    let enrolment = Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap()));
    let daemon = Daemon {
        client: Client::new(base, None).unwrap(),
        key,
        enrolment,
        save: None,
        exec: driver(),
        pty: Some(Arc::new(PtyDriver::new(cfg))),
        agents: None,
        tls: None,
        backoff: Backoff {
            min: Duration::from_millis(50),
            max: Duration::from_millis(200),
            refused: Duration::from_millis(200),
        },
    };
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        let _ = daemon.run(stopped).await;
    });
    stop
}

fn elevate(core: &Core, dev: &TestDevice) {
    let sid = dev.session.lock().unwrap().clone().unwrap();
    let until = ainkrad_core_server::scheduler::Clock::unix(&*core.app.clock) + 300;
    assert!(core.app.auth.elevate(&sid, &dev.id, until));
}

impl Fx {
    async fn new(name: &str) -> Self {
        let core = Core::start(name, quick()).await;
        let base = format!("http://{}", core.host);
        let st = state(name);
        let e = paired(&core, &base, None, &st).await;
        let dir = PathBuf::from(format!("/tmp/ath-{name}-{}", std::process::id() % 100_000));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stop = spawn_daemon(&st, &base, &dir);
        let fx = Self {
            runner: e.device_id,
            owner: core.device("device", &["read", "terminal"]).await,
            core,
            dir,
            stop,
            st,
        };
        for _ in 0..500 {
            if fx.core.app.hub.online(&fx.runner) {
                elevate(&fx.core, &fx.owner);
                return fx;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the runner did not come online");
    }

    /// A client device with the terminal scope, elevated unless `stepped_up` is false.
    async fn device(&self, stepped_up: bool) -> TestDevice {
        let d = self.core.device("device", &["read", "terminal"]).await;
        if stepped_up {
            elevate(&self.core, &d);
        }
        d
    }

    async fn call(
        &self,
        dev: &TestDevice,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let bytes = body.map(|v| v.to_string()).unwrap_or_default();
        let mut req = format!(
            "{method} {uri} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n",
            self.core.host
        );
        for (n, v) in dev.headers(method, uri, bytes.as_bytes()) {
            req += &format!("{n}: {v}\r\n");
        }
        if !bytes.is_empty() {
            req += "content-type: application/json\r\n";
        }
        req += &format!("content-length: {}\r\n\r\n{bytes}", bytes.len());
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", self.core.port))
            .await
            .unwrap();
        tcp.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tcp.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text[9..12].parse().unwrap();
        let body = text.split_once("\r\n\r\n").map_or("", |x| x.1);
        let (a, b) = (body.find(['{', '[']), body.rfind(['}', ']']));
        let json = a
            .zip(b)
            .and_then(|(a, b)| serde_json::from_str(&body[a..=b]).ok());
        (status, json.unwrap_or(Value::Null))
    }

    async fn create(&self, dev: &TestDevice, program: &str, args: &[&str]) -> (u16, Value) {
        let body = json!({"runner": self.runner, "program": program, "args": args, "cwd": "/",
            "env": {"PLANTED": PLANTED}, "size": {"rows": 24, "cols": 80}});
        self.call(dev, "POST", "/api/v1/terminals", Some(body))
            .await
    }

    async fn sh(&self, dev: &TestDevice) -> String {
        let (s, b) = self.create(dev, "/bin/sh", &["-c", SCRIPT]).await;
        assert_eq!(s, 201, "{b}");
        b["id"].as_str().unwrap().to_owned()
    }

    async fn ws(&self, dev: &TestDevice, id: &str) -> Client2 {
        let uri = format!("/api/v1/terminals/{id}/ws");
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", self.core.port))
            .await
            .unwrap();
        let mut req = format!("ws://{}{uri}", self.core.host)
            .into_client_request()
            .unwrap();
        for (n, v) in dev.headers("GET", &uri, b"") {
            req.headers_mut()
                .insert(n, HeaderValue::from_str(&v).unwrap());
        }
        let io: Box<dyn Io> = Box::new(tcp);
        let (ws, _) = tokio_tungstenite::client_async(req, io)
            .await
            .expect("upgraded");
        Client2 {
            ws,
            seq: 0,
            seen: String::new(),
        }
    }

    async fn status(&self, dev: &TestDevice, id: &str) -> String {
        let r = self
            .call(dev, "GET", &format!("/api/v1/terminals/{id}"), None)
            .await;
        r.1["status"].as_str().unwrap_or("-").to_owned()
    }

    async fn until(&self, what: &str, mut f: impl AsyncFnMut() -> bool) {
        for _ in 0..300 {
            if f().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {what}");
    }

    async fn count(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.core.app.pool)
            .await
            .unwrap()
    }

    /// Every text the Core keeps or logs about terminals.
    async fn everything(&self) -> String {
        let q =
            |sql: &'static str| sqlx::query_scalar::<_, String>(sql).fetch_all(&self.core.app.pool);
        let parts = [
            q("SELECT payload FROM events").await.unwrap(),
            q("SELECT details FROM audit_events").await.unwrap(),
            q("SELECT json_array(id,runner,status,rows,cols,output_seq,opened_by,created_at,exit_code,exit_signal) FROM core_terminals").await.unwrap(),
        ];
        parts.concat().join("\n") + &String::from_utf8_lossy(&super::log().0.lock().unwrap())
    }
}

struct Client2 {
    ws: Ws,
    seq: u64,
    seen: String,
}

impl Client2 {
    async fn send(&mut self, body: Body) {
        let f = Frame::new(0, self.seq, body);
        self.seq += 1;
        self.send_text(serde_json::to_string(&f).unwrap()).await;
    }
    async fn send_text(&mut self, t: String) {
        let _ = self.ws.send(Message::Text(t.into())).await;
    }
    async fn type_line(&mut self, line: &str) {
        let data = B64.encode(format!("{line}\n"));
        self.send(Body::Output(Output { data })).await;
    }
    /// Reads until everything seen so far contains `needle`.
    async fn read_until(&mut self, needle: &str) {
        let end = tokio::time::Instant::now() + Duration::from_secs(10);
        while !self.seen.contains(needle) {
            let m = tokio::time::timeout_at(end, self.ws.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = m else {
                panic!("no {needle:?} in {:?} ({m:?})", self.seen)
            };
            let data = match serde_json::from_str::<Frame>(&t).unwrap().body().unwrap() {
                Some(Body::Output(Output { data })) => data,
                Some(Body::Control(Control::Snapshot(Snapshot { data, .. }))) => data,
                other => {
                    self.seen += &format!("[{other:?}]");
                    continue;
                }
            };
            self.seen += &String::from_utf8_lossy(&B64.decode(data).unwrap());
        }
    }
    /// Whether the server ended the socket (a close frame, an error or EOF) within `secs`.
    async fn ended(&mut self, secs: u64) -> bool {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            match tokio::time::timeout_at(end, self.ws.next()).await {
                Err(_) => return false,
                Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => return true,
                Ok(_) => {}
            }
        }
    }
}

/// H1 and E2-05.5: create, attach, type, resize, signal, detach and close through the real
/// handlers, with typed input and a create's env nowhere in what the Core keeps.
#[tokio::test]
async fn a_terminal_is_created_attached_resized_signalled_and_closed_through_the_api() {
    let fx = Fx::new("t-e2e").await;
    let o = &fx.owner;
    let id = fx.sh(o).await;
    let (s, list) = fx.call(o, "GET", "/api/v1/terminals", None).await;
    assert!(s == 200 && list[0]["id"] == id.as_str(), "{list}");

    let mut c = fx.ws(o, &id).await;
    c.read_until("ready").await;
    c.type_line(TYPED).await;
    c.read_until(&format!("got:{TYPED}")).await;
    c.send(Body::Control(Control::Resize(Size {
        rows: 31,
        cols: 101,
    })))
    .await;
    c.type_line("size").await;
    c.read_until("31 101").await;
    assert_eq!(
        fx.call(o, "GET", &format!("/api/v1/terminals/{id}"), None)
            .await
            .1["attached"],
        1
    );
    drop(c);

    let sig = format!("/api/v1/terminals/{id}/signal");
    assert_eq!(
        fx.call(o, "POST", &sig, Some(json!({"signal": "WINCH"})))
            .await
            .0,
        204
    );
    assert_eq!(
        fx.call(o, "POST", &sig, Some(json!({"signal": "NOPE"})))
            .await
            .0,
        400
    );
    let (s, closed) = fx
        .call(o, "DELETE", &format!("/api/v1/terminals/{id}"), None)
        .await;
    assert!(s == 200 && closed["status"] == "reaped", "{closed}");
    fx.until("the host gone", async || {
        std::fs::read_dir(&fx.dir).unwrap().count() == 0
    })
    .await;

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'terminal.%' ORDER BY seq",
    )
    .fetch_all(&fx.core.app.pool)
    .await
    .unwrap();
    for a in [
        "terminal.opened",
        "terminal.attached",
        "terminal.signalled",
        "terminal.closed",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} in {actions:?}");
    }
    assert_eq!(
        fx.count(
            "SELECT count(*) FROM audit_events WHERE action LIKE 'terminal.%' AND entity_id=0"
        )
        .await,
        0,
        "every row names its terminal"
    );
    let all = fx.everything().await;
    for secret in [TYPED, PLANTED, "got:", "ready"] {
        assert!(
            !all.contains(secret),
            "{secret:?} reached the Core's records"
        );
    }
}

/// H2: a hundred signals leave no stream behind; signal and close need the opener and a live
/// step-up; each signal is audited by name.
#[tokio::test]
async fn signals_do_not_leak_streams_and_signal_and_close_are_gated() {
    let fx = Fx::new("t-sig").await;
    let o = &fx.owner;
    let id = fx.sh(o).await;
    let sig = format!("/api/v1/terminals/{id}/signal");
    for i in 0..100 {
        let r = fx
            .call(o, "POST", &sig, Some(json!({"signal": "WINCH"})))
            .await;
        assert_eq!(r.0, 204, "signal {i}: {r:?}\n{}", fx.everything().await);
    }
    fx.until("only the monitor stream left", async || {
        fx.core.app.hub.runners()[&fx.runner].load <= 1
    })
    .await;
    assert!(
        fx.sh(o).await.starts_with("t_"),
        "the runner still takes terminals"
    );
    assert_eq!(fx.count("SELECT count(*) FROM audit_events WHERE action='terminal.signalled' AND details LIKE '%WINCH%'").await, 100);

    // Another device: the terminal does not exist for it. No step-up: refused at the gate.
    let other = fx.device(true).await;
    let cold = fx.device(false).await;
    for (m, u) in [
        ("POST", sig.as_str()),
        ("DELETE", &format!("/api/v1/terminals/{id}")[..]),
    ] {
        let body = (m == "POST").then(|| json!({"signal": "KILL"}));
        assert_eq!(
            fx.call(&other, m, u, body.clone()).await.0,
            404,
            "{m} by another device"
        );
        let (s, b) = fx.call(&cold, m, u, body).await;
        assert!(
            s == 403 && b["code"] == "step_up_required",
            "{m} without step-up: {s} {b}"
        );
    }
    assert_eq!(
        fx.status(o, &id).await,
        "running",
        "nothing of that reached the terminal"
    );
}

/// M2 and the reaping: a device lists only its own terminals; exited ones are reaped after a
/// while and never count against the caps; the caps hold under concurrent creates.
#[tokio::test]
async fn listing_is_private_exited_terminals_are_reaped_and_the_cap_holds() {
    let fx = Fx::new("t-cap").await;
    let (a, b) = (&fx.owner, &fx.device(true).await);
    let ida = fx.sh(a).await;
    let idb = fx.sh(b).await;
    let ids = |r: &Value| {
        r.as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(&fx.call(a, "GET", "/api/v1/terminals", None).await.1),
        std::slice::from_ref(&ida)
    );
    assert_eq!(
        ids(&fx.call(b, "GET", "/api/v1/terminals", None).await.1),
        [idb]
    );

    // Old exited rows: reaped on list; and exited rows hold no host, so no cap.
    let now = ainkrad_core_server::scheduler::Clock::unix(&*fx.core.app.clock);
    for (n, age) in [
        (0, 4000),
        (1, 10),
        (2, 10),
        (3, 10),
        (4, 10),
        (5, 10),
        (6, 10),
        (7, 10),
        (8, 10),
    ] {
        sqlx::query("INSERT INTO core_terminals(id,runner,status,rows,cols,output_seq,opened_by,created_at,last_activity) VALUES(?,?,'exited',24,80,0,?,'2026-01-01T00:00:00.000Z',?)")
            .bind(format!("t_old{n}")).bind(&fx.runner).bind(&b.id).bind(now - age)
            .execute(&fx.core.app.pool).await.unwrap();
    }
    let listed = ids(&fx.call(b, "GET", "/api/v1/terminals", None).await.1);
    assert!(
        !listed.contains(&"t_old0".to_owned()) && listed.contains(&"t_old1".to_owned()),
        "{listed:?}"
    );
    assert_eq!(
        fx.count("SELECT count(*) FROM core_terminals WHERE id='t_old0' AND status='reaped'")
            .await,
        1
    );

    // The device limit is 8 live ones: 12 concurrent creates by a fresh device give exactly 8.
    let c = &fx.device(true).await;
    let results =
        futures_util::future::join_all((0..12).map(|_| fx.create(c, "/bin/cat", &[]))).await;
    let created = results.iter().filter(|r| r.0 == 201).count();
    let limited = results
        .iter()
        .filter(|r| r.0 == 503 && r.1["code"] == "terminal_limit")
        .count();
    assert_eq!((created, limited), (8, 4), "{results:?}");
}

/// M4: an exit is recorded by a stream opened after a Core restart (no watcher left), and
/// a create whose row cannot be written closes the host it opened.
#[tokio::test]
async fn an_exit_is_recorded_after_a_restart_and_a_failed_create_leaves_no_host() {
    let fx = Fx::new("t-rec").await;
    let o = &fx.owner;
    let (_, b) = fx.create(o, "/bin/cat", &[]).await;
    let id = b["id"].as_str().unwrap().to_owned();
    fx.core.app.terminals.forget_monitors();
    let sig = format!("/api/v1/terminals/{id}/signal");
    assert_eq!(
        fx.call(o, "POST", &sig, Some(json!({"signal": "TERM"})))
            .await
            .0,
        204
    );
    fx.until("the exit recorded", async || {
        fx.status(o, &id).await == "exited"
    })
    .await;
    fx.call(o, "DELETE", &format!("/api/v1/terminals/{id}"), None)
        .await;

    fx.until("the first host gone", async || {
        std::fs::read_dir(&fx.dir).unwrap().count() == 0
    })
    .await;
    sqlx::query("CREATE TRIGGER no_rows BEFORE INSERT ON core_terminals BEGIN SELECT RAISE(ABORT, 'no'); END")
        .execute(&fx.core.app.pool).await.unwrap();
    assert_ne!(fx.create(o, "/bin/cat", &[]).await.0, 201);
    fx.until("the orphan host closed", async || {
        std::fs::read_dir(&fx.dir).unwrap().count() == 0
    })
    .await;
}

/// M3 and M5: a client that stops reading cannot hold up a revocation, an oversized message
/// ends the socket, and a client's credit frame is not forwarded (`client_frame`'s unit test).
#[tokio::test]
async fn a_stalled_client_cannot_delay_revocation_and_a_huge_message_ends_the_socket() {
    let fx = Fx::new("t-ws").await;
    let flood = fx.device(true).await;
    let (s, b) = fx
        .create(
            &flood,
            "/usr/bin/yes",
            &["abcdefghijklmnopqrstuvwxyz0123456789"],
        )
        .await;
    assert_eq!(s, 201, "{b}");
    let id = b["id"].as_str().unwrap().to_owned();
    let stalled = fx.ws(&flood, &id).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let now = fx.core.app.clock.now();
    assert!(
        gov::revoke_device(&fx.core.app.pool, &flood.id, AuditActor::System, None, &now)
            .await
            .unwrap()
    );
    fx.core.app.auth.revoked(&flood.id);
    fx.until("the stalled socket detached", async || {
        fx.count("SELECT count(*) FROM audit_events WHERE action='terminal.detached'")
            .await
            == 1
    })
    .await;
    drop(stalled);

    let id2 = fx.sh(&fx.owner).await;
    let mut c = fx.ws(&fx.owner, &id2).await;
    c.read_until("ready").await;
    c.send_text("x".repeat(200 * 1024)).await;
    assert!(c.ended(5).await, "a 200 KiB message closes the socket");
}

mod liveness;
