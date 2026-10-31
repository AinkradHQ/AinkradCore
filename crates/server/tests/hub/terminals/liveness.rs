//! A terminal's end without its owner asking: its runner host process killed (`kill -9`), a
//! runner restart that finds a host gone, and an idle terminal nobody is attached to. Real Core
//! API, runner daemon and `ainkrad-ptyhost`, as in the parent module; each wait is bounded.

use super::*;
use ainkrad_core::settings::{Key as Setting, Scope};

/// Stops a replacement runner daemon when the test ends, pass or fail.
struct StopOnDrop(watch::Sender<bool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

fn host_pid(fx: &Fx, id: &str) -> u64 {
    let rec = std::fs::read_to_string(fx.dir.join(format!("{id}.json"))).unwrap();
    serde_json::from_str::<Value>(&rec).unwrap()["pid"]
        .as_u64()
        .unwrap()
}

/// Terminal children of killed hosts, killed again when the test ends (a hung-up shell
/// normally dies on its own; this makes sure).
#[derive(Default)]
struct Kids(Vec<String>);
impl Drop for Kids {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", pid])
                .status();
        }
    }
}

fn kill_9(kids: &mut Kids, pid: u64) {
    let children = std::process::Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
        .unwrap();
    kids.0.extend(
        String::from_utf8_lossy(&children.stdout)
            .split_whitespace()
            .map(str::to_owned),
    );
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
}

async fn terminal(fx: &Fx, id: &str) -> Value {
    let uri = format!("/api/v1/terminals/{id}");
    fx.call(&fx.owner, "GET", &uri, None).await.1
}

/// The `terminal.exited` events about `id`, as their payloads.
async fn exited_events(fx: &Fx, id: &str) -> Vec<Value> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind='terminal.exited'")
            .fetch_all(&fx.core.app.pool)
            .await
            .unwrap();
    rows.iter()
        .filter_map(|p| serde_json::from_str::<Value>(p).ok())
        .filter(|v| v["terminal"] == id)
        .collect()
}

async fn running_of(fx: &Fx) -> i64 {
    fx.count("SELECT count(*) FROM core_terminals WHERE status IN ('created','running')")
        .await
}

async fn set(fx: &Fx, key: Setting, value: &str) {
    let now = fx.core.app.clock.now();
    ainkrad_core_server::store::settings::set(
        &fx.core.app.pool,
        key,
        Scope::Server,
        value,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
}

/// The bug the E2 fault suite found: after `kill -9` of the host the Core listed the terminal
/// `running` for good. Now the runner reports the loss: the row is `exited` with a reason, the
/// event is emitted, the slot is free and the attached client's socket ends.
#[tokio::test]
async fn a_killed_host_ends_its_terminal_and_frees_the_slot() {
    let fx = Fx::new("t-hostkill").await;
    let o = &fx.owner;
    // One terminal per device: a free slot is then visible as a create that works again.
    set(&fx, Setting::TerminalMaxPerDevice, "1").await;
    let (s, b) = fx.create(o, "/bin/sh", &["-c", "sleep 100000"]).await;
    assert_eq!(s, 201, "{b}");
    let id = b["id"].as_str().unwrap().to_owned();
    assert_eq!(
        fx.create(o, "/bin/cat", &[]).await.0,
        503,
        "the slot is taken"
    );
    let mut c = fx.ws(o, &id).await;
    fx.until("the client attached", async || {
        terminal(&fx, &id).await["attached"] == 1
    })
    .await;

    let mut kids = Kids::default();
    kill_9(&mut kids, host_pid(&fx, &id));

    fx.until("the terminal reported exited", async || {
        fx.status(o, &id).await == "exited"
    })
    .await;
    let t = terminal(&fx, &id).await;
    assert_eq!(t["exit_signal"], "host_lost", "{t}");
    // The row is written before its event: wait for the event too.
    fx.until("the exited event", async || {
        !exited_events(&fx, &id).await.is_empty()
    })
    .await;
    let events = exited_events(&fx, &id).await;
    assert!(
        events.len() == 1 && events[0]["reason"] == "host_lost",
        "{events:?}"
    );
    assert!(c.ended(10).await, "the client got an end-of-stream");
    assert_eq!(running_of(&fx).await, 0);
    let (s, b) = fx.create(o, "/bin/cat", &[]).await;
    assert_eq!(s, 201, "the slot was freed: {b}");
    // The dead terminal can still be closed by its owner.
    let uri = format!("/api/v1/terminals/{id}");
    assert_eq!(fx.call(o, "DELETE", &uri, None).await.0, 200);
}

/// Restart recovery does not wait for a client: a runner that comes back (its hello lists what
/// it still holds) settles the Core's rows, so a host lost while nobody watched ends its
/// terminal, and a live one is watched again and its later exit is recorded.
#[tokio::test]
async fn a_runner_hello_settles_terminals_that_ended_while_nobody_watched() {
    let fx = Fx::new("t-hello").await;
    let o = &fx.owner;
    let lost = fx.sh(o).await;
    let (_, b) = fx.create(o, "/bin/cat", &[]).await;
    let kept = b["id"].as_str().unwrap().to_owned();
    // Nothing watches, as after a Core restart; the runner goes away and a host dies.
    fx.core.app.terminals.forget_monitors();
    fx.stop.send_replace(true);
    fx.until("the runner offline", async || {
        !fx.core.app.hub.online(&fx.runner)
    })
    .await;
    let mut kids = Kids::default();
    kill_9(&mut kids, host_pid(&fx, &lost));
    // The rows were written more than a second ago: a hello only settles older rows.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(fx.status(o, &lost).await, "running");

    let base = format!("http://{}", fx.core.host);
    let _runner = StopOnDrop(spawn_daemon(&fx.st, &base, &fx.dir));
    fx.until("the lost host ended", async || {
        fx.status(o, &lost).await == "exited"
    })
    .await;
    assert_eq!(terminal(&fx, &lost).await["exit_signal"], "host_lost");
    fx.until("the exited event", async || {
        !exited_events(&fx, &lost).await.is_empty()
    })
    .await;
    assert_eq!(exited_events(&fx, &lost).await.len(), 1);
    assert_eq!(fx.status(o, &kept).await, "running");

    // The live one is watched again: its exit is recorded with no client and no signal call.
    let live = fx
        .call(o, "GET", &format!("/api/v1/terminals/{kept}"), None)
        .await
        .1;
    assert_eq!(live["orphaned"], true, "{live}");
    kill_9(&mut kids, host_pid(&fx, &kept));
    fx.until("the watched terminal's end recorded", async || {
        fx.status(o, &kept).await == "exited"
    })
    .await;
}

/// A running terminal nobody is attached to is closed once it has been idle past
/// `terminal.idle_secs`; an attached one, and one a client just left, stay.
#[tokio::test]
async fn an_idle_terminal_with_nobody_attached_is_closed() {
    let fx = Fx::new("t-idle").await;
    let o = &fx.owner;
    let orphan = fx.sh(o).await;
    let watched = fx.sh(o).await;
    let mut c = fx.ws(o, &watched).await;
    c.read_until("ready").await;
    assert_eq!(terminal(&fx, &orphan).await["orphaned"], true);
    assert_eq!(terminal(&fx, &watched).await["orphaned"], false);

    // Off (0) closes nothing, however long it has been.
    set(&fx, Setting::TerminalIdleSecs, "0").await;
    tokio::time::sleep(Duration::from_millis(2200)).await;
    ainkrad_core_server::api::v1::sweep_terminals(&fx.core.app).await;
    assert_eq!(fx.status(o, &orphan).await, "running");

    set(&fx, Setting::TerminalIdleSecs, "1").await;
    // A pass that cannot reach the runner (busy, offline) leaves the row for the next one.
    for _ in 0..20 {
        ainkrad_core_server::api::v1::sweep_terminals(&fx.core.app).await;
        if fx.status(o, &orphan).await != "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(fx.status(o, &orphan).await, "-", "the orphan was closed");
    assert_eq!(
        fx.count("SELECT count(*) FROM core_terminals WHERE status='reaped'")
            .await,
        1
    );
    let closed: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind='terminal.closed'")
            .fetch_all(&fx.core.app.pool)
            .await
            .unwrap();
    assert!(
        closed
            .iter()
            .any(|p| p.contains(&orphan) && p.contains("\"reason\":\"idle\"")),
        "{closed:?}"
    );
    fx.until("the host gone", async || {
        !fx.dir.join(format!("{orphan}.json")).exists()
    })
    .await;
    assert_eq!(
        fx.status(o, &watched).await,
        "running",
        "a client is attached"
    );

    // Leaving restarts the count: just detached is not idle.
    drop(c);
    fx.until("the client left", async || {
        terminal(&fx, &watched).await["attached"] == 0
    })
    .await;
    ainkrad_core_server::api::v1::sweep_terminals(&fx.core.app).await;
    assert_eq!(fx.status(o, &watched).await, "running");
}

/// One terminal takes at most four attached clients: the fifth is refused with 429 and a
/// slot freed by a closing client is usable again, so a flood of attaches cannot hold the
/// runner's shared stream pool.
#[tokio::test]
async fn attaches_are_capped_per_terminal() {
    let fx = Fx::new("t-attach-cap").await;
    let o = &fx.owner;
    let id = fx.sh(o).await;
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut c = fx.ws(o, &id).await;
        c.read_until("ready").await;
        held.push(c);
    }
    let uri = format!("/api/v1/terminals/{id}/ws");
    let try_ws = async || {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fx.core.port))
            .await
            .unwrap();
        let mut req = format!("ws://{}{uri}", fx.core.host)
            .into_client_request()
            .unwrap();
        for (n, v) in o.headers("GET", &uri, b"") {
            req.headers_mut()
                .insert(n, HeaderValue::from_str(&v).unwrap());
        }
        let io: Box<dyn Io> = Box::new(tcp);
        tokio_tungstenite::client_async(req, io).await
    };
    match try_ws().await {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status(), 429),
        other => panic!(
            "the fifth attach must be refused with 429: {:?}",
            other.map(|_| ())
        ),
    }
    drop(held.pop());
    fx.until("a slot was freed", async || try_ws().await.is_ok())
        .await;
}

/// A terminal that exits while nobody is attached reaches the Core through the runner's hello
/// with its exit, but nobody acked its host. The sweep hangs it up once it has been exited a
/// while, so the host does not linger and count against the runner's capacity.
#[tokio::test]
async fn an_exited_terminal_nobody_acked_is_hung_up() {
    let fx = Fx::new("t-ack-exited").await;
    let o = &fx.owner;
    let (s, b) = fx.create(o, "/bin/sh", &["-c", "sleep 3"]).await;
    assert_eq!(s, 201, "{b}");
    let id = b["id"].as_str().unwrap().to_owned();
    fx.core.app.terminals.forget_monitors();
    fx.stop.send_replace(true);
    fx.until("the runner offline", async || {
        !fx.core.app.hub.online(&fx.runner)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(4500)).await;
    let base = format!("http://{}", fx.core.host);
    let _runner = StopOnDrop(spawn_daemon(&fx.st, &base, &fx.dir));
    fx.until("the exit was recorded", async || {
        fx.status(o, &id).await == "exited"
    })
    .await;
    assert!(
        fx.dir.join(format!("{id}.json")).exists(),
        "the host lingers, unacked"
    );
    sqlx::query("UPDATE core_terminals SET last_activity=last_activity-1000 WHERE id=?")
        .bind(&id)
        .execute(&fx.core.app.pool)
        .await
        .unwrap();
    ainkrad_core_server::api::v1::sweep_terminals(&fx.core.app).await;
    assert!(
        !fx.dir.join(format!("{id}.json")).exists(),
        "the sweep acked the exited host"
    );
    assert_eq!(fx.status(o, &id).await, "exited", "the row stays listed");
}

/// A revoked device's running terminal is closed by the sweep: its shell does not outlive its
/// access. Another device's terminal is left alone.
#[tokio::test]
async fn a_revoked_devices_terminals_are_closed() {
    let fx = Fx::new("t-revoked").await;
    let gone = fx.device(true).await;
    let mine = fx.sh(&gone).await;
    let other = fx.sh(&fx.owner).await;
    let now = fx.core.app.clock.now();
    assert!(
        gov::revoke_device(&fx.core.app.pool, &gone.id, AuditActor::System, None, &now)
            .await
            .unwrap()
    );
    fx.core.app.auth.revoked(&gone.id);
    ainkrad_core_server::api::v1::sweep_terminals(&fx.core.app).await;
    let status = async |id: &str| -> String {
        sqlx::query_scalar("SELECT status FROM core_terminals WHERE id=?")
            .bind(id.to_owned())
            .fetch_one(&fx.core.app.pool)
            .await
            .unwrap()
    };
    assert_eq!(status(&mine).await, "reaped");
    assert_eq!(status(&other).await, "running");
    fx.until("the host is gone", async || {
        !fx.dir.join(format!("{mine}.json")).exists()
    })
    .await;
}
