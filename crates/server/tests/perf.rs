//! Performance budgets (E1-19.1) against the real `ainkrad-core-server` binary, on loopback. Run with
//! `make perf` (release build, `ulimit -n` raised for 200 sockets). Ignored by `make test`.
//!
//! The budgets (the plan's E1-19 AC; the two latencies are ours, the plan names no figure):
//!
//! | Budget | Limit |
//! |---|---|
//! | startup to serving (spawn to the first `GET /healthz` 200), worst of 3 cold starts | <= 3 s |
//! | idle CPU, no clients, `CORE_PERF_IDLE_SECS` (default 30) | < 1 % of one core |
//! | idle CPU, 200 event sockets connected | < 1 % of one core |
//! | idle RSS, no clients and with 200 sockets | < 150 MB |
//! | p99 signed API request (`GET /api/v1/me`), 200 clients at 2 req/s each, sockets connected | <= 100 ms |
//! | p99 event fan-out (commit to receipt on each of 200 sockets) | <= 1 s |
//! | file descriptors after the sockets close | back to the idle baseline (+ 5) |
//!
//! The test process appends events straight into the server's database (the sockets poll the table,
//! so no in-process shortcut is involved). CPU is `ps cputime` (hundredths of a second on macOS).
//! It prints a markdown table on stderr and fails if any budget is missed.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_core_server::store::{begin_write, connect, events, kinds};
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const STARTUP_S: f64 = 3.0;
const IDLE_CPU_PCT: f64 = 1.0;
const IDLE_RSS_MB: f64 = 150.0;
const API_P99_MS: f64 = 100.0;
const FANOUT_P99_MS: f64 = 1000.0;
const FD_SLACK: usize = 5;
/// Events the producer sends, one every 200 ms.
const FANOUT_EVENTS: usize = 100;

struct Server {
    child: tokio::process::Child,
    pid: u32,
}

impl Server {
    /// Spawns `serve` and returns it with the seconds until `/healthz` answered.
    async fn start(db: &str, port: u16, log: &std::path::Path) -> (Self, f64) {
        let t = Instant::now();
        let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
            .args([
                "serve",
                db,
                "--listen",
                &format!("loopback:{port}"),
                "--trusted-proxy",
                "127.0.0.1",
            ])
            .stderr(std::fs::File::create(log).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let http = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{port}/healthz");
        loop {
            if let Ok(r) = http.get(&url).send().await
                && r.status() == 200
            {
                return (Self { child, pid }, t.elapsed().as_secs_f64());
            }
            assert!(t.elapsed() < Duration::from_secs(30), "never served");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn kill(mut self) {
        self.child.kill().await.unwrap();
    }
}

fn ps(pid: u32, col: &str) -> String {
    let out = Command::new("ps")
        .args(["-o", &format!("{col}="), "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn cpu_secs(pid: u32) -> f64 {
    ps(pid, "cputime")
        .split(':')
        .fold(0.0, |a, p| a * 60.0 + p.parse::<f64>().unwrap_or(0.0))
}

fn rss_mb(pid: u32) -> f64 {
    ps(pid, "rss").parse::<f64>().unwrap_or(0.0) / 1024.0
}

/// Open descriptors of `pid` (`lsof`; the header line is not one).
fn fds(pid: u32) -> usize {
    let out = Command::new("lsof")
        .args(["-n", "-p", &pid.to_string()])
        .output()
        .expect("lsof runs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .count()
        .saturating_sub(1)
}

/// CPU as a percentage of one core over `secs`, and the RSS at the end.
async fn idle(pid: u32, secs: u64) -> (f64, f64) {
    let before = cpu_secs(pid);
    tokio::time::sleep(Duration::from_secs(secs)).await;
    ((cpu_secs(pid) - before) / secs as f64 * 100.0, rss_mb(pid))
}

fn p99(v: &mut [f64]) -> f64 {
    v.sort_by(f64::total_cmp);
    v[((v.len() as f64 * 0.99).ceil() as usize)
        .saturating_sub(1)
        .min(v.len() - 1)]
}

fn chrono_now() -> String {
    let s = now_us() / 1000;
    format!(
        "{:02}:{:02}.{:03}",
        s / 60_000 % 60,
        s / 1000 % 60,
        s % 1000
    )
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// A session over the handshake, as a client does it.
async fn login(http: &reqwest::Client, bind: &str, dev: &TestDevice, n: usize) {
    let post = |path: &str, body: &str, signed: bool| {
        let mut r = http
            .post(format!("http://{bind}{path}"))
            .header("content-type", "application/json")
            // Loopback is a trusted proxy, so each client claims its own address: the per-address
            // challenge limit is for one client, not for 200 test clients on one machine.
            .header(
                "x-forwarded-for",
                format!("10.0.{}.{}", n / 250, n % 250 + 1),
            )
            .body(body.to_owned());
        if signed {
            for (n, v) in dev.headers_session("POST", path, body.as_bytes(), None) {
                r = r.header(n, v);
            }
        }
        r
    };
    let id = serde_json::json!({"device_id": dev.id}).to_string();
    let ch: serde_json::Value = post("/handshake/challenge", &id, false)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ch["challenge"].is_string(), "client {n}: {ch}");
    let body = serde_json::json!({"challenge": ch["challenge"]}).to_string();
    let s: serde_json::Value = post("/handshake/session", &body, true)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    dev.set_session(s["session_id"].as_str().map(str::to_owned));
    assert!(dev.session.lock().unwrap().is_some(), "{s}");
}

async fn ws(bind: &str, dev: &TestDevice, after: i64) -> Ws {
    let mut req = format!("ws://{bind}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    for (n, v) in dev.headers("GET", "/api/v1/events/ws", b"") {
        req.headers_mut().insert(n, v.parse().unwrap());
    }
    req.headers_mut()
        .insert("last-event-id", after.to_string().parse().unwrap());
    connect_async(req).await.unwrap().0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "performance budgets: `make perf`"]
async fn budgets() {
    let idle_secs: u64 = std::env::var("CORE_PERF_IDLE_SECS")
        .ok()
        .map_or(30, |v| v.parse().expect("a number"));
    let api_secs: u64 = std::env::var("CORE_PERF_API_SECS")
        .ok()
        .map_or(20, |v| v.parse().expect("a number"));
    let clients: usize = std::env::var("CORE_PERF_CLIENTS")
        .ok()
        .map_or(200, |v| v.parse().expect("a number"));
    let dir = std::env::temp_dir().join(format!("core-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");
    let db_arg = db.to_str().unwrap();
    let identity = Identity::load_or_create(&dir).unwrap();
    let pool = connect(&db).await.unwrap();
    let mut tx = begin_write(&pool).await.unwrap();
    kinds::register(&mut tx, "perf", &[("perf.tick", "read")], &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut devs = Vec::new();
    for n in 0..clients {
        let clock = Arc::new(SystemClock);
        let name = format!("c{n}");
        let d = TestDevice::enroll(&pool, &name, "device", &["read"], &identity.fp, clock).await;
        devs.push(Arc::new(d));
    }
    pool.close().await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");

    // Startup: three cold starts on the populated database; the worst counts.
    let mut starts = Vec::new();
    let mut server = None;
    for run in 0..3 {
        if let Some(s) = server.take() {
            Server::kill(s).await;
        }
        let (s, secs) = Server::start(db_arg, port, &dir.join(format!("server{run}.log"))).await;
        starts.push(secs);
        server = Some(s);
    }
    let server = server.unwrap();
    let pid = server.pid;
    let start_worst = starts.iter().copied().fold(0.0, f64::max);

    // Idle, nobody connected.
    eprintln!("perf: {} idle, no clients", chrono_now());
    tokio::time::sleep(Duration::from_secs(5)).await;
    let fd_base = fds(pid);
    let (cpu0, rss0) = idle(pid, idle_secs).await;

    // 200 sessions and sockets, then idle again.
    eprintln!("perf: {} 200 sessions and sockets", chrono_now());
    let http = reqwest::Client::new();
    for (n, d) in devs.iter().enumerate() {
        login(&http, &bind, d, n).await;
    }
    let pool = connect(&db).await.unwrap();
    let after = events::last_event_seq(&pool).await.unwrap();
    let mut sockets = Vec::new();
    for d in &devs {
        sockets.push(ws(&bind, d, after).await);
    }
    // Every socket is read from the start (that is what answers the server's pings); the readers
    // keep the perf ticks they see and finish after FANOUT_EVENTS of them.
    let mut readers = Vec::new();
    for mut socket in sockets {
        readers.push(tokio::spawn(async move {
            let mut ms = Vec::new();
            while ms.len() < FANOUT_EVENTS {
                let m = tokio::time::timeout(Duration::from_secs(120), socket.next())
                    .await
                    .expect("an event within 120 s");
                if let Some(Ok(Message::Text(t))) = m {
                    let e: serde_json::Value = serde_json::from_str(&t).unwrap();
                    if e["kind"] == "perf.tick" {
                        let sent = e["payload"]["sent_us"].as_u64().unwrap();
                        ms.push(now_us().saturating_sub(sent) as f64 / 1000.0);
                    }
                } else {
                    assert!(matches!(m, Some(Ok(_))), "socket ended: {m:?}");
                }
            }
            ms
        }));
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let fd_open = fds(pid);
    let (cpu200, rss200) = idle(pid, idle_secs).await;

    eprintln!("perf: {} api latency", chrono_now());
    // API latency: every client asks `/me` twice a second, sockets still connected.
    let mut tasks = Vec::new();
    for (n, d) in devs.iter().cloned().enumerate() {
        let (http, bind) = (http.clone(), bind.clone());
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(n as u64 * 2)).await;
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            let (began, mut ms, mut bad) = (Instant::now(), Vec::new(), 0u32);
            while began.elapsed() < Duration::from_secs(api_secs) {
                tick.tick().await;
                let mut r = http.get(format!("http://{bind}/api/v1/me"));
                for (name, v) in d.headers("GET", "/api/v1/me", b"") {
                    r = r.header(name, v);
                }
                let t = Instant::now();
                let ok = match r.send().await {
                    Ok(resp) => resp.status() == 200 && resp.bytes().await.is_ok(),
                    Err(_) => false,
                };
                ms.push(t.elapsed().as_secs_f64() * 1000.0);
                if t.elapsed() > Duration::from_secs(1) {
                    eprintln!(
                        "perf: {} client {n}: a request took {:?} (ok: {ok})",
                        chrono_now(),
                        t.elapsed()
                    );
                }
                bad += u32::from(!ok);
            }
            (ms, bad)
        }));
    }
    let (mut api, mut bad) = (Vec::new(), 0);
    for t in tasks {
        let (ms, b) = t.await.unwrap();
        api.extend(ms);
        bad += b;
    }
    let (api_n, api_p99) = (api.len(), p99(&mut api));
    let api_max = api.last().copied().unwrap_or(0.0);
    eprintln!(
        "perf: {} api p99 {api_p99:.1} ms, max {api_max:.1}, {api_n} requests, {bad} failed",
        chrono_now()
    );
    eprintln!("perf: {} fan-out", chrono_now());
    // Fan-out: one event every 200 ms, committed in the server's own database file.
    for _ in 0..FANOUT_EVENTS {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sent = now_us();
        let mut tx = begin_write(&pool).await.unwrap();
        events::append(&mut tx, "perf.tick", &serde_json::json!({"sent_us": sent}))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut fan = Vec::new();
    for r in readers {
        fan.extend(r.await.unwrap());
    }
    let (fan_n, fan_p99) = (fan.len(), p99(&mut fan));
    let fan_max = fan.last().copied().unwrap_or(0.0);

    // The sockets are gone (their tasks ended): descriptors return to the baseline.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (fd_end, rss_end) = (fds(pid), rss_mb(pid));
    pool.close().await;
    server.kill().await;

    let rows = [
        (
            "startup to serving, worst of 3",
            format!("{start_worst:.2} s ({starts:.2?})"),
            format!("<= {STARTUP_S} s"),
            start_worst <= STARTUP_S,
        ),
        (
            "idle CPU, no clients",
            format!("{cpu0:.3} %"),
            format!("< {IDLE_CPU_PCT} %"),
            cpu0 < IDLE_CPU_PCT,
        ),
        (
            "idle RSS, no clients",
            format!("{rss0:.1} MB"),
            format!("< {IDLE_RSS_MB} MB"),
            rss0 < IDLE_RSS_MB,
        ),
        (
            "idle CPU, 200 sockets",
            format!("{cpu200:.3} %"),
            format!("< {IDLE_CPU_PCT} %"),
            cpu200 < IDLE_CPU_PCT,
        ),
        (
            "idle RSS, 200 sockets",
            format!("{rss200:.1} MB"),
            format!("< {IDLE_RSS_MB} MB"),
            rss200 < IDLE_RSS_MB,
        ),
        (
            "p99 API latency (GET /api/v1/me)",
            format!("{api_p99:.1} ms (max {api_max:.1}, {api_n} requests, {bad} failed)"),
            format!("<= {API_P99_MS} ms, 0 failed"),
            api_p99 <= API_P99_MS && bad == 0,
        ),
        (
            "p99 event fan-out, 200 sockets",
            format!("{fan_p99:.1} ms (max {fan_max:.1}, {fan_n} deliveries)"),
            format!(
                "<= {FANOUT_P99_MS} ms, all {} delivered",
                clients * FANOUT_EVENTS
            ),
            fan_p99 <= FANOUT_P99_MS && fan_n == clients * FANOUT_EVENTS,
        ),
        (
            "descriptors after sockets close",
            format!("{fd_end} (idle {fd_base}, with sockets {fd_open}; RSS after {rss_end:.1} MB)"),
            format!("<= idle + {FD_SLACK}"),
            fd_end <= fd_base + FD_SLACK,
        ),
    ];
    eprintln!("\n| Measure | Measured | Budget | |\n|---|---|---|---|");
    for (what, got, budget, pass) in &rows {
        eprintln!(
            "| {what} | {got} | {budget} | {} |",
            if *pass { "PASS" } else { "FAIL" }
        );
    }
    let failed: Vec<_> = rows.iter().filter(|r| !r.3).map(|r| r.0).collect();
    assert!(failed.is_empty(), "budgets missed: {failed:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
