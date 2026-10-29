//! Event bus soak (E1-04.5): a producer appends events at `CORE_SOAK_PER_MIN` (default 10 000)
//! for `CORE_SOAK_SECS` (default 3600) while 20 clients read them over a real socket: 10 on the
//! WebSocket, 9 paging `GET /api/v1/events`, and one WebSocket that never reads. Asserts:
//!
//! - every reading client got every event, each seq once, in order, and none was closed;
//! - the stalled client, and only it, was closed: the server logs exactly one close, 1013 with a
//!   resume hint (the client sees that frame only if it gets through; a socket stuck this hard
//!   may only see the connection drop, as the stream documents);
//! - the process's RSS is flat: the last quarter's peak is within 20 % (+16 MB) of the second
//!   quarter's.
//!
//! Ignored by `make test`; `make soak` runs the hour, `CORE_SOAK_SECS=300 make soak` five
//! minutes. Memory is the whole test process (server and clients), sampled with `ps`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{begin_write, connect, events, kinds};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |v| v.parse().expect("a number"))
}

/// The server's log, kept to count how many sockets it closed and why.
#[derive(Clone, Default)]
struct Log(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn rss_kb() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

async fn ws(host: &str, dev: &TestDevice, after: i64) -> Ws {
    let mut req = format!("ws://{host}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    let h = req.headers_mut();
    for (name, value) in dev.headers("GET", "/api/v1/events/ws", b"") {
        h.insert(name, value.parse().unwrap());
    }
    h.insert("last-event-id", after.to_string().parse().unwrap());
    connect_async(req).await.unwrap().0
}

/// `GET path` over HTTP/1.1, signed, the JSON body. Each call takes a fresh session, so an
/// hour outlives none.
async fn get(host: &str, app: &App, dev: &TestDevice, path: &str) -> Value {
    let session = app.auth.issue_session(&dev.id, SystemClock.unix());
    dev.set_session(Some(session.id));
    let signed: String = dev
        .headers("GET", path, b"")
        .iter()
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .collect();
    let mut s = tokio::net::TcpStream::connect(host).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{signed}Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "{}",
        &text[..text.len().min(200)]
    );
    serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap()
}

/// Checks `seq` follows `last` and records it.
fn take(who: &str, last: &mut i64, seq: i64) {
    assert_eq!(seq, *last + 1, "{who}: a gap or a duplicate");
    *last = seq;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "soak: `make soak`"]
async fn ten_thousand_a_minute_to_twenty_clients_one_stalled() {
    let log = Log::default();
    let writer = log.clone();
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();
    let secs = env("CORE_SOAK_SECS", 3600);
    let per_min = env("CORE_SOAK_PER_MIN", 10_000);
    let dir = std::env::temp_dir().join(format!("core-soak-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let mut tx = begin_write(&pool).await.unwrap();
    kinds::register(&mut tx, "soak", &[("soak.tick", "read")], &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let app = App::new(
        pool.clone(),
        Arc::new(SystemClock),
        host.clone(),
        identity.clone(),
    );
    let mut devs = Vec::new();
    for n in 0..20 {
        let clock = Arc::new(SystemClock);
        let dev = TestDevice::enroll(
            &pool,
            &format!("c{n}"),
            "device",
            &["read"],
            &identity.fp,
            clock,
        )
        .await;
        let session = app.auth.issue_session(&dev.id, SystemClock.unix());
        dev.set_session(Some(session.id));
        devs.push(Arc::new(dev));
    }
    let service = router(app.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });

    let start = events::last_event_seq(&pool).await.unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let head = Arc::new(AtomicI64::new(start));

    // Readers: 10 sockets, 9 pollers. Each returns how many events it read.
    let mut readers = Vec::new();
    for (n, dev) in devs.iter().take(19).cloned().enumerate() {
        let (host, done, head, app) = (host.clone(), done.clone(), head.clone(), app.clone());
        readers.push(tokio::spawn(async move {
            let who = format!("client {n}");
            let mut last = start;
            if n < 10 {
                let mut socket = ws(&host, &dev, start).await;
                while !(done.load(Ordering::Relaxed) && last >= head.load(Ordering::Relaxed)) {
                    let msg = tokio::time::timeout(Duration::from_secs(30), socket.next()).await;
                    match msg.expect("an event or a ping within 30 s") {
                        Some(Ok(Message::Text(t))) => {
                            let e: Value = serde_json::from_str(&t).unwrap();
                            take(&who, &mut last, e["seq"].as_i64().unwrap());
                        }
                        Some(Ok(Message::Close(f))) => panic!("{who} was closed: {f:?}"),
                        Some(Ok(_)) => {}
                        other => panic!("{who}: the socket ended: {other:?}"),
                    }
                }
            } else {
                while !(done.load(Ordering::Relaxed) && last >= head.load(Ordering::Relaxed)) {
                    let page =
                        get(&host, &app, &dev, &format!("/api/v1/events?after={last}")).await;
                    for e in page["items"].as_array().unwrap() {
                        take(&who, &mut last, e["seq"].as_i64().unwrap());
                    }
                    if page["next_after"].is_null() {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            last - start
        }));
    }
    let mut stalled = ws(&host, &devs[19], start).await;

    // The producer: a batch every 100 ms, ~1 KB a payload.
    let producer = {
        let (pool, done, head) = (pool.clone(), done.clone(), head.clone());
        tokio::spawn(async move {
            let filler = "x".repeat(1000);
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            let (began, mut sent) = (Instant::now(), 0u64);
            while began.elapsed() < Duration::from_secs(secs) {
                tick.tick().await;
                let due = per_min * began.elapsed().as_millis() as u64 / 60_000;
                let mut tx = begin_write(&pool).await.unwrap();
                let mut seq = 0;
                while sent < due {
                    let p = json!({"n": sent, "filler": filler});
                    seq = events::append(&mut tx, "soak.tick", &p).await.unwrap();
                    sent += 1;
                }
                tx.commit().await.unwrap();
                if seq > 0 {
                    head.store(seq, Ordering::Relaxed);
                }
            }
            done.store(true, Ordering::Relaxed);
            sent
        })
    };

    let sampler = {
        let done = done.clone();
        tokio::spawn(async move {
            let mut samples = Vec::new();
            while !done.load(Ordering::Relaxed) {
                samples.push(rss_kb());
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            samples
        })
    };

    let sent = producer.await.unwrap();
    let samples = sampler.await.unwrap();
    let mut read = Vec::new();
    for r in readers {
        read.push(r.await.unwrap());
    }
    // The stalled client: everything it has, then how its socket ended.
    let (mut got, mut close) = (0u64, None);
    loop {
        match tokio::time::timeout(Duration::from_secs(30), stalled.next()).await {
            Ok(Some(Ok(Message::Text(_)))) => got += 1,
            Ok(Some(Ok(Message::Close(f)))) => {
                close = f.map(|f| (u16::from(f.code), f.reason.to_string()));
                break;
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_)) | None) => break,
            Err(_) => panic!("the stalled client was never closed"),
        }
    }
    assert!(
        got < sent,
        "the stalled client was cut off ({got} of {sent})"
    );
    if let Some((code, reason)) = &close {
        assert_eq!(*code, 1013, "{reason}");
        assert!(reason.contains("resume from the last seq read"), "{reason}");
    }

    // The server's side: exactly one socket closed, for being too slow.
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let closed: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("event stream closed"))
        .collect();
    assert_eq!(closed.len(), 1, "only the stalled client: {closed:?}");
    assert!(closed[0].contains("code=1013"), "{}", closed[0]);
    assert!(
        closed[0].contains("resume from the last seq read"),
        "{}",
        closed[0]
    );

    let q = samples.len() / 4;
    let (second, last) = (&samples[q..2 * q], &samples[3 * q..]);
    let (base, peak) = (
        second.iter().copied().max().unwrap_or(0),
        last.iter().copied().max().unwrap_or(0),
    );
    eprintln!(
        "soak: {secs} s, {sent} events ({per_min}/min), 19 readers read {:?}, stalled read {got} \
         then closed {close:?}; RSS KB every 10 s: {samples:?}; second-quarter peak {base}, \
         last-quarter peak {peak}",
        read.iter().collect::<std::collections::BTreeSet<_>>()
    );
    assert!(
        read.iter().all(|&r| r == sent as i64),
        "every reader got all {sent}: {read:?}"
    );
    assert!(
        peak <= base + base / 5 + 16 * 1024,
        "RSS grew: {base} KB -> {peak} KB"
    );
    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
