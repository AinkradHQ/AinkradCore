//! The event stream (E10.2) over a real socket: replay after a disconnect with nothing
//! missed or repeated, HTTP replay agreeing with the socket, live-only without a resume
//! point, and slow or silent clients closed with a resume hint instead of buffered.

use std::time::Duration;

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use super::super::events::StreamConfig;
use super::*;
use crate::store::audit;
use crate::store::events::{last_event_seq, list_events};

pub(super) type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The app served on a loopback port (its `Host`), sharing `fx`'s database and clock.
pub(super) async fn serve(fx: &Fx, stream: StreamConfig) -> App {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    // The same identity and sessions as `fx.app`, on this listener's Host.
    let app = App {
        host,
        stream,
        ..fx.app.clone()
    };
    let service = router(app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    app
}

pub(super) fn quick() -> StreamConfig {
    StreamConfig {
        poll: Duration::from_millis(20),
        heartbeat: Duration::from_secs(30),
        send_timeout: Duration::from_secs(5),
        page: 7,
        backstop: crate::auth::BACKSTOP,
    }
}

pub(super) async fn connect(
    app: &App,
    dev: &TestDevice,
    after: Option<&str>,
) -> Result<Ws, WsError> {
    let url = format!("ws://{}/api/v1/events/ws", app.host);
    let mut req = url.into_client_request().unwrap();
    let h = req.headers_mut();
    for (name, value) in dev.headers("GET", "/api/v1/events/ws", b"") {
        h.insert(name, value.parse().unwrap());
    }
    if let Some(after) = after {
        h.insert("last-event-id", after.parse().unwrap());
    }
    connect_async(req).await.map(|(ws, _)| ws)
}

/// The next event frame, as JSON; pings and pongs are skipped.
pub(super) async fn next(ws: &mut Ws) -> Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("an event within 10 s")
            .expect("the socket is open")
            .unwrap();
        if let Message::Text(t) = msg {
            return serde_json::from_str(&t).unwrap();
        }
    }
}

/// Events until (and including) seq `to`.
async fn until(ws: &mut Ws, to: i64) -> Vec<Value> {
    let mut got = vec![];
    while got
        .last()
        .is_none_or(|e: &Value| e["seq"].as_i64().unwrap() < to)
    {
        got.push(next(ws).await);
    }
    got
}

/// An audited change, as any write path appends one.
async fn audited(pool: &SqlitePool, action: &str) {
    let e = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: None,
        details: json!({}).to_string(),
    };
    audit::append_one(pool, &e).await.unwrap();
}

/// An event of a module's own kind, written as a module writes it.
async fn emitted(pool: &SqlitePool, n: i64) {
    let mut tx = crate::store::begin_write(pool).await.unwrap();
    crate::store::events::append(&mut tx, "ops.line", &json!({"n": n}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn seqs(events: &[Value]) -> Vec<i64> {
    events.iter().map(|e| e["seq"].as_i64().unwrap()).collect()
}

#[tokio::test]
async fn a_ten_minute_disconnect_replays_every_missed_event_once_in_order() {
    let fx = fx().await;
    let app = serve(&fx, quick()).await;
    let pool = &fx.app.pool;
    for n in 0..3 {
        emitted(pool, n).await;
    }

    let mut ws = connect(&app, &fx.dev, Some("0")).await.unwrap();
    let head = last_event_seq(pool).await.unwrap();
    let first = until(&mut ws, head).await;
    assert_eq!(first.len(), list_events(pool, 0, 1000).await.unwrap().len());
    let seen = head;
    drop(ws);

    // Away: a module's events, then audited changes.
    for n in 1..=12 {
        emitted(pool, n).await;
    }
    for action in ["thing.started", "thing.done", "thing.archived"] {
        audited(pool, action).await;
    }
    let head = last_event_seq(pool).await.unwrap();
    let missed = list_events(pool, seen, 1000).await.unwrap();
    assert!(missed.len() >= 15, "{} missed", missed.len());

    let resume = seen.to_string();
    let mut ws = connect(&app, &fx.dev, Some(&resume)).await.unwrap();
    let replayed = until(&mut ws, head).await;
    let want: Vec<i64> = missed.iter().map(|e| e.seq).collect();
    assert_eq!(seqs(&replayed), want, "every missed event, once, in order");
    let kinds: Vec<&str> = replayed
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for kind in ["ops.line", "audit"] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }
    assert_eq!(replayed[0]["payload"], json!({"n": 1}));
    let change = replayed.iter().find(|e| e["kind"] == "audit").unwrap();
    assert_eq!(change["payload"]["action"], "thing.started");
    assert_eq!(change["payload"]["actor_kind"], "system");

    // The HTTP replay is the same events, frame for frame.
    let uri = format!("/api/v1/events?after={seen}&limit=1000");
    let page = fx.ok(&uri).await;
    assert_eq!(page["items"], Value::Array(replayed.clone()));
    assert!(page["next_after"].is_null());
    let small = fx.ok(&format!("/api/v1/events?after={seen}&limit=5")).await;
    assert_eq!(small["items"], Value::Array(replayed[..5].to_vec()));
    assert_eq!(small["next_after"], replayed[4]["seq"]);

    // Then it is live.
    audited(pool, "thing.reopened").await;
    let live = next(&mut ws).await;
    assert_eq!(live["seq"], head + 1);
    assert_eq!(live["payload"]["action"], "thing.reopened");
}

#[tokio::test]
async fn without_a_resume_point_the_socket_is_live_only() {
    let fx = fx().await;
    let app = serve(&fx, quick()).await;
    let mut ws = connect(&app, &fx.dev, None).await.unwrap();
    let head = last_event_seq(&fx.app.pool).await.unwrap();
    // Give the socket a poll to settle, then write.
    tokio::time::sleep(Duration::from_millis(100)).await;
    emitted(&fx.app.pool, 1).await;
    assert_eq!(next(&mut ws).await["seq"], head + 1, "nothing older");

    match connect(&app, &fx.dev, Some("soon")).await {
        Err(WsError::Http(r)) => assert_eq!(r.status(), StatusCode::BAD_REQUEST),
        other => panic!("a bad Last-Event-ID is refused: {other:?}"),
    }
    match connect(&app, &fx.stranger(), Some("0")).await {
        Err(WsError::Http(r)) => assert_eq!(r.status(), StatusCode::UNAUTHORIZED),
        other => panic!("a stranger is refused: {other:?}"),
    }
}

/// Reads to the end of the socket: how many events, the last seq, and the close frame if
/// one came.
pub(super) async fn drain(ws: &mut Ws) -> (usize, i64, Option<(CloseCode, String)>) {
    let (mut events, mut last) = (0, 0);
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                events += 1;
                last = serde_json::from_str::<Value>(&t).unwrap()["seq"]
                    .as_i64()
                    .unwrap();
            }
            Ok(Some(Ok(Message::Close(frame)))) => {
                return (events, last, frame.map(|f| (f.code, f.reason.to_string())));
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_)) | None) => return (events, last, None),
            Err(_) => panic!("the server never closed the socket"),
        }
    }
}

#[tokio::test]
async fn a_client_that_stops_reading_is_closed_with_a_resume_hint() {
    let fx = fx().await;
    // 40 MB of events: more than the socket buffers hold.
    let text = "x".repeat(8 * 1024);
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000) \
         INSERT INTO events (at, kind, payload) SELECT ?, 'ops.blob', json_object('text', ?) \
         FROM n",
    )
    .bind(NOW)
    .bind(&text)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    let stream = StreamConfig {
        send_timeout: Duration::from_millis(300),
        page: 50,
        ..quick()
    };
    let app = serve(&fx, stream).await;
    let mut ws = connect(&app, &fx.dev, Some("0")).await.unwrap();
    // Not reading: the server's sends block, then time out.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (got, last, close) = drain(&mut ws).await;
    assert!(
        got > 0 && (got as i64) < total,
        "disconnected after {got} of {total}"
    );
    // The hint is best effort: a socket stuck this hard may never deliver the close frame.
    if let Some((code, reason)) = close {
        assert_eq!(code, CloseCode::Again, "{reason}");
        let hint: i64 = reason.rsplit(' ').next().unwrap().parse().unwrap();
        assert!(
            hint >= last,
            "{reason}: the server sent up to {hint}, we read {last}"
        );
    }

    // Resuming from the last event read carries on with the next one: nothing skipped.
    let mut ws = connect(&app, &fx.dev, Some(&last.to_string()))
        .await
        .unwrap();
    assert_eq!(next(&mut ws).await["seq"], last + 1);
}

#[tokio::test]
async fn a_silent_client_is_closed_after_three_heartbeats() {
    let fx = fx().await;
    let stream = StreamConfig {
        heartbeat: Duration::from_millis(100),
        ..quick()
    };
    let app = serve(&fx, stream).await;
    let mut ws = connect(&app, &fx.dev, None).await.unwrap();
    // Not reading means not answering pings.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let (_, _, close) = drain(&mut ws).await;
    let (code, reason) = close.expect("a close frame");
    assert_eq!(code, CloseCode::Away, "{reason}");
}

/// E1-04.4: a client whose resume point was trimmed gets a defined answer on both paths, then
/// recovers from the snapshot endpoint and misses nothing after it.
#[tokio::test]
async fn a_client_past_retention_gets_410_or_4410_and_recovers_from_latest() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    for n in 0..5 {
        sqlx::query("INSERT INTO events (at, kind, payload) VALUES (?, 'ops.line', ?)")
            .bind("2026-01-01T00:00:00.000Z")
            .bind(json!({"n": n}).to_string())
            .execute(pool)
            .await
            .unwrap();
    }
    // Everything so far is old by then, the device key's audit included.
    let trimmed = crate::store::events::trim(pool, "2027-01-01T00:00:00.000Z", 3600, 1000)
        .await
        .unwrap()
        .unwrap();
    let floor = trimmed.floor;
    assert!(trimmed.removed >= 5);

    let (status, body) = fx.get("/api/v1/events?after=0").await;
    assert_eq!(status, StatusCode::GONE, "{body}");
    assert_eq!(body["code"], "past_retention");
    assert_eq!(body["floor"], floor);
    assert!(body["error_id"].as_str().unwrap().starts_with("err_"));

    let app = serve(&fx, quick()).await;
    let mut ws = connect(&app, &fx.dev, Some("0")).await.unwrap();
    let (got, _, close) = drain(&mut ws).await;
    assert_eq!(got, 0, "nothing from below the floor");
    let (code, reason) = close.expect("a close frame");
    assert_eq!(code, CloseCode::from(4410), "{reason}");
    assert!(reason.contains(&format!("floor {floor}")), "{reason}");

    // Re-sync: the snapshot's seq, then everything after it.
    let latest = fx.ok("/api/v1/events/latest").await;
    assert_eq!(latest["floor"], floor);
    let head = latest["seq"].as_i64().unwrap();
    assert!(head >= floor);
    emitted(pool, 99).await;
    let page = fx.ok(&format!("/api/v1/events?after={head}")).await;
    assert_eq!(seqs(page["items"].as_array().unwrap()), [head + 1]);
    let mut ws = connect(&app, &fx.dev, Some(&head.to_string()))
        .await
        .unwrap();
    assert_eq!(next(&mut ws).await["payload"], json!({"n": 99}));
}

/// More idle sockets than the pool has connections: none is closed and the API still answers.
/// Each socket's revocation and scope pollers read the database; a poller parked mid-query by
/// the socket's own loop held its connection, and four of them starved the pool (E1-19).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_idle_sockets_never_starve_the_pool() {
    let fx = fx().await;
    // A backstop as fast as the read poll, so a socket often parks its watcher mid-check.
    let stream = StreamConfig {
        backstop: Duration::from_millis(20),
        ..quick()
    };
    let app = serve(&fx, stream).await;
    let mut sockets = vec![];
    for n in 0..40 {
        let dev = fx.enroll(&format!("s{n}"), &ALL).await;
        sockets.push(connect(&app, &dev, None).await.expect("connected"));
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let answered = tokio::time::timeout(Duration::from_secs(3), fx.get("/api/v1/me")).await;
    assert_eq!(
        answered.expect("the API answers within 3 s").0,
        StatusCode::OK
    );
    for ws in &mut sockets {
        let got = tokio::time::timeout(Duration::from_millis(10), ws.next()).await;
        assert!(
            !matches!(
                got,
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_)))
            ),
            "{got:?}"
        );
    }
}

/// E1-19: idle sockets cost no event reads. Between events the head does not move and no socket
/// reads its page; one event is then read once per socket and reaches every socket that may see
/// it within the budget, and a `read`-only socket never gets an admin-only `audit` event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_sockets_read_nothing_and_an_event_still_reaches_every_scoped_socket() {
    use std::sync::atomic::Ordering;
    let fx = fx().await;
    let app = serve(&fx, quick()).await;
    const N: usize = 30;
    let mut admins = vec![];
    let mut readers = vec![];
    for n in 0..N {
        if n % 2 == 0 {
            let dev = fx.enroll(&format!("a{n}"), &ALL).await;
            admins.push(connect(&app, &dev, None).await.expect("connected"));
        } else {
            let dev = fx.enroll(&format!("r{n}"), &["read"]).await;
            readers.push(connect(&app, &dev, None).await.expect("connected"));
        }
    }
    // Settle: the enrolments' audit events reach the admin sockets and are read.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for ws in &mut admins {
        while tokio::time::timeout(Duration::from_millis(20), ws.next())
            .await
            .is_ok()
        {}
    }
    let before = app.live.reads.load(Ordering::Relaxed);
    // 50 head polls at `quick()`'s 20 ms, no new event.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let idle = app.live.reads.load(Ordering::Relaxed) - before;
    assert_eq!(idle, 0, "{N} idle sockets read {idle} pages in 1 s");

    // An admin-only audit row, then an event every socket may see.
    audited(&fx.app.pool, "device.renamed").await;
    emitted(&fx.app.pool, 7).await;
    let started = std::time::Instant::now();
    for ws in &mut admins {
        let got = next(ws).await;
        assert_eq!(got["kind"], "audit", "{got}");
        assert_eq!(next(ws).await["payload"], json!({"n": 7}));
    }
    for ws in &mut readers {
        let got = next(ws).await;
        assert_eq!(got["kind"], "ops.line", "the audit row is hidden: {got}");
        assert_eq!(got["payload"], json!({"n": 7}));
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "delivered in {:?}",
        started.elapsed()
    );
    let spent = app.live.reads.load(Ordering::Relaxed) - before;
    assert!(
        spent <= 3 * N as u64,
        "{spent} page reads for two events on {N} sockets"
    );
}
