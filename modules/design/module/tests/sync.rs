//! V1-03 acceptance through the Core's real gate and a real socket: two clients converge, a hostile update is refused
//! and the peer dropped, crossing moves revert, a reconnect resumes from a cursor, nothing acknowledged is lost
//! across a restart, compaction and unloading work, a revoked device is cut, presence is stamped and capped.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, gov, migrate};
use design_doc::{NodeType, Replica};
use design_model::tree::forest;
use design_module::{Design, Limits};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const PAGE: &str = "n_pageaaaaaaaa";
const DOC: &str = "dd_00000000000000aa";

struct Fx {
    app: App,
    dev: Arc<TestDevice>,
    design: Design,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn enroll(app: &App, name: &str, scopes: &[&str]) -> TestDevice {
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        name,
        "device",
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    dev
}

async fn boot(limits: Limits) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "design-sync-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let design = Design::with_limits(limits);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(design.clone())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
    let mut app = App::new(
        pool,
        Arc::new(SystemClock),
        "core.test".to_owned(),
        identity,
    );
    app.modules = Arc::from(modules);
    let dev = enroll(&app, "admin", &["admin", "read"]).await;
    new_doc(&app, DOC, "design", "active").await;
    serve(app, Arc::new(dev), design, dir).await
}

async fn serve(app: App, dev: Arc<TestDevice>, design: Design, dir: PathBuf) -> Fx {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = App {
        host: listener.local_addr().unwrap().to_string(),
        ..app
    };
    let service = router(app.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    Fx {
        app,
        dev,
        design,
        dir,
    }
}

async fn new_doc(app: &App, id: &str, kind: &str, state: &str) {
    sqlx::query(
        "INSERT INTO design_docs (id, kind, name, state, created_by) VALUES (?, ?, 'd', ?, 'test')",
    )
    .bind(id)
    .bind(kind)
    .bind(state)
    .execute(&app.pool)
    .await
    .unwrap();
}

async fn connect_as(
    fx: &Fx,
    dev: &TestDevice,
    doc: &str,
    after: Option<i64>,
) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    let path = format!("/modules/design/v1/docs/{doc}/sync");
    let mut req = format!("ws://{}{path}", fx.app.host)
        .into_client_request()
        .unwrap();
    for (n, v) in dev.headers("GET", &path, b"") {
        req.headers_mut().insert(n, v.parse().unwrap());
    }
    if let Some(a) = after {
        req.headers_mut()
            .insert("last-update-seq", a.to_string().parse().unwrap());
    }
    connect_async(req).await.map(|(w, _)| w)
}

async fn connect_doc(fx: &Fx, after: Option<i64>) -> Ws {
    connect_as(fx, &fx.dev, DOC, after)
        .await
        .expect("the socket opens")
}

/// The next frame: `Bin(tag, seq, body)`, `Text`, or `Closed(code)`.
#[derive(Debug)]
enum F {
    Bin(u8, i64, Vec<u8>),
    Text(Value),
    Closed(u16),
}

async fn next(ws: &mut Ws) -> F {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a frame in time");
        match m {
            Some(Ok(Message::Binary(b))) => {
                let seq = i64::from_be_bytes(b[1..9].try_into().unwrap());
                return F::Bin(b[0], seq, b[9..].to_vec());
            }
            Some(Ok(Message::Text(t))) => {
                return F::Text(serde_json::from_str(t.as_str()).unwrap());
            }
            Some(Ok(Message::Close(c))) => return F::Closed(c.map_or(0, |c| u16::from(c.code))),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return F::Closed(0),
        }
    }
}

async fn send(ws: &mut Ws, update: &[u8]) {
    let mut v = vec![1u8];
    v.extend_from_slice(update);
    ws.send(Message::Binary(v.into())).await.unwrap();
}

/// Connect, take the snapshot, return a replica holding it.
async fn client(fx: &Fx) -> (Ws, Replica) {
    let mut ws = connect_doc(fx, None).await;
    let mut r = Replica::new();
    match next(&mut ws).await {
        F::Bin(2, _, s) => r.apply_trusted(&s).unwrap(),
        f => panic!("expected a snapshot, got {f:?}"),
    }
    (ws, r)
}

/// Send `update` and wait for its ack; returns the seq.
async fn push(ws: &mut Ws, update: &[u8]) -> i64 {
    send(ws, update).await;
    loop {
        match next(ws).await {
            F::Bin(3, seq, _) => return seq,
            F::Bin(..) | F::Text(_) => {}
            F::Closed(c) => panic!("closed {c} while waiting for an ack"),
        }
    }
}

/// Apply live updates until the replica's model equals `want`.
async fn catch_up(ws: &mut Ws, r: &mut Replica, want: &design_model::Doc) {
    for _ in 0..50 {
        if &r.read().unwrap() == want {
            return;
        }
        if let F::Bin(1, _, u) = next(ws).await {
            r.apply_trusted(&u).unwrap();
        }
    }
    panic!("never converged");
}

fn first_edit(r: &mut Replica) -> Vec<u8> {
    r.edit(|e| {
        e.insert_node(PAGE, NodeType::Page, None, "a", "p", &json!({}), None);
        e.insert_node(
            "n_aaaaaaaaaaab",
            NodeType::Frame,
            Some(PAGE),
            "a",
            "f",
            &json!({}),
            None,
        );
    })
    .1
}

#[tokio::test]
async fn two_clients_converge_and_every_ack_means_stored() {
    let fx = boot(Limits::default()).await;
    let ((mut wa, mut a), (mut wb, mut b)) = (client(&fx).await, client(&fx).await);
    let u = first_edit(&mut a);
    assert_eq!(push(&mut wa, &u).await, 1);
    // the ack came after the commit: the row is there already
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM design_updates WHERE doc = ?")
        .bind(DOC)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    catch_up(&mut wb, &mut b, &a.read().unwrap()).await;
    let u = b
        .edit(|e| {
            e.set_prop("n_aaaaaaaaaaab", "w", Some(&json!(40)));
        })
        .1;
    assert_eq!(push(&mut wb, &u).await, 2);
    catch_up(&mut wa, &mut a, &b.read().unwrap()).await;
    assert_eq!(a.read().unwrap().nodes["n_aaaaaaaaaaab"].props["w"], 40);
    let origin: String = sqlx::query_scalar("SELECT origin FROM design_updates WHERE seq = 2")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(origin, format!("person:{}", fx.dev.id));
}

#[tokio::test]
async fn a_hostile_update_is_refused_the_peer_dropped_and_the_doc_untouched() {
    let fx = boot(Limits::default()).await;
    let (mut wa, mut a) = client(&fx).await;
    push(&mut wa, &first_edit(&mut a)).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM design_updates")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    // 1. a node outside the schema
    let mut evil = Replica::new();
    evil.apply_trusted(&a.state()).unwrap();
    let bad = evil
        .edit(|e| {
            e.insert_node(
                "n_aaaaaaaaaaac",
                NodeType::Frame,
                Some(PAGE),
                "a",
                "f",
                &json!({"script": 1}),
                None,
            )
        })
        .1;
    let (mut w, _) = client(&fx).await;
    send(&mut w, &bad).await;
    assert!(
        matches!(next(&mut w).await, F::Closed(1008)),
        "schema violation drops the peer"
    );
    // 2. a move clock far above the document's: a refused remote update closes the connection too
    let mut c = Replica::new();
    c.apply_trusted(&a.state()).unwrap();
    let far = c
        .edit(|e| {
            e.insert_node(
                "n_aaaaaaaaaaac",
                NodeType::Frame,
                Some(PAGE),
                "a",
                "f",
                &json!({}),
                None,
            );
            e.set_clock_unchecked("n_aaaaaaaaaaac", 1 << 40);
        })
        .1;
    let (mut w, _) = client(&fx).await;
    send(&mut w, &far).await;
    assert!(
        matches!(next(&mut w).await, F::Closed(1008)),
        "clock cap violation drops the peer"
    );
    // 3. garbage, and an unknown frame tag
    let (mut w, _) = client(&fx).await;
    send(&mut w, &[9, 9, 9, 9, 9]).await;
    assert!(matches!(next(&mut w).await, F::Closed(1008)));
    let (mut w, _) = client(&fx).await;
    w.send(Message::Binary(vec![7u8, 1].into())).await.unwrap();
    assert!(matches!(next(&mut w).await, F::Closed(1008)));
    // 4. a frame over the cap
    let (mut w, _) = client(&fx).await;
    let _ = w.send(Message::Binary(vec![1u8; 2 << 20].into())).await;
    assert!(matches!(next(&mut w).await, F::Closed(1009 | 0)));
    // nothing was stored, nothing reached the honest client, and the doc still loads
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM design_updates")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(after, before);
    let (_, fresh) = client(&fx).await;
    assert_eq!(fresh.read().unwrap(), a.read().unwrap());
    // the honest peer heard of the dropped peers (presence "gone"), never of their updates
    while let Ok(f) = tokio::time::timeout(Duration::from_millis(200), next(&mut wa)).await {
        assert!(matches!(f, F::Text(_)), "{f:?}");
    }
}

#[tokio::test]
async fn crossing_moves_through_the_core_revert_the_loser() {
    let fx = boot(Limits::default()).await;
    let (mut wa, mut a) = client(&fx).await;
    let setup = a
        .edit(|e| {
            e.insert_node(PAGE, NodeType::Page, None, "a", "p", &json!({}), None);
            e.insert_node(
                "n_aaaaaaaaaaab",
                NodeType::Frame,
                Some(PAGE),
                "a",
                "f",
                &json!({}),
                None,
            );
            e.insert_node(
                "n_aaaaaaaaaaac",
                NodeType::Frame,
                Some(PAGE),
                "b",
                "f",
                &json!({}),
                None,
            );
        })
        .1;
    push(&mut wa, &setup).await;
    let (mut wb, mut b) = client(&fx).await;
    let (x, y) = ("n_aaaaaaaaaaab", "n_aaaaaaaaaaac");
    // both move before either hears of the other's move
    let ua = a.edit(|e| e.move_node(x, Some(y), "a").unwrap()).1;
    let ub = b.edit(|e| e.move_node(y, Some(x), "a").unwrap()).1;
    send(&mut wa, &ua).await;
    send(&mut wb, &ub).await;
    loop {
        // wait until the Core has both
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM design_updates")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
        if n == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (_, core) = client(&fx).await;
    let m = core.read().unwrap();
    catch_up(&mut wa, &mut a, &m).await;
    catch_up(&mut wb, &mut b, &m).await;
    let f = forest(&m);
    assert_eq!(f.reverted.len(), 1);
    assert!(f.detached.is_empty(), "reverted, not detached");
    assert_eq!(f.parent[&f.reverted[0]], PAGE);
}

#[tokio::test]
async fn a_reconnect_resumes_from_its_cursor() {
    let fx = boot(Limits::default()).await;
    let (mut wa, mut a) = client(&fx).await;
    push(&mut wa, &first_edit(&mut a)).await;
    for i in 0..3 {
        let u = a
            .edit(|e| {
                e.set_prop("n_aaaaaaaaaaab", "w", Some(&json!(i)));
            })
            .1;
        push(&mut wa, &u).await;
    }
    // had seen seq 2: gets 3 and 4 as updates, no snapshot
    let mut ws = connect_doc(&fx, Some(2)).await;
    for want in [3, 4] {
        assert!(matches!(next(&mut ws).await, F::Bin(1, s, _) if s == want));
    }
    // a cursor from the future is not trusted: a snapshot
    let mut ws = connect_doc(&fx, Some(99)).await;
    assert!(matches!(next(&mut ws).await, F::Bin(2, 4, _)));
}

#[tokio::test]
async fn compaction_unloading_and_a_restart_lose_nothing() {
    let limits = Limits {
        idle: Duration::from_millis(150),
        compact_updates: 3,
        ..Limits::default()
    };
    let fx = boot(limits).await;
    let (mut wa, mut a) = client(&fx).await;
    push(&mut wa, &first_edit(&mut a)).await;
    for i in 0..4 {
        let u = a
            .edit(|e| {
                e.set_prop("n_aaaaaaaaaaab", "w", Some(&json!(i)));
            })
            .1;
        push(&mut wa, &u).await;
    }
    let (snap_seq, has_snap): (i64, bool) =
        sqlx::query_as("SELECT snapshot_seq, snapshot IS NOT NULL FROM design_docs WHERE id = ?")
            .bind(DOC)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(has_snap && snap_seq == 3, "folded at 3 updates: {snap_seq}");
    let log: i64 = sqlx::query_scalar("SELECT count(*) FROM design_updates")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(log, 2, "only the updates after the snapshot remain");
    let auto: i64 =
        sqlx::query_scalar("SELECT count(*) FROM design_versions WHERE doc = ? AND kind = 'auto'")
            .bind(DOC)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(
        auto, 1,
        "one auto version at the first compaction, none within 10 minutes"
    );
    // a cursor older than the compacted log gets a snapshot
    let mut ws = connect_doc(&fx, Some(1)).await;
    assert!(matches!(next(&mut ws).await, F::Bin(2, 5, _)));
    drop(ws);
    // idle: the actor unloads after the last peer leaves
    drop(wa);
    for _ in 0..40 {
        if fx.design.loaded().await == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(fx.design.loaded().await, 0, "unloaded when idle");
    // a restart: a brand-new Core process (new registry) over the same database
    let design2 = Design::default();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(design2.clone())];
    let mut app = fx.app.clone();
    app.modules = Arc::from(modules);
    let fx2 = serve(app, fx.dev.clone(), design2, fx.dir.clone()).await;
    let (_, again) = client(&fx2).await;
    assert_eq!(
        again.read().unwrap(),
        a.read().unwrap(),
        "everything acknowledged is there"
    );
    assert_eq!(again.read().unwrap().nodes["n_aaaaaaaaaaab"].props["w"], 3);
}

#[tokio::test]
async fn a_revoked_device_is_cut_and_a_read_only_device_never_opens() {
    let fx = boot(Limits::default()).await;
    let (mut ws, _) = client(&fx).await;
    let id = fx.dev.id.clone();
    let now = fx.app.clock.now();
    assert!(
        gov::revoke_device(&fx.app.pool, &id, BY, None, &now)
            .await
            .unwrap()
    );
    fx.app.auth.revoked(&id);
    assert!(
        matches!(next(&mut ws).await, F::Closed(4001)),
        "cut by the revocation"
    );
    let fx = boot(Limits::default()).await;
    let viewer = enroll(&fx.app, "viewer", &["read"]).await;
    let err = connect_as(&fx, &viewer, DOC, None)
        .await
        .expect_err("refused");
    assert!(matches!(err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 403));
}

#[tokio::test]
async fn archived_docs_and_mockups_do_not_sync() {
    let fx = boot(Limits::default()).await;
    new_doc(&fx.app, "dd_00000000000000ab", "design", "archived").await;
    new_doc(&fx.app, "dd_00000000000000ac", "mockup", "active").await;
    for (doc, status) in [
        ("dd_00000000000000ab", 409),
        ("dd_00000000000000ac", 404),
        ("dd_00000000000000ad", 404),
        ("nope", 404),
    ] {
        let err = connect_as(&fx, &fx.dev, doc, None)
            .await
            .expect_err("refused");
        assert!(
            matches!(err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == status),
            "{doc}"
        );
    }
}

#[tokio::test]
async fn presence_is_stamped_validated_and_capped() {
    let fx = boot(Limits::default()).await;
    let ((mut wa, _), (mut wb, _)) = (client(&fx).await, client(&fx).await);
    wa.send(Message::Text(
        json!({"cursor": [10.5, 20.0], "selection": ["n_aaaaaaaaaaab"]})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let F::Text(p) = next(&mut wb).await else {
        panic!("presence")
    };
    assert_eq!(p["peer"], format!("person:{}", fx.dev.id));
    assert_eq!(p["cursor"], json!([10.5, 20.0]));
    // a peer cannot name itself: the field is refused, and the socket dropped
    wa.send(Message::Text(
        json!({"peer": "person:d_other"}).to_string().into(),
    ))
    .await
    .unwrap();
    assert!(matches!(next(&mut wa).await, F::Closed(1008)));
    assert!(matches!(next(&mut wb).await, F::Text(v) if v["gone"] == true));
    // a flood is dropped down to the cap (20/s, burst 40), the socket stays up
    let (mut wc, _) = client(&fx).await;
    for _ in 0..200 {
        wc.send(Message::Text(
            json!({"cursor": [1.0, 2.0]}).to_string().into(),
        ))
        .await
        .unwrap();
    }
    let mut got = 0;
    while let Ok(Some(Ok(Message::Text(_)))) =
        tokio::time::timeout(Duration::from_millis(400), wb.next()).await
    {
        got += 1;
    }
    assert!((1..=60).contains(&got), "{got} presence frames");
}

#[tokio::test]
async fn too_many_updates_close_the_socket() {
    let fx = boot(Limits {
        update_rate: 2.0,
        ..Limits::default()
    })
    .await;
    let (mut w, mut r) = client(&fx).await;
    let mut closed = false;
    for i in 0..30 {
        let u = r
            .edit(|e| {
                e.insert_node(
                    &format!(
                        "n_aaaaaaaaaa{}a",
                        ["b", "c", "d", "e", "f", "g", "h", "i", "j", "k"][i % 10]
                    ),
                    NodeType::Page,
                    None,
                    "a",
                    "p",
                    &json!({}),
                    None,
                )
            })
            .1;
        send(&mut w, &u).await;
        if let Ok(F::Closed(c)) =
            tokio::time::timeout(Duration::from_millis(30), async { next(&mut w).await }).await
        {
            assert_eq!(c, 4429);
            closed = true;
            break;
        }
    }
    assert!(closed);
}

#[tokio::test]
async fn a_refused_update_is_quarantined_and_never_reaches_another_device() {
    let fx = boot(Limits::default()).await;
    let (mut wa, mut a) = client(&fx).await;
    push(&mut wa, &first_edit(&mut a)).await;
    let good = a.state();
    // device A forges an update that is out of schema, sends it, and is dropped
    let bad = a
        .edit(|e| {
            e.insert_node(
                "n_aaaaaaaaaaac",
                NodeType::Frame,
                Some(PAGE),
                "a",
                "f",
                &json!({"script": 1}),
                None,
            );
        })
        .1;
    send(&mut wa, &bad).await;
    assert!(matches!(next(&mut wa).await, F::Closed(1008)));
    // nothing of it was stored, in the log or in a snapshot
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT data FROM design_updates WHERE doc = ?")
        .bind(DOC)
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "only the update that passed the trial apply");
    let mut from_log = Replica::new();
    for r in &rows {
        from_log.apply_trusted(r).unwrap();
    }
    assert_eq!(
        from_log.read().unwrap(),
        Replica::from_stored([good.as_slice()])
            .unwrap()
            .read()
            .unwrap()
    );
    // device B resyncs by snapshot and by cursor: neither carries the bad update, and both read back clean
    let (_, b) = client(&fx).await;
    assert!(!b.read().unwrap().nodes.contains_key("n_aaaaaaaaaaac"));
    let mut ws = connect_doc(&fx, Some(0)).await;
    let mut via_cursor = Replica::new();
    while let F::Bin(t, _, body) = next(&mut ws).await {
        assert!(t == 1 || t == 2);
        via_cursor.apply_trusted(&body).unwrap();
        if via_cursor.read().unwrap().nodes.len() == 2 {
            break;
        }
    }
    assert!(
        !via_cursor
            .read()
            .unwrap()
            .nodes
            .contains_key("n_aaaaaaaaaaac")
    );
    assert_eq!(b.read().unwrap(), via_cursor.read().unwrap());
}

#[tokio::test]
async fn an_update_that_depends_on_missing_state_asks_for_a_resync_and_nothing_is_stored() {
    let fx = boot(Limits::default()).await;
    let (mut wa, mut a) = client(&fx).await;
    let first = first_edit(&mut a);
    let second = a
        .edit(|e| {
            e.set_prop("n_aaaaaaaaaaab", "w", Some(&json!(1)));
        })
        .1;
    // the second update arrives without the first: the Core cannot place it, so the client must resync
    send(&mut wa, &second).await;
    assert!(matches!(next(&mut wa).await, F::Closed(4412)));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM design_updates")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "nothing stored");
    // resync: reconnect (snapshot), resend in order: the Core accepts both
    let (mut wb, _) = client(&fx).await;
    assert_eq!(push(&mut wb, &first).await, 1);
    assert_eq!(push(&mut wb, &second).await, 2);
}

#[tokio::test]
async fn incremental_edits_from_one_device_are_all_accepted() {
    // the shape of real use: one client, a run of small edits, each building on the last (insert, text, prop, move,
    // delete); the dependency rule must never mistake them for missing state
    let fx = boot(Limits::default()).await;
    let (mut w, mut a) = client(&fx).await;
    push(&mut w, &first_edit(&mut a)).await;
    let mut seq = 1;
    for step in 0..5 {
        let u = a
            .edit(|e| match step {
                0 => e.insert_node(
                    "n_aaaaaaaaaaac",
                    NodeType::Text,
                    Some(PAGE),
                    "b",
                    "t",
                    &json!({}),
                    Some("h\u{e9}llo"),
                ),
                1 => {
                    e.insert_text("n_aaaaaaaaaaac", 2, "\u{1f600}");
                }
                2 => {
                    e.set_prop("n_aaaaaaaaaaab", "w", Some(&json!(7)));
                }
                3 => {
                    let _ = e.move_node("n_aaaaaaaaaaac", Some("n_aaaaaaaaaaab"), "a");
                }
                _ => e.remove_node("n_aaaaaaaaaaac"),
            })
            .1;
        seq += 1;
        assert_eq!(push(&mut w, &u).await, seq, "step {step}");
    }
    let (_, fresh) = client(&fx).await;
    assert_eq!(fresh.read().unwrap(), a.read().unwrap());
}

#[tokio::test]
async fn a_device_may_hold_only_so_many_sockets() {
    let fx = boot(Limits {
        max_per_device: 3,
        ..Limits::default()
    })
    .await;
    let mut held = vec![];
    for _ in 0..3 {
        held.push(client(&fx).await);
    }
    let err = connect_as(&fx, &fx.dev, DOC, None)
        .await
        .expect_err("the fourth is refused");
    assert!(matches!(err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 429));
    // a closed socket frees its place
    drop(held.pop());
    let mut again = None;
    for _ in 0..40 {
        if let Ok(w) = connect_as(&fx, &fx.dev, DOC, None).await {
            again = Some(w);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(again.is_some(), "a place was freed");
}

#[tokio::test]
async fn only_so_many_documents_are_loaded_and_idle_ones_make_room() {
    let fx = boot(Limits {
        max_docs: 2,
        idle: Duration::from_secs(3600),
        ..Limits::default()
    })
    .await;
    let (b, c) = ("dd_00000000000000ab", "dd_00000000000000ac");
    new_doc(&fx.app, b, "design", "active").await;
    new_doc(&fx.app, c, "design", "active").await;
    let first = connect_as(&fx, &fx.dev, DOC, None).await.unwrap();
    let _second = connect_as(&fx, &fx.dev, b, None).await.unwrap();
    let err = connect_as(&fx, &fx.dev, c, None)
        .await
        .expect_err("both loaded docs are in use");
    assert!(matches!(err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 503));
    // the first doc goes idle (nobody holds it): it is evicted at once for the new one, long before its idle timer
    drop(first);
    let mut third = None;
    for _ in 0..40 {
        if let Ok(w) = connect_as(&fx, &fx.dev, c, None).await {
            third = Some(w);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(third.is_some(), "an idle doc made room");
    assert_eq!(fx.design.loaded().await, 2);
}

#[tokio::test]
async fn auto_versions_stay_inside_their_byte_budget() {
    let fx = boot(Limits {
        compact_updates: 1,
        auto_secs: 0,
        auto_bytes: 3000,
        ..Limits::default()
    })
    .await;
    let (mut w, mut a) = client(&fx).await;
    push(&mut w, &first_edit(&mut a)).await;
    for i in 0..40 {
        let u = a
            .edit(|e| {
                e.set_prop("n_aaaaaaaaaaab", "w", Some(&json!(i)));
            })
            .1;
        push(&mut w, &u).await;
    }
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT length(state) FROM design_versions WHERE doc = ? AND kind = 'auto'")
            .bind(DOC)
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    let total: i64 = rows.iter().map(|r| r.0).sum();
    assert!(
        !rows.is_empty() && rows.len() < 41,
        "{} versions kept",
        rows.len()
    );
    assert!(total <= 3000, "{total} bytes of auto versions");
}

#[tokio::test]
async fn a_poisoned_replica_that_cannot_be_rebuilt_is_never_served() {
    let fx = boot(Limits::default()).await;
    let (mut wa, mut a) = client(&fx).await;
    push(&mut wa, &first_edit(&mut a)).await;
    // storage turns bad: the rebuild after the next refusal cannot succeed
    sqlx::query("INSERT INTO design_updates (doc, seq, data, origin) VALUES (?, 99, x'ff01', 'x')")
        .bind(DOC)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let bad = a
        .edit(|e| {
            e.insert_node(
                "n_aaaaaaaaaaac",
                NodeType::Frame,
                Some(PAGE),
                "a",
                "f",
                &json!({"script": 1}),
                None,
            );
        })
        .1;
    send(&mut wa, &bad).await;
    assert!(matches!(next(&mut wa).await, F::Closed(1008)));
    // a newcomer is closed with a server error, never sent a snapshot of the poisoned replica
    let mut ws = connect_doc(&fx, None).await;
    assert!(matches!(next(&mut ws).await, F::Closed(1011)));
    let mut ws = connect_doc(&fx, Some(1)).await;
    assert!(matches!(next(&mut ws).await, F::Closed(1011)));
}
