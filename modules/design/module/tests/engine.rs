//! V1-05 acceptance: one doc crate on both sides of the socket. The App engine's document (`design_doc::Live`) and a
//! second device (`design_doc::Replica`) edit the same design concurrently through the Core's real sync socket, 50
//! random edits (25 rounds, both sides each round, every fifth round a crossing move), and after every round the
//! engine, the device and the Core's own replica read the same document.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate};
use design_doc::{Live, Model, NodeType, Replica, parse_ops};
use design_model::tree::forest;
use design_module::{Design, Limits};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const DOC: &str = "dd_00000000000000aa";
const PAGE: &str = "n_pageaaaaaaaa";
/// What `encode_update_v1` returns for an edit that changed nothing.
const EMPTY: [u8; 2] = [0, 0];

struct Fx {
    app: App,
    dev: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn boot() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "design-engine-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let design = Design::with_limits(Limits::default());
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(design)];
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
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        "admin",
        "device",
        &["admin", "read"],
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    sqlx::query(
        "INSERT INTO design_docs (id, kind, name, state, created_by) VALUES (?, 'design', 'd', 'active', 'test')",
    )
    .bind(DOC)
    .execute(&app.pool)
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = App {
        host: listener.local_addr().unwrap().to_string(),
        ..app
    };
    let service = router(app.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    Fx { app, dev, dir }
}

async fn open(fx: &Fx) -> Ws {
    let path = format!("/modules/design/v1/docs/{DOC}/sync");
    let mut req = format!("ws://{}{path}", fx.app.host)
        .into_client_request()
        .unwrap();
    for (n, v) in fx.dev.headers("GET", &path, b"") {
        req.headers_mut().insert(n, v.parse().unwrap());
    }
    connect_async(req).await.expect("the socket opens").0
}

/// The next binary frame `(tag, seq, body)`; text (presence) is skipped, a close fails the test.
async fn next(ws: &mut Ws) -> (u8, i64, Vec<u8>) {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("a frame in time");
        match m {
            Some(Ok(Message::Binary(b))) => {
                let seq = i64::from_be_bytes(b[1..9].try_into().unwrap());
                return (b[0], seq, b[9..].to_vec());
            }
            Some(Ok(Message::Close(c))) => panic!("closed: {c:?}"),
            Some(Ok(_)) => {}
            Some(Err(e)) => panic!("socket error: {e}"),
            None => panic!("socket ended"),
        }
    }
}

/// The two kinds of replica on the device side of the socket.
enum Rep {
    Engine(Box<Live>),
    Device(Box<Replica>),
}

impl Rep {
    /// Apply what the Core sent: the engine through its own gate, the device as trusted Core bytes.
    fn apply(&mut self, u: &[u8]) {
        match self {
            Rep::Engine(l) => l
                .apply_remote(u)
                .expect("the engine takes what the Core relays"),
            Rep::Device(r) => {
                r.apply_remote(u).unwrap();
            }
        }
    }
    fn read(&self) -> Model {
        match self {
            Rep::Engine(l) => l.read(),
            Rep::Device(r) => r.read().unwrap(),
        }
    }
}

struct Side {
    ws: Ws,
    rep: Rep,
    /// The highest seq of a relayed frame applied.
    seen: i64,
}

/// Open a socket and take the snapshot.
async fn join(fx: &Fx, mut rep: Rep) -> Side {
    let mut ws = open(fx).await;
    let (tag, seq, snap) = next(&mut ws).await;
    assert_eq!(tag, 2, "a snapshot first");
    rep.apply(&snap);
    Side { ws, rep, seen: seq }
}

/// Send `u` (nothing when the edit changed nothing) and wait for its ack, applying whatever the Core relays meanwhile.
async fn push(s: &mut Side, u: &[u8]) -> Option<i64> {
    if u.is_empty() || u == EMPTY {
        return None;
    }
    let mut v = vec![1u8];
    v.extend_from_slice(u);
    s.ws.send(Message::Binary(v.into())).await.unwrap();
    loop {
        match next(&mut s.ws).await {
            (3, seq, _) => return Some(seq),
            (1, seq, b) => {
                s.rep.apply(&b);
                s.seen = seq;
            }
            _ => {}
        }
    }
}

/// Apply relayed updates until this side has seen `seq` (an update the other side pushed).
async fn until_seen(s: &mut Side, seq: Option<i64>) {
    let Some(seq) = seq else { return };
    while s.seen < seq {
        if let (1, n, b) = next(&mut s.ws).await {
            s.rep.apply(&b);
            s.seen = n;
        }
    }
}

fn id(i: u64) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = vec![b'a'; 12];
    let (mut i, mut k) = (i, 11);
    while i > 0 {
        s[k] = A[(i % 32) as usize];
        i /= 32;
        k -= 1;
    }
    format!("n_{}", String::from_utf8(s).unwrap())
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, v: &'a [String]) -> &'a String {
        &v[(self.next() % v.len() as u64) as usize]
    }
}

const ORDERS: [&str; 6] = ["a", "b", "c", "m", "n", "z"];

/// One random edit, as a list of ops for the engine (`Ok`) or as an edit on the device (`Err`), from the model both
/// sides currently read. Frames are only ever moved by the crossing rounds (pairs `X`/`Y`), so those stay unrelated
/// until their round; random moves and deletes touch rects only.
enum Edit {
    Add { id: String, parent: String },
    Move { id: String, parent: String },
    Prop { id: String, x: u64 },
    Delete { id: String },
}

fn random_edit(m: &Model, rng: &mut Rng, fresh: String) -> Edit {
    let containers: Vec<String> = m
        .nodes
        .iter()
        .filter(|(_, n)| n.ty.is_container())
        .map(|(i, _)| i.clone())
        .collect();
    let rects: Vec<String> = m
        .nodes
        .iter()
        .filter(|(_, n)| n.ty == NodeType::Rect)
        .map(|(i, _)| i.clone())
        .collect();
    let kind = if rects.is_empty() { 0 } else { rng.next() % 4 };
    match kind {
        0 => Edit::Add {
            id: fresh,
            parent: rng.pick(&containers).clone(),
        },
        1 => Edit::Move {
            id: rng.pick(&rects).clone(),
            parent: rng.pick(&containers).clone(),
        },
        2 => Edit::Prop {
            id: rng.pick(&rects).clone(),
            x: rng.next() % 500,
        },
        _ => Edit::Delete {
            id: rng.pick(&rects).clone(),
        },
    }
}

fn engine_ops(e: &Edit, order: &str) -> Value {
    match e {
        Edit::Add { id, parent } => {
            json!([{"op": "add", "id": id, "type": "rect", "parent": parent,
            "order": order, "props": {"w": 10, "h": 10}}])
        }
        Edit::Move { id, parent } => {
            json!([{"op": "move", "id": id, "parent": parent, "order": order}])
        }
        Edit::Prop { id, x } => json!([{"op": "set", "id": id, "key": "x", "value": x}]),
        Edit::Delete { id } => json!([{"op": "delete", "id": id}]),
    }
}

/// The engine's edit; a batch its validators refuse writes nothing (and sends nothing).
fn engine_edit(l: &mut Live, ops: Value) -> Vec<u8> {
    let _ = l.apply_ops(&parse_ops(ops.to_string().as_bytes()).unwrap());
    l.outbox(true)
}

fn device_edit(r: &mut Replica, e: &Edit, order: &str) -> Vec<u8> {
    r.edit(|ed| match e {
        Edit::Add { id, parent } => ed.insert_node(
            id,
            NodeType::Rect,
            Some(parent),
            order,
            "r",
            &json!({"w": 10, "h": 10}),
            None,
        ),
        Edit::Move { id, parent } => {
            let _ = ed.move_node(id, Some(parent), order);
        }
        Edit::Prop { id, x } => {
            ed.set_prop(id, "x", Some(&json!(x)));
        }
        Edit::Delete { id } => ed.remove_node(id),
    })
    .1
}

#[tokio::test]
async fn an_engine_and_the_core_converge_through_fifty_random_concurrent_edits() {
    let fx = boot().await;
    let mut e = join(&fx, Rep::Engine(Box::new(Live::new()))).await;
    // the engine makes the page, the crossing pairs and a frame for random content
    let mut seed =
        vec![json!({"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"})];
    let pairs: Vec<(String, String)> = (0..5).map(|k| (id(100 + 2 * k), id(101 + 2 * k))).collect();
    for (k, (x, y)) in pairs.iter().enumerate() {
        for (n, f) in [(x, "x"), (y, "y")] {
            seed.push(
                json!({"op": "add", "id": n, "type": "frame", "parent": PAGE,
                "order": format!("b{k}{f}"), "props": {"w": 100, "h": 100}}),
            );
        }
    }
    seed.push(json!({"op": "add", "id": id(99), "type": "frame", "parent": PAGE, "order": "c"}));
    let Rep::Engine(l) = &mut e.rep else {
        unreachable!()
    };
    let u = engine_edit(l, Value::Array(seed));
    assert!(push(&mut e, &u).await.is_some(), "the seed is stored");
    let mut d = join(&fx, Rep::Device(Box::new(Replica::new()))).await;
    assert_eq!(
        d.rep.read(),
        e.rep.read(),
        "the device starts from the engine's seed"
    );
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let (mut next_e, mut next_d) = (1000u64, 2000u64);
    let mut crossings = 0;
    for round in 0..25 {
        let m = e.rep.read();
        let order = ORDERS[(rng.next() % ORDERS.len() as u64) as usize];
        // both edits are made before either side hears of the other's: concurrent
        let crossing = round % 5 == 4;
        let (ue, ud) = if crossing {
            let (x, y) = &pairs[round / 5];
            let ue = {
                let Rep::Engine(l) = &mut e.rep else {
                    unreachable!()
                };
                engine_edit(
                    l,
                    json!([{"op": "move", "id": x, "parent": y, "order": "a"}]),
                )
            };
            let Rep::Device(r) = &mut d.rep else {
                unreachable!()
            };
            let (moved, ud) = r.edit(|ed| ed.move_node(y, Some(x), "a"));
            moved.expect("y under x is a legal local move");
            (ue, ud)
        } else {
            let we = random_edit(&m, &mut rng, id(next_e));
            let wd = random_edit(&m, &mut rng, id(next_d));
            next_e += 1;
            next_d += 1;
            let ue = {
                let Rep::Engine(l) = &mut e.rep else {
                    unreachable!()
                };
                engine_edit(l, engine_ops(&we, order))
            };
            let Rep::Device(r) = &mut d.rep else {
                unreachable!()
            };
            (ue, device_edit(r, &wd, order))
        };
        if crossing {
            assert!(
                !ue.is_empty() && ud != EMPTY,
                "round {round}: both moves were made"
            );
        }
        let se = push(&mut e, &ue).await;
        let sd = push(&mut d, &ud).await;
        until_seen(&mut e, sd).await;
        until_seen(&mut d, se).await;
        let (me, md) = (e.rep.read(), d.rep.read());
        assert_eq!(me, md, "round {round}: engine and device converge");
        assert_eq!(forest(&me), forest(&md), "round {round}: the same tree");
        if crossing {
            let f = forest(&me);
            assert!(
                !f.broken.is_empty(),
                "round {round}: the crossing left one cycle"
            );
            assert!(
                f.detached.is_empty(),
                "round {round}: the loser is reverted, not detached"
            );
            crossings += 1;
        }
    }
    assert_eq!(crossings, 5);
    // the Core's own replica, as a newcomer gets it, holds the same document; so does one rebuilt from storage
    let fresh = join(&fx, Rep::Device(Box::new(Replica::new()))).await;
    let want = e.rep.read();
    assert_eq!(fresh.rep.read(), want, "the Core's replica converged too");
    let (snap, snap_seq): (Option<Vec<u8>>, i64) =
        sqlx::query_as("SELECT snapshot, snapshot_seq FROM design_docs WHERE id = ?")
            .bind(DOC)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    let log: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT data FROM design_updates WHERE doc = ? AND seq > ? ORDER BY seq",
    )
    .bind(DOC)
    .bind(snap_seq)
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    let stored = Replica::from_stored(snap.iter().chain(log.iter()).map(Vec::as_slice)).unwrap();
    assert_eq!(
        stored.read().unwrap(),
        want,
        "what is stored is what everyone reads"
    );
    // and an engine that joins now loads the Core's snapshot through its own gate
    let late = join(&fx, Rep::Engine(Box::new(Live::new()))).await;
    assert_eq!(late.rep.read(), want);
}
