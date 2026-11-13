//! The local terminal path through the real Core API, runner daemon and `ainkrad-ptyhost`
//! (spec `Specs/2026-11-12-local-terminal-path.md`): the Core grants and records, the app's
//! bytes go over the host's Unix socket and never through the Core.

use super::*;
use ainkrad_proto::v2::local::attach_message;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

struct Sock {
    r: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    w: tokio::net::unix::OwnedWriteHalf,
    challenge: String,
    seen: String,
}

impl Sock {
    async fn open(fx: &Fx, id: &str) -> Self {
        let s = UnixStream::connect(fx.dir.join(format!("{id}.local.sock")))
            .await
            .expect("the host has a local socket");
        let (r, w) = s.into_split();
        let mut me = Self {
            r: BufReader::new(r).lines(),
            w,
            challenge: String::new(),
            seen: String::new(),
        };
        let v = me.next().await.expect("a challenge");
        assert_eq!(v["type"], "challenge", "{v}");
        me.challenge = v["nonce"].as_str().unwrap().to_owned();
        me
    }
    async fn next(&mut self) -> Option<Value> {
        let line = tokio::time::timeout(Duration::from_secs(10), self.r.next_line())
            .await
            .expect("the host answers")
            .ok()??;
        Some(serde_json::from_str(&line).unwrap())
    }
    async fn send(&mut self, v: Value) {
        let _ = self.w.write_all(format!("{v}\n").as_bytes()).await;
    }
    /// The grant, proved with `dev`'s routine key.
    async fn auth(&mut self, dev: &TestDevice, grant: &str) -> Result<(), String> {
        let sig = URL_SAFE_NO_PAD.encode(dev.sign(&attach_message(&self.challenge, grant)));
        self.send(json!({"type":"auth","grant":grant,"sig":sig}))
            .await;
        loop {
            let v = self.next().await.ok_or("closed")?;
            match v["type"].as_str() {
                Some("authed") => return Ok(()),
                Some("error") => return Err(v["message"].as_str().unwrap().to_owned()),
                _ => {}
            }
        }
    }
    async fn until(&mut self, needle: &str) {
        while !self.seen.contains(needle) {
            let v = self
                .next()
                .await
                .unwrap_or_else(|| panic!("no {needle:?}: {:?}", self.seen));
            if let Some(d) = v["data"]
                .as_str()
                .filter(|_| v["type"] == "out" || v["type"] == "snapshot")
            {
                self.seen += &String::from_utf8_lossy(&B64.decode(d).unwrap());
            }
        }
    }
}

#[tokio::test]
async fn the_core_grants_the_app_types_locally_and_the_core_records_it() {
    let fx = Fx::new("t-local").await;
    let o = &fx.owner;
    let id = fx.sh(o).await;
    let uri = format!("/api/v1/terminals/{id}/local");

    // The Core is the authority: no step-up, no grant; and a device without the scope, none.
    let cold = fx.device(false).await;
    let (s, _) = fx.call(&cold, "POST", &uri, None).await;
    assert_eq!(s, 403, "no step-up");
    assert_eq!(
        fx.count("SELECT count(*) FROM audit_events WHERE action='terminal.attached'")
            .await,
        0
    );
    let reader = fx.core.device("device", &["read"]).await;
    elevate(&fx.core, &reader);
    assert_eq!(
        fx.call(&reader, "POST", &uri, None).await.0,
        403,
        "no terminal scope"
    );

    let (s, g) = fx.call(o, "POST", &uri, None).await;
    assert_eq!(s, 200, "{g}");
    assert_eq!(g["socket"], format!("{id}.local.sock"));
    assert_eq!(g["runner"], fx.runner.as_str());
    assert_eq!(g["lease_secs"], 45);
    let grant = g["grant"].as_str().unwrap().to_owned();

    // The attach is recorded as local, and counts as an attached client.
    let rows = fx.count("SELECT count(*) FROM audit_events WHERE action='terminal.attached' AND details LIKE '%\"local\":true%'").await;
    assert_eq!(rows, 1);
    let (_, t) = fx
        .call(o, "GET", &format!("/api/v1/terminals/{id}"), None)
        .await;
    assert_eq!(t["attached"], 1, "{t}");

    // The bytes go over the socket: type and read back with the Core's WebSocket never opened.
    let mut s = Sock::open(&fx, &id).await;
    s.auth(o, &grant).await.unwrap();
    s.send(json!({"type":"attach","seq":0})).await;
    s.until("ready").await;
    s.send(json!({"type":"input","data":B64.encode("hi-local\n")}))
        .await;
    s.until("got:hi-local").await;
    // The Core never saw the bytes.
    assert!(!fx.everything().await.contains("hi-local"));

    // A grant works once; another device's key cannot use it.
    let mut again = Sock::open(&fx, &id).await;
    assert!(
        again
            .auth(o, &grant)
            .await
            .unwrap_err()
            .contains("already used")
    );
    let (_, g2) = fx.call(o, "POST", &uri, None).await;
    let thief = fx.device(true).await;
    let mut again = Sock::open(&fx, &id).await;
    assert!(
        again
            .auth(&thief, g2["grant"].as_str().unwrap())
            .await
            .unwrap_err()
            .contains("proof")
    );

    // A renewal is not another attach.
    assert_eq!(
        fx.count("SELECT count(*) FROM audit_events WHERE action='terminal.attached'")
            .await,
        1
    );

    // Release is the detach, recorded; the terminal keeps running.
    assert_eq!(fx.call(o, "DELETE", &uri, None).await.0, 204);
    assert_eq!(fx.count("SELECT count(*) FROM audit_events WHERE action='terminal.detached' AND details LIKE '%\"local\":true%'").await, 1);
    let (_, t) = fx
        .call(o, "GET", &format!("/api/v1/terminals/{id}"), None)
        .await;
    assert_eq!(
        (t["attached"].as_u64(), t["status"].as_str()),
        (Some(0), Some("running")),
        "{t}"
    );
    // The shell still answers on the Core's own path (same terminal, same host).
    let mut c = fx.ws(o, &id).await;
    c.type_line("after").await;
    c.read_until("got:after").await;
    let _ = fx
        .call(o, "DELETE", &format!("/api/v1/terminals/{id}"), None)
        .await;
}

#[tokio::test]
async fn a_grant_is_refused_for_a_missing_terminal_and_an_ended_one() {
    let fx = Fx::new("t-local-gone").await;
    let o = &fx.owner;
    let (s, _) = fx
        .call(o, "POST", "/api/v1/terminals/t_nope/local", None)
        .await;
    assert_eq!(s, 404);
    let id = fx.sh(o).await;
    let (s, _) = fx
        .call(o, "DELETE", &format!("/api/v1/terminals/{id}"), None)
        .await;
    assert_eq!(s, 200);
    let (s, _) = fx
        .call(o, "POST", &format!("/api/v1/terminals/{id}/local"), None)
        .await;
    assert!(s == 404 || s == 409, "{s}");
}
