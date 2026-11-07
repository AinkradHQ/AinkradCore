//! The socket with a hand-played Core (`Tools::poll`) and a client that speaks raw lines, as the
//! agent could, shim or not.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ConnTool, ToolResult, ToolsPoll};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::*;

const SHORT: Duration = Duration::from_millis(300);

fn dir(tag: &str) -> PathBuf {
    // Short and under /tmp: a unix socket path is at most 100 bytes (macOS temp dirs are longer).
    let d = PathBuf::from(format!("/tmp/ct-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tool(name: &str) -> ConnTool {
    ConnTool {
        name: name.to_owned(),
        description: "d".to_owned(),
        write: false,
        input_schema: Some(
            json!({"type": "object", "properties": {"repo": {"type": "string"}},
            "required": ["repo"], "additionalProperties": false}),
        ),
    }
}

fn poll(
    session: &str,
    after: u64,
    results: Vec<ToolResult>,
    tools: Option<Vec<ConnTool>>,
) -> ToolsPoll {
    ToolsPoll {
        session: session.to_owned(),
        after,
        wait_ms: Some(100),
        results,
        tools,
    }
}

/// The Core tells `session` its tools.
async fn list(t: &Tools, session: &str, names: &[&str]) {
    let tools = names.iter().map(|n| tool(n)).collect();
    t.poll(&poll(session, 0, vec![], Some(tools)), SHORT).await;
}

struct Client {
    r: BufReader<tokio::net::unix::OwnedReadHalf>,
    w: tokio::net::unix::OwnedWriteHalf,
}

impl Client {
    async fn open(sock: &Path) -> Client {
        let (r, w) = UnixStream::connect(sock).await.unwrap().into_split();
        Client {
            r: BufReader::new(r),
            w,
        }
    }

    async fn send(&mut self, raw: &[u8]) {
        let _ = self.w.write_all(raw).await;
        let _ = self.w.write_all(b"\n").await;
    }

    /// The next line, `None` when the server closed.
    async fn next(&mut self) -> Option<Value> {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), self.r.read_line(&mut line))
            .await
            .expect("no answer");
        match n {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(serde_json::from_str(&line).unwrap()),
        }
    }

    async fn ask(&mut self, body: Value) -> Value {
        self.send(body.to_string().as_bytes()).await;
        self.next().await.expect("the connection closed")
    }
}

fn rig(tag: &str, session: &str) -> (Arc<Tools>, Front, PathBuf) {
    let t = Arc::new(Tools::default());
    let sock = socket_in(&dir(tag));
    let front = start(&sock, t.clone(), session).unwrap();
    (t, front, sock)
}

fn call(id: u64, name: &str, extra: Value) -> Value {
    let mut params = json!({"name": name, "arguments": {"repo": "o/r"}});
    if let (Some(p), Some(e)) = (params.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

#[tokio::test]
async fn the_session_is_the_socket_never_the_body() {
    let t = Arc::new(Tools::default());
    let (da, db) = (dir("id-a"), dir("id-b"));
    let (sa, sb) = (socket_in(&da), socket_in(&db));
    let _fa = start(&sa, t.clone(), "as_a").unwrap();
    let _fb = start(&sb, t.clone(), "as_b").unwrap();
    list(&t, "as_a", &["github.get_issue"]).await;
    list(&t, "as_b", &["jira.get_issue"]).await;
    let mut a = Client::open(&sa).await;
    // Every place a body could name a session: top level, params, arguments, _meta.
    let forged = json!({"session": "as_b", "sessionId": "as_b", "_meta": {"session": "as_b"}});
    let listed = a
        .ask(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "session": "as_b",
            "params": forged}),
        )
        .await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["github_get_issue"], "A's socket lists A's tools");
    // B's tool is not callable through A's socket, whatever the body says.
    let r = a.ask(call(2, "jira_get_issue", forged.clone())).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown_tool")
    );
    // A's own tool, with a body claiming B: the call is A's.
    let caller = {
        let mut a = Client::open(&sa).await;
        tokio::spawn(async move { a.ask(call(3, "github_get_issue", forged)).await })
    };
    let for_b = t
        .poll(&poll("as_b", 0, vec![], None), Duration::from_millis(150))
        .await;
    assert!(for_b.calls.is_empty(), "the forged session got a call");
    let for_a = t
        .poll(&poll("as_a", 0, vec![], None), Duration::from_secs(2))
        .await;
    assert_eq!(for_a.calls[0].tool, "github.get_issue");
    let id = for_a.calls[0].id.clone();
    let answer = ToolResult {
        id,
        ok: true,
        result: Some(json!({"title": "x"})),
        code: None,
        message: None,
    };
    t.poll(
        &poll("as_a", 1, vec![answer], None),
        Duration::from_millis(50),
    )
    .await;
    assert_eq!(caller.await.unwrap()["result"]["isError"], false);
}

#[tokio::test]
async fn an_unknown_session_is_refused_and_no_state_is_made() {
    let (t, _front, sock) = rig("unknown", "as_nobody");
    let mut c = Client::open(&sock).await;
    let l = c
        .ask(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .await;
    assert_eq!(l["result"]["tools"], json!([]));
    let r = c.ask(call(2, "github_get_issue", json!({}))).await;
    assert_eq!(r["result"]["isError"], true);
    c.ask(json!({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}}))
        .await;
    assert!(
        !t.holds("as_nobody"),
        "a request made state for a session the Core never listed"
    );
}

#[tokio::test]
async fn bad_input_is_answered_or_dropped_and_never_breaks_the_connection() {
    let (t, _front, sock) = rig("bad", "as_a");
    list(&t, "as_a", &["github.get_issue"]).await;
    let mut c = Client::open(&sock).await;
    c.send(b"not json").await;
    assert_eq!(c.next().await.unwrap()["error"]["code"], -32700);
    // Invalid UTF-8 inside a string.
    c.send(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"x\":\"\xff\xfe\"}")
        .await;
    assert_eq!(c.next().await.unwrap()["error"]["code"], -32700);
    // Nesting far past the parser's own limit is a parse error, not a crash.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    c.send(deep.as_bytes()).await;
    assert_eq!(c.next().await.unwrap()["error"]["code"], -32700);
    // A batch is refused whole.
    c.send(
        br#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]"#,
    )
    .await;
    assert_eq!(c.next().await.unwrap()["error"]["code"], -32600);
    // A notification and a blank line are not answered: the next answer is the ping's.
    c.send(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;
    c.send(b"   ").await;
    c.send(br#"{"jsonrpc":"2.0","id":7,"result":{}}"#).await; // a reply to nothing we asked
    let p = c
        .ask(json!({"jsonrpc": "2.0", "id": 8, "method": "ping"}))
        .await;
    assert_eq!(p["id"], 8);
    // Arguments that are not an object, an unknown method.
    let r = c
        .ask(json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "github_get_issue", "arguments": [1]}}))
        .await;
    assert_eq!(r["error"]["code"], -32602);
    assert_eq!(
        c.ask(json!({"jsonrpc": "2.0", "id": 10, "method": "nope"}))
            .await["error"]["code"],
        -32601
    );
}

#[tokio::test]
async fn an_oversized_request_gets_one_error_and_the_connection_closes() {
    let (_t, _front, sock) = rig("big", "as_a");
    let mut c = Client::open(&sock).await;
    let huge = vec![b'a'; MAX_REQUEST + 1024];
    c.send(&huge).await;
    // The unread rest of the line may turn the close into a reset that eats the reply.
    let first = c.next().await;
    assert!(first.is_none_or(|e| e["error"]["code"] == -32600));
    assert!(
        c.next().await.is_none(),
        "the connection stays open after an unbounded line"
    );
    // The server is still serving others, and a line right at the cap is read (and refused as
    // JSON, not as too large).
    let mut d = Client::open(&sock).await;
    let at_cap = vec![b' '; MAX_REQUEST - 1];
    let mut line = at_cap;
    line.insert(0, b'x');
    d.send(&line).await;
    assert_eq!(d.next().await.unwrap()["error"]["code"], -32700);
}

#[tokio::test]
async fn requests_at_once_are_capped_per_connection() {
    let (t, _front, sock) = rig("conc", "as_a");
    list(&t, "as_a", &["github.get_issue"]).await;
    let mut c = Client::open(&sock).await;
    // The Core never answers: PER_CONN calls wait; the next one is refused at once, by id.
    for i in 0..PER_CONN as u64 {
        c.send(
            call(100 + i, "github_get_issue", json!({}))
                .to_string()
                .as_bytes(),
        )
        .await;
    }
    c.send(
        call(999, "github_get_issue", json!({}))
            .to_string()
            .as_bytes(),
    )
    .await;
    let busy = c.next().await.unwrap();
    assert_eq!(busy["id"], 999);
    assert_eq!(busy["error"]["code"], -32001);
    // A notification over the cap is dropped without a word; another connection is unaffected.
    let mut other = Client::open(&sock).await;
    let p = other
        .ask(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await;
    assert_eq!(p["id"], 1);
}

#[tokio::test]
async fn connections_are_capped_per_session() {
    let (_t, _front, sock) = rig("conns", "as_a");
    let mut held = Vec::new();
    for _ in 0..PER_SESSION {
        let mut c = Client::open(&sock).await;
        c.ask(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
            .await;
        held.push(c);
    }
    let mut extra = UnixStream::connect(&sock).await.unwrap();
    let mut buf = [0; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf))
        .await
        .expect("the extra connection hung");
    assert!(matches!(n, Ok(0)), "over the limit: {n:?}");
    // One goes away: a new one is served again (polled, bounded: the slot frees with its task).
    drop(held.pop());
    let mut served = false;
    for _ in 0..50 {
        let mut c = Client::open(&sock).await;
        c.send(br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#).await;
        if c.next().await.is_some() {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(served);
}

#[tokio::test]
async fn ending_the_session_removes_the_socket_and_closes_every_connection() {
    let (_t, front, sock) = rig("end", "as_a");
    let mut c = Client::open(&sock).await;
    c.ask(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await;
    assert!(sock.exists());
    // A stale socket from a crashed runner is replaced by the next start.
    drop(front);
    assert!(!sock.exists(), "the socket outlived the session");
    assert!(
        c.next().await.is_none(),
        "a connection outlived the session"
    );
    assert!(UnixStream::connect(&sock).await.is_err());
    std::fs::write(&sock, b"stale").unwrap();
    let _again = start(&sock, Arc::new(Tools::default()), "as_a").unwrap();
    assert!(UnixStream::connect(&sock).await.is_ok());
}

#[tokio::test]
async fn the_socket_is_private_and_a_long_path_is_refused() {
    let (_t, _front, sock) = rig("mode", "as_a");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&sock), 0o600);
    let long = PathBuf::from(format!("/tmp/{}/tools.sock", "a".repeat(100)));
    assert!(start(&long, Arc::new(Tools::default()), "as_a").is_err());
}

#[tokio::test]
async fn a_changed_list_is_announced_and_the_same_list_is_not() {
    let (t, _front, sock) = rig("note", "as_a");
    let mut c = Client::open(&sock).await;
    c.ask(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        .await;
    list(&t, "as_a", &["github.get_issue"]).await;
    let n = c.next().await.unwrap();
    assert_eq!(n["method"], "notifications/tools/list_changed");
    // The same list again, and another session's: nothing is sent; the next line is the ping's.
    list(&t, "as_a", &["github.get_issue"]).await;
    list(&t, "as_z", &["jira.get_issue"]).await;
    let p = c
        .ask(json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}))
        .await;
    assert_eq!(p["id"], 2);
    // And the list a harness then asks for is the live one, schema included.
    let l = c
        .ask(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
        .await;
    assert_eq!(
        l["result"]["tools"][0]["inputSchema"]["additionalProperties"],
        false
    );
    list(&t, "as_a", &[]).await;
    assert_eq!(
        c.next().await.unwrap()["method"],
        "notifications/tools/list_changed"
    );
    let l = c
        .ask(json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}))
        .await;
    assert_eq!(l["result"]["tools"], json!([]));
}

#[tokio::test]
async fn the_whole_flow_runs_and_a_result_over_the_cap_is_a_plain_refusal() {
    let (t, _front, sock) = rig("flow", "as_a");
    list(&t, "as_a", &["github.get_issue"]).await;
    let mut c = Client::open(&sock).await;
    let mut seen = String::new();
    let init = c
        .ask(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26"}}))
        .await;
    seen += &init.to_string();
    assert_eq!(init["result"]["capabilities"]["tools"]["listChanged"], true);
    for (n, result) in [
        (1u64, json!({"title": "t"})),
        (
            2,
            json!("x".repeat(ainkrad_proto::v2::MAX_RESULT_BYTES + 10)),
        ),
    ] {
        c.send(
            call(10 + n, "github_get_issue", json!({}))
                .to_string()
                .as_bytes(),
        )
        .await;
        let batch = t
            .poll(&poll("as_a", n - 1, vec![], None), Duration::from_secs(2))
            .await;
        assert_eq!(batch.calls[0].tc_seq, n);
        assert_eq!(batch.calls[0].args, json!({"repo": "o/r"}));
        let answer = ToolResult {
            id: batch.calls[0].id.clone(),
            ok: true,
            result: Some(result),
            code: None,
            message: None,
        };
        t.poll(
            &poll("as_a", n, vec![answer], None),
            Duration::from_millis(50),
        )
        .await;
        let r = c.next().await.unwrap();
        seen += &r.to_string();
        if n == 1 {
            assert_eq!(r["result"]["isError"], false);
        } else {
            assert_eq!(r["result"]["isError"], true);
            assert!(
                r["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("too_large")
            );
        }
    }
    // Nothing on the wire but plain data: no auth header, no token shape.
    for needle in ["Authorization", "Bearer", "ghp_", "cit_run"] {
        assert!(!seen.contains(needle), "{needle} on the socket");
    }
}
