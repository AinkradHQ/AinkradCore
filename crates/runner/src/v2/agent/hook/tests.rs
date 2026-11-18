use std::io::{BufRead, BufReader, Cursor, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;

static N: AtomicU32 = AtomicU32::new(0);

/// How the fake Core answers a call.
enum Reply {
    Body(Value),
    Refuse,
    Silent,
}

/// A fake session socket: records each `tools/call`'s params and answers as told. Runs for the process.
fn fake_core(reply: Reply) -> (String, Arc<Mutex<Vec<Value>>>) {
    let path = format!(
        "/tmp/ainkrad-b803-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut w = stream.try_clone().unwrap();
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let req: Value = serde_json::from_str(&line).unwrap();
                log.lock().unwrap().push(req["params"].clone());
                let (ok, body) = match &reply {
                    Reply::Silent => {
                        std::thread::sleep(Duration::from_secs(5));
                        continue;
                    }
                    Reply::Body(b) => (true, b.clone()),
                    Reply::Refuse => (false, json!({"code": "forbidden", "message": "no"})),
                };
                let answer = json!({"jsonrpc": "2.0", "id": req["id"], "result": {
                    "content": [{"type": "text", "text": body.to_string()}], "isError": !ok}});
                let _ = writeln!(w, "{answer}");
            }
        }
    });
    (path, seen)
}

fn hook(kind: Kind, sock: &str, stdin: &str, wait: Duration) -> String {
    run(kind, sock, Cursor::new(stdin.to_owned()), wait)
}

const PROMPT: &str =
    r#"{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"how do I deploy?"}"#;
const WAIT: Duration = Duration::from_millis(1500);

#[test]
fn a_bundle_is_one_json_object_with_additional_context() {
    let bundle = "<<outside data>>\n[rec_1] deploys go through make ship\n<</outside data>>";
    let (sock, seen) = fake_core(Reply::Body(json!({"text": bundle, "ids": ["rec_1"]})));
    let out = hook(Kind::Prompt, &sock, PROMPT, WAIT);
    let v: Value = serde_json::from_str(&out).expect("one JSON object");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit");
    assert_eq!(v["hookSpecificOutput"]["additionalContext"], bundle);
    assert_eq!(v.as_object().unwrap().len(), 1);
    let call = seen.lock().unwrap()[0].clone();
    assert_eq!(call["name"], "ainkrad_call");
    assert_eq!(call["arguments"]["op"], "brainAiContext");
    assert_eq!(call["arguments"]["args"]["mode"], "prompt");
    assert_eq!(call["arguments"]["args"]["prompt"], "how do I deploy?");
    // No session or credential is named: the socket is the session.
    assert!(!call.to_string().contains("session"));
}

#[test]
fn an_empty_bundle_prints_nothing() {
    let (sock, _) = fake_core(Reply::Body(json!({"text": "", "ids": []})));
    assert_eq!(hook(Kind::Prompt, &sock, PROMPT, WAIT), "");
}

#[test]
fn a_bundle_over_the_limit_is_dropped_whole() {
    let (sock, _) = fake_core(Reply::Body(
        json!({"text": "x".repeat(MAX_CONTEXT_CHARS + 1)}),
    ));
    assert_eq!(hook(Kind::Prompt, &sock, PROMPT, WAIT), "");
}

#[test]
fn it_fails_open_on_a_refusal_a_missing_socket_and_bad_input() {
    let (sock, _) = fake_core(Reply::Refuse);
    assert_eq!(hook(Kind::Prompt, &sock, PROMPT, WAIT), "");
    assert_eq!(
        hook(Kind::Prompt, "/nonexistent/tools.sock", PROMPT, WAIT),
        ""
    );
    let (sock, seen) = fake_core(Reply::Body(json!({"text": "t"})));
    for bad in [
        "",
        "not json",
        r#"{"prompt":""}"#,
        r#"{"prompt":"  "}"#,
        "{}",
    ] {
        assert_eq!(hook(Kind::Prompt, &sock, bad, WAIT), "", "{bad}");
    }
    assert!(seen.lock().unwrap().is_empty(), "nothing to ask: no call");
}

#[test]
fn it_fails_open_when_the_core_does_not_answer_in_time() {
    let (sock, _) = fake_core(Reply::Silent);
    let started = std::time::Instant::now();
    assert_eq!(
        hook(Kind::Prompt, &sock, PROMPT, Duration::from_millis(200)),
        ""
    );
    assert!(started.elapsed() < Duration::from_millis(900));
}

#[test]
fn a_checkpoint_asks_the_core_and_prints_nothing() {
    let (sock, seen) = fake_core(Reply::Body(json!({"requested": true})));
    assert_eq!(
        hook(Kind::Checkpoint, &sock, r#"{"reason":"other"}"#, WAIT),
        ""
    );
    let call = seen.lock().unwrap()[0].clone();
    assert_eq!(call["arguments"]["op"], "brainAiCheckpoint");
    // Even a refusal or a dead socket prints nothing.
    let (sock, _) = fake_core(Reply::Refuse);
    assert_eq!(hook(Kind::Checkpoint, &sock, "", WAIT), "");
    assert_eq!(
        hook(Kind::Checkpoint, "/nonexistent/tools.sock", "", WAIT),
        ""
    );
}

#[test]
fn only_the_two_kinds_exist() {
    assert_eq!(Kind::parse("prompt"), Some(Kind::Prompt));
    assert_eq!(Kind::parse("checkpoint"), Some(Kind::Checkpoint));
    assert_eq!(Kind::parse("stop"), None);
}
