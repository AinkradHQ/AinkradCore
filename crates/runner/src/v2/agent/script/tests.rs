use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::child::{Request, execute};
use super::client::{Client, Refusal};
use super::engine::{self, Run};
use super::shim::{reply_text, run_script_with};
use super::{Limits, cap, cli};

static N: AtomicU32 = AtomicU32::new(0);

/// A fake Core: a unix socket that answers each `tools/call` line with `answer(name, arguments)`,
/// `Ok(body)` as a result and `Err((code, message))` as the relay's refusal. Runs for the process.
fn fake_core(
    answer: impl Fn(&str, &Value) -> Result<Value, (&'static str, &'static str)> + Send + 'static,
) -> String {
    let path = format!(
        "/tmp/ainkrad-e3-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut w = stream.try_clone().unwrap();
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let req: Value = serde_json::from_str(&line).unwrap();
                // A notification first, as the relay sends one when the list changes.
                let _ = writeln!(
                    w,
                    r#"{{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}}"#
                );
                let p = &req["params"];
                let (ok, body) = match answer(p["name"].as_str().unwrap(), &p["arguments"]) {
                    Ok(v) => (true, v),
                    Err((code, message)) => (false, json!({"code": code, "message": message})),
                };
                let r = json!({"jsonrpc": "2.0", "id": req["id"], "result": {
                    "content": [{"type": "text", "text": body.to_string()}], "isError": !ok}});
                let _ = writeln!(w, "{r}");
            }
        }
    });
    path
}

fn lim() -> Limits {
    Limits {
        memory: 16 << 20,
        stack: 256 << 10,
        time_ms: 500,
        deadline_ms: 5_000,
        calls: 5,
    }
}

fn go(code: &str) -> Run {
    engine::run(code, &lim(), |n, a, _| Ok(json!({"op": n, "args": a})))
}

fn value(code: &str) -> String {
    go(code)
        .result
        .unwrap_or_else(|e| format!("ERR {}", e.message))
}

#[test]
fn values_and_operation_calls() {
    assert_eq!(value("return 1+1"), "2");
    assert_eq!(value("1+1"), "null", "no return is null");
    assert_eq!(
        value("return ainkrad.agents.listAgentSessions({n: 3})"),
        r#"{"args":{"n":3},"op":"listAgentSessions"}"#
    );
    assert_eq!(
        value("return ainkrad.health.getCoreHealth()"),
        r#"{"args":{},"op":"getCoreHealth"}"#
    );
    assert_eq!(go("ainkrad.a.b({}); ainkrad.a.c({})").calls, 2);
}

#[test]
fn a_runaway_loop_is_stopped_at_the_time_cap() {
    let t = Instant::now();
    let r = go("while(true){}");
    assert_eq!(
        r.result.unwrap_err().message,
        "the script ran past its time limit"
    );
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[test]
fn memory_recursion_and_huge_strings_end_with_plain_errors() {
    for c in [
        "let a=[]; for(;;) a.push(new Array(100000).fill(1));",
        "return 'x'.repeat(1<<28).length",
        "function f(){return f()+1} return f()",
        "let s='x'; for(;;) s+=s;",
    ] {
        assert!(go(c).result.is_err(), "{c}");
    }
}

#[test]
fn no_ambient_authority() {
    for c in [
        "typeof require",
        "typeof process",
        "typeof fetch",
        "typeof std",
        "typeof os",
        "typeof setTimeout",
        "typeof setInterval",
        "typeof XMLHttpRequest",
        "typeof __op",
        "typeof __log",
        "typeof WebAssembly",
        "typeof module",
        "typeof Deno",
    ] {
        assert_eq!(value(&format!("return {c}")), "\"undefined\"", "{c}");
    }
    // No module loader: a dynamic import never loads anything, and (the `Promise` intrinsic) does
    // not abort the process; the script goes on.
    assert_eq!(value("import('os'); return 1"), "1");
    assert!(go("return import.meta").result.is_err());
    assert!(go("require('fs')").result.is_err());
    assert!(go("fetch('http://x')").result.is_err());
    assert!(go("process.exit(1)").result.is_err());
    // `ainkrad` cannot be changed.
    let e = go("ainkrad.x = 1").result.unwrap_err();
    assert!(e.message.contains("read-only"), "{}", e.message);
    assert!(go("delete ainkrad.a").result.is_err());
    assert_eq!(value("return Object.keys(ainkrad).length"), "0");
}

#[test]
fn console_is_captured_and_bounded() {
    let r = go("console.log('a', 1, {x: 2}); return 1");
    assert_eq!(r.logs, vec![r#"a 1 {"x":2}"#]);
    let r = go("for (let i = 0; i < 5000; i++) console.log('line ' + i);");
    assert!(r.logs.iter().map(String::len).sum::<usize>() < 2 * super::MAX_CONSOLE);
    assert_eq!(r.logs.last().unwrap(), "[console output truncated]");
}

#[test]
fn errors_carry_a_line_and_a_refusal_is_a_catchable_error() {
    let e = go("let a = 1;\nlet b = 2;\nnull.x;").result.unwrap_err();
    assert_eq!(e.line, Some(3), "{e:?}");
    let e = go("let a = ;").result.unwrap_err();
    assert!(e.line.is_some(), "{e:?}");
    let r = engine::run(
        "try { ainkrad.g.op({}) } catch (e) { return [e.code, e.message] }",
        &lim(),
        |_, _, _| Err(Refusal::new("not_granted", "no")),
    );
    assert_eq!(r.result.unwrap(), r#"["not_granted","no"]"#);
    let e = engine::run("ainkrad.g.op({})", &lim(), |_, _, _| {
        Err(Refusal::new("rate_limited", "slow"))
    })
    .result
    .unwrap_err();
    assert_eq!(e.code.as_deref(), Some("rate_limited"));
}

#[test]
fn the_call_budget_and_argument_size_are_enforced_before_the_host() {
    let r = engine::run(
        "const out = []; for (let i = 0; i < 9; i++) { try { ainkrad.g.op({i}) } catch (e) { out.push(e.code) } } return out",
        &lim(),
        |_, _, _| Ok(json!(1)),
    );
    assert_eq!(
        r.result.unwrap(),
        r#"["too_many_calls","too_many_calls","too_many_calls","too_many_calls"]"#
    );
    let host_calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let h = host_calls.clone();
    let big = format!(
        "try {{ ainkrad.g.op({{s: 'x'.repeat({})}}) }} catch (e) {{ return e.code }}",
        super::MAX_CALL_ARGS + 1
    );
    let r = engine::run(&big, &lim(), move |_, _, _| {
        h.set(h.get() + 1);
        Ok(json!(1))
    });
    assert_eq!(r.result.unwrap(), "\"args_too_large\"");
    assert_eq!(host_calls.get(), 0);
    // Arguments are an object.
    assert_eq!(
        value("try { ainkrad.g.op(5) } catch (e) { return e.code }"),
        "\"bad_args\""
    );
}

#[test]
fn only_the_final_value_comes_back_bounded() {
    let core = fake_core(|_, _| Ok(json!({"big": "y".repeat(100_000)})));
    let req = Request {
        code: "const r = ainkrad.g.op({}); return r.big".to_owned(),
        run: "r1".to_owned(),
        limits: Limits::default(),
    };
    let e = execute(&core, &req);
    assert!(e.ok && e.calls == 1);
    let v = e.value.unwrap();
    assert!(
        v.len() < super::MAX_VALUE + 100 && v.contains("[truncated:"),
        "{}",
        v.len()
    );
    let (ok, text) = reply_text(&Envelope_ok(&v));
    assert!(ok && text.ends_with("ms]"));
}

#[allow(non_snake_case)]
fn Envelope_ok(v: &str) -> super::child::Envelope {
    super::child::Envelope {
        ok: true,
        value: Some(v.to_owned()),
        error: None,
        logs: vec!["hi".into()],
        calls: 2,
        ms: 7,
        approvals: vec![],
    }
}

#[test]
fn a_script_calls_the_core_through_the_socket_and_sees_refusals() {
    let core = fake_core(|name, a| {
        assert_eq!(name, "ainkrad_call");
        assert_eq!(a["run"], "r2");
        match a["op"].as_str().unwrap() {
            "listAgentSessions" => Ok(json!({"items": [{"id": "as_1"}, {"id": "as_2"}]})),
            _ => Err(("not_granted", "this session may not")),
        }
    });
    let req = Request {
        code: "const l = ainkrad.agents.listAgentSessions({}); \
               let d; try { ainkrad.agents.dropAll({}) } catch (e) { d = e.code } \
               return {n: l.items.length, d}"
            .to_owned(),
        run: "r2".to_owned(),
        limits: Limits::default(),
    };
    let e = execute(&core, &req);
    assert_eq!(e.value.as_deref(), Some(r#"{"n":2,"d":"not_granted"}"#));
    assert_eq!(e.calls, 2);
    // No socket: the script gets `unavailable`, the process is fine.
    let e = execute("/tmp/ainkrad-e3-nothing.sock", &req);
    assert!(!e.ok);
    assert_eq!(e.error.unwrap().code.as_deref(), Some("unavailable"));
}

#[test]
fn the_client_returns_refusals_as_data_and_keeps_the_relays_limits() {
    let core = fake_core(|_, a| {
        if a["wait"].is_null() {
            Ok(json!("ok"))
        } else {
            Err(("rate_limited", "slow"))
        }
    });
    let mut c = Client::connect(&core).unwrap();
    let w = Duration::from_secs(2);
    assert_eq!(c.call("ainkrad_call", &json!({}), w).unwrap(), json!("ok"));
    assert_eq!(
        c.call("ainkrad_call", &json!({"wait": 1}), w).unwrap_err(),
        Refusal::new("rate_limited", "slow")
    );
    let big = json!({"s": "x".repeat(ainkrad_proto::v2::MAX_ARGS_BYTES)});
    assert_eq!(
        c.call("ainkrad_call", &big, w).unwrap_err().code,
        "args_too_large"
    );
    assert_eq!(
        c.call("ainkrad_call", &json!({}), w).unwrap(),
        json!("ok"),
        "still usable"
    );
}

#[test]
fn a_silent_core_is_a_timeout_not_a_hang() {
    let path = format!("/tmp/ainkrad-e3-silent-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        let _held: Vec<_> = l.incoming().flatten().collect();
        std::thread::sleep(Duration::from_secs(5));
    });
    let mut c = Client::connect(&path).unwrap();
    let t = Instant::now();
    assert_eq!(
        c.call("ainkrad_call", &json!({}), Duration::from_millis(200))
            .unwrap_err()
            .code,
        "timeout"
    );
    assert!(t.elapsed() < Duration::from_secs(2));
}

fn run_cli(core: Option<&str>, args: &[&str], stdin: &str) -> (u8, String, String) {
    cli::exec(args, core, &mut stdin.as_bytes())
}

#[test]
fn the_cli_speaks_json_and_exits_by_refusal_class() {
    let core = fake_core(|name, a| match (name, a["op"].as_str()) {
        ("ainkrad_search", _) => Ok(json!({"definitions": [a["query"]]})),
        ("ainkrad_schema", _) => Ok(json!({"op": a["op"]})),
        (_, Some("listAgentSessions")) => Ok(json!({"args": a["args"], "key": a["key"]})),
        (_, Some("approve")) => Err(("approval_denied", "no")),
        (_, Some("flood")) => Err(("rate_limited", "slow")),
        _ => Err(("not_granted", "no")),
    });
    let c = Some(core.as_str());
    let (code, out, _) = run_cli(c, &["search", "list", "sessions"], "");
    assert_eq!(
        (code, out.trim()),
        (0, r#"{"definitions":["list sessions"]}"#)
    );
    let (_, out, _) = run_cli(c, &["schema", "listAgentSessions"], "");
    assert_eq!(out.trim(), r#"{"op":"listAgentSessions"}"#);
    let (_, out, _) = run_cli(
        c,
        &[
            "agents",
            "listAgentSessions",
            "--json",
            r#"{"limit":2}"#,
            "--key",
            "k1",
        ],
        "",
    );
    assert_eq!(out.trim(), r#"{"args":{"limit":2},"key":"k1"}"#);
    let (_, out, _) = run_cli(
        c,
        &["agents", "listAgentSessions", "--json", "-"],
        r#"{"limit":3}"#,
    );
    assert_eq!(out.trim(), r#"{"args":{"limit":3},"key":null}"#);
    let (code, _, err) = run_cli(c, &["agents", "nope"], "");
    assert_eq!(code, 2);
    assert_eq!(
        serde_json::from_str::<Value>(&err).unwrap()["error"]["code"],
        "not_granted"
    );
    assert_eq!(run_cli(c, &["x", "approve"], "").0, 3);
    assert_eq!(run_cli(c, &["x", "flood"], "").0, 4);
    assert_eq!(
        run_cli(c, &["x", "y", "--json", "[1]"], "").0,
        2,
        "bad args are refused"
    );
    assert_eq!(
        run_cli(None, &["agents", "listAgentSessions"], "").0,
        1,
        "no socket in the environment"
    );
    assert_eq!(run_cli(c, &[], "").0, 1);
}

fn fake_engine(body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = std::path::PathBuf::from(format!(
        "/tmp/ainkrad-e3-engine-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[tokio::test]
async fn a_crashing_or_hanging_engine_child_is_an_error_not_a_dead_shim() {
    let crash = fake_engine("kill -ABRT $$");
    let (ok, text) = run_script_with(
        &crash,
        "/nope",
        "return 1",
        Limits::default(),
        Duration::from_secs(1),
    )
    .await;
    assert!(
        !ok && text.contains("stopped unexpectedly") && text.contains("session is fine"),
        "{text}"
    );
    let garbage = fake_engine("echo not json");
    let (ok, _) = run_script_with(
        &garbage,
        "/nope",
        "return 1",
        Limits::default(),
        Duration::from_secs(1),
    )
    .await;
    assert!(!ok);
    let hang = fake_engine("sleep 30");
    let limits = Limits {
        deadline_ms: 100,
        ..Limits::default()
    };
    let t = Instant::now();
    let (ok, text) = run_script_with(
        &hang,
        "/nope",
        "return 1",
        limits,
        Duration::from_millis(200),
    )
    .await;
    assert!(!ok && text.contains("did not finish"), "{text}");
    assert!(t.elapsed() < Duration::from_secs(5));
    let (ok, text) = run_script_with(
        &crash,
        "/nope",
        &"x".repeat(super::MAX_CODE + 1),
        Limits::default(),
        Duration::from_secs(1),
    )
    .await;
    assert!(!ok && text.contains("bytes"));
}

#[test]
fn replies_say_value_console_cost_and_errors_carry_line_and_code() {
    let (ok, t) = reply_text(&Envelope_ok("{\"a\":1}"));
    assert!(ok);
    assert_eq!(t, "{\"a\":1}\nconsole:\nhi\n[2 calls, 7 ms]");
    let mut e = Envelope_ok("");
    e.ok = false;
    e.error = Some(engine::ScriptError {
        message: "boom".into(),
        line: Some(4),
        code: Some("not_granted".into()),
    });
    let (ok, t) = reply_text(&e);
    assert!(
        !ok && t.starts_with("error: boom (line 4) [not_granted]"),
        "{t}"
    );
    assert_eq!(cap("abc", 10), "abc");
    assert!(cap("abcdef", 3).starts_with("abc... [truncated: 3 of 6"));
    assert!(cap("ééé", 3).starts_with('é'), "never cuts a character");
}

#[test]
fn waiting_on_an_operation_is_not_script_time_but_the_deadline_holds() {
    let slow = |_: &str, _: Value, _: Value| {
        std::thread::sleep(Duration::from_millis(700));
        Ok(json!(1))
    };
    // 700 ms in the host, a 500 ms running-time cap: the wait is not the script's time.
    let r = engine::run("ainkrad.g.op({}); return 2", &lim(), slow);
    assert_eq!(r.result.unwrap(), "2");
    // The wall deadline counts everything: past it, the next instruction stops the script.
    let tight = Limits {
        deadline_ms: 600,
        ..lim()
    };
    let r = engine::run("ainkrad.g.op({}); while (true) {}", &tight, slow);
    assert!(r.result.unwrap_err().message.contains("time limit"));
}

#[test]
fn a_denial_is_a_typed_catchable_error_and_options_pass_through() {
    let r = engine::run(
        "try { ainkrad.g.op({}) } catch (e) { return [e instanceof ainkrad.ApprovalError, e.name, e.code] }",
        &lim(),
        |_, _, _| Err(Refusal::new("approval_denied", "a person denied this")),
    );
    assert_eq!(
        r.result.unwrap(),
        r#"[true,"ApprovalError","approval_denied"]"#
    );
    let r = engine::run(
        "try { ainkrad.g.op({}) } catch (e) { return e instanceof ainkrad.ApprovalError }",
        &lim(),
        |_, _, _| Err(Refusal::new("not_granted", "no")),
    );
    assert_eq!(r.result.unwrap(), "false");
    let r = engine::run(
        "return ainkrad.g.op({}, {key: 'k1', repeat: true})",
        &lim(),
        |_, _, o| Ok(o),
    );
    assert_eq!(r.result.unwrap(), r#"{"key":"k1","repeat":true}"#);
    for bad in ["{key: 5}", "{repeat: 'yes'}", "{other: 1}", "5"] {
        let r = engine::run(
            &format!("try {{ ainkrad.g.op({{}}, {bad}) }} catch (e) {{ return e.code }}"),
            &lim(),
            |_, _, _| Ok(json!(1)),
        );
        assert_eq!(r.result.unwrap(), "\"bad_args\"", "{bad}");
    }
}

#[test]
fn a_script_call_tells_the_core_its_time_left_and_its_options() {
    let core = fake_core(|_, a| {
        let w = a["wait_ms"].as_u64().unwrap();
        assert!(w > 1_000 && w < 5_000, "{w}");
        assert_eq!((&a["key"], &a["repeat"]), (&json!("k"), &json!(true)));
        Ok(json!("done"))
    });
    let req = Request {
        code: "return ainkrad.g.op({}, {key: 'k', repeat: true})".to_owned(),
        run: "r3".to_owned(),
        limits: Limits {
            deadline_ms: 5_000,
            ..Limits::default()
        },
    };
    let e = execute(&core, &req);
    assert_eq!(e.value.as_deref(), Some("\"done\""), "{:?}", e.error);
    assert!(e.approvals.is_empty());
}

#[test]
fn replies_list_the_calls_that_waited_for_a_person() {
    let mut e = Envelope_ok("1");
    e.approvals = vec![
        super::child::Approval {
            op: "closeIssue".into(),
            request: "cm_1".into(),
            outcome: "approved".into(),
        },
        super::child::Approval {
            op: "deleteNote".into(),
            request: "cm_2".into(),
            outcome: "denied".into(),
        },
    ];
    let (_, t) = reply_text(&e);
    assert!(
        t.contains("approvals: closeIssue approved (cm_1); deleteNote denied (cm_2)"),
        "{t}"
    );
}
