//! Code Mode end to end (E3): the real `ainkrad-runner` shim (`mcp-stdio`) in front of a real
//! tools socket with a fake Core behind it; the `ainkrad` CLI as the harness's shell would run it
//! (a link named `ainkrad`); and the script child under an OS sandbox with nothing allowed
//! (Seatbelt `(deny default)` on macOS, bubblewrap on Linux). Build with `--features quickjs`.
#![cfg(all(feature = "quickjs", unix))]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ConnTool, ToolResult, ToolsPoll};
use ainkrad_runner::v2::agent::script::install_bin;
use ainkrad_runner::v2::agent::tools::Tools;
use ainkrad_runner::v2::agent::tools::sock::start;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner"))
}

fn tool(name: &str) -> ConnTool {
    ConnTool {
        name: name.to_owned(),
        description: "d".to_owned(),
        write: false,
        input_schema: None,
    }
}

/// The fake Core: lists `ainkrad.search`, `ainkrad.call` and `ainkrad.schema`, answers calls.
async fn core(tools: Arc<Tools>, session: &'static str) {
    let list = vec![
        tool("ainkrad.search"),
        tool("ainkrad.call"),
        tool("ainkrad.schema"),
    ];
    let (mut after, mut results, mut first) = (0, Vec::new(), true);
    loop {
        let poll = ToolsPoll {
            session: session.to_owned(),
            after,
            wait_ms: Some(100),
            results: std::mem::take(&mut results),
            tools: first.then(|| list.clone()),
        };
        first = false;
        let batch = tools.poll(&poll, Duration::from_millis(150)).await;
        for c in batch.calls {
            after = c.tc_seq;
            let (ok, body) = match (c.tool.as_str(), c.args["op"].as_str()) {
                ("ainkrad.search", _) => (true, json!({"definitions": []})),
                ("ainkrad.call", Some("listAgentSessions")) => (
                    true,
                    json!({"items": [{"id": "as_1", "state": "running"}, {"id": "as_2", "state": "ended"}]}),
                ),
                ("ainkrad.call", _) => (false, json!({"code": "not_granted", "message": "no"})),
                _ => (false, json!({"code": "unknown_tool", "message": "no"})),
            };
            results.push(ToolResult {
                approval: None,
                id: c.id,
                ok,
                result: ok.then(|| body.clone()),
                code: (!ok).then(|| body["code"].as_str().unwrap().to_owned()),
                message: (!ok).then(|| "no".to_owned()),
            });
        }
    }
}

fn sock_path(tag: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/e3-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("tools.sock")
}

struct Shim {
    child: tokio::process::Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl Shim {
    fn start(sock: &std::path::Path) -> Self {
        let mut child = Command::new(exe())
            .arg("mcp-stdio")
            .arg(sock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self { child, lines }
    }

    async fn ask(&mut self, id: u64, method: &str, params: Value) -> Value {
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
        loop {
            let l = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
                .await
                .expect("the shim answered")
                .unwrap()
                .expect("the shim is alive");
            let v: Value = serde_json::from_str(&l).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    async fn run(&mut self, id: u64, code: &str) -> (bool, String) {
        let v = self
            .ask(
                id,
                "tools/call",
                json!({"name": "ainkrad_run", "arguments": {"code": code}}),
            )
            .await;
        (
            v["result"]["isError"] == true,
            v["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_script_runs_in_the_shim_and_the_model_sees_one_result() {
    let tools = Arc::new(Tools::default());
    let sock = sock_path("shim");
    let _front = start(&sock, tools.clone(), "as_a").unwrap();
    tokio::spawn(core(tools.clone(), "as_a"));
    let mut shim = Shim::start(&sock);
    // Only the two Code Mode tools are listed: the Core's internal ones are not.
    let l = shim.ask(1, "tools/list", json!({})).await;
    let names: Vec<&str> = l["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for _ in 0..50 {
        if names.contains(&"ainkrad_run") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let l = shim.ask(2, "tools/list", json!({})).await;
    let mut names: Vec<&str> = l["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["ainkrad_run", "ainkrad_search"]);
    // Two operations, one tool result; a refusal is a catchable error.
    let (err, text) = shim
        .run(
            3,
            "const l = ainkrad.agents.listAgentSessions({}); \
             let d; try { ainkrad.agents.dropAll({}) } catch (e) { d = e.code } \
             console.log('seen', l.items.length); \
             return {running: l.items.filter(s => s.state === 'running').map(s => s.id), d}",
        )
        .await;
    assert!(!err, "{text}");
    assert!(
        text.starts_with(r#"{"running":["as_1"],"d":"not_granted"}"#),
        "{text}"
    );
    assert!(
        text.contains("console:\nseen 2") && text.contains("[2 calls,"),
        "{text}"
    );
    // An error carries its line; the shim is healthy for the next script, and other tools pass through.
    let (err, text) = shim.run(4, "let a = 1;\nnull.x;").await;
    assert!(err && text.contains("(line 2)"), "{text}");
    let (err, text) = shim
        .run(5, "return typeof require + typeof process + typeof fetch")
        .await;
    assert!(
        !err && text.starts_with("\"undefinedundefinedundefined\""),
        "{text}"
    );
    let s = shim
        .ask(
            6,
            "tools/call",
            json!({"name": "ainkrad_search", "arguments": {"query": "x"}}),
        )
        .await;
    assert_eq!(s["result"]["isError"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ainkrad_cli_runs_from_a_link_named_ainkrad_with_the_socket_in_env() {
    let tools = Arc::new(Tools::default());
    let sock = sock_path("cli");
    let _front = start(&sock, tools.clone(), "as_c").unwrap();
    tokio::spawn(core(tools.clone(), "as_c"));
    let bin = install_bin(sock.parent().unwrap(), &exe()).unwrap();
    let (sock, bin) = (sock.clone(), bin.clone());
    let run = move |args: Vec<&'static str>, with_sock: bool| {
        let (sock, bin) = (sock.clone(), bin.clone());
        tokio::task::spawn_blocking(move || {
            let mut c = std::process::Command::new(bin.join("ainkrad"));
            c.args(args).env_clear();
            if with_sock {
                c.env("AINKRAD_TOOLS_SOCK", &sock);
            }
            c.output().unwrap()
        })
    };
    // The core's first list is sent at its first poll: retry briefly until the tools are listed.
    let mut out = run(vec!["agents", "listAgentSessions", "--json", "{}"], true)
        .await
        .unwrap();
    for _ in 0..30 {
        if out.status.success() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        out = run(vec!["agents", "listAgentSessions", "--json", "{}"], true)
            .await
            .unwrap();
    }
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["items"][1]["id"], "as_2");
    let refused = run(vec!["agents", "dropAll"], true).await.unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&refused.stderr).unwrap()["error"]["code"],
        "not_granted"
    );
    let none = run(vec!["agents", "listAgentSessions"], false)
        .await
        .unwrap();
    assert_eq!(none.status.code(), Some(1));
}

/// Runs the script child under `wrapper` with nothing but the socket it is told and a request.
fn script_under(wrapper: &[String], code: &str, time_ms: u64) -> Option<Value> {
    use std::io::Write;
    let req = json!({"code": code, "run": "r1", "limits": {"time_ms": time_ms}});
    let mut c = std::process::Command::new(&wrapper[0]);
    c.args(&wrapper[1..])
        .arg(exe())
        .args(["__script", "/tmp/e3-no-such.sock"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = c.spawn().ok()?;
    child
        .stdin
        .take()?
        .write_all(req.to_string().as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    serde_json::from_slice(&out.stdout).ok()
}

/// Asserts the engine's guarantees hold inside a sandbox that allows nothing.
fn sandbox_holds(wrapper: &[String]) {
    let v = script_under(
        wrapper,
        "return [typeof require, typeof process, typeof fetch, typeof std, typeof os]",
        5000,
    )
    .expect("the script child ran in the sandbox");
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(
        v["value"],
        r#"["undefined","undefined","undefined","undefined","undefined"]"#
    );
    // The only way out is the socket, and it is not there: a plain error, the child is fine.
    let v = script_under(
        wrapper,
        "try { ainkrad.g.op({}) } catch (e) { return e.code }",
        5000,
    )
    .unwrap();
    assert_eq!(v["value"], "\"unavailable\"", "{v}");
    let v = script_under(wrapper, "while (true) {}", 500).unwrap();
    assert_eq!(v["ok"], false);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("time limit"),
        "{v}"
    );
    let v = script_under(wrapper, "return 'x'.repeat(1 << 28).length", 5000).unwrap();
    assert_eq!(v["ok"], false, "{v}");
}

#[cfg(target_os = "macos")]
#[test]
fn the_script_child_holds_under_a_deny_default_seatbelt_profile() {
    let profile = format!(
        "(version 1)(deny default)(allow process-exec (literal \"{}\"))(allow file-read*)(allow sysctl-read)(allow mach-lookup)",
        exe().display()
    );
    let wrapper: Vec<String> = vec!["/usr/bin/sandbox-exec".into(), "-p".into(), profile.clone()];
    // Seatbelt cannot nest: inside an already sandboxed shell the check cannot run. Loud, not silent.
    let probe = std::process::Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status();
    if !probe.is_ok_and(|s| s.success()) {
        eprintln!(
            "SKIPPED: sandbox-exec cannot run here (nested Seatbelt); run it in a normal Terminal"
        );
        return;
    }
    // Control: the profile really denies (it allows exec of the runner only, so `true` is refused).
    let control = std::process::Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/true"])
        .status()
        .unwrap();
    assert!(!control.success(), "the profile allows more than it should");
    sandbox_holds(&wrapper);
}

#[cfg(target_os = "linux")]
#[test]
fn the_script_child_holds_under_bubblewrap() {
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .status();
    if !probe.is_ok_and(|s| s.success()) {
        eprintln!("SKIPPED: bubblewrap cannot run here");
        return;
    }
    let wrapper: Vec<String> = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/tmp",
        "--clearenv",
    ]
    .map(String::from)
    .into();
    sandbox_holds(&wrapper);
}

/// How the fake Core's person answers a risky call (E6.5).
#[derive(Clone, Copy)]
enum Person {
    Approves,
    Denies,
    /// Never answers: the Core gives up at the call's `wait_ms`.
    Away,
}

/// A fake Core whose `closeIssue` is risky: it waits for `person`, answers with the approval's
/// request id, and records the arguments of every `ainkrad.call`.
async fn approving_core(
    tools: Arc<Tools>,
    session: &'static str,
    person: Person,
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
) {
    let list = vec![tool("ainkrad.search"), tool("ainkrad.call")];
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<ToolResult>();
    let (mut after, mut first, mut n) = (0, true, 0);
    loop {
        let mut results = Vec::new();
        while let Ok(r) = done_rx.try_recv() {
            results.push(r);
        }
        let poll = ToolsPoll {
            session: session.to_owned(),
            after,
            wait_ms: Some(50),
            results,
            tools: first.then(|| list.clone()),
        };
        first = false;
        for c in tools.poll(&poll, Duration::from_millis(100)).await.calls {
            after = c.tc_seq;
            seen.lock().unwrap().push(c.args.clone());
            n += 1;
            let request = format!("cm_{n}");
            let tx = done_tx.clone();
            tokio::spawn(async move {
                let risky = c.args["op"] == "closeIssue";
                let r = |ok: bool, code: Option<&str>| ToolResult {
                    approval: risky.then(|| request.clone()),
                    id: c.id.clone(),
                    ok,
                    result: ok.then(|| json!({"closed": true})),
                    code: code.map(str::to_owned),
                    message: code.map(|_| "no".to_owned()),
                };
                let answer = match (risky, person) {
                    (false, _) | (true, Person::Approves) => r(true, None),
                    (true, Person::Denies) => r(false, Some("approval_denied")),
                    (true, Person::Away) => {
                        let ms = c.args["wait_ms"].as_u64().unwrap_or(600_000);
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        r(false, Some("approval_timeout"))
                    }
                };
                let _ = tx.send(answer);
            });
        }
    }
}

const RISKY: &str = "let out; \
    try { out = ainkrad.github.closeIssue({number: 1}, {key: 'k1'}) } \
    catch (e) { out = [e instanceof ainkrad.ApprovalError, e.code] } \
    return out";

async fn listed(shim: &mut Shim) {
    for i in 0..50 {
        let l = shim.ask(1000 + i, "tools/list", json!({})).await;
        if l.to_string().contains("ainkrad_run") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("ainkrad_run was never listed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_risky_call_waits_for_a_person_and_the_result_says_how_it_ended() {
    for (tag, person, value, outcome) in [
        ("appr", Person::Approves, r#"{"closed":true}"#, "approved"),
        (
            "deny",
            Person::Denies,
            r#"[true,"approval_denied"]"#,
            "denied",
        ),
    ] {
        let tools = Arc::new(Tools::default());
        let sock = sock_path(tag);
        let session: &'static str = if tag == "appr" { "as_p" } else { "as_d" };
        let _front = start(&sock, tools.clone(), session).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        tokio::spawn(approving_core(tools.clone(), session, person, seen.clone()));
        let mut shim = Shim::start(&sock);
        listed(&mut shim).await;
        let (err, text) = shim.run(1, RISKY).await;
        assert!(!err, "{text}");
        assert!(text.starts_with(value), "{text}");
        assert!(
            text.contains(&format!("approvals: closeIssue {outcome} (cm_1)")),
            "{text}"
        );
        let args = seen.lock().unwrap()[0].clone();
        assert_eq!(args["key"], "k1", "{args}");
        let w = args["wait_ms"].as_u64().unwrap();
        assert!(
            w > 500_000 && w <= 600_000,
            "the default 10 min deadline: {w}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_nobody_answers_ends_at_the_deadline_and_the_session_goes_on() {
    use std::io::Write;
    let tools = Arc::new(Tools::default());
    let sock = sock_path("away");
    let _front = start(&sock, tools.clone(), "as_w").unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    tokio::spawn(approving_core(
        tools.clone(),
        "as_w",
        Person::Away,
        seen.clone(),
    ));
    let mut shim = Shim::start(&sock);
    listed(&mut shim).await;
    // A script with a 3 s deadline (and a 1 s running-time cap the wait does not count against).
    let s = sock.clone();
    let out = tokio::task::spawn_blocking(move || {
        let req = json!({"code": RISKY, "run": "rw",
            "limits": {"time_ms": 1_000, "deadline_ms": 3_000}});
        let mut child = std::process::Command::new(exe())
            .args(["__script", s.to_str().unwrap()])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(req.to_string().as_bytes())
            .unwrap();
        let t = std::time::Instant::now();
        let out = child.wait_with_output().unwrap();
        (
            serde_json::from_slice::<Value>(&out.stdout).unwrap(),
            t.elapsed(),
        )
    })
    .await
    .unwrap();
    let (v, took) = out;
    assert_eq!(v["value"], r#"[true,"approval_timeout"]"#, "{v}");
    assert_eq!(v["approvals"][0]["outcome"], "timed_out", "{v}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    // Nothing is left waiting: the next script of the session runs at once.
    let t = std::time::Instant::now();
    let (err, text) = shim
        .run(2, "return ainkrad.agents.listAgentSessions({})")
        .await;
    assert!(!err && text.starts_with(r#"{"closed":true}"#), "{text}");
    assert!(t.elapsed() < Duration::from_secs(5));
}
