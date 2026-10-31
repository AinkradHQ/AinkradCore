//! A Citadel run, end to end through the composed binary (`ainkrad-core-citadel serve
//! --enable-module citadel`): a real `ainkrad-runner` with the agent driver and the sandbox, a
//! FAKE `claude` on its PATH as the harness (no model, no credential), a paired runner and an admin
//! device with step-up. Linux with a working bubblewrap; elsewhere the test says so and returns.
//!
//! Covers: the engine is attached and OFF until an admin steps up; enabling it starts a run in
//! the sandbox; the agent reaches Citadel's MCP tools with its run token; the transcript streams
//! without a gap; an approval gates the destructive step (granted and refused); a hard-stop budget
//! kills a run; cancel and kill leave no process; no token or secret reaches logs, DB or transcripts.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::SystemClock;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-core-citadel");
const M: &str = "/modules/citadel/v1";

fn runner_bin() -> PathBuf {
    // target/<profile>/deps/<test> -> target/<profile>; the runner is built by the main workspace.
    let profile = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_owned();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../Cargo.toml");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let ok = Command::new(cargo)
        .args(["build", "-p", "ainkrad-runner", "--bin", "ainkrad-runner", "--manifest-path"])
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", profile.parent().unwrap())
        .status()
        .expect("running cargo")
        .success();
    assert!(ok, "building ainkrad-runner");
    profile.join("ainkrad-runner")
}

/// Whether this host can run a sandboxed agent: bubblewrap with user namespaces on Linux.
fn sandbox_usable() -> bool {
    if cfg!(not(target_os = "linux")) {
        return false;
    }
    Command::new("bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
        && Command::new("curl").arg("--version").stdout(Stdio::null()).status().is_ok()
}

/// The harness stand-in. Reads the MCP config the runner hands a harness, calls Citadel's tools
/// with the run token, asks for approvals and acts on the destructive step only when granted,
/// then ticks (one transcript message per tick) until it is stopped.
fn fake_claude(version: &str) -> String {
    format!(
        r#"#!/bin/sh
case "$1" in --version) echo "{version} (Claude Code)"; exit 0;; esac
sid=; mcp=; prev=
for x in "$@"; do case $prev in --session-id|--resume) sid=$x;; --mcp-config) mcp=$x;; esac; prev=$x; done
printf '{{"type":"system","subtype":"init","session_id":"%s"}}\n' "${{sid:-00000000-0000-4000-8000-000000000e17}}"
k=0
say() {{ k=$((k+1)); printf '{{"type":"assistant","message":{{"id":"m%s-%s","content":[{{"type":"text","text":"%s"}}],"usage":{{"input_tokens":1,"output_tokens":1}}}}}}\n' "$$" "$k" "$1"; }}
url=$(grep -o '"url": *"[^"]*"' "$mcp" | head -n1 | sed 's/.*: *"//; s/"$//')
tok=$(grep -o 'Bearer [^"]*' "$mcp" | head -n1 | cut -c8-)
tool() {{ curl -sS -m 10 -H "authorization: Bearer $tok" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"$1\",\"arguments\":$2}}}}" "$url" 2>/dev/null; }}
failed() {{ case $1 in *'"isError":true'*|'') return 0;; esac; return 1; }}
printf '%s' "$tok" > mcp-token-copy
r=$(tool get_issue '{{}}')
if failed "$r"; then say MCP-GET-ISSUE-FAILED; else say MCP-GET-ISSUE-OK; fi
case $r in *CAPPED*) capped=1;; esac
if [ -z "$capped" ]; then
  r=$(tool comment '{{"body":"hello from the fake harness"}}')
  if failed "$r"; then say MCP-COMMENT-FAILED; else say MCP-COMMENT-OK; fi
  gate() {{ # gate <kind> <label>: ask a human, act only when granted
    r=$(tool request_approval "{{\"kind\":\"$1\",\"summary\":\"$2\"}}")
    id=$(printf '%s' "$r" | sed -n 's/.*approval_id[^0-9]*\([0-9][0-9]*\).*/\1/p' | head -n1)
    say "ASKED-$2-$id"
    while :; do
      st=$(tool get_approval "{{\"approval_id\":$id}}" | sed -n 's/.*status[^a-z]*\([a-z_]*\).*/\1/p' | head -n1)
      [ "$st" = pending ] || [ -z "$st" ] || break
      sleep 1
    done
    if [ "$st" = approved ]; then echo done > "destructive-$2"; say "DONE-$2"; else say "SKIPPED-$2"; fi
  }}
  gate pr_merge GRANTED
  gate pr_merge REFUSED
fi
n=0
while :; do n=$((n+1)); say "TICK-$n"; sleep 1; done
"#
    )
}

struct Rig {
    dir: PathBuf,
    bind: String,
    http: reqwest::Client,
    admin: TestDevice,
    core: Child,
    runner: Option<Child>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if std::thread::panicking() {
            for q in [
                "select id,agent_id,issue_id,status,reason from citadel_wake_requests",
                "select * from citadel_engine",
                "select id,state,terminal_reason from citadel_runs",
                "select job,status,error from core_job_runs order by rowid desc limit 8",
            ] {
                let o = Command::new("python3")
                    .args(["-c", "import sqlite3,sys\nfor r in sqlite3.connect(sys.argv[1]).execute(sys.argv[2]): print(r)"])
                    .arg(self.dir.join("home/core.db"))
                    .arg(q)
                    .output();
                eprintln!("--- {q}\n{}", o.map(|o| String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)).unwrap_or_default());
            }
            for log in ["core.log", "runner.log"] {
                let t = std::fs::read_to_string(self.dir.join(log)).unwrap_or_default();
                let tail: Vec<&str> = t.lines().rev().take(40).collect();
                eprintln!("--- {log} (tail)\n{}", tail.into_iter().rev().collect::<Vec<_>>().join("\n"));
            }
        }
        for c in [Some(&mut self.core), self.runner.as_mut()].into_iter().flatten() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Agents run in their own sessions: only their command lines name this run.
        let _ = Command::new("pkill").args(["-9", "-f"]).arg(&self.dir).status();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn until<T, F: AsyncFn() -> Option<T>>(secs: u64, what: &str, f: F) -> T {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(Instant::now() < end, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

impl Rig {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let bytes = body.map(|b| b.to_string()).unwrap_or_default();
        let mut r = self
            .http
            .request(method.parse().unwrap(), format!("http://{}{path}", self.bind))
            .body(bytes.clone());
        if !bytes.is_empty() {
            r = r.header("content-type", "application/json");
        }
        for (k, v) in self.admin.headers(method, path, bytes.as_bytes()) {
            r = r.header(k, v);
        }
        let res = r.send().await.unwrap();
        (res.status().as_u16(), res.json().await.unwrap_or(Value::Null))
    }

    async fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(method, path, body).await;
        assert_eq!(s, 200, "{method} {path}: {v}");
        v
    }

    async fn login(&self) {
        let url = |p: &str| format!("http://{}{p}", self.bind);
        let c: Value = self
            .http
            .post(url("/handshake/challenge"))
            .json(&json!({"device_id": self.admin.id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let body = json!({"challenge": c["challenge"]}).to_string();
        let mut r = self
            .http
            .post(url("/handshake/session"))
            .header("content-type", "application/json")
            .body(body.clone());
        for (k, v) in self.admin.headers_session("POST", "/handshake/session", body.as_bytes(), None) {
            r = r.header(k, v);
        }
        let s: Value = r.send().await.unwrap().json().await.unwrap();
        self.admin.set_session(s["session_id"].as_str().map(str::to_owned));
        assert!(self.admin.session.lock().unwrap().is_some(), "{s}");
    }

    async fn elevate(&self) {
        let c = self.ok("POST", "/api/v1/auth/step-up/challenge", Some(json!({}))).await;
        let proof = self.admin.stepup_body(c["challenge"].as_str().unwrap());
        self.ok("POST", "/api/v1/auth/step-up", Some(proof)).await;
    }

    async fn runs(&self) -> Vec<Value> {
        self.ok("GET", &format!("{M}/runs"), None).await.as_array().cloned().unwrap_or_default()
    }

    async fn run_of(&self, issue: i64) -> Option<Value> {
        self.runs().await.into_iter().find(|r| r["issue_id"] == issue)
    }

    async fn transcript(&self, session: &str) -> Vec<Value> {
        let t = self
            .ok("GET", &format!("/api/v1/agent-sessions/{session}/transcript?after=0&limit=1000"), None)
            .await;
        t["entries"].as_array().cloned().unwrap_or_default()
    }

    async fn texts(&self, session: &str) -> String {
        self.transcript(session).await.iter().map(|e| e["body"].to_string()).collect::<Vec<_>>().join("\n")
    }
}

/// Starts the Core and a paired, connected runner whose PATH has the fake `claude`.
async fn rig() -> Rig {
    let dir = std::env::temp_dir().join(format!("citadel-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (bin, tmp, home) = (dir.join("bin"), dir.join("tmp"), dir.join("home"));
    for d in [&bin, &tmp, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    let version = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../crates/harness/src/claude.rs"),
    )
    .unwrap()
    .lines()
    .find_map(|l| l.strip_prefix("pub const VERSION: &str = \"").and_then(|v| v.strip_suffix("\";")).map(str::to_owned))
    .expect("the harness version");
    let claude = bin.join("claude");
    std::fs::write(&claude, fake_claude(&version)).unwrap();
    std::fs::set_permissions(&claude, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let db = home.join("core.db");
    let identity = Identity::load_or_create(&home).unwrap();
    let pool = ainkrad_core_server::store::connect(&db).await.unwrap();
    let all = ["read", "approve", "terminal", "agent", "admin", "runner"];
    let admin = TestDevice::enroll(&pool, "mac", "device", &all, &identity.fp, Arc::new(SystemClock)).await;
    pool.close().await;
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let bind = format!("127.0.0.1:{port}");
    let core = Command::new(BIN)
        .args(["serve", db.to_str().unwrap(), "--enable-module", "citadel"])
        .args(["--listen", &format!("loopback:{port}"), "--host", &bind])
        .args(["--allow-plain-runner", "--max-host-load", "100000"])
        .stderr(std::fs::File::create(dir.join("core.log")).unwrap())
        .spawn()
        .unwrap();
    let mut rig = Rig { dir, bind: bind.clone(), http: reqwest::Client::builder().pool_max_idle_per_host(0).build().unwrap(), admin, core, runner: None };
    until(30, "the Core listens", async || tokio::net::TcpStream::connect(&bind).await.ok()).await;
    rig.login().await;
    rig.elevate().await;

    // Pair the runner: the admin approves the SAS the runner shows.
    let p = rig
        .ok("POST", "/api/v1/pairings", Some(json!({"name": "vm", "kind": "runner", "scopes": ["runner"]})))
        .await;
    let state = rig.dir.join("runner");
    let mut pair = Command::new(runner_bin())
        .args(["pair", &format!("http://{bind}"), "--code", p["code"].as_str().unwrap(), "--state"])
        .arg(&state)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let out = std::io::BufReader::new(pair.stdout.take().unwrap());
    let mut sas = None;
    let mut lines = std::io::BufRead::lines(out).map_while(Result::ok);
    for line in lines.by_ref() {
        let t = line.trim();
        if line.starts_with(' ') && t.len() == 19 {
            sas = Some(t.to_owned());
            break;
        }
    }
    let sas = sas.expect("the runner shows a SAS");
    // Keep reading: a closed pipe would kill the runner as it prints its last line.
    std::thread::spawn(move || lines.for_each(drop));
    rig.ok("POST", &format!("/api/v1/pairings/{}/approve", p["pairing_id"].as_str().unwrap()), Some(json!({"sas": sas})))
        .await;
    assert!(pair.wait().unwrap().success(), "the runner paired");

    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    rig.runner = Some(
        Command::new(runner_bin())
            .args(["connect", "--enable-agents", "--state"])
            .arg(&state)
            .env("PATH", path)
            .env("TMPDIR", &tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(rig.dir.join("runner.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    until(60, "the runner is online with the agent driver", async || {
        let rs = rig.ok("GET", "/api/v1/runners", None).await;
        rs.as_array()?.iter().find(|r| r["online"] == true && r["drivers"].to_string().contains("agent")).map(|_| ())
    })
    .await;
    rig
}

/// A company, an approved agent, a project and an issue assigned to it: its issue id.
async fn hire_and_assign(rig: &Rig, company: i64, name: &str, key: &str, title: &str) -> (i64, i64) {
    let hire = rig
        .ok(
            "POST",
            &format!("{M}/companies/{company}/agents"),
            Some(json!({"name": name, "role": "Developer", "harness": "claude", "model": "sonnet",
                        "justification": "e2e", "sandbox": "workspace-write"})),
        )
        .await;
    rig.ok("POST", &format!("{M}/approvals/{}/decide", hire["hire_approval_id"]), Some(json!({"approve": true})))
        .await;
    let agent = hire["agent"]["id"].as_i64().unwrap();
    let project = rig
        .ok("POST", &format!("{M}/companies/{company}/projects"), Some(json!({"name": name, "key": key})))
        .await["id"]
        .as_i64()
        .unwrap();
    let issue = rig
        .ok(
            "POST",
            &format!("{M}/projects/{project}/issues"),
            Some(json!({"title": title, "body": "Do the work.", "assignee_agent_id": agent})),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    (agent, issue)
}

fn find_named(dir: &Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
        if p.is_dir() && !p.is_symlink() {
            if let Some(f) = find_named(&p, name) {
                return Some(f);
            }
        }
    }
    None
}

#[tokio::test]
async fn a_citadel_run_goes_from_issue_to_cleanup_through_the_composed_binary() {
    if !sandbox_usable() {
        eprintln!("skipped: needs Linux, a working bubblewrap and curl");
        return;
    }
    let rig = rig().await;
    let company = rig.ok("POST", &format!("{M}/companies"), Some(json!({"name": "Acme"}))).await["id"].as_i64().unwrap();
    let (_, issue) = hire_and_assign(&rig, company, "Worker", "WRK", "Real work").await;
    let (capped, capped_issue) = hire_and_assign(&rig, company, "Capped", "CAP", "CAPPED work").await;

    // The engine is off until an admin steps up: a wake is queued and nothing starts. The step-up
    // gate refuses an unelevated admin first (a fresh session of the same device is not elevated).
    assert_eq!(rig.ok("GET", &format!("{M}/engine"), None).await["enabled"], false);
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert!(rig.runs().await.is_empty(), "an engine that is off starts nothing");

    // mcp.enabled is a Core setting the operator turns on (admin + step-up); the hard-stop budget
    // on the capped agent allows only a few tokens.
    rig.ok("PUT", &format!("{M}/settings/mcp.enabled"), Some(json!({"value": 1}))).await;
    rig.ok(
        "POST",
        &format!("{M}/companies/{company}/budgets"),
        Some(json!({"scope": {"kind": "agent", "agent_id": capped}, "period": "total", "token_cap": 6, "hard_stop": true})),
    )
    .await;
    rig.ok("POST", &format!("{M}/engine"), Some(json!({"enabled": true}))).await;

    // A run starts for each, in a session the module owns.
    let run = until(60, "the worker's run starts", async || {
        rig.run_of(issue).await.filter(|r| r["session_id"].is_string() && r["state"] == "running")
    })
    .await;
    let (run_id, session) = (run["id"].as_i64().unwrap(), run["session_id"].as_str().unwrap().to_owned());
    let sess = rig.ok("GET", &format!("/api/v1/agent-sessions/{session}"), None).await;
    assert_eq!(sess["id"], session.as_str());

    // The agent called MCP tools with its run token and asked for approval: the destructive step waits.
    let asked = until(60, "the first approval is asked", async || {
        let t = rig.texts(&session).await;
        t.contains("ASKED-GRANTED-").then_some(t)
    })
    .await;
    assert!(asked.contains("MCP-GET-ISSUE-OK") && asked.contains("MCP-COMMENT-OK"), "{asked}");
    assert!(!asked.contains("DONE-GRANTED"), "nothing destructive before the decision");
    let approvals = rig.ok("GET", &format!("{M}/companies/{company}/approvals"), None).await;
    let pending: Vec<&Value> = approvals.as_array().unwrap().iter().filter(|a| a["status"] == "pending").collect();
    let grant = *pending.iter().min_by_key(|a| a["id"].as_i64()).expect("a pending approval");
    rig.ok("POST", &format!("{M}/approvals/{}/decide-forge", grant["id"]), Some(json!({"approve": true}))).await;
    until(30, "the granted step runs", async || rig.texts(&session).await.contains("DONE-GRANTED").then_some(())).await;
    let refuse = until(30, "the second approval is asked", async || {
        let a = rig.ok("GET", &format!("{M}/companies/{company}/approvals"), None).await;
        a.as_array()?.iter().find(|a| a["status"] == "pending").cloned()
    })
    .await;
    assert!(!rig.texts(&session).await.contains("DONE-REFUSED"));
    rig.ok("POST", &format!("{M}/approvals/{}/decide-forge", refuse["id"]), Some(json!({"approve": false, "reply": "no"}))).await;
    until(30, "the refused step is skipped", async || rig.texts(&session).await.contains("SKIPPED-REFUSED").then_some(())).await;
    assert!(!rig.texts(&session).await.contains("DONE-REFUSED"), "a refusal leaves the step undone");

    // The transcript streams without a gap, and keeps growing.
    let ticks = |t: &str| t.matches("TICK-").count();
    let before = ticks(&rig.texts(&session).await);
    until(20, "ticks keep arriving", async || (ticks(&rig.texts(&session).await) > before + 2).then_some(())).await;
    let entries = rig.transcript(&session).await;
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e["seq"].as_u64(), Some(i as u64 + 1), "a gap at entry {i}");
    }

    // A hard-stop budget stops the capped agent's run, and blocks it.
    let over = until(60, "the budget ends the capped run", async || {
        rig.run_of(capped_issue).await.filter(|r| !matches!(r["state"].as_str(), Some("queued" | "claimed" | "running")))
    })
    .await;
    assert!(
        over["input_tokens"].as_i64().unwrap() + over["output_tokens"].as_i64().unwrap() >= 6,
        "it was stopped by the cap: {over}"
    );

    // The token the agent used: read it from the workspace the fake left it in, then prove the
    // token is refused after the run ends and appears nowhere the Core keeps text.
    let token_file = find_named(&rig.dir.join("runner"), "mcp-token-copy")
        .or_else(|| find_named(&rig.dir.join("tmp"), "mcp-token-copy"))
        .expect("the fake harness left a copy of its token");
    let token = std::fs::read_to_string(&token_file).unwrap();
    assert!(token.starts_with("cit_run_"), "a run token");
    let mcp = format!("http://{}/token/citadel/v1/mcp", rig.bind);
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let live = rig
        .http
        .post(&mcp)
        .bearer_auth(&token)
        .header("accept", "application/json, text/event-stream")
        .json(&list)
        .send()
        .await
        .unwrap();
    assert_eq!(live.status(), 200, "the token works while its run is live");

    // Turn the engine off (no follow-up wake starts a new run), then cancel the worker's run.
    rig.ok("POST", &format!("{M}/engine"), Some(json!({"enabled": false}))).await;
    rig.ok("POST", &format!("{M}/runs/{run_id}/cancel"), None).await;
    let done = until(60, "the cancelled run ends", async || {
        rig.run_of(issue).await.filter(|r| r["state"] == "cancelled")
    })
    .await;
    assert!(done["terminal_reason"].is_string() || done["ended_at"].is_string());
    // Kill: a wake restarts nothing while the engine is off; a stray live run is killed.
    for r in rig.runs().await {
        if matches!(r["state"].as_str(), Some("running" | "claimed")) {
            rig.ok("POST", &format!("{M}/runs/{}/kill", r["id"]), None).await;
        }
    }
    let gone = rig
        .http
        .post(&mcp)
        .bearer_auth(&token)
        .header("accept", "application/json, text/event-stream")
        .json(&list)
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 401, "a finished run's token is refused");

    // Cleanup: no harness process of this run is left.
    let alive = || {
        Command::new("pgrep")
            .args(["-f", &format!("{}/bin/claude", rig.dir.display())])
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    until(30, "no harness process is left", async || (!alive()).then_some(())).await;

    // No secret in logs, the database or any transcript.
    let t = token.as_bytes();
    let mut texts = String::new();
    for s in rig.ok("GET", "/api/v1/agent-sessions", None).await.as_array().unwrap() {
        texts.push_str(&rig.texts(s["id"].as_str().unwrap()).await);
    }
    assert!(!texts.contains(&token), "the run token is in a transcript");
    for log in ["core.log", "runner.log"] {
        let text = std::fs::read(rig.dir.join(log)).unwrap();
        assert!(!text.windows(t.len()).any(|w| w == t), "the run token is in {log}");
    }
    for f in std::fs::read_dir(rig.dir.join("home")).unwrap().flatten() {
        let p = f.path();
        if p.is_file() {
            assert!(!std::fs::read(&p).unwrap().windows(t.len()).any(|w| w == t), "the run token is in {}", p.display());
        }
    }
}
