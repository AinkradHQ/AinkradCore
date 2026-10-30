//! The agent driver on its own, with a scripted harness (`Script`): capacity and slots, the
//! transcript (seq, acknowledgement, gap), approvals and messages, cancel and kill, restart and
//! resume; and the security properties of secret delivery (E2-07.2/.3): only the session's
//! harness sees a value, the transcript never holds it, its files are 0600 in a 0700 dir and go
//! at the end, at a kill, and after a `kill -9` of the runner.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;

use ainkrad_proto::v2::SecretGrant;
use tokio::io::{AsyncBufReadExt, BufReader};
use zeroize::Zeroizing;

use super::*;
use crate::{Executor, Job, Report};

/// Throwaway values: at least 8 bytes (the redactor's floor), shaped like no real key.
const ENV_VALUE: &str = "throwaway-env-value-41c7";
const FILE_VALUE: &str = "throwaway-file-value-9d2e";
const ASKPASS_VALUE: &str = "throwaway-askpass-value-77b0";

#[derive(Default)]
struct Seen {
    env: HashMap<i64, Vec<(String, String)>>,
    messages: Vec<String>,
    resumes: Vec<Option<String>>,
}

/// A harness that runs `sh -c <script>` with the run's own variables: each stdout line is a
/// `line` event; a line `APPROVAL` asks for a tool approval and reports the answer. A non-zero
/// exit fails with its last line as the reason.
#[derive(Clone)]
struct Script {
    script: String,
    seen: Arc<Mutex<Seen>>,
}

fn script(s: &str) -> Script {
    Script {
        script: s.to_owned(),
        seen: Arc::default(),
    }
}

impl Executor for Script {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        self.seen
            .lock()
            .unwrap()
            .resumes
            .push(job.resume_session.clone());
        Ok(Some(format!("h-{}", job.context_ref)))
    }

    async fn run(&self, job: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let env = self
            .seen
            .lock()
            .unwrap()
            .env
            .get(&job.run)
            .cloned()
            .unwrap_or_default();
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&self.script)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .envs(env)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut last = String::new();
        while let Ok(Some(line)) = lines.next_line().await {
            if line == "APPROVAL" {
                let (reply, answer) = crate::Reply::new();
                let ask = Report::Approval {
                    id: "t1".to_owned(),
                    tool: "Bash".to_owned(),
                    input: json!({"command": "make deploy"}),
                    timeout_secs: 30,
                    reply,
                };
                let _ = reports.send(ask).await;
                let a = answer.await.unwrap();
                let _ = reports
                    .send(Report::Event(
                        json!({"type": "answer", "approved": a.approved}),
                    ))
                    .await;
                continue;
            }
            let _ = reports
                .send(Report::Event(json!({"type": "line", "text": line})))
                .await;
            last = line;
        }
        let _ = reports
            .send(Report::Usage(Tokens {
                input: 3,
                output: 4,
                ..Tokens::default()
            }))
            .await;
        match child.wait().await {
            Ok(s) if s.success() => Outcome::Succeeded,
            _ => Outcome::Failed {
                reason: last,
                fingerprint: None,
            },
        }
    }

    fn control(&self, _: i64, control: Control) {
        if let Control::Message { text, .. } = control {
            self.seen.lock().unwrap().messages.push(text);
        }
    }

    fn session_env(&self, run: i64, env: Option<Vec<(String, String)>>) {
        let mut seen = self.seen.lock().unwrap();
        match env {
            Some(env) => drop(seen.env.insert(run, env)),
            None => drop(seen.env.remove(&run)),
        }
    }
}

fn dirs(name: &str) -> (PathBuf, AgentConfig) {
    let base = if cfg!(target_os = "linux") {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .unwrap_or_else(|| PathBuf::from("/dev/shm"))
    } else {
        std::env::var_os("AINKRAD_TEST_RAMDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
    };
    let root = base.join(format!("agent-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let config = AgentConfig {
        stop_grace: Duration::from_millis(300),
        ..AgentConfig::new(root.join("agents"), root.join("secrets"))
    };
    (root, config)
}

fn start(session: &str, harness: &str) -> AgentStart {
    AgentStart {
        session: session.to_owned(),
        harness: harness.to_owned(),
        model: None,
        prompt: Some("do it".to_owned()),
        workspace: None,
        policy: Default::default(),
        resume: None,
        secrets: vec![],
    }
}

/// Leases `l_env`, `l_file`, `l_askpass`, each delivered its own way.
fn leases() -> Redeem {
    Arc::new(|lease: String| {
        Box::pin(async move {
            let (delivery, value) = match lease.as_str() {
                "l_env" => ("env", ENV_VALUE),
                "l_file" => ("file", FILE_VALUE),
                "l_askpass" => ("askpass", ASKPASS_VALUE),
                _ => return Err("no such lease".to_owned()),
            };
            Ok(secrets::Leased {
                name: format!("test.{delivery}"),
                delivery: delivery.to_owned(),
                value: Zeroizing::new(value.to_owned()),
            })
        })
    })
}

fn grants() -> Vec<SecretGrant> {
    [
        ("l_env", "TOKEN"),
        ("l_file", "TOKEN_FILE"),
        ("l_askpass", "ASKPASS"),
    ]
    .map(|(lease, var)| SecretGrant {
        lease: lease.to_owned(),
        var: var.to_owned(),
    })
    .into()
}

/// Reads the whole transcript until the session is no longer running.
async fn drain(d: &AgentDriver, session: &str) -> (Vec<TranscriptEntry>, AgentEvents) {
    drain_from(d, session, 0).await
}

/// Reads the transcript after `from` (what the Core holds) until the session is over.
async fn drain_from(
    d: &AgentDriver,
    session: &str,
    from: u64,
) -> (Vec<TranscriptEntry>, AgentEvents) {
    let mut all = Vec::new();
    for _ in 0..200 {
        let after = all.last().map_or(from, |e: &TranscriptEntry| e.seq);
        let read = AgentRead {
            session: session.to_owned(),
            after,
            wait_ms: Some(2000),
        };
        let ev = d.read(&read).await.unwrap();
        all.extend(ev.entries.clone());
        if ev.state != AgentState::Running && all.last().map_or(0, |e| e.seq) == ev.last_seq {
            return (all, ev);
        }
    }
    panic!("the session did not end");
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn types(entries: &[TranscriptEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| e.body["type"].as_str().unwrap_or("").to_owned())
        .collect()
}

#[tokio::test]
async fn two_sessions_run_at_once_and_capacity_and_slots_hold() {
    let (root, mut config) = dirs("capacity");
    config.slots = BTreeMap::from([("fake".to_owned(), 2), ("other".to_owned(), 1)]);
    let gate = root.join("go");
    let s = script(&format!(
        "echo up; while [ ! -e '{}' ]; do sleep 0.05; done; echo done",
        gate.display()
    ));
    let d = Arc::new(AgentDriver::new(config, s).unwrap());
    let info = d.info();
    assert_eq!((info.capacity, info.streams), (2, Some(12)));
    d.start(start("as_a", "fake")).unwrap();
    d.start(start("as_b", "fake")).unwrap();
    // Both are running at the same time: each has said `up` and neither has ended.
    for s in ["as_a", "as_b"] {
        let read = AgentRead {
            session: s.to_owned(),
            after: 0,
            wait_ms: Some(2000),
        };
        let mut seen = Vec::new();
        while !seen
            .iter()
            .any(|e: &TranscriptEntry| e.body["text"] == "up")
        {
            let ev = d
                .read(&AgentRead {
                    after: seen.last().map_or(0, |e| e.seq),
                    ..read.clone()
                })
                .await
                .unwrap();
            assert_eq!(ev.state, AgentState::Running);
            seen.extend(ev.entries);
        }
    }
    assert_eq!(
        d.states()
            .values()
            .filter(|s| **s == AgentState::Running)
            .count(),
        2
    );
    let busy = d.start(start("as_c", "other")).unwrap_err();
    assert_eq!(busy.code, ErrorCode::Busy, "past the driver's capacity");
    let refused = d.start(start("as_d", "unlisted")).unwrap_err();
    assert_eq!(
        refused.code,
        ErrorCode::InvalidArgs,
        "a harness with no slot"
    );
    // A resent start of a running session answers with it and starts nothing.
    assert_eq!(
        d.start(start("as_a", "fake")).unwrap().state,
        AgentState::Running
    );
    std::fs::write(&gate, "").unwrap();
    for s in ["as_a", "as_b"] {
        let (entries, ev) = drain(&d, s).await;
        assert_eq!(ev.outcome, Some(Outcome::Succeeded));
        assert_eq!(ev.usage.map(|u| u.output), Some(4), "metered");
        assert_eq!(
            ev.harness_session.as_deref(),
            Some(format!("h-{s}").as_str())
        );
        let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, (1..=ev.last_seq).collect::<Vec<_>>(), "no gap");
    }
    // A slot frees as a session ends.
    d.start(start("as_c", "other")).unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn slots_split_the_capacity_per_harness() {
    let (root, mut config) = dirs("slots");
    config.slots = BTreeMap::from([("fake".to_owned(), 1), ("other".to_owned(), 1)]);
    let d = Arc::new(AgentDriver::new(config, script("sleep 5")).unwrap());
    d.start(start("as_a", "fake")).unwrap();
    assert_eq!(
        d.start(start("as_b", "fake")).unwrap_err().code,
        ErrorCode::Busy
    );
    d.start(start("as_c", "other")).unwrap();
    for s in ["as_a", "as_c"] {
        d.stop(AgentStop {
            session: s.to_owned(),
            kill: true,
        })
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_read_acknowledges_what_the_core_holds_and_a_gap_is_explicit() {
    let (root, mut config) = dirs("ack");
    config.max_entries = 3;
    let d = Arc::new(
        AgentDriver::new(
            config.clone(),
            script("for i in 1 2 3 4 5 6; do echo $i; done"),
        )
        .unwrap(),
    );
    d.start(start("as_a", "fake")).unwrap();
    until("the end", || d.states()["as_a"] == AgentState::Ended).await;
    // Nothing was read: past `max_entries`, the oldest went, and the read says so first.
    let ev = d
        .read(&AgentRead {
            session: "as_a".into(),
            after: 0,
            wait_ms: None,
        })
        .await
        .unwrap();
    let gap = &ev.entries[0];
    assert_eq!(gap.body["type"], "gap");
    assert_eq!(
        (gap.body["from"].as_u64(), gap.seq),
        (Some(1), ev.last_seq - 3)
    );
    let seqs: Vec<u64> = ev.entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (ev.last_seq - 3..=ev.last_seq).collect::<Vec<_>>());
    // The Core holding everything: the transcript file goes, the state stays.
    let file = config.dir.join("as_a/transcript.jsonl");
    assert!(file.exists());
    let done = d
        .read(&AgentRead {
            session: "as_a".into(),
            after: ev.last_seq,
            wait_ms: None,
        })
        .await
        .unwrap();
    assert!(done.entries.is_empty() && done.state == AgentState::Ended);
    assert!(!file.exists(), "a fully read transcript is not kept");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn an_approval_and_a_message_round_trip() {
    let (root, config) = dirs("approve");
    let s = script("echo before; echo APPROVAL; echo after");
    let seen = Arc::clone(&s.seen);
    let d = Arc::new(AgentDriver::new(config, s).unwrap());
    d.start(start("as_a", "fake")).unwrap();
    let mut entries = Vec::new();
    while !types(&entries).contains(&"approval_request".to_owned()) {
        let after = entries.last().map_or(0, |e: &TranscriptEntry| e.seq);
        entries.extend(
            d.read(&AgentRead {
                session: "as_a".into(),
                after,
                wait_ms: Some(2000),
            })
            .await
            .unwrap()
            .entries,
        );
    }
    let ask = entries
        .iter()
        .find(|e| e.body["type"] == "approval_request")
        .unwrap();
    assert_eq!(
        (ask.body["id"].as_str(), ask.body["tool"].as_str()),
        (Some("t1"), Some("Bash"))
    );
    d.send("as_a", "also run the tests".to_owned()).unwrap();
    assert_eq!(seen.lock().unwrap().messages, ["also run the tests"]);
    let wrong = AgentDecide {
        session: "as_a".into(),
        request: "t9".into(),
        approved: true,
        reply: None,
    };
    assert_eq!(d.decide(wrong).unwrap_err().code, ErrorCode::InvalidArgs);
    let ok = AgentDecide {
        session: "as_a".into(),
        request: "t1".into(),
        approved: true,
        reply: None,
    };
    d.decide(ok).unwrap();
    let (rest, ev) = drain(&d, "as_a").await;
    let all: Vec<_> = rest.iter().map(|e| e.body.clone()).collect();
    assert!(
        all.iter()
            .any(|b| b["type"] == "approval_decided" && b["approved"] == true),
        "{all:?}"
    );
    assert!(
        all.iter()
            .any(|b| b["type"] == "answer" && b["approved"] == true),
        "the harness got it"
    );
    assert!(all.iter().any(|b| b["type"] == "message"));
    assert_eq!(ev.outcome, Some(Outcome::Succeeded));
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn cancel_ends_after_the_grace_and_kill_at_once() {
    let (root, config) = dirs("stop");
    let d = Arc::new(AgentDriver::new(config, script("echo up; sleep 30")).unwrap());
    d.start(start("as_a", "fake")).unwrap();
    d.start(start("as_b", "fake")).unwrap();
    d.stop(AgentStop {
        session: "as_a".into(),
        kill: true,
    })
    .unwrap();
    assert_eq!(d.states()["as_a"], AgentState::Ended, "a kill ends it now");
    d.stop(AgentStop {
        session: "as_b".into(),
        kill: false,
    })
    .unwrap();
    until("the grace", || d.states()["as_b"] == AgentState::Ended).await;
    for s in ["as_a", "as_b"] {
        let (_, ev) = drain(&d, s).await;
        assert!(
            matches!(ev.outcome, Some(Outcome::Cancelled { .. })),
            "{:?}",
            ev.outcome
        );
    }
    // Stopping an ended session is answered, not refused.
    assert_eq!(
        d.stop(AgentStop {
            session: "as_a".into(),
            kill: true
        })
        .unwrap()
        .state,
        AgentState::Ended
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_new_driver_reloads_a_running_session_as_interrupted_and_resumes_it() {
    let (root, config) = dirs("restart");
    let first =
        Arc::new(AgentDriver::new(config.clone(), script("echo one; echo two; sleep 30")).unwrap());
    first.start(start("as_a", "fake")).unwrap();
    let mut seen = Vec::new();
    while seen.len() < 3 {
        let after = seen.last().map_or(0, |e: &TranscriptEntry| e.seq);
        seen.extend(
            first
                .read(&AgentRead {
                    session: "as_a".into(),
                    after,
                    wait_ms: Some(2000),
                })
                .await
                .unwrap()
                .entries,
        );
    }
    // The Core read up to `one` only; then the runner process goes (its state stays on disk).
    let held = seen.iter().find(|e| e.body["text"] == "one").unwrap().seq;
    first
        .read(&AgentRead {
            session: "as_a".into(),
            after: held,
            wait_ms: None,
        })
        .await
        .unwrap();
    let s = script("echo resumed");
    let resumes = Arc::clone(&s.seen);
    let second = Arc::new(AgentDriver::new(config, s).unwrap());
    let ev = second
        .read(&AgentRead {
            session: "as_a".into(),
            after: held,
            wait_ms: None,
        })
        .await
        .unwrap();
    assert_eq!(ev.state, AgentState::Interrupted);
    assert_eq!(
        ev.entries[0].seq,
        held + 1,
        "the rest of the transcript, from where the Core is"
    );
    assert_eq!(ev.entries[0].body["text"], "two");
    assert_eq!(ev.entries.last().unwrap().body["type"], "interrupted");
    assert_eq!(ev.harness_session.as_deref(), Some("h-as_a"));
    let mut again = start("as_a", "fake");
    again.resume = ev.harness_session.clone();
    second.start(again).unwrap();
    let (rest, end) = drain_from(&second, "as_a", held).await;
    assert_eq!(resumes.lock().unwrap().resumes, [Some("h-as_a".to_owned())]);
    assert_eq!(
        rest[0].seq,
        held + 1,
        "numbering continues across the restart"
    );
    assert!(
        rest.iter()
            .any(|e| e.body["type"] == "started" && e.body["resumed"] == true)
    );
    assert_eq!(end.outcome, Some(Outcome::Succeeded));
    first
        .stop(AgentStop {
            session: "as_a".into(),
            kill: true,
        })
        .unwrap();
    let _ = std::fs::remove_dir_all(root);
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// E2-07.2/.3: each delivery reaches the session's harness, and only it; every value it
/// prints is masked in the transcript (memory and disk) and in its failure reason; the files
/// are private and gone at the end.
#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: requires AINKRAD_TEST_RAMDIR on a verified RAM disk"
)]
async fn a_secret_reaches_only_its_session_and_never_its_transcript() {
    let (root, config) = dirs("secrets");
    let gate = root.join("go");
    let s = script(&format!(
        "echo \"env=$TOKEN\"; echo \"file=$(cat \"$TOKEN_FILE\")\"; echo \"askpass=$(sh \"$GIT_ASKPASS\")\"; \
         echo \"same=$ASKPASS\"; while [ ! -e '{}' ]; do sleep 0.05; done; echo \"$TOKEN\"; exit 3",
        gate.display()
    ));
    let d = Arc::new(
        AgentDriver::new(config.clone(), s)
            .unwrap()
            .with_redeem(leases()),
    );
    let mut req = start("as_a", "fake");
    req.secrets = grants();
    d.start(req).unwrap();
    // An unrelated session on the same runner, printing its whole environment.
    let other = Arc::new(AgentDriver::new(dirs("secrets-other").1, script("env")).unwrap());
    let mut seen = Vec::new();
    while seen.len() < 5 {
        let after = seen.last().map_or(0, |e: &TranscriptEntry| e.seq);
        seen.extend(
            d.read(&AgentRead {
                session: "as_a".into(),
                after,
                wait_ms: Some(2000),
            })
            .await
            .unwrap()
            .entries,
        );
    }
    let text = serde_json::to_string(&seen).unwrap();
    for (label, name) in [
        ("env", "test.env"),
        ("file", "test.file"),
        ("askpass", "test.askpass"),
    ] {
        let line = format!("{label}=[redacted:{name}]");
        assert!(
            text.contains(&line),
            "{label} was delivered and masked: {text}"
        );
    }
    // The files are 0600 in a 0700 dir; the helper is 0700 and holds no value.
    let dir = config.secrets_dir.join("as_a");
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&config.secrets_dir), 0o700);
    for f in std::fs::read_dir(&dir).unwrap().flatten() {
        let body = std::fs::read_to_string(f.path()).unwrap();
        if f.file_name().to_string_lossy().ends_with(".askpass") {
            assert_eq!(mode(&f.path()), 0o700);
            assert!(
                !body.contains(ASKPASS_VALUE),
                "the helper reads the file, never holds the value"
            );
        } else {
            assert_eq!(mode(&f.path()), 0o600);
        }
    }
    // Not in this (the runner's) process, nor in what it spawns, nor in another session.
    let runner_env: String = std::env::vars()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    let child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("env")
        .output()
        .unwrap();
    other.start(start("as_o", "fake")).unwrap();
    let (other_entries, _) = drain(&other, "as_o").await;
    let other_text = serde_json::to_string(&other_entries).unwrap();
    for v in [ENV_VALUE, FILE_VALUE, ASKPASS_VALUE] {
        assert!(
            !runner_env.contains(v),
            "the runner's own env holds a session's secret"
        );
        assert!(
            !String::from_utf8_lossy(&child.stdout).contains(v),
            "a sibling process got it"
        );
        assert!(!other_text.contains(v), "another session got it");
    }
    std::fs::write(&gate, "").unwrap();
    let (rest, ev) = drain(&d, "as_a").await;
    let all = serde_json::to_string(&[seen, rest]).unwrap() + &format!("{ev:?}");
    let disk = std::fs::read_dir(config.dir.join("as_a"))
        .unwrap()
        .flatten()
        .map(|f| std::fs::read_to_string(f.path()).unwrap_or_default())
        .collect::<String>();
    for v in [ENV_VALUE, FILE_VALUE, ASKPASS_VALUE] {
        assert!(
            !all.contains(v),
            "a value in the transcript or the outcome: {all}"
        );
        assert!(!disk.contains(v), "a value on disk beside the transcript");
    }
    assert!(
        matches!(&ev.outcome, Some(Outcome::Failed { reason, .. }) if reason == "[redacted:test.env]"),
        "the failure reason is masked too: {:?}",
        ev.outcome
    );
    assert!(!dir.exists(), "the session's secrets went with it");
    // A lease the runner cannot redeem fails the session, not the runner.
    let mut bad = start("as_b", "fake");
    bad.secrets = vec![SecretGrant {
        lease: "l_nope".into(),
        var: "X".into(),
    }];
    d.start(bad).unwrap();
    let (_, ev) = drain(&d, "as_b").await;
    assert!(matches!(ev.outcome, Some(Outcome::Failed { .. })));
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(dirs("secrets-other").0);
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: requires AINKRAD_TEST_RAMDIR on a verified RAM disk"
)]
async fn a_kill_removes_the_secrets_and_a_reserved_variable_is_refused() {
    let (root, config) = dirs("kill");
    let d = Arc::new(
        AgentDriver::new(config.clone(), script("sleep 30"))
            .unwrap()
            .with_redeem(leases()),
    );
    let mut req = start("as_a", "fake");
    req.secrets = grants();
    d.start(req).unwrap();
    let dir = config.secrets_dir.join("as_a");
    until("delivery", || dir.join("s1").exists()).await;
    d.stop(AgentStop {
        session: "as_a".into(),
        kill: true,
    })
    .unwrap();
    until("removal", || !dir.exists()).await;
    for var in [
        "PATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "lower",
        "A-B",
        "",
    ] {
        let mut req = start("as_b", "fake");
        req.secrets = vec![SecretGrant {
            lease: "l_env".into(),
            var: var.into(),
        }];
        assert_eq!(
            d.start(req).unwrap_err().code,
            ErrorCode::InvalidArgs,
            "{var}"
        );
    }
    assert_eq!(
        d.start(start("../x", "fake")).unwrap_err().code,
        ErrorCode::InvalidArgs
    );
    let _ = std::fs::remove_dir_all(root);
}

/// The other half of the next test: a runner process that delivers a file secret, says so,
/// and waits to be killed. Does nothing unless the parent test set `AGENT_KILL9_ROOT`.
#[tokio::test]
async fn kill9_helper() {
    let Some(root) = std::env::var_os("AGENT_KILL9_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let config = AgentConfig::new(root.join("agents"), root.join("secrets"));
    let d = Arc::new(
        AgentDriver::new(config, script("sleep 5"))
            .unwrap()
            .with_redeem(leases()),
    );
    let mut req = start("as_a", "fake");
    req.secrets = grants();
    d.start(req).unwrap();
    until("delivery", || root.join("secrets/as_a/s1").exists()).await;
    // A real orphan group with an environment secret must die before startup sweeps files.
    let mut orphan = std::process::Command::new("/bin/sh");
    use std::os::unix::process::CommandExt;
    let mut child = orphan
        .args(["-c", "sleep 600 & wait"])
        .env("ORPHAN_SECRET", ENV_VALUE)
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id();
    std::fs::write(
        root.join("agents/as_a/pgid"),
        ainkrad_harness::process_identity(pid).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("orphan-pid"), pid.to_string()).unwrap();
    println!("AGENT-KILL9-READY");
    tokio::time::sleep(Duration::from_secs(60)).await;
    child.kill().unwrap();
    child.wait().unwrap();
}

/// A runner killed with SIGKILL removes nothing; the next one to start removes it all, and
/// finds the session interrupted.
#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: requires AINKRAD_TEST_RAMDIR on a verified RAM disk"
)]
async fn after_a_kill_9_the_next_runner_removes_the_secrets() {
    let (root, config) = dirs("kill9");
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v2::agent::tests::kill9_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("AGENT_KILL9_ROOT", &root)
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        while let Ok(Some(l)) = lines.next_line().await {
            if l.contains("AGENT-KILL9-READY") {
                return true;
            }
        }
        false
    });
    assert!(ready.await.unwrap(), "the helper delivered its secrets");
    child.start_kill().unwrap(); // SIGKILL
    child.wait().await.unwrap();
    let file = config.secrets_dir.join("as_a/s1");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        FILE_VALUE,
        "a kill -9 cleans nothing up"
    );
    let next = AgentDriver::new(config.clone(), script("true")).unwrap();
    assert!(
        !config.secrets_dir.join("as_a").exists(),
        "the next runner removed them"
    );
    assert_eq!(std::fs::read_dir(&config.secrets_dir).unwrap().count(), 0);
    assert_eq!(next.states()["as_a"], AgentState::Interrupted);
    let pid = std::fs::read_to_string(root.join("orphan-pid")).unwrap();
    until("whole orphan group gone", || {
        let ps = std::process::Command::new("ps")
            .args(["-A", "-o", "pgid=,stat="])
            .output()
            .unwrap();
        !String::from_utf8_lossy(&ps.stdout).lines().any(|line| {
            let mut cols = line.split_whitespace();
            cols.next() == Some(pid.trim()) && !cols.next().unwrap_or("").starts_with('Z')
        })
    })
    .await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_stale_process_record_cannot_kill_an_unrelated_group() {
    use std::os::unix::process::CommandExt;
    let (root, config) = dirs("stale-pid");
    let mut unrelated = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = unrelated.id();
    let dir = config.dir.join("as_stale");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pgid"), format!("{pid}:wrong-start-time")).unwrap();
    let _driver = AgentDriver::new(config, script("true")).unwrap();
    assert!(
        unrelated.try_wait().unwrap().is_none(),
        "a recycled pid was killed"
    );
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn requested_isolation_never_falls_back_to_unconfined() {
    let mut request = start("as_closed", "fake");
    request.policy.sandboxed = true;
    assert!(Unconfined.prepare(&request, &mut vec![]).is_err());
}
