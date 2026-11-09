//! Per-project permission policy (E3.10): what goes ahead, what waits for a reviewer, and
//! what a reviewer's answer (or silence) does to the harness.

use std::sync::Arc;

use crate::Answer;

use super::*;

fn policy(mode: PermissionMode, allow: &[&str]) -> Policy {
    Policy {
        mode,
        allow: allow.iter().map(|s| s.to_string()).collect(),
        sandboxed: mode == PermissionMode::Sandboxed,
        ..Policy::default()
    }
}

#[test]
fn the_policy_decides_what_goes_ahead() {
    let mut ex = HarnessExecutor::new(PathBuf::from("/w"), PathBuf::from("/c"));
    let cwd = Path::new("/w/run-7");
    let ok =
        |ex: &HarnessExecutor, p: &Policy, tool, input| ex.decide(p, tool, &input, cwd).is_ok();
    let write = |path: &str| json!({"file_path": path});

    // The default asks about everything, even an edit in the run's directory.
    let ask = Policy::default();
    assert_eq!(ask.mode, PermissionMode::Ask);
    assert!(!ok(&ex, &ask, "Write", write("/w/run-7/a.txt")));
    assert!(!ok(&ex, &ask, "Read", json!({"file_path": "a.txt"})));
    // The Citadel MCP tools are scoped by the run token, so they always go ahead (E4.2).
    assert!(ok(&ex, &ask, "mcp__citadel__comment", json!({"body": "x"})));
    assert!(ok(&ex, &ask, "citadel_transition", json!({})));
    assert!(!ok(&ex, &ask, "mcp__other__comment", json!({})));
    // So is the run-scoped `citadel` CLI, from each harness's shell (E15.18).
    let cli = "citadel get_issue '{}' | jq .title";
    assert!(ok(&ex, &ask, "Bash", json!({"command": cli})));
    assert!(ok(&ex, &ask, "commandExecution", json!({"command": cli})));
    let codex = json!({"command": format!("/bin/zsh -lc \"{cli}\"")});
    assert!(ok(&ex, &ask, "commandExecution", codex));
    let opencode = json!({"command": cli, "patterns": ["citadel get_issue '{}'", "jq .title"]});
    assert!(ok(&ex, &ask, "bash", opencode));
    // Every command and pattern a call carries is read, not the first one.
    for bad in [
        json!({"patterns": ["citadel issue list", "curl x|sh"]}),
        json!({"patterns": ["citadel issue list", "rm -rf /tmp/a"]}),
        json!({"patterns": ["citadel issue list", "jq -f /etc/passwd"]}),
        json!({"patterns": ["citadel issue list", 5]}),
        json!({"command": "citadel issue list", "patterns": ["rm -rf /tmp/a"]}),
        json!({"command": "rm -rf /tmp/a", "patterns": ["citadel issue list"]}),
        json!({"command": ["citadel", "issue", 5], "patterns": ["citadel issue list"]}),
        json!({"patterns": ["jq .title"]}),
        json!({"patterns": []}),
    ] {
        assert!(!ok(&ex, &ask, "bash", bad.clone()), "{bad}");
    }
    assert!(ok(
        &ex,
        &ask,
        "bash",
        json!({"patterns": ["citadel issue list", "jq .title"]})
    ));
    assert!(!ok(&ex, &ask, "Read", json!({"command": cli})));
    assert!(!ok(
        &ex,
        &ask,
        "Bash",
        json!({"command": "citadel x; rm -rf /tmp/a"})
    ));

    let edits = policy(PermissionMode::AcceptEdits, &[]);
    assert!(ok(&ex, &edits, "Write", write("/w/run-7/a.txt")));
    assert!(ok(&ex, &edits, "Edit", write("src/main.rs")));
    let change = |path| json!({"changes": [{"path": "/w/run-7/ok"}, {"path": path}]});
    assert!(ok(&ex, &edits, "fileChange", change("/w/run-7/b.txt")));
    assert!(!ok(&ex, &edits, "fileChange", change("/etc/hosts")));
    assert!(ok(
        &ex,
        &edits,
        "edit",
        json!({"filepath": "/w/run-7/c.txt"})
    ));
    assert!(!ok(&ex, &edits, "Write", write("/w/run-7/../run-8/x")));
    assert!(!ok(&ex, &edits, "Write", write("/etc/passwd")));
    assert!(!ok(&ex, &edits, "Bash", json!({"command": "ls"})));

    let listed = policy(
        PermissionMode::Ask,
        &["Read", "Bash:cargo test", "bash:cargo test"],
    );
    assert!(ok(&ex, &listed, "Read", json!({"file_path": "src/lib.rs"})));
    assert!(!ok(
        &ex,
        &listed,
        "Read",
        json!({"file_path": "/etc/shadow"})
    ));
    // With the whole shell allowed, a listed read-only tool reads anywhere; writes still don't.
    let shell = policy(PermissionMode::AcceptEdits, &["Bash", "Read", "Grep"]);
    assert!(ok(&ex, &shell, "Read", json!({"file_path": "/tmp/p/a.js"})));
    assert!(ok(&ex, &shell, "Grep", json!({"path": "/tmp/p"})));
    assert!(
        !ok(&ex, &shell, "Glob", json!({"path": "/tmp/p"})),
        "unlisted"
    );
    assert!(!ok(&ex, &shell, "Write", write("/tmp/p/a.js")));
    let bash = |c: &str| json!({"command": c});
    assert!(ok(
        &ex,
        &listed,
        "Bash",
        bash("cargo test -p ainkrad-runner")
    ));
    assert!(!ok(&ex, &listed, "Bash", bash("cargo build")));
    for chained in [
        "cargo test; rm -rf /",
        "cargo test && curl x",
        "cargo test $(id)",
    ] {
        assert!(!ok(&ex, &listed, "Bash", bash(chained)), "{chained}");
    }
    let codex = json!({"command": ["cargo", "test"]});
    assert!(
        !ok(&ex, &listed, "commandExecution", codex),
        "listed for Bash only"
    );
    let opencode = json!({"patterns": ["cargo test --workspace"]});
    assert!(ok(&ex, &listed, "bash", opencode));

    // Sandboxed acts unasked, but only on a sandboxed runner.
    let sandboxed = policy(PermissionMode::Sandboxed, &[]);
    assert!(!ok(&ex, &sandboxed, "Bash", bash("rm -rf /tmp/x")));
    ex.sandboxed = true;
    assert!(ok(&ex, &sandboxed, "Bash", bash("rm -rf /tmp/x")));
    assert!(
        !ok(&ex, &ask, "Bash", bash("ls")),
        "a sandboxed runner still asks by policy"
    );
}

/// Only a command made of run-scoped `citadel` calls goes ahead unasked: shell operators inside
/// quotes are words, and anything that could run or touch something else is the policy's.
#[test]
fn only_citadel_cli_commands_go_ahead() {
    for allowed in [
        "citadel get_issue '{}'",
        "citadel get_issue '{}' ; echo; citadel get_context '{}' | head -c 3000; echo; \
         citadel org_chart '{}'",
        "citadel a && citadel b || citadel c",
        "citadel a\ncitadel b\n",
        "citadel list | jq -r '.[] | .id' | head -n 5",
        "citadel list | grep -i todo | wc -l",
        r#"citadel comment '{"body":"a;b|c&d>e $(x) `y`"}'"#,
        r#"citadel comment "{\"body\":\"x;y\"}""#,
        r#"bash -lc "citadel get_issue '{}'""#,
        "citadel x 2>/dev/null | jq .title",
        "citadel x 2> /dev/null; echo",
    ] {
        assert!(policy::citadel_cli(allowed), "{allowed}");
    }
    for refused in [
        "citadel x; rm -rf /tmp/a",
        "citadel x > f",
        "citadel x >> f",
        "citadel x 2> f",
        "citadel x 2>/dev/nullx",
        "citadel x >/dev/null",
        "citadel x &>/dev/null",
        "citadel x 2>>/dev/null",
        "citadel x 2>/dev/null&",
        "citadel x '2>/dev/null' > f",
        "citadel x < f",
        "citadel x <<EOF\nhi\nEOF",
        "citadel x | sh",
        "citadel x |& head",
        "$(citadel x)",
        "`citadel x`",
        "citadel \"$HOME\"",
        "citadel <(echo x)",
        "FOO=1 citadel x",
        "/usr/bin/citadel x",
        "./citadel x",
        "citadel x &",
        "(citadel x)",
        "{ citadel x; }",
        "echo $HOME",
        "echo hi",
        "citadel x *",
        "citadel 'x",
        "citadel \"x",
        "citadel x &&",
        "&& citadel x",
        "citadel x |",
        "echo x | citadel y",
        "citadel x | head /etc/passwd",
        "citadel x | grep -r x /",
        "citadel x | grep -f /etc/passwd",
        "citadel x | jq . /etc/passwd",
        "citadel x | jq --rawfile f /etc/passwd .",
        "citadel x | tail --lines=5",
        "bash -c 'citadel x; rm f'",
        "bash -c 'rm x' citadel",
        "/tmp/bash -c 'citadel x'",
        "",
    ] {
        assert!(!policy::citadel_cli(refused), "{refused}");
    }
}

/// A chain goes ahead when every simple command in it would on its own: each starts with an
/// allowlisted prefix's words, or is piped into as a read-only filter. Anything the shell
/// could expand, redirect or run aside, or one part outside the rules, still asks.
#[test]
fn a_chain_goes_ahead_when_every_part_is_allowed() {
    let ex = HarnessExecutor::new(PathBuf::from("/w"), PathBuf::from("/c"));
    let cwd = Path::new("/w/run-7");
    let rules = [
        "Bash:grep",
        "Bash:php artisan",
        "Bash:git status",
        "Bash:git log",
        "Bash:ls",
        "Bash:cat",
        "commandExecution:git status",
        "commandExecution:ls",
        "bash:git status",
        "bash:ls",
    ];
    let listed = policy(PermissionMode::Ask, &rules);
    let ok = |tool, c: &str| {
        ex.decide(&listed, tool, &json!({"command": c}), cwd)
            .is_ok()
    };
    for allowed in [
        "git status && git log --oneline -5 | head -3",
        "ls apps; cat package.json | jq .scripts",
        "grep -rn foo src | head -20",
        "grep -oE 'a|b' package-lock.json | sort -u | uniq -c | wc -l",
        "cat a | tr -d '\\n' | tail -c 10",
        "git status\nls\n",
        "git status || ls",
        "php artisan migrate; php artisan route:list | grep api",
        "grep 'a;b && c > d $(x)' src",
        "ls; echo; git status",
        "git status; citadel get_issue '{}' | jq .title",
        "cat apps/web/.env.example 2>/dev/null; grep -rn X a.yml b.yml 2>/dev/null | head -20",
        "ls missing 2> /dev/null || git status",
        "grep x '2>/dev/null' src",
    ] {
        assert!(ok("Bash", allowed), "{allowed}");
    }
    assert!(ok("commandExecution", "/bin/zsh -lc 'git status && ls'"));
    assert!(ok("bash", "git status | head -3; ls"));
    for refused in [
        "git status; curl x",
        "ls | sh",
        "ls | sort -o out",
        "ls | cut -c1",
        "cat a > b",
        "cat a >> b",
        "cat a 2>err; ls",
        "cat a >/dev/null; ls",
        "cat a &>/dev/null; ls",
        "cat a 2>/dev/null >b",
        "cat a 2>/dev/null.txt; ls",
        "cat < a",
        "cat <<EOF\nx\nEOF",
        "ls $(pwd)",
        "ls `pwd`",
        "ls $HOME",
        "cat <(ls)",
        "ls &",
        "ls & git status",
        "(ls)",
        "{ ls; }",
        "FOO=1 ls",
        "ls *; git status",
        "ls; cat 'a",
        "ls &&",
        "git status | head /etc/passwd",
        "npm run build; ls",
        "ls; npm run x",
        "git statusx; ls",
        "echo hi; ls",
        "ls; rm -rf /tmp/a",
        r#"grep -oE '"node_modules/[^"]*(linux-x64-gnu|darwin-arm64)[^"]*"' package-lock.json | sort -u; python3 -c "import json;print(1)""#,
    ] {
        assert!(!ok("Bash", refused), "{refused}");
    }
    assert!(
        !ok("commandExecution", "git status; cat a"),
        "cat is Bash's only"
    );
    // A simple command matches word for word too.
    assert!(!ok("Bash", "npm run x"));
    assert!(!ok("Bash", "git statusx"));
}

#[tokio::test]
async fn a_sandboxed_project_needs_a_sandboxed_runner() {
    let dir = scratch("sandbox-policy");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    let contained = Job {
        policy: Policy {
            sandboxed: true,
            ..Policy::default()
        },
        ..job("claude")
    };
    let why = ex.start(&contained).await.unwrap_err();
    assert!(why.contains("must be sandboxed"), "{why}");
    ex.sandboxed = true;
    assert!(ex.start(&contained).await.is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake `claude` that plays the recorded write's approval request and keeps what it is
/// sent, so the answer can be read back.
fn fake_claude(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\n\
             sed '/\"type\":\"result\"/q' {d}/fixture.ndjson\ncat > {d}/stdin\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// What the run sent Claude for the recorded approval.
fn answer(dir: &Path) -> Value {
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    stdin
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|m| m["type"] == "control_response")
        .expect("no answer sent")["response"]["response"]
        .clone()
}

/// The recorded write is outside the default policy: it is escalated, the run waits, and
/// the reviewer's answer reaches Claude: approve lets it through, deny passes the reply.
#[tokio::test]
async fn an_escalated_call_waits_for_the_reviewer() {
    for (approved, reply) in [(true, None), (false, Some("not in this sprint"))] {
        let dir = scratch(&format!("escalate-{approved}"));
        let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
        ex.bins.insert("claude".to_owned(), fake_claude(&dir));
        let ex = Arc::new(ex);
        let job = job("claude");
        ex.start(&job).await.unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let running = {
            let (ex, job) = (ex.clone(), job.clone());
            tokio::spawn(async move { ex.run(&job, RunToken::new("t".to_owned()), tx).await })
        };
        let (tool, input, to) = loop {
            match rx.recv().await.expect("no escalation") {
                Report::Approval {
                    tool,
                    input,
                    reply,
                    timeout_secs,
                    ..
                } => {
                    assert_eq!(timeout_secs, ainkrad_proto::runner::APPROVAL_TIMEOUT_SECS);
                    break (tool, input, reply);
                }
                _ => continue,
            }
        };
        assert_eq!(tool, "Write");
        assert_eq!(input["file_path"], "/tmp/citadel-fixture/work/hello.txt");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!running.is_finished(), "the run did not wait");
        let reply = reply.map(str::to_owned);
        to.send(Answer { approved, reply });
        assert_eq!(running.await.unwrap(), Outcome::Succeeded);
        let sent = answer(&dir);
        if approved {
            assert_eq!(sent["behavior"], "allow", "{sent}");
        } else {
            assert_eq!(sent["behavior"], "deny", "{sent}");
            assert_eq!(sent["message"], "not in this sprint");
        }
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        assert!(argv.contains("--permission-mode\ndefault\n"), "{argv}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Nobody answers: the call is denied with a reason once the wait runs out.
#[tokio::test]
async fn an_unanswered_escalation_is_denied_on_timeout() {
    let dir = scratch("escalate-timeout");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), fake_claude(&dir));
    ex.approval_timeout = Duration::from_millis(100);
    let job = job("claude");
    ex.start(&job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);
    let sent = answer(&dir);
    assert_eq!(sent["behavior"], "deny");
    let reason = sent["message"].as_str().unwrap();
    assert!(reason.contains("none answered within 100ms"), "{reason}");
    let decided = chunks(&mut rx)
        .into_iter()
        .find(|e| e["type"] == "approval_decided")
        .unwrap();
    assert_eq!(decided["approved"], false);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Citadel MCP tool is scoped by the run token: the harness's request for it is allowed at
/// once, with no approval in the transcript and none sent to the server.
#[tokio::test]
async fn a_citadel_tool_is_allowed_without_an_approval() {
    let cli = r#""tool_name":"Bash","display_name":"Bash","input":{"command":"citadel get_issue '{}' ; echo; citadel get_context '{}' | head -c 3000; echo; citadel org_chart '{}'"}"#;
    for (name, call) in [
        ("citadel-tool", r#""tool_name":"mcp__citadel__get_issue""#),
        ("citadel-cli", cli),
    ] {
        citadel_call_is_allowed(name, call).await;
    }
}

/// A chain whose every part the policy allows goes ahead without asking a reviewer.
#[tokio::test]
async fn an_allowed_chain_is_not_escalated() {
    let chain = r#""tool_name":"Bash","display_name":"Bash","input":{"command":"git status && git log --oneline -5 | head -3; ls apps"}"#;
    let job = Job {
        policy: policy(
            PermissionMode::Ask,
            &["Bash:git status", "Bash:git log", "Bash:ls"],
        ),
        ..job("claude")
    };
    let types = allowed_without_asking("allowed-chain", chain, &job, None).await;
    assert!(types.iter().any(|t| t == "approval_decided"), "{types:?}");
}

/// The admin changed the project's policy after the run was assigned (1.24): the next call is
/// decided by the new rules, with no reviewer asked.
#[tokio::test]
async fn a_policy_update_decides_the_next_call() {
    let sleep = r#""tool_name":"Bash","display_name":"Bash","input":{"command":"git fetch origin && sleep 15; date +%T"}"#;
    let update = policy(PermissionMode::Ask, &["Bash:git fetch"]);
    let types = allowed_without_asking("policy-update", sleep, &job("claude"), Some(update)).await;
    assert!(types.iter().any(|t| t == "approval_decided"), "{types:?}");
}

/// Plays the recorded approval request with `call` in place of its `Write`.
async fn citadel_call_is_allowed(name: &str, call: &str) {
    let types = allowed_without_asking(name, call, &job("claude"), None).await;
    assert!(
        !types.iter().any(|t| t.starts_with("approval_")),
        "{types:?}"
    );
}

/// Plays the recorded approval request with `call` in place of its `Write` and checks it is
/// allowed with no reviewer asked; the run's event types. `update` is a `PolicyUpdate` the
/// run gets before the call.
async fn allowed_without_asking(
    name: &str,
    call: &str,
    job: &Job,
    update: Option<Policy>,
) -> Vec<String> {
    let dir = scratch(name);
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), fake_claude(&dir));
    // An escalated call fails the test rather than hang it.
    ex.approval_timeout = Duration::from_millis(100);
    let write = r#""tool_name":"Write","display_name":"Write","input":{"file_path":"/tmp/citadel-fixture/work/hello.txt","content":"hi"}"#;
    let fixture = FIXTURE.replace(write, call);
    assert_ne!(fixture, FIXTURE);
    std::fs::write(dir.join("fixture.ndjson"), fixture).unwrap();
    ex.start(job).await.unwrap();
    if let Some(policy) = update {
        ex.control(job.run, crate::Control::Policy(policy));
    }
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert_eq!(answer(&dir)["behavior"], "allow");
    let reports: Vec<Report> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        !reports.iter().any(|r| matches!(r, Report::Approval { .. })),
        "{name} was escalated"
    );
    let types: Vec<String> = reports
        .into_iter()
        .filter_map(|r| match r {
            Report::Event(e) => e["type"].as_str().map(str::to_owned),
            _ => None,
        })
        .collect();
    assert!(types.iter().any(|t| t == "turn_ended"), "{types:?}");
    assert!(
        !types.iter().any(|t| t == "approval_escalated"),
        "{types:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    types
}

/// Every command a rule can never cover is refused by BOTH ways a rule can allow a call: the
/// whole-call match (`allows`) and the chain check (`chain_allowed`); a stored rule that is not a
/// legal rule is re-checked at use on both. The controls prove each path does allow a covered call.
#[test]
fn a_rule_never_covers_a_destructive_or_wrapped_call_on_either_path() {
    use super::super::policy::chain_allowed;
    let ex = HarnessExecutor::new(PathBuf::from("/w"), PathBuf::from("/c"));
    let cwd = Path::new("/w/run-7");
    // (rule, tool, command)
    let cases = [
        ("Bash:git push", "Bash", "git push --force"),
        ("Bash:git push", "Bash", "git push --del origin x"),
        ("Bash:git push", "Bash", "git push --mirr"),
        ("Bash:git push", "Bash", "GIT_SSH_COMMAND=x git push"),
        ("Bash:git push", "Bash", "git push origin +main"),
        ("Bash:git", "Bash", "git -c core.sshCommand=x push"),
        ("Bash:rm", "Bash", "rm -rf /"),
        ("Bash:rm", "Bash", "RM -rf x"),
        ("Bash:rm", "Bash", "rm --recur x"),
        ("Bash:cargo", "Bash", "RUSTC_WRAPPER=x cargo build"),
        ("Bash:cargo", "Bash", "cargo -Zunstable-options build"),
        ("Bash:cargo", "Bash", "cargo build --conf x=y"),
        ("Bash:sudo", "Bash", "sudo ls"),
        ("Bash:cargo test", "Bash", "SUDO ls"),
        ("Bash:cargo test", "Bash", "BASH -c 'rm -rf x'"),
        // Stored before the check existed, or inserted directly.
        (
            "commandExecution:bash -lc",
            "commandExecution",
            "bash -lc 'rm -rf ~' x",
        ),
        (
            "commandExecution:bash -lc",
            "commandExecution",
            "bash -lc ls",
        ),
        ("Bash:sh -c", "Bash", "sh -c ls"),
        ("Bash:env", "Bash", "env ls"),
        ("Bash:xargs", "Bash", "xargs ls"),
        ("Bash:python3 -c", "Bash", "python3 -c x"),
        ("Bash:FOO=1 git", "Bash", "FOO=1 git status"),
        ("Bash:git push --force", "Bash", "git push --force"),
        ("Bash:rm -rf", "Bash", "rm -rf x"),
    ];
    for (rule, tool, command) in cases {
        let p = policy(PermissionMode::Ask, &[rule]);
        let input = json!({"command": command});
        assert!(
            ex.decide(&p, tool, &input, cwd).is_err(),
            "decide: {rule} {command}"
        );
        let rules: Vec<Vec<String>> = ainkrad_proto::runner::rule_prefix(rule, tool)
            .into_iter()
            .collect();
        assert!(!chain_allowed(&rules, command), "chain: {rule} {command}");
        // Chained after a covered command, a destructive part still stops the chain.
        let chained = format!("{command} && ls");
        let rules: Vec<Vec<String>> = ainkrad_proto::runner::rule_prefix(rule, tool)
            .into_iter()
            .collect();
        assert!(
            !chain_allowed(&rules, &chained),
            "chain&&: {rule} {command}"
        );
    }
    // Controls.
    for (rule, command) in [
        ("Bash:git push", "git push origin main"),
        ("Bash:cargo test", "cargo test -p x"),
        ("Bash:cargo test", "bash -lc 'cargo test -p x' y"),
    ] {
        let p = policy(PermissionMode::Ask, &[rule]);
        assert!(
            ex.decide(&p, "Bash", &json!({"command": command}), cwd)
                .is_ok(),
            "{command}"
        );
        let rules: Vec<Vec<String>> = ainkrad_proto::runner::rule_prefix(rule, "Bash")
            .into_iter()
            .collect();
        assert!(chain_allowed(&rules, command), "chain: {command}");
    }
    let rules: Vec<Vec<String>> = ainkrad_proto::runner::rule_prefix("Bash:cargo test", "Bash")
        .into_iter()
        .collect();
    assert!(chain_allowed(&rules, "cargo test -p x && cargo test -p y"));
    assert!(!chain_allowed(&rules, "cargo test -p x && cargo build"));
}

/// The review's list of spellings that run something else: none is on the allowlist, so on both
/// matching paths (whole call and chain) they only ever escalate, whatever rules exist.
#[test]
fn what_is_not_on_the_allowlist_escalates_on_both_paths() {
    use super::super::policy::chain_allowed;
    let ex = HarnessExecutor::new(PathBuf::from("/w"), PathBuf::from("/c"));
    let cwd = Path::new("/w/run-7");
    let rules = [
        "Bash:ls",
        "Bash:cargo test",
        "Bash:git status",
        "Bash:echo",
        "Bash:python3 a.py",
        "Bash:grep",
    ];
    let p = policy(PermissionMode::Ask, &rules);
    let usable: Vec<Vec<String>> = rules
        .iter()
        .filter_map(|r| ainkrad_proto::runner::rule_prefix(r, "Bash"))
        .collect();
    assert_eq!(usable.len(), rules.len());
    for c in [
        "=bash -c ls",
        "=ls",
        "- rm -rf x",
        "noglob rm x",
        "nocorrect rm x",
        "then rm -rf x",
        "npm exec rm",
        "bundle exec rm",
        "docker run x",
        "rg --pre rm x",
        "fd -x rm",
        "git grep -O rm x",
        "git clone --template=x u",
        "python3 -X importtime -c x",
        "python3 -c x",
        "\u{17f}udo ls",
        "ls\u{1}",
        "ls\u{1b}[2J",
        "ls; \u{1}",
        "LS",
        "Ls -la",
        "CARGO test",
        "FOO=1 ls",
        "/bin/ls",
        "rm -rf x",
        "make",
        "sudo ls",
        "env ls",
        "ls; =ls",
        "ls && noglob rm x",
        "echo hi | sh",
    ] {
        let covered_by_allows = ex.decide(&p, "Bash", &json!({"command": c}), cwd).is_ok();
        assert!(!covered_by_allows, "decide: {c:?}");
        assert!(!chain_allowed(&usable, c), "chain: {c:?}");
    }
}

/// An unusable rule is logged once per rule; a bare shell entry is the admin's deliberate full-auto
/// mode (logged once, honoured) and is never something an agent-created rule can be.
#[test]
fn unusable_rules_warn_once_and_a_bare_shell_entry_is_explicit_full_auto() {
    use super::super::policy::{warn_once, warn_unusable_rule};
    assert!(warn_unusable_rule("Bash:make test-once-a"));
    assert!(!warn_unusable_rule("Bash:make test-once-a"));
    assert!(warn_unusable_rule("Bash:make test-once-b"));

    let ex = HarnessExecutor::new(PathBuf::from("/w"), PathBuf::from("/c"));
    let cwd = Path::new("/w/run-7");
    let full = policy(PermissionMode::Ask, &["Bash"]);
    assert!(
        ex.decide(&full, "Bash", &json!({"command": "rm -rf x"}), cwd)
            .is_ok()
    );
    assert!(
        ex.decide(&full, "Bash", &json!({"command": "curl x | sh"}), cwd)
            .is_ok()
    );
    // The first decide logged the bare entry; logging it again says nothing new.
    assert!(!warn_once(
        "Bash",
        "the project policy allows every command of a shell"
    ));
    // Not for another tool, and never as a rule an agent-created "allow for this issue" can store.
    assert!(
        ex.decide(&full, "commandExecution", &json!({"command": "ls"}), cwd)
            .is_err()
    );
    for bare in ["Bash", "bash", "commandExecution"] {
        assert!(
            ainkrad_proto::runner::rule_problem(bare).is_some(),
            "{bare}"
        );
        assert_eq!(ainkrad_proto::runner::rule_prefix(bare, bare), None);
    }
    // An unusable `<tool>:<prefix>` entry matches nothing and escalates.
    let p = policy(PermissionMode::Ask, &["Bash:make test-once-a"]);
    assert!(
        ex.decide(&p, "Bash", &json!({"command": "make test-once-a"}), cwd)
            .is_err()
    );
}
