//! An agent waiting on its own background job (the Workan.Space trial): short `sleep`s, `date`,
//! and `until`/`while` loops of allowed commands go ahead without a reviewer; anything else in
//! them still asks.

use ainkrad_proto::runner::PermissionMode;

use super::*;

#[test]
fn polling_a_background_job_goes_ahead() {
    let ex = HarnessExecutor::new(PathBuf::from("/w"), PathBuf::from("/c"));
    let cwd = Path::new("/w/run-7");
    let policy = Policy {
        mode: PermissionMode::Ask,
        allow: ["Bash:grep", "Bash:cat", "Bash:tail"]
            .map(str::to_owned)
            .to_vec(),
        sandboxed: false,
        ..Policy::default()
    };
    let ok = |p: &Policy, tool, c: &str| ex.decide(p, tool, &json!({"command": c}), cwd).is_ok();
    for allowed in [
        r#"until grep -q "ALL DONE" wrk3-dod/summary.log; do sleep 15; done; cat wrk3-dod/summary.log"#,
        r#"sleep 280; grep -E "e2e|collection" wrk3-dod/summary.log"#,
        "sleep 5; date +%T; tail -c 600 x.log",
        "while grep -q RUNNING x.log; do sleep 2m; done",
        "until grep -q DONE x.log\ndo\n  sleep 0.5\ndone\ntail -5 x.log",
        "sleep 300s && date -u +%s",
        "true; tail x.log | wc -l",
    ] {
        assert!(ok(&policy, "Bash", allowed), "{allowed}");
    }
    for refused in [
        "sleep 99999",
        "sleep 301",
        "sleep 6m",
        "sleep 1h",
        "sleep inf",
        "sleep 1 2",
        "date -s 0101",
        "date -f /etc/passwd",
        "until rm -rf x; do sleep 1; done",
        "until grep -q x f; do rm -rf x; done",
        "until grep -q x $(ls); do sleep 1; done",
        "until grep -q x f; do sleep $(echo 1); done",
        "while true; do curl x; done",
        "while true; do until true; do sleep 1; done; done",
        "until grep -q x f; do sleep 1",
        "do sleep 1; done",
        "sleep 1; done",
        "until grep -q x f; do sleep 1; done | sh",
        "until grep -q x f; do sleep 1; done > out",
        "for i in 1 2; do sleep 1; done",
        "f() { sleep 1; }; f",
        "wc -l /etc/passwd",
        // A rule never reaches outside the workspace: the log is polled by a relative path.
        "tail /tmp/x.log",
        "until grep -q DONE /tmp/x.log; do sleep 1; done",
        "cat ../x.log",
    ] {
        assert!(!ok(&policy, "Bash", refused), "{refused}");
    }
    // A shell's harmless wait needs no rule; another tool's command does.
    let none = Policy::default();
    assert!(ok(&none, "Bash", "sleep 15; date +%T"));
    assert!(ok(&none, "bash", "sleep 15"));
    assert!(ok(&none, "commandExecution", "/bin/zsh -lc 'sleep 15'"));
    assert!(!ok(&none, "Bash", "sleep 15; cat /tmp/x.log"));
    assert!(!ok(&none, "Other", "sleep 15"));
}
