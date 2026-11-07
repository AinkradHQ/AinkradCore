//! More `connection …` tests: wrong usage, secrets kept off the command line, the step-up flow,
//! JSON mode and `agent run --connection-access`.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::common::*;
use crate::connections::{CONN_LINES, fails, ok, run};
use crate::connections_fake::*;
use crate::scheduler_fake::{DEVICE, device};

#[test]
fn wrong_usage_exits_2_and_sends_nothing() {
    let (fake, ks) = device("cn-usage", conns, false);
    let no_token = &[("AINKRAD_CONNECTION_TOKEN", "")];
    for (w, stdin) in [
        (&["connection"][..], ""),
        (&["connection", "nope"], ""),
        (&["connection", "show"], ""),
        (&["connection", "show", "x"], ""),
        (&["connection", "show", "0"], ""),
        (&["connection", "ls", "--kind", "Git/Hub"], ""),
        (&["connection", "add"], ""),
        (&["connection", "add", "Bad Kind"], "tok"),
        (&["connection", "add", "github"], ""),
        (
            &[
                "connection",
                "add",
                "github",
                "--token-file",
                "/nonexistent/x",
            ],
            "",
        ),
        (&["connection", "credential", "3"], "\n"),
        (&["connection", "rename", "3"], ""),
        (&["connection", "grant", "3", "agent", "bot"], ""),
        (
            &["connection", "grant", "3", "team", "bot", "--caps", "a"],
            "",
        ),
        (
            &["connection", "grant", "3", "agent", "a/b", "--caps", "a"],
            "",
        ),
        (
            &["connection", "grant", "3", "agent", "bot", "--caps", ","],
            "",
        ),
        (
            &["connection", "grant", "3", "agent", "bot", "--caps", "*"],
            "",
        ),
        (
            &[
                "connection",
                "grant",
                "3",
                "agent",
                "bot",
                "--caps",
                "a",
                "--limit",
                "nokey",
            ],
            "",
        ),
        (
            &[
                "connection",
                "grant",
                "3",
                "agent",
                "bot",
                "--caps",
                "a",
                "--limit",
                "k=",
            ],
            "",
        ),
        (&["connection", "revoke", "3", "agent"], ""),
        (&["connection", "default", "github", "x"], ""),
        (&["connection", "default", "github", "3", "--clear"], ""),
        (&["connection", "default", "--clear"], ""),
        (&["connection", "activity", "3", "--limit", "many"], ""),
        (&["connection", "app", "github", "set"], ""),
        (
            &["connection", "app", "github", "set", "--field", "novalue"],
            "",
        ),
        (
            &[
                "connection",
                "login",
                "github",
                "--callback-url",
                "http://x/?code=a",
            ],
            "",
        ),
        (&["connection", "login", "github", "--connection", "x"], ""),
        (
            &["agent", "run", DEVICE, "claude", "--connection-access", ""],
            "",
        ),
        (
            &["agent", "run", DEVICE, "claude", "--connection-access", ","],
            "",
        ),
        (
            &[
                "agent",
                "run",
                DEVICE,
                "claude",
                "--connection-access",
                "read_repo,*",
            ],
            "",
        ),
    ] {
        let o = run(&ks, w, stdin, no_token);
        assert_eq!(o.status.code(), Some(2), "{w:?}: {o:?}");
        assert!(!text(&o).1.is_empty() && stdout(&o).is_empty(), "{w:?}");
    }
    assert_eq!(
        fake.requests().len(),
        0,
        "usage errors reach no route, not even a handshake"
    );
}

#[test]
fn an_app_secret_on_the_command_line_is_refused_before_it_is_sent() {
    let (fake, ks) = device("cn-appsecret", conns, false);
    let o = run(
        &ks,
        &[
            "connection",
            "app",
            "github",
            "set",
            "--field",
            "client_secret=HUNTER2",
        ],
        "",
        &[],
    );
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    let (out, err) = text(&o);
    assert!(
        err.contains("client_secret is secret") && !format!("{out}{err}").contains("HUNTER2"),
        "{err}"
    );
    assert!(matching(&fake, "put /api/v1/connection-apps").is_empty());
}

#[test]
fn a_token_on_the_command_line_works_but_is_warned_about_and_not_echoed() {
    let (fake, ks) = device("cn-argv", conns, false);
    let o = run(
        &ks,
        &["connection", "add", "github", "--token", "ARGV-TOKEN-1"],
        "",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    let (out, err) = text(&o);
    assert!(err.contains("warning: --token"), "{err}");
    assert!(!format!("{out}{err}").contains("ARGV-TOKEN-1"));
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/connections ")[0])["token"],
        json!("ARGV-TOKEN-1")
    );
}

#[test]
fn a_step_up_is_done_once_and_the_write_retried_once() {
    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("cn-step", gated, true);
    let o = run(&ks, &["connection", "add", "github"], "tok", &[]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), CONN_LINES);
    assert_eq!(matching(&fake, "post /api/v1/connections ").len(), 2);
    assert_eq!(matching(&fake, "post /api/v1/auth/step-up ").len(), 1);

    // No step-up key: exit 9, the write tried once, no step-up sent.
    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("cn-nokey", gated, false);
    let o = run(&ks, &["connection", "add", "github"], "tok", &[]);
    assert_eq!(o.status.code(), Some(9), "{o:?}");
    assert!(text(&o).1.contains("no step-up key"), "{o:?}");
    assert_eq!(matching(&fake, "post /api/v1/connections ").len(), 1);
    assert_eq!(matching(&fake, "post /api/v1/auth/step-up ").len(), 0);
}

#[test]
fn json_mode_prints_the_cores_json_untouched() {
    let (_fake, ks) = device("cn-json", conns, false);
    let j = |w: &[&str]| -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(w);
        serde_json::from_str(&ok(&ks, &all)).unwrap_or_else(|e| panic!("{w:?}: {e}"))
    };
    let conn: Value = serde_json::from_str(CONN).unwrap();
    assert_eq!(
        j(&["connection", "kinds"]),
        serde_json::from_str::<Value>(KINDS).unwrap()
    );
    assert_eq!(j(&["connection", "ls"]).as_array().unwrap().len(), 2);
    assert_eq!(j(&["connection", "show", "3"]), conn);
    assert_eq!(j(&["connection", "test", "3"]), conn);
    assert_eq!(j(&["connection", "rm", "4"]), json!({"deleted": true}));
    assert_eq!(
        j(&["connection", "grants", "3"]),
        json!([serde_json::from_str::<Value>(GRANT).unwrap()])
    );
    assert_eq!(
        j(&["connection", "default"]),
        json!([{"kind": "github", "connection": 3}])
    );
    assert_eq!(
        j(&["connection", "activity", "3"])
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        j(&["connection", "app", "github"])["configured"],
        json!(true)
    );
}

#[test]
fn agent_run_passes_connection_access() {
    let (fake, ks) = device("cn-agent", conns, false);
    ok(
        &ks,
        &[
            "agent",
            "run",
            DEVICE,
            "claude",
            "hello",
            "--connection-access",
            "read_repo, issues_write",
        ],
    );
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/agent-sessions ")[0]),
        json!({"runner": DEVICE, "harness": "claude", "prompt": "hello", "connection_access": ["read_repo", "issues_write"]})
    );
    // Left out: not sent at all.
    ok(&ks, &["agent", "run", DEVICE, "claude"]);
    assert!(
        body_of(&matching(&fake, "post /api/v1/agent-sessions ")[1])
            .get("connection_access")
            .is_none()
    );
}

#[test]
fn the_empty_allowlist_text_is_the_cores() {
    let (_fake, ks) = device("cn-empty", conns, false);
    let e = fails(
        &ks,
        &["agent", "run", DEVICE, "claude", "--connection-access", ","],
        2,
    );
    assert!(
        e.contains("empty_allowlist: connection_access names at least one capability; leave it out for the default (read-class capabilities only)"),
        "{e}"
    );
}
