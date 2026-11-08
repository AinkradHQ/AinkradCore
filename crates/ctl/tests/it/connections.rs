//! `connection …` against a fake Core that answers the contract's shapes (C5) and records every
//! request: golden output per command, the bodies sent, how refusals are said, the step-up flow,
//! JSON mode, wrong usage (exit 2, nothing sent) and `agent run --connection-access`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::json;

use crate::common::*;
use crate::connections_fake::*;
use crate::scheduler_fake::device;

/// ctl with `stdin` on its standard input and `env` set (the ambient token variable removed).
pub fn run(ks: &str, words: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(CTL);
    cmd.args(["--keystore", ks])
        .args(words)
        .env("AINKRAD_STEPUP_PASSPHRASE_FILE", passphrase_file())
        .env_remove("AINKRAD_CONNECTION_TOKEN")
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut pipe = child.stdin.take().unwrap();
    let _ = pipe.write_all(stdin.as_bytes());
    drop(pipe);
    child.wait_with_output().unwrap()
}

pub fn plain(ks: &str, words: &[&str]) -> Output {
    run(ks, words, "", &[])
}

pub fn ok(ks: &str, words: &[&str]) -> String {
    let o = plain(ks, words);
    assert!(o.status.success(), "{words:?}: {o:?}");
    stdout(&o)
}

pub fn fails(ks: &str, words: &[&str], code: i32) -> String {
    let o = plain(ks, words);
    assert_eq!(o.status.code(), Some(code), "{words:?}: {o:?}");
    assert!(stdout(&o).is_empty(), "{words:?}: {o:?}");
    text(&o).1
}

pub const CONN_ROW: &str = "3\tgithub\twork\tactive\toctocat\tdefault\n";
pub const JIRA_ROW: &str = "4\tjira\tacme\tauth_suspected (disabled)\t-\t-\n";
pub const CONN_LINES: &str = "id 3\nkind github\nname work\nauth token\nidentity octocat\nstatus active\ndisabled no\nlast_tested 2026-11-07T00:00:00.000Z\ndefault yes\ngrants 2\n";

#[test]
fn read_commands_print_the_golden_output() {
    let (fake, ks) = device("cn-read", conns, false);
    assert_eq!(
        ok(&ks, &["connection", "kinds"]),
        "github\tGitHub\tconfigured\tauth oauth,token,app_install (unavailable)\n\
\x20 read_repo\tread\tread\tRead repositories\n\
\x20 issues_write\tissues\twrite\tChange issues\n\
\x20 limit repos\towner/name list\n\
jira\tJira\tnot configured\tauth \n"
    );
    assert_eq!(
        ok(&ks, &["connections", "ls"]),
        format!("{CONN_ROW}{JIRA_ROW}")
    );
    ok(&ks, &["connection", "ls", "--kind", "github"]);
    assert!(
        fake.requests()
            .iter()
            .any(|r| r.starts_with("get /api/v1/connections?kind=github "))
    );
    assert_eq!(ok(&ks, &["connection", "show", "3"]), CONN_LINES);
    assert_eq!(
        ok(&ks, &["connection", "show", "4"]),
        "id 4\nkind jira\nname acme\nlabel team\nauth oauth\nidentity -\nstatus auth_suspected\nreason auth_suspected\nuntil 2026-11-07T01:00:00.000Z\ndisabled yes\nlast_tested never\ndefault no\ngrants 0\n"
    );
    assert_eq!(
        ok(&ks, &["connection", "grants", "3"]),
        "agent\tbot\tread_repo,issues_write\trepos=a/b,c/d\n"
    );
    assert_eq!(
        ok(&ks, &["connection", "default"]),
        "github\tconnection 3\n"
    );
    assert_eq!(
        ok(&ks, &["connection", "default", "github"]),
        "github\tconnection 3\n"
    );
    assert_eq!(ok(&ks, &["connection", "default", "jira"]), "jira\t-\n");
    assert_eq!(
        ok(&ks, &["connection", "activity", "3", "--limit", "5"]),
        "9\t2026-11-07T00:00:00.000Z\tcall\tissues.create\tok\t-\tbot\tas_1\n8\t2026-11-06T00:00:00.000Z\ttest\t-\t-\t-\t-\t-\n"
    );
    assert!(
        fake.requests()
            .iter()
            .any(|r| r.starts_with("get /api/v1/connections/3/activity?limit=5 "))
    );
    assert_eq!(
        ok(&ks, &["connection", "app", "github"]),
        "kind github\nconfigured yes\napp_install_configured no\nredirect_uri http://127.0.0.1:47613/callback\nfield client_id\tplain\tset\nfield client_secret\tsecret\tset\n"
    );
}

#[test]
fn write_commands_send_what_was_asked_and_say_what_they_did() {
    let (fake, ks) = device("cn-write", conns, false);
    let sent = |line: &str, n: usize| body_of(&matching(&fake, line)[n]);

    let o = run(
        &ks,
        &[
            "connection",
            "add",
            "github",
            "--name",
            "work",
            "--label",
            "main",
        ],
        "ghp_tok\n",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), CONN_LINES);
    assert_eq!(
        sent("post /api/v1/connections ", 0),
        json!({"kind": "github", "auth_method": "token", "token": "ghp_tok", "name": "work", "label": "main"})
    );
    let o = run(
        &ks,
        &[
            "connection",
            "add",
            "jira",
            "--email",
            "me@example.com",
            "--site",
            "acme",
        ],
        "t2",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent("post /api/v1/connections ", 1),
        json!({"kind": "jira", "auth_method": "token", "token": "t2", "email": "me@example.com", "site": "acme"})
    );
    // From the environment, no stdin.
    let o = run(
        &ks,
        &["connection", "add", "github"],
        "",
        &[("AINKRAD_CONNECTION_TOKEN", "from-env")],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent("post /api/v1/connections ", 2)["token"],
        json!("from-env")
    );

    let o = run(&ks, &["connection", "credential", "3"], "newtok\r\n", &[]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent("put /api/v1/connections/3/credential ", 0),
        json!({"token": "newtok"})
    );

    assert!(ok(&ks, &["connection", "rename", "3", "main"]).contains("name main\n"));
    assert_eq!(
        sent("patch /api/v1/connections/3 ", 0),
        json!({"name": "main"})
    );
    ok(&ks, &["connection", "disable", "3"]);
    assert_eq!(
        sent("patch /api/v1/connections/3 ", 1),
        json!({"disabled": true})
    );
    ok(&ks, &["connection", "enable", "3"]);
    assert_eq!(
        sent("patch /api/v1/connections/3 ", 2),
        json!({"disabled": false})
    );
    assert_eq!(
        ok(&ks, &["connection", "rm", "4"]),
        "removed connection 4\n"
    );

    assert_eq!(
        ok(
            &ks,
            &[
                "connection",
                "grant",
                "3",
                "agent",
                "bot",
                "--caps",
                "read_repo,issues_write",
                "--limit",
                "repos=a/b",
                "--limit",
                "repos=c/d"
            ]
        ),
        "agent\tbot\tread_repo,issues_write\trepos=a/b,c/d\n"
    );
    assert_eq!(
        sent("put /api/v1/connections/3/grants ", 0),
        json!({"grantee_kind": "agent", "grantee": "bot", "capabilities": ["read_repo", "issues_write"], "limits": {"repos": ["a/b", "c/d"]}})
    );
    assert_eq!(
        ok(&ks, &["connection", "revoke", "3", "agent", "bot"]),
        "revoked agent bot from connection 3\n"
    );
    assert_eq!(
        ok(&ks, &["connection", "default", "github", "3"]),
        "connection 3 is the default github\n"
    );
    assert_eq!(
        sent("put /api/v1/connection-defaults/github ", 0),
        json!({"connection": 3})
    );
    assert_eq!(
        ok(&ks, &["connection", "default", "github", "--clear"]),
        "cleared the default github connection\n"
    );
    assert_eq!(
        matching(&fake, "delete /api/v1/connection-defaults/github ").len(),
        1
    );

    // An app: a plain field on the command line, the secret from stdin; an empty value clears.
    let o = run(
        &ks,
        &[
            "connection",
            "app",
            "github",
            "set",
            "--field",
            "client_id=abc",
            "--field",
            "client_secret=-",
            "--field",
            "extra=",
        ],
        "S3CRET\n",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent("put /api/v1/connection-apps/github ", 0),
        json!({"fields": {"client_id": "abc", "client_secret": "S3CRET", "extra": null}})
    );
}

#[test]
fn refusals_are_said_plainly_with_the_exit_code_of_a_refusal() {
    let (_fake, ks) = device("cn-err", conns, false);
    let tok = |words: &[&str], stdin: &str| {
        let o = run(&ks, words, stdin, &[]);
        assert_eq!(o.status.code(), Some(4), "{words:?}: {o:?}");
        text(&o).1
    };
    assert_eq!(
        fails(&ks, &["connection", "show", "404"], 4),
        "ainkradctl: 404 not_found: connection 404: no such connection\n"
    );
    assert_eq!(
        tok(&["connection", "add", "github"], "REJECT-1"),
        "ainkradctl: 400 credential_rejected: adding a github connection: the service refused that credential\n"
    );
    assert_eq!(
        fails(&ks, &["connection", "rm", "3"], 4),
        "ainkradctl: 409 conflict: removing connection 3: connection 3 is its kind's default; fix: make another connection the default (`connection default <kind> <id>`) or clear it (`connection default <kind> --clear`), then remove this one\n"
    );
    assert_eq!(
        fails(&ks, &["connection", "test", "6"], 4),
        "ainkradctl: 429 rate_limited: testing connection 6: too soon, wait 7 s and try again\n"
    );
    assert_eq!(
        fails(
            &ks,
            &[
                "connection",
                "grant",
                "404",
                "role",
                "member",
                "--caps",
                "read_repo"
            ],
            4
        ),
        "ainkradctl: 404 not_found: granting role member connection 404: no such connection\n"
    );
    let o = run(
        &ks,
        &["connection", "app", "jira", "set", "--field", "client_id=x"],
        "",
        &[],
    );
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert_eq!(
        text(&o).1,
        "ainkradctl: 403 forbidden_scope: setting the jira sign-in app: only the Core's owner changes Ainkrad's sign-in apps\n"
    );
    // The Core echoing a secret back: it is blanked.
    let e = tok(&["connection", "add", "github"], "ECHO-HUNTER2");
    assert!(e.contains("odd token ***") && !e.contains("HUNTER2"), "{e}");
}

#[test]
fn a_test_prints_its_result_first() {
    let (_fake, ks) = device("cn-test", conns, false);
    assert_eq!(
        ok(&ks, &["connection", "test", "3"]),
        format!("tested connection 3: active\n{CONN_LINES}")
    );
    assert!(
        ok(&ks, &["connection", "test", "4"])
            .starts_with("tested connection 4: auth_suspected (auth_suspected)\n")
    );
}
