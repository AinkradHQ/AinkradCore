//! `account`, `pool` and `budget` against the fake Core that answers the contract's shapes and
//! records every request: golden output per command, the bodies sent, how refusals are said, the
//! step-up flow, JSON mode, wrong usage (exit 2, nothing sent) and the contract check.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::json;

use crate::acct_fake::*;
use crate::common::*;
use crate::connections_fake::{body_of, matching, text};
use crate::scheduler_fake::device;

/// ctl with `stdin` on its standard input and `env` set (the ambient key and code removed).
pub fn run(ks: &str, words: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(CTL);
    cmd.args(["--keystore", ks])
        .args(words)
        .env("AINKRAD_STEPUP_PASSPHRASE_FILE", passphrase_file())
        .env_remove("AINKRAD_ACCOUNT_KEY")
        .env_remove("AINKRAD_ACCOUNT_CODE")
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

pub fn ok(ks: &str, words: &[&str]) -> String {
    let o = run(ks, words, "", &[]);
    assert!(o.status.success(), "{words:?}: {o:?}");
    stdout(&o)
}

/// A run that must fail with `code`, printing nothing on stdout; its stderr.
pub fn fails(ks: &str, words: &[&str], stdin: &str, code: i32) -> String {
    let o = run(ks, words, stdin, &[]);
    assert_eq!(o.status.code(), Some(code), "{words:?}: {o:?}");
    assert!(stdout(&o).is_empty(), "{words:?}: {o:?}");
    text(&o).1
}

#[test]
fn read_commands_print_the_golden_output() {
    let (fake, ks) = device("ac-read", accounts, false);
    assert_eq!(
        ok(&ks, &["account", "providers"]),
        "anthropic\tAnthropic\tclaude\thttps://api.example\tenv,gateway\tbuilt-in\n\
         claude-sub\tClaude subscription\tclaude\thttps://claude.example\tenv\tbuilt-in\n"
    );
    assert_eq!(
        ok(&ks, &["account", "usage"]),
        "7\t5h 1200 tokens 3 msgs $0.0150\t7d 9000 tokens 30 msgs $0.1500\tutilisation 83.4%\tdrops 1\n\
         \x20 limit tokens/18000 s\t1200/100000\twarn 80%\n"
    );
    let costs = "9\t2026-11-07T00:00:00.000Z\tas_1#2\taccount 7\tanthropic\tsonnet-x\tin 10 out 20 cache 30\tlist_price\t$0.0012\n\
         8\t2026-11-06T00:00:00.000Z\tas_1#1\taccount -\tanthropic\tsonnet-x\tin 1 out 2 cache 3\tunpriced (approximate)\tunpriced\n";
    assert_eq!(ok(&ks, &["account", "costs"]), costs);
    ok(
        &ks,
        &[
            "account",
            "costs",
            "--account",
            "7",
            "--session",
            "as_1",
            "--limit",
            "5",
        ],
    );
    assert!(
        !matching(&fake, "get /api/v1/costs?account=7&session=as_1&limit=5 ").is_empty(),
        "{:?}",
        fake.requests()
    );
    assert_eq!(
        ok(&ks, &["pool", "ls"]),
        "2\tmain\tanthropic\tmembers 7,9\tdefault\n3\tsubs\tclaude-sub\tmembers -\t-\n"
    );
    assert_eq!(
        ok(&ks, &["pools", "show", "2"]),
        "2\tmain\tanthropic\tmembers 7,9\tdefault\n\
         \x20 seat 1\t7\tanthropic\twork\tcooling\tlive 2/3\tfail 1 auth 0\n\
         \x20 seat 2\taccount 9\n"
    );
    assert_eq!(
        ok(
            &ks,
            &["budget", "ls", "--kind", "account", "--subject", "9"]
        ),
        "4\taccount:9\tmonth\ttokens 250/1000000\tusd $0.0015/$5.0000\twarn 80%\thard-stop\n"
    );
    assert!(!matching(&fake, "get /api/v1/budgets?kind=account&subject=9 ").is_empty());
    // ls and show are the S9 ones, unchanged.
    assert!(ok(&ks, &["account", "ls"]).starts_with("7\tanthropic\twork\tcooling\t"));
    assert!(ok(&ks, &["account", "show", "7"]).contains("state_reason rate_limited until "));
    let e = fails(&ks, &["pool", "show", "404"], "", 4);
    assert_eq!(e, "ainkradctl: 404 not_found: pool 404: no such pool\n");
}

#[test]
fn write_commands_send_what_was_asked_and_say_what_they_did() {
    let (fake, ks) = device("ac-write", accounts, false);
    let sent = |line: &str, n: usize| body_of(&matching(&fake, line)[n]);

    let o = run(
        &ks,
        &[
            "account",
            "add",
            "anthropic",
            "--label",
            "work",
            "--cap",
            "2",
            "--runners",
            "d_runner1, d_r2",
        ],
        "sk-test-1\n",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        "9\tanthropic\twork\tactive\tlive 0/2\tfail 0 auth 0\nrunners d_runner1,d_r2\n"
    );
    assert_eq!(
        sent("post /api/v1/accounts ", 0),
        json!({"provider": "anthropic", "label": "work", "value": "sk-test-1", "cap": 2, "runners": ["d_runner1", "d_r2"]})
    );
    // The label defaults to the provider; no cap and no runners are left out of the body.
    let o = run(&ks, &["account", "add", "openai"], "sk-test-2", &[]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        "9\topenai\topenai\tactive\tlive 0/4\tfail 0 auth 0\nrunners -\n"
    );
    assert_eq!(
        sent("post /api/v1/accounts ", 1),
        json!({"provider": "openai", "label": "openai", "value": "sk-test-2"})
    );

    assert_eq!(
        ok(
            &ks,
            &["account", "state", "9", "disabled", "--reason", "rotated"]
        ),
        "9\tanthropic\twork\tdisabled\tlive 0/4\tfail 0 auth 0\n"
    );
    assert_eq!(
        sent("put /api/v1/accounts/9/state ", 0),
        json!({"state": "disabled", "reason": "rotated"})
    );
    let o = run(
        &ks,
        &[
            "account",
            "state",
            "9",
            "cooling",
            "--until",
            "2026-11-09T00:00:00.000Z",
        ],
        "",
        &[],
    );
    assert!(o.status.success() && text(&o).1.is_empty(), "{o:?}");
    assert_eq!(
        sent("put /api/v1/accounts/9/state ", 1),
        json!({"state": "cooling", "until": "2026-11-09T00:00:00.000Z"})
    );
    // A hold with no end says so (stderr), `active` does not.
    let o = run(&ks, &["account", "state", "9", "limited"], "", &[]);
    assert!(
        text(&o).1.contains("stays limited until you set it active"),
        "{o:?}"
    );
    let o = run(&ks, &["account", "state", "9", "active"], "", &[]);
    assert!(text(&o).1.is_empty(), "{o:?}");

    assert_eq!(
        ok(&ks, &["account", "cap", "9", "0"]),
        "9\tanthropic\twork\tactive\tlive 0/-\tfail 0 auth 0\n"
    );
    assert_eq!(sent("put /api/v1/accounts/9/cap ", 0), json!({"cap": 0}));
    assert_eq!(
        ok(
            &ks,
            &[
                "account",
                "limit",
                "set",
                "9",
                "tokens",
                "18000",
                "100000",
                "--warn-percent",
                "90"
            ]
        ),
        "account 9 limit tokens/18000 s cap 100000 warn 90%\n"
    );
    assert_eq!(
        sent("put /api/v1/accounts/9/limits ", 0),
        json!({"unit": "tokens", "window_secs": 18000, "cap": 100000, "warn_percent": 90})
    );
    assert_eq!(
        ok(&ks, &["account", "limit", "clear", "9", "tokens", "18000"]),
        "cleared account 9 limit tokens/18000 s\n"
    );
    assert_eq!(
        ok(&ks, &["account", "limit", "clear", "9", "messages", "60"]),
        "account 9 had no limit messages/60 s\n"
    );
    ok(
        &ks,
        &[
            "account",
            "session-limits",
            "9",
            "--max-tokens",
            "400000",
            "--max-usd-micros",
            "2000000",
        ],
    );
    assert_eq!(
        sent("put /api/v1/accounts/9/session-limits ", 0),
        json!({"max_tokens": 400000, "max_usd_micros": 2000000})
    );
    let o = run(
        &ks,
        &["account", "rotate", "9", "--runners", "d_runner1"],
        "sk-new\n",
        &[],
    );
    assert_eq!(stdout(&o), format!("{ACCT_ROW}runners d_runner1\n"));
    assert_eq!(
        sent("put /api/v1/accounts/9/secret ", 0),
        json!({"value": "sk-new", "runners": ["d_runner1"]})
    );
    assert_eq!(
        ok(&ks, &["account", "test", "9"]),
        "tested account 9: ok (123 ms, runner d_runner1)\n"
    );
    assert_eq!(
        ok(&ks, &["account", "test", "10"]),
        "tested account 10: inconclusive (nothing was sent)\n"
    );
    assert_eq!(ok(&ks, &["account", "rm", "9"]), "removed account 9\n");

    assert_eq!(
        ok(&ks, &["pool", "create", "extra", "anthropic"]),
        "6\textra\tanthropic\tmembers -\t-\n"
    );
    assert_eq!(
        sent("post /api/v1/pools ", 0),
        json!({"name": "extra", "provider": "anthropic"})
    );
    assert_eq!(
        ok(&ks, &["pool", "add", "2", "5"]),
        "2\tmain\tanthropic\tmembers 7,9,5\tdefault\n"
    );
    assert_eq!(
        ok(&ks, &["pool", "remove", "2", "9"]),
        "2\tmain\tanthropic\tmembers 7\tdefault\n"
    );
    assert_eq!(
        ok(&ks, &["pool", "default", "3"]),
        "3\tsubs\tclaude-sub\tmembers -\tdefault\n"
    );
    assert_eq!(ok(&ks, &["pool", "rm", "3"]), "removed pool 3\n");
    assert_eq!(matching(&fake, "put /api/v1/pools/2/members/5 ").len(), 1);
    assert_eq!(
        matching(&fake, "delete /api/v1/pools/2/members/9 ").len(),
        1
    );

    let set = ok(
        &ks,
        &[
            "budget",
            "set",
            "account",
            "9",
            "month",
            "--tokens",
            "2000000",
            "--usd-micros",
            "7000000",
            "--warn-percent",
            "70",
            "--no-hard-stop",
        ],
    );
    assert!(
        set.starts_with(
            "4\taccount:9\tmonth\ttokens 250/2000000\tusd $0.0015/$7.0000\twarn 70%\twarn-only"
        ),
        "{set}"
    );
    assert_eq!(
        sent("put /api/v1/budgets ", 0),
        json!({"kind": "account", "subject": "9", "period": "month", "token_cap": 2000000, "usd_cap_micros": 7000000, "warn_at_percent": 70, "hard_stop": false})
    );
    ok(
        &ks,
        &["budget", "raise", "4", "2026-11", "--tokens", "500000"],
    );
    assert_eq!(
        sent("post /api/v1/budgets/4/raise ", 0),
        json!({"period_key": "2026-11", "tokens": 500000})
    );
    assert_eq!(ok(&ks, &["budget", "rm", "4"]), "removed budget 4\n");
    assert_eq!(ok(&ks, &["budget", "rm", "5"]), "there was no budget 5\n");
}

#[test]
fn a_key_comes_from_a_file_the_environment_or_the_command_line_with_a_warning() {
    let (fake, ks) = device("ac-key", accounts, false);
    let file = std::path::Path::new(&ks).parent().unwrap().join("key.txt");
    std::fs::write(&file, "sk-from-file\n").unwrap();
    let key = |n: usize| body_of(&matching(&fake, "post /api/v1/accounts ")[n])["value"].clone();
    assert!(
        run(
            &ks,
            &[
                "account",
                "add",
                "anthropic",
                "--key-file",
                file.to_str().unwrap()
            ],
            "",
            &[]
        )
        .status
        .success()
    );
    assert!(
        run(
            &ks,
            &["account", "add", "anthropic"],
            "",
            &[("AINKRAD_ACCOUNT_KEY", "sk-from-env")]
        )
        .status
        .success()
    );
    let o = run(
        &ks,
        &["account", "add", "anthropic", "--key", "sk-from-argv"],
        "",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    let err = text(&o).1;
    assert!(
        err.contains("warning: --key puts the API key in the process list")
            && err.contains("$AINKRAD_ACCOUNT_KEY"),
        "{err}"
    );
    assert_eq!(
        [key(0), key(1), key(2)],
        [
            json!("sk-from-file"),
            json!("sk-from-env"),
            json!("sk-from-argv")
        ]
    );
}

#[test]
fn json_mode_prints_what_the_core_answered() {
    let (_fake, ks) = device("ac-json", accounts, false);
    let o = run(
        &ks,
        &["--json", "account", "add", "anthropic", "--label", "j"],
        "sk-x",
        &[],
    );
    let v: serde_json::Value = serde_json::from_str(stdout(&o).trim()).unwrap();
    assert_eq!(
        (v["account"]["label"].as_str(), v["runners"].clone()),
        (Some("j"), json!([]))
    );
    let v: serde_json::Value =
        serde_json::from_str(ok(&ks, &["--json", "pool", "ls"]).trim()).unwrap();
    assert_eq!(v[0]["members"], json!([7, 9]));
    let v: serde_json::Value =
        serde_json::from_str(ok(&ks, &["--json", "account", "test", "9"]).trim()).unwrap();
    assert_eq!(v["result"], "ok");
    for w in [
        &["account", "usage"][..],
        &["account", "costs"],
        &["budget", "ls"],
        &["account", "providers"],
    ] {
        let mut a = vec!["--json"];
        a.extend_from_slice(w);
        serde_json::from_str::<serde_json::Value>(ok(&ks, &a).trim()).unwrap();
    }
}

#[test]
fn every_call_is_in_the_contract_with_its_scope() {
    let path = format!("{}/../../api/openapi.json", env!("CARGO_MANIFEST_DIR"));
    let api: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let calls = [
        ("get", "/api/v1/accounts/providers"),
        ("post", "/api/v1/accounts"),
        ("post", "/api/v1/accounts/logins"),
        ("get", "/api/v1/accounts/logins/{id}"),
        ("delete", "/api/v1/accounts/logins/{id}"),
        ("post", "/api/v1/accounts/logins/{id}/code"),
        ("put", "/api/v1/accounts/{id}/state"),
        ("put", "/api/v1/accounts/{id}/cap"),
        ("put", "/api/v1/accounts/{id}/limits"),
        (
            "delete",
            "/api/v1/accounts/{id}/limits/{unit}/{window_secs}",
        ),
        ("put", "/api/v1/accounts/{id}/session-limits"),
        ("put", "/api/v1/accounts/{id}/secret"),
        ("post", "/api/v1/accounts/{id}/test"),
        ("delete", "/api/v1/accounts/{id}"),
        ("get", "/api/v1/accounts/usage"),
        ("get", "/api/v1/costs"),
        ("get", "/api/v1/pools"),
        ("post", "/api/v1/pools"),
        ("put", "/api/v1/pools/{id}/members/{account}"),
        ("delete", "/api/v1/pools/{id}/members/{account}"),
        ("put", "/api/v1/pools/{id}/default"),
        ("delete", "/api/v1/pools/{id}"),
        ("get", "/api/v1/budgets"),
        ("put", "/api/v1/budgets"),
        ("post", "/api/v1/budgets/{id}/raise"),
        ("delete", "/api/v1/budgets/{id}"),
    ];
    for (method, route) in calls {
        let op = &api["paths"][route][method];
        let reads = [
            "/api/v1/accounts/providers",
            "/api/v1/budgets",
            "/api/v1/pools",
        ];
        let want = if method == "get" && reads.contains(&route) {
            "read"
        } else {
            "admin"
        };
        assert_eq!(
            op["x-ainkrad-scope"].as_str(),
            Some(want),
            "{method} {route}"
        );
    }
}
