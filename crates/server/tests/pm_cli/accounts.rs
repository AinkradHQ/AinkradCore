//! The account commands (E15.1): add, list, assign, unassign, disable, enable; never a token.

use crate::{cli, db, ok};

#[test]
fn manages_the_account_pool() {
    let db = db("accounts");
    let a = ok(&db, &["company", "add", "A"]);
    let b = ok(&db, &["company", "add", "B"]);
    let id = ok(
        &db,
        &[
            "account",
            "add",
            "claude",
            "claude-work",
            "--credential",
            "claude-work.token",
            "--billing",
            "subscription",
        ],
    );
    ok(&db, &["account", "add", "codex", "codex-1"]);
    ok(&db, &["account", "assign", "claude-work", &a]);
    ok(&db, &["account", "assign", "claude-work", &b]);
    ok(&db, &["account", "unassign", "claude-work", &b]);
    ok(
        &db,
        &["account", "disable", "claude-work", "--reason", "rotating"],
    );
    let list = ok(&db, &["account", "list"]);
    let row: Vec<&str> = list.lines().next().unwrap().split('\t').collect();
    assert_eq!(
        row,
        [
            id.as_str(),
            "claude",
            "claude-work",
            "disabled",
            "subscription",
            "accounts/claude-work",
            "claude-work.token",
            "CLAUDE_CODE_OAUTH_TOKEN",
            a.as_str(),
            "-",
            "rotating"
        ]
    );
    ok(&db, &["account", "enable", "claude-work"]);
    assert!(ok(&db, &["account", "list"]).contains("\tactive\t"));
    for bad in [
        &[
            "account",
            "add",
            "claude",
            "x",
            "--credential",
            "/etc/passwd",
        ][..],
        &["account", "add", "claude", "Bad Label"],
        &[
            "account",
            "add",
            "claude",
            "y",
            "--env",
            "PATH",
            "--credential",
            "y",
        ],
        &["account", "add", "pi", "z"],
        &["account", "assign", "nobody", &a],
        &["account", "assign", "codex-1", "999"],
    ] {
        assert!(cli(&db, bad).is_err(), "{bad:?}");
    }
}

/// `ainkrad-core-server account limit <set|clear> <db> <rest…>`.
fn limit(db: &crate::Db, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(["account", "limit", args[0]])
        .arg(&db.0)
        .args(&args[1..])
        .output()
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

#[test]
fn sets_limits_and_reports_usage() {
    let db = db("account-limits");
    let a = ok(&db, &["company", "add", "A"]);
    ok(&db, &["account", "add", "claude", "claude-1"]);
    ok(&db, &["account", "assign", "claude-1", &a]);
    limit(&db, &["set", "claude-1", "5h", "1000", "tokens"]).unwrap();
    let warn = ["set", "claude-1", "7d", "50", "messages", "--warn", "90"];
    limit(&db, &warn).unwrap();
    let report = ok(&db, &["account", "usage"]);
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    let limits = &report[0]["limits"];
    assert_eq!(limits[0]["window_secs"], 18_000);
    assert_eq!(limits[0]["used"], 0);
    assert_eq!(limits[1]["unit"], "messages");
    assert_eq!(limits[1]["warn_percent"], 90);
    let mine = ok(&db, &["account", "usage", "--company", &a]);
    let mine: serde_json::Value = serde_json::from_str(&mine).unwrap();
    assert_eq!(mine[0]["label"], "claude-1", "assigned, even unused");
    limit(&db, &["clear", "claude-1", "5h", "tokens"]).unwrap();
    assert!(limit(&db, &["clear", "claude-1", "5h", "tokens"]).is_err());
    for bad in [
        &["set", "claude-1", "5w", "10", "tokens"][..],
        &["set", "claude-1", "5h", "0", "tokens"],
        &["set", "claude-1", "5h", "10", "dollars"],
    ] {
        assert!(limit(&db, bad).is_err(), "{bad:?}");
    }
}

#[test]
fn sets_and_lists_an_agents_fallback_chain() {
    let db = db("fallbacks");
    let c = ok(&db, &["company", "add", "A"]);
    let dev = ok(
        &db,
        &[
            "agent",
            "add",
            &c,
            "Dev",
            "--harness",
            "claude",
            "--model",
            "opus",
            "--org-role",
            "ceo",
            "--active",
        ],
    );
    let fallback = |rest: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
            .args(["agent", "fallback", rest[0]])
            .arg(&db.0)
            .args(&rest[1..])
            .output()
            .unwrap();
        match out.status.success() {
            true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
            false => Err(String::from_utf8(out.stderr).unwrap()),
        }
    };
    fallback(&["set", &dev, "claude/sonnet", "codex/gpt-x"]).unwrap();
    assert_eq!(
        fallback(&["list", &dev]).unwrap(),
        "claude/sonnet\ncodex/gpt-x"
    );
    assert!(
        fallback(&["set", &dev, "claude/opus"]).is_err(),
        "its own entry"
    );
    assert!(fallback(&["set", &dev, "pi/x"]).is_err());
    assert!(fallback(&["set", "999", "codex/x"]).is_err());
    fallback(&["set", &dev]).unwrap();
    assert_eq!(fallback(&["list", &dev]).unwrap(), "");
}
