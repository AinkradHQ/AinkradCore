//! The project profile commands (E15.13): set fields, show them back; a bad value is refused.

use std::process::Command;

use crate::{Db, db, ok};

/// `citadel-server project profile <verb> <db> <rest…>`: stdout, or stderr on failure.
fn profile(db: &Db, verb: &str, rest: &[&str]) -> Result<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_citadel-server"))
        .args(["project", "profile", verb])
        .arg(&db.0)
        .args(rest)
        .output()
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

#[test]
fn sets_and_shows_a_profile() {
    let db = db("profile");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "PRF", "Profiled"]);
    let set = r#"{"stack": "Rust", "definition_of_done": ["tests pass"], "merged_by": "lead",
                  "permission_mode": "accept_edits"}"#;
    assert_eq!(profile(&db, "set", &[&p, set]).unwrap().trim(), p);
    let shown: serde_json::Value =
        serde_json::from_str(&profile(&db, "show", &[&p]).unwrap()).unwrap();
    assert_eq!(shown["stack"], "Rust");
    assert_eq!(shown["definition_of_done"][0], "tests pass");
    assert_eq!(shown["merged_by"], "lead");
    assert_eq!(shown["permission_mode"], "accept_edits");

    let bad = profile(&db, "set", &[&p, r#"{"docs": [""]}"#]).unwrap_err();
    assert!(bad.contains("empty entry"), "{bad}");
    assert!(profile(&db, "set", &[&p, "not json"]).is_err());
    assert!(profile(&db, "show", &["999"]).is_err());
}

/// The permission policy is set whole from flags (repeated --allow) and shown back as JSON.
#[test]
fn sets_and_shows_a_policy() {
    let db = db("policy");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "POL", "Policed"]);
    let policy = |verb: &str, rest: &[&str]| -> Result<String, String> {
        let out = Command::new(env!("CARGO_BIN_EXE_citadel-server"))
            .args(["project", "policy", verb])
            .arg(&db.0)
            .args(rest)
            .output()
            .unwrap();
        match out.status.success() {
            true => Ok(String::from_utf8(out.stdout).unwrap()),
            false => Err(String::from_utf8(out.stderr).unwrap()),
        }
    };
    let set = [
        &p,
        "--mode",
        "accept_edits",
        "--allow",
        "Bash:npm run",
        "--allow",
        "Bash:composer",
    ];
    assert_eq!(policy("set", &set).unwrap().trim(), p);
    let shown: serde_json::Value = serde_json::from_str(&policy("show", &[&p]).unwrap()).unwrap();
    assert_eq!(
        shown,
        serde_json::json!({"mode": "accept_edits", "allow": ["Bash:npm run", "Bash:composer"],
            "sandboxed": false})
    );
    assert!(policy("set", &[&p, "--mode", "yolo"]).is_err());
    assert!(
        policy("set", &[&p, "--allow", "Edit"]).is_err(),
        "--mode is required"
    );
    assert!(policy("set", &[&p, "--mode", "ask", "--allow", " "]).is_err());
    assert!(policy("set", &["999", "--mode", "ask"]).is_err());
    let shown: serde_json::Value = serde_json::from_str(&policy("show", &[&p]).unwrap()).unwrap();
    assert_eq!(shown["mode"], "accept_edits", "unchanged");
}
