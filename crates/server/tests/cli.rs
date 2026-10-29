//! The admin verbs of `ainkrad-core-server` on a scratch database: device keys and settings.

use std::path::PathBuf;
use std::process::Command;

/// A scratch database path in its own temp dir, removed on drop.
struct Db(PathBuf);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn db(name: &str) -> Db {
    let dir = std::env::temp_dir().join(format!("core-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Db(dir.join("core.db"))
}

/// `ainkrad-core-server <verb> <noun> <db> <rest…>`: its trimmed stdout, or its stderr on failure.
fn cli(db: &Db, args: &[&str]) -> Result<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(&args[..2])
        .arg(&db.0)
        .args(&args[2..])
        .output()
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

fn ok(db: &Db, args: &[&str]) -> String {
    cli(db, args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

#[test]
fn devices_are_added_listed_and_revoked() {
    let db = db("devices");
    let key = ok(&db, &["device", "add", "mac"]);
    assert!(key.starts_with("cit_device_"), "{key}");
    let list = ok(&db, &["device", "list"]);
    assert!(list.starts_with("1\tmac\tcreated "), "{list}");
    assert!(!list.contains(&key), "never a key");
    ok(&db, &["device", "revoke", "1"]);
    assert!(ok(&db, &["device", "list"]).contains("\trevoked "));
    let again = cli(&db, &["device", "revoke", "1"]).unwrap_err();
    assert!(again.contains("no live device key 1"), "{again}");
}

#[test]
fn settings_are_set_refused_reset_and_their_history_listed() {
    let db = db("settings");
    let list = ok(&db, &["setting", "list"]);
    assert!(
        list.lines()
            .any(|l| l == "api.request_burst\t120\tcount\tdefault\t10..=10000\tserver"),
        "{list}"
    );
    let key = "api.request_burst";
    ok(&db, &["setting", "set", key, "500"]);
    let got = ok(&db, &["setting", "get", key, "--scope", "server"]);
    assert!(
        got.starts_with(&format!("{key}\t500\tcount\tserver\t")),
        "{got}"
    );
    for (args, why) in [
        (vec!["setting", "set", key, "5"], "out of bounds"),
        (vec!["setting", "set", "no.such", "1"], "no setting"),
    ] {
        let e = cli(&db, &args).unwrap_err();
        assert!(e.contains(why), "{args:?}: {e}");
    }
    assert!(cli(&db, &["setting", "set", key, "500", "--scope", "company:1"]).is_err());
    let reset = ok(&db, &["setting", "reset", key]);
    assert!(
        reset.starts_with(&format!("{key}\t120\tcount\tdefault")),
        "{reset}"
    );
    let history = ok(&db, &["setting", "history", key]);
    let lines: Vec<&str> = history.lines().collect();
    assert_eq!(lines.len(), 2, "{history}");
    assert!(lines[0].contains("server\t500 -> inherited"), "{history}");
    assert!(lines[1].contains("server\tinherited -> 500"), "{history}");
}

#[test]
fn public_serve_refuses_to_start_without_a_hostname_and_an_acme_contact() {
    let db = db("public");
    for flags in [
        &["--listen", "public"][..],
        &["--listen", "public", "--hostname", "core.example"],
        &["--listen", "public", "--acme-contact", "ops@example.test"],
        &["--listen", "loopback:0", "--hostname", "core.example"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
            .arg("serve")
            .arg(&db.0)
            .args(flags)
            .output()
            .unwrap();
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(!out.status.success(), "{flags:?} started");
        assert!(err.contains("--hostname"), "{flags:?}: {err}");
        assert!(
            !db.0.exists(),
            "{flags:?}: refused before the database is created"
        );
    }
}

/// E1-10.1, E1-10.3: `audit verify` passes on a whole chain and names the first edited row;
/// `audit export` writes JSONL that `audit verify --export` re-verifies on its own.
#[test]
fn the_audit_chain_is_verified_and_exported() {
    let db = db("audit");
    for name in ["mac", "phone", "pad"] {
        ok(&db, &["device", "add", name]);
    }
    ok(&db, &["device", "revoke", "2"]);
    let verified = ok(&db, &["audit", "verify"]);
    assert!(
        verified.starts_with("audit chain ok: 4 rows (0 from before the chain), head seq 4 "),
        "{verified}"
    );

    let export = db.0.with_file_name("audit.jsonl");
    let path = export.to_str().unwrap();
    ok(&db, &["audit", "export", path]);
    let text = std::fs::read_to_string(&export).unwrap();
    assert_eq!(text.lines().count(), 4);
    assert!(
        text.lines()
            .all(|l| l.contains("\"hash\":\"") && l.contains("\"prev_hash\":\""))
    );
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(["audit", "verify", "--export", path])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        verified,
        "the export alone agrees"
    );
    assert!(
        cli(&db, &["audit", "export", path])
            .unwrap_err()
            .contains("exists"),
        "never overwritten"
    );

    // An edit behind the triggers' back.
    let sql = Command::new("sqlite3")
        .arg(&db.0)
        .arg("DROP TRIGGER audit_events_no_update; UPDATE audit_events SET details = '{\"x\":1}' WHERE seq = 3;")
        .status();
    match sql {
        Ok(s) if s.success() => {
            let err = cli(&db, &["audit", "verify"]).unwrap_err();
            assert!(err.contains("audit chain broken at seq 3"), "{err}");
        }
        // ponytail: no sqlite3 CLI (a slim container); the store tests cover the edit.
        _ => eprintln!("sqlite3 not found; skipped the tamper half"),
    }
}
