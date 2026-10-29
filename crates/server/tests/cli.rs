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
    }
}
