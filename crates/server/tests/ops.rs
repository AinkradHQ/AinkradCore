//! The operations verbs (E1-13) end to end through the binary: `--help`, `init`, an encrypted
//! signed `backup` restored into a fresh home, `export`/`import`, and the refusals. No network:
//! the bucket half runs only with `AINKRAD_MINIO=1` (and `AINKRAD_BACKUP_*` pointing at it).

use std::path::{Path, PathBuf};
use std::process::Command;

use ainkrad_core_server::store::{self, events, kinds};

/// A scratch dir, removed on drop.
struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(name: &str) -> Dir {
    let d = std::env::temp_dir().join(format!("core-ops-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Dir(d)
}

/// Runs the binary with `env`: its trimmed stdout, or its stderr on failure.
fn run(args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"));
    cmd.args(args).env_remove("AINKRAD_CONFIG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

fn ok(args: &[&str], env: &[(&str, &str)]) -> String {
    run(args, env).unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A new home with two devices (one revoked) and three events; its signer fingerprint.
async fn home_with_state(home: &Path) -> String {
    let fp = ok(&["init", s(home)], &[]);
    let db = home.join("core.db");
    for name in ["mac", "phone"] {
        ok(&["device", "add", s(&db), name], &[]);
    }
    ok(&["device", "revoke", s(&db), "2"], &[]);
    let pool = store::connect(&db).await.unwrap();
    let mut tx = store::begin_write(&pool).await.unwrap();
    kinds::register(&mut tx, "probe", &["probe.line"], &[])
        .await
        .unwrap();
    for i in 0..3 {
        events::append(&mut tx, "probe.line", &serde_json::json!({ "i": i }))
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    pool.close().await;
    fp
}

/// What must survive a round trip: the device list, the audit chain's head, the event range.
async fn state(home: &Path) -> (String, String, i64, i64) {
    let db = home.join("core.db");
    let devices = ok(&["device", "list", s(&db)], &[]);
    let audit = ok(&["audit", "verify", s(&db)], &[]);
    let pool = store::connect(&db).await.unwrap();
    let range = (
        events::floor(&pool).await.unwrap(),
        events::last_event_seq(&pool).await.unwrap(),
    );
    pool.close().await;
    (devices, audit, range.0, range.1)
}

#[test]
fn help_documents_every_verb() {
    let help = ok(&["--help"], &[]);
    for verb in [
        "init",
        "serve",
        "backup",
        "backup-keygen",
        "restore",
        "export",
        "import",
        "device add",
        "device list",
        "device revoke",
        "audit verify",
        "audit export",
        "setting list",
        "openapi",
    ] {
        assert!(
            help.contains(&format!("ainkrad-core-server {verb} "))
                || help.contains(&format!("ainkrad-core-server {verb}\n")),
            "--help does not document `{verb}`"
        );
    }
}

#[tokio::test]
async fn init_makes_a_private_home_and_never_overwrites_one() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("init");
    let home = d.0.join("home");
    let fp = ok(&["init", s(&home)], &[]);
    assert_eq!(fp.len(), 43, "{fp}");
    let mode = |p: &str| {
        std::fs::metadata(home.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(
        [
            mode(""),
            mode("keys"),
            mode("keys/master.key"),
            mode("keys/backup-signing.p8")
        ],
        [0o700, 0o700, 0o600, 0o600]
    );
    assert_eq!(
        std::fs::read(home.join("keys/master.key")).unwrap().len(),
        32
    );
    let e = run(&["init", s(&home)], &[]).unwrap_err();
    assert!(e.contains("not empty"), "{e}");
    // The home works: the config drives the backup verbs, and its database is migrated.
    let config = home.join("config.toml");
    let out = ok(&["device", "list", s(&home.join("core.db"))], &[]);
    assert_eq!(out, "");
    let e = run(&["backup", "--config", s(&config), "--local-only"], &[]).unwrap_err();
    assert!(e.contains("backup_recipient"), "{e}");
}

#[tokio::test]
async fn a_backup_restores_into_a_fresh_home_and_matches() {
    let d = dir("restore");
    let home = d.0.join("home");
    let fp = home_with_state(&home).await;
    let keygen = ok(&["backup-keygen"], &[]);
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap();
    let env = [("AINKRAD_BACKUP_RECIPIENT", recipient)];
    let config = home.join("config.toml");

    let first = ok(&["backup", "--config", s(&config), "--local-only"], &env);
    let second = ok(&["backup", "--config", s(&config), "--local-only"], &env);
    assert!(
        first.ends_with(".age") && first != second,
        "{first} {second}"
    );
    let bytes = std::fs::read(&first).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !bytes.windows(15).any(|w| w == b"SQLite format 3"),
        "encrypted"
    );

    let fresh = d.0.join("restored");
    let id = s(&identity);
    let new_fp = ok(
        &[
            "restore",
            &first,
            "--identity",
            id,
            "--signer",
            &fp,
            s(&fresh),
        ],
        &[],
    );
    assert_ne!(new_fp, fp, "the new home signs with its own key");
    let before = state(&home).await;
    assert!(
        before.2 == 0 && before.3 >= 3,
        "events to compare: {before:?}"
    );
    assert_eq!(state(&fresh).await, before);
    assert_eq!(
        std::fs::read(fresh.join("keys/master.key")).unwrap(),
        std::fs::read(home.join("keys/master.key")).unwrap()
    );

    // Refusals, each before anything is written.
    let other = d.0.join("other");
    let e = run(
        &[
            "restore",
            &first,
            "--identity",
            id,
            "--signer",
            &new_fp,
            s(&other),
        ],
        &[],
    )
    .unwrap_err();
    assert!(e.contains("not the pinned signer"), "{e}");
    assert!(!other.exists(), "nothing written");
    let e = run(
        &[
            "restore",
            &first,
            "--identity",
            id,
            "--signer",
            &fp,
            s(&fresh),
        ],
        &[],
    )
    .unwrap_err();
    assert!(e.contains("not empty"), "{e}");
    let mut tampered = bytes.clone();
    let at = tampered.len() - 40;
    tampered[at] ^= 1;
    let bad = d.0.join("tampered.age");
    std::fs::write(&bad, tampered).unwrap();
    let e = run(
        &[
            "restore",
            s(&bad),
            "--identity",
            id,
            "--signer",
            &fp,
            s(&other),
        ],
        &[],
    )
    .unwrap_err();
    assert!(!other.exists(), "nothing written: {e}");
    let wrong = d.0.join("wrong-identity.txt");
    std::fs::write(&wrong, ok(&["backup-keygen"], &[])).unwrap();
    let e = run(
        &[
            "restore",
            &first,
            "--identity",
            s(&wrong),
            "--signer",
            &fp,
            s(&other),
        ],
        &[],
    )
    .unwrap_err();
    assert!(e.contains("decrypting"), "{e}");
    assert!(!other.exists());
}

#[tokio::test]
async fn export_then_import_reproduces_the_state() {
    let d = dir("export");
    let home = d.0.join("home");
    let fp = home_with_state(&home).await;
    let file = d.0.join("core.export");
    let config = home.join("config.toml");
    ok(&["export", "--config", s(&config), s(&file)], &[]);
    let e = run(&["export", "--config", s(&config), s(&file)], &[]).unwrap_err();
    assert!(e.contains("exists"), "never over a file: {e}");
    let copy = d.0.join("imported");
    ok(&["import", s(&file), "--signer", &fp, s(&copy)], &[]);
    assert_eq!(state(&copy).await, state(&home).await);
    let e = run(&["import", s(&file), "--signer", &fp, s(&copy)], &[]).unwrap_err();
    assert!(e.contains("not empty"), "{e}");
}

/// The bucket half against a local MinIO (`AINKRAD_MINIO=1` and `AINKRAD_BACKUP_*` set):
/// two backups go up under different names and one restores from `s3:<key>`.
#[tokio::test]
async fn a_backup_lands_in_the_bucket_and_restores_from_it() {
    if std::env::var("AINKRAD_MINIO").as_deref() != Ok("1") {
        eprintln!("skipped: AINKRAD_MINIO=1 runs it against AINKRAD_BACKUP_*");
        return;
    }
    let d = dir("minio");
    let home = d.0.join("home");
    let fp = home_with_state(&home).await;
    let keygen = ok(&["backup-keygen"], &[]);
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap();
    let env = [("AINKRAD_BACKUP_RECIPIENT", recipient)];
    let config = home.join("config.toml");
    let key = ok(&["backup", "--config", s(&config)], &env);
    let again = ok(&["backup", "--config", s(&config)], &env);
    assert!(
        key.starts_with("core/") && key.ends_with(".age") && key != again,
        "{key} {again}"
    );
    let fresh = d.0.join("restored");
    let src = format!("s3:{key}");
    ok(
        &[
            "restore",
            &src,
            "--identity",
            s(&identity),
            "--signer",
            &fp,
            s(&fresh),
        ],
        &[],
    );
    assert_eq!(state(&fresh).await, state(&home).await);
}
