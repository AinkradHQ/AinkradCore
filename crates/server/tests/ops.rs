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

/// Runs the binary, which must succeed: its trimmed stdout and its stderr.
fn ok_err(args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(args)
        .env_remove("AINKRAD_CONFIG")
        .output()
        .unwrap();
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "{args:?}: {err}");
    (
        String::from_utf8(out.stdout).unwrap().trim().to_owned(),
        err,
    )
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
    let pool = store::connect(&db).await.unwrap();
    let mut ids = Vec::new();
    for name in ["mac", "phone"] {
        let clock = std::sync::Arc::new(ainkrad_core_server::scheduler::SystemClock);
        let d = ainkrad_core_server::auth::testing::TestDevice::enroll(
            &pool,
            name,
            "device",
            &["read"],
            "fp",
            clock,
        )
        .await;
        ids.push(d.id);
    }
    ok(&["device", "revoke", s(&db), &ids[1]], &[]);
    let mut tx = store::begin_write(&pool).await.unwrap();
    kinds::register(&mut tx, "probe", &[("probe.line", "read")], &[])
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
        "device list",
        "device revoke",
        "bootstrap",
        "recover",
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
    // This home never served, so it has no Core identity: the old format's shape. It restores,
    // and says loudly that everything must be paired again.
    let (new_fp, err) = ok_err(&[
        "restore",
        &first,
        "--identity",
        id,
        "--signer",
        &fp,
        s(&fresh),
    ]);
    assert!(
        err.contains("WARNING") && err.contains("no Core identity key"),
        "{err}"
    );
    assert!(!fresh.join("core-identity.p8").exists());
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

/// Disaster recovery (E1 exit gate finding 1): a backup carries the Core identity, encrypted,
/// and a restore puts it back, 0600, so the paired devices and runners still accept the Core.
#[tokio::test]
async fn a_restored_home_keeps_the_core_identity() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("identity");
    let home = d.0.join("home");
    let fp = home_with_state(&home).await;
    // What serve makes on first start.
    let core = ainkrad_core_server::auth::Identity::load_or_create(
        &home,
        &ainkrad_core_server::ops::secretbox::SecretBox::for_home(&home).unwrap(),
    )
    .unwrap();
    let der = std::fs::read(home.join("core-identity.p8")).unwrap();
    let keygen = ok(&["backup-keygen"], &[]);
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap();
    let config = home.join("config.toml");
    let file = ok(
        &["backup", "--config", s(&config), "--local-only"],
        &[("AINKRAD_BACKUP_RECIPIENT", recipient)],
    );
    let sealed = std::fs::read(&file).unwrap();
    assert!(
        !sealed.windows(der.len()).any(|w| w == der.as_slice()),
        "the identity key is only inside the encrypted payload"
    );

    let fresh = d.0.join("restored");
    let (_, err) = ok_err(&[
        "restore",
        &file,
        "--identity",
        s(&identity),
        "--signer",
        &fp,
        s(&fresh),
    ]);
    assert!(
        err.contains("Core identity was restored") && err.contains(&core.fp),
        "{err}"
    );
    assert!(!err.contains("WARNING"), "{err}");
    let restored = fresh.join("core-identity.p8");
    let mode = std::fs::metadata(&restored).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        der,
        "the same key, not a new one"
    );
    let again = ainkrad_core_server::auth::Identity::load_or_create(
        &fresh,
        &ainkrad_core_server::ops::secretbox::SecretBox::for_home(&fresh).unwrap(),
    )
    .unwrap();
    assert_eq!(again.fp, core.fp);
    assert_eq!(again.spki, core.spki);

    // An export is plaintext: it never carries the identity, and its import says so.
    let export = d.0.join("core.export");
    ok(&["export", "--config", s(&config), s(&export)], &[]);
    let plain = std::fs::read(&export).unwrap();
    assert!(!plain.windows(der.len()).any(|w| w == der.as_slice()));
    let (_, err) = ok_err(&[
        "import",
        s(&export),
        "--signer",
        &fp,
        s(&d.0.join("imported")),
    ]);
    assert!(err.contains("WARNING"), "{err}");
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

/// The secrets broker (E2-07): an export (plaintext, beside the master key) never carries a
/// secret, sealed or not; an encrypted backup does, and it opens on the restored home.
#[tokio::test]
async fn an_export_never_carries_secrets_and_a_backup_does() {
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::settings::{Key, Scope};
    use ainkrad_core_server::ops::secretbox::SecretBox;
    use ainkrad_core_server::store::secrets;
    const VALUE: &str = "export-planted-value-3c9d";
    let d = dir("secrets");
    let home = d.0.join("home");
    let fp = home_with_state(&home).await;
    let pool = store::connect(&home.join("core.db")).await.unwrap();
    let clock = std::sync::Arc::new(ainkrad_core_server::scheduler::SystemClock);
    use ainkrad_core_server::auth::testing::TestDevice;
    let owner = TestDevice::enroll(&pool, "owner", "device", &["admin"], "fp", clock.clone()).await;
    let runner = TestDevice::enroll(&pool, "vm", "runner", &["runner"], "fp", clock).await;
    let now = "2026-10-30T10:00:00.000Z";
    store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        now,
    )
    .await
    .unwrap();
    let sealer = SecretBox::from_file(&home.join("keys/master.key")).unwrap();
    let scope = [runner.id.clone()];
    let new = secrets::NewValue {
        value: VALUE,
        runners: Some(&scope),
        delivery: None,
    };
    secrets::create(
        &pool,
        &sealer,
        "k",
        &new,
        &owner.id,
        AuditActor::System,
        now,
    )
    .await
    .unwrap();
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT sealed FROM core_secrets")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;

    let config = home.join("config.toml");
    let file = d.0.join("core.export");
    ok(&["export", "--config", s(&config), s(&file)], &[]);
    let plain = std::fs::read(&file).unwrap();
    let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(
        !has(&plain, &sealed[13..45]),
        "a sealed value in the export"
    );
    assert!(!has(&plain, VALUE.as_bytes()));
    let imported = d.0.join("imported");
    ok(&["import", s(&file), "--signer", &fp, s(&imported)], &[]);
    let pool = store::connect(&imported.join("core.db")).await.unwrap();
    assert!(secrets::list(&pool).await.unwrap().is_empty());
    pool.close().await;

    let keygen = ok(&["backup-keygen"], &[]);
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap();
    let env = [("AINKRAD_BACKUP_RECIPIENT", recipient)];
    let backup = ok(&["backup", "--config", s(&config), "--local-only"], &env);
    let restored = d.0.join("restored");
    ok_err(&[
        "restore",
        &backup,
        "--identity",
        s(&identity),
        "--signer",
        &fp,
        s(&restored),
    ]);
    let pool = store::connect(&restored.join("core.db")).await.unwrap();
    let sealer = SecretBox::from_file(&restored.join("keys/master.key")).unwrap();
    let (lease, _) = secrets::lease(
        &pool,
        "k",
        &runner.id,
        None,
        &owner.id,
        AuditActor::System,
        now,
        1,
    )
    .await
    .unwrap();
    let got = secrets::redeem(
        &pool,
        &sealer,
        &lease,
        &runner.id,
        AuditActor::System,
        now,
        2,
    )
    .await
    .unwrap();
    assert_eq!(got.value.as_str(), VALUE);
    pool.close().await;
}

/// The identity is sealed under the master key: an archive that carries it without that key
/// is refused (nothing written), and a legacy plaintext one is sealed in the new home.
#[tokio::test]
async fn a_sealed_identity_needs_its_master_key_and_a_legacy_one_is_sealed_on_restore() {
    use ainkrad_core_server::auth::Identity;
    use ainkrad_core_server::ops::{archive, sealed, secretbox::SecretBox};
    let d = dir("seal-restore");
    let home = d.0.join("home");
    let fp = home_with_state(&home).await;
    let signer =
        archive::load_signer(&std::fs::read(home.join("keys/backup-signing.p8")).unwrap()).unwrap();
    let core = Identity::load_or_create(&home, &SecretBox::for_home(&home).unwrap()).unwrap();
    let (db, master, sealed_id) = (
        home.join("core.db"),
        home.join("keys/master.key"),
        home.join("core-identity.p8"),
    );
    assert!(sealed::is_sealed(&std::fs::read(&sealed_id).unwrap()));
    let make = |name: &str, files: &[(&str, &Path)]| -> PathBuf {
        let p = d.0.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        archive::write(&mut f, &signer, "export", "2026-11-01T00:00:00.000Z", files).unwrap();
        p
    };

    // Sealed identity, no master key in the archive: refused, nothing left behind.
    let a = make(
        "a.export",
        &[("core.db", &db), ("core-identity.p8", &sealed_id)],
    );
    let ra = d.0.join("ra");
    let e = run(&["import", s(&a), "--signer", &fp, s(&ra)], &[]).unwrap_err();
    assert!(e.contains("sealed") && e.contains("no master key"), "{e}");
    assert!(!ra.exists());

    // Sealed identity with a DIFFERENT master key: refused too, never a new identity.
    let other = d.0.join("other.key");
    std::fs::write(&other, [5u8; 32]).unwrap();
    let b = make(
        "b.export",
        &[
            ("core.db", &db),
            ("keys/master.key", &other),
            ("core-identity.p8", &sealed_id),
        ],
    );
    let rb = d.0.join("rb");
    let e = run(&["import", s(&b), "--signer", &fp, s(&rb)], &[]).unwrap_err();
    assert!(e.contains("does not hold"), "{e}");
    assert!(!rb.exists());

    // The same key set restores it, still sealed.
    let c = make(
        "c.export",
        &[
            ("core.db", &db),
            ("keys/master.key", &master),
            ("core-identity.p8", &sealed_id),
        ],
    );
    let rc = d.0.join("rc");
    ok(&["import", s(&c), "--signer", &fp, s(&rc)], &[]);
    let seal = SecretBox::for_home(&rc).unwrap();
    assert_eq!(Identity::load_or_create(&rc, &seal).unwrap().fp, core.fp);

    // A legacy plaintext identity (a backup made before sealing) is sealed on restore.
    let der = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let legacy = d.0.join("legacy.p8");
    std::fs::write(&legacy, der.as_ref()).unwrap();
    let want = Identity::from_pkcs8(der.as_ref()).unwrap().fp;
    let l = make(
        "l.export",
        &[
            ("core.db", &db),
            ("keys/master.key", &master),
            ("core-identity.p8", &legacy),
        ],
    );
    let rl = d.0.join("rl");
    ok(&["import", s(&l), "--signer", &fp, s(&rl)], &[]);
    let raw = std::fs::read(rl.join("core-identity.p8")).unwrap();
    assert!(sealed::is_sealed(&raw));
    assert!(!raw.windows(der.as_ref().len()).any(|w| w == der.as_ref()));
    let seal = SecretBox::for_home(&rl).unwrap();
    assert_eq!(Identity::load_or_create(&rl, &seal).unwrap().fp, want);
}
