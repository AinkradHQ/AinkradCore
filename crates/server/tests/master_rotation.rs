//! Master-key rotation (E2-07.1): `secrets rotate-master` re-seals every secret under a new
//! key in one transaction; crashes at either seam leave a store a re-run completes; a backup
//! carries the retired keys; the CLI refuses beside a server.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::ops::master_rotate::{Report, Stop, purge_retired, rotate};
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_core_server::store;
use ainkrad_core_server::store::secrets::{self, NewValue};
use sqlx::SqlitePool;

const NOW: &str = "2026-10-31T10:00:00.000Z";

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(name: &str) -> Dir {
    let d = std::env::temp_dir().join(format!("core-mkr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Dir(d)
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Result<(String, String), String> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"));
    cmd.args(args).env_remove("AINKRAD_CONFIG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let (o, e) = (
        String::from_utf8(out.stdout).unwrap().trim().to_owned(),
        String::from_utf8(out.stderr).unwrap(),
    );
    match out.status.success() {
        true => Ok((o, e)),
        false => Err(e),
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

struct Home {
    root: PathBuf,
    fp: String,
    pool: SqlitePool,
    owner: TestDevice,
    runner: TestDevice,
}

impl Home {
    fn db(&self) -> PathBuf {
        self.root.join("core.db")
    }
    fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }
    fn master(&self) -> SecretBox {
        SecretBox::from_private_file(&self.keys().join("master.key")).unwrap()
    }
    /// What `serve` would load: the current key and every spare beside it.
    fn serve_box(&self) -> SecretBox {
        SecretBox::for_serve(&self.keys().join("master.key")).unwrap()
    }
    fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.keys())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("master."))
            .collect();
        v.sort();
        v
    }
}

fn value(name: &str, version: usize) -> String {
    format!("throwaway-{name}-v{version}-4f2a")
}

/// A new home with `n` secrets, each rotated up to `versions`.
async fn home(root: &Path, n: usize, versions: usize) -> Home {
    let (fp, _) = run(&["init", s(root)], &[]).unwrap();
    let pool = store::connect(&root.join("core.db")).await.unwrap();
    let clock = Arc::new(SystemClock);
    let owner = TestDevice::enroll(&pool, "owner", "device", &["admin"], "fp", clock.clone()).await;
    let runner = TestDevice::enroll(&pool, "vm", "runner", &["runner"], "fp", clock).await;
    store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let h = Home {
        root: root.to_path_buf(),
        fp,
        pool,
        owner,
        runner,
    };
    let sealer = h.master();
    let scope = [h.runner.id.clone()];
    for i in 0..n {
        let name = format!("s{i}.token");
        for v in 1..=versions {
            let val = value(&name, v);
            let new = NewValue {
                value: &val,
                runners: Some(&scope),
                delivery: None,
            };
            match v {
                1 => secrets::create(
                    &h.pool,
                    &sealer,
                    &name,
                    &new,
                    &h.owner.id,
                    AuditActor::System,
                    NOW,
                )
                .await
                .map(drop),
                _ => secrets::rotate(
                    &h.pool,
                    &sealer,
                    &name,
                    &new,
                    &h.owner.id,
                    AuditActor::System,
                    NOW,
                )
                .await
                .map(drop),
            }
            .unwrap();
        }
    }
    h
}

/// Leases and redeems every secret through `sealer`; returns the values by name.
async fn read_all(h: &Home, sealer: &SecretBox, n: usize) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for i in 0..n {
        let name = format!("s{i}.token");
        let (lease, _) = secrets::lease(
            &h.pool,
            &name,
            &h.runner.id,
            None,
            &h.owner.id,
            AuditActor::System,
            NOW,
            1,
        )
        .await
        .unwrap();
        let got = secrets::redeem(
            &h.pool,
            sealer,
            &lease,
            &h.runner.id,
            AuditActor::System,
            NOW,
            2,
        )
        .await
        .unwrap();
        out.push((name, got.value.as_str().to_owned()));
    }
    out
}

async fn assert_reads(h: &Home, sealer: &SecretBox, n: usize, versions: usize) {
    for (name, got) in read_all(h, sealer, n).await {
        assert_eq!(got, value(&name, versions), "{name}");
    }
}

async fn rows(pool: &SqlitePool) -> Vec<(String, String, Vec<u8>)> {
    sqlx::query_as("SELECT name, key_id, sealed FROM core_secrets ORDER BY name")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn audits(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'secret.master_rotated'")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn go(h: &Home, stop: Stop) -> Result<Report, String> {
    rotate(&h.db(), &h.keys(), stop)
        .await
        .map_err(|e| e.to_string())
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn rotate_reseals_every_secret_and_reads_them_all_back() {
    let d = dir("all");
    let h = home(&d.0.join("home"), 5, 3).await;
    let (old_id, before) = (h.master().key_id().to_owned(), rows(&h.pool).await);
    let old_key = std::fs::read(h.keys().join("master.key")).unwrap();

    let r = go(&h, Stop::Never).await.unwrap();
    assert_eq!((r.secrets, r.moved, r.resumed), (5, 5, false));
    assert_eq!(r.from, old_id);
    let new = h.master();
    assert_eq!(new.key_id(), r.to);
    assert_ne!(new.key_id(), old_id);
    for ((n0, _, b0), (n1, k1, b1)) in before.iter().zip(rows(&h.pool).await) {
        assert_eq!((n0, k1.as_str()), (&n1, new.key_id()));
        assert_ne!(b0, &b1, "{n0}: fresh nonce and key");
    }
    // The new key alone reads every secret, at its last version.
    assert_reads(&h, &new, 5, 3).await;
    // Files: the new key is current (0600), the old one kept as retired (0600, same bytes).
    assert_eq!(mode(&h.keys().join("master.key")), 0o600);
    let retired = h.keys().join(format!("master.{old_id}.key.retired"));
    assert_eq!(mode(&retired), 0o600);
    assert_eq!(std::fs::read(&retired).unwrap(), old_key);
    assert_eq!(
        h.names(),
        [
            format!("master.{old_id}.key.retired"),
            "master.key".to_owned()
        ]
    );
    // Serve holds both keys.
    assert!(h.serve_box().holds(&old_id));
    // One audit row: key ids and counts, no key bytes.
    let a = audits(&h.pool).await;
    assert_eq!(a.len(), 1, "{a:?}");
    let v: serde_json::Value = serde_json::from_str(&a[0]).unwrap();
    assert_eq!(
        (v["total"].as_i64(), v["resealed"].as_i64()),
        (Some(5), Some(5))
    );
    assert_eq!(v["to_key_id"], r.to);
    assert_eq!(v["from_key_ids"][0], old_id);
    h.pool.close().await;
}

#[tokio::test]
async fn a_tampered_swapped_or_rolled_back_row_is_still_refused_after_rotation() {
    let d = dir("tamper");
    let h = home(&d.0.join("home"), 2, 2).await;
    go(&h, Stop::Never).await.unwrap();
    let sealer = h.master();
    let r = rows(&h.pool).await;
    // AAD swap: s0's blob under s1's name.
    sqlx::query("UPDATE core_secrets SET sealed = ? WHERE name = 's1.token'")
        .bind(&r[0].2)
        .execute(&h.pool)
        .await
        .unwrap();
    let (lease, _) = secrets::lease(
        &h.pool,
        "s1.token",
        &h.runner.id,
        None,
        &h.owner.id,
        AuditActor::System,
        NOW,
        1,
    )
    .await
    .unwrap();
    let e = secrets::redeem(
        &h.pool,
        &sealer,
        &lease,
        &h.runner.id,
        AuditActor::System,
        NOW,
        2,
    )
    .await
    .err()
    .expect("swapped blob refused");
    assert!(e.to_string().contains("secrets_unavailable"), "{e}");
    // Version rollback: the right blob, an older version number.
    sqlx::query("UPDATE core_secrets SET sealed = ?, version = 1 WHERE name = 's1.token'")
        .bind(&r[1].2)
        .execute(&h.pool)
        .await
        .unwrap();
    let (lease, _) = secrets::lease(
        &h.pool,
        "s1.token",
        &h.runner.id,
        None,
        &h.owner.id,
        AuditActor::System,
        NOW,
        1,
    )
    .await
    .unwrap();
    assert!(
        secrets::redeem(
            &h.pool,
            &sealer,
            &lease,
            &h.runner.id,
            AuditActor::System,
            NOW,
            2
        )
        .await
        .is_err(),
        "a rolled-back version opens"
    );
    // A changed byte.
    let mut flipped = r[0].2.clone();
    *flipped.last_mut().unwrap() ^= 1;
    sqlx::query("UPDATE core_secrets SET sealed = ? WHERE name = 's0.token'")
        .bind(&flipped)
        .execute(&h.pool)
        .await
        .unwrap();
    let (lease, _) = secrets::lease(
        &h.pool,
        "s0.token",
        &h.runner.id,
        None,
        &h.owner.id,
        AuditActor::System,
        NOW,
        1,
    )
    .await
    .unwrap();
    assert!(
        secrets::redeem(
            &h.pool,
            &sealer,
            &lease,
            &h.runner.id,
            AuditActor::System,
            NOW,
            2
        )
        .await
        .is_err()
    );
    // And a rotation over the damage refuses and changes nothing.
    let before = rows(&h.pool).await;
    let e = go(&h, Stop::Never).await.unwrap_err();
    assert!(e.contains("did not open"), "{e}");
    assert_eq!(rows(&h.pool).await, before);
    h.pool.close().await;
}

#[tokio::test]
async fn a_crash_before_the_commit_changes_nothing_and_a_rerun_completes() {
    let d = dir("precommit");
    let h = home(&d.0.join("home"), 3, 2).await;
    let (old_id, before) = (h.master().key_id().to_owned(), rows(&h.pool).await);
    let e = go(&h, Stop::BeforeCommit).await.unwrap_err();
    assert!(e.contains("before commit"), "{e}");
    assert_eq!(rows(&h.pool).await, before, "rolled back");
    assert!(
        audits(&h.pool).await.is_empty(),
        "the audit row rolled back with it"
    );
    assert_eq!(h.master().key_id(), old_id);
    assert_reads(&h, &h.serve_box(), 3, 2).await;
    let pending = h
        .names()
        .into_iter()
        .find(|n| ainkrad_core_server::ops::secretbox::key_file_kind(n).is_some_and(|k| !k.1))
        .expect("a pending key");

    let r = go(&h, Stop::Never).await.unwrap();
    assert!(r.resumed && r.moved == 3, "{r:?}");
    assert_eq!(
        format!("master.{}.key", r.to),
        pending,
        "the pending key is the target"
    );
    assert_eq!(h.master().key_id(), r.to);
    assert_reads(&h, &h.master(), 3, 2).await;
    assert_eq!(audits(&h.pool).await.len(), 1);
    h.pool.close().await;
}

#[tokio::test]
async fn a_crash_after_the_commit_is_served_and_a_rerun_is_a_no_op_that_switches() {
    let d = dir("preswitch");
    let h = home(&d.0.join("home"), 3, 2).await;
    let old_id = h.master().key_id().to_owned();
    go(&h, Stop::BeforeSwitch).await.unwrap_err();
    // Rows under the new key, master.key still the old one: serve opens them with the spare.
    assert_eq!(h.master().key_id(), old_id);
    assert!(rows(&h.pool).await.iter().all(|r| r.1 != old_id));
    assert_reads(&h, &h.serve_box(), 3, 2).await;
    // Without the spare the old key alone does not open them (nothing silently falls back).
    let e = secrets::lease(
        &h.pool,
        "s0.token",
        &h.runner.id,
        None,
        &h.owner.id,
        AuditActor::System,
        NOW,
        1,
    )
    .await
    .unwrap();
    let e = secrets::redeem(
        &h.pool,
        &h.master(),
        &e.0,
        &h.runner.id,
        AuditActor::System,
        NOW,
        2,
    )
    .await
    .err()
    .expect("old key alone");
    assert!(e.to_string().contains("secrets_unavailable"), "{e}");
    let after = rows(&h.pool).await;

    let r = go(&h, Stop::Never).await.unwrap();
    assert!(r.resumed);
    assert_eq!(r.moved, 0, "nothing left to move");
    assert_eq!(rows(&h.pool).await, after, "no row touched");
    assert_eq!(
        audits(&h.pool).await.len(),
        1,
        "audited once, at the commit"
    );
    assert_eq!(h.master().key_id(), r.to);
    assert_reads(&h, &h.master(), 3, 2).await;
    h.pool.close().await;
}

#[tokio::test]
async fn a_missing_wrong_or_loose_key_is_refused_and_nothing_changes() {
    let d = dir("refuse");
    let h = home(&d.0.join("home"), 2, 1).await;
    let before = rows(&h.pool).await;
    let names = h.names();

    // A row names a key that is nowhere in keys/.
    sqlx::query("UPDATE core_secrets SET key_id = '0123456789abcdef' WHERE name = 's0.token'")
        .execute(&h.pool)
        .await
        .unwrap();
    let e = go(&h, Stop::Never).await.unwrap_err();
    assert!(
        e.contains("0123456789abcdef") && e.contains("Nothing was changed"),
        "{e}"
    );
    assert_eq!(h.names(), names, "no key file was written");
    sqlx::query("UPDATE core_secrets SET key_id = ? WHERE name = 's0.token'")
        .bind(&before[0].1)
        .execute(&h.pool)
        .await
        .unwrap();

    // Group-readable master key.
    let key = h.keys().join("master.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
    let e = go(&h, Stop::Never).await.unwrap_err();
    assert!(e.contains("must be 0600"), "{e}");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

    // A spare whose name is not its key.
    let liar = h.keys().join("master.0123456789abcdef.key.retired");
    std::fs::write(&liar, [3u8; 32]).unwrap();
    std::fs::set_permissions(&liar, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        go(&h, Stop::Never).await.is_ok(),
        "an unused liar spare is only a warning"
    );
    std::fs::remove_file(&liar).unwrap();

    // A retired copy of the current key that is not that key: refused, and the good state kept.
    let current = h.master().key_id().to_owned();
    let bad = h.keys().join(format!("master.{current}.key.retired"));
    std::fs::write(&bad, [9u8; 32]).unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    let names = h.names();
    let e = go(&h, Stop::Never).await.unwrap_err();
    assert!(e.contains("retired copy of the current key"), "{e}");
    assert_eq!(h.names(), names, "no pending key written");
    assert_eq!(std::fs::read(&bad).unwrap(), [9u8; 32], "left as it was");
    std::fs::remove_file(&bad).unwrap();

    // No master key at all.
    std::fs::remove_file(h.keys().join("master.key")).unwrap();
    let e = go(&h, Stop::Never).await.unwrap_err();
    assert!(e.contains("no master key"), "{e}");
    h.pool.close().await;
}

#[tokio::test]
async fn purge_removes_only_old_retired_keys_no_secret_names() {
    let d = dir("purge");
    let h = home(&d.0.join("home"), 1, 1).await;
    let old_id = h.master().key_id().to_owned();
    go(&h, Stop::Never).await.unwrap();
    let retired = h.keys().join(format!("master.{old_id}.key.retired"));
    assert!(
        purge_retired(&h.db(), &h.keys(), 30)
            .await
            .unwrap()
            .is_empty(),
        "too young"
    );
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(40 * 86_400);
    let set_old = || {
        std::fs::File::options()
            .write(true)
            .open(&retired)
            .unwrap()
            .set_modified(old)
            .unwrap()
    };
    set_old();
    // A huge window must not overflow into purging everything.
    assert!(
        purge_retired(&h.db(), &h.keys(), u64::MAX)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(retired.exists());
    // Still named by a row: kept.
    sqlx::query("UPDATE core_secrets SET key_id = ?")
        .bind(&old_id)
        .execute(&h.pool)
        .await
        .unwrap();
    assert!(
        purge_retired(&h.db(), &h.keys(), 30)
            .await
            .unwrap()
            .is_empty(),
        "named"
    );
    assert!(retired.exists());
    let current = h.master().key_id().to_owned();
    sqlx::query("UPDATE core_secrets SET key_id = ?")
        .bind(&current)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        purge_retired(&h.db(), &h.keys(), 30).await.unwrap(),
        [old_id]
    );
    assert!(!retired.exists());
    assert!(
        h.keys().join("master.key").exists(),
        "the current key is never purged"
    );
    h.pool.close().await;
}

#[tokio::test]
async fn the_cli_rotates_and_refuses_beside_a_server_or_another_admin() {
    let d = dir("cli");
    let h = home(&d.0.join("home"), 2, 1).await;
    let db = h.db();
    let before = rows(&h.pool).await;
    let key_bytes = std::fs::read(h.keys().join("master.key")).unwrap();

    // A listening socket: a server may be running.
    let sock = std::os::unix::net::UnixListener::bind(h.root.join("core.sock")).unwrap();
    let e = run(&["secrets", "rotate-master", s(&db)], &[]).unwrap_err();
    assert!(e.contains("a server may be running"), "{e}");
    drop(sock);
    // Another holder of <db>.lock (a serve with a custom socket, another admin command).
    let lock = std::fs::File::create(h.root.join("core.db.lock")).unwrap();
    lock.lock().unwrap();
    let e = run(&["secrets", "rotate-master", s(&db)], &[]).unwrap_err();
    assert!(
        e.contains("is in use by a server or another admin command"),
        "{e}"
    );
    assert_eq!(rows(&h.pool).await, before);
    assert_eq!(
        std::fs::read(h.keys().join("master.key")).unwrap(),
        key_bytes
    );
    drop(lock);
    // No database: refused, not created.
    let e = run(
        &["secrets", "rotate-master", s(&d.0.join("none/core.db"))],
        &[],
    )
    .unwrap_err();
    assert!(e.contains("no database"), "{e}");

    let (out, err) = run(&["secrets", "rotate-master", s(&db)], &[]).unwrap();
    assert!(err.contains("2 of 2 secrets re-sealed"), "{err}");
    let fresh = std::fs::read(h.keys().join("master.key")).unwrap();
    assert_ne!(fresh, key_bytes);
    // No key material on stdout or stderr.
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    for key in [&key_bytes, &fresh] {
        for text in [&out, &err] {
            assert!(
                !text.contains(&hex(key))
                    && !text.contains(&ainkrad_core_server::auth::crypto::b64(key))
            );
        }
    }
    assert_reads(&h, &h.master(), 2, 1).await;
    let (_, err) = run(
        &[
            "secrets",
            "purge-retired-keys",
            s(&db),
            "--older-than-days",
            "0",
        ],
        &[],
    )
    .unwrap();
    assert!(err.contains("1 retired master key(s) removed"), "{err}");
    let e = run(
        &[
            "secrets",
            "purge-retired-keys",
            s(&db),
            "--older-than-days",
            "x",
        ],
        &[],
    )
    .unwrap_err();
    assert!(e.contains("whole number"), "{e}");
    h.pool.close().await;
}

fn backup(h: &Home, recipient: &str) -> String {
    run(
        &[
            "backup",
            "--config",
            s(&h.root.join("config.toml")),
            "--local-only",
        ],
        &[("AINKRAD_BACKUP_RECIPIENT", recipient)],
    )
    .unwrap()
    .0
}

fn restore(file: &str, identity: &Path, fp: &str, to: &Path) {
    run(
        &[
            "restore",
            file,
            "--identity",
            s(identity),
            "--signer",
            fp,
            s(to),
        ],
        &[],
    )
    .unwrap();
}

#[tokio::test]
async fn backups_across_a_rotation_restore_with_every_key_their_rows_name() {
    let d = dir("backup");
    let h = home(&d.0.join("home"), 2, 2).await;
    let (keygen, _) = run(&["backup-keygen"], &[]).unwrap();
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap()
        .to_owned();
    let old_id = h.master().key_id().to_owned();

    let before = backup(&h, &recipient);
    go(&h, Stop::BeforeSwitch).await.unwrap_err();
    // A backup in the crash window: rows under the new key, master.key the old one.
    let mid = backup(&h, &recipient);
    go(&h, Stop::Never).await.unwrap();
    let new_id = h.master().key_id().to_owned();
    let after = backup(&h, &recipient);
    h.pool.close().await;

    // Before: the old key is current and reads the old rows.
    let r1 = d.0.join("r-before");
    restore(&before, &identity, &h.fp, &r1);
    let k = SecretBox::for_serve(&r1.join("keys/master.key")).unwrap();
    assert_eq!(k.key_id(), old_id);
    let pool = store::connect(&r1.join("core.db")).await.unwrap();
    assert!(rows(&pool).await.iter().all(|r| r.1 == old_id));
    pool.close().await;

    // Mid-rotation: the rows name the new key, which came with the backup as a spare.
    let r2 = d.0.join("r-mid");
    restore(&mid, &identity, &h.fp, &r2);
    let k = SecretBox::for_serve(&r2.join("keys/master.key")).unwrap();
    let pool = store::connect(&r2.join("core.db")).await.unwrap();
    let named: Vec<String> = rows(&pool).await.into_iter().map(|r| r.1).collect();
    assert!(
        named.iter().all(|id| id == &new_id && k.holds(id)),
        "{named:?}"
    );
    pool.close().await;
    for f in std::fs::read_dir(r2.join("keys")).unwrap() {
        let f = f.unwrap();
        assert_eq!(mode(&f.path()), 0o600, "{:?}", f.file_name());
    }
    // ... and the restored home finishes the rotation.
    let (_, err) = run(&["secrets", "rotate-master", s(&r2.join("core.db"))], &[]).unwrap();
    assert!(err.contains("resumed an earlier run"), "{err}");

    // After: the new key is current and the old one came along, retired.
    let r3 = d.0.join("r-after");
    restore(&after, &identity, &h.fp, &r3);
    let k = SecretBox::for_serve(&r3.join("keys/master.key")).unwrap();
    assert_eq!(k.key_id(), new_id);
    assert!(k.holds(&old_id), "the retired key is resolvable");
    assert!(
        r3.join(format!("keys/master.{old_id}.key.retired"))
            .exists()
    );
    let pool = store::connect(&r3.join("core.db")).await.unwrap();
    assert!(rows(&pool).await.iter().all(|r| r.1 == new_id));
    pool.close().await;
}

#[tokio::test]
async fn a_restore_whose_secrets_name_a_key_the_archive_lacks_fails_loudly() {
    let d = dir("lostkey");
    let h = home(&d.0.join("home"), 2, 1).await;
    let (keygen, _) = run(&["backup-keygen"], &[]).unwrap();
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap()
        .to_owned();
    let old_id = h.master().key_id().to_owned();
    go(&h, Stop::Never).await.unwrap();
    let (_, err) = run(
        &[
            "secrets",
            "purge-retired-keys",
            s(&h.db()),
            "--older-than-days",
            "0",
        ],
        &[],
    )
    .unwrap();
    assert!(err.contains(&old_id), "{err}");
    // The database now names the purged key (an older database, or a rolled-back copy).
    sqlx::query("UPDATE core_secrets SET key_id = ?")
        .bind(&old_id)
        .execute(&h.pool)
        .await
        .unwrap();
    let file = backup(&h, &recipient);
    h.pool.close().await;
    let to = d.0.join("restored");
    let e = run(
        &[
            "restore",
            &file,
            "--identity",
            s(&identity),
            "--signer",
            &h.fp,
            s(&to),
        ],
        &[],
    )
    .unwrap_err();
    assert!(e.contains("restore refused") && e.contains(&old_id), "{e}");
    assert!(
        !to.join("core.db").exists(),
        "the half-built home is removed"
    );
}

// The sealed key files (the Core identity and the ACME account) move with the master key.

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::ops::sealed;

/// What `serve` has made by now: the identity, and an ACME account, both sealed under the
/// current master key. The identity's fingerprint.
fn put_state(h: &Home) -> String {
    let seal = h.master();
    let fp = Identity::load_or_create(&h.root, &seal).unwrap().fp;
    let tls = h.root.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let account = tls.join("account.json");
    let kf = sealed::KeyFile {
        path: &account,
        home: &h.root,
        label: sealed::ACME_LABEL,
    };
    sealed::create(kf, &seal, b"{\"stand-in\":1}").unwrap();
    fp
}

fn file_key(h: &Home, rel: &str) -> String {
    sealed::key_id_of(&std::fs::read(h.root.join(rel)).unwrap()).unwrap()
}

#[tokio::test]
async fn rotation_keeps_the_identity_and_the_account_usable_through_every_crash_window() {
    let d = dir("sealed-files");
    let h = home(&d.0.join("home"), 2, 1).await;
    let fp = put_state(&h);
    let old_id = h.master().key_id().to_owned();
    let id_file = "core-identity.p8";
    let account = "tls/account.json";
    assert_eq!(file_key(&h, id_file), old_id);

    // Crash after the commit, before the files: still under the old key, opened with the same
    // identity by what serve loads; a purge keeps the retired key the file still names.
    go(&h, Stop::BeforeFiles).await.unwrap_err();
    assert_eq!(file_key(&h, id_file), old_id);
    let served = h.serve_box();
    assert_eq!(Identity::load_or_create(&h.root, &served).unwrap().fp, fp);
    assert!(
        purge_retired(&h.db(), &h.keys(), 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.names().iter().any(|n| n.ends_with(".retired")));

    // Crash after the files, before the switch: under the pending key, master.key still the
    // old one; serve opens them through the spare.
    go(&h, Stop::BeforeSwitch).await.unwrap_err();
    let pending = file_key(&h, id_file);
    assert_ne!(pending, old_id);
    assert_eq!(file_key(&h, account), pending);
    assert_eq!(h.master().key_id(), old_id);
    assert_eq!(
        Identity::load_or_create(&h.root, &h.serve_box())
            .unwrap()
            .fp,
        fp
    );
    assert!(
        Identity::load_or_create(&h.root, &h.master()).is_err(),
        "the old key alone does not open it, and no new identity is made"
    );

    // Done: same identity, new key, account readable; the retired key is now unnamed.
    let r = go(&h, Stop::Never).await.unwrap();
    assert_eq!(
        (r.to.as_str(), h.master().key_id()),
        (pending.as_str(), pending.as_str())
    );
    assert_eq!(
        Identity::load_or_create(&h.root, &h.master()).unwrap().fp,
        fp
    );
    let acct = std::fs::read(h.root.join(account)).unwrap();
    assert_eq!(
        sealed::open_bytes(&h.master(), sealed::ACME_LABEL, &acct)
            .unwrap()
            .as_slice(),
        b"{\"stand-in\":1}"
    );
    assert_eq!(mode(&h.root.join(id_file)), 0o600);
    assert_eq!(
        purge_retired(&h.db(), &h.keys(), 0).await.unwrap(),
        vec![old_id]
    );
    assert_eq!(
        Identity::load_or_create(&h.root, &h.serve_box())
            .unwrap()
            .fp,
        fp
    );
    h.pool.close().await;
}

#[tokio::test]
async fn rotation_refuses_when_a_key_file_names_a_key_the_home_does_not_hold() {
    let d = dir("sealed-unheld");
    let h = home(&d.0.join("home"), 0, 0).await;
    put_state(&h);
    let before = std::fs::read(h.root.join("core-identity.p8")).unwrap();
    // A master key that is not the one the identity was sealed under (a swapped file).
    let master = h.keys().join("master.key");
    std::fs::write(&master, [9u8; 32]).unwrap();
    let e = go(&h, Stop::Never).await.unwrap_err();
    assert!(
        e.contains("not in") && e.contains("Nothing was changed"),
        "{e}"
    );
    assert_eq!(
        std::fs::read(h.root.join("core-identity.p8")).unwrap(),
        before
    );
    assert_eq!(h.names(), vec!["master.key".to_owned()], "nothing written");
    h.pool.close().await;
}

#[tokio::test]
async fn backups_carry_the_sealed_identity_and_restore_it_before_during_and_after_a_rotation() {
    let d = dir("sealed-backup");
    let h = home(&d.0.join("home"), 1, 1).await;
    let fp = put_state(&h);
    let (keygen, _) = run(&["backup-keygen"], &[]).unwrap();
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap()
        .to_owned();
    let before = backup(&h, &recipient);
    go(&h, Stop::BeforeSwitch).await.unwrap_err();
    let mid = backup(&h, &recipient);
    go(&h, Stop::Never).await.unwrap();
    let after = backup(&h, &recipient);
    h.pool.close().await;
    for (name, file) in [("before", before), ("mid", mid), ("after", after)] {
        let to = d.0.join(format!("r-{name}"));
        restore(&file, &identity, &h.fp, &to);
        let raw = std::fs::read(to.join("core-identity.p8")).unwrap();
        assert!(sealed::is_sealed(&raw), "{name}: restored sealed");
        let seal = SecretBox::for_home(&to).unwrap();
        assert_eq!(
            Identity::load_or_create(&to, &seal).unwrap().fp,
            fp,
            "{name}"
        );
        assert_eq!(mode(&to.join("core-identity.p8")), 0o600);
    }
}

#[tokio::test]
async fn purge_refuses_to_guess_when_a_sealed_file_cannot_be_read() {
    let d = dir("sealed-purge");
    let h = home(&d.0.join("home"), 0, 0).await;
    put_state(&h);
    let old_id = h.master().key_id().to_owned();
    go(&h, Stop::BeforeFiles).await.unwrap_err();
    let retired = h.keys().join(format!("master.{old_id}.key.retired"));
    assert!(retired.exists());
    // The identity file's key id is damaged: the file still names the retired key, but a purge
    // cannot tell, so it must not delete anything.
    let file = h.root.join("core-identity.p8");
    let good = std::fs::read(&file).unwrap();
    let mut bad = good.clone();
    bad[5] = b'Z';
    std::fs::write(&file, &bad).unwrap();
    let e = purge_retired(&h.db(), &h.keys(), 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("unreadable key id"), "{e}");
    assert!(retired.exists(), "nothing was purged");
    assert!(go(&h, Stop::Never).await.is_err(), "rotation refuses too");
    // Repaired, the file names the retired key and the purge keeps it.
    std::fs::write(&file, &good).unwrap();
    assert!(
        purge_retired(&h.db(), &h.keys(), 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(retired.exists());
    h.pool.close().await;
}
