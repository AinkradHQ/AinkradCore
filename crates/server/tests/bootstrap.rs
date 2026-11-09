//! The host's verbs (handshake spec §7.3, §12, §17.24, §17.26, review H2), through the binary:
//! `bootstrap` pairs the first device and is refused once one exists (revoked included); a
//! declined bootstrap can be run again; `recover` enrols a new admin whatever devices exist,
//! revoking the others only when told to, and is audited.

use std::process::Stdio;
use std::sync::Arc;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::gateway::Local;
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_core_server::store::{self, gov};
use axum::body::{Body, to_bytes};
use axum::http::Request;
use sqlx::SqlitePool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout};
use tower::ServiceExt;

struct Host {
    dir: std::path::PathBuf,
    db: std::path::PathBuf,
    pool: SqlitePool,
    app: App,
    identity: Arc<Identity>,
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn host(name: &str) -> Host {
    let dir = std::env::temp_dir().join(format!("core-host-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");
    let pool = store::connect(&db).await.unwrap();
    // The master key the spawned server loads (it seals the identity).
    std::fs::create_dir_all(dir.join("keys")).unwrap();
    std::fs::write(dir.join("keys/master.key"), [7u8; 32]).unwrap();
    std::fs::set_permissions(
        dir.join("keys/master.key"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
    let app = App::new(
        pool.clone(),
        Arc::new(SystemClock),
        "localhost".to_owned(),
        identity.clone(),
    );
    Host {
        dir,
        db,
        pool,
        app,
        identity,
    }
}

fn spawn(args: &[&str]) -> (Child, Lines<BufReader<ChildStdout>>) {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    (child, lines)
}

/// The value after `prefix ` on the next line that starts with it.
async fn line(lines: &mut Lines<BufReader<ChildStdout>>, prefix: &str) -> String {
    loop {
        let l = lines
            .next_line()
            .await
            .unwrap()
            .expect("the verb printed more");
        if let Some(rest) = l.strip_prefix(&format!("{prefix} ")) {
            return rest.to_owned();
        }
    }
}

async fn type_in(child: &mut Child, text: &str) {
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(text.as_bytes())
        .await
        .unwrap();
}

/// A new device claims `code` over the host's socket; it comes back with its id and the SAS.
async fn claim(h: &Host, code: &str) -> (TestDevice, String) {
    let mut dev = TestDevice::new(&h.identity.fp, Arc::new(SystemClock));
    let mut r = Request::post("/pair/claim")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Body::from(dev.claim_body(Some(code), None).to_string()))
        .unwrap();
    r.extensions_mut().insert(Local { same_user: true });
    let res = router(h.app.clone()).oneshot(r).await.unwrap();
    assert_eq!(res.status(), 202);
    let got: serde_json::Value =
        serde_json::from_slice(&to_bytes(res.into_body(), 1 << 16).await.unwrap()).unwrap();
    dev.id = got["device_id"].as_str().unwrap().to_owned();
    (dev, got["sas"].as_str().unwrap().to_owned())
}

/// Runs a host verb through code, claim, SAS and `answer`: the claimant and the verb's success.
async fn run(h: &Host, args: &[&str], before: &str, answer: &str) -> (TestDevice, bool) {
    let (mut child, mut lines) = spawn(args);
    type_in(&mut child, before).await;
    let code = line(&mut lines, "code").await;
    assert_eq!(line(&mut lines, "core_fp").await, h.identity.fp);
    let (dev, sas) = claim(h, &code).await;
    assert!(line(&mut lines, "device").await.starts_with(&dev.id));
    assert_eq!(
        line(&mut lines, "sas").await,
        sas,
        "the host shows the claimant's SAS"
    );
    type_in(&mut child, answer).await;
    drop(child.stdin.take());
    let ok = child.wait().await.unwrap().success();
    (dev, ok)
}

async fn status(h: &Host, id: &str) -> (String, Vec<String>, bool) {
    let d = gov::get_device(&h.pool, id).await.unwrap().unwrap();
    (d.status, d.scopes, d.revoked_at.is_some())
}

async fn audited(h: &Host, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

fn hostname() -> String {
    let out = std::process::Command::new("hostname").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[tokio::test]
async fn bootstrap_pairs_the_first_device_and_only_the_first() {
    let h = host("bootstrap").await;
    let db = h.db.to_str().unwrap();
    // Declined: rejected, audited, and bootstrap can be run again.
    let (declined, ok) = run(&h, &["bootstrap", db, "Mac"], "", "n\n").await;
    assert!(!ok);
    assert_eq!(status(&h, &declined.id).await.0, "rejected");
    assert_eq!(audited(&h, "pairing.rejected").await, 1);
    let (mac, ok) = run(&h, &["bootstrap", db, "Mac"], "", "y\n").await;
    assert!(ok, "a declined attempt does not block the next");
    let (st, scopes, _) = status(&h, &mac.id).await;
    assert_eq!(
        (st.as_str(), scopes),
        ("active", gov::SCOPES.map(str::to_owned).to_vec())
    );

    // A second bootstrap is refused, and stays refused once the only device is revoked.
    for revoke in [false, true] {
        if revoke {
            let by = ainkrad_core::audit::AuditActor::System;
            assert!(
                gov::revoke_device(&h.pool, &mac.id, by, None, "2026-10-29T00:00:00.000Z")
                    .await
                    .unwrap()
            );
        }
        let (child, _) = spawn(&["bootstrap", db]);
        let out = child.wait_with_output().await.unwrap();
        assert!(!out.status.success());
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("a device exists"), "revoked {revoke}: {err}");
    }
}

#[tokio::test]
async fn recover_enrols_a_new_admin_after_every_device_is_revoked() {
    let h = host("recover-all").await;
    let db = h.db.to_str().unwrap();
    let clock = Arc::new(SystemClock);
    let old = TestDevice::enroll(
        &h.pool,
        "lost",
        "device",
        &gov::SCOPES,
        &h.identity.fp,
        clock.clone(),
    )
    .await;
    let runner = TestDevice::enroll(
        &h.pool,
        "runner",
        "runner",
        &["runner"],
        &h.identity.fp,
        clock,
    )
    .await;
    let by = ainkrad_core::audit::AuditActor::System;
    gov::revoke_device(&h.pool, &old.id, by, None, "2026-10-29T00:00:00.000Z")
        .await
        .unwrap();

    // A wrong host name changes nothing.
    let (mut child, _) = spawn(&["recover", db]);
    type_in(&mut child, "not-this-host\n").await;
    drop(child.stdin.take());
    assert!(!child.wait().await.unwrap().success());
    assert_eq!(audited(&h, "recover.started").await, 0);

    let confirm = format!("{}\n", hostname());
    let (new, ok) = run(&h, &["recover", db, "New Mac"], &confirm, "y\n").await;
    assert!(ok);
    let (st, scopes, _) = status(&h, &new.id).await;
    assert_eq!(
        (st.as_str(), scopes),
        ("active", gov::SCOPES.map(str::to_owned).to_vec())
    );
    assert_eq!(audited(&h, "recover.started").await, 1);
    assert_eq!(
        audited(&h, "device.enrolled").await,
        3,
        "two fixtures and the recovered admin"
    );
    assert!(!status(&h, &runner.id).await.2, "the runner is kept");
}

#[tokio::test]
async fn recover_revokes_the_app_devices_unless_told_to_keep_them() {
    let h = host("recover-keep").await;
    let db = h.db.to_str().unwrap();
    let clock = Arc::new(SystemClock);
    let phone = TestDevice::enroll(
        &h.pool,
        "phone",
        "device",
        &["read"],
        &h.identity.fp,
        clock.clone(),
    )
    .await;
    let runner = TestDevice::enroll(
        &h.pool,
        "runner",
        "runner",
        &["runner"],
        &h.identity.fp,
        clock,
    )
    .await;
    let confirm = format!("{}\n", hostname());
    let (first, ok) = run(&h, &["recover", db, "--keep-devices"], &confirm, "y\n").await;
    assert!(ok);
    assert!(!status(&h, &phone.id).await.2, "kept with --keep-devices");
    // The spec's default (§12): every app device is revoked, runners kept.
    let (second, ok) = run(&h, &["recover", db], &confirm, "y\n").await;
    assert!(ok);
    for revoked in [&phone.id, &first.id] {
        assert!(status(&h, revoked).await.2, "{revoked} revoked");
    }
    assert!(
        !status(&h, &runner.id).await.2,
        "the runner is kept by default"
    );
    let (third, ok) = run(&h, &["recover", db, "--revoke-runners"], &confirm, "y\n").await;
    assert!(ok);
    for revoked in [&second.id, &runner.id] {
        assert!(status(&h, revoked).await.2, "{revoked} revoked");
    }
    assert_eq!(status(&h, &third.id).await.0, "active");
}

/// N4: the user is checked before the database is opened: a missing database is refused and
/// not created.
#[tokio::test]
async fn the_host_verbs_never_create_a_database() {
    let h = host("no-db").await;
    let missing = h.dir.join("missing.db");
    for verb in ["bootstrap", "recover"] {
        let (child, _) = spawn(&[verb, missing.to_str().unwrap()]);
        let out = child.wait_with_output().await.unwrap();
        assert!(!out.status.success());
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("no database at"), "{verb}: {err}");
        assert!(!missing.exists(), "{verb} created the database");
        assert!(!h.dir.join("missing.db-wal").exists());
    }
}
