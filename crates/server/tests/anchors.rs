//! `audit anchor` and `audit verify-anchors` through the binary (E1-10.4): exit 0 on a clean
//! chain, exit 3 (not 1) once the chain was truncated behind the anchors' back, exit 1 when it
//! cannot check at all.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::store;
use sqlx::AssertSqlSafe;

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(args)
        .env_remove("AINKRAD_CONFIG")
        .env_remove("AINKRAD_BACKUP_ENDPOINT")
        .env_remove("AINKRAD_ANCHOR_FILE")
        .output()
        .unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[tokio::test]
async fn anchor_then_verify_exits_0_and_a_truncated_chain_exits_3() {
    let d = Dir(std::env::temp_dir().join(format!("core-anchors-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&d.0);
    std::fs::create_dir_all(&d.0).unwrap();
    let home = d.0.join("home");
    assert!(bin(&["init", s(&home)]).status.success());
    let pool = store::connect(&home.join("core.db")).await.unwrap();
    let clock = std::sync::Arc::new(ainkrad_core_server::scheduler::SystemClock);
    for name in ["mac", "phone", "tablet"] {
        ainkrad_core_server::auth::testing::TestDevice::enroll(
            &pool,
            name,
            "device",
            &["read"],
            "fp",
            clock.clone(),
        )
        .await;
    }
    let fp = Identity::load_or_create(
        &home,
        &ainkrad_core_server::ops::secretbox::SecretBox::for_home(&home).unwrap(),
    )
    .unwrap()
    .fp;
    let file = d.0.join("anchors.jsonl");

    let none = bin(&["audit", "anchor", s(&home)]);
    assert_eq!(none.status.code(), Some(1), "no sink is refused");
    let done = bin(&[
        "audit",
        "anchor",
        s(&home),
        "--local-only",
        "--file",
        s(&file),
    ]);
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let ok = bin(&[
        "audit",
        "verify-anchors",
        s(&home),
        "--from",
        s(&file),
        "--core-fp",
        &fp,
    ]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stdout).starts_with("audit anchors ok: 1 anchors"));

    // Tail removed with its counter: `audit verify` still passes it, the anchors do not.
    let seq: i64 = sqlx::query_scalar("SELECT max(seq) FROM audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    for q in [
        "DROP TRIGGER audit_events_no_delete".to_owned(),
        format!("DELETE FROM audit_events WHERE seq = {seq}"),
        format!(
            "UPDATE sqlite_sequence SET seq = {} WHERE name = 'audit_events'",
            seq - 1
        ),
    ] {
        sqlx::raw_sql(AssertSqlSafe(q))
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
    let db = home.join("core.db");
    assert!(bin(&["audit", "verify", s(&db)]).status.success());
    let bad = bin(&[
        "audit",
        "verify-anchors",
        s(&home),
        "--from",
        s(&file),
        "--core-fp",
        &fp,
    ]);
    assert_eq!(
        bad.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
    assert!(String::from_utf8_lossy(&bad.stderr).contains("truncated"));
    let gone = bin(&[
        "audit",
        "verify-anchors",
        s(&home),
        "--from",
        s(&d.0.join("missing")),
    ]);
    assert_eq!(gone.status.code(), Some(1));
}
