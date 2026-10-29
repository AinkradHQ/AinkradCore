//! `bootstrap` (handshake spec §7.3, §17.24): on an empty store it pairs the first device,
//! claimed over the host's socket, approved by a `y` typed at the host; once any device exists,
//! revoked included, it is refused. Its network refusals are in `api::v1::tests::pairing`.

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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;

fn bootstrap(db: &std::path::Path) -> tokio::process::Child {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(["bootstrap", db.to_str().unwrap(), "Mac"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

/// The value after `prefix ` on the next line that starts with it.
async fn line<R: tokio::io::AsyncBufRead + Unpin>(
    lines: &mut tokio::io::Lines<R>,
    prefix: &str,
) -> String {
    loop {
        let l = lines
            .next_line()
            .await
            .unwrap()
            .expect("bootstrap printed more");
        if let Some(rest) = l.strip_prefix(&format!("{prefix} ")) {
            return rest.to_owned();
        }
    }
}

#[tokio::test]
async fn bootstrap_pairs_the_first_device_from_the_host_and_only_the_first() {
    let dir = std::env::temp_dir().join(format!("core-bootstrap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");
    let pool = store::connect(&db).await.unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let app = App::new(
        pool.clone(),
        Arc::new(SystemClock),
        "localhost".to_owned(),
        identity.clone(),
    );

    let mut cli = bootstrap(&db);
    let mut lines = BufReader::new(cli.stdout.take().unwrap()).lines();
    let code = line(&mut lines, "code").await;
    assert_eq!(line(&mut lines, "core_fp").await, identity.fp);

    // The new device claims over the host's socket, as this user.
    let mut mac = TestDevice::new(&identity.fp, Arc::new(SystemClock));
    let body = mac.claim_body(Some(&code), None).to_string();
    let mut r = Request::post("/pair/claim")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    r.extensions_mut().insert(Local { same_user: true });
    let res = router(app.clone()).oneshot(r).await.unwrap();
    assert_eq!(res.status(), 202);
    let got: serde_json::Value =
        serde_json::from_slice(&to_bytes(res.into_body(), 1 << 16).await.unwrap()).unwrap();
    mac.id = got["device_id"].as_str().unwrap().to_owned();

    // The host sees the same SAS and types y.
    assert!(line(&mut lines, "device").await.starts_with(&mac.id));
    assert_eq!(line(&mut lines, "sas").await, got["sas"].as_str().unwrap());
    let mut stdin = cli.stdin.take().unwrap();
    stdin.write_all(b"y\n").await.unwrap();
    drop(stdin);
    let approved = line(&mut lines, "approved").await;
    assert_eq!(approved, mac.id);
    assert!(cli.wait().await.unwrap().success());
    let row = gov::get_device(&pool, &mac.id).await.unwrap().unwrap();
    assert_eq!((row.status.as_str(), row.name.as_str()), ("active", "Mac"));
    assert_eq!(row.scopes, gov::SCOPES.map(str::to_owned), "every scope");

    // A second bootstrap is refused, and stays refused once the only device is revoked.
    for revoke in [false, true] {
        if revoke {
            let by = ainkrad_core::audit::AuditActor::System;
            assert!(
                gov::revoke_device(&pool, &mac.id, by, None, "2026-10-29T00:00:00.000Z")
                    .await
                    .unwrap()
            );
        }
        let out = bootstrap(&db).wait_with_output().await.unwrap();
        assert!(!out.status.success());
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("a device exists"), "revoked {revoke}: {err}");
    }
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
