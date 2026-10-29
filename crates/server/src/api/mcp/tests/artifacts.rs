//! `publish_artifact` (E15.12): by content, and by path through the run's runner (played here by
//! answering the reads as the connection would); paths that leave the worktree, types outside
//! the allowlist and a full quota are refused with the reason recorded on the run.

use ainkrad_core::exec::RunnerId;
use ainkrad_core::settings::{Key, Scope};
use base64::Engine;
use serde_json::json;

use super::plan::{ok, refused};
use super::*;
use crate::store::artifacts::{blob_path, finish_read, incoming_path, take_reads};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Answers the run's reads as its runner would: `file` for every path, or `why`.
fn runner(
    fx: &Fx,
    runner: RunnerId,
    answer: Result<Vec<u8>, String>,
) -> tokio::task::JoinHandle<()> {
    let (pool, root) = (fx.app.pool.clone(), fx.app.artifacts.clone());
    tokio::spawn(async move {
        loop {
            let taken = take_reads(&pool, runner).await.unwrap();
            if let Some((read, _, _, _)) = taken.into_iter().next() {
                let outcome = answer.clone().map(|bytes| {
                    let to = incoming_path(&root, read);
                    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                    std::fs::write(to, bytes).unwrap();
                });
                finish_read(&pool, read, outcome).await.unwrap();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
}

async fn runner_of(pool: &SqlitePool, c: &Company) -> RunnerId {
    let id: i64 = sqlx::query_scalar("SELECT runner_id FROM leases WHERE run_id = ?")
        .bind(c.run.id.0)
        .fetch_one(pool)
        .await
        .unwrap();
    RunnerId(id)
}

#[tokio::test]
async fn published_by_content_or_path_and_refused_with_the_reason() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let req = crate::store::work::submit_intake(
        pool,
        a.company,
        "R",
        "",
        AuditActor::User(ainkrad_core::work::UserId(1)),
    )
    .await
    .unwrap()
    .requirement_id
    .unwrap();
    sqlx::query("UPDATE issues SET requirement_id = ? WHERE id = ?")
        .bind(req.0)
        .bind(a.issue.0)
        .execute(pool)
        .await
        .unwrap();

    let out = ok(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "qa.md", "kind": "report",
        "content": b64(b"# QA\npass")}),
    )
    .await;
    assert_eq!(
        (out["mime"].as_str(), out["size"].as_i64()),
        (Some("text/markdown"), Some(9))
    );
    assert_eq!(out["requirement_id"], req.0, "listed on the requirement");

    let box_ = runner_of(pool, &a).await;
    let reading = runner(&fx, box_, Ok(b"\x89PNG".to_vec()));
    let out = ok(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "shot.png", "kind": "screenshot",
        "path": "out/shot.png"}),
    )
    .await;
    reading.await.unwrap();
    assert_eq!(
        (out["mime"].as_str(), out["size"].as_i64()),
        (Some("image/png"), Some(4))
    );

    // Out of the worktree: refused here, or by the runner.
    let why = refused(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "p.txt",
        "path": "../../etc/passwd"}),
    )
    .await;
    assert!(why.contains("plain relative path"), "{why}");
    let reading = runner(
        &fx,
        box_,
        Err("out/link leads outside the worktree".to_owned()),
    );
    let why = refused(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "l.txt",
        "path": "out/link"}),
    )
    .await;
    reading.await.unwrap();
    assert!(why.contains("leads outside"), "{why}");
    let why = refused(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "x.exe",
        "content": b64(b"MZ")}),
    )
    .await;
    assert!(why.contains("type not allowed"), "{why}");

    // The company's storage full: refused, the reason on the run.
    let by = AuditActor::User(ainkrad_core::work::UserId(1));
    let at = Scope::Company(a.company);
    crate::store::settings::set(pool, Key::ArtifactCompanyQuotaBytes, at, "1000000", by, NOW)
        .await
        .unwrap();
    let why = refused(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "big.txt",
        "content": b64(&[b'x'; 999_990])}),
    )
    .await;
    assert!(why.contains("storage is full"), "{why}");
    let on_run: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(details, '$.reason') FROM audit_events \
         WHERE action = 'artifact.refused' AND run_id = ? ORDER BY seq",
    )
    .bind(a.run.id.0)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(on_run.len(), 4, "{on_run:?}");
    assert!(on_run[3].contains("storage is full"));
}

/// Every secret in a text artifact is redacted before it is hashed or stored (E15.18): the run
/// token the server knows (through the real MCP endpoint, which holds it), every key shape, and
/// a by-path file the runner sent; none reaches the blob or the database. An image is stored as
/// it is and marked unscanned.
#[tokio::test]
async fn text_artifacts_are_redacted_before_they_are_stored() {
    use ainkrad_proto::redact::PLANTED;
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let token = a.token.expose().to_owned();
    let secrets: Vec<&str> = PLANTED.iter().map(|(_, s)| *s).chain([&*token]).collect();
    let body = secrets.join("\n");

    let publish = call(
        "publish_artifact",
        json!({"name": "leak.md", "content": b64(body.as_bytes())}),
    );
    let (status, reply) = rpc(&fx.app, Some(&token), publish).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    let out: Value = serde_json::from_str(text).unwrap();
    assert_eq!(out["redactions"], secrets.len(), "{out}");
    assert_eq!(out["unscanned"], false);
    let blob = std::fs::read_to_string(blob_path(
        &fx.app.artifacts,
        out["sha256"].as_str().unwrap(),
    ))
    .unwrap();
    assert!(blob.contains("[redacted:run_token]"), "{blob}");

    // By path: the runner's copy (here not redacted) goes through the server's pass too.
    let reading = runner(
        &fx,
        runner_of(pool, &a).await,
        Ok(body.clone().into_bytes()),
    );
    let by_path = ok(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "leak.log", "path": "l.log"}),
    )
    .await;
    reading.await.unwrap();
    assert_eq!(by_path["redactions"], secrets.len());

    let png = [b"\x89PNG".as_slice(), token.as_bytes()].concat();
    let shot = ok(
        &fx,
        &a,
        "publish_artifact",
        json!({"name": "s.png", "content": b64(&png)}),
    )
    .await;
    assert_eq!(
        (shot["unscanned"].as_bool(), shot["redactions"].as_i64()),
        (Some(true), Some(0))
    );

    let stored: Vec<(String, i64, bool)> =
        sqlx::query_as("SELECT sha256, redactions, unscanned FROM artifacts ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(stored[0].1, secrets.len() as i64);
    assert_eq!(stored[2].1, 0);
    assert!(stored[2].2 && !stored[0].2 && !stored[1].2);
    let mut seen = String::new();
    for (sha, _, unscanned) in &stored {
        if !unscanned {
            seen += &std::fs::read_to_string(blob_path(&fx.app.artifacts, sha)).unwrap();
        }
    }
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT name || mime || sha256 FROM artifacts UNION ALL SELECT details FROM audit_events",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    seen += &rows.join("\n");
    for s in &secrets {
        assert!(!seen.contains(s), "{s} was stored");
    }
    assert_eq!(
        std::fs::read(blob_path(&fx.app.artifacts, &stored[2].0)).unwrap(),
        png
    );
}
