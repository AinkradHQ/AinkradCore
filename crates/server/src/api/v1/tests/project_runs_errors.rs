//! M2 (PR 318 review): a run's error is redacted, scrubbed of the project's secret names and
//! lease ids, and cut to 1 KB before it is stored, audited or put in an event.

use ainkrad_proto::v2::RunPhase;

use super::project_runs::{Fake, info, project, run, start};
use super::*;
use crate::store::runs::ERROR_MAX;

const BEARER: &str = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";

#[tokio::test]
async fn a_runner_reason_is_redacted_and_cut_before_it_is_kept() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let long = "x".repeat(5000);
    *link.start.lock().unwrap() = Err(format!("pull failed: {BEARER} l_0123456789abcdef {long}"));
    let id = start(&fx, &link, p).await.unwrap();
    let r = run(&fx, &id).await;
    assert_eq!(r.state, "failed");
    let error = r.error.unwrap();
    assert!(error.len() <= ERROR_MAX, "{}", error.len());
    assert!(!error.contains("eyJhbGci"), "{error}");
    assert!(!error.contains("l_0123456789abcdef"), "{error}");
    assert!(error.starts_with("pull failed:"));
    let details: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'project.run_stopped'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        !details.contains("eyJhbGci") && details.len() < 2 * ERROR_MAX,
        "{details}"
    );
    let payload: String =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'project.run_stopped'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        !payload.contains("eyJhbGci") && payload.len() < 2 * ERROR_MAX,
        "{payload}"
    );
}

#[tokio::test]
async fn the_projects_secret_names_are_scrubbed_from_a_crash_reason() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let now = fx.app.clock.now();
    sqlx::query("INSERT INTO core_secret_groups (name, created_at, updated_at) VALUES ('g', ?, ?)")
        .bind(&now)
        .bind(&now)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE core_projects SET secret_group = (SELECT id FROM core_secret_groups) WHERE id = ?",
    )
    .bind(p)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO core_secrets (name, owner, delivery, version, key_id, sealed, size, \
         created_at, updated_at, group_id) VALUES ('shop.stripe_live', ?, 'env', 1, \
         '0123456789abcdef', x'00', 1, ?, ?, (SELECT id FROM core_secret_groups))",
    )
    .bind(&fx.dev.id)
    .bind(&now)
    .bind(&now)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    *link.start.lock().unwrap() = Ok(RunPhase::Running);
    let id = start(&fx, &link, p).await.unwrap();
    // The runner reports a crash naming the secret.
    let mut crashed = info(&id, RunPhase::Failed);
    crashed.failed_service = Some("web".into());
    crashed.reason = Some("bad key stripe_live (shop.stripe_live)".into());
    *link.listed.lock().unwrap() = Some(vec![crashed]);
    crate::runs::reconcile(&fx.app, &link, "r1").await;
    let error = run(&fx, &id).await.error.unwrap();
    assert!(!error.contains("stripe_live"), "{error}");
    assert!(error.starts_with("web: bad key"), "{error}");
}
