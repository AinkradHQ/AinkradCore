//! L2 (PR 318 review): an invalid request costs no lease, and a failed start drops the leases it
//! made.

use ainkrad_proto::v2::RunPhase;

use super::project_runs::{Fake, project, run, start, w};
use super::secrets::{V1, broker, create};
use super::*;
use crate::store::run_specs;

async fn leases(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// A project whose spec references `${secret:api_key}`, a secret of its group scoped to `runner`.
async fn with_secret(fx: &Fx, runner: &str, image: &str) -> i64 {
    // The secret first: the secrets API refuses a name that starts with an existing project's slug.
    assert_eq!(
        create(fx, "shop.api_key", V1, &[runner]).await.0,
        StatusCode::OK
    );
    let p = project(fx, "shop").await;
    let now = fx.app.clock.now();
    let spec = serde_json::json!({"services": {"web": {"image": image,
                                  "env": {"T": "${secret:api_key}"}}}});
    run_specs::save_unchecked(&fx.app.pool, p, &spec, w(&now))
        .await
        .unwrap();
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
    sqlx::query("UPDATE core_secrets SET group_id = (SELECT id FROM core_secret_groups) WHERE name = 'shop.api_key'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    p
}

#[tokio::test]
async fn a_request_that_is_invalid_anyway_leases_nothing() {
    let (fx, vm) = broker().await;
    let p = with_secret(&fx, &vm.id, "node:22").await;
    // A limit the runner request refuses (`RunStart::problem`); the spec itself is fine.
    sqlx::query("UPDATE core_projects SET mem_limit_mb = 8 WHERE id = ?")
        .bind(p)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let mut link = Fake::new();
    link.runners = vec![vm.id.clone()];
    let id = start(&fx, &link, p).await.unwrap();
    let r = run(&fx, &id).await;
    assert_eq!(r.state, "failed");
    assert!(
        r.error.unwrap().contains("limits"),
        "the request is refused first"
    );
    assert_eq!(leases(&fx).await, 0);
}

#[tokio::test]
async fn a_failed_start_drops_its_unredeemed_leases() {
    let (fx, vm) = broker().await;
    let p = with_secret(&fx, &vm.id, "node:22").await;
    let mut link = Fake::new();
    link.runners = vec![vm.id.clone()];
    *link.start.lock().unwrap() = Err("pulling node:22 failed".into());
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id).await.state, "failed");
    assert_eq!(leases(&fx).await, 0, "the lease made for the start is gone");
    // A start that works leaves its lease for the runner to redeem.
    *link.start.lock().unwrap() = Ok(RunPhase::Running);
    start(&fx, &link, p).await.unwrap();
    assert_eq!(leases(&fx).await, 1);
}
