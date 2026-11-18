//! L3 (PR 318 review): a run is placed on a runner whose policy has `runs` on, and among those on
//! one every referenced secret may be leased to.

use ainkrad_proto::v2::RunnerPolicy;

use super::project_runs::{Fake, project, w};
use super::*;
use crate::runs;

#[test]
fn a_policy_without_runs_reads_as_off() {
    let p: RunnerPolicy =
        serde_json::from_str(r#"{"terminals":true,"agents":false,"agent_capacity":2}"#).unwrap();
    assert!(!p.runs);
}

#[tokio::test]
async fn a_secret_prefers_a_runner_in_its_scope() {
    let fx = fx().await;
    let p = project(&fx, "shop").await;
    let now = fx.app.clock.now();
    let spec = serde_json::json!({"services": {"web": {"image": "node:22",
                                  "env": {"T": "${secret:api_key}"}}}});
    crate::store::run_specs::save(&fx.app.pool, p, &spec, "manual", w(&now))
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
    sqlx::query(
        "INSERT INTO core_secrets (name, owner, delivery, version, key_id, sealed, size, \
         created_at, updated_at, group_id, runners) VALUES ('shop.api_key', ?, 'env', 1, \
         '0123456789abcdef', x'00', 1, ?, ?, (SELECT id FROM core_secret_groups), '[\"b\"]')",
    )
    .bind(&fx.dev.id)
    .bind(&now)
    .bind(&now)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let mut link = Fake::new();
    link.runners = vec!["a".into(), "b".into()];
    let pending = runs::begin_start(&fx.app, &link, p, w(&now)).await.unwrap();
    assert_eq!(
        pending.run.runner, "b",
        "a is first by load, but only b may lease the secret"
    );
}
