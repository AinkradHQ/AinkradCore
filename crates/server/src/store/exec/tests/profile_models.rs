//! Models per role from the project profile (E15.13, feeding E15.5): an agent with no model of
//! its own runs on its role's; a tier it has no model for runs on the role's model for it; its
//! own models still win.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{ModelRoute, Tier};
use serde_json::json;

use super::wake::{dispatch, runner, wake};
use super::*;
use crate::profile::ProfilePatch;
use crate::store::org::set_tiers;
use crate::store::work::{get_issue, update_profile};

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

#[tokio::test]
async fn an_agent_without_a_model_runs_on_its_roles_model_from_the_profile() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, first) = fixture(pool, "A").await;
    let project = get_issue(pool, first).await.unwrap().unwrap().project_id;
    sqlx::query("UPDATE agents SET model = '' WHERE id = ?")
        .bind(dev.0)
        .execute(pool)
        .await
        .unwrap();
    let models = json!({"models": [{"role": "developer", "model": "claude-sonnet",
                                    "small": "claude-haiku"}]});
    let patch: ProfilePatch = serde_json::from_value(models).unwrap();
    update_profile(pool, project, &patch, BY)
        .await
        .unwrap()
        .unwrap();
    let r = runner(pool, "box").await;
    let run_on = |issue: IssueId, key: &'static str| async move {
        enqueue_wake(pool, &wake(dev, Some(issue), key))
            .await
            .unwrap();
        let run = dispatch(pool, r, NOW).await.expect("a run");
        let by = AuditActor::Runner(r);
        start_run(pool, run.id, by, None, NOW).await.unwrap();
        transition_run(
            pool,
            run.id,
            by,
            &ainkrad_core::exec::RunEvent::Succeed,
            NOW,
        )
        .await
        .unwrap();
        run
    };

    // Unestimated: standard, on the role's model.
    let run = run_on(first, "w1").await;
    assert_eq!(run.tier, Some(Tier::Standard));
    assert_eq!(run.model_used.as_deref(), Some("claude-sonnet"));

    // One point: small, on the role's small model.
    sqlx::query("UPDATE issues SET points = 1 WHERE id = ?")
        .bind(first.0)
        .execute(pool)
        .await
        .unwrap();
    let run = run_on(first, "w2").await;
    assert_eq!(run.tier, Some(Tier::Small));
    assert_eq!(run.model_used.as_deref(), Some("claude-haiku"));

    // The agent's own small model wins over the profile's.
    let own = ModelRoute {
        harness: Harness::Claude,
        model: "own-small".to_owned(),
    };
    assert!(
        set_tiers(pool, dev, &[(Tier::Small, own)], BY)
            .await
            .unwrap()
    );
    let run = run_on(first, "w3").await;
    assert_eq!(run.model_used.as_deref(), Some("own-small"));
}
