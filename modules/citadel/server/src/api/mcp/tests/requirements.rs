//! Plan-first over MCP (E15.10): a dev's start on a requirement's issue is refused with the
//! reason until its plan is approved; only a planner files and submits the plan.

use serde_json::json;

use super::plan::{ok, planning_team, refused};
use super::*;

#[tokio::test]
async fn start_waits_for_the_plan_and_only_a_planner_files_it() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    sqlx::query(
        "INSERT INTO requirements (id, company_id, number, title, requested_by_user_id) \
         VALUES (7, ?, 3, 'Phone alerts', 1)",
    )
    .bind(a.company.0)
    .execute(pool)
    .await
    .unwrap();
    for sql in [
        "UPDATE issues SET requirement_id = 7 WHERE id = ?",
        "UPDATE projects SET requirement_id = 7 WHERE id = \
         (SELECT project_id FROM issues WHERE id = ?)",
    ] {
        sqlx::query(sql)
            .bind(a.issue.0)
            .execute(pool)
            .await
            .unwrap();
    }

    let why = refused(&fx, &a, "transition", json!({"transition": "start"})).await;
    assert!(why.contains("R-3") && why.contains("not approved"), "{why}");
    let plan = json!({"epics": [{"title": "Delivery", "tasks": [
        {"title": "Sender", "points": 3}]}], "submit": true});
    let why = refused(&fx, &a, "plan_requirement", plan.clone()).await;
    assert!(why.contains("plans a requirement"), "{why}");

    // As the project's product owner: filed, but incomplete (no assignee), so not submitted.
    let (_, _, dev) = planning_team(pool, &a).await;
    let out = ok(&fx, &a, "plan_requirement", plan).await;
    assert_eq!(out["key"], "R-3");
    assert_eq!(out["submitted"]["status"], "refused", "{out}");
    assert_eq!(out["problems"][0], "AAA-2 has no assignee", "{out}");
    let task = out["tasks"][0].as_i64().unwrap();
    sqlx::query("UPDATE issues SET owner_agent_id = ? WHERE id = ?")
        .bind(dev.0)
        .bind(task)
        .execute(pool)
        .await
        .unwrap();
    let out = ok(&fx, &a, "plan_requirement", json!({"submit": true})).await;
    assert_eq!(out["submitted"]["status"], "pending_approval", "{out}");
    assert_eq!(out["state"], "plan_review");
}

/// `ask_human` (E15.11): the card is in the requirement's thread, the issue waits on the admin,
/// and the reply says to stop.
#[tokio::test]
async fn ask_human_posts_a_card_and_waits_on_the_admin() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let req = crate::store::work::submit_intake(
        pool,
        a.company,
        "R",
        "",
        AuditActor::User(citadel_core::work::UserId(1)),
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
    let bad = refused(
        &fx,
        &a,
        "ask_human",
        json!({"question": "?", "options": [""]}),
    )
    .await;
    assert!(bad.contains("options"), "{bad}");
    let out = ok(
        &fx,
        &a,
        "ask_human",
        json!({"question": "Which key?",
        "options": [".p8", ".p12"]}),
    )
    .await;
    assert_eq!(out["status"], "waiting_on_human");
    assert_eq!(out["requirement"], "R-1");
    let q = crate::store::work::list_questions(pool, Some(req), None, true)
        .await
        .unwrap();
    assert_eq!(
        (q.len(), q[0].agent_id, q[0].run_id),
        (1, a.agent, Some(a.run.id))
    );
    let i = crate::store::work::get_issue(pool, a.issue)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        i.next_actor,
        Some(NextActor::Human(citadel_core::work::UserId(1)))
    );
    let why = refused(&fx, &a, "post_to_requirement", json!({"body": "hi"})).await;
    assert!(why.contains("owner"), "{why}");
}
