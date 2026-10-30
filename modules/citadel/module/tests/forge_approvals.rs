//! Forge approvals (PR #53 review F1, F3): a PR merge or workflow push is decided only on the
//! step-up `decide-forge` route, and a merge approval is bound to the head the approver saw.

mod common;
mod gov_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::gov::{ApprovalKind, NewApproval};
use citadel_module::store::gov::open_approval;
use common::*;
use gov_seed::*;
use serde_json::{Value, json};

fn step_up_required(r: &(StatusCode, Value)) -> bool {
    r.0 == StatusCode::FORBIDDEN && r.1["code"] == "step_up_required"
}

async fn ask(fx: &Fx, s: &Seed, kind: ApprovalKind, payload: Value) -> i64 {
    let n = NewApproval {
        company_id: s.company,
        kind,
        issue_id: Some(s.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: s.agent,
        payload: payload.to_string(),
    };
    open_approval(&fx.app.pool, &n, NOW).await.unwrap().id.0
}

async fn status(fx: &Fx, id: i64) -> String {
    sqlx::query_scalar("SELECT status FROM citadel_approvals WHERE id = ?")
        .bind(id)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn forge_kinds_are_decided_only_on_the_step_up_route() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    let phone = enroll(&fx.app, "phone", &["read", "approve"], true).await;
    let yes = json!({"approve": true});
    for kind in [ApprovalKind::PrMerge, ApprovalKind::WorkflowPush] {
        let id = ask(&fx, &s, kind, json!({})).await;
        // `decide` refuses the kind for everyone, the elevated admin too.
        for dev in [&phone, &fx.dev] {
            let r = call(
                &fx,
                Some(dev),
                Method::POST,
                &format!("/approvals/{id}/decide"),
                Some(yes.clone()),
            )
            .await;
            assert_eq!(r.0, StatusCode::BAD_REQUEST, "{kind:?}: {r:?}");
        }
        assert_eq!(status(&fx, id).await, "pending");
        // An unelevated phone cannot use the forge route.
        let uri = format!("/approvals/{id}/decide-forge");
        let r = call(&fx, Some(&phone), Method::POST, &uri, Some(yes.clone())).await;
        assert!(step_up_required(&r), "{r:?}");
        assert_eq!(status(&fx, id).await, "pending");
        let r = call(&fx, Some(&fx.dev), Method::POST, &uri, Some(yes.clone())).await;
        assert_eq!(r.0, StatusCode::OK, "{r:?}");
    }
    // Every other kind is refused on the forge route and decided on `decide`.
    let other = ask(&fx, &s, ApprovalKind::BudgetOverrun, json!({"budget": 1})).await;
    let r = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        &format!("/approvals/{other}/decide-forge"),
        Some(yes.clone()),
    )
    .await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{r:?}");
    let r = call(
        &fx,
        Some(&phone),
        Method::POST,
        &format!("/approvals/{other}/decide"),
        Some(json!({"approve": false})),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    // A read-only device cannot reach the route at all.
    let reader = enroll(&fx.app, "reader", &["read"], true).await;
    let r = call(
        &fx,
        Some(&reader),
        Method::POST,
        "/approvals/1/decide-forge",
        Some(yes),
    )
    .await;
    assert_eq!(
        (r.0, &r.1["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
}

async fn pr(fx: &Fx, s: &Seed, head_sha: &str) {
    sqlx::query(
        "INSERT INTO citadel_project_repos (id, project_id, name, url) VALUES (1, ?, 'app', 'x')",
    )
    .bind(s.project.0)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO citadel_issue_prs (issue_id, repo_id, state, number, title, body, head, base, head_sha) \
         VALUES (?, 1, 'open', 7, 't', 'b', 'feat', 'main', ?)",
    )
    .bind(s.issue.0)
    .bind(head_sha)
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

async fn pr_state(fx: &Fx) -> String {
    sqlx::query_scalar("SELECT state FROM citadel_issue_prs WHERE repo_id = 1")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_merge_approval_is_bound_to_the_head_the_approver_saw() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    pr(&fx, &s, "aaaa").await;
    let payload = |sha: &str| json!({"pr": 7, "repo_id": 1, "head_sha": sha});
    // The branch moved to `bbbb` after the approver saw `aaaa`: nothing merges.
    let stale = ask(&fx, &s, ApprovalKind::PrMerge, payload("zzzz")).await;
    let uri = format!("/approvals/{stale}/decide-forge");
    let r = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        &uri,
        Some(json!({"approve": true})),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(pr_state(&fx).await, "open", "a moved head is not merged");
    assert_eq!(audited(&fx.app.pool, "issue.pr_merge_stale").await.len(), 1);
    // An approval that names no head is refused the same way (fail closed).
    let bare = ask(
        &fx,
        &s,
        ApprovalKind::PrMerge,
        json!({"pr": 7, "repo_id": 1}),
    )
    .await;
    call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        &format!("/approvals/{bare}/decide-forge"),
        Some(json!({"approve": true})),
    )
    .await;
    assert_eq!(pr_state(&fx).await, "open");
    // The matching head merges.
    let ok = ask(&fx, &s, ApprovalKind::PrMerge, payload("aaaa")).await;
    let r = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        &format!("/approvals/{ok}/decide-forge"),
        Some(json!({"approve": true})),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(pr_state(&fx).await, "merging");
}

/// A tool permission lets a harness run something, so it is decided on the same step-up route as
/// a forge effect, never on the plain `decide` an unlocked phone has.
#[tokio::test]
async fn a_tool_permission_is_decided_only_on_the_step_up_route() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    let phone = enroll(&fx.app, "phone", &["read", "approve"], true).await;
    let n = NewApproval {
        company_id: s.company,
        kind: ApprovalKind::PermissionEscalation,
        issue_id: Some(s.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: s.agent,
        payload: json!({"tool": "Bash"}).to_string(),
    };
    let id = open_approval(&fx.app.pool, &n, &fx.app.clock.now())
        .await
        .unwrap()
        .id
        .0;
    let yes = json!({"approve": true});
    for dev in [&phone, &fx.dev] {
        let r = call(
            &fx,
            Some(dev),
            Method::POST,
            &format!("/approvals/{id}/decide"),
            Some(yes.clone()),
        )
        .await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{r:?}");
    }
    let uri = format!("/approvals/{id}/decide-forge");
    let r = call(&fx, Some(&phone), Method::POST, &uri, Some(yes.clone())).await;
    assert!(step_up_required(&r), "{r:?}");
    assert_eq!(status(&fx, id).await, "pending");
    let r = call(&fx, Some(&fx.dev), Method::POST, &uri, Some(yes)).await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(status(&fx, id).await, "approved");
}
