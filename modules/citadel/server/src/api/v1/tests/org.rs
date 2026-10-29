//! Companies, the org chart, agents, runners, stuck issues, requests.

use citadel_core::org::TeamRole;
use citadel_core::work::ProjectMode;
use serde_json::json;

use super::super::BY;
use super::*;
use crate::store::org::{add_department, add_team, seat_member};

#[tokio::test]
async fn reads_the_org_and_keeps_companies_apart() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let d = add_department(&fx.app.pool, a.company, "Engineering", BY)
        .await
        .unwrap();
    let t = add_team(&fx.app.pool, d.id, "Core", BY).await.unwrap();
    seat_member(&fx.app.pool, t.id, a.agent, TeamRole::TeamLead, Some(8), BY)
        .await
        .unwrap();

    let companies = fx.ok("/api/v1/companies").await;
    assert_eq!(companies.as_array().unwrap().len(), 2);

    let chart = fx
        .ok(&format!("/api/v1/companies/{}/org", a.company.0))
        .await;
    assert_eq!(chart["company"]["name"], "A");
    assert_eq!(chart["agents"].as_array().unwrap().len(), 1, "only A's");
    assert_eq!(chart["agents"][0]["status"], "active");
    let seat = &chart["departments"][0]["teams"][0]["members"][0];
    assert_eq!(
        *seat,
        json!({"agent_id": a.agent.0, "team_role": "team_lead", "capacity": 8})
    );

    let agents = fx
        .ok(&format!("/api/v1/companies/{}/agents", b.company.0))
        .await;
    assert_eq!(agents.as_array().unwrap().len(), 1);
    assert_eq!(agents[0]["id"], b.agent.0);
    let agent = fx.ok(&format!("/api/v1/agents/{}", a.agent.0)).await;
    assert_eq!(agent["harness"], "opencode");

    let runners = fx.ok("/api/v1/runners").await;
    assert_eq!(runners.as_array().unwrap().len(), 2);
    assert!(fx.ok("/api/v1/stuck").await.is_array());

    for missing in [
        "/api/v1/companies/99/org",
        "/api/v1/companies/99/agents",
        "/api/v1/agents/99",
    ] {
        let (status, body) = fx.get(missing).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
        assert_eq!(body["code"], "not_found");
    }
}

#[tokio::test]
async fn a_request_lands_in_the_company_intake_audited_as_the_admin() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/requests", a.company.0);
    let issue = fx
        .ok_post(
            &uri,
            json!({"title": "A billing page", "body": "For the shop."}),
        )
        .await;
    assert_eq!(issue["title"], "A billing page");
    assert_eq!(
        issue["next_actor"],
        json!({"kind": "human", "user_id": 1}),
        "no CEO yet"
    );
    assert!(issue["key"].as_str().unwrap().contains('-'));
    let (status, _) = fx.post(&uri, json!({"title": " "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .post("/api/v1/companies/99/requests", json!({"title": "x"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let by: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT actor_kind, actor_id FROM audit_events WHERE action = 'intake.submitted'",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(by, [("user".to_owned(), Some(1))]);
}
