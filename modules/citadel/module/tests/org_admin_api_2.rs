//! The org_admin routes end to end through the Core's gate (ported from the monolith's
//! `api/v1/tests/{structure,org}.rs`): structure (departments, teams, seats) and the org chart.
//!
//! Seed data: the monolith's `seed` ran an agent through the run engine; here an active agent is
//! the raw writer's (`store::org::create_agent`, the `test-support` feature).

#![allow(dead_code, unused_imports)]

mod common;

use ainkrad_core_server::api::v1::BY;
use axum::http::{Method, StatusCode};
use citadel_module::domain::org::{
    AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole, TeamRole,
};
use citadel_module::store::org;
use common::*;
use serde_json::{Value, json};

async fn api(fx: &Fx, m: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), m, path, body).await
}

async fn get(fx: &Fx, path: &str) -> (StatusCode, Value) {
    api(fx, Method::GET, path, None).await
}

async fn post(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    api(fx, Method::POST, path, Some(body)).await
}

async fn ok(fx: &Fx, path: &str) -> Value {
    let (status, body) = get(fx, path).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

async fn ok_post(fx: &Fx, path: &str, body: Value) -> Value {
    let (status, got) = post(fx, path, body).await;
    assert_eq!(status, StatusCode::OK, "POST {path}: {got}");
    got
}

async fn patch(fx: &Fx, id: i64, body: Value) -> (StatusCode, Value) {
    api(fx, Method::PATCH, &format!("/agents/{id}"), Some(body)).await
}

async fn company(fx: &Fx, name: &str) -> CompanyId {
    org::create_company(&fx.app.pool, name).await.unwrap().id
}

fn new_agent(company: CompanyId, name: &str) -> NewAgent {
    NewAgent {
        company_id: company,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    }
}

async fn agent(fx: &Fx, company: CompanyId, name: &str) -> AgentId {
    org::create_agent(&fx.app.pool, &new_agent(company, name))
        .await
        .unwrap()
        .id
}

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(format!("citadel.{action}"))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn seats(fx: &Fx, agent: i64) -> Vec<String> {
    sqlx::query_scalar("SELECT team_role FROM citadel_team_memberships WHERE agent_id = ?")
        .bind(agent)
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

// --- structure.rs ---------------------------------------------------------------------------

#[tokio::test]
async fn departments_and_teams_are_created_renamed_moved_and_deleted() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let a_agent = agent(&fx, a, "A dev").await;
    let b_agent = agent(&fx, b, "B dev").await;
    let c = a.0;
    let uri = format!("/companies/{c}/departments");
    let made = ok_post(
        &fx,
        &uri,
        json!({"name": " Eng ", "about": "Builds it", "head_agent_id": a_agent.0}),
    )
    .await;
    // Adapted: `createDepartment` answers the flat `Department` (no `teams`).
    assert_eq!(
        (&made["name"], &made["about"], &made["head_agent_id"]),
        (&json!("Eng"), &json!("Builds it"), &json!(a_agent.0))
    );
    let dept = made["id"].as_i64().unwrap();
    assert_eq!(
        post(&fx, &uri, json!({"name": "Eng"})).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&fx, &uri, json!({"name": " "})).await.0,
        StatusCode::BAD_REQUEST
    );
    let foreign = json!({"name": "X", "head_agent_id": b_agent.0});
    assert_eq!(post(&fx, &uri, foreign).await.0, StatusCode::NOT_FOUND);

    let du = format!("/departments/{dept}");
    let (status, got) = api(
        &fx,
        Method::PATCH,
        &du,
        Some(json!({"name": "Platform", "head_agent_id": null})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        (&got["name"], &got["head_agent_id"], &got["about"]),
        (&json!("Platform"), &Value::Null, &json!("Builds it"))
    );
    assert_eq!(
        api(&fx, Method::PATCH, &du, Some(json!({}))).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, _) = api(
        &fx,
        Method::PATCH,
        &du,
        Some(json!({"head_agent_id": b_agent.0})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let team = ok_post(&fx, &format!("{du}/teams"), json!({"name": "Core"})).await;
    // Adapted: `createTeam` answers the flat `Team` (no `members`).
    assert_eq!(team["name"], json!("Core"));
    let tid = team["id"].as_i64().unwrap();
    let other = ok_post(&fx, &uri, json!({"name": "Ops"})).await["id"]
        .as_i64()
        .unwrap();
    let tu = format!("/teams/{tid}");
    let (status, got) = api(
        &fx,
        Method::PATCH,
        &tu,
        Some(json!({"name": "Kernel", "department_id": other})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["name"], "Kernel");
    let chart = ok(&fx, &format!("/companies/{c}/org")).await;
    let ops = chart["departments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == other)
        .unwrap();
    assert_eq!(ops["teams"][0]["name"], "Kernel", "moved");
    assert_eq!(chart["departments"][0]["about"], "Builds it");
    let (status, _) = api(
        &fx,
        Method::PATCH,
        &tu,
        Some(json!({"department_id": 99999})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // An empty department goes; a team goes with its seats. Adapted: the monolith refused (409)
    // to delete a department that still had teams; `deleteDepartment` is the first slice's and
    // takes its teams with it (`org_api.rs`), so that assertion is dropped.
    assert_eq!(api(&fx, Method::DELETE, &du, None).await.0, StatusCode::OK);
    assert_eq!(
        api(&fx, Method::DELETE, &du, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(api(&fx, Method::DELETE, &tu, None).await.0, StatusCode::OK);
    assert_eq!(
        api(&fx, Method::DELETE, &format!("/departments/{other}"), None)
            .await
            .0,
        StatusCode::OK
    );
    for action in [
        "department.added",
        "department.updated",
        "department.deleted",
        "team.added",
        "team.updated",
        "team.deleted",
    ] {
        assert!(audited(&fx, action).await >= 1, "{action}");
    }
}

#[tokio::test]
async fn a_team_has_one_lead_and_seats_stay_in_the_company() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let a_agent = agent(&fx, a, "A dev").await;
    let b_agent = agent(&fx, b, "B dev").await;
    let dept = ok_post(
        &fx,
        &format!("/companies/{}/departments", a.0),
        json!({"name": "Eng"}),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    let team = ok_post(
        &fx,
        &format!("/departments/{dept}/teams"),
        json!({"name": "Core"}),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    let second = agent(&fx, a, "Second").await;
    let seat = |agent: i64| format!("/teams/{team}/members/{agent}");
    let put = |agent: i64, body: Value| {
        let uri = seat(agent);
        let fx = &fx;
        async move { api(fx, Method::PUT, &uri, Some(body)).await }
    };

    let (status, got) = put(a_agent.0, json!({"team_role": "team_lead", "capacity": 8})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["members"],
        json!([{"agent_id": a_agent.0, "team_role": "team_lead", "capacity": 8}])
    );
    // Re-seating the lead is a change, not a clash; a second lead is a conflict.
    assert_eq!(
        put(a_agent.0, json!({"team_role": "team_lead"})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        put(second.0, json!({"team_role": "team_lead"})).await.0,
        StatusCode::CONFLICT
    );
    let (status, got) = put(second.0, json!({"team_role": "member"})).await;
    assert_eq!(
        (status, got["members"].as_array().unwrap().len()),
        (StatusCode::OK, 2)
    );
    assert_eq!(
        put(b_agent.0, json!({"team_role": "member"})).await.0,
        StatusCode::NOT_FOUND
    );
    // Adapted: a bad role is parsed by hand, so it is a 400 (the monolith's serde enum was 422).
    assert_eq!(
        put(a_agent.0, json!({"team_role": "chief"})).await.0,
        StatusCode::BAD_REQUEST
    );

    let (status, got) = api(&fx, Method::DELETE, &seat(a_agent.0), None).await;
    assert_eq!(
        (status, got["members"].as_array().unwrap().len()),
        (StatusCode::OK, 1)
    );
    assert_eq!(
        api(&fx, Method::DELETE, &seat(a_agent.0), None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(second.0, json!({"team_role": "team_lead"})).await.0,
        StatusCode::OK,
        "the seat is free again"
    );
    assert_eq!(audited(&fx, "team.member_seated").await, 4);
    assert_eq!(audited(&fx, "team.member_unseated").await, 1);
}

// --- org.rs ---------------------------------------------------------------------------------

#[tokio::test]
async fn reads_the_org_and_keeps_companies_apart() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let a_agent = agent(&fx, a, "A dev").await;
    let b_agent = agent(&fx, b, "B dev").await;
    let d = org::add_department(&fx.app.pool, a, "Engineering", BY)
        .await
        .unwrap();
    let t = org::add_team(&fx.app.pool, d.id, "Core", BY).await.unwrap();
    org::seat_member(&fx.app.pool, t.id, a_agent, TeamRole::TeamLead, Some(8), BY)
        .await
        .unwrap();

    let companies = ok(&fx, "/companies").await;
    assert_eq!(companies.as_array().unwrap().len(), 2);

    let chart = ok(&fx, &format!("/companies/{}/org", a.0)).await;
    assert_eq!(chart["company"]["name"], "A");
    assert_eq!(chart["agents"].as_array().unwrap().len(), 1, "only A's");
    assert_eq!(chart["agents"][0]["status"], "active");
    let seat = &chart["departments"][0]["teams"][0]["members"][0];
    assert_eq!(
        *seat,
        json!({"agent_id": a_agent.0, "team_role": "team_lead", "capacity": 8})
    );

    let agents = ok(&fx, &format!("/companies/{}/agents", b.0)).await;
    assert_eq!(agents.as_array().unwrap().len(), 1);
    assert_eq!(agents[0]["id"], b_agent.0);
    let one = ok(&fx, &format!("/agents/{}", a_agent.0)).await;
    assert_eq!(one["harness"], "opencode");
    // Not ported: `listRunners` is the Core's.

    for missing in ["/companies/99/org", "/companies/99/agents", "/agents/99"] {
        let (status, body) = get(&fx, missing).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
        assert_eq!(body["code"], "not_found");
    }
}

#[tokio::test]
async fn a_request_lands_in_the_company_intake_audited_as_the_admin() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let uri = format!("/companies/{}/requests", a.0);
    let issue = ok_post(
        &fx,
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
    let (status, _) = post(&fx, &uri, json!({"title": " "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(&fx, "/companies/99/requests", json!({"title": "x"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let by: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT actor_kind, actor_id FROM audit_events WHERE action = 'citadel.intake.submitted'",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(by, [("user".to_owned(), Some(1))]);
}
