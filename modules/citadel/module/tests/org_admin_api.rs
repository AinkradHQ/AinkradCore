//! The org_admin routes end to end through the Core's gate (ported from the monolith's
//! `api/v1/tests/{agents,staffing,structure,org}.rs`): editing an agent, staffing (template and
//! proposals), structure (departments, teams, seats), the org chart. See `org_admin_api_2.rs`
//! for avatars, routing and companies.
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

// --- agents.rs ----------------------------------------------------------------------------

#[tokio::test]
async fn an_agent_is_edited_field_by_field_and_audited() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let id = agent(&fx, a, "A dev").await.0;
    let b_agent = agent(&fx, b, "B dev").await;
    let before = ok(&fx, &format!("/agents/{id}")).await;
    assert_eq!(before["effort"], Value::Null);
    assert_eq!(before["guidelines"], json!([]));

    let all = json!({"role": " QA lead ", "description": "Finds bugs", "harness": "claude",
        "model": "sonnet", "effort": "high", "sandbox": "read-only",
        "runner_tags": ["macos"], "instructions": "Be thorough.",
        "guidelines": ["Test first", "No force pushes"]});
    let (status, got) = patch(&fx, id, all).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["role"], "QA lead");
    assert_eq!(got["harness"], "claude");
    assert_eq!(got["effort"], "high");
    assert_eq!(got["sandbox"], "read-only");
    assert_eq!(got["runner_tags"], json!(["macos"]));
    assert_eq!(got["guidelines"], json!(["Test first", "No force pushes"]));
    assert_eq!(
        ok(&fx, &format!("/agents/{id}")).await["instructions"],
        "Be thorough."
    );

    // A partial change keeps the rest; null clears effort and the sandbox.
    let (status, got) = patch(&fx, id, json!({"effort": null, "sandbox": "full-access"})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        (&got["effort"], &got["sandbox"], &got["role"]),
        (&Value::Null, &json!("full-access"), &json!("QA lead"))
    );
    assert_eq!(audited(&fx, "agent.updated").await, 2);
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'citadel.agent.updated' \
         ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["fields"], json!(["effort", "sandbox"]));

    // Refused: nothing to change, a blank role, a bad value, a bad tag.
    for bad in [
        json!({}),
        json!({"role": " "}),
        json!({"effort": "extreme"}),
        json!({"sandbox": "read_only"}),
        json!({"runner_tags": ["a b"]}),
        json!({"guidelines": [""]}),
    ] {
        let (status, _) = patch(&fx, id, bad.clone()).await;
        assert!(status.is_client_error(), "{bad}: {status}");
        assert_ne!(status, StatusCode::OK, "{bad}");
    }
    assert_eq!(patch(&fx, id, json!({})).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        patch(&fx, 999, json!({"role": "x"})).await.0,
        StatusCode::NOT_FOUND
    );

    // A reporting line: another company's manager is not found, a loop is a conflict.
    let boss = agent(&fx, a, "Boss").await;
    assert_eq!(
        patch(&fx, id, json!({"reports_to": b_agent.0})).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, got) = patch(&fx, id, json!({"reports_to": boss.0})).await;
    assert_eq!(
        (status, &got["reports_to"]),
        (StatusCode::OK, &json!(boss.0))
    );
    assert_eq!(
        patch(&fx, boss.0, json!({"reports_to": id})).await.0,
        StatusCode::CONFLICT
    );
    let (_, got) = patch(&fx, id, json!({"reports_to": null})).await;
    assert_eq!(got["reports_to"], Value::Null);
}

// The run engine (S7) owns waking and ending an agent: the HTTP halves are kept, their routes
// are not built, and the run/issue/wake assertions of the monolith need the run tables.
#[tokio::test]
#[ignore = "S7: wakeAgent needs the run engine and the wake queue"]
async fn wake_runs_the_active_agent_and_refuses_the_paused() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let uri = format!("/agents/{id}/wake");
    let woken = ok_post(&fx, &uri, json!({})).await;
    assert_eq!(woken["status"], "active");
    assert_eq!(audited(&fx, "agent.woken").await, 1);
    ok_post(&fx, &format!("/agents/{id}/pause"), json!({})).await;
    assert_eq!(post(&fx, &uri, json!({})).await.0, StatusCode::CONFLICT);
    assert_eq!(
        post(&fx, "/agents/999/wake", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "S7: terminateAgent ends runs and hands issues over (run engine)"]
async fn terminate_ends_runs_hands_issues_to_the_admin_and_wakes_nothing_again() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let uri = format!("/agents/{id}/terminate");
    assert_eq!(
        post(&fx, &uri, json!({"reason": " "})).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&fx, "/agents/999/terminate", json!({"reason": "x"}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let gone = ok_post(&fx, &uri, json!({"reason": "Replaced by Sam"})).await;
    assert_eq!(gone["status"], "terminated", "{gone}");
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'citadel.agent.terminated'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["reason"], "Replaced by Sam");
    assert_eq!(
        post(&fx, &format!("/agents/{id}/wake"), json!({})).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&fx, &uri, json!({"reason": "again"})).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        patch(&fx, id, json!({"role": "x"})).await.0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn a_hires_profile_seat_and_palette_apply_when_it_is_approved() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let dept = ok_post(
        &fx,
        &format!("/companies/{}/departments", a.0),
        json!({"name": "Engineering"}),
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
    let theirs_dept = ok_post(
        &fx,
        &format!("/companies/{}/departments", b.0),
        json!({"name": "Ops"}),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    let theirs = ok_post(
        &fx,
        &format!("/departments/{theirs_dept}/teams"),
        json!({"name": "Run"}),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    let palettes = ok(&fx, "/avatars/palettes").await;
    let palette = palettes[1]["id"].as_str().unwrap().to_owned();

    let proposal = |name: &str, role: &str| {
        json!({"name": name, "role": "Developer", "harness": "claude", "model": "sonnet",
               "justification": "Needed", "description": "Writes Rust", "effort": "low",
               "sandbox": "workspace-write", "instructions": "Small PRs.",
               "guidelines": ["Test first"], "team_id": team, "team_role": role,
               "palette_id": palette})
    };
    let uri = format!("/companies/{}/agents", a.0);
    let proposed = ok_post(&fx, &uri, proposal("Sam", "team_lead")).await;
    let id = proposed["agent"]["id"].as_i64().unwrap();
    assert_eq!(
        proposed["agent"]["description"], "",
        "applied on approval, not before"
    );
    assert!(seats(&fx, id).await.is_empty());
    let decide = format!("/approvals/{}/decide", proposed["hire_approval_id"]);
    ok_post(&fx, &decide, json!({"approve": true})).await;
    let hired = ok(&fx, &format!("/agents/{id}")).await;
    assert_eq!(hired["status"], "active");
    assert_eq!(hired["description"], "Writes Rust");
    assert_eq!(hired["effort"], "low");
    assert_eq!(hired["sandbox"], "workspace-write");
    assert_eq!(hired["instructions"], "Small PRs.");
    assert_eq!(hired["guidelines"], json!(["Test first"]));
    assert_eq!(hired["appearance"]["palette_id"], json!(palette));
    assert_eq!(seats(&fx, id).await, ["team_lead"]);

    // Refused at the proposal: the lead seat is taken, another company's team, an unknown
    // palette, a role without a team, a bad profile.
    assert_eq!(
        post(&fx, &uri, proposal("Kim", "team_lead")).await.0,
        StatusCode::CONFLICT
    );
    let mut other = proposal("Kim", "member");
    other["team_id"] = json!(theirs);
    assert_eq!(post(&fx, &uri, other).await.0, StatusCode::NOT_FOUND);
    let mut bad = proposal("Kim", "member");
    bad["palette_id"] = json!("nope");
    assert_eq!(post(&fx, &uri, bad).await.0, StatusCode::BAD_REQUEST);
    let mut bad = proposal("Kim", "member");
    bad["team_id"] = Value::Null;
    assert_eq!(post(&fx, &uri, bad).await.0, StatusCode::BAD_REQUEST);
    let mut bad = proposal("Kim", "member");
    bad["guidelines"] = json!([" "]);
    assert_eq!(post(&fx, &uri, bad).await.0, StatusCode::BAD_REQUEST);
    // A plain proposal (API minor 16) still works.
    let plain = json!({"name": "Old", "role": "QA", "harness": "claude", "model": "sonnet",
                       "justification": "Needed"});
    ok_post(&fx, &uri, plain).await;
}

// --- staffing.rs (the template and a proposed agent; the project, profile and requirement tests
// of that file belong to the work and planning slices) ----------------------------------------

#[tokio::test]
async fn the_template_and_a_proposed_agent_wait_on_their_hires() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let a_agent = agent(&fx, a, "A dev").await;
    let b_agent = agent(&fx, b, "B dev").await;
    let c = a.0;
    let template = format!("/companies/{c}/templates/engineering");
    let applied = ok_post(&fx, &template, json!({})).await;
    let agents = applied["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 7, "{applied}");
    assert!(agents.iter().all(|a| a["status"] == "pending_approval"));
    assert_eq!(applied["hire_approval_ids"].as_array().unwrap().len(), 7);
    let again = ok_post(&fx, &template, json!({})).await;
    assert_eq!(
        again["hire_approval_ids"],
        json!([]),
        "a re-apply adds nothing"
    );
    let (status, _) = post(&fx, &format!("/companies/{c}/templates/sales"), json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let proposal = json!({"name": "Designer", "role": "Designer", "harness": "claude",
                          "model": "sonnet", "reports_to": a_agent.0,
                          "justification": "We need screens"});
    let proposed = ok_post(&fx, &format!("/companies/{c}/agents"), proposal.clone()).await;
    assert_eq!(
        proposed["agent"]["status"], "pending_approval",
        "{proposed}"
    );
    assert!(proposed["hire_approval_id"].is_i64());
    assert_eq!(audited(&fx, "agent.hire_requested").await, 8);

    // Another company's manager, a blank justification, another company's path.
    let mut theirs = proposal.clone();
    theirs["name"] = json!("Other");
    theirs["reports_to"] = json!(b_agent.0);
    let uri = format!("/companies/{c}/agents");
    assert_eq!(post(&fx, &uri, theirs).await.0, StatusCode::NOT_FOUND);
    let mut blank = proposal.clone();
    blank["name"] = json!("Blank");
    blank["justification"] = json!(" ");
    assert_eq!(post(&fx, &uri, blank).await.0, StatusCode::BAD_REQUEST);
    for uri in [
        format!("/companies/{}/agents", b.0),
        format!("/companies/{}/templates/engineering", b.0),
    ] {
        let (status, _) = call_in(
            &fx,
            Some(&fx.dev),
            Some(&a.0.to_string()),
            Method::POST,
            &uri,
            Some(proposal.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn approving_a_proposed_agent_hires_it() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let proposal = json!({"name": "Designer", "role": "Designer", "harness": "claude",
                          "model": "sonnet", "justification": "We need screens"});
    let proposed = ok_post(&fx, &format!("/companies/{}/agents", a.0), proposal).await;
    let approval = proposed["hire_approval_id"].as_i64().unwrap();
    let decided = ok_post(
        &fx,
        &format!("/approvals/{approval}/decide"),
        json!({"approve": true}),
    )
    .await;
    assert_eq!(decided["status"], "approved", "{decided}");
    let agent = ok(&fx, &format!("/agents/{}", proposed["agent"]["id"])).await;
    assert_eq!(agent["status"], "active", "approving hires it");
}
