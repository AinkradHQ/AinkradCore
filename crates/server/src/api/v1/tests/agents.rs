//! Editing and ending an agent (API minor 17): `updateAgent`, `wakeAgent`, `terminateAgent`, and
//! a hire's profile, team seat and palette applied when it is approved.

use ainkrad_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::org::{self, add_department, add_team};

async fn patch(fx: &Fx, id: i64, body: Value) -> (StatusCode, Value) {
    let uri = format!("/api/v1/agents/{id}");
    send(&fx.app, req(Method::PATCH, &uri, Some(&fx.key), Some(body))).await
}

async fn seats(fx: &Fx, agent: i64) -> Vec<String> {
    sqlx::query_scalar("SELECT team_role FROM team_memberships WHERE agent_id = ?")
        .bind(agent)
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_agent_is_edited_field_by_field_and_audited() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let id = a.agent.0;
    let before = fx.ok(&format!("/api/v1/agents/{id}")).await;
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
        fx.ok(&format!("/api/v1/agents/{id}")).await["instructions"],
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
        "SELECT details FROM audit_events WHERE action = 'agent.updated' ORDER BY seq DESC LIMIT 1",
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
    let boss = org::create_agent(
        &fx.app.pool,
        &NewAgent {
            company_id: a.company,
            name: "Boss".to_owned(),
            role: "Lead".to_owned(),
            org_role: OrgRole::None,
            reports_to: None,
            harness: Harness::Claude,
            model: String::new(),
            runner_tags: vec![],
            status: AgentStatus::Active,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        patch(&fx, id, json!({"reports_to": b.agent.0})).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, got) = patch(&fx, id, json!({"reports_to": boss.id.0})).await;
    assert_eq!(
        (status, &got["reports_to"]),
        (StatusCode::OK, &json!(boss.id.0))
    );
    assert_eq!(
        patch(&fx, boss.id.0, json!({"reports_to": id})).await.0,
        StatusCode::CONFLICT
    );
    let (_, got) = patch(&fx, id, json!({"reports_to": null})).await;
    assert_eq!(got["reports_to"], Value::Null);
}

#[tokio::test]
async fn wake_runs_the_active_agent_and_refuses_the_paused() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/wake", a.agent.0);
    let woken = fx.ok_post(&uri, json!({})).await;
    assert_eq!(woken["status"], "active");
    assert_eq!(audited(&fx, "agent.woken").await, 1);
    let manual: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND source = 'manual' \
         AND issue_id = ?",
    )
    .bind(a.agent.0)
    .bind(a.issue.0)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(manual, 1, "on the issue waiting on it");
    fx.ok_post(&format!("/api/v1/agents/{}/pause", a.agent.0), json!({}))
        .await;
    assert_eq!(fx.post(&uri, json!({})).await.0, StatusCode::CONFLICT);
    assert_eq!(
        fx.post("/api/v1/agents/999/wake", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn terminate_ends_runs_hands_issues_to_the_admin_and_wakes_nothing_again() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/terminate", a.agent.0);
    assert_eq!(
        fx.post(&uri, json!({"reason": " "})).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fx.post("/api/v1/agents/999/terminate", json!({"reason": "x"}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let gone = fx.ok_post(&uri, json!({"reason": "Replaced by Sam"})).await;
    assert_eq!(gone["status"], "terminated", "{gone}");
    let run: String = sqlx::query_scalar("SELECT state FROM runs WHERE id = ?")
        .bind(a.run.id.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(run, "cancelled");
    let (agent, user): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT next_agent_id, next_user_id FROM issues WHERE id = ?")
            .bind(a.issue.0)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((agent, user), (None, Some(1)), "handed to the admin");
    let details: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'agent.terminated'")
            .fetch_one(pool)
            .await
            .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["reason"], "Replaced by Sam");
    assert_eq!(details["issues"], json!([a.issue.0]));
    assert_eq!(details["runs"], json!([a.run.id.0]));

    // No new wakes: one asked for it is kept as a dropped record; waking it by hand is refused.
    let wake = NewWakeRequest {
        agent_id: a.agent,
        issue_id: Some(a.issue),
        source: WakeSource::Comment,
        reason: "late".to_owned(),
        idempotency_key: "late".to_owned(),
        not_before: None,
    };
    let stored = enqueue_wake(pool, &wake).await.unwrap();
    assert_eq!(stored.status.as_str(), "dropped");
    assert_eq!(
        fx.post(&format!("/api/v1/agents/{}/wake", a.agent.0), json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fx.post(&uri, json!({"reason": "again"})).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        patch(&fx, a.agent.0, json!({"role": "x"})).await.0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn a_hires_profile_seat_and_palette_apply_when_it_is_approved() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let c = a.company.0;
    let dept = add_department(pool, a.company, "Engineering", super::super::BY)
        .await
        .unwrap();
    let team = add_team(pool, dept.id, "Core", super::super::BY)
        .await
        .unwrap();
    let theirs_dept = add_department(pool, b.company, "Ops", super::super::BY)
        .await
        .unwrap();
    let theirs = add_team(pool, theirs_dept.id, "Run", super::super::BY)
        .await
        .unwrap();
    let palettes = fx.ok("/api/v1/avatars/palettes").await;
    let palette = palettes[1]["id"].as_str().unwrap().to_owned();

    let proposal = |name: &str, role: &str| {
        json!({"name": name, "role": "Developer", "harness": "claude", "model": "sonnet",
               "justification": "Needed", "description": "Writes Rust", "effort": "low",
               "sandbox": "workspace-write", "instructions": "Small PRs.",
               "guidelines": ["Test first"], "team_id": team.id.0, "team_role": role,
               "palette_id": palette})
    };
    let uri = format!("/api/v1/companies/{c}/agents");
    let proposed = fx.ok_post(&uri, proposal("Sam", "team_lead")).await;
    let id = proposed["agent"]["id"].as_i64().unwrap();
    assert_eq!(
        proposed["agent"]["description"], "",
        "applied on approval, not before"
    );
    assert!(seats(&fx, id).await.is_empty());
    let decide = format!(
        "/api/v1/approvals/{}/decision",
        proposed["hire_approval_id"]
    );
    fx.ok_post(&decide, json!({"approve": true})).await;
    let hired = fx.ok(&format!("/api/v1/agents/{id}")).await;
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
        fx.post(&uri, proposal("Kim", "team_lead")).await.0,
        StatusCode::CONFLICT
    );
    let mut other = proposal("Kim", "member");
    other["team_id"] = json!(theirs.id.0);
    assert_eq!(fx.post(&uri, other).await.0, StatusCode::NOT_FOUND);
    let mut bad = proposal("Kim", "member");
    bad["palette_id"] = json!("nope");
    assert_eq!(fx.post(&uri, bad).await.0, StatusCode::BAD_REQUEST);
    let mut bad = proposal("Kim", "member");
    bad["team_id"] = Value::Null;
    assert_eq!(fx.post(&uri, bad).await.0, StatusCode::BAD_REQUEST);
    let mut bad = proposal("Kim", "member");
    bad["guidelines"] = json!([" "]);
    assert_eq!(fx.post(&uri, bad).await.0, StatusCode::BAD_REQUEST);
    // A plain proposal (API minor 16) still works.
    let plain = json!({"name": "Old", "role": "QA", "harness": "claude", "model": "sonnet",
                       "justification": "Needed"});
    fx.ok_post(&uri, plain).await;
}
