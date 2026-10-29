//! Shaping the org over HTTP (API minor 17): departments (about, head), teams, seats.

use ainkrad_core::work::ProjectMode;
use serde_json::json;

use super::*;

async fn call(fx: &Fx, m: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    send(&fx.app, req(m, uri, Some(&fx.key), body)).await
}

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn departments_and_teams_are_created_renamed_moved_and_deleted() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let c = a.company.0;
    let uri = format!("/api/v1/companies/{c}/departments");
    let made = fx
        .ok_post(
            &uri,
            json!({"name": " Eng ", "about": "Builds it", "head_agent_id": a.agent.0}),
        )
        .await;
    assert_eq!(
        (
            &made["name"],
            &made["about"],
            &made["head_agent_id"],
            &made["teams"]
        ),
        (
            &json!("Eng"),
            &json!("Builds it"),
            &json!(a.agent.0),
            &json!([])
        )
    );
    let dept = made["id"].as_i64().unwrap();
    assert_eq!(
        fx.post(&uri, json!({"name": "Eng"})).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fx.post(&uri, json!({"name": " "})).await.0,
        StatusCode::BAD_REQUEST
    );
    let foreign = json!({"name": "X", "head_agent_id": b.agent.0});
    assert_eq!(fx.post(&uri, foreign).await.0, StatusCode::NOT_FOUND);

    let du = format!("/api/v1/departments/{dept}");
    let (status, got) = call(
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
        call(&fx, Method::PATCH, &du, Some(json!({}))).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, _) = call(
        &fx,
        Method::PATCH,
        &du,
        Some(json!({"head_agent_id": b.agent.0})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let team = fx
        .ok_post(&format!("{du}/teams"), json!({"name": "Core"}))
        .await;
    assert_eq!(
        (&team["name"], &team["members"]),
        (&json!("Core"), &json!([]))
    );
    let tid = team["id"].as_i64().unwrap();
    let other = fx.ok_post(&uri, json!({"name": "Ops"})).await["id"]
        .as_i64()
        .unwrap();
    let tu = format!("/api/v1/teams/{tid}");
    let (status, got) = call(
        &fx,
        Method::PATCH,
        &tu,
        Some(json!({"name": "Kernel", "department_id": other})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["name"], "Kernel");
    let chart = fx.ok(&format!("/api/v1/companies/{c}/org")).await;
    let ops = chart["departments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == other)
        .unwrap();
    assert_eq!(ops["teams"][0]["name"], "Kernel", "moved");
    assert_eq!(chart["departments"][0]["about"], "Builds it");
    let (status, _) = call(
        &fx,
        Method::PATCH,
        &tu,
        Some(json!({"department_id": 99999})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A department with teams stays; an empty one goes; a team goes with its seats.
    assert_eq!(
        call(
            &fx,
            Method::DELETE,
            &format!("/api/v1/departments/{other}"),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(call(&fx, Method::DELETE, &du, None).await.0, StatusCode::OK);
    assert_eq!(
        call(&fx, Method::DELETE, &du, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(call(&fx, Method::DELETE, &tu, None).await.0, StatusCode::OK);
    assert_eq!(
        call(
            &fx,
            Method::DELETE,
            &format!("/api/v1/departments/{other}"),
            None
        )
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
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let dept = fx
        .ok_post(
            &format!("/api/v1/companies/{}/departments", a.company.0),
            json!({"name": "Eng"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let team = fx
        .ok_post(
            &format!("/api/v1/departments/{dept}/teams"),
            json!({"name": "Core"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let second = crate::store::org::create_agent(
        &fx.app.pool,
        &NewAgent {
            company_id: a.company,
            name: "Second".to_owned(),
            role: "Dev".to_owned(),
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
    let seat = |agent: i64| format!("/api/v1/teams/{team}/members/{agent}");
    let put = |agent: i64, body: Value| {
        let uri = seat(agent);
        let fx = &fx;
        async move { call(fx, Method::PUT, &uri, Some(body)).await }
    };

    let (status, got) = put(a.agent.0, json!({"team_role": "team_lead", "capacity": 8})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["members"],
        json!([{"agent_id": a.agent.0, "team_role": "team_lead", "capacity": 8}])
    );
    // Re-seating the lead is a change, not a clash; a second lead is a conflict.
    assert_eq!(
        put(a.agent.0, json!({"team_role": "team_lead"})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        put(second.id.0, json!({"team_role": "team_lead"})).await.0,
        StatusCode::CONFLICT
    );
    let (status, got) = put(second.id.0, json!({"team_role": "member"})).await;
    assert_eq!(
        (status, got["members"].as_array().unwrap().len()),
        (StatusCode::OK, 2)
    );
    assert_eq!(
        put(b.agent.0, json!({"team_role": "member"})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(a.agent.0, json!({"team_role": "chief"})).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let (status, got) = call(&fx, Method::DELETE, &seat(a.agent.0), None).await;
    assert_eq!(
        (status, got["members"].as_array().unwrap().len()),
        (StatusCode::OK, 1)
    );
    assert_eq!(
        call(&fx, Method::DELETE, &seat(a.agent.0), None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(second.id.0, json!({"team_role": "team_lead"})).await.0,
        StatusCode::OK,
        "the seat is free again"
    );
    assert_eq!(audited(&fx, "team.member_seated").await, 4);
    assert_eq!(audited(&fx, "team.member_unseated").await, 1);
}
