//! Quest from the app (API minor 9): project settings and labels, labels on issues, team
//! capacity, flow times, the owner's sprint commit, a sprint's review and retro, epic keys and
//! `project_id` on issue events. Each refuses another company's data and is audited.

use ainkrad_core::gov::KnowledgeKind;
use ainkrad_core::org::TeamRole;
use ainkrad_core::work::SprintId;
use serde_json::json;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;
use crate::store::org;
use crate::store::work::{RetroItem, propose_retro};

fn with(company: CompanyId, mut r: Request<Body>) -> Request<Body> {
    let v = company.0.to_string().parse().unwrap();
    r.headers_mut().insert(COMPANY_HEADER, v);
    r
}

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn put(fx: &Fx, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::PUT, uri, Some(&fx.key), Some(body))).await
}

async fn delete(fx: &Fx, uri: &str) -> (StatusCode, Value) {
    send(&fx.app, req(Method::DELETE, uri, Some(&fx.key), None)).await
}

/// Every route of this file, as company B's, refused while working in A.
#[tokio::test]
async fn another_companys_quest_data_is_refused() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let label = fx
        .ok_post(
            &format!("/api/v1/projects/{}/labels", b.project.0),
            json!({"name": "ui"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let sprint = fx
        .ok_post(
            &format!("/api/v1/projects/{}/sprints", b.project.0),
            json!({"name": "S", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let (p, i) = (b.project.0, b.issue.0);
    for (method, uri, body) in [
        (
            Method::PUT,
            format!("/api/v1/projects/{p}"),
            Some(json!({"name": "X"})),
        ),
        (Method::GET, format!("/api/v1/projects/{p}/labels"), None),
        (
            Method::POST,
            format!("/api/v1/projects/{p}/labels"),
            Some(json!({"name": "x"})),
        ),
        (
            Method::PUT,
            format!("/api/v1/projects/{p}/labels/{label}"),
            Some(json!({"name": "y"})),
        ),
        (
            Method::DELETE,
            format!("/api/v1/projects/{p}/labels/{label}"),
            None,
        ),
        (
            Method::PUT,
            format!("/api/v1/issues/{i}/labels/{label}"),
            None,
        ),
        (
            Method::DELETE,
            format!("/api/v1/issues/{i}/labels/{label}"),
            None,
        ),
        (Method::GET, format!("/api/v1/projects/{p}/capacity"), None),
        (
            Method::PUT,
            format!("/api/v1/projects/{p}/capacity/{}", b.agent.0),
            Some(json!({})),
        ),
        (Method::GET, format!("/api/v1/projects/{p}/flow"), None),
        (Method::GET, format!("/api/v1/issues/{i}/flow"), None),
        (
            Method::POST,
            format!("/api/v1/sprints/{sprint}/commit"),
            Some(json!({})),
        ),
        (
            Method::GET,
            format!("/api/v1/sprints/{sprint}/review"),
            None,
        ),
    ] {
        let r = with(a.company, req(method.clone(), &uri, Some(&fx.key), body));
        assert_eq!(
            send(&fx.app, r).await.0,
            StatusCode::NOT_FOUND,
            "{method} {uri}"
        );
    }
}

#[tokio::test]
async fn project_settings_labels_and_epic_keys() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let p = a.project.0;
    let uri = format!("/api/v1/projects/{p}");
    let (status, got) = put(&fx, &uri, json!({"name": "Renamed", "mode": "kanban"})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        (got["name"].clone(), got["mode"].clone()),
        (json!("Renamed"), json!("kanban"))
    );
    assert_eq!(got["key"], "AAA", "the key never changes");
    assert_eq!(audited(&fx, "project.updated").await, 1);
    let theirs = org::add_department(&fx.app.pool, b.company, "Eng", BY_ADMIN)
        .await
        .unwrap();
    let team = org::add_team(&fx.app.pool, theirs.id, "T", BY_ADMIN)
        .await
        .unwrap();
    assert_eq!(
        put(&fx, &uri, json!({"team_id": team.id.0})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(&fx, &uri, json!({"name": " "})).await.0,
        StatusCode::BAD_REQUEST
    );
    // A scrum project with a planned sprint stays scrum.
    let bp = b.project.0;
    fx.ok_post(
        &format!("/api/v1/projects/{bp}/sprints"),
        json!({"name": "S", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
    )
    .await;
    let (status, _) = put(
        &fx,
        &format!("/api/v1/projects/{bp}"),
        json!({"mode": "kanban"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let labels = format!("/api/v1/projects/{p}/labels");
    let ui = fx.ok_post(&labels, json!({"name": "ui"})).await["id"]
        .as_i64()
        .unwrap();
    let api = fx.ok_post(&labels, json!({"name": "api"})).await["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        fx.post(&labels, json!({"name": "ui"})).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, renamed) = put(&fx, &format!("{labels}/{ui}"), json!({"name": "UI"})).await;
    assert_eq!(
        (status, renamed["name"].clone()),
        (StatusCode::OK, json!("UI"))
    );
    let i = a.issue.0;
    let (status, issue) = put(&fx, &format!("/api/v1/issues/{i}/labels/{ui}"), json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["labels"][0]["name"], "UI");
    put(
        &fx,
        &format!("/api/v1/issues/{i}/labels/{api}"),
        json!(null),
    )
    .await;
    let board = fx.ok(&format!("/api/v1/projects/{p}/issues")).await;
    let names: Vec<&str> = board[0]["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["UI", "api"], "{board}");
    let blabel = fx
        .ok_post(
            &format!("/api/v1/projects/{bp}/labels"),
            json!({"name": "x"}),
        )
        .await["id"]
        .clone();
    let (status, _) = put(
        &fx,
        &format!("/api/v1/issues/{i}/labels/{blabel}"),
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another project's label");
    let (_, issue) = delete(&fx, &format!("/api/v1/issues/{i}/labels/{api}")).await;
    assert_eq!(issue["labels"].as_array().unwrap().len(), 1);
    let (status, left) = delete(&fx, &format!("{labels}/{ui}")).await;
    assert_eq!(
        (status, left.as_array().unwrap().len()),
        (StatusCode::OK, 1)
    );
    let issue = fx.ok(&format!("/api/v1/issues/{i}")).await;
    assert_eq!(
        issue["labels"],
        json!([]),
        "a deleted label leaves every issue"
    );
    for action in [
        "label.created",
        "label.renamed",
        "label.deleted",
        "issue.labeled",
    ] {
        assert!(audited(&fx, action).await > 0, "{action}");
    }

    // Epic keys: per project, never reused; the label events name their project.
    let epics = format!("/api/v1/projects/{p}/epics");
    let e1 = fx.ok_post(&epics, json!({"title": "One"})).await;
    let e2 = fx.ok_post(&epics, json!({"title": "Two"})).await;
    assert_eq!(
        (e1["key"].clone(), e2["key"].clone()),
        (json!("AAA-E1"), json!("AAA-E2"))
    );
    sqlx::query("DELETE FROM epics WHERE id = ?")
        .bind(e2["id"].as_i64())
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let e3 = fx.ok_post(&epics, json!({"title": "Three"})).await;
    assert_eq!(e3["key"], "AAA-E3");
    let theirs = fx
        .ok_post(
            &format!("/api/v1/projects/{bp}/epics"),
            json!({"title": "B"}),
        )
        .await;
    assert_eq!(theirs["key"], "BBB-E1");
    let unnamed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE 'issue.%' AND entity_kind = 'issue' \
         AND json_extract(details, '$.project_id') IS NULL",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(unnamed, 0, "every issue event names its project");
    let events = fx.ok("/api/v1/events?limit=500").await;
    assert!(events.to_string().contains("\"project_id\""), "{events}");
}

const BY_ADMIN: AuditActor = AuditActor::User(super::super::ADMIN);

#[tokio::test]
async fn capacity_commit_flow_and_review() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let pool = &fx.app.pool;
    let d = org::add_department(pool, a.company, "Eng", BY_ADMIN)
        .await
        .unwrap();
    let team = org::add_team(pool, d.id, "Core", BY_ADMIN).await.unwrap();
    org::seat_member(
        pool,
        team.id,
        a.agent,
        TeamRole::ProductOwner,
        Some(2),
        BY_ADMIN,
    )
    .await
    .unwrap();
    let p = a.project.0;
    let (status, _) = put(
        &fx,
        &format!("/api/v1/projects/{p}"),
        json!({"team_id": team.id.0}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cap = fx.ok(&format!("/api/v1/projects/{p}/capacity")).await;
    assert_eq!(
        (cap["total"].clone(), cap["members"][0]["team_role"].clone()),
        (json!(2), json!("product_owner"))
    );
    let set = format!("/api/v1/projects/{p}/capacity/{}", a.agent.0);
    let (status, cap) = put(&fx, &set, json!({"capacity": 3})).await;
    assert_eq!((status, cap["total"].clone()), (StatusCode::OK, json!(3)));
    assert_eq!(audited(&fx, "member.capacity_set").await, 1);
    let (status, _) = put(
        &fx,
        &format!("/api/v1/projects/{p}/capacity/9999"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A sprint of 5 points over a capacity of 3: the owner commits it with a reason.
    let sprint = fx
        .ok_post(
            &format!("/api/v1/projects/{p}/sprints"),
            json!({"name": "S1", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let i = a.issue.0;
    fx.ok_post(
        &format!("/api/v1/issues/{i}/estimate"),
        json!({"points": 5}),
    )
    .await;
    fx.ok_post(
        &format!("/api/v1/issues/{i}/sprint"),
        json!({"sprint_id": sprint}),
    )
    .await;
    let commit = format!("/api/v1/sprints/{sprint}/commit");
    let (status, body) = fx.post(&commit, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "over capacity: {body}");
    let started = fx
        .ok_post(&commit, json!({"override_reason": "crunch"}))
        .await;
    assert_eq!(started["state"], "active");
    let gate: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'sprint.started'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        gate.contains("\"owner\"") && gate.contains("crunch"),
        "{gate}"
    );
    assert_eq!(
        fx.post(&commit, json!({})).await.0,
        StatusCode::CONFLICT,
        "started already"
    );

    // Flow: the issue's age; done, its cycle and lead, and the project's throughput.
    let flow = fx.ok(&format!("/api/v1/issues/{i}/flow")).await;
    assert!(
        flow["age_secs"].is_i64() && flow["lead_secs"].is_null(),
        "{flow}"
    );
    for step in ["start", "review", "done"] {
        sqlx::query("UPDATE issues SET state = ? WHERE id = ?")
            .bind(match step {
                "start" => "in_progress",
                "review" => "in_review",
                _ => "done",
            })
            .bind(i)
            .execute(pool)
            .await
            .unwrap();
    }
    let flow = fx.ok(&format!("/api/v1/issues/{i}/flow")).await;
    assert!(
        flow["cycle_secs"].is_i64() && flow["lead_secs"].is_i64(),
        "{flow}"
    );
    let until = "2100-01-01T00:00:00.000Z";
    let project = fx
        .ok(&format!(
            "/api/v1/projects/{p}/flow?since=2000-01-01T00:00:00.000Z&until={until}"
        ))
        .await;
    assert_eq!(project["throughput"], 1, "{project}");
    assert!(fx.ok(&format!("/api/v1/projects/{p}/flow")).await["since"].is_string());

    // Review and retro: absent before it closes, then what the PO proposed.
    let review = format!("/api/v1/sprints/{sprint}/review");
    assert!(fx.ok(&review).await["review"].is_null());
    fx.ok_post(&format!("/api/v1/sprints/{sprint}/close"), json!({}))
        .await;
    let item = RetroItem {
        kind: KnowledgeKind::Retro,
        title: "Smaller stories".to_owned(),
        body: "Split anything over 3 points.".to_owned(),
    };
    propose_retro(pool, SprintId(sprint), &[item], a.agent)
        .await
        .unwrap();
    let got = fx.ok(&review).await;
    assert_eq!(got["review"]["completed"], 5, "{got}");
    assert_eq!(got["retro"][0]["title"], "Smaller stories");
    assert_eq!(got["retro"][0]["status"], "proposed");
}
