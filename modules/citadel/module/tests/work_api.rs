//! Quest in server mode through the Core's gate: projects, backlog, board, epics, sprints,
//! reports, WIP limits. Ported from the monolith's `api/v1/tests/projects.rs`.

mod common;
mod work_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::work::ProjectMode;
use common::*;
use serde_json::{Value, json};
use work_seed::*;

#[tokio::test]
async fn plans_a_sprint_and_reports_on_it() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "SCR", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let projects = ok(&fx, &format!("/companies/{}/projects", a.company)).await;
    assert_eq!(projects.as_array().unwrap().len(), 1, "only A's");
    assert_eq!(projects[0]["mode"], "scrum");
    assert_eq!(
        ok(&fx, &format!("/projects/{}", b.project)).await["key"],
        "BBB"
    );

    let p = a.project;
    let idea = ok_post(
        &fx,
        &format!("/projects/{p}/issues"),
        json!({"title": "Idea"}),
    )
    .await;
    let backlog = ok(&fx, &format!("/projects/{p}/backlog")).await;
    let ids: Vec<&Value> = backlog
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["id"])
        .collect();
    assert!(ids.contains(&&idea["id"]), "{backlog}");
    let board = ok(&fx, &format!("/projects/{p}/issues")).await;
    assert_eq!(board.as_array().unwrap().len(), 2);

    let sprint = ok_post(
        &fx,
        &format!("/projects/{p}/sprints"),
        json!({"name": "S1", "goal": "Ship", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
    )
    .await;
    assert_eq!(sprint["state"], "planned");
    let (status, _) = post(
        &fx,
        &format!("/projects/{p}/sprints"),
        json!({"name": "S0", "starts_on": "2026-10-30", "ends_on": "2026-10-19"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "ends before it starts");
    let sid = sprint["id"].as_i64().unwrap();
    let joined = ok_post(
        &fx,
        &format!("/issues/{}/sprint", idea["id"]),
        json!({"sprint_id": sid}),
    )
    .await;
    assert_eq!(joined["sprint_id"], sid);
    let (status, body) = post(
        &fx,
        &format!("/issues/{}/sprint", idea["id"]),
        json!({"sprint_id": b.project + 100}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let left = ok_post(&fx, &format!("/issues/{}/sprint", idea["id"]), json!({})).await;
    assert!(left["sprint_id"].is_null());

    let sprints = ok(&fx, &format!("/projects/{p}/sprints")).await;
    assert_eq!(sprints[0]["name"], "S1");
    let report = ok(&fx, &format!("/sprints/{sid}/report")).await;
    assert_eq!(report["state"], "planned");
    assert!(report["burndown"].is_array());
    let (status, body) = post(&fx, &format!("/sprints/{sid}/close"), json!({})).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a planned sprint does not close: {body}"
    );
    let velocity = ok(&fx, &format!("/projects/{p}/velocity")).await;
    assert_eq!(velocity["sprints"], json!([]));
    assert!(ok(&fx, &format!("/projects/{p}/epics")).await.is_array());
    assert_eq!(
        get(&fx, "/sprints/99/report").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&fx, "/projects/99/backlog").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn sets_kanban_wip_limits_and_the_engine_holds_them() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "KAN", ProjectMode::Kanban).await;
    let uri = format!("/projects/{}/wip", a.project);
    let limits = ok_post(&fx, &uri, json!({"state": "in_review", "limit": 1})).await;
    assert_eq!(limits, json!([{"state": "in_review", "limit": 1}]));
    assert_eq!(ok(&fx, &uri).await, limits);
    let (status, _) = post(&fx, &uri, json!({"state": "done", "limit": 1})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "no limit on a terminal column"
    );
    let (status, _) = post(&fx, &uri, json!({"state": "sideways", "limit": 1})).await;
    assert!(
        status.is_client_error(),
        "an unknown state is refused: {status}"
    );
    let cleared = ok_post(&fx, &uri, json!({"state": "in_review"})).await;
    assert_eq!(cleared, json!([]));
    let s = seed(&fx.app.pool, "S", "SCR", ProjectMode::Scrum).await;
    let (status, _) = post(
        &fx,
        &format!("/projects/{}/wip", s.project),
        json!({"state": "todo", "limit": 2}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "scrum has no WIP limits");
}

#[tokio::test]
async fn deletes_an_empty_planned_sprint_in_its_company() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "SCR", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let new = json!({"name": "S1", "starts_on": "2026-10-19", "ends_on": "2026-10-30"});
    let sid = ok_post(&fx, &format!("/projects/{}/sprints", a.project), new).await["id"]
        .as_i64()
        .unwrap();
    let uri = format!("/sprints/{sid}");
    let b_company = b.company.to_string();
    assert_eq!(
        call_in(
            &fx,
            Some(&fx.dev),
            Some(&b_company),
            Method::DELETE,
            &uri,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "another company's sprint"
    );
    let issue = ok_post(
        &fx,
        &format!("/projects/{}/issues", a.project),
        json!({"title": "Idea"}),
    )
    .await;
    let sprint_of = format!("/issues/{}/sprint", issue["id"]);
    ok_post(&fx, &sprint_of, json!({"sprint_id": sid})).await;
    let delete = || call(&fx, Some(&fx.dev), Method::DELETE, &uri, None);
    let (status, body) = delete().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("sprint remove"), "{body}");

    ok_post(&fx, &sprint_of, json!({})).await;
    let (status, gone) = delete().await;
    assert_eq!((status, &gone["id"]), (StatusCode::OK, &json!(sid)));
    assert_eq!(delete().await.0, StatusCode::NOT_FOUND);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.sprint.deleted' AND entity_id = ?",
    )
    .bind(sid)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}
