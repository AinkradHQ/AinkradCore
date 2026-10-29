//! Quest in server mode: projects, backlog, board, epics, sprints, reports, WIP limits.

use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;

#[tokio::test]
async fn plans_a_sprint_and_reports_on_it() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "SCR", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let projects = fx
        .ok(&format!("/api/v1/companies/{}/projects", a.company.0))
        .await;
    assert_eq!(projects.as_array().unwrap().len(), 1, "only A's");
    assert_eq!(projects[0]["mode"], "scrum");
    assert_eq!(
        fx.ok(&format!("/api/v1/projects/{}", b.project.0)).await["key"],
        "BBB"
    );

    let p = a.project.0;
    let idea = fx
        .ok_post(
            &format!("/api/v1/projects/{p}/issues"),
            json!({"title": "Idea"}),
        )
        .await;
    let backlog = fx.ok(&format!("/api/v1/projects/{p}/backlog")).await;
    let ids: Vec<&Value> = backlog
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["id"])
        .collect();
    assert!(ids.contains(&&idea["id"]), "{backlog}");
    let board = fx.ok(&format!("/api/v1/projects/{p}/issues")).await;
    assert_eq!(board.as_array().unwrap().len(), 2);

    let sprint = fx
        .ok_post(
            &format!("/api/v1/projects/{p}/sprints"),
            json!({"name": "S1", "goal": "Ship", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
        )
        .await;
    assert_eq!(sprint["state"], "planned");
    let (status, _) = fx
        .post(
            &format!("/api/v1/projects/{p}/sprints"),
            json!({"name": "S0", "starts_on": "2026-10-30", "ends_on": "2026-10-19"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "ends before it starts");
    let sid = sprint["id"].as_i64().unwrap();
    let joined = fx
        .ok_post(
            &format!("/api/v1/issues/{}/sprint", idea["id"]),
            json!({"sprint_id": sid}),
        )
        .await;
    assert_eq!(joined["sprint_id"], sid);
    let (status, body) = fx
        .post(
            &format!("/api/v1/issues/{}/sprint", idea["id"]),
            json!({"sprint_id": b.project.0 + 100}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let left = fx
        .ok_post(&format!("/api/v1/issues/{}/sprint", idea["id"]), json!({}))
        .await;
    assert!(left["sprint_id"].is_null());

    let sprints = fx.ok(&format!("/api/v1/projects/{p}/sprints")).await;
    assert_eq!(sprints[0]["name"], "S1");
    let report = fx.ok(&format!("/api/v1/sprints/{sid}/report")).await;
    assert_eq!(report["state"], "planned");
    assert!(report["burndown"].is_array());
    let (status, body) = fx
        .post(&format!("/api/v1/sprints/{sid}/close"), json!({}))
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a planned sprint does not close: {body}"
    );
    let velocity = fx.ok(&format!("/api/v1/projects/{p}/velocity")).await;
    assert_eq!(velocity["sprints"], json!([]));
    assert!(
        fx.ok(&format!("/api/v1/projects/{p}/epics"))
            .await
            .is_array()
    );
    assert_eq!(
        fx.get("/api/v1/sprints/99/report").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.get("/api/v1/projects/99/backlog").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn sets_kanban_wip_limits_and_the_engine_holds_them() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "KAN", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/projects/{}/wip", a.project.0);
    let limits = fx
        .ok_post(&uri, json!({"state": "in_review", "limit": 1}))
        .await;
    assert_eq!(limits, json!([{"state": "in_review", "limit": 1}]));
    assert_eq!(fx.ok(&uri).await, limits);
    let (status, _) = fx.post(&uri, json!({"state": "done", "limit": 1})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "no limit on a terminal column"
    );
    let (status, _) = fx
        .post(&uri, json!({"state": "sideways", "limit": 1}))
        .await;
    assert!(
        status.is_client_error(),
        "an unknown state is refused: {status}"
    );
    let cleared = fx.ok_post(&uri, json!({"state": "in_review"})).await;
    assert_eq!(cleared, json!([]));
    let s = seed(&fx.app.pool, "S", "SCR", ProjectMode::Scrum).await;
    let (status, _) = fx
        .post(
            &format!("/api/v1/projects/{}/wip", s.project.0),
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
    let sid = fx
        .ok_post(&format!("/api/v1/projects/{}/sprints", a.project.0), new)
        .await["id"]
        .as_i64()
        .unwrap();
    let uri = format!("/api/v1/sprints/{sid}");
    let as_b = |m| {
        let mut r = req(m, &uri, Some(&fx.key), None);
        r.headers_mut()
            .insert(COMPANY_HEADER, b.company.0.to_string().parse().unwrap());
        send(&fx.app, r)
    };
    assert_eq!(
        as_b(Method::DELETE).await.0,
        StatusCode::NOT_FOUND,
        "another company's sprint"
    );
    let issue = fx
        .ok_post(
            &format!("/api/v1/projects/{}/issues", a.project.0),
            json!({"title": "Idea"}),
        )
        .await;
    let sprint_of = format!("/api/v1/issues/{}/sprint", issue["id"]);
    fx.ok_post(&sprint_of, json!({"sprint_id": sid})).await;
    let delete = || send(&fx.app, req(Method::DELETE, &uri, Some(&fx.key), None));
    let (status, body) = delete().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("sprint remove"), "{body}");

    fx.ok_post(&sprint_of, json!({})).await;
    let (status, gone) = delete().await;
    assert_eq!((status, &gone["id"]), (StatusCode::OK, &json!(sid)));
    assert_eq!(delete().await.0, StatusCode::NOT_FOUND);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'sprint.deleted' AND entity_id = ?",
    )
    .bind(sid)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}
