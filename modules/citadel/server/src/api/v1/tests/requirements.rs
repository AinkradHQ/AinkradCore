//! Requirements over the client API (E15.10): a request is a requirement, listed with its
//! state and read as a live tree; its issues carry its id (Quest's tag).

use serde_json::json;

use super::*;

#[tokio::test]
async fn a_request_is_a_requirement_with_a_tree() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let c = a.company.0;
    let body = json!({"title": "Phone alerts", "body": "Buzz me"});
    let asked = fx
        .ok_post(&format!("/api/v1/companies/{c}/requests"), body)
        .await;
    let id = asked["requirement_id"]
        .as_i64()
        .expect("the request is a requirement");
    let issue = fx.ok(&format!("/api/v1/issues/{}", asked["id"])).await;
    assert_eq!(issue["requirement_id"], id);

    let all = fx.ok("/api/v1/requirements").await;
    assert_eq!(all[0]["key"], "R-1");
    assert_eq!(all[0]["state"], "planning");
    let one = fx.ok(&format!("/api/v1/requirements/{id}")).await;
    assert_eq!(
        (one["title"].as_str(), one["plan_version"].as_i64()),
        (Some("Phone alerts"), Some(0))
    );
    let tree = fx.ok(&format!("/api/v1/requirements/{id}/tree")).await;
    assert_eq!(tree["requirement"]["id"], id);
    assert_eq!(
        (tree["points"].as_i64(), tree["percent_done"].as_i64()),
        (Some(0), Some(0))
    );
    assert_eq!(tree["epics"], json!([]));
    assert_eq!(
        tree["other"][0]["issue_id"], asked["id"],
        "the request itself"
    );
    assert!(
        tree.get("diff").is_none() || tree["diff"].is_null(),
        "no plan approved yet"
    );
    let (status, _) = fx.get("/api/v1/requirements/999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The thread (E15.11): an agent's question is a card; a post answers it (auto-targeted) and
/// wakes the asker; with nothing open a post goes to the owner.
#[tokio::test]
async fn the_thread_shows_questions_and_routes_answers_to_the_asker() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Scrum).await;
    let asked = crate::store::work::submit_intake(pool, a.company, "Alerts", "", super::super::BY)
        .await
        .unwrap();
    let r = asked.requirement_id.unwrap();
    sqlx::query("UPDATE issues SET requirement_id = ? WHERE id = ?")
        .bind(r.0)
        .bind(a.issue.0)
        .execute(pool)
        .await
        .unwrap();
    let q = crate::store::work::ask_human(pool, a.agent, None, a.issue, "Which key?", &[])
        .await
        .unwrap();
    let uri = format!("/api/v1/requirements/{}/thread", r.0);
    let thread = fx.ok(&uri).await;
    assert_eq!(thread["to_question_id"], q.id.0);
    let card = &thread["items"][0];
    assert_eq!(card["kind"], "question", "{thread}");
    assert_eq!(card["question"]["asked_by_agent_id"], a.agent.0);
    assert_eq!(card["question"]["issue_key"], "AAA-1");

    let both = json!({"body": "x", "question_id": q.id.0, "to_owner": true});
    assert_eq!(fx.post(&uri, both).await.0, StatusCode::BAD_REQUEST);
    let posted = fx.ok_post(&uri, json!({"body": "The .p8"})).await;
    assert_eq!(posted["woke_agent_id"], a.agent.0);
    assert_eq!(posted["answered"]["state"], "answered");
    let thread = fx.ok(&uri).await;
    assert!(thread.get("to_question_id").is_none() || thread["to_question_id"].is_null());
    assert_eq!(
        thread["items"][0]["question"]["answer"], "The .p8",
        "a receipt"
    );

    let posted = fx.ok_post(&uri, json!({"body": "Status?"})).await;
    assert!(posted["comment_id"].is_i64(), "to the owner: {posted}");
    let thread = fx.ok(&uri).await;
    assert_eq!(thread["items"][1]["kind"], "message");
    assert_eq!(thread["items"][1]["comment"]["body"], "Status?");
}
