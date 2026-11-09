//! API minor 11: a project's permission policy, a company's skills, and retiring and
//! superseding knowledge; each refused for another company's data and audited.

use citadel_core::gov::KnowledgeKind;
use citadel_core::work::{ProjectMode, UserId};
use serde_json::json;

use super::companies::with;
use super::*;
use crate::store::gov::{add_knowledge, project_knowledge};

async fn audited(pool: &SqlitePool, action: &str) -> Vec<Value> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = ? ORDER BY seq")
            .bind(action)
            .fetch_all(pool)
            .await
            .unwrap();
    rows.iter()
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

#[tokio::test]
async fn the_policy_is_replaced_whole_and_audited() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/projects/{}/policy", a.project.0);
    let put = |body: Value| send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), Some(body)));

    assert_eq!(
        fx.ok(&uri).await,
        json!({"mode": "ask", "allow": [], "sandboxed": false})
    );
    let set = json!({"mode": "accept_edits", "allow": ["Bash:npm run", "Bash:composer"]});
    let (status, got) = put(set).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["allow"], json!(["Bash:npm run", "Bash:composer"]));
    assert_eq!(fx.ok(&uri).await, got);
    // The sandboxed mode implies sandboxed runs; a blank entry is refused, nothing changes.
    let (_, got) = put(json!({"mode": "sandboxed"})).await;
    assert_eq!(got["sandboxed"], true);
    let (status, _) = put(json!({"mode": "ask", "allow": [" "]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(fx.ok(&uri).await["mode"], "sandboxed");
    let (status, _) = fx.get("/api/v1/projects/999/policy").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let rows = audited(&fx.app.pool, "project.policy_set").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["allow"], json!(["Bash:npm run", "Bash:composer"]));

    // Working in B, A's policy is not there.
    let r = with(
        b.company,
        req(
            Method::PUT,
            &uri,
            Some(&fx.key),
            Some(json!({"mode": "ask"})),
        ),
    );
    let (status, _) = send(&fx.app, r).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(fx.ok(&uri).await["mode"], "sandboxed", "unchanged");
}

#[tokio::test]
async fn skills_are_published_as_new_versions_within_the_company() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/skills", a.company.0);
    let publish = |body: Value| fx.post(&uri, body);

    let one = json!({"name": "laravel", "body": "# Use Pint", "attach_to": "project",
        "attach_id": a.project.0});
    let (status, v1) = publish(one).await;
    assert_eq!(status, StatusCode::OK, "{v1}");
    assert_eq!(
        (v1["version"].as_i64(), v1["attached_id"].as_i64()),
        (Some(1), Some(a.project.0))
    );
    let two = json!({"name": "laravel", "body": "# Use Pint and Larastan", "attach_to": "role",
        "attach_role": "Developer"});
    let (_, v2) = publish(two).await;
    assert_eq!(
        (v2["version"].as_i64(), v2["attached_role"].as_str()),
        (Some(2), Some("Developer"))
    );
    let list = fx.ok(&uri).await;
    assert_eq!(
        list.as_array().unwrap().len(),
        2,
        "the old version stays: {list}"
    );
    assert_eq!(list[0]["bytes"], 10);

    for bad in [
        json!({"name": "x", "body": "b", "attach_to": "project", "attach_id": b.project.0}),
        json!({"name": "x", "body": "b", "attach_to": "project"}),
        json!({"name": " ", "body": "b", "attach_to": "company"}),
        json!({"name": "x", "body": "b".repeat(64 * 1024 + 1), "attach_to": "company"}),
    ] {
        let (status, got) = publish(bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {got}");
    }
    // skills.max_bytes is a setting.
    let setting = format!("/api/v1/settings/company:{}/skills.max_bytes", a.company.0);
    let (status, got) = send(
        &fx.app,
        req(
            Method::PUT,
            &setting,
            Some(&fx.key),
            Some(json!({"value": 4})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let (status, _) = publish(json!({"name": "x", "body": "12345", "attach_to": "company"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let rows = audited(&fx.app.pool, "skill.published").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let r = with(b.company, req(Method::GET, &uri, Some(&fx.key), None));
    assert_eq!(send(&fx.app, r).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn knowledge_is_retired_or_superseded_and_kept() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let admin = UserId(1);
    let add = |title: &'static str| {
        add_knowledge(
            pool,
            a.project,
            KnowledgeKind::Decision,
            title,
            "Use Pest.",
            admin,
        )
    };
    let old = add("Tests").await.unwrap().id.0;
    let gone = add("Docker").await.unwrap().id.0;

    let (status, got) = fx
        .post(
            &format!("/api/v1/knowledge/{gone}/retire"),
            json!({"reason": "  "}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{got}");
    let retired = fx
        .ok_post(
            &format!("/api/v1/knowledge/{gone}/retire"),
            json!({"reason": "we left Docker"}),
        )
        .await;
    assert_eq!(
        (&retired["status"], &retired["retired_reason"]),
        (&json!("retired"), &json!("we left Docker"))
    );
    let (status, _) = fx
        .post(
            &format!("/api/v1/knowledge/{gone}/retire"),
            json!({"reason": "again"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let new = fx
        .ok_post(
            &format!("/api/v1/knowledge/{old}/supersede"),
            json!({"body": "Use Pest, not PHPUnit."}),
        )
        .await;
    assert_eq!(
        (new["supersedes"].as_i64(), &new["title"]),
        (Some(old), &json!("Tests"))
    );
    let given = project_knowledge(pool, a.project).await.unwrap();
    let ids: Vec<i64> = given.entries.iter().map(|k| k.id.0).collect();
    assert_eq!(
        ids,
        vec![new["id"].as_i64().unwrap()],
        "only the new version is given"
    );
    let kept = crate::store::gov::list_knowledge_entries(pool, a.project)
        .await
        .unwrap();
    assert_eq!(kept.len(), 3, "retired entries stay for history");

    let retired = audited(pool, "knowledge.retired").await;
    assert_eq!(retired.len(), 2, "{retired:?}");
    assert_eq!(retired[1]["superseded_by"], new["id"]);
    let added = audited(pool, "knowledge.added").await;
    assert_eq!(added.last().unwrap()["supersedes"], old);

    // Working in B, A's entries are not there.
    let uri = format!("/api/v1/knowledge/{}/retire", new["id"]);
    let r = with(
        b.company,
        req(
            Method::POST,
            &uri,
            Some(&fx.key),
            Some(json!({"reason": "x"})),
        ),
    );
    let (status, got) = send(&fx.app, r).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{got}");
}
