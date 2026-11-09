//! Skills, knowledge and artifacts through the Core's client gate (ported from the monolith's
//! `api/v1/tests/{library,artifacts}.rs`). Left as `#[ignore]`d stubs, each with its blocker:
//! the project permission policy (S4's routes) and the artifact file serving (the Core gives the
//! module no artifacts directory).
//!
//! Adapted: `skills.max_bytes` is set server-wide through the module's settings (the monolith set
//! it for one company); the artifacts are stored under a temp dir of their own.

mod common;
mod gov_seed;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::UserId as CoreUserId;
use ainkrad_proto::redact::Redactor;
use axum::http::{Method, StatusCode};
use citadel_module::domain::gov::{ArtifactKind, KnowledgeKind};
use citadel_module::domain::work::{RunId, UserId};
use citadel_module::store::artifacts::{NewArtifact, publish_artifact};
use citadel_module::store::gov::{add_knowledge, list_knowledge_entries, project_knowledge};
use common::*;
use gov_seed::*;
use serde_json::{Value, json};

async fn post(fx: &Fx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::POST, uri, Some(body)).await
}

async fn get(fx: &Fx, uri: &str) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::GET, uri, None).await
}

#[tokio::test]
#[ignore = "S4: GET/PUT /projects/{id}/policy are the project's routes (store::work policy)"]
async fn the_policy_is_replaced_whole_and_audited() {
    todo!("monolith api/v1/tests/library.rs")
}

#[tokio::test]
async fn skills_are_published_as_new_versions_within_the_company() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA").await;
    let b = seed(&fx.app.pool, "B", "BBB").await;
    let uri = format!("/companies/{}/skills", a.company.0);

    let one = json!({"name": "laravel", "body": "# Use Pint", "attach_to": "project",
        "attach_id": a.project.0});
    let (status, v1) = post(&fx, &uri, one).await;
    assert_eq!(status, StatusCode::OK, "{v1}");
    assert_eq!(
        (v1["version"].as_i64(), v1["attached_id"].as_i64()),
        (Some(1), Some(a.project.0))
    );
    let two = json!({"name": "laravel", "body": "# Use Pint and Larastan", "attach_to": "role",
        "attach_role": "Developer"});
    let (_, v2) = post(&fx, &uri, two).await;
    assert_eq!(
        (v2["version"].as_i64(), v2["attached_role"].as_str()),
        (Some(2), Some("Developer"))
    );
    let (_, list) = get(&fx, &uri).await;
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
        let (status, got) = post(&fx, &uri, bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {got}");
    }
    // skills.max_bytes is a setting (server-wide here).
    let by = AuditActor::User(CoreUserId(1));
    citadel_module::settings::handle()
        .set(&fx.app.pool, "skills.max_bytes", "4", by, NOW)
        .await
        .unwrap();
    let (status, _) = post(
        &fx,
        &uri,
        json!({"name": "x", "body": "12345", "attach_to": "company"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let rows = audited(&fx.app.pool, "skill.published").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let in_b = Some(b.company.0.to_string());
    let (status, _) = call_in(&fx, Some(&fx.dev), in_b.as_deref(), Method::GET, &uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn knowledge_is_retired_or_superseded_and_kept() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA").await;
    let b = seed(pool, "B", "BBB").await;
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

    let (status, got) = post(
        &fx,
        &format!("/knowledge/{gone}/retire"),
        json!({"reason": "  "}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{got}");
    let (status, retired) = post(
        &fx,
        &format!("/knowledge/{gone}/retire"),
        json!({"reason": "we left Docker"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{retired}");
    assert_eq!(
        (&retired["status"], &retired["retired_reason"]),
        (&json!("retired"), &json!("we left Docker"))
    );
    let (status, _) = post(
        &fx,
        &format!("/knowledge/{gone}/retire"),
        json!({"reason": "again"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, new) = post(
        &fx,
        &format!("/knowledge/{old}/supersede"),
        json!({"body": "Use Pest, not PHPUnit."}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{new}");
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
    let kept = list_knowledge_entries(pool, a.project).await.unwrap();
    assert_eq!(kept.len(), 3, "retired entries stay for history");
    let (status, listed) = get(&fx, &format!("/projects/{}/knowledge", a.project.0)).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed.as_array().unwrap().len(), 3);
    assert_eq!(listed[0]["superseded_by"], new["id"]);
    let (status, _) = post(
        &fx,
        &format!("/knowledge/{old}/supersede"),
        json!({"body": "x", "kind": "poem"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a bad kind is a 400");

    let retired = audited(pool, "knowledge.retired").await;
    assert_eq!(retired.len(), 2, "{retired:?}");
    assert_eq!(retired[1]["superseded_by"], new["id"]);
    let added = audited(pool, "knowledge.added").await;
    assert_eq!(added.last().unwrap()["supersedes"], old);

    // Working in B, A's entries are not there.
    let uri = format!("/knowledge/{}/retire", new["id"]);
    let in_b = Some(b.company.0.to_string());
    let (status, got) = call_in(
        &fx,
        Some(&fx.dev),
        in_b.as_deref(),
        Method::POST,
        &uri,
        Some(json!({"reason": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{got}");
}

async fn publish(fx: &Fx, s: &Seed, name: &str, kind: ArtifactKind, bytes: &[u8]) -> i64 {
    let new = NewArtifact {
        company: s.company,
        issue: Some(s.issue),
        requirement: None,
        run: Some(RunId(7)),
        agent: Some(s.agent),
        name: name.to_owned(),
        kind,
        user: None,
    };
    publish_artifact(
        &fx.app.pool,
        &fx.dir.join("artifacts"),
        &new,
        bytes,
        &Redactor::new(),
    )
    .await
    .unwrap()
    .id
    .0
}

#[tokio::test]
async fn artifacts_are_listed_and_kept_to_their_company() {
    let fx = fx().await;
    let pool = fx.app.pool.clone();
    let a = seed(&pool, "A", "AAA").await;
    let b = seed(&pool, "B", "BBB").await;
    let html = b"<script>alert(1)</script>";
    let page = publish(&fx, &a, "page.html", ArtifactKind::Report, html).await;
    let md = publish(&fx, &a, "qa.md", ArtifactKind::Report, b"# QA\npass").await;
    let png = publish(&fx, &a, "shot.png", ArtifactKind::Screenshot, b"\x89PNG..").await;
    let theirs = publish(&fx, &b, "theirs.md", ArtifactKind::Report, b"secret").await;

    let in_a = Some(a.company.0.to_string());
    let list = |uri: String| {
        let (fx, in_a) = (&fx, in_a.clone());
        async move { call_in(fx, Some(&fx.dev), in_a.as_deref(), Method::GET, &uri, None).await }
    };
    let (_, mine) = list("/artifacts".to_owned()).await;
    let ids: Vec<i64> = mine["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [png, md, page], "A's, newest first");
    let (_, reports) = list("/artifacts?kind=report&limit=1".to_owned()).await;
    assert_eq!(reports["items"][0]["id"], md);
    assert_eq!(reports["next_after"], md);
    let by_agent = format!("/artifacts?agent={}&issue={}", a.agent.0, a.issue.0);
    assert_eq!(list(by_agent).await.1["items"].as_array().unwrap().len(), 3);
    let (_, one) = get(&fx, &format!("/artifacts/{png}")).await;
    assert_eq!(
        (one["preview"].as_str(), one["run_id"].as_i64()),
        (Some("image"), Some(7))
    );

    // Another company's: not there.
    let (status, _) = list(format!("/artifacts/{theirs}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, usage) = get(&fx, &format!("/companies/{}/artifact-usage", a.company.0)).await;
    assert_eq!(usage["used_bytes"], (html.len() + 9 + 6) as i64);
    assert_eq!(usage["quota_bytes"], 2_000_000_000_i64);
}
