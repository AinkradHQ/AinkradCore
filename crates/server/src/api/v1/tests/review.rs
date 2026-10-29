//! API minor 16: an issue's pull requests, the audit log newest first, and a project's
//! knowledge with a human's decision on a proposal; each refused for another company's data.

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_core::gov::KnowledgeKind;
use ainkrad_core::work::{ProjectMode, UserId};
use serde_json::json;

use super::companies::with;
use super::*;
use crate::store::gov::{Proposal, add_knowledge, propose};

#[tokio::test]
async fn an_issues_prs_are_listed_in_repo_order() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}/prs", a.issue.0);
    assert_eq!(fx.ok(&uri).await, json!([]));

    for (name, position) in [("web", 1), ("api", 0)] {
        let repo: i64 = sqlx::query_scalar(
            "INSERT INTO project_repos (project_id, name, url, position) VALUES (?, ?, ?, ?) \
             RETURNING id",
        )
        .bind(a.project.0)
        .bind(name)
        .bind(format!("https://example.test/{name}.git"))
        .bind(position)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO issue_prs (issue_id, repo_id, state, number, title, body, head, base, \
             checks, push_held, unpushed_at, updated_at) VALUES (?, ?, 'open', 7, 'T', 'B', \
             'aaa-1', 'main', 'failure', 'refused', '2026-10-22T09:00:00Z', \
             '2026-10-22T09:30:00.5Z')",
        )
        .bind(a.issue.0)
        .bind(repo)
        .execute(pool)
        .await
        .unwrap();
    }
    let got = fx.ok(&uri).await;
    let repos: Vec<&str> = got
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["repo"].as_str().unwrap())
        .collect();
    assert_eq!(repos, ["api", "web"], "repo order: {got}");
    let pr = &got[0];
    assert_eq!(
        (&pr["state"], &pr["number"], &pr["checks"], &pr["push_held"]),
        (
            &json!("open"),
            &json!(7),
            &json!("failure"),
            &json!("refused")
        )
    );
    assert_eq!(pr["unpushed_at"], "2026-10-22T09:00:00.000Z");
    assert_eq!(pr["updated_at"], "2026-10-22T09:30:00.500Z");

    assert_eq!(
        fx.get("/api/v1/issues/999/prs").await.0,
        StatusCode::NOT_FOUND
    );
    let r = with(b.company, req(Method::GET, &uri, Some(&fx.key), None));
    assert_eq!(send(&fx.app, r).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_audit_log_pages_newest_first_within_the_company() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let mut ours = vec![];
    for (company, action, id) in [
        (a.company, "knowledge.added", 1),
        (b.company, "knowledge.added", 2),
        (a.company, "knowledge_x.made", 3),
        (a.company, "knowledge.accepted", 1),
        (a.company, "issue.state_changed", 9),
    ] {
        let e = NewAuditEvent {
            actor: AuditActor::User(UserId(1)),
            action: action.to_owned(),
            entity: Some(AuditEntity {
                kind: action.split('.').next().unwrap().to_owned(),
                id,
            }),
            company_id: Some(company),
            run_id: None,
            details: json!({"n": id}).to_string(),
        };
        let seq = crate::store::audit::append(pool, &e).await.unwrap().seq.0;
        if company == a.company {
            ours.push(seq);
        }
    }
    ours.reverse();
    let seqs = |v: &Value| -> Vec<i64> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_i64().unwrap())
            .collect()
    };
    let get = |uri: String| {
        let r = with(a.company, req(Method::GET, &uri, Some(&fx.key), None));
        send(&fx.app, r)
    };

    // Paged backwards through A's rows only, B's never among them.
    let mut seen = vec![];
    let mut uri = "/api/v1/audit?limit=2".to_owned();
    loop {
        let (status, page) = get(uri.clone()).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        seen.extend(seqs(&page));
        match page["next_before"].as_i64() {
            Some(before) => uri = format!("/api/v1/audit?limit=2&before={before}"),
            None => break,
        }
    }
    let all: Vec<i64> = seqs(&get("/api/v1/audit".to_owned()).await.1);
    assert!(all.starts_with(&ours), "{all:?} {ours:?}");
    assert_eq!(&seen[..ours.len()], &ours[..], "{seen:?}");
    assert_eq!(seen, all, "pages join up to the whole log");

    // `kind` is a prefix (an `_` in it is no wildcard), `target` a kind and maybe an id.
    let (_, page) = get("/api/v1/audit?kind=knowledge.".to_owned()).await;
    let actions: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["knowledge.accepted", "knowledge.added"]);
    assert_eq!(
        page["items"][0]["actor"],
        json!({"kind": "user", "user_id": 1})
    );
    assert_eq!(page["items"][0]["details"], json!({"n": 1}));
    let (_, page) = get("/api/v1/audit?target=knowledge:1".to_owned()).await;
    assert_eq!(seqs(&page), vec![ours[1], ours[3]]);
    let (_, page) = get("/api/v1/audit?target=issue".to_owned()).await;
    assert!(seqs(&page).starts_with(&[ours[0]]), "{page}");
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["entity_kind"] == "issue")
    );
    let (status, _) = get("/api/v1/audit?target=issue:x".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // `actor` keeps one kind of actor: these rows are all the admin's.
    let (_, users) = get("/api/v1/audit?actor=user&limit=100".to_owned()).await;
    assert!(seqs(&users).starts_with(&ours), "{users}");
    for e in users["items"].as_array().unwrap() {
        assert_eq!(e["actor"]["kind"], "user");
    }
    for none in ["agent", "system"] {
        let (status, page) = get(format!("/api/v1/audit?actor={none}&kind=knowledge.")).await;
        assert_eq!((status, seqs(&page)), (StatusCode::OK, vec![]), "{none}");
    }
    let (status, _) = get("/api/v1/audit?actor=robot".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Without the header the admin sees B's row too.
    let page = fx.ok("/api/v1/audit?kind=knowledge.added").await;
    assert_eq!(page["items"].as_array().unwrap().len(), 2, "{page}");
}

#[tokio::test]
async fn knowledge_is_listed_and_a_human_decides_proposals() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let proposal = |title: &str, body: String| Proposal {
        project: a.project,
        kind: KnowledgeKind::Landmine,
        title: title.to_owned(),
        body,
        spec: false,
        profile_field: None,
        rationale: Some("bit us twice".to_owned()),
    };
    let big = "é".repeat(10 * 1024);
    let one = propose(pool, &proposal("Ports", big.clone()), a.agent)
        .await
        .unwrap()
        .id
        .0;
    let two = propose(pool, &proposal("Docker", "No.".to_owned()), a.agent)
        .await
        .unwrap()
        .id
        .0;
    let old = add_knowledge(
        pool,
        a.project,
        KnowledgeKind::Decision,
        "Tests",
        "Use Pest.",
        UserId(1),
    )
    .await
    .unwrap()
    .id
    .0;
    let list_uri = format!("/api/v1/projects/{}/knowledge", a.project.0);
    let list = fx.ok(&list_uri).await;
    assert_eq!(list.as_array().unwrap().len(), 3, "{list}");
    let first = &list[0];
    assert_eq!(
        (
            &first["status"],
            &first["rationale"],
            &first["proposed_by_agent_id"]
        ),
        (
            &json!("proposed"),
            &json!("bit us twice"),
            &json!(a.agent.0)
        )
    );
    assert_eq!(first["body_truncated"], true, "a 20 KiB body is cut");
    assert!(first["body"].as_str().unwrap().len() <= 16 * 1024);
    assert!(first["created_at"].as_str().unwrap().ends_with('Z'));

    let at = |id: i64, verb: &str| format!("/api/v1/knowledge/{id}/{verb}");
    // Accepted by a human, the whole body comes back.
    let accepted = fx.ok_post(&at(one, "accept"), json!({})).await;
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["body"], big.as_str());
    assert_eq!(accepted["body_truncated"], false);
    // Refusals, as the CLI's: a reasonless rejection is a 400, a decided entry a 409, and so is
    // retiring an entry that was never accepted.
    let (status, got) = fx.post(&at(two, "reject"), json!({"reason": " "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{got}");
    let (status, got) = fx.post(&at(two, "retire"), json!({"reason": "x"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{got}");
    let rejected = fx
        .ok_post(&at(two, "reject"), json!({"reason": "not a landmine"}))
        .await;
    assert_eq!(
        (&rejected["status"], &rejected["reason"]),
        (&json!("rejected"), &json!("not a landmine"))
    );
    let (status, _) = fx.post(&at(one, "accept"), json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = fx.post(&at(999, "accept"), json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let new = fx
        .ok_post(&at(old, "supersede"), json!({"body": "Use Pest 3."}))
        .await;
    let list = fx.ok(&list_uri).await;
    let entry = |id: i64| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|k| k["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(entry(old)["superseded_by"], new["id"]);
    assert_eq!(entry(new["id"].as_i64().unwrap())["supersedes"], old);

    let decided: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action IN ('knowledge.accepted', \
         'knowledge.rejected') AND actor_kind = 'user' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(decided, ["knowledge.accepted", "knowledge.rejected"]);

    // Working in B, A's project and entries are not there.
    let r = with(b.company, req(Method::GET, &list_uri, Some(&fx.key), None));
    assert_eq!(send(&fx.app, r).await.0, StatusCode::NOT_FOUND);
    let r = with(
        b.company,
        req(
            Method::POST,
            &at(one, "reject"),
            Some(&fx.key),
            Some(json!({"reason": "x"})),
        ),
    );
    assert_eq!(send(&fx.app, r).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        fx.get("/api/v1/projects/999/knowledge").await.0,
        StatusCode::NOT_FOUND
    );
}
