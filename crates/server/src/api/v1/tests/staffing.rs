//! Staffing and planning from the app (API minor 7): the Engineering template and a proposed
//! agent are hires that wait on approval (#43); a project is created; an agent's profile proposal
//! is decided by a person (#48) and shows in the profile's history; a requirement is renamed,
//! cancelled and given attachments. Each refuses another company's data and is audited.

use ainkrad_core::gov::KnowledgeKind;
use serde_json::json;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;
use ainkrad_core::settings::{Key, Scope};

use crate::store::gov::{Proposal, propose};
use crate::store::{org, settings};

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

fn raw(uri: &str, key: &str, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

#[tokio::test]
async fn the_template_and_a_proposed_agent_wait_on_their_hires() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let c = a.company.0;
    let applied = fx
        .ok_post(
            &format!("/api/v1/companies/{c}/templates/engineering"),
            json!({}),
        )
        .await;
    let agents = applied["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 7, "{applied}");
    assert!(agents.iter().all(|a| a["status"] == "pending_approval"));
    assert_eq!(applied["hire_approval_ids"].as_array().unwrap().len(), 7);
    let again = fx
        .ok_post(
            &format!("/api/v1/companies/{c}/templates/engineering"),
            json!({}),
        )
        .await;
    assert_eq!(
        again["hire_approval_ids"],
        json!([]),
        "a re-apply adds nothing"
    );
    let (status, _) = fx
        .post(&format!("/api/v1/companies/{c}/templates/sales"), json!({}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let proposal = json!({"name": "Designer", "role": "Designer", "harness": "claude",
                          "model": "sonnet", "reports_to": a.agent.0,
                          "justification": "We need screens"});
    let proposed = fx
        .ok_post(&format!("/api/v1/companies/{c}/agents"), proposal.clone())
        .await;
    assert_eq!(
        proposed["agent"]["status"], "pending_approval",
        "{proposed}"
    );
    let approval = proposed["hire_approval_id"].as_i64().unwrap();
    let decided = fx
        .ok_post(
            &format!("/api/v1/approvals/{approval}/decision"),
            json!({"approve": true}),
        )
        .await;
    assert_eq!(decided["status"], "approved", "{decided}");
    let agent = fx
        .ok(&format!("/api/v1/agents/{}", proposed["agent"]["id"]))
        .await;
    assert_eq!(agent["status"], "active", "approving hires it");
    assert_eq!(audited(&fx, "agent.hire_requested").await, 8);

    // Another company's manager, a blank justification, another company's path.
    let mut theirs = proposal.clone();
    theirs["name"] = json!("Other");
    theirs["reports_to"] = json!(b.agent.0);
    let uri = format!("/api/v1/companies/{c}/agents");
    assert_eq!(fx.post(&uri, theirs).await.0, StatusCode::NOT_FOUND);
    let mut blank = proposal.clone();
    blank["name"] = json!("Blank");
    blank["justification"] = json!(" ");
    assert_eq!(fx.post(&uri, blank).await.0, StatusCode::BAD_REQUEST);
    for uri in [
        format!("/api/v1/companies/{}/agents", b.company.0),
        format!("/api/v1/companies/{}/templates/engineering", b.company.0),
    ] {
        let r = req(Method::POST, &uri, Some(&fx.key), Some(proposal.clone()));
        let (status, _) = send(&fx.app, with(a.company, r)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn a_project_is_created_with_a_checked_key() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let uri = format!("/api/v1/companies/{}/projects", a.company.0);
    let p = fx
        .ok_post(
            &uri,
            json!({"name": "Mobile", "key": "MOB", "mode": "scrum"}),
        )
        .await;
    assert_eq!(
        (p["key"].clone(), p["mode"].clone()),
        (json!("MOB"), json!("scrum"))
    );
    assert_eq!(audited(&fx, "project.created").await, 1);
    for (body, want) in [
        (json!({"name": "Again", "key": "MOB"}), StatusCode::CONFLICT),
        (json!({"name": "Bad", "key": "mob-1"}), StatusCode::CONFLICT),
        (json!({"name": " ", "key": "NEW"}), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(fx.post(&uri, body.clone()).await.0, want, "{body}");
    }
    // A team of company B, and company B's projects while working in A.
    let by = AuditActor::User(super::super::ADMIN);
    let dept = org::add_department(&fx.app.pool, b.company, "Eng", by)
        .await
        .unwrap();
    let team = org::add_team(&fx.app.pool, dept.id, "T", by)
        .await
        .unwrap()
        .id
        .0;
    let body = json!({"name": "X", "key": "XX", "team_id": team});
    assert_eq!(fx.post(&uri, body).await.0, StatusCode::NOT_FOUND);
    let theirs = format!("/api/v1/companies/{}/projects", b.company.0);
    let r = req(
        Method::POST,
        &theirs,
        Some(&fx.key),
        Some(json!({"name": "Y", "key": "YY"})),
    );
    assert_eq!(
        send(&fx.app, with(a.company, r)).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_person_decides_profile_proposals_and_the_history_shows_them() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let proposal = |project, title: &str, field: Option<&str>| Proposal {
        project,
        kind: KnowledgeKind::Decision,
        title: title.to_owned(),
        body: "Squash nothing.".to_owned(),
        spec: false,
        profile_field: field.map(str::to_owned),
        rationale: Some("history matters".to_owned()),
    };
    let pool = &fx.app.pool;
    let conv = propose(
        pool,
        &proposal(a.project, "C", Some("conventions")),
        a.agent,
    )
    .await
    .unwrap()
    .id
    .0;
    let stack = propose(pool, &proposal(a.project, "S", Some("stack")), a.agent)
        .await
        .unwrap()
        .id
        .0;
    let plain = propose(pool, &proposal(a.project, "P", None), a.agent)
        .await
        .unwrap()
        .id
        .0;
    let theirs = propose(pool, &proposal(b.project, "B", Some("stack")), b.agent)
        .await
        .unwrap()
        .id
        .0;
    let p = a.project.0;
    let got = fx.ok(&format!("/api/v1/projects/{p}/profile")).await;
    assert_eq!(got["proposals"][0]["rationale"], "history matters", "{got}");

    let decide = |id: i64| format!("/api/v1/projects/{p}/profile/proposals/{id}/decision");
    let accepted = fx.ok_post(&decide(conv), json!({"accept": true})).await;
    assert_eq!(accepted["profile"]["conventions"], "Squash nothing.");
    assert_eq!(accepted["proposals"].as_array().unwrap().len(), 1);
    let (status, _) = fx.post(&decide(stack), json!({"accept": false})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a rejection needs a reason"
    );
    fx.ok_post(&decide(stack), json!({"accept": false, "reason": "no"}))
        .await;
    for (id, want) in [
        (conv, StatusCode::CONFLICT),
        (plain, StatusCode::NOT_FOUND),
        (theirs, StatusCode::NOT_FOUND),
    ] {
        let (status, _) = fx.post(&decide(id), json!({"accept": true})).await;
        assert_eq!(status, want, "entry {id}");
    }

    let history = fx
        .ok(&format!("/api/v1/projects/{p}/profile/history"))
        .await;
    let actions: Vec<&str> = history
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        [
            "knowledge.rejected",
            "project.profile_set",
            "knowledge.accepted",
            "knowledge.proposed",
            "knowledge.proposed"
        ],
        "{history}"
    );
    let set = &history[1];
    assert_eq!(set["details"]["values"]["conventions"], "Squash nothing.");
    assert_eq!(set["actor"], json!({"kind": "user", "user_id": 1}));
    assert_eq!(history[4]["details"]["rationale"], "history matters");
    let next = history[1]["seq"].as_i64().unwrap();
    let page = fx
        .ok(&format!(
            "/api/v1/projects/{p}/profile/history?after={next}&limit=1"
        ))
        .await;
    assert_eq!(page[0]["action"], "knowledge.accepted");

    let uri = format!("/api/v1/projects/{}/profile/history", b.project.0);
    let r = req(Method::GET, &uri, Some(&fx.key), None);
    assert_eq!(
        send(&fx.app, with(a.company, r)).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_requirement_is_renamed_cancelled_and_given_attachments() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let ask = |c: CompanyId| format!("/api/v1/companies/{}/requests", c.0);
    let body = json!({"title": "Phone alerts"});
    let r = fx.ok_post(&ask(a.company), body.clone()).await["requirement_id"]
        .as_i64()
        .unwrap();
    let rb = fx.ok_post(&ask(b.company), body).await["requirement_id"]
        .as_i64()
        .unwrap();
    let uri = format!("/api/v1/requirements/{r}");
    let (status, renamed) = send(
        &fx.app,
        req(
            Method::PUT,
            &uri,
            Some(&fx.key),
            Some(json!({"title": " Push alerts "})),
        ),
    )
    .await;
    assert_eq!(
        (status, renamed["title"].clone()),
        (StatusCode::OK, json!("Push alerts"))
    );
    let (status, _) = send(
        &fx.app,
        req(Method::PUT, &uri, Some(&fx.key), Some(json!({"title": ""}))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(audited(&fx, "requirement.renamed").await, 1);

    // Attachments: in the thread, redacted; refused by type, size and company.
    let attach = |name: &str| format!("/api/v1/requirements/{r}/attachments/{name}");
    let secret = b"key: ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n";
    let (status, art) = send(&fx.app, raw(&attach("notes.txt"), &fx.key, secret)).await;
    assert_eq!(status, StatusCode::OK, "{art}");
    assert_eq!(art["requirement_id"], r);
    let thread = fx.ok(&format!("/api/v1/requirements/{r}/thread")).await;
    assert!(thread.to_string().contains("notes.txt"), "{thread}");
    let event: (String, Option<i64>) = sqlx::query_as(
        "SELECT actor_kind, actor_id FROM audit_events WHERE action = 'artifact.published'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(event, ("user".to_owned(), Some(1)));
    let (status, _) = send(&fx.app, raw(&attach("tool.exe"), &fx.key, b"MZ")).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (key, at) = (Key::ArtifactMaxFileBytes, Scope::Company(a.company));
    let by = AuditActor::User(super::super::ADMIN);
    settings::set(&fx.app.pool, key, at, "1000", by, NOW)
        .await
        .unwrap();
    let big = vec![b'x'; 5000];
    let (status, _) = send(&fx.app, raw(&attach("big.txt"), &fx.key, &big)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        audited(&fx, "artifact.refused").await,
        2,
        "each refusal is audited"
    );
    let theirs = format!("/api/v1/requirements/{rb}/attachments/x.txt");
    let (status, _) = send(&fx.app, with(a.company, raw(&theirs, &fx.key, b"x"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Cancel: refused while a run works on one of its issues, then its open issues go with it.
    sqlx::query("UPDATE issues SET requirement_id = ? WHERE id = ?")
        .bind(r)
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let cancel = format!("/api/v1/requirements/{r}/cancel");
    let (status, _) = fx.post(&cancel, json!({"reason": "dropped"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "a run works on it");
    sqlx::query("UPDATE runs SET state = 'succeeded', terminal_reason = 'test' WHERE id = ?")
        .bind(a.run.id.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let done = fx.ok_post(&cancel, json!({"reason": "dropped"})).await;
    assert_eq!(done["state"], "cancelled");
    let issue = fx.ok(&format!("/api/v1/issues/{}", a.issue.0)).await;
    assert_eq!(issue["state"], "cancelled");
    assert_eq!(fx.post(&cancel, json!({})).await.0, StatusCode::CONFLICT);
    let (status, _) = send(
        &fx.app,
        req(
            Method::PUT,
            &uri,
            Some(&fx.key),
            Some(json!({"title": "Again"})),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a cancelled requirement keeps its name"
    );
    assert_eq!(audited(&fx, "requirement.cancelled").await, 1);

    let theirs = format!("/api/v1/requirements/{rb}/cancel");
    let r = req(Method::POST, &theirs, Some(&fx.key), Some(json!({})));
    assert_eq!(
        send(&fx.app, with(a.company, r)).await.0,
        StatusCode::NOT_FOUND
    );
}
