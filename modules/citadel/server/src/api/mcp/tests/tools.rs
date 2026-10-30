//! Every tool: what it does on the run's own issue, that it never reaches another company's
//! issue, and that each call is audited.

use citadel_core::audit::{AuditActor, AuditFilter};
use citadel_core::gov::{
    ApprovalStatus, KnowledgeKind, KnowledgeStatus, NewKnowledgeEntry, SkillAttach,
};
use citadel_core::work::{IssueState, NextActor, UserId};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::super::args::ToolError;
use super::super::tools::call;
use super::*;
use crate::store::gov::{
    create_knowledge_entry, get_approval, get_knowledge_entry, list_approvals, publish_skill,
};
use crate::store::work::{get_issue, list_blockers, list_comments, list_issues};

fn args(v: Value) -> JsonObject {
    v.as_object().unwrap().clone()
}

async fn ok(fx: &Fx, c: &Company, tool: &str, a: Value) -> Value {
    call(&fx.app, c.scope(), &Default::default(), tool, &args(a))
        .await
        .unwrap_or_else(|e| panic!("{tool}: {e}"))
}

async fn refused(fx: &Fx, c: &Company, tool: &str, a: Value) -> String {
    match call(&fx.app, c.scope(), &Default::default(), tool, &args(a)).await {
        Err(e @ (ToolError::Refused(_) | ToolError::Invalid(_))) => e.to_string(),
        other => panic!("{tool} was not refused: {other:?}"),
    }
}

#[tokio::test]
async fn get_issue_pages_comments_and_lists_blockers_and_subtasks() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    for n in 0..3 {
        ok(&fx, &a, "comment", json!({"body": format!("note {n}")})).await;
    }
    let sub = ok(&fx, &a, "create_subtask", json!({"title": "Part"})).await;
    ok(&fx, &a, "report_blocker", json!({"title": "Need a key"})).await;

    let first = ok(&fx, &a, "get_issue", json!({"limit": 2})).await;
    assert_eq!(first["key"], "AAA-1");
    assert_eq!(first["next_actor"], json!({"agent": a.agent.0}));
    // The default page is the newest: a long thread never hides its latest comments.
    assert_eq!(first["comments"].as_array().unwrap().len(), 2);
    assert_eq!(first["comments"][1]["body"], "note 2");
    assert!(first["next_comments_after"].is_null());
    let before = first["older_comments_before"].as_i64().unwrap();
    let older = ok(&fx, &a, "get_issue", json!({"comments_before": before})).await;
    assert_eq!(older["comments"][0]["body"], "note 0");
    assert!(older["older_comments_before"].is_null());
    // Forward paging from a comment already seen still works.
    let after = older["comments"][0]["id"].as_i64().unwrap();
    let rest = ok(
        &fx,
        &a,
        "get_issue",
        json!({"comments_after": after, "limit": 1}),
    )
    .await;
    assert_eq!(rest["comments"][0]["body"], "note 1");
    assert!(rest["next_comments_after"].as_i64().is_some());
    assert_eq!(first["subtasks"][0]["key"], sub["key"]);
    assert_eq!(first["blockers"][0]["title"], "Need a key");
    // A subtask is reachable too.
    let s = ok(&fx, &a, "get_issue", json!({"issue_id": sub["issue_id"]})).await;
    assert_eq!(s["kind"], "subtask");
    assert!(
        refused(&fx, &a, "get_issue", json!({"limit": 500}))
            .await
            .contains("limit")
    );
}

#[tokio::test]
async fn get_context_gives_accepted_knowledge_and_the_runs_skills() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let project = get_issue(pool, a.issue).await.unwrap().unwrap().project_id;
    for (title, status, by) in [
        ("Use WAL", KnowledgeStatus::Accepted, Some(UserId(1))),
        ("Maybe", KnowledgeStatus::Proposed, None),
    ] {
        let k = NewKnowledgeEntry {
            project_id: project,
            kind: KnowledgeKind::Decision,
            title: title.to_owned(),
            body: "body".to_owned(),
            status,
            proposed_by: None,
            decided_by: by,
        };
        create_knowledge_entry(pool, &k).await.unwrap();
    }
    let attach = SkillAttach::Role("Developer".to_owned());
    let by = AuditActor::User(UserId(1));
    publish_skill(pool, a.company, "rust", "Write Rust.", &attach, by)
        .await
        .unwrap();

    let ctx = ok(&fx, &a, "get_context", json!({})).await;
    assert_eq!(ctx["project"]["key"], "AAA");
    let titles: Vec<&str> = ctx["knowledge"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Use WAL"], "only accepted entries");
    assert_eq!(ctx["skills"][0]["name"], "rust");
    assert_eq!(ctx["skills"][0]["body"], "Write Rust.");
    assert_eq!(ctx["dropped_skills"], json!([]));
}

#[tokio::test]
async fn comment_is_idempotent_per_key_and_written_as_the_agent() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let first = ok(
        &fx,
        &a,
        "comment",
        json!({"body": "x", "idempotency_key": "k1"}),
    )
    .await;
    let again = ok(
        &fx,
        &a,
        "comment",
        json!({"body": "y", "idempotency_key": "k1"}),
    )
    .await;
    assert_eq!(first["comment_id"], again["comment_id"]);
    let comments = list_comments(&fx.app.pool, a.issue).await.unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].run_id, Some(a.run.id));
    assert!(
        refused(&fx, &a, "comment", json!({"body": " "}))
            .await
            .contains("body")
    );
}

#[tokio::test]
async fn transition_follows_the_next_actor_rule() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let start = ok(&fx, &a, "transition", json!({"transition": "start"})).await;
    assert_eq!(start["state"], "in_progress");
    let own = json!({"transition": "submit_for_review", "reviewer_agent_id": a.agent.0});
    assert!(
        refused(&fx, &a, "transition", own)
            .await
            .contains("own issue")
    );
    let review = json!({"transition": "submit_for_review", "reviewer_user_id": 1});
    let moved = ok(&fx, &a, "transition", review).await;
    assert_eq!(moved["state"], "in_review");
    assert_eq!(moved["next_actor"], json!({"user": 1}));
    // It now waits on the reviewer: the agent may not move it.
    let done = json!({"transition": "done"});
    assert!(
        refused(&fx, &a, "transition", done)
            .await
            .contains("next actor")
    );
    let bogus = json!({"transition": "approve"});
    assert!(
        refused(&fx, &a, "transition", bogus)
            .await
            .contains("next actor")
    );

    // A subtask: blocked by a linked blocker, then nothing illegal goes through.
    let sub = ok(&fx, &a, "create_subtask", json!({"title": "Part"})).await;
    let sid = sub["issue_id"].clone();
    let blocker = ok(&fx, &a, "report_blocker", json!({"title": "Dep"})).await;
    let block = json!({"transition": "block", "issue_id": sid,
                       "blocker_issue_id": blocker["blocker_issue_id"]});
    assert_eq!(ok(&fx, &a, "transition", block).await["state"], "blocked");
    let illegal = json!({"transition": "done", "issue_id": sid});
    assert!(
        refused(&fx, &a, "transition", illegal)
            .await
            .contains("cannot done")
    );
    let unknown = json!({"transition": "approve", "issue_id": sid});
    assert!(
        refused(&fx, &a, "transition", unknown)
            .await
            .contains("not one of")
    );
}

#[tokio::test]
async fn create_subtask_and_report_blocker_stay_in_the_runs_project() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let sub = ok(
        &fx,
        &a,
        "create_subtask",
        json!({"title": "Part", "body": "b"}),
    )
    .await;
    let stored = get_issue(
        pool,
        citadel_core::work::IssueId(sub["issue_id"].as_i64().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stored.parent_id, Some(a.issue));
    assert_eq!(stored.next_actor, Some(NextActor::Agent(a.agent)));
    assert_eq!(stored.state, IssueState::Todo);

    let made = ok(
        &fx,
        &a,
        "report_blocker",
        json!({"title": "Key", "assignee_user_id": 1}),
    )
    .await;
    let blocker = made["blocker_issue_id"].as_i64().unwrap();
    assert_eq!(list_blockers(pool, a.issue).await.unwrap()[0].0, blocker);
    // Linking an existing issue of the company; a cycle is refused.
    let other = ok(
        &fx,
        &a,
        "report_blocker",
        json!({"blocker_issue_id": blocker}),
    )
    .await;
    assert_eq!(
        other["blocker_issue_id"], blocker,
        "an existing link is fine"
    );
    let cycle = json!({"blocker_issue_id": a.issue.0, "issue_id": stored.id.0});
    ok(&fx, &a, "report_blocker", cycle).await;
    let back = json!({"blocker_issue_id": stored.id.0});
    assert!(
        refused(&fx, &a, "report_blocker", back)
            .await
            .contains("cycle")
    );
    assert!(
        refused(&fx, &a, "report_blocker", json!({}))
            .await
            .contains("title")
    );
}

#[tokio::test]
async fn request_approval_and_propose_knowledge_start_pending() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let asked = json!({"kind": "pr_merge", "summary": "Merge #3"});
    let approval = ok(&fx, &a, "request_approval", asked).await;
    assert_eq!(approval["status"], "pending");
    let stored = get_approval(
        pool,
        citadel_core::gov::ApprovalId(approval["approval_id"].as_i64().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stored.status, ApprovalStatus::Pending);
    assert_eq!(
        (stored.requested_by, stored.issue_id),
        (a.agent, Some(a.issue))
    );
    let sprint = json!({"kind": "sprint_commit", "summary": "x"});
    assert!(
        refused(&fx, &a, "request_approval", sprint)
            .await
            .contains("kind")
    );

    // The requester reads the decision and its reply; another agent cannot see it.
    let id = json!({"approval_id": stored.id.0});
    let read = ok(&fx, &a, "get_approval", id.clone()).await;
    assert_eq!(
        (read["status"].as_str(), &read["reply"]),
        (Some("pending"), &Value::Null)
    );
    let now = "2026-10-22T10:00:00.000Z";
    let admin = citadel_core::work::UserId(1);
    crate::store::gov::decide_approval(pool, stored.id, true, admin, Some("ship it"), now)
        .await
        .unwrap();
    let read = ok(&fx, &a, "get_approval", id.clone()).await;
    assert_eq!(
        (read["status"].as_str(), read["reply"].as_str()),
        (Some("approved"), Some("ship it"))
    );
    let b = company(pool, "B", "BBB").await;
    assert!(
        refused(&fx, &b, "get_approval", id)
            .await
            .contains("no approval")
    );

    let k = json!({"kind": "landmine", "title": "Flaky", "body": "Retry once."});
    let proposed = ok(&fx, &a, "propose_knowledge", k).await;
    let id = citadel_core::gov::KnowledgeEntryId(proposed["knowledge_entry_id"].as_i64().unwrap());
    let entry = get_knowledge_entry(pool, id).await.unwrap().unwrap();
    assert_eq!(entry.status, KnowledgeStatus::Proposed);
    assert_eq!(entry.proposed_by, Some(a.agent));
}

/// Run A's token, for each tool, against company B's issue: refused, and B is untouched.
#[tokio::test]
async fn no_tool_reaches_another_runs_issue() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let bi = b.issue.0;
    let attempts = [
        ("get_issue", json!({"issue_id": bi})),
        ("comment", json!({"body": "x", "issue_id": bi})),
        ("transition", json!({"transition": "start", "issue_id": bi})),
        ("report_blocker", json!({"title": "x", "issue_id": bi})),
        ("report_blocker", json!({"blocker_issue_id": bi})),
        (
            "transition",
            json!({"transition": "block", "blocker_issue_id": bi}),
        ),
        (
            "request_approval",
            json!({"kind": "pr_merge", "summary": "x", "issue_id": bi}),
        ),
        ("submit", json!({})),
    ];
    for (tool, a_args) in attempts {
        let why = refused(&fx, &a, tool, a_args).await;
        assert!(!why.contains("B work"), "{tool}: {why}");
    }
    // The tools that take no issue act on A's own.
    ok(&fx, &a, "create_subtask", json!({"title": "Mine"})).await;
    ok(
        &fx,
        &a,
        "propose_knowledge",
        json!({"kind": "state", "title": "t", "body": "b"}),
    )
    .await;
    let ctx = ok(&fx, &a, "get_context", json!({})).await;
    assert_eq!(ctx["project"]["key"], "AAA");

    let b_issue = get_issue(pool, b.issue).await.unwrap().unwrap();
    assert_eq!(b_issue.state, IssueState::Todo);
    assert!(list_comments(pool, b.issue).await.unwrap().is_empty());
    assert!(list_blockers(pool, b.issue).await.unwrap().is_empty());
    let b_project = b_issue.project_id;
    assert_eq!(list_issues(pool, b_project).await.unwrap().len(), 1);
    assert!(list_approvals(pool, b.company).await.unwrap().is_empty());

    // Every call was audited as A's agent, refused or not.
    let filter = AuditFilter {
        run_id: Some(a.run.id),
        ..AuditFilter::default()
    };
    let calls: Vec<_> = audit::list(pool, &filter, None, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.action.starts_with("mcp."))
        .collect();
    assert_eq!(calls.len(), 11);
    assert!(calls.iter().all(|e| e.actor == AuditActor::Agent(a.agent)));
    assert_eq!(calls[7].action, "mcp.unknown_tool");
    assert_eq!(
        calls
            .iter()
            .filter(|e| e.details.contains("\"ok\":false"))
            .count(),
        8
    );
}

/// `list_backlog` is for the project's product owner or team lead, or the CEO or CTO: anyone
/// else, or a project of another company, is refused.
#[tokio::test]
async fn list_backlog_is_for_leads_and_executives_only() {
    use crate::store::org::update_agent;
    use crate::store::org::{create_department, create_membership, create_team, get_agent};
    use crate::store::work::{get_project, update_project};
    use citadel_core::org::{OrgRole, TeamMembership, TeamRole};

    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let project = get_issue(pool, a.issue).await.unwrap().unwrap().project_id;
    let why = refused(&fx, &a, "list_backlog", json!({})).await;
    assert!(why.contains("product owner"), "{why}");

    let dept = create_department(pool, a.company, "Eng").await.unwrap();
    let team = create_team(pool, dept.id, "Core").await.unwrap();
    let mut p = get_project(pool, project).await.unwrap().unwrap();
    p.team_id = Some(team.id);
    assert!(update_project(pool, &p).await.unwrap());
    let po = TeamMembership {
        team_id: team.id,
        agent_id: a.agent,
        team_role: TeamRole::ProductOwner,
    };
    create_membership(pool, &po).await.unwrap();
    let page = ok(&fx, &a, "list_backlog", json!({"limit": 1})).await;
    assert_eq!(page["issues"][0]["key"], "AAA-1");
    assert_eq!(page["issues"][0]["state"], "todo");
    assert_eq!(page["next_offset"], 1);
    let none = ok(&fx, &a, "list_backlog", json!({"state": "backlog"})).await;
    assert_eq!(none["issues"], json!([]));
    assert!(none["next_offset"].is_null());
    let bad = refused(&fx, &a, "list_backlog", json!({"kind": "epic"})).await;
    assert!(bad.contains("unknown kind"), "{bad}");

    // Another company's project looks like none at all.
    let foreign = get_issue(pool, b.issue).await.unwrap().unwrap().project_id;
    let why = refused(&fx, &a, "list_backlog", json!({"project_id": foreign.0})).await;
    assert!(why.contains("no project"), "{why}");
    let why = refused(&fx, &b, "list_backlog", json!({"project_id": project.0})).await;
    assert!(why.contains("no project"), "{why}");

    // B's agent as B's CTO reads B's backlog with no team at all.
    let mut cto = get_agent(pool, b.agent).await.unwrap().unwrap();
    cto.org_role = OrgRole::Cto;
    assert!(update_agent(pool, &cto).await.unwrap());
    let page = ok(&fx, &b, "list_backlog", json!({})).await;
    assert_eq!(page["issues"][0]["key"], "BBB-1");
}

#[tokio::test]
async fn get_issue_warns_when_the_repo_is_implicit() {
    use crate::store::work::{Commands, Repo, add_repo, set_issue_repos};
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "WRN").await;
    let project = get_issue(&fx.app.pool, a.issue)
        .await
        .unwrap()
        .unwrap()
        .project_id;
    let by = AuditActor::User(UserId(1));
    for name in ["core", "app"] {
        let r = Repo {
            id: 0,
            project_id: project,
            name: name.to_owned(),
            url: format!("https://example.test/{name}.git"),
            default_branch: "main".to_owned(),
            position: 0,
            primary: false,
            forge: None,
            commands: Commands::default(),
        };
        add_repo(&fx.app.pool, &r, by).await.unwrap().unwrap();
    }
    let got = ok(&fx, &a, "get_issue", json!({})).await;
    let w = got["warning"].as_str().unwrap();
    assert!(w.contains("primary repo core"), "{w}");
    set_issue_repos(&fx.app.pool, a.issue, &["app".to_owned()], by)
        .await
        .unwrap();
    assert!(
        ok(&fx, &a, "get_issue", json!({}))
            .await
            .get("warning")
            .is_none()
    );
}
