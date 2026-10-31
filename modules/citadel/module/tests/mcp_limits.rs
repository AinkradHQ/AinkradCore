//! Limits of the MCP tools (S8 remainder): the call and creation caps (also under parallel
//! calls), redaction of everything the tools write, the empty-done check and the bounds and
//! checks of plans. Over HTTP through the real router, with Citadel mounted.

mod common;
mod mcp_harness;
mod work_seed;

use ainkrad_core::audit::AuditActor;
use axum::http::StatusCode;
use citadel_module::domain::exec::RunEvent;
use citadel_module::domain::org::CompanyId;
use citadel_module::domain::work::ProjectId;
use citadel_module::store::exec as engine;
use citadel_module::store::work;
use futures_util::future::join_all;
use mcp_harness::*;
use serde_json::{Value, json};

#[tokio::test]
async fn every_new_tool_counts_against_the_cap_is_off_when_mcp_is_off_and_dies_with_the_run() {
    let (w, a, ta, _, _) = two().await;
    let app = &w.fx.app;
    set(app, "mcp.max_calls_per_run", "3").await;
    for _ in 0..3 {
        ok(&w, &ta, "org_chart", json!({})).await;
    }
    for name in [
        "org_chart",
        "ask_human",
        "publish_artifact",
        "propose_knowledge",
        "list_backlog",
    ] {
        let why = refused(&w, &ta, name, json!({"question": "q"})).await;
        assert!(why.contains("tool calls"), "{name}: {why}");
    }
    set(app, "mcp.max_calls_per_run", "2000").await;
    // Audited once per call, by name.
    assert_eq!(
        count(
            app,
            "SELECT count(*) FROM audit_events WHERE action = 'citadel.mcp.org_chart'"
        )
        .await,
        4 - 1 + 1 // three answered, one refused by the cap before the tool ran
    );
    // MCP off: every token, every tool, the same 401.
    set(app, "mcp.enabled", "0").await;
    for name in ["ask_human", "publish_artifact", "plan_sprint"] {
        let (status, _) = rpc(app, Some(&ta), tool(name, json!({}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
    }
    set(app, "mcp.enabled", "1").await;
    // The run ends: its token stops working for the new tools too.
    let cancel = RunEvent::Cancel {
        reason: "stopped".into(),
    };
    engine::transition_run(
        &app.pool,
        a.run.id,
        AuditActor::System,
        &cancel,
        &app.clock.now(),
    )
    .await
    .unwrap();
    let (status, _) = rpc(app, Some(&ta), tool("ask_human", json!({"question": "q"}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        count(app, "SELECT count(*) FROM citadel_questions").await,
        0
    );
}

#[tokio::test]
async fn done_needs_a_real_result_on_this_issue() {
    let (w, a, ta, _, _) = two().await;
    ok(&w, &ta, "transition", json!({"transition": "start"})).await;
    // A short comment, a question to a human, and a long comment on another issue do not count.
    ok(&w, &ta, "comment", json!({"body": "ok"})).await;
    sqlx::query(
        "INSERT INTO citadel_comments (issue_id, author_agent_id, body, run_id, idempotency_key) \
         VALUES (?, ?, ?, ?, 'question:99')",
    )
    .bind(a.seed.issue)
    .bind(a.seed.agent)
    .bind("q".repeat(200))
    .bind(a.run.id.0)
    .execute(app_pool(&w))
    .await
    .unwrap();
    let sub = ok(&w, &ta, "create_subtask", json!({"title": "side"})).await["issue_id"].clone();
    ok(
        &w,
        &ta,
        "comment",
        json!({"issue_id": sub, "body": "x".repeat(200)}),
    )
    .await;
    let why = refused(&w, &ta, "transition", json!({"transition": "done"})).await;
    assert!(why.contains("nothing shows"), "{why}");
}

/// A `cit_run_` token shape an agent might paste into anything it writes.
fn planted() -> String {
    format!("cit_run_{}", "ab12".repeat(16))
}

#[tokio::test]
async fn a_secret_shape_is_redacted_from_everything_every_tool_writes() {
    let (w, a, ta, _, _) = two().await;
    let app = &w.fx.app;
    make_ceo(&w, &a).await;
    sqlx::query("UPDATE citadel_projects SET mode = 'scrum'")
        .execute(app_pool(&w))
        .await
        .unwrap();
    let p = planted();
    let t = format!("leak {p} end");
    ok(&w, &ta, "comment", json!({"body": t})).await;
    ok(&w, &ta, "ask_human", json!({"question": t, "options": [t]})).await;
    ok(
        &w,
        &ta,
        "propose_knowledge",
        json!({"kind": "decision", "title": t, "body": t}),
    )
    .await;
    ok(&w, &ta, "create_subtask", json!({"title": t, "body": t})).await;
    ok(
        &w,
        &ta,
        "request_approval",
        json!({"kind": "pr_merge", "summary": t, "details": t}),
    )
    .await;
    ok(
        &w,
        &ta,
        "plan_sprint",
        json!({"name": t, "goal": t, "starts_on": "2030-01-01", "ends_on": "2030-01-14"}),
    )
    .await;
    let art = ok(
        &w,
        &ta,
        "publish_artifact",
        json!({"name": "n.md", "content": b64(t.as_bytes())}),
    )
    .await;
    assert_eq!(art["redactions"], 1, "{art}");
    let got = ok(
        &w,
        &ta,
        "get_artifact",
        json!({"artifact_id": art["artifact_id"]}),
    )
    .await;
    assert!(!got["content"].as_str().unwrap().contains(&p), "{got}");
    for (table, col) in [
        ("citadel_comments", "body"),
        ("citadel_questions", "question || options"),
        ("citadel_knowledge_entries", "title || body"),
        ("citadel_issues", "title || body"),
        ("citadel_approvals", "payload"),
        ("citadel_sprints", "name || goal"),
        ("audit_events", "details"),
    ] {
        let hits = count(
            app,
            &format!("SELECT count(*) FROM {table} WHERE instr({col}, '{p}') > 0"),
        )
        .await;
        assert_eq!(hits, 0, "{table} holds the secret shape");
    }
    assert!(
        count(
            app,
            "SELECT count(*) FROM citadel_comments WHERE body LIKE 'leak %'"
        )
        .await
            >= 1
    );
}

#[tokio::test]
async fn creation_is_capped_per_run_and_under_parallel_calls() {
    let (w, _, ta, _, tb) = two().await;
    let app = &w.fx.app;
    // Subtasks (issues), comments, approvals and knowledge each stop at their cap.
    for (setting, tool_name, args) in [
        (
            "mcp.max_issues_per_run",
            "create_subtask",
            json!({"title": "t"}),
        ),
        ("mcp.max_comments_per_run", "comment", json!({"body": "c"})),
        (
            "mcp.max_approvals_per_run",
            "request_approval",
            json!({"kind": "pr_merge", "summary": "s"}),
        ),
        (
            "mcp.max_knowledge_per_run",
            "propose_knowledge",
            json!({"kind": "decision", "title": "t", "body": "b"}),
        ),
    ] {
        set(app, setting, "2").await;
        ok(&w, &ta, tool_name, args.clone()).await;
        ok(&w, &ta, tool_name, args.clone()).await;
        let why = refused(&w, &ta, tool_name, args.clone()).await;
        assert!(why.contains(setting), "{tool_name}: {why}");
        // Another run has its own count.
        ok(&w, &tb, tool_name, args).await;
    }
    // Parallel calls cannot overshoot.
    set(app, "mcp.max_questions_per_run", "2").await;
    let calls: Vec<_> = (0..8)
        .map(|n| invoke(&w, &ta, "ask_human", json!({"question": format!("q{n}")})))
        .collect();
    let done = join_all(calls).await;
    assert_eq!(
        done.iter().filter(|(failed, _)| !failed).count(),
        2,
        "{done:?}"
    );
    set(app, "mcp.max_artifacts_per_run", "3").await;
    let calls: Vec<_> = (0..8u8)
        .map(|n| {
            let args = json!({"name": format!("f{n}.md"), "content": b64(&[b'a' + n])});
            invoke(&w, &ta, "publish_artifact", args)
        })
        .collect();
    let done = join_all(calls).await;
    assert_eq!(
        done.iter().filter(|(failed, _)| !failed).count(),
        3,
        "{done:?}"
    );
}

#[tokio::test]
async fn plans_are_bounded_checked_per_project_and_cannot_approve_themselves_or_grant_repos() {
    let (w, a, ta, b, _) = two().await;
    let app = &w.fx.app;
    let intake = work::submit_intake(
        app_pool(&w),
        CompanyId(a.seed.company),
        "A goal",
        "a",
        AuditActor::System,
    )
    .await
    .unwrap();
    let req = intake.requirement_id.unwrap().0;
    make_ceo(&w, &a).await;
    let epic = |n: usize, project: i64, tasks: usize| {
        json!({"title": format!("e{n}"), "project_id": project,
               "tasks": (0..tasks).map(|t| json!({"title": format!("t{t}")})).collect::<Vec<_>>()})
    };
    // One call cannot file more than 100 epics and tasks, even within the list limits.
    let big: Vec<Value> = (0..40).map(|n| epic(n, a.seed.project, 3)).collect();
    let why = refused(
        &w,
        &ta,
        "plan_requirement",
        json!({"requirement_id": req, "epics": big.clone()}),
    )
    .await;
    assert!(why.contains("at most 100"), "{why}");
    let why = refused(
        &w,
        &ta,
        "apply_plan",
        json!({"requirement_id": req, "epics": big}),
    )
    .await;
    assert!(why.contains("at most 100"), "{why}");
    // The run's creation cap bounds the sum of its calls.
    set(app, "mcp.max_issues_per_run", "3").await;
    let why = refused(
        &w,
        &ta,
        "plan_requirement",
        json!({"requirement_id": req, "epics": [epic(1, a.seed.project, 3)]}),
    )
    .await;
    assert!(why.contains("max_issues_per_run"), "{why}");
    set(app, "mcp.max_issues_per_run", "50").await;
    // An epic in another company's project: the planning check applies here too.
    let why = refused(
        &w,
        &ta,
        "plan_requirement",
        json!({"requirement_id": req, "epics": [epic(1, b.seed.project, 0)]}),
    )
    .await;
    assert!(why.contains("in this company"), "{why}");
    // A plan cannot name repos, and a foreign sprint looks like none.
    let why = refused(
        &w,
        &ta,
        "apply_plan",
        json!({"requirement_id": req, "epics": [{"title": "e", "project_id": a.seed.project,
               "tasks": [{"title": "t", "repos": ["core"]}]}]}),
    )
    .await;
    assert!(why.contains("cannot name repos"), "{why}");
    let sprint = work::create_sprint(
        &app.pool,
        &citadel_module::domain::work::NewSprint {
            project_id: ProjectId(b.seed.project),
            name: "b".into(),
            goal: String::new(),
            state: citadel_module::domain::work::SprintState::Planned,
            starts_on: Some("2030-01-01".into()),
            ends_on: Some("2030-01-14".into()),
        },
    )
    .await
    .unwrap();
    let why = refused(
        &w,
        &ta,
        "apply_plan",
        json!({"requirement_id": req, "epics": [], "sprint": {"sprint_id": sprint.id.0}}),
    )
    .await;
    assert!(why.contains("in this company"), "{why}");
    // Submitting under a product-owner policy is for the product owner, not any planner.
    sqlx::query("UPDATE citadel_projects SET requirement_id = ?, sprint_approval = 'product_owner' WHERE id = ?")
        .bind(req)
        .bind(a.seed.project)
        .execute(&app.pool)
        .await
        .unwrap();
    let why = refused(
        &w,
        &ta,
        "plan_requirement",
        json!({"requirement_id": req, "submit": true}),
    )
    .await;
    assert!(why.contains("only a product owner"), "{why}");
    assert_eq!(
        count(
            app,
            "SELECT count(*) FROM citadel_requirements WHERE state != 'planning'"
        )
        .await,
        0
    );
}
