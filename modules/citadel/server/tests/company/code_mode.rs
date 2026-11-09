//! E15.18 "Code Mode, our way" (decision #59): what a full plan build costs an agent, measured
//! through the real server, runner and MCP with the fake harness playing a product owner.
//!
//! - **Tool definitions per role**: each of the template's six agents (CEO, CTO, product owner,
//!   team lead, developer, QA) runs once and asks `tools/list`; the reply's size is what its
//!   harness loads into context before the first turn.
//! - **A plan build**: a request is routed to Engineering; its product owner reads the issue, the
//!   project and the org, then files the full plan (3 epics, 9 tasks with estimates, assignees
//!   and repos), places every task in a new sprint and submits the plan, one tool call per step,
//!   the way the current tools allow. Counted: tool calls (each one a model turn for a
//!   tool-calling agent), operations the server audited, bytes the model wrote (arguments) and
//!   read back (results), and the run's wall time.
//!
//! - **Four ways** (`Way`): the baseline (every tool listed, one call per step); role-scoped
//!   tools; `apply_plan` (the whole plan in one call); and the run's `citadel` CLI, two shell
//!   commands whose filtered output is all that returns to the model (`cli`).
//!
//! Tokens are estimated at 4 bytes each. "Context" is what enters the model's context once:
//! the tool definitions, every argument and every result. "Billed" is what a model without
//! prompt caching is sent over the run: the definitions plus everything before it, every turn.
//!
//! The fake harness has no model latency, so the wall time is transport and process time
//! only; "model s" adds `TURN_MS` per turn. The acceptance (at least 50% fewer billed tokens
//! and 50% less time than the baseline) is checked on the modelled time always, and on the
//! wall time when the sessions are repeated (`CODE_MODE_REPEAT` > 1, medians).
//!
//! `make test` runs it once (fast mode). `CODE_MODE_REPEAT=<n>` runs each session `n` times and
//! keeps the median time; `CODE_MODE_OUT=<file>` writes the numbers as JSON.

use citadel_core::audit::AuditActor;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::{IssueId, ProjectId, ProjectMode};
use citadel_server::store::settings;
use citadel_server::store::work::{Commands, Repo, add_repo, get_issue, submit_intake};
use serde_json::{Value, json};

use super::stage::{ADMIN, Org, Stage};

mod cli;
mod measure;
pub use measure::*;

/// A `tools/list` request.
fn list_request() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
}

fn call(name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": args}})
}

/// The `tools/list` reply's size, in bytes, as its harness reads it.
fn defs_bytes(reply: &Value) -> usize {
    reply["result"].to_string().len()
}

/// The size of each role's `tools/list`, one run per agent of the template.
pub async fn tool_lists(stage: &mut Stage, o: &Org, key: &str) -> Vec<(&'static str, usize)> {
    let project = stage.project(o, key, ProjectMode::Kanban).await;
    let roles = [
        ("dev", o.dev),
        ("qa", o.qa),
        ("po", o.po),
        ("lead", o.lead),
        ("ceo", o.ceo),
        ("cto", o.cto),
    ];
    let mut out = vec![];
    for (role, agent) in roles {
        let issue = stage.issue(project, role, None).await;
        let key = stage.key(issue).await;
        // Then it starts the issue: a run that only reads is nudged again.
        let start = call("transition", json!({"transition": "start"}));
        let n = stage.play_requests(&key, &[list_request(), start]);
        stage.assign(issue, agent).await;
        assert_eq!(stage.ended(issue, 1).await, "succeeded");
        let replies = stage.raw_replies(&key, n);
        let tools = replies[0]["result"]["tools"].as_array().map_or(0, Vec::len);
        assert!(tools > 0, "{role}: {replies:?}");
        out.push((role, defs_bytes(&replies[0])));
    }
    out
}

/// The plan every session builds: 3 epics of 3 tasks, each with an estimate, an assignee and
/// the repos it touches.
fn epics(o: &Org) -> Vec<Value> {
    let areas = [
        ("Export API", "api"),
        ("Export UI", "web"),
        ("Export ops", "api"),
    ];
    let steps = [
        ("Design", 2, o.lead),
        ("Build", 5, o.dev),
        ("Verify", 3, o.qa),
    ];
    areas
        .iter()
        .map(|(area, repo)| {
            let tasks: Vec<Value> = steps
                .iter()
                .map(|(step, points, who)| {
                    json!({"title": format!("{step}: {area}"),
                           "body": format!("{step} the {area} part of the CSV export: columns \
                                            id, date, total; streamed, UTF-8, tested on 10k \
                                            orders; see the project spec."),
                           "points": points, "assignee_agent_id": who.0, "repos": [repo]})
                })
                .collect();
            json!({"title": area, "tasks": tasks})
        })
        .collect()
}

pub const SPRINT: (&str, &str, &str, &str) = ("Sprint 1", "CSV export", "2026-10-26", "2026-11-06");

/// A requirement routed to Engineering as project EXP, with two repos, its kickoff with the
/// product owner, who has run once on it. The project and the kickoff.
pub async fn routed(stage: &mut Stage, o: &Org) -> (ProjectId, IssueId) {
    let engineering: i64 =
        sqlx::query_scalar("SELECT id FROM departments WHERE company_id = ? AND name = ?")
            .bind(o.company.0)
            .bind("Engineering")
            .fetch_one(&stage.pool)
            .await
            .unwrap();
    let route = json!({"routes": [{"department_id": engineering, "name": "CSV export",
                                   "key": "EXP", "mode": "scrum"}]});
    stage.play_key("INTAKE-1", &[("route_intake", route)]);
    // Its first look starts the kickoff: a run that only reads is nudged again.
    stage.play_key("EXP-1", &[("transition", json!({"transition": "start"}))]);
    // The product owner's first run uses the runner's `citadel` once, as earlier runs on a
    // long-lived runner would have: macOS checks a new executable on its first run (~0.25 s),
    // a once-per-runner cost that is not part of a plan build.
    stage.script_key("EXP-1", 1, "citadel --help > /dev/null\n");
    let body = "Customers want their orders as CSV: an API, a page and the ops around it.";
    let by = AuditActor::User(ADMIN);
    let intake = submit_intake(&stage.pool, o.company, "CSV export", body, by)
        .await
        .unwrap()
        .id;
    assert_eq!(stage.ended(intake, 1).await, "succeeded");
    let kickoff = by_key(stage, "EXP-1").await;
    assert_eq!(stage.ended(kickoff, 1).await, "succeeded");
    let project = get_issue(&stage.pool, kickoff)
        .await
        .unwrap()
        .unwrap()
        .project_id;
    for name in ["api", "web"] {
        let r = Repo {
            id: 0,
            project_id: project,
            name: name.to_owned(),
            url: stage.repo_url(&stage.bare(name)),
            default_branch: "main".to_owned(),
            position: 0,
            primary: false,
            forge: None,
            commands: Commands::default(),
        };
        add_repo(&stage.pool, &r, by).await.unwrap().unwrap();
    }
    (project, kickoff)
}

async fn by_key(stage: &Stage, key: &str) -> IssueId {
    let (project, number) = key.rsplit_once('-').unwrap();
    let id: i64 = sqlx::query_scalar(
        "SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id \
         WHERE p.key = ? AND i.number = ?",
    )
    .bind(project)
    .bind(number.parse::<i64>().unwrap())
    .fetch_one(&stage.pool)
    .await
    .unwrap();
    IssueId(id)
}

/// The next issue id and the next sprint id.
async fn next_ids(stage: &Stage) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT coalesce(max(id), 0) + 1 FROM issues), \
         (SELECT coalesce(max(id), 0) + 1 FROM sprints)",
    )
    .fetch_one(&stage.pool)
    .await
    .unwrap()
}

/// The reads every session starts with: the issue, the project, the org.
fn reads() -> Vec<Value> {
    vec![
        call("get_issue", json!({})),
        call("get_context", json!({})),
        call("org_chart", json!({})),
    ]
}

/// Today's way: one tool call per step. The tasks' and the sprint's ids are the next ones in
/// their tables, as the agent would read them from each reply.
async fn current_calls(stage: &Stage, o: &Org) -> Vec<Value> {
    let epics = epics(o);
    let (first_task, sprint) = next_ids(stage).await;
    let mut calls = reads();
    let plan: Vec<Value> = epics
        .iter()
        .map(|e| {
            let tasks: Vec<Value> = e["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| {
                    let mut t = t.clone();
                    t.as_object_mut().unwrap().remove("repos");
                    t
                })
                .collect();
            json!({"title": e["title"], "tasks": tasks})
        })
        .collect();
    calls.push(call("plan_requirement", json!({"epics": plan})));
    let tasks: Vec<&Value> = epics
        .iter()
        .flat_map(|e| e["tasks"].as_array().unwrap())
        .collect();
    for (i, t) in tasks.iter().enumerate() {
        let issue = first_task + i as i64;
        calls.push(call(
            "set_repos",
            json!({"issue_id": issue, "repos": t["repos"]}),
        ));
    }
    let (name, goal, starts_on, ends_on) = SPRINT;
    calls.push(call(
        "plan_sprint",
        json!({"name": name, "goal": goal, "starts_on": starts_on, "ends_on": ends_on}),
    ));
    for i in 0..tasks.len() {
        let issue = first_task + i as i64;
        calls.push(call(
            "sprint_add_issue",
            json!({"sprint_id": sprint, "issue_id": issue}),
        ));
    }
    calls.push(call("plan_requirement", json!({"submit": true})));
    calls
}

/// Plays `calls` (after a `tools/list`) as the product owner's next run on the kickoff and
/// measures it; every call must succeed.
pub async fn play_calls(stage: &mut Stage, o: &Org, kickoff: IssueId, calls: &[Value]) -> Usage {
    let mut requests = vec![list_request()];
    requests.extend(calls.iter().cloned());
    let n = stage.play_requests("EXP-1", &requests);
    stage.wake(kickoff, o.po).await;
    assert_eq!(stage.ended(kickoff, n as i64).await, "succeeded");
    let replies = stage.raw_replies("EXP-1", n);
    assert_eq!(replies.len(), requests.len(), "{replies:?}");
    let mut u = Usage {
        defs: defs_bytes(&replies[0]),
        ..Usage::default()
    };
    for (req, reply) in requests[1..].iter().zip(&replies[1..]) {
        let text = reply["result"]["content"][0]["text"].as_str().unwrap_or("");
        assert_ne!(reply["result"]["isError"], true, "{req}: {text}");
        let wrote = req["params"]["arguments"].to_string().len();
        u.turns += 1;
        u.wrote += wrote;
        u.read += text.len();
        u.per_turn.push(wrote + text.len());
    }
    run_numbers(stage, kickoff, n, &mut u).await;
    u
}

/// The audited operations and wall time of run `n` on `issue`.
pub async fn run_numbers(stage: &Stage, issue: IssueId, n: u32, u: &mut Usage) {
    let (run, ms): (i64, f64) = sqlx::query_as(
        "SELECT id, (julianday(ended_at) - julianday(started_at)) * 86400000.0 FROM runs \
         WHERE issue_id = ? ORDER BY id LIMIT 1 OFFSET ?",
    )
    .bind(issue.0)
    .bind(n as i64 - 1)
    .fetch_one(&stage.pool)
    .await
    .unwrap();
    u.ops = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE run_id = ? AND action LIKE 'mcp.%'",
    )
    .bind(run)
    .fetch_one(&stage.pool)
    .await
    .unwrap();
    u.ms = ms;
}

/// The plan is in place: 9 tasks with estimates, assignees and repos, all in the sprint, the
/// plan submitted for the owner's approval.
pub async fn check_plan(stage: &Stage, project: ProjectId) {
    let (tasks, sprinted, pointed, owned): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), count(sprint_id), count(points), count(owner_agent_id) FROM issues \
         WHERE project_id = ? AND epic_id IS NOT NULL",
    )
    .bind(project.0)
    .fetch_one(&stage.pool)
    .await
    .unwrap();
    assert_eq!((tasks, sprinted, pointed, owned), (9, 9, 9, 9));
    let repos: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issue_repos r JOIN issues i ON i.id = r.issue_id \
         WHERE i.project_id = ? AND r.state = 'approved'",
    )
    .bind(project.0)
    .fetch_one(&stage.pool)
    .await
    .unwrap();
    assert_eq!(repos, 9);
    let state: String = sqlx::query_scalar(
        "SELECT r.state FROM requirements r JOIN projects p ON p.requirement_id = r.id \
         WHERE p.id = ?",
    )
    .bind(project.0)
    .fetch_one(&stage.pool)
    .await
    .unwrap();
    assert_eq!(state, "plan_review");
}

/// Role-scoped tool lists on (the default) or off, server-wide (E15.18 step 1).
pub async fn scope_tools(stage: &Stage, on: bool) {
    let by = AuditActor::User(ADMIN);
    let (key, at) = (Key::McpRoleScopedTools, Scope::Server);
    let value = if on { "1" } else { "0" };
    settings::set(&stage.pool, key, at, value, by, &stage.now())
        .await
        .unwrap();
}

/// One plan build, on a fresh stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    /// Every tool listed, one call per step: the baseline.
    Current,
    /// The role's tools only, one call per step (step 1).
    Scoped,
    /// The role's tools, the whole plan in one `apply_plan` (steps 1 and 2).
    ApplyPlan,
    /// The run's `citadel` CLI from the shell: two commands (step 3).
    Cli,
}

/// The whole plan as one `apply_plan`, submitted.
fn apply_call(o: &Org) -> Value {
    let (name, goal, starts_on, ends_on) = SPRINT;
    call(
        "apply_plan",
        json!({"idempotency_key": "plan-1", "epics": epics(o), "submit": true,
               "sprint": {"name": name, "goal": goal, "starts_on": starts_on,
                          "ends_on": ends_on}}),
    )
}

pub async fn session(mut stage: Stage, way: Way) -> Usage {
    let o = stage.org().await;
    scope_tools(&stage, way != Way::Current).await;
    let (project, kickoff) = routed(&mut stage, &o).await;
    let calls = match way {
        Way::Current | Way::Scoped => current_calls(&stage, &o).await,
        Way::ApplyPlan => {
            let mut calls = reads();
            calls.push(apply_call(&o));
            calls
        }
        Way::Cli => vec![],
    };
    let u = match way {
        Way::Cli => cli::cli_session(&mut stage, &o, kickoff).await,
        _ => play_calls(&mut stage, &o, kickoff, &calls).await,
    };
    check_plan(&stage, project).await;
    u
}

/// Every role's tool list with and without scoping, and a plan build each way.
#[tokio::test]
async fn a_plan_build_is_measured() {
    let mut stage = Stage::new("code-mode-roles").await;
    let o = stage.org().await;
    scope_tools(&stage, false).await;
    let all = tool_lists(&mut stage, &o, "ALL").await;
    scope_tools(&stage, true).await;
    let scoped = tool_lists(&mut stage, &o, "ROLE").await;
    drop(stage);
    let roles: RoleLists = all
        .iter()
        .zip(&scoped)
        .map(|((role, a), (_, s))| (*role, *a, *s))
        .collect();
    for (role, a, s) in &roles {
        assert!(s < a, "{role}: scoped {s} of {a}");
    }
    let base = median("code-mode-current", |s| session(s, Way::Current)).await;
    let scoped = median("code-mode-scoped", |s| session(s, Way::Scoped)).await;
    let applied = median("code-mode-apply", |s| session(s, Way::ApplyPlan)).await;
    let cli = median("code-mode-cli", |s| session(s, Way::Cli)).await;
    report(
        &roles,
        &[
            ("current", &base),
            ("scoped", &scoped),
            ("apply_plan", &applied),
            ("cli", &cli),
        ],
    );
    assert_eq!(
        base.turns, 24,
        "3 reads, 1 plan, 9 repos, 1 sprint, 9 adds, 1 submit"
    );
    assert_eq!((base.ops, scoped.turns), (24, 24));
    assert!(scoped.defs < base.defs);
    assert_eq!((applied.turns, applied.ops), (4, 4), "3 reads and the plan");
    assert_eq!(
        (cli.turns, cli.ops),
        (2, 4),
        "2 commands: 3 reads, then the plan"
    );
    // The acceptance (decision #59): at least 50% fewer tokens and 50% less time.
    for (name, u) in [("apply_plan", &applied), ("cli", &cli)] {
        let tokens = saved(base.billed_tokens() as f64, u.billed_tokens() as f64);
        let modeled = saved(base.modeled_ms(), u.modeled_ms());
        assert!(tokens >= 50.0, "{name}: {tokens:.0}% fewer tokens");
        assert!(modeled >= 50.0, "{name}: {modeled:.0}% less modelled time");
        // One run's wall time is noisy on a busy machine: the median of several is checked.
        if repeats() > 1 {
            let time = saved(base.ms, u.ms);
            assert!(time >= 50.0, "{name}: {time:.0}% less wall time");
        }
    }
}
