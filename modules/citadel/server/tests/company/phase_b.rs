//! E9.5, the Phase B end-to-end: one scrum project from a goal to a reviewed sprint, every agent
//! a fake harness playing its script through the real runner and MCP, every human step the
//! admin's CLI, the forge a fake GitHub.
//!
//! CEO intake (a requirement) → routed to Engineering → the product owner files the full plan and
//! the owner approves it (plan-first, E15.10) → the product owner plans a sprint and the team lead
//! estimates it → the commit waits on the owner (scripted `approval approve`) → the developer
//! starts and asks the owner a question, which lands in the requirement's thread; the owner's
//! answer there wakes the developer (E15.11) → it works the issue, publishes its file as an
//! artifact from its worktree (E15.12) and opens a PR → QA passes it → the owner approves the merge (CLI) → merged
//! with a merge commit → the issue is done → the sprint closes with its review.
//!
//! `phase_b_with_opencode` (ignored; `make e2e-b`) is the same flow with the developer's step
//! played by a real OpenCode on its free model, instructed by the issue body (it asks nothing);
//! the rest stays scripted.

use tokio::process::Command;

use citadel_core::work::{IssueId, IssueState, ProjectId};
use citadel_server::store::forge::{PrPhase, issue_pr};
use citadel_server::store::work::get_issue;
use ainkrad_providers::{Kind, fake};
use serde_json::{Value, json};

use super::stage::{ADMIN, Stage};

/// `citadel-server <verb> <noun> <db> <rest…>` as the admin: its stdout, trimmed. Awaited,
/// never blocking: the in-process server shares this test's runtime.
async fn cli(stage: &Stage, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_citadel-server"))
        .args(&args[..2])
        .arg(&stage.db)
        .args(&args[2..])
        .output()
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{args:?}: {err}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// The pending approval of `kind` in `company`, from `approval list`.
async fn pending(stage: &Stage, company: i64, kind: &str) -> String {
    let listed = cli(
        stage,
        &["approval", "list", &company.to_string(), "--pending"],
    )
    .await;
    listed
        .lines()
        .find(|l| l.split('\t').nth(1) == Some(kind))
        .unwrap_or_else(|| panic!("no pending {kind}: {listed}"))
        .split('\t')
        .next()
        .unwrap()
        .to_owned()
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

/// The free model the OpenCode variant uses unless `MODEL` says otherwise.
const OPENCODE_MODEL: &str = "opencode/nemotron-3.5-lightning-free";

#[tokio::test]
async fn phase_b_one_scrum_project_from_goal_to_reviewed_sprint() {
    phase_b(false).await;
}

#[tokio::test]
#[ignore = "a real OpenCode plays the developer; run by make e2e-b with an isolated HOME"]
async fn phase_b_with_opencode() {
    phase_b(true).await;
}

async fn phase_b(opencode: bool) {
    let mut stage = Stage::new("phase-b").await;
    let o = stage.org().await;
    let company = o.company.0.to_string();
    let engineering: i64 =
        sqlx::query_scalar("SELECT id FROM departments WHERE company_id = ? AND name = ?")
            .bind(o.company.0)
            .bind("Engineering")
            .fetch_one(&stage.pool)
            .await
            .unwrap();

    // 1. A goal comes in; the CEO routes it to Engineering.
    let route = json!({"routes": [{"department_id": engineering, "name": "CSV export",
                                   "key": "EXP", "mode": "scrum"}]});
    stage.play_key("INTAKE-1", &[("route_intake", route)]);
    // The product owner's first look at its kickoff: the spec the request became; it starts
    // the kickoff (a run that only reads is nudged again).
    stage.play_key(
        "EXP-1",
        &[
            ("get_context", json!({})),
            ("transition", json!({"transition": "start"})),
        ],
    );
    let body = "Customers want their orders as CSV.";
    let intake = cli(
        &stage,
        &["intake", "add", &company, "CSV export", "--body", body],
    )
    .await;
    let intake = IssueId(intake.parse().unwrap());
    assert_eq!(stage.ended(intake, 1).await, "succeeded");
    // The CEO was told its job: route the request (1.22).
    let told = std::fs::read_to_string(stage.dir.join("plays/INTAKE-1.1.prompt")).unwrap();
    for said in [
        "the CEO, on INTAKE-1",
        "route it with route_intake",
        "A summary",
    ] {
        assert!(told.contains(said), "{said} missing from {told}");
    }
    assert_eq!(
        get_issue(&stage.pool, intake).await.unwrap().unwrap().state,
        IssueState::Done
    );
    let kickoff = by_key(&stage, "EXP-1").await;
    assert_eq!(stage.ended(kickoff, 1).await, "succeeded");
    let ctx = &stage.replies(kickoff, 1).await[0];
    let spec = ctx["project"]["spec"].as_str().unwrap();
    assert!(spec.contains(body), "the request became the spec: {ctx}");
    let project = get_issue(&stage.pool, kickoff)
        .await
        .unwrap()
        .unwrap()
        .project_id;

    // The admin puts the project on a forge.
    let (api, hub) = fake::github("forge_token").await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    if opencode {
        use_opencode(&stage, project).await;
    }
    if !opencode {
        hub.lock().unwrap().git = Some(origin);
    }

    // 2. Plan-first (E15.10): the product owner files the requirement's full plan, an epic with
    //    its estimated, assigned task, and submits it; the owner approves it from the shell.
    let requirement = get_issue(&stage.pool, kickoff)
        .await
        .unwrap()
        .unwrap()
        .requirement_id
        .expect("the routed project carries the requirement");
    let task = json!({"title": "CSV export", "body": feature_body(opencode), "points": 3,
                      "assignee_agent_id": o.dev.0});
    stage.play_key(
        "EXP-1",
        &[(
            "plan_requirement",
            json!({"epics": [{"title": "CSV export", "tasks": [task]}], "submit": true}),
        )],
    );
    stage.wake(kickoff, o.po).await;
    assert_eq!(stage.ended(kickoff, 2).await, "succeeded");
    let planned = &stage.replies(kickoff, 2).await[0];
    assert_eq!(
        planned["submitted"]["status"], "pending_approval",
        "{planned}"
    );
    let feature = IssueId(planned["tasks"][0].as_i64().unwrap());
    let shown: Value = serde_json::from_str(
        &cli(&stage, &["requirement", "show", &requirement.0.to_string()]).await,
    )
    .unwrap();
    assert_eq!(shown["state"], "plan_review", "no dev work yet: {shown}");
    let plan = pending(&stage, o.company.0, "plan_approval").await;
    cli(
        &stage,
        &["approval", "approve", &plan, "--reply", "Plan looks right"],
    )
    .await;
    let tree: Value = serde_json::from_str(
        &cli(&stage, &["requirement", "tree", &requirement.0.to_string()]).await,
    )
    .unwrap();
    assert_eq!(tree["requirement"]["state"], "in_progress", "{tree}");
    assert_eq!(
        (tree["points"].as_i64(), tree["tasks"].as_i64()),
        (Some(3), Some(1))
    );
    assert_eq!(tree["epics"][0]["tasks"][0]["issue_id"], feature.0);

    // 3. Woken with the approval, the product owner plans sprint 1 and hands the kickoff to the
    //    team lead, who estimates and hands it back; the product owner commits.
    let sprint = 1;
    stage.play_key(
        "EXP-1",
        &[
            (
                "plan_sprint",
                json!({"name": "Sprint 1", "goal": "CSV export",
                                   "starts_on": "2026-10-22", "ends_on": "2026-11-04"}),
            ),
            (
                "sprint_add_issue",
                json!({"sprint_id": sprint, "issue_id": feature.0}),
            ),
            (
                "assign_issue",
                json!({"issue_id": kickoff.0, "agent_id": o.lead.0}),
            ),
        ],
    );
    stage.play_key(
        "EXP-1",
        &[
            (
                "estimate_issue",
                json!({"issue_id": feature.0, "points": 3}),
            ),
            (
                "assign_issue",
                json!({"issue_id": kickoff.0, "agent_id": o.po.0}),
            ),
        ],
    );
    stage.play_key("EXP-1", &[("commit_sprint", json!({"sprint_id": sprint}))]);
    // 4. Once the owner approves, the product owner gives the issue to the developer.
    stage.play_key(
        "EXP-1",
        &[(
            "assign_issue",
            json!({"issue_id": feature.0, "agent_id": o.dev.0}),
        )],
    );
    // The developer's runs (unless OpenCode plays them): it starts and asks the owner a
    // question (E15.11), then, woken with the answer, works the issue; then QA's two looks.
    if !opencode {
        let ask = json!({"question": "Comma or semicolon as the separator?",
                         "options": ["comma", "semicolon"]});
        stage.play_key(
            "EXP-2",
            &[
                ("transition", json!({"transition": "start"})),
                ("ask_human", ask),
            ],
        );
        let dev = stage.play_key(
            "EXP-2",
            &[
                ("comment", json!({"body": "Writing the exporter."})),
                (
                    "publish_artifact",
                    json!({"name": "export.csv", "kind": "file", "path": "export.csv"}),
                ),
                (
                    "open_pr",
                    json!({"title": "EXP-2: CSV export", "body": "Adds CSV export."}),
                ),
                ("transition", json!({"transition": "done"})),
            ],
        );
        let commit =
            "printf 'id,total\\n' > export.csv && git add -A && git commit -qm 'Add CSV export'";
        stage.script(feature, dev, commit).await;
    }
    // QA's first look comes before the PR is open: its pass is refused, which is its answer
    // for now (a run that only reads is nudged again).
    stage.play_key(
        "EXP-2",
        &[
            ("get_issue", json!({})),
            (
                "qa_verdict",
                json!({"verdict": "pass", "notes": "Too early"}),
            ),
        ],
    );
    stage.play_key(
        "EXP-2",
        &[(
            "qa_verdict",
            json!({"verdict": "pass", "notes": "CSV opens in a spreadsheet"}),
        )],
    );
    assert_eq!(stage.ended(kickoff, 5).await, "succeeded");
    for (n, step) in [(3, 0), (3, 1), (3, 2), (4, 0), (4, 1), (5, 0)] {
        let r = &stage.replies(kickoff, n).await[step];
        assert!(r.get("error").is_none(), "run {n} step {step}: {r}");
    }
    let commit = &stage.replies(kickoff, 5).await[0];
    assert_eq!(commit["status"], "pending_approval", "{commit}");

    // The gate: the project's owner policy; the owner approves the commit from the shell.
    let gate = pending(&stage, o.company.0, "sprint_commit").await;
    cli(&stage, &["approval", "approve", &gate, "--reply", "Go"]).await;
    assert_eq!(stage.ended(kickoff, 6).await, "succeeded");

    // 5. The developer works the issue: commit, start, comment, PR, done.
    if opencode {
        deny_outside_tools(&stage, o.company, feature).await;
    }
    stage.ended(feature, 1).await;
    let dev_runs = if opencode { 1 } else { 2 };
    if !opencode {
        // The question is in the requirement's thread; the owner answers there, and the answer
        // wakes the developer, not the CEO or the product owner.
        let r = requirement.0.to_string();
        let thread = cli(&stage, &["requirement", "thread", &r]).await;
        let card: Value = thread
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .find(|v| v["kind"] == "question")
            .unwrap_or_else(|| panic!("no question card: {thread}"));
        assert_eq!(card["question"]["asked_by_agent_id"], o.dev.0, "{card}");
        for kind in ["plan_approval", "sprint_commit"] {
            let card = format!("\"approval_kind\":\"{kind}\"");
            assert!(
                thread.contains(&card),
                "the {kind} card is in the thread: {thread}"
            );
        }
        assert_eq!(card["question"]["issue_key"], "EXP-2");
        let posted: Value =
            serde_json::from_str(&cli(&stage, &["requirement", "post", &r, "comma"]).await)
                .unwrap();
        assert_eq!(posted["woke_agent_id"], o.dev.0, "{posted}");
        assert_eq!(stage.ended(feature, 2).await, "succeeded");
        // The file it published from its worktree is in the requirement's thread (E15.12).
        let published = &stage.replies(feature, 2).await[1];
        assert_eq!(published["size"], 9, "{published}");
        let thread = cli(&stage, &["requirement", "thread", &r]).await;
        assert!(
            thread.contains("\"kind\":\"artifact\"") && thread.contains("export.csv"),
            "{thread}"
        );
    }
    let i = get_issue(&stage.pool, feature).await.unwrap().unwrap();
    assert_eq!(i.state, IssueState::InReview, "done went to QA");
    let pr = issue_pr(&stage.pool, feature)
        .await
        .unwrap()
        .expect("a PR was asked for");
    assert_eq!(pr.phase, PrPhase::Requested);
    // QA looked before the PR was open.
    stage.ended(feature, dev_runs + 1).await;

    // 6. The PR opens; QA is woken and passes it.
    stage.poll().await;
    let pr = issue_pr(&stage.pool, feature).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.number), (PrPhase::Open, Some(1)));
    assert_eq!(stage.ended(feature, dev_runs + 2).await, "succeeded");
    // The fake's plays count only its own runs: with OpenCode as the developer, QA's pass is
    // the fake's second run on the issue, else its fourth.
    let pass = if opencode { 2 } else { 4 };
    let verdict = stage.replies(feature, pass).await;
    assert_eq!(verdict[0]["verdict"], "pass", "{verdict:?}");

    // 7. The owner approves the merge; the poller merges with a merge commit; done.
    let merge = pending(&stage, o.company.0, "pr_merge").await;
    cli(&stage, &["approval", "approve", &merge]).await;
    stage.poll().await;
    assert_eq!(hub.lock().unwrap().merges, [(1, "merge".to_owned())]);
    let i = get_issue(&stage.pool, feature).await.unwrap().unwrap();
    assert_eq!(i.state, IssueState::Done);

    // 8. The sprint closes with its review.
    cli(&stage, &["sprint", "close", &sprint.to_string()]).await;
    let report: Value =
        serde_json::from_str(&cli(&stage, &["sprint", "report", "1"]).await).unwrap();
    assert_eq!(report["state"], "closed", "{report}");
    assert_eq!(report["review"]["committed"], 3, "{report}");
    assert_eq!(report["review"]["completed"], 3, "{report}");
    assert_eq!(report["review"]["carried"], json!([]), "{report}");

    let trail: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT action FROM audit_events WHERE action IN ('intake.routed', \
         'sprint.started', 'pr.requested', 'pr.opened', 'qa.verdict', 'approval.approved', \
         'pr.merged', 'sprint.closed', 'requirement.plan_approved', 'question.asked', \
         'question.answered', 'artifact.published') ORDER BY action",
    )
    .fetch_all(&stage.pool)
    .await
    .unwrap();
    let expected = if opencode { 9 } else { 12 };
    assert_eq!(trail.len(), expected, "{trail:?}");
}

/// The task's body: with `opencode`, what the real model is told to do.
/// `E2E_CLI=1`: the OpenCode developer is told to use the run's `citadel` CLI (E15.18), its four
/// steps in one shell command, instead of four MCP tool calls.
fn cli_mode() -> bool {
    std::env::var("E2E_CLI").as_deref() == Ok("1")
}

fn feature_body(opencode: bool) -> String {
    if !opencode {
        return "Export orders as CSV.".to_owned();
    }
    if cli_mode() {
        return "This is a Citadel end-to-end check. Run exactly this one shell command and \
                nothing else, then reply with one line: printf '%s' \
                '[{\"op\":\"transition\",\"args\":{\"transition\":\"start\"}},\
                {\"op\":\"comment\",\"args\":{\"body\":\"e2e: on it\"}},\
                {\"op\":\"open_pr\",\"args\":{\"title\":\"EXP-2: CSV export\"}},\
                {\"op\":\"transition\",\"args\":{\"transition\":\"done\"}}]' \
                | citadel batch"
            .to_owned();
    }
    "This is a Citadel end-to-end check. Use only the citadel MCP tools, in this order: 1. \
     transition with transition \"start\"; 2. comment with body \"e2e: on it\"; 3. open_pr \
     with title \"EXP-2: CSV export\"; 4. transition with transition \"done\". Do not edit \
     files or run shell commands. Then reply with one line."
        .to_owned()
}

/// Switches the project's company's developer to a real OpenCode.
async fn use_opencode(stage: &Stage, project: ProjectId) {
    let model = std::env::var("MODEL").unwrap_or_else(|_| OPENCODE_MODEL.to_owned());
    sqlx::query(
        "UPDATE agents SET harness = 'opencode', model = ? \
         WHERE name = 'Developer 1' AND company_id = (SELECT company_id FROM projects \
         WHERE id = ?)",
    )
    .bind(model)
    .bind(project.0)
    .execute(&stage.pool)
    .await
    .unwrap();
}

/// While a real model works `issue`'s first run (up to 10 minutes), the owner denies every tool
/// call it asks for outside the Citadel MCP tools, with a reply that says so.
async fn deny_outside_tools(stage: &Stage, company: citadel_core::org::CompanyId, issue: IssueId) {
    use citadel_core::gov::{ApprovalKind, ApprovalStatus};
    use citadel_server::store::gov::{decide_approval, list_approvals};
    let reply = "Denied: use only the citadel MCP tools named in the issue.";
    for _ in 0..600 {
        let ended: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runs WHERE issue_id = ? \
             AND state NOT IN ('queued', 'claimed', 'running')",
        )
        .bind(issue.0)
        .fetch_one(&stage.pool)
        .await
        .unwrap();
        if ended > 0 {
            return;
        }
        for a in list_approvals(&stage.pool, company).await.unwrap() {
            if a.kind == ApprovalKind::PermissionEscalation && a.status == ApprovalStatus::Pending {
                let now = stage.now();
                // With the CLI, its one `citadel batch` command is allowed (E15.18).
                let ok = cli_mode() && a.payload.contains("| citadel batch");
                let why = (!ok).then_some(reply);
                let _ = decide_approval(&stage.pool, a.id, ok, ADMIN, why, &now).await;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    panic!("the developer's run did not end in 10 minutes");
}
