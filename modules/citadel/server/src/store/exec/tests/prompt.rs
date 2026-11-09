//! The run prompt: one template, a job per role and a reason per wake, always with the done
//! rule, within its budget.

use super::wake::{dispatch, runner};
use super::*;

const DONE_RULE: &str = "Done rule: do the next action this issue needs from you with the \
                         citadel tools. Do not end your turn until you have changed the issue \
                         (transition, route, plan, a comment and hand-off, a PR, a verdict) or \
                         asked the human (ask_human). A summary alone is not done: a run that \
                         ends without acting is woken again, then escalated.";

fn facts(role: Role) -> Facts {
    Facts {
        agent: "Ada".to_owned(),
        role,
        key: "EXP-1".to_owned(),
        title: "CSV export".to_owned(),
        kind: IssueKind::Task,
        state: IssueState::Todo,
        intake: false,
        requirement: false,
        wake: Some((WakeSource::Assignment, "issue 1 reassign".to_owned())),
    }
}

/// The prompt's `Your job on this wake:` line.
fn job_line(f: &Facts) -> String {
    let prompt = render(f);
    let line = prompt
        .lines()
        .find(|l| l.starts_with("Your job on this wake: "));
    line.expect("a job line").to_owned()
}

#[test]
fn the_ceo_on_an_intake_request_routes_it() {
    let f = Facts {
        agent: "Chief".to_owned(),
        role: Role::Ceo,
        key: "INTAKE-1".to_owned(),
        title: "CSV export for the orders page".to_owned(),
        intake: true,
        wake: Some((
            WakeSource::Assignment,
            "intake request: CSV export".to_owned(),
        )),
        ..facts(Role::Ceo)
    };
    let expected = format!(
        "You are Chief, the CEO, on INTAKE-1 (task, todo): \"CSV export for the orders page\".\n\
         Why you were woken: it was handed to you (intake request: CSV export).\n\
         Your job on this wake: this is an intake request: route it with route_intake. Read \
         org_chart first; when the request names or clearly concerns one of its projects, \
         route to that project ({{project_id}}); otherwise to a department as a new project.\n\
         Read the issue (get_issue) and your context (get_context) first.\n\
         {DONE_RULE}"
    );
    assert_eq!(render(&f), expected);
}

#[test]
fn each_role_gets_its_job() {
    let po = Facts {
        requirement: true,
        ..facts(Role::ProductOwner)
    };
    let review = Facts {
        state: IssueState::InReview,
        ..facts(Role::Developer)
    };
    let cases: [(Facts, &[&str]); 9] = [
        (facts(Role::Cto), &["hand it to that team", "ask_human"]),
        (
            po,
            &[
                "apply_plan",
                "plan_requirement",
                "points",
                "assignees",
                "repos",
                "submit: true",
            ],
        ),
        (facts(Role::ProductOwner), &["groom it"]),
        (
            facts(Role::TeamLead),
            &[
                "assign_issue",
                "estimate_issue",
                "decide_repo",
                "review_knowledge",
            ],
        ),
        (
            facts(Role::Developer),
            &["worktree", "Definition of Done", "open_pr", "done"],
        ),
        (facts(Role::Qa), &["Definition of Done", "qa_verdict"]),
        (
            facts(Role::DevOps),
            &["infrastructure", "production", "open_pr"],
        ),
        (review, &["review it"]),
        (
            Facts {
                intake: true,
                ..facts(Role::Ceo)
            },
            &["route_intake", "org_chart", "{project_id}"],
        ),
    ];
    for (f, words) in cases {
        let line = job_line(&f);
        for word in words {
            assert!(
                line.contains(word),
                "{:?}: {word} missing from {line}",
                f.role
            );
        }
        assert!(render(&f).ends_with(DONE_RULE), "{:?}", f.role);
        // The roles that run long jobs are told to poll them, not block on them.
        let polls = [Role::Developer, Role::DevOps, Role::Qa].contains(&f.role);
        assert_eq!(render(&f).contains("short polls"), polls, "{:?}", f.role);
    }
}

#[test]
fn each_wake_reason_says_why() {
    let cases = [
        (WakeSource::Assignment, "it was handed to you (r)."),
        (WakeSource::Comment, "a new comment or answer on it (r)."),
        (
            WakeSource::BlockerClosed,
            "a blocker of it closed, so it can move (r).",
        ),
        (WakeSource::Approval, "an approval on it was decided (r)."),
        (WakeSource::Escalation, "it was escalated to you (r)."),
        (
            WakeSource::Retry,
            "a retry: an earlier run on it did not finish (r).",
        ),
        (WakeSource::Timer, "a scheduled check or repair (r)."),
        (WakeSource::Manual, "the admin woke you (r)."),
    ];
    for (source, why) in cases {
        let f = Facts {
            wake: Some((source, "r".to_owned())),
            ..facts(Role::Developer)
        };
        let expected = format!("\nWhy you were woken: {why}\n");
        assert!(render(&f).contains(&expected), "{source:?}: {}", render(&f));
    }
    let none = Facts {
        wake: None,
        ..facts(Role::Developer)
    };
    assert!(render(&none).contains("\nWhy you were woken: it waits on you.\n"));
}

#[test]
fn roles_come_from_org_role_seats_and_title() {
    assert_eq!(Role::of("ceo", "product_owner", "CEO"), Role::Ceo);
    assert_eq!(Role::of("cto", "", "CTO"), Role::Cto);
    assert_eq!(
        Role::of("none", "member,product_owner", "PO"),
        Role::ProductOwner
    );
    assert_eq!(Role::of("none", "team_lead", "Team Lead"), Role::TeamLead);
    assert_eq!(Role::of("none", "member", "QA"), Role::Qa);
    assert_eq!(Role::of("none", "member", "DevOps"), Role::DevOps);
    assert_eq!(Role::of("none", "", "Developer"), Role::Developer);
}

#[test]
fn a_prompt_stays_within_its_budget() {
    let long = "x ".repeat(5000);
    let f = Facts {
        agent: long.clone(),
        title: long.clone(),
        requirement: true,
        wake: Some((WakeSource::Comment, long)),
        ..facts(Role::DevOps)
    };
    let prompt = render(&f);
    assert!(prompt.len() <= PROMPT_MAX, "{} bytes", prompt.len());
    assert_eq!(
        prompt.matches('…').count(),
        3,
        "agent, title and reason are cut"
    );
}

/// The server builds it from the run's agent, issue and wake: the CEO on its intake request.
#[tokio::test]
async fn a_run_gets_its_prompt_from_its_agent_issue_and_wake() {
    let db = db().await;
    let pool = &db.pool;
    let (ceo, i) = fixture(pool, "A").await;
    sqlx::query("UPDATE agents SET org_role = 'ceo', name = 'Chief' WHERE id = ?")
        .bind(ceo.0)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE projects SET intake = 1")
        .execute(pool)
        .await
        .unwrap();
    let w = NewWakeRequest {
        agent_id: ceo,
        issue_id: Some(i),
        source: WakeSource::Assignment,
        reason: "intake request: Work".to_owned(),
        idempotency_key: "k".to_owned(),
        not_before: None,
    };
    enqueue_wake(pool, &w).await.unwrap();
    let mac = runner(pool, "mac").await;
    let run = dispatch(pool, mac, "2026-10-21T10:00:00.000Z")
        .await
        .unwrap();
    let prompt = run_prompt(pool, run.id).await.unwrap().unwrap();
    assert!(
        prompt.starts_with(
            "You are Chief, the CEO, on CIT-1 (task, todo): \"Work\".\n\
             Why you were woken: it was handed to you (intake request: Work).\n\
             Your job on this wake: this is an intake request: route it with route_intake."
        ),
        "{prompt}"
    );
    // A run with no issue gets none: the runner's own.
    let (other, _) = fixture(pool, "B").await;
    let mut w = w;
    (w.agent_id, w.issue_id, w.idempotency_key) = (other, None, "k2".to_owned());
    enqueue_wake(pool, &w).await.unwrap();
    let bare = dispatch(pool, mac, "2026-10-21T10:00:00.000Z")
        .await
        .unwrap();
    assert_eq!(run_prompt(pool, bare.id).await.unwrap(), None);
}
