use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::exec::{
    Lease, NewCostEvent, NewRun, NewWakeRequest, RunState, RunnerStatus, WakeSource, WakeStatus,
};
use ainkrad_core::org::{AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use ainkrad_core::work::{
    Actor, IssueKind, IssueState, NewComment, NewIssue, NewProject, NextActor, ProjectMode,
    SprintApproval, UserId,
};

use super::*;
use crate::store::org::{create_agent, create_company};
use crate::store::work::{create_comment, create_issue, create_project, delete_issue, get_comment};
use crate::store::{MIGRATOR, connect};

mod account_picks;
mod account_settings;
mod accounts;
mod blockers;
mod breaker;
mod budgets;
mod chain;
mod checkout;
mod cost;
mod drops;
mod escalation;
mod fallbacks;
mod flow;
mod lease;
mod limits;
mod no_action;
mod product_owner;
mod profile_models;
mod prompt;
mod queue;
mod repair;
mod schedule;
mod settings;
mod stages;
mod stale;
mod stall;
mod sticky;
mod stuck;
mod tiers;
mod token;
mod transcript;
mod transition;
mod usage;
mod wake;

/// A migrated database in its own temp dir, removed on drop.
struct Db {
    pool: SqlitePool,
    dir: PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citadel-exec-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("citadel.db")).await.unwrap();
    Db { pool, dir }
}

fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

/// A company with one agent and one issue.
async fn fixture(pool: &SqlitePool, name: &str) -> (AgentId, IssueId) {
    let c = create_company(pool, name).await.unwrap();
    (agent(pool, c.id).await, issue(pool, c.id).await)
}

async fn agent(pool: &SqlitePool, company_id: CompanyId) -> AgentId {
    let a = NewAgent {
        company_id,
        name: "Dev".to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

async fn issue(pool: &SqlitePool, company_id: CompanyId) -> IssueId {
    let p = NewProject {
        company_id,
        team_id: None,
        name: "Citadel".to_owned(),
        key: "CIT".to_owned(),
        mode: ProjectMode::Scrum,
        sprint_approval: SprintApproval::Owner,
    };
    let p = create_project(pool, &p).await.unwrap();
    let i = NewIssue {
        project_id: p.id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

/// Seats `lead` as team lead and `dev` as a member of one team that owns every project of
/// their company, so an issue `dev` escalates goes to `lead` (E6.3).
async fn lead_team(pool: &SqlitePool, dev: AgentId, lead: AgentId) {
    use crate::store::org::{create_department, create_membership, create_team, get_agent};
    use ainkrad_core::org::{TeamMembership, TeamRole};
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let d = create_department(pool, company, "Engineering")
        .await
        .unwrap();
    let team = create_team(pool, d.id, "Core").await.unwrap().id;
    for (agent_id, team_role) in [(lead, TeamRole::TeamLead), (dev, TeamRole::Member)] {
        let seat = TeamMembership {
            team_id: team,
            agent_id,
            team_role,
        };
        create_membership(pool, &seat).await.unwrap();
    }
    sqlx::query("UPDATE projects SET team_id = ? WHERE company_id = ?")
        .bind(team.0)
        .bind(company.0)
        .execute(pool)
        .await
        .unwrap();
}

fn new_run(agent_id: AgentId, issue_id: Option<IssueId>) -> NewRun {
    NewRun {
        agent_id,
        issue_id,
        wake_request_id: None,
        harness: Harness::Claude,
    }
}

#[tokio::test]
async fn runner_crud_and_only_the_key_hash_is_stored() {
    let db = db().await;
    let pool = &db.pool;
    let key = "ck_runner_s3cret";
    let new = NewRunner {
        name: "mac-mini".to_owned(),
        tags: vec!["macos".to_owned(), "xcode".to_owned()],
    };
    let mut r = create_runner(pool, &new, key).await.unwrap();
    assert_eq!(r.status, RunnerStatus::Offline);
    assert_eq!(get_runner(pool, r.id).await.unwrap(), Some(r.clone()));
    assert_eq!(get_runner_by_key(pool, key).await.unwrap(), Some(r.clone()));
    assert_eq!(get_runner_by_key(pool, "ck_other").await.unwrap(), None);
    assert!(!format!("{r:?}").contains(key));

    let stored: Vec<u8> = sqlx::query_scalar("SELECT key_hash FROM runners WHERE id = ?")
        .bind(r.id.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(stored, key_hash(key));
    assert_eq!(stored.len(), 32);
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runners WHERE instr(CAST(key_hash AS TEXT), ?) > 0 \
         OR instr(name, ?) > 0 OR instr(tags, ?) > 0",
    )
    .bind(key)
    .bind(key)
    .bind(key)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(leaked, 0);

    let dup = create_runner(pool, &new, "ck_another").await.unwrap_err();
    assert!(is_constraint(&dup), "{dup}");

    // Unhealthy exactly when there is a reason.
    r.status = RunnerStatus::Unhealthy;
    let no_reason = update_runner(pool, &r).await.unwrap_err();
    assert!(is_constraint(&no_reason), "{no_reason}");
    r.health_reason = Some("claude 2.1.0 not in the compatibility matrix".to_owned());
    r.last_seen_at = Some("2026-10-21T10:00:00Z".to_owned());
    assert!(update_runner(pool, &r).await.unwrap());
    assert_eq!(list_runners(pool).await.unwrap(), vec![r.clone()]);
    r.status = RunnerStatus::Online;
    let stale_reason = update_runner(pool, &r).await.unwrap_err();
    assert!(is_constraint(&stale_reason), "{stale_reason}");

    assert!(delete_runner(pool, r.id).await.unwrap());
    assert!(!delete_runner(pool, r.id).await.unwrap());
}

#[tokio::test]
async fn run_crud_and_terminal_states_need_a_reason() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let runner = create_runner(
        pool,
        &NewRunner {
            name: "r".to_owned(),
            tags: vec![],
        },
        "k",
    )
    .await
    .unwrap();
    let mut run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    assert_eq!(run.state, RunState::Queued);
    assert_eq!(run.terminal_reason, None);
    assert_eq!(run.usage, Usage::default());
    assert_eq!(get_run(pool, run.id).await.unwrap(), Some(run.clone()));

    // `update_run` writes the harness version, session and usage, nothing else.
    let stored = run.clone();
    run.harness_version = Some("2.0.1".to_owned());
    run.session_id = Some("sess-1".to_owned());
    run.usage = Usage {
        input_tokens: 1200,
        output_tokens: 300,
        cache_tokens: 9000,
        cost_usd_micros: Some(42_000),
    };
    let bypass = Run {
        state: RunState::Failed,
        terminal_reason: Some("forged".to_owned()),
        runner_id: Some(runner.id),
        claimed_at: Some("2026-10-21T10:00:00Z".to_owned()),
        started_at: Some("2026-10-21T10:00:01Z".to_owned()),
        ended_at: Some("2026-10-21T10:05:00Z".to_owned()),
        failure_fingerprint: Some("x".to_owned()),
        ..run.clone()
    };
    assert!(update_run(pool, &bypass).await.unwrap());
    let updated = Run {
        harness_version: run.harness_version.clone(),
        session_id: run.session_id.clone(),
        usage: run.usage,
        ..stored
    };
    assert_eq!(get_run(pool, run.id).await.unwrap(), Some(updated.clone()));
    assert_eq!(list_runs(pool, dev).await.unwrap(), vec![updated]);

    // The schema: a live run has no reason, a terminal one a non-empty reason.
    let set = |state: &'static str, reason: Option<&'static str>| {
        sqlx::query("UPDATE runs SET state = ?, terminal_reason = ? WHERE id = ?")
            .bind(state)
            .bind(reason)
            .bind(run.id.0)
            .execute(pool)
    };
    let live_with_reason = set("running", Some("early")).await.unwrap_err();
    assert!(is_constraint(&live_with_reason), "{live_with_reason}");
    for state in [
        RunState::Succeeded,
        RunState::Failed,
        RunState::Cancelled,
        RunState::TimedOut,
        RunState::RunnerLost,
    ] {
        for reason in [None, Some("")] {
            let e = set(state.as_str(), reason).await.unwrap_err();
            assert!(is_constraint(&e), "{state:?} {reason:?}: {e}");
        }
    }
    set("failed", Some("token_cap")).await.unwrap();

    assert!(delete_run(pool, run.id).await.unwrap());
    assert_eq!(get_run(pool, run.id).await.unwrap(), None);
}

#[tokio::test]
async fn unpriced_usage_stays_null_never_zero() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mut run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    run.usage.input_tokens = 500;
    assert!(update_run(pool, &run).await.unwrap());
    let event = record_cost_event(
        pool,
        &NewCostEvent {
            run_id: run.id,
            agent_id: dev,
            issue_id: Some(i),
            usage: Usage {
                input_tokens: 500,
                ..Usage::default()
            },
            idempotency_key: "run-1-usage-1".to_owned(),
        },
    )
    .await
    .unwrap();
    assert_eq!(event.usage.cost_usd_micros, None);
    assert_eq!(
        get_run(pool, run.id)
            .await
            .unwrap()
            .unwrap()
            .usage
            .cost_usd_micros,
        None
    );

    for sql in [
        "SELECT cost_usd_micros, priced FROM runs",
        "SELECT cost_usd_micros, priced FROM cost_events",
    ] {
        let (cost, priced): (Option<i64>, bool) =
            sqlx::query_as(sql).fetch_one(pool).await.unwrap();
        assert_eq!((cost, priced), (None, false), "{sql}");
    }
    // The flag and the amount cannot disagree.
    let zero_unpriced = sqlx::query("UPDATE runs SET cost_usd_micros = 0 WHERE id = ?")
        .bind(run.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(is_constraint(&zero_unpriced), "{zero_unpriced}");
}

#[tokio::test]
async fn runs_and_wakes_stay_within_the_agents_company() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, _) = fixture(pool, "A").await;
    let (_, foreign) = fixture(pool, "B").await;
    let run = create_run(pool, &new_run(dev, Some(foreign)))
        .await
        .unwrap_err();
    assert!(is_raised(&run, "issue belongs to another company"), "{run}");
    let wake = create_wake_request(
        pool,
        &NewWakeRequest {
            agent_id: dev,
            issue_id: Some(foreign),
            source: WakeSource::Manual,
            reason: "poke".to_owned(),
            idempotency_key: "w".to_owned(),
            not_before: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        is_raised(&wake, "issue belongs to another company"),
        "{wake}"
    );
    // A run with no issue is fine.
    create_run(pool, &new_run(dev, None)).await.unwrap();
}
