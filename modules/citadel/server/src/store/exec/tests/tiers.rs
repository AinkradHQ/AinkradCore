//! Per-task model routing (E15.5): a small task starts on its agent's small model, a bigger one
//! on its own; the chain still falls back; a new run is a fresh session unless the project
//! allows continuing an unfinished one; the per-task report is exact.

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunEvent;
use citadel_core::gov::Billing;
use citadel_core::org::{ModelRoute, Tier};
use citadel_core::settings::{Key, Scope};
use citadel_core::work::ProjectId;

use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::exec::{Fallback, fallback_routes, switch_route};
use crate::store::gov::{set_billing, set_price, task_costs};
use crate::store::org::{list_tiers, set_fallbacks, set_tiers};
use crate::store::work::{add_issue_label, create_label, get_issue};

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

fn route(harness: Harness, model: &str) -> ModelRoute {
    ModelRoute {
        harness,
        model: model.to_owned(),
    }
}

/// An issue of `project`, of `kind` with `points`, assigned to nobody.
async fn task(
    pool: &SqlitePool,
    project: ProjectId,
    kind: IssueKind,
    points: Option<u32>,
) -> IssueId {
    let i = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind,
        title: format!("{} of {points:?}", kind.as_str()),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points,
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

/// The fixture's agent with a small tier, its project, and a runner.
async fn setup(pool: &SqlitePool) -> (AgentId, ProjectId, RunnerId) {
    let (dev, first) = fixture(pool, "A").await;
    let small = (Tier::Small, route(Harness::Claude, "claude-haiku"));
    assert!(
        set_tiers(pool, dev, std::slice::from_ref(&small), BY)
            .await
            .unwrap()
    );
    assert_eq!(list_tiers(pool, dev).await.unwrap(), vec![small]);
    let project = get_issue(pool, first).await.unwrap().unwrap().project_id;
    (dev, project, runner(pool, "box").await)
}

/// Wakes `dev` on `issue` and dispatches its run.
async fn run_of(pool: &SqlitePool, dev: AgentId, issue: IssueId, r: RunnerId) -> Run {
    static N: AtomicUsize = AtomicUsize::new(0);
    let key = format!("w{}", N.fetch_add(1, Ordering::Relaxed));
    enqueue_wake(pool, &wake(dev, Some(issue), &key))
        .await
        .unwrap();
    dispatch(pool, r, NOW).await.expect("a run")
}

#[tokio::test]
async fn a_one_point_chore_runs_small_and_a_five_point_story_standard() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, project, r) = setup(pool).await;
    for bad in [
        vec![(Tier::Standard, route(Harness::Claude, "x"))],
        vec![(Tier::Small, route(Harness::Claude, " "))],
        vec![
            (Tier::Small, route(Harness::Claude, "a")),
            (Tier::Small, route(Harness::Codex, "b")),
        ],
    ] {
        let e = set_tiers(pool, dev, &bad, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{bad:?}");
    }

    let chore = task(pool, project, IssueKind::Task, Some(1)).await;
    let label = create_label(pool, project, "Chore").await.unwrap();
    add_issue_label(pool, chore, label.id, BY).await.unwrap();
    let run = run_of(pool, dev, chore, r).await;
    assert_eq!(run.tier, Some(Tier::Small));
    assert_eq!(run.model_used.as_deref(), Some("claude-haiku"));
    assert_eq!(
        run.fallback_reason, None,
        "the small model is the run's first choice"
    );

    let story = task(pool, project, IssueKind::Story, Some(5)).await;
    let run = run_of(pool, dev, story, r).await;
    assert_eq!(run.tier, Some(Tier::Standard));
    assert_eq!(run.model_used.as_deref(), Some("claude-opus"));

    // A chore by label is small whatever its points; a big task with no large model on the
    // agent is large on the agent's own.
    let labelled = task(pool, project, IssueKind::Story, Some(13)).await;
    add_issue_label(pool, labelled, label.id, BY).await.unwrap();
    assert_eq!(run_of(pool, dev, labelled, r).await.tier, Some(Tier::Small));
    let big = task(pool, project, IssueKind::Story, Some(8)).await;
    let run = run_of(pool, dev, big, r).await;
    assert_eq!(run.tier, Some(Tier::Large));
    assert_eq!(run.model_used.as_deref(), Some("claude-opus"));
    let unestimated = task(pool, project, IssueKind::Task, None).await;
    assert_eq!(
        run_of(pool, dev, unestimated, r).await.tier,
        Some(Tier::Standard)
    );
    let dispatched = "SELECT count(*) FROM audit_events WHERE action = 'wake.dispatched' \
                      AND json_extract(details, '$.tier') = 'small' \
                      AND json_extract(details, '$.model') = 'claude-haiku'";
    let n: i64 = sqlx::query_scalar(dispatched)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn rules_and_settings_move_the_lines() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, project, r) = setup(pool).await;
    let (rules, defaults) = list_tier_rules(pool, project).await.unwrap();
    assert!(defaults);
    assert_eq!(rules.len(), DEFAULT_RULES.len());
    for bad in [
        vec![("chore".to_owned(), Tier::Small)],
        vec![("kind:epic".to_owned(), Tier::Small)],
        vec![
            ("label:a".to_owned(), Tier::Small),
            ("label:a".to_owned(), Tier::Large),
        ],
    ] {
        let e = set_tier_rules(pool, project, &bad, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{bad:?}");
    }
    let rules = vec![("kind:bug".to_owned(), Tier::Large)];
    assert!(set_tier_rules(pool, project, &rules, BY).await.unwrap());
    assert_eq!(
        list_tier_rules(pool, project).await.unwrap(),
        (rules, false)
    );
    let set = "SELECT count(*) FROM audit_events WHERE action = 'project.tier_rules_set'";
    let n: i64 = sqlx::query_scalar(set).fetch_one(pool).await.unwrap();
    assert_eq!(n, 1);

    // A one-point bug is large by its kind; with no point line, a one-point task is standard.
    let bug = task(pool, project, IssueKind::Bug, Some(1)).await;
    assert_eq!(run_of(pool, dev, bug, r).await.tier, Some(Tier::Large));
    let at = Scope::Project(project);
    crate::store::settings::set(pool, Key::RoutingSmallMaxPoints, at, "0", BY, NOW)
        .await
        .unwrap();
    let one = task(pool, project, IssueKind::Task, Some(1)).await;
    assert_eq!(run_of(pool, dev, one, r).await.tier, Some(Tier::Standard));
}

#[tokio::test]
async fn a_refused_small_model_still_falls_back() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, project, r) = setup(pool).await;
    let sonnet = route(Harness::Claude, "claude-sonnet");
    set_fallbacks(pool, dev, std::slice::from_ref(&sonnet), BY)
        .await
        .unwrap();
    let chore = task(pool, project, IssueKind::Task, Some(1)).await;
    let run = run_of(pool, dev, chore, r).await;
    let after: Vec<ModelRoute> = fallback_routes(pool, &run, &Harness::ALL, NOW)
        .await
        .unwrap()
        .into_iter()
        .map(|(r, _)| r)
        .collect();
    let own = route(Harness::Claude, "claude-opus");
    assert_eq!(after, vec![own.clone(), sonnet]);
    let fallback = Fallback {
        to: &own,
        account: None,
        class: "model_unavailable",
        reason: "no such model",
    };
    let by = AuditActor::Runner(r);
    let moved = switch_route(pool, run.id, &fallback, by, NOW)
        .await
        .unwrap();
    assert_eq!(moved.model_used.as_deref(), Some("claude-opus"));
    assert_eq!(
        moved.tier,
        Some(Tier::Small),
        "the tier is the task's, not the model's"
    );
    assert!(
        moved
            .fallback_reason
            .unwrap()
            .starts_with("claude/claude-haiku: model_unavailable")
    );
}

#[tokio::test]
async fn a_new_run_continues_an_unfinished_session_only_when_allowed() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, project, r) = setup(pool).await;
    let issue = task(pool, project, IssueKind::Story, Some(5)).await;
    let first = run_of(pool, dev, issue, r).await;
    let by = AuditActor::Runner(r);
    start_run(pool, first.id, by, Some("sess-1".to_owned()), NOW)
        .await
        .unwrap();
    let fail = RunEvent::Fail {
        reason: "dropped".to_owned(),
        fingerprint: None,
    };
    transition_run(pool, first.id, by, &fail, NOW)
        .await
        .unwrap();
    enqueue_wake(pool, &wake(dev, Some(issue), "again"))
        .await
        .unwrap();
    let second = dispatch(pool, r, NOW).await.unwrap();
    assert_eq!(
        resume_session(pool, &second).await.unwrap(),
        None,
        "fresh by default"
    );

    let at = Scope::Project(project);
    crate::store::settings::set(pool, Key::ResumeUnfinished, at, "1", BY, NOW)
        .await
        .unwrap();
    let resumed = resume_session(pool, &second).await.unwrap();
    assert_eq!(resumed.as_deref(), Some("sess-1"));

    // A finished run is never continued.
    start_run(pool, second.id, by, None, NOW).await.unwrap();
    transition_run(pool, second.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    enqueue_wake(pool, &wake(dev, Some(issue), "third"))
        .await
        .unwrap();
    let third = dispatch(pool, r, NOW).await.unwrap();
    assert_eq!(resume_session(pool, &third).await.unwrap(), None);
}

#[tokio::test]
async fn the_context_is_the_first_usage_and_the_session_the_latest_start() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, project, r) = setup(pool).await;
    let issue = task(pool, project, IssueKind::Task, Some(1)).await;
    let run = run_of(pool, dev, issue, r).await;
    let chunks = [
        serde_json::json!({"type": "session_started", "id": "thread-1"}),
        serde_json::json!({"type": "usage_so_far", "input": 0, "output": 0, "cache_read": 0,
                           "cache_write": 0}),
        serde_json::json!({"type": "usage_so_far", "input": 1200, "output": 30,
                           "cache_read": 8000, "cache_write": 300}),
        serde_json::json!({"type": "usage", "input": 5000, "output": 900, "cache_read": 20000,
                           "cache_write": 300}),
        serde_json::json!({"type": "session_started", "id": "thread-2"}),
    ];
    for (seq, chunk) in chunks.iter().enumerate() {
        append_run_event(pool, run.id, r, seq as u64 + 1, chunk, NOW)
            .await
            .unwrap();
    }
    let run = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(run.context_tokens, Some(9500));
    assert_eq!(run.session_id.as_deref(), Some("thread-2"));
}

#[tokio::test]
async fn the_per_task_report_is_exact() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, project, r) = setup(pool).await;
    // Opus is priced at $3 / $15 / $0.30 per Mtok; haiku has no price.
    set_price(
        pool,
        Harness::Claude,
        "claude-opus",
        [3_000_000, 15_000_000, 300_000],
        BY,
        NOW,
    )
    .await
    .unwrap();
    let story = task(pool, project, IssueKind::Story, Some(5)).await;
    let chore = task(pool, project, IssueKind::Task, Some(1)).await;
    let by = AuditActor::Runner(r);
    let work = |run: Run, start: &'static str, end: &'static str, used: Usage| async move {
        start_run(pool, run.id, by, None, start).await.unwrap();
        let run = get_run(pool, run.id).await.unwrap().unwrap();
        record_run_usage(pool, &run, 1, &used, end).await.unwrap();
        transition_run(pool, run.id, by, &RunEvent::Succeed, end)
            .await
            .unwrap();
        // Transitions stamp the real clock; the fixture's times are set after.
        sqlx::query("UPDATE runs SET started_at = ?, ended_at = ? WHERE id = ?")
            .bind(start)
            .bind(end)
            .bind(run.id.0)
            .execute(pool)
            .await
            .unwrap();
    };
    let usage = |input, output, cache| Usage {
        input_tokens: input,
        output_tokens: output,
        cache_tokens: cache,
        cost_usd_micros: None,
    };
    // Two priced runs on the story: 60 s and 30 s.
    let first = run_of(pool, dev, story, r).await;
    work(
        first,
        "2026-10-22T10:00:00.000Z",
        "2026-10-22T10:01:00.000Z",
        usage(1_000_000, 100_000, 0),
    )
    .await;
    let second = run_of(pool, dev, story, r).await;
    work(
        second,
        "2026-10-22T10:02:00.000Z",
        "2026-10-22T10:02:30.000Z",
        usage(0, 0, 1_000_000),
    )
    .await;
    // One unpriced small run on the chore, then a subscription one.
    let third = run_of(pool, dev, chore, r).await;
    work(
        third,
        "2026-10-22T10:03:00.000Z",
        "2026-10-22T10:03:06.000Z",
        usage(9_000, 500, 0),
    )
    .await;
    set_billing(pool, Harness::Claude, Billing::Subscription, BY)
        .await
        .unwrap();
    let fourth = run_of(pool, dev, chore, r).await;
    work(
        fourth,
        "2026-10-22T10:04:00.000Z",
        "2026-10-22T10:04:04.000Z",
        usage(100, 10, 0),
    )
    .await;

    let tasks = task_costs(pool, CompanyId(1), None, NOW).await.unwrap();
    let keys: Vec<&str> = tasks.iter().map(|t| t.key.as_str()).collect();
    assert_eq!(keys, ["CIT-2", "CIT-3"], "most tokens first");
    let s = &tasks[0];
    assert_eq!(
        (s.runs, s.priced_runs, s.unpriced_runs, s.subscription_runs),
        (2, 2, 0, 0)
    );
    assert_eq!(
        (s.input_tokens, s.output_tokens, s.cache_tokens),
        (1_000_000, 100_000, 1_000_000)
    );
    // $3 + $1.50 + $0.30.
    assert_eq!(s.cost_usd_micros, 4_800_000);
    assert_eq!(
        (s.secs, s.points, s.tier.as_deref()),
        (90, Some(5), Some("standard"))
    );
    let c = &tasks[1];
    assert_eq!(
        (c.runs, c.priced_runs, c.unpriced_runs, c.subscription_runs),
        (2, 0, 1, 1)
    );
    assert_eq!(
        (c.cost_usd_micros, c.unpriced_tokens, c.subscription_tokens),
        (0, 9_500, 110)
    );
    assert_eq!((c.secs, c.tier.as_deref()), (10, Some("small")));
    let json = crate::store::gov::task_json(c);
    assert_eq!(json["cost_usd"], "0.000000");

    let since = task_costs(pool, CompanyId(1), Some("2099-01-01T00:00:00Z"), NOW).await;
    assert!(since.unwrap().is_empty());
    let bad = task_costs(pool, CompanyId(1), Some("yesterday"), NOW).await;
    assert!(matches!(bad, Err(Error::InvalidArgument(_))));
}
