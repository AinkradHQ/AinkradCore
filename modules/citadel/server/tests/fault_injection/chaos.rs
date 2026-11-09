//! Scenario 9: dispatchers, ticks, reapers, renewals, run ends and reassignments interleaved on a
//! seeded schedule, with bursts that run several of them concurrently; the invariants are
//! checked after every step, and at the end that the ticks' repairs (E15.8) never looped.

use citadel_core::audit::AuditActor;
use citadel_core::exec::{Run, RunEvent, RunState, RunnerId, StuckKind};
use citadel_core::org::{AgentId, AgentStatus, Harness};
use citadel_core::work::{IssueId, IssueTransition, NextActor, UserId};
use citadel_server::store::exec::{
    dispatch_next, enqueue_wake, list_runs, reap_expired_leases, renew_lease, schedule_retry,
    set_agent_timer, tick,
};
use citadel_server::store::org::{get_agent, update_agent};
use citadel_server::store::work::{checkout_issue, get_issue, transition_issue};
use sqlx::SqlitePool;

use super::harness::*;
use crate::wake;

const STEPS: usize = 200;
const SEEDS: [u64; 3] = [0x5EED, 0x0C17_ADE1, 42];

/// Idle issues an agent was handed but never re-woken (a run ended without a retry, or the
/// caller never asked for one) and agents the breaker paused are reported, with reasons;
/// nothing else may be.
const EXPECTED: &[StuckKind] = &[
    StuckKind::TodoIdle,
    StuckKind::InProgressIdle,
    StuckKind::AgentPausedByBreaker,
];

struct World {
    agents: Vec<AgentId>,
    issues: Vec<IssueId>,
    runners: Vec<RunnerId>,
}

async fn live_runs(pool: &SqlitePool, w: &World) -> Vec<Run> {
    let mut live = vec![];
    for a in &w.agents {
        let runs = list_runs(pool, *a).await.unwrap();
        live.extend(runs.into_iter().filter(|r| !r.state.is_terminal()));
    }
    live
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seeded_interleavings_keep_every_invariant() {
    for seed in SEEDS {
        chaos(seed).await;
    }
}

async fn chaos(seed: u64) {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let mut rng = Rng::new(seed);
    let (c, p) = company(pool, "A").await;
    let lead = agent(pool, c, "Lead", &[], None).await;
    let mut w = World {
        agents: vec![lead],
        issues: vec![],
        runners: vec![],
    };
    for n in 0..2 {
        w.agents
            .push(agent(pool, c, &format!("Dev{n}"), &[], Some(lead)).await);
    }
    set_agent_timer(pool, w.agents[1], Some(900)).await.unwrap();
    for _ in 0..4 {
        let i = issue(pool, p).await;
        assign(pool, i, w.agents[1 + w.issues.len() % 2]).await;
        w.issues.push(i);
    }
    for n in 0..3 {
        w.runners.push(runner(pool, &format!("mac{n}"), &[]).await);
    }

    for n in 0..STEPS {
        let action = rng.below(13);
        let now = clock.now();
        eprintln!("seed {seed:#x} step {n} t+{}s action {action}", clock.secs);
        match action {
            0 => {
                let a = w.agents[rng.below(w.agents.len())];
                let i = match rng.below(5) {
                    4 => None,
                    k => Some(w.issues[k]),
                };
                let key = format!("chaos:{}", rng.below(150));
                enqueue_wake(pool, &wake(a, i, &key)).await.unwrap();
            }
            1 | 2 => {
                let r = w.runners[rng.below(w.runners.len())];
                dispatch_next(pool, r, &[], &Harness::ALL, &now)
                    .await
                    .unwrap();
            }
            3 => {
                let live = live_runs(pool, &w).await;
                if let Some(run) = pick(&mut rng, &live) {
                    let event = match (run.state, rng.below(6)) {
                        (RunState::Claimed, 0..=2) => RunEvent::Start { session: None },
                        (RunState::Running, 0 | 1) => RunEvent::Succeed,
                        (_, 0..=2) => fail(["E1@build", "E2@test"][rng.below(2)]),
                        (_, 3) => RunEvent::Timeout,
                        (_, 4) => RunEvent::Cancel {
                            reason: "chaos".to_owned(),
                        },
                        _ => RunEvent::Heartbeat,
                    };
                    let ended = step(pool, run, event, &now).await;
                    // A caller that retries most of the time, and sometimes never does.
                    if ended.state.is_terminal() && rng.below(4) != 0 {
                        schedule_retry(pool, ended.id, &now).await.unwrap();
                    }
                }
            }
            4 | 5 => {
                let live = live_runs(pool, &w).await;
                if let Some(run) = pick(&mut rng, &live) {
                    // Refused once expired: the runner is lost for good.
                    let _ = renew_lease(pool, run.id, run.runner_id.unwrap(), &now).await;
                }
            }
            6 => {
                let live = live_runs(pool, &w).await;
                if let Some(run) = pick(&mut rng, &live)
                    && let Some(i) = run.issue_id
                {
                    // Conflict and not-checkable are answers, not faults.
                    let _ = checkout_issue(pool, i, run.id, &now).await;
                }
            }
            7 | 8 => {
                clock.advance(1 + rng.below(60) as i64);
            }
            9 => {
                tick(pool, &now).await.unwrap();
            }
            10 => burst(pool, &w, &now).await,
            11 => {
                // A human resumes an agent the loop breaker paused.
                let a = w.agents[rng.below(w.agents.len())];
                let mut agent = get_agent(pool, a).await.unwrap().unwrap();
                agent.status = AgentStatus::Active;
                update_agent(pool, &agent).await.unwrap();
            }
            _ => {
                let i = w.issues[rng.below(w.issues.len())];
                let open = !get_issue(pool, i)
                    .await
                    .unwrap()
                    .unwrap()
                    .state
                    .is_terminal();
                let next = NextActor::Agent(w.agents[rng.below(w.agents.len())]);
                let t = match (open, rng.below(3)) {
                    (true, 0) => IssueTransition::Cancel,
                    (true, _) => IssueTransition::Reassign { next },
                    (false, _) => IssueTransition::Reopen { next },
                };
                let by = AuditActor::User(UserId(1));
                transition_issue(pool, i, &t, by).await.unwrap();
            }
        }
        assert_invariants(pool, &clock.now(), EXPECTED).await;
    }
    no_repair_loops(pool, seed).await;
}

/// The ticks repaired what got stuck (E15.8) and never looped: the whole run is well inside one
/// repair window, so no issue got more than its budget of repairs, and at most one hand-off
/// to the admin.
async fn no_repair_loops(pool: &SqlitePool, seed: u64) {
    let per_issue: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT entity_id, sum(action <> 'repair.exhausted'), sum(action = 'repair.exhausted') \
         FROM audit_events WHERE entity_kind = 'issue' AND action LIKE 'repair.%' \
         GROUP BY entity_id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    eprintln!("seed {seed:#x}: repairs per issue (issue, repairs, hand-offs) {per_issue:?}");
    for (issue, repairs, handoffs) in per_issue {
        let budget = citadel_core::settings::Key::RepairBudget.default();
        assert!(repairs <= budget, "issue {issue}: {repairs} repairs");
        assert!(handoffs <= 1, "issue {issue}: {handoffs} hand-offs");
    }
}

fn pick<'a>(rng: &mut Rng, runs: &'a [Run]) -> Option<&'a Run> {
    (!runs.is_empty()).then(|| &runs[rng.below(runs.len())])
}

/// Two ticks, a bare reaper and every runner dispatching, all at once.
async fn burst(pool: &SqlitePool, w: &World, now: &str) {
    let mut tasks = vec![];
    for r in &w.runners {
        let (pool, r, now) = (pool.clone(), *r, now.to_owned());
        tasks.push(tokio::spawn(async move {
            dispatch_next(&pool, r, &[], &Harness::ALL, &now)
                .await
                .unwrap();
        }));
    }
    for n in 0..3 {
        let (pool, now) = (pool.clone(), now.to_owned());
        tasks.push(tokio::spawn(async move {
            if n == 2 {
                reap_expired_leases(&pool, &now).await.unwrap();
            } else {
                tick(&pool, &now).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}
