//! Scenario 10 (E15.8): the stuck detector's automatic repairs under chaos. Over 200 seeded
//! steps hours apart, agents ignore their wakes, runners go offline, runs fail or vanish and
//! issues change hands, with a tick at every other step. After every step the invariants hold;
//! at the end no issue got more than its budget of repairs in any window, nor more than one
//! hand-off to the admin per window: repairs never loop.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{Run, RunEvent, RunState, RunnerId, StuckKind};
use ainkrad_core::org::{AgentId, Harness};
use ainkrad_core::settings::Key;
use ainkrad_core::work::{IssueId, IssueTransition, NextActor};
use ainkrad_core_server::store::exec::{dispatch_next, list_runs, tick};
use ainkrad_core_server::store::work::{get_issue, transition_issue};
use sqlx::SqlitePool;

use super::harness::*;

const STEPS: usize = 200;
const SEEDS: [u64; 3] = [7, 0x0BAD_5EED, 99];

/// What may be reported stuck between repairs.
const EXPECTED: &[StuckKind] = &[
    StuckKind::TodoIdle,
    StuckKind::InProgressIdle,
    StuckKind::ReviewNoReviewer,
    StuckKind::WakeNoRunner,
    StuckKind::AgentPausedByBreaker,
];

#[tokio::test]
async fn repairs_never_loop_under_chaos() {
    for seed in SEEDS {
        chaos(seed).await;
    }
}

async fn live(pool: &SqlitePool, agents: &[AgentId]) -> Vec<Run> {
    let mut all = vec![];
    for a in agents {
        let runs = list_runs(pool, *a).await.unwrap();
        all.extend(runs.into_iter().filter(|r| !r.state.is_terminal()));
    }
    all
}

async fn chaos(seed: u64) {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let mut rng = Rng::new(seed);
    let (c, p) = company(pool, "A").await;
    let lead = agent(pool, c, "Lead", &[], None).await;
    let devs = [
        agent(pool, c, "Dev", &[], Some(lead)).await,
        // Only the GPU runner serves it, and that one comes and goes.
        agent(pool, c, "Gpu", &["gpu"], Some(lead)).await,
    ];
    let agents = [lead, devs[0], devs[1]];
    let mut issues: Vec<IssueId> = vec![];
    for n in 0..4 {
        let i = issue(pool, p).await;
        assign(pool, i, devs[n % 2]).await;
        issues.push(i);
    }
    let runners: [RunnerId; 2] = [
        runner(pool, "cpu", &[]).await,
        runner(pool, "gpu", &["gpu"]).await,
    ];

    for n in 0..STEPS {
        let now = clock.now();
        let action = rng.below(8);
        eprintln!("seed {seed} step {n} t+{}s action {action}", clock.secs);
        match action {
            0 => {
                clock.advance(600 + rng.below(3 * 3600) as i64);
            }
            1 | 2 => {
                tick(pool, &now).await.unwrap();
            }
            3 => {
                let r = runners[rng.below(2)];
                if let Some(run) = dispatch_next(pool, r, &[], &Harness::ALL, &now)
                    .await
                    .unwrap()
                {
                    // Started, then left running: it ends later, or its lease runs out.
                    step(pool, &run, RunEvent::Start { session: None }, &now).await;
                }
            }
            4 => {
                let runs = live(pool, &agents).await;
                if !runs.is_empty() {
                    let run = &runs[rng.below(runs.len())];
                    let event = match (run.state, rng.below(3)) {
                        (RunState::Running, 0) => RunEvent::Succeed,
                        (_, 1) => fail("E1@build"),
                        _ => RunEvent::Cancel {
                            reason: "chaos".to_owned(),
                        },
                    };
                    step(pool, run, event, &now).await;
                }
            }
            5 => {
                // An agent that ignores its wakes.
                let a = agents[rng.below(agents.len())];
                sqlx::query(
                    "UPDATE wake_requests SET status = 'dropped', \
                     dropped_reason = 'chaos: ignored' WHERE agent_id = ? AND status = 'pending'",
                )
                .bind(a.0)
                .execute(pool)
                .await
                .unwrap();
            }
            6 => {
                // The GPU runner goes offline or comes back.
                sqlx::query(
                    "UPDATE runners SET status = CASE status WHEN 'online' THEN 'offline' \
                     ELSE 'online' END WHERE id = ?",
                )
                .bind(runners[1].0)
                .execute(pool)
                .await
                .unwrap();
            }
            _ => {
                let i = issues[rng.below(issues.len())];
                let open = !get_issue(pool, i)
                    .await
                    .unwrap()
                    .unwrap()
                    .state
                    .is_terminal();
                let next = NextActor::Agent(agents[rng.below(agents.len())]);
                let t = match open {
                    true => IssueTransition::Reassign { next },
                    false => IssueTransition::Reopen { next },
                };
                transition_issue(pool, i, &t, AuditActor::System)
                    .await
                    .unwrap();
            }
        }
        assert_invariants(pool, &clock.now(), EXPECTED).await;
    }
    no_loops(pool, seed).await;
}

/// Within any repair window ending at a repair, an issue had at most its budget of repairs
/// and one hand-off to the admin.
async fn no_loops(pool: &SqlitePool, seed: u64) {
    let window = Key::RepairWindowSecs.default();
    let worst: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT e.entity_id, \
         (SELECT count(*) FROM audit_events o WHERE o.entity_kind = 'issue' \
             AND o.entity_id = e.entity_id AND o.action LIKE 'repair.%' \
             AND o.action <> 'repair.exhausted' \
             AND julianday(json_extract(o.details, '$.at')) \
                 > julianday(json_extract(e.details, '$.at'), ?1) \
             AND o.seq <= e.seq), \
         (SELECT count(*) FROM audit_events o WHERE o.entity_kind = 'issue' \
             AND o.entity_id = e.entity_id AND o.action = 'repair.exhausted' \
             AND julianday(json_extract(o.details, '$.at')) \
                 > julianday(json_extract(e.details, '$.at'), ?1) \
             AND o.seq <= e.seq) \
         FROM audit_events e WHERE e.entity_kind = 'issue' AND e.action LIKE 'repair.%'",
    )
    .bind(format!("-{window} seconds"))
    .fetch_all(pool)
    .await
    .unwrap();
    let total = worst.len();
    eprintln!("seed {seed}: {total} repairs");
    assert!(total > 0, "seed {seed}: the chaos never needed a repair");
    for (issue, repairs, handoffs) in worst {
        assert!(
            repairs <= Key::RepairBudget.default(),
            "seed {seed}: issue {issue} had {repairs} repairs in one window"
        );
        assert!(
            handoffs <= 1,
            "seed {seed}: issue {issue}: {handoffs} hand-offs"
        );
    }
}
