//! Run transitions through the state machine, with their audit events.

use citadel_core::audit::{AuditActor, AuditFilter};
use citadel_core::exec::{RunEvent, apply};

use super::*;
use crate::store::audit;

const NOW: &str = "2026-10-21T10:00:00.000Z";

async fn runner(pool: &SqlitePool, name: &str) -> RunnerId {
    let r = NewRunner {
        name: name.to_owned(),
        tags: vec![],
    };
    create_runner(pool, &r, name).await.unwrap().id
}

async fn run_audit(pool: &SqlitePool, id: RunId) -> Vec<String> {
    let filter = AuditFilter {
        run_id: Some(id),
        ..AuditFilter::default()
    };
    audit::list(pool, &filter, None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect()
}

fn cancel(why: &str) -> RunEvent {
    RunEvent::Cancel {
        reason: why.to_owned(),
    }
}

#[tokio::test]
async fn walks_to_success_stamping_columns_and_auditing_each_step() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let r = runner(pool, "mac").await;
    let id = create_run(pool, &new_run(dev, Some(i))).await.unwrap().id;
    let by = AuditActor::Runner(r);

    let claimed = transition_run(pool, id, by, &RunEvent::Claim { runner: r }, NOW)
        .await
        .unwrap();
    assert_eq!(
        (claimed.state, claimed.runner_id),
        (RunState::Claimed, Some(r))
    );
    assert!(claimed.claimed_at.is_some() && claimed.started_at.is_none());
    // `Start` only goes through `start_run`, which also issues the run's token.
    let start = RunEvent::Start { session: None };
    assert!(matches!(
        transition_run(pool, id, by, &start, NOW).await,
        Err(TransitionError::StartNeedsToken)
    ));
    let running = start_run(pool, id, by, Some("sess-1".to_owned()), NOW)
        .await
        .unwrap()
        .0;
    assert_eq!(running.session_id.as_deref(), Some("sess-1"));
    assert!(running.started_at.is_some());
    // A heartbeat changes nothing and is not audited.
    let beat = transition_run(pool, id, by, &RunEvent::Heartbeat, NOW)
        .await
        .unwrap();
    assert_eq!(beat, running);
    let fail = RunEvent::Fail {
        reason: "tests red".to_owned(),
        fingerprint: Some("test@verify".to_owned()),
    };
    let failed = transition_run(pool, id, by, &fail, NOW).await.unwrap();
    assert_eq!(failed.state, RunState::Failed);
    assert_eq!(failed.terminal_reason.as_deref(), Some("tests red"));
    assert_eq!(
        failed.failure_fingerprint.as_deref(),
        Some("failed:test@verify")
    );
    assert!(failed.ended_at.is_some());
    assert_eq!(get_run(pool, id).await.unwrap(), Some(failed));
    assert_eq!(
        run_audit(pool, id).await,
        [
            "run.claimed",
            "run.running",
            "run.token_issued",
            "run.failed"
        ]
    );

    // Terminal absorbs everything; nothing more is audited.
    assert!(matches!(
        transition_run(pool, id, by, &RunEvent::Succeed, NOW).await,
        Err(TransitionError::Illegal(_))
    ));
    assert_eq!(run_audit(pool, id).await.len(), 4);
    assert!(matches!(
        transition_run(pool, RunId(999), by, &RunEvent::Succeed, NOW).await,
        Err(TransitionError::NotFound)
    ));
}

#[tokio::test]
async fn cancel_before_dispatch_ends_terminal_with_its_reason() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let id = create_run(pool, &new_run(dev, Some(i))).await.unwrap().id;
    let run = transition_run(pool, id, AuditActor::System, &cancel("issue closed"), NOW)
        .await
        .unwrap();
    assert_eq!(run.state, RunState::Cancelled);
    assert_eq!(run.terminal_reason.as_deref(), Some("issue closed"));
    assert!(run.ended_at.is_some() && run.claimed_at.is_none());
    assert_eq!(run_audit(pool, id).await, ["run.cancelled"]);
    let event = &audit::list(pool, &AuditFilter::default(), None, 100)
        .await
        .unwrap()[0];
    assert_eq!(event.actor, AuditActor::System);
    assert_eq!(
        event.details,
        r#"{"from":"queued","event":"cancel","reason":"issue closed"}"#
    );
}

#[tokio::test]
async fn concurrent_transitions_on_one_run_have_exactly_one_winner() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let id = create_run(pool, &new_run(dev, Some(i))).await.unwrap().id;
    let mut runners = vec![];
    for n in 0..8 {
        runners.push(runner(pool, &format!("r{n}")).await);
    }
    let tasks: Vec<_> = runners
        .iter()
        .map(|&r| {
            let pool = pool.clone();
            tokio::spawn(async move {
                transition_run(
                    &pool,
                    id,
                    AuditActor::Runner(r),
                    &RunEvent::Claim { runner: r },
                    NOW,
                )
                .await
            })
        })
        .collect();
    let mut winners = vec![];
    for t in tasks {
        match t.await.unwrap() {
            Ok(run) => winners.push(run.runner_id),
            Err(TransitionError::Conflict | TransitionError::Illegal(_)) => {}
            Err(e) => panic!("unexpected {e}"),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(
        get_run(pool, id).await.unwrap().unwrap().runner_id,
        winners[0]
    );
    assert_eq!(run_audit(pool, id).await, ["run.claimed"]);
}

/// A run changed between the read and the write loses with `Conflict`, unaudited.
#[tokio::test]
async fn a_transition_from_a_stale_read_conflicts() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let id = create_run(pool, &new_run(dev, Some(i))).await.unwrap().id;
    // Another writer holds the lock with the run already moved on, uncommitted.
    let mut other = pool.begin().await.unwrap();
    sqlx::query("UPDATE runs SET state = 'claimed' WHERE id = ?")
        .bind(id.0)
        .execute(&mut *other)
        .await
        .unwrap();
    let racer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            transition_run(&pool, id, AuditActor::System, &cancel("stop"), NOW).await
        })
    };
    // Let the racer read `queued` and queue up behind the lock, then commit.
    tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(300)))
        .await
        .unwrap();
    other.commit().await.unwrap();
    assert!(matches!(
        racer.await.unwrap(),
        Err(TransitionError::Conflict)
    ));
    assert_eq!(
        get_run(pool, id).await.unwrap().unwrap().state,
        RunState::Claimed
    );
    assert!(run_audit(pool, id).await.is_empty());
}

#[tokio::test]
async fn a_failed_audit_rolls_the_transition_back() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let before = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    sqlx::query(
        "CREATE TRIGGER audit_down BEFORE INSERT ON audit_events \
         BEGIN SELECT RAISE(ABORT, 'audit down'); END",
    )
    .execute(pool)
    .await
    .unwrap();
    let err = transition_run(pool, before.id, AuditActor::System, &cancel("stop"), NOW)
        .await
        .unwrap_err();
    assert!(matches!(&err, TransitionError::Db(e) if is_raised(e, "audit down")));
    assert_eq!(
        get_run(pool, before.id).await.unwrap(),
        Some(before.clone())
    );
    sqlx::query("DROP TRIGGER audit_down")
        .execute(pool)
        .await
        .unwrap();
    assert!(run_audit(pool, before.id).await.is_empty());
}

/// Every (state, event) pair against a real row: the store agrees with the machine and
/// every stored row passes the schema's CHECKs (a violation would fail the update).
#[tokio::test]
async fn store_agrees_with_the_machine_for_every_state_and_event() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let r = runner(pool, "mac").await;
    let by = AuditActor::Runner(r);
    let claim = RunEvent::Claim { runner: r };
    let start = RunEvent::Start { session: None };
    let fail = RunEvent::Fail {
        reason: "boom".to_owned(),
        fingerprint: None,
    };
    let cancelled = cancel("stop");
    // How to reach each state from queued.
    let paths: Vec<Vec<&RunEvent>> = vec![
        vec![],
        vec![&claim],
        vec![&claim, &start],
        vec![&claim, &start, &RunEvent::Succeed],
        vec![&claim, &start, &fail],
        vec![&claim, &RunEvent::Timeout],
        vec![&claim, &RunEvent::RunnerLost],
        vec![&cancelled],
    ];
    let events = [
        claim.clone(),
        start.clone(),
        RunEvent::Heartbeat,
        RunEvent::Succeed,
        fail.clone(),
        RunEvent::Fail {
            reason: String::new(),
            fingerprint: None,
        },
        cancel("user"),
        cancel(" "),
        RunEvent::Timeout,
        RunEvent::RunnerLost,
        RunEvent::TokenCap,
    ];
    for path in &paths {
        for e in &events {
            let id = create_run(pool, &new_run(dev, Some(i))).await.unwrap().id;
            for step in path {
                go(pool, id, by, step).await.unwrap();
            }
            let from = get_run(pool, id).await.unwrap().unwrap();
            let got = go(pool, id, by, e).await;
            match apply(from.state, e) {
                Ok(t) => {
                    let run = got.unwrap();
                    assert_eq!(run.state, t.state, "{:?} {e:?}", from.state);
                    assert_eq!(run.terminal_reason, t.reason.map(|r| r.to_string()));
                    assert_eq!(run.state.is_terminal(), run.ended_at.is_some());
                }
                Err(_) => {
                    assert!(matches!(got, Err(TransitionError::Illegal(_))));
                    assert_eq!(get_run(pool, id).await.unwrap(), Some(from));
                }
            }
        }
    }
}

/// `transition_run`, except `Start`, which only `start_run` applies.
async fn go(
    pool: &SqlitePool,
    id: RunId,
    by: AuditActor,
    e: &RunEvent,
) -> Result<Run, TransitionError> {
    match e {
        RunEvent::Start { session } => start_run(pool, id, by, session.clone(), NOW)
            .await
            .map(|(run, _)| run),
        _ => transition_run(pool, id, by, e, NOW).await,
    }
}
