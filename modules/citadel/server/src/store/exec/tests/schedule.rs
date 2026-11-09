//! The scheduler's tick: timers fire once per interval and only with work to do; the tick
//! also reaps expired leases.

use super::flow::set;
use super::lease::{assigned, working};
use super::wake::{dispatch, runner};
use super::*;

const HOUR: i64 = 3600;

async fn timer_keys(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT idempotency_key FROM wake_requests WHERE source = 'timer' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn an_idle_timer_agent_does_not_run() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    assert!(set_agent_timer(pool, dev, Some(HOUR)).await.unwrap());
    let at = "2026-10-21T10:00:00.000Z";
    let report = tick(pool, at).await.unwrap();
    assert_eq!((report.woken, report.idle), (vec![], vec![dev]));
    assert_eq!(timer_keys(pool).await, Vec::<String>::new());
    assert_eq!(dispatch(pool, mac, at).await, None);

    // Work arrives: the skipped slot is still due and fires on the next tick.
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    let report = tick(pool, "2026-10-21T10:00:05.000Z").await.unwrap();
    assert_eq!(report.woken.len(), 1);
    // A blocked issue is not work: it waits on its blockers.
    let (other, j) = fixture(pool, "B").await;
    set_agent_timer(pool, other, Some(HOUR)).await.unwrap();
    set(pool, j, IssueState::Blocked, Some(NextActor::Agent(other))).await;
    let report = tick(pool, "2026-10-21T10:00:10.000Z").await.unwrap();
    assert_eq!((report.woken, report.idle), (vec![], vec![other]));
}

#[tokio::test]
async fn an_agent_with_work_gets_exactly_one_timer_wake_per_interval() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    set_agent_timer(pool, dev, Some(HOUR)).await.unwrap();
    let mut woken = vec![];
    for at in [
        "2026-10-21T10:00:00.000Z",
        "2026-10-21T10:00:00.000Z",
        "2026-10-21T10:30:00.000Z",
        "2026-10-21T10:59:59.999Z",
        "2026-10-21T11:00:00.000Z",
        "2026-10-21T11:45:00.000Z",
    ] {
        let report = tick(pool, at).await.unwrap();
        assert_eq!(report.idle, vec![], "{at}");
        woken.extend(report.woken.into_iter().map(|w| (at, w)));
    }
    let fired: Vec<_> = woken.iter().map(|(at, _)| *at).collect();
    assert_eq!(
        fired,
        vec!["2026-10-21T10:00:00.000Z", "2026-10-21T11:00:00.000Z"]
    );
    let (_, first) = &woken[0];
    assert_eq!(
        (first.source, first.agent_id, first.issue_id, first.status),
        (WakeSource::Timer, dev, None, WakeStatus::Pending)
    );
    // 10:00Z is slot 497938 of an hour since the epoch; 11:00Z the next.
    assert_eq!(
        timer_keys(pool).await,
        vec![
            format!("timer:agent:{}:slot:497938", dev.0),
            format!("timer:agent:{}:slot:497939", dev.0),
        ]
    );
    // The second folds into the first while it still waits: one run, not two.
    assert_eq!(woken[1].1.coalesced_into, Some(first.id));
    // A paused agent's timer does not fire.
    sqlx::query("UPDATE agents SET status = 'paused' WHERE id = ?")
        .bind(dev.0)
        .execute(pool)
        .await
        .unwrap();
    let report = tick(pool, "2026-10-21T12:00:00.000Z").await.unwrap();
    assert_eq!((report.woken, report.idle), (vec![], vec![]));
}

#[tokio::test]
async fn an_agent_not_opted_in_is_never_timer_woken() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::InProgress, Some(NextActor::Agent(dev))).await;
    set_agent_timer(pool, dev, Some(60)).await.unwrap();
    set_agent_timer(pool, dev, None).await.unwrap();
    for h in 10..14 {
        let report = tick(pool, &format!("2026-10-21T{h}:00:00.000Z"))
            .await
            .unwrap();
        assert_eq!((report.woken, report.idle), (vec![], vec![]));
    }
    assert_eq!(timer_keys(pool).await, Vec::<String>::new());
    // A zero or negative interval is refused.
    assert!(set_agent_timer(pool, dev, Some(0)).await.is_err());
}

#[tokio::test]
async fn a_tick_reaps_expired_leases() {
    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let run = working(pool, mac, "2026-10-21T10:00:00.000Z").await;
    let report = tick(pool, "2026-10-21T10:01:00.000Z").await.unwrap();
    assert_eq!(report.reaped, vec![]);
    // Lapsed at 10:01:30 but inside the grace: the run is still live.
    let report = tick(pool, "2026-10-21T10:01:30.000Z").await.unwrap();
    assert_eq!(report.reaped, vec![]);
    let report = tick(pool, "2026-10-21T10:06:30.000Z").await.unwrap();
    assert_eq!(report.reaped.len(), 1);
    assert_eq!(report.reaped[0].run_id, run.id);
    assert!(matches!(
        tick(pool, "soon").await,
        Err(LeaseError::Db(Error::InvalidArgument(_)))
    ));
}
