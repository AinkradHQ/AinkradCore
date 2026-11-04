//! The Core budget engine (KAN-448): limits per subject over calendar periods, counted in the
//! transaction that records a cost, warned once per period, reported as a stop mid-run, reserved
//! atomically for a new session, raised by an approved overrun, and audited.

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::store::accounts as acc;
use crate::store::budgets::guard::{self, Reservation};
use crate::store::budgets::{self, NewBudget};
use crate::store::costs::{self, NewCost};
use crate::store::pools;
use crate::store::secrets::Error;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

type Mutate = Box<dyn Fn(&mut NewBudget<'_>)>;

fn bud<'a>(kind: &'a str, subject: &'a str, period: &'a str, tokens: i64) -> NewBudget<'a> {
    NewBudget {
        kind,
        subject,
        company: None,
        period,
        token_cap: tokens,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    }
}

async fn set(fx: &Fx, b: &NewBudget<'_>) -> budgets::Budget {
    budgets::set(&fx.app.pool, b, &fx.dev.id, BY, NOW)
        .await
        .unwrap()
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

/// `tokens` input tokens at `at` by agent `a1` of company `7`, plus `extra` subjects.
async fn spend(
    fx: &Fx,
    key: &str,
    tokens: i64,
    usd: Option<i64>,
    at: &str,
    extra: &[(&str, &str)],
) -> costs::Recorded {
    let mut subjects = vec![("agent", "a1"), ("company", "7")];
    subjects.extend_from_slice(extra);
    let c = NewCost {
        session: "s1",
        epoch: 0,
        account_id: None,
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "m",
        input_tokens: tokens,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: usd,
        approximate: false,
        subjects: &subjects,
        idempotency_key: key,
        occurred_at: at,
    };
    costs::record(&fx.app.pool, &c, at).await.unwrap()
}

async fn standing(fx: &Fx, id: i64) -> budgets::Standing {
    budgets::standing_of(&fx.app.pool, id, NOW)
        .await
        .unwrap()
        .unwrap()
}

async fn actions(fx: &Fx, like: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE ? ORDER BY seq")
        .bind(like)
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_budget_is_created_changed_and_deleted_with_an_audit_row_and_validated() {
    let fx = fx().await;
    let a = set(&fx, &bud("agent", "a1", "day", 1000)).await;
    assert_eq!(
        (
            a.kind.as_str(),
            a.warn_at_percent,
            a.hard_stop,
            a.company.clone()
        ),
        ("agent", 80, true, None)
    );
    let again = set(&fx, &bud("agent", "a1", "day", 5000)).await;
    assert_eq!((again.id, again.token_cap), (a.id, 5000));
    // A company budget is its own company binding.
    let c = set(&fx, &bud("company", "7", "month", 10)).await;
    assert_eq!(c.company.as_deref(), Some("7"));
    let mut wrong = bud("company", "7", "week", 10);
    wrong.company = Some("8");
    assert_eq!(
        code(budgets::set(&fx.app.pool, &wrong, &fx.dev.id, BY, NOW).await),
        "bad_request"
    );
    // Another subject may carry its owner's company.
    let mut p = bud("project", "p1", "total", 10);
    p.company = Some("7");
    assert_eq!(set(&fx, &p).await.company.as_deref(), Some("7"));

    let bad: Vec<Mutate> = vec![
        Box::new(|b| b.kind = "team"),
        Box::new(|b| b.period = "hour"),
        Box::new(|b| b.subject = "has space"),
        Box::new(|b| b.subject = ""),
        Box::new(|b| b.token_cap = -1),
        Box::new(|b| b.usd_cap_micros = Some(-1)),
        Box::new(|b| b.warn_at_percent = Some(0)),
        Box::new(|b| b.warn_at_percent = Some(101)),
        Box::new(|b| b.company = Some("no good")),
    ];
    for f in bad {
        let mut b = bud("agent", "a9", "day", 1);
        f(&mut b);
        assert_eq!(
            code(budgets::set(&fx.app.pool, &b, &fx.dev.id, BY, NOW).await),
            "bad_request"
        );
    }
    // An account or a pool the Core owns must exist.
    assert_eq!(
        code(
            budgets::set(
                &fx.app.pool,
                &bud("account", "99", "day", 1),
                &fx.dev.id,
                BY,
                NOW
            )
            .await
        ),
        "not_found"
    );
    assert_eq!(
        code(
            budgets::set(
                &fx.app.pool,
                &bud("pool", "99", "day", 1),
                &fx.dev.id,
                BY,
                NOW
            )
            .await
        ),
        "not_found"
    );

    assert!(
        budgets::remove(&fx.app.pool, a.id, &fx.dev.id, BY)
            .await
            .unwrap()
    );
    assert!(
        !budgets::remove(&fx.app.pool, a.id, &fx.dev.id, BY)
            .await
            .unwrap()
    );
    assert_eq!(
        actions(&fx, "budget.%").await,
        [
            "budget.created",
            "budget.set",
            "budget.created",
            "budget.created",
            "budget.deleted"
        ]
    );
}

#[tokio::test]
async fn one_event_moves_the_counter_of_every_subject_it_names_in_the_period_it_happened() {
    let (fx, vm, s) = setup().await;
    let acct = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let pool = pools::create(&fx.app.pool, "main-pool", "anthropic", &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    pools::add_member(&fx.app.pool, pool.id, acct.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let (acct_id, pool_id) = (acct.id.to_string(), pool.id.to_string());
    let ids = [
        set(&fx, &bud("agent", "a1", "day", 10_000)).await.id,
        set(&fx, &bud("company", "7", "month", 10_000)).await.id,
        set(&fx, &bud("project", "p1", "week", 10_000)).await.id,
        set(&fx, &bud("department", "d2", "total", 10_000)).await.id,
        set(&fx, &bud("account", &acct_id, "day", 10_000)).await.id,
        set(&fx, &bud("pool", &pool_id, "day", 10_000)).await.id,
        set(&fx, &bud("sprint", "s9", "day", 10_000)).await.id,
    ];
    let named = [
        ("project", "p1"),
        ("department", "d1"),
        ("department", "d2"),
    ];
    let c = |key: &str, at: &str, tokens: i64| {
        let (fx, key, at, acct) = (&fx, key.to_owned(), at.to_owned(), acct.id);
        async move {
            let subjects: Vec<(&str, &str)> =
                [&[("agent", "a1"), ("company", "7")][..], &named].concat();
            let c = NewCost {
                session: "s1",
                epoch: 0,
                account_id: Some(acct),
                legacy_account_id: None,
                provider: "anthropic",
                harness: "claude",
                model: "m",
                input_tokens: tokens,
                output_tokens: 0,
                cache_tokens: 0,
                reported_usd_micros: Some(tokens * 10),
                approximate: false,
                subjects: &subjects,
                idempotency_key: &key,
                occurred_at: &at,
            };
            costs::record(&fx.app.pool, &c, &at).await.unwrap();
        }
    };
    // Thursday the 22nd, then Friday the 23rd, in the same week and month.
    c("e1", "2026-10-22T10:00:00.000Z", 100).await;
    c("e2", "2026-10-23T08:00:00.000Z", 40).await;
    let rows: Vec<(i64, String, i64, i64)> = sqlx::query_as(
        "SELECT budget_id, period_key, tokens, usd_micros FROM core_budget_spend ORDER BY budget_id, period_key",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    let key = |i: usize, k: &str, t: i64| (ids[i], k.to_owned(), t, t * 10);
    let want = vec![
        key(0, "2026-10-22", 100),
        key(0, "2026-10-23", 40),
        key(1, "2026-10", 140),
        key(2, "2026-10-19", 140),
        key(3, "total", 140),
        key(4, "2026-10-22", 100),
        key(4, "2026-10-23", 40),
        key(5, "2026-10-22", 100),
        key(5, "2026-10-23", 40),
    ];
    assert_eq!(rows, want);
    // A subject nobody budgeted (the sprint) has nothing, and an event that did not name it is not its.
    assert!(rows.iter().all(|r| r.0 != ids[6]));
}

#[tokio::test]
async fn a_budget_set_mid_period_counts_what_was_spent_and_recompute_repairs_the_counters() {
    let fx = fx().await;
    spend(&fx, "e1", 300, Some(30), "2026-10-22T08:00:00.000Z", &[]).await;
    spend(&fx, "e2", 200, Some(20), "2026-10-22T09:00:00.000Z", &[]).await;
    let b = set(&fx, &bud("agent", "a1", "day", 1000)).await;
    let st = standing(&fx, b.id).await;
    assert_eq!(
        (st.period_key.as_str(), st.spent, st.usd_spent, st.left()),
        ("2026-10-22", 500, 50, 500)
    );
    sqlx::query("UPDATE core_budget_spend SET tokens = 7")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(standing(&fx, b.id).await.spent, 7);
    assert_eq!(budgets::recompute(&fx.app.pool, BY).await.unwrap(), 1);
    assert_eq!(standing(&fx, b.id).await.spent, 500);
    // The same event again changes nothing: the retry is a no-op.
    spend(&fx, "e2", 200, Some(20), "2026-10-22T09:00:00.000Z", &[]).await;
    assert_eq!(standing(&fx, b.id).await.spent, 500);
}

#[tokio::test]
async fn a_warning_and_an_exhaustion_alert_once_per_period_and_a_hard_stop_is_reported() {
    let fx = fx().await;
    let mut b = bud("agent", "a1", "total", 1000);
    b.warn_at_percent = Some(50);
    let hard = set(&fx, &b).await;
    let mut soft_b = bud("company", "7", "total", 750);
    soft_b.hard_stop = false;
    let soft = set(&fx, &soft_b).await;
    let ev = |k: &'static str, n: i64| {
        let fx = &fx;
        async move {
            spend(fx, k, n, None, "2026-10-22T10:00:00.000Z", &[])
                .await
                .guard
        }
    };
    let ids = |v: &[budgets::Standing]| v.iter().map(|s| s.budget.id).collect::<Vec<_>>();
    let g = ev("e1", 400).await;
    assert!(g.warned.is_empty() && g.stop.is_empty());
    // 600 spent: past 50% of the agent's 1000 and 80% (the default) of the company's 750.
    let g = ev("e2", 200).await;
    assert_eq!(ids(&g.warned), [hard.id, soft.id]);
    assert!(g.newly_exhausted.is_empty() && g.stop.is_empty());
    assert!(ev("e3", 100).await.warned.is_empty(), "once per period");
    // 760: the soft company budget ran out (an alert, no stop); 1160: the hard one.
    let g = ev("e4", 60).await;
    assert_eq!(ids(&g.newly_exhausted), [soft.id]);
    assert!(g.stop.is_empty(), "a budget that only warns stops nobody");
    let g = ev("e5", 400).await;
    assert_eq!(ids(&g.newly_exhausted), [hard.id]);
    assert_eq!(ids(&g.stop), [hard.id]);
    // Still exhausted: told to stop again, but not alerted again.
    let g = ev("e6", 1).await;
    assert!(g.newly_exhausted.is_empty());
    assert_eq!(ids(&g.stop), [hard.id]);
    assert_eq!(actions(&fx, "budget.warning").await.len(), 2);
    assert_eq!(actions(&fx, "budget.exhausted").await.len(), 2);
    // The next period is a fresh counter with a fresh alert: a day-budget warns again tomorrow.
    let day = set(&fx, &bud("agent", "a1", "day", 100)).await;
    let g = spend(&fx, "d1", 90, None, "2026-10-23T09:00:00.000Z", &[])
        .await
        .guard;
    assert!(g.warned.iter().any(|s| s.budget.id == day.id));
    let g = spend(&fx, "d2", 90, None, "2026-10-24T09:00:00.000Z", &[])
        .await
        .guard;
    assert!(g.warned.iter().any(|s| s.budget.id == day.id));
}

#[tokio::test]
async fn a_dollars_only_budget_runs_out_in_dollars() {
    let fx = fx().await;
    let mut b = bud("agent", "a1", "day", 0);
    b.usd_cap_micros = Some(1000);
    let id = set(&fx, &b).await.id;
    let g = spend(
        &fx,
        "e1",
        5_000_000,
        Some(600),
        "2026-10-22T10:00:00.000Z",
        &[],
    )
    .await
    .guard;
    assert!(g.stop.is_empty(), "no token limit");
    let g = spend(&fx, "e2", 1, Some(500), "2026-10-22T10:01:00.000Z", &[])
        .await
        .guard;
    assert_eq!(g.stop.len(), 1);
    let st = standing(&fx, id).await;
    assert!(st.dollars_only() && st.exhausted());
    assert_eq!((st.usd_left(), st.left()), (Some(-100), i64::MAX));
}

#[tokio::test]
async fn an_approved_raise_lifts_the_stop_and_the_next_exhaustion_alerts_again() {
    let fx = fx().await;
    let b = set(&fx, &bud("agent", "a1", "total", 100)).await;
    let at = "2026-10-22T10:00:00.000Z";
    assert_eq!(
        spend(&fx, "e1", 100, None, at, &[]).await.guard.stop.len(),
        1
    );
    let mut tx = crate::store::begin_write(&fx.app.pool).await.unwrap();
    guard::raise_in(&mut tx, b.id, "total", 50, 0, &fx.dev.id, BY)
        .await
        .unwrap();
    for (id, key, t, u) in [
        (b.id, "total", 0, 0),
        (b.id, "total", -1, 5),
        (b.id, "x y", 1, 0),
        (b.id, "", 1, 0),
    ] {
        assert_eq!(
            code(guard::raise_in(&mut tx, id, key, t, u, &fx.dev.id, BY).await),
            "bad_request"
        );
    }
    assert_eq!(
        code(guard::raise_in(&mut tx, 999, "total", 1, 0, &fx.dev.id, BY).await),
        "not_found"
    );
    tx.commit().await.unwrap();
    let st = standing(&fx, b.id).await;
    assert_eq!((st.raised, st.left(), st.exhausted()), (50, 50, false));
    let g = spend(&fx, "e2", 50, None, at, &[]).await.guard;
    assert_eq!((g.newly_exhausted.len(), g.stop.len()), (1, 1));
    assert_eq!(actions(&fx, "budget.raised").await.len(), 1);
    assert_eq!(actions(&fx, "budget.exhausted").await.len(), 2);
}

mod holds;
mod pool_budgets;
