//! Reservations, holds, corrections and removal.

use super::*;

async fn reserve(
    fx: &Fx,
    session: &str,
    subjects: &[(&str, &str)],
    tokens: i64,
    usd: i64,
    ttl: i64,
    now: &str,
) -> Reservation {
    let mut tx = crate::store::begin_write(&fx.app.pool).await.unwrap();
    let r = guard::reserve_in(&mut tx, session, subjects, tokens, usd, ttl, now)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    r
}

#[tokio::test]
async fn two_sessions_cannot_both_reserve_the_last_of_a_budget() {
    let fx = fx().await;
    let b = set(&fx, &bud("company", "7", "total", 1000)).await;
    let subjects = [("company", "7"), ("agent", "a1")];
    // Racing: exactly one of the two takes 600 of 1000.
    let (r1, r2) = tokio::join!(
        reserve(&fx, "s1", &subjects, 600, 0, 3600, NOW),
        reserve(&fx, "s2", &subjects, 600, 0, 3600, NOW)
    );
    let granted = [&r1, &r2]
        .iter()
        .filter(|r| ***r == Reservation::Granted)
        .count();
    assert_eq!(granted, 1, "{r1:?} {r2:?}");
    let denied = [r1, r2]
        .into_iter()
        .find_map(|r| match r {
            Reservation::Denied(v) => Some(v),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        denied.iter().map(|s| s.budget.id).collect::<Vec<_>>(),
        [b.id]
    );
    assert_eq!((denied[0].held, denied[0].left()), (600, 1000));
    let holder = if reserve(&fx, "s1", &subjects, 600, 0, 3600, NOW).await == Reservation::Granted {
        "s1"
    } else {
        "s2"
    };
    // The holder reserving again (a resume) is not counted against itself.
    assert_eq!(
        reserve(&fx, holder, &subjects, 900, 0, 3600, NOW).await,
        Reservation::Granted
    );
    let other = if holder == "s1" { "s2" } else { "s1" };
    assert!(matches!(
        reserve(&fx, other, &subjects, 200, 0, 3600, NOW).await,
        Reservation::Denied(_)
    ));
    // Releasing frees it.
    let mut c = fx.app.pool.acquire().await.unwrap();
    assert_eq!(guard::release_in(&mut c, holder).await.unwrap(), 1);
    drop(c);
    assert_eq!(
        reserve(&fx, other, &subjects, 1000, 0, 3600, NOW).await,
        Reservation::Granted
    );
}

#[tokio::test]
async fn a_hold_shrinks_as_the_session_spends_lapses_unreleased_and_a_warn_only_budget_never_blocks()
 {
    let fx = fx().await;
    set(&fx, &bud("company", "7", "total", 1000)).await;
    let mut soft = bud("agent", "a1", "total", 1);
    soft.hard_stop = false;
    set(&fx, &soft).await;
    let subjects = [("company", "7"), ("agent", "a1")];
    assert_eq!(
        reserve(&fx, "s1", &subjects, 600, 0, 3600, NOW).await,
        Reservation::Granted
    );
    // s1 spends 250: its hold is 350 and the budget has 750 left, 350 of it held.
    spend(&fx, "e1", 250, None, "2026-10-22T10:00:00.000Z", &[]).await;
    assert!(matches!(
        reserve(&fx, "s2", &subjects, 500, 0, 3600, NOW).await,
        Reservation::Denied(_)
    ));
    assert_eq!(
        reserve(&fx, "s2", &subjects, 400, 0, 3600, NOW).await,
        Reservation::Granted
    );
    // s2 never releases: after its ttl the hold lapses.
    let later = "2026-10-22T11:30:00.000Z";
    assert_eq!(
        reserve(&fx, "s3", &subjects, 400, 0, 60, later).await,
        Reservation::Granted
    );
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_budget_holds WHERE session = 's2'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(left, 0, "an expired hold is purged");
    // Dollars: a reservation for more than the dollar cap is denied; an exhausted budget denies even 0.
    let mut usd = bud("project", "p1", "day", 0);
    usd.usd_cap_micros = Some(100);
    set(&fx, &usd).await;
    assert!(matches!(
        reserve(&fx, "s4", &[("project", "p1")], 0, 101, 60, NOW).await,
        Reservation::Denied(_)
    ));
    assert_eq!(
        reserve(&fx, "s4", &[("project", "p1")], 0, 100, 60, NOW).await,
        Reservation::Granted
    );
    let mut c = fx.app.pool.acquire().await.unwrap();
    for (s, t, u, ttl, kind) in [
        ("", 1, 1, 60, "agent"),
        ("s", -1, 0, 60, "agent"),
        ("s", 1, 0, 0, "agent"),
        ("s", 1, 0, 60, "team"),
    ] {
        let r = guard::reserve_in(&mut c, s, &[(kind, "a1")], t, u, ttl, NOW).await;
        assert_eq!(code(r), "bad_request");
    }
}

#[tokio::test]
async fn a_correction_counts_in_the_period_of_the_event_it_corrects() {
    let fx = fx().await;
    let b = set(&fx, &bud("agent", "a1", "day", 1_000_000)).await;
    let first = spend(&fx, "e1", 100, Some(500), "2026-10-20T10:00:00.000Z", &[])
        .await
        .event;
    let mut c = fx.app.pool.acquire().await.unwrap();
    let fix = costs::correct_in(&mut c, first.id, 200, "bill-1", "2026-10-22T10:00:00.000Z")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fix.event.occurred_at, "2026-10-20T10:00:00.000Z");
    drop(c);
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT period_key, tokens, usd_micros FROM core_budget_spend WHERE budget_id = ?",
    )
    .bind(b.id)
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows, [("2026-10-20".to_owned(), 100, 200)]);
}

#[tokio::test]
async fn removing_a_budget_takes_its_counters_and_holds_and_a_list_filters_by_company() {
    let fx = fx().await;
    let mut a = bud("project", "p1", "day", 100);
    a.company = Some("7");
    let a = set(&fx, &a).await;
    let mut b = bud("project", "p2", "day", 100);
    b.company = Some("8");
    set(&fx, &b).await;
    set(&fx, &bud("agent", "a1", "day", 100)).await;
    spend(
        &fx,
        "e1",
        10,
        None,
        "2026-10-22T10:00:00.000Z",
        &[("project", "p1")],
    )
    .await;
    assert_eq!(
        reserve(&fx, "s1", &[("project", "p1")], 10, 0, 60, NOW).await,
        Reservation::Granted
    );
    let list = |kind: Option<&'static str>,
                subject: Option<&'static str>,
                company: Option<&'static str>| {
        let fx = &fx;
        async move {
            budgets::list(&fx.app.pool, kind, subject, company, NOW)
                .await
                .unwrap()
                .into_iter()
                .map(|s| s.budget.subject)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(list(None, None, None).await, ["p1", "p2", "a1"]);
    assert_eq!(list(None, None, Some("7")).await, ["p1"]);
    assert_eq!(list(Some("project"), None, None).await, ["p1", "p2"]);
    assert_eq!(list(Some("agent"), Some("a1"), None).await, ["a1"]);
    assert!(list(None, None, Some("9")).await.is_empty());
    assert!(
        budgets::remove(&fx.app.pool, a.id, &fx.dev.id, BY)
            .await
            .unwrap()
    );
    let rest: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_budget_spend WHERE budget_id = ?1) + \
                (SELECT count(*) FROM core_budget_holds WHERE budget_id = ?1)",
    )
    .bind(a.id)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rest, 0);
    // The ledger is untouched.
    let mut c = fx.app.pool.acquire().await.unwrap();
    assert_eq!(costs::totals(&mut c).await.unwrap().events, 1);
}

#[tokio::test]
async fn a_module_removes_a_subjects_or_a_companys_budgets_and_reads_who_owns_one() {
    let fx = fx().await;
    let mut a = bud("agent", "a1", "day", 10);
    a.company = Some("7");
    let a = set(&fx, &a).await;
    let mut b = bud("agent", "a1", "month", 10);
    b.company = Some("7");
    set(&fx, &b).await;
    let mut p = bud("project", "p1", "day", 10);
    p.company = Some("7");
    set(&fx, &p).await;
    set(&fx, &bud("project", "p2", "day", 10)).await;
    assert_eq!(
        budgets::company_of(&fx.app.pool, a.id).await.unwrap(),
        Some(Some("7".to_owned()))
    );
    assert_eq!(budgets::company_of(&fx.app.pool, 999).await.unwrap(), None);
    let p2 = budgets::list(&fx.app.pool, Some("project"), Some("p2"), None, NOW)
        .await
        .unwrap();
    assert_eq!(
        budgets::company_of(&fx.app.pool, p2[0].budget.id)
            .await
            .unwrap(),
        Some(None)
    );
    // standings_for reads the budgets any listed subject names, once each.
    let mut c = fx.app.pool.acquire().await.unwrap();
    let st = guard::standings_for(
        &mut c,
        &[("agent", "a1"), ("agent", "a1"), ("project", "p2")],
        NOW,
        "",
        false,
    )
    .await
    .unwrap();
    assert_eq!(st.len(), 3);
    // One subject's budgets, every period; then a company's, with what it owns.
    assert_eq!(
        budgets::remove_subject_in(&mut c, "agent", "a1", "test", BY)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        budgets::remove_company_in(&mut c, "7", "test", BY)
            .await
            .unwrap(),
        1
    );
    drop(c);
    let left: Vec<String> = budgets::list(&fx.app.pool, None, None, None, NOW)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.budget.subject)
        .collect();
    assert_eq!(left, ["p2"]);
    assert_eq!(actions(&fx, "budget.deleted").await.len(), 3);
}
