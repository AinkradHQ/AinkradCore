//! E7-2: the 5-hour window (`hour5`) and the message cap of a budget.

use super::*;

#[tokio::test]
async fn hour5_buckets_are_five_hours_from_the_unix_epoch_not_from_midnight() {
    let fx = fx().await;
    let b = set(&fx, &bud("agent", "a1", "hour5", 1000)).await;
    // 2026-11-18T20:00Z is a bucket start (1795032000 = 99724 * 18000); it ends at 01:00Z.
    spend(&fx, "h1", 10, None, "2026-11-18T21:00:00.000Z", &[]).await;
    spend(&fx, "h2", 20, None, "2026-11-18T23:30:00.000Z", &[]).await;
    spend(&fx, "h3", 40, None, "2026-11-19T01:30:00.000Z", &[]).await;
    let at = |t: &'static str| {
        let fx = &fx;
        async move {
            budgets::standing_of(&fx.app.pool, b.id, t)
                .await
                .unwrap()
                .unwrap()
        }
    };
    let first = at("2026-11-18T22:00:00.000Z").await;
    assert_eq!(
        (first.period_key.as_str(), first.spent),
        ("2026-11-18T20:00Z", 30)
    );
    let second = at("2026-11-19T02:00:00.000Z").await;
    assert_eq!(
        (second.period_key.as_str(), second.spent),
        ("2026-11-19T01:00Z", 40)
    );
    assert_eq!(
        budgets::period_end("hour5", &first.period_start()).as_deref(),
        Some("2026-11-19T01:00:00.000Z")
    );
}

#[tokio::test]
async fn a_message_cap_counts_one_per_cost_event_warns_and_stops_like_a_token_cap() {
    let fx = fx().await;
    let mut b = bud("agent", "a1", "hour5", 0);
    b.message_cap = Some(4);
    b.warn_at_percent = Some(50);
    let made = set(&fx, &b).await;
    assert_eq!(made.message_cap, Some(4));
    let at = "2026-11-18T21:00:00.000Z";
    // Huge token counts do not matter: a messages-only budget has no token limit.
    let g = spend(&fx, "m1", 5_000_000, None, at, &[]).await.guard;
    assert!(g.warned.is_empty() && g.stop.is_empty());
    let g = spend(&fx, "m2", 1, None, at, &[]).await.guard;
    assert_eq!(g.warned.len(), 1, "2 of 4 is 50%");
    // The same event again is a retry, not a message.
    spend(&fx, "m2", 1, None, at, &[]).await;
    let g = spend(&fx, "m3", 1, None, at, &[]).await.guard;
    assert!(g.warned.is_empty() && g.stop.is_empty());
    let g = spend(&fx, "m4", 1, None, at, &[]).await.guard;
    assert_eq!(g.newly_exhausted.len(), 1);
    assert_eq!(
        g.stop.len(),
        1,
        "the fourth message used the cap: the session stops"
    );
    let st = budgets::standing_of(&fx.app.pool, made.id, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((st.messages, st.messages_left()), (4, Some(0)));
    assert!(
        st.exhausted() && !st.has_room(0, 0),
        "a new session is not admitted"
    );
    // A recount from the ledger gives the same number.
    sqlx::query("UPDATE core_budget_spend SET messages = 99")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    budgets::recompute(&fx.app.pool, BY).await.unwrap();
    let st = budgets::standing_of(&fx.app.pool, made.id, at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st.messages, 4);
}

#[tokio::test]
async fn a_message_cap_is_validated_and_several_windows_may_stand_on_one_account() {
    let fx = fx().await;
    let mut none = bud("agent", "a1", "day", 0);
    assert_eq!(
        code(budgets::set(&fx.app.pool, &none, &fx.dev.id, BY, NOW).await),
        "bad_request",
        "no cap at all"
    );
    none.message_cap = Some(0);
    assert_eq!(
        code(budgets::set(&fx.app.pool, &none, &fx.dev.id, BY, NOW).await),
        "bad_request",
        "a zero message cap"
    );
    let mut week = bud("agent", "a1", "week", 0);
    week.message_cap = Some(900);
    let mut five = bud("agent", "a1", "hour5", 0);
    five.message_cap = Some(60);
    let (w, f) = (set(&fx, &week).await, set(&fx, &five).await);
    assert_ne!(w.id, f.id);
    let all = budgets::list(&fx.app.pool, Some("agent"), Some("a1"), None, NOW)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    // Changing the cap of one window leaves the other alone.
    five.message_cap = Some(120);
    assert_eq!(set(&fx, &five).await.message_cap, Some(120));
}
