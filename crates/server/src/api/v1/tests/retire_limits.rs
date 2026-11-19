//! E7 closeout: migration 0049 turns stored account limits into budgets and drops the table.

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};

#[tokio::test]
async fn stored_limits_become_budgets_and_the_table_goes() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let p = &fx.app.pool;
    undo(p, CORE, CORE_MIGRATIONS, 48).await.unwrap();
    // A budget the account already has for `week`: a stricter cap and a soft stop.
    sqlx::query(
        "INSERT INTO core_budgets (subject_kind, subject_id, period, token_cap, warn_at_percent, \
         hard_stop, created_at, updated_at) VALUES ('account', ?, 'week', 100, 90, 0, ?, ?)",
    )
    .bind(a.id.to_string())
    .bind(NOW)
    .bind(NOW)
    .execute(p)
    .await
    .unwrap();
    // Five hours of tokens and messages, and a 1000-second window (shorter than any period: it takes
    // the shortest, hour5), merge into one hour5 budget with the smaller token cap; a day of messages
    // and a 2-day window of tokens (next shorter period: day) merge into one day budget; a 7-day cap
    // above the existing week budget's loses to it, and its hard stop wins.
    for (unit, win, cap, warn) in [
        ("tokens", 18000, 500, Some(70)),
        ("messages", 18000, 40, None),
        ("messages", 86400, 90, None),
        ("tokens", 1000, 5, None),
        ("tokens", 172_800, 7, None),
        ("tokens", 604_800, 300, None),
    ] {
        sqlx::query(
            "INSERT INTO core_account_limits (account_id, unit, window_secs, cap, warn_percent) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(a.id)
        .bind(unit)
        .bind(win)
        .bind(cap)
        .bind(warn)
        .execute(p)
        .await
        .unwrap();
    }
    migrate_core(p).await.unwrap();
    let rows: Vec<(String, i64, Option<i64>, i64, i64)> = sqlx::query_as(
        "SELECT period, token_cap, message_cap, warn_at_percent, hard_stop FROM core_budgets \
         WHERE subject_kind = 'account' AND subject_id = ? ORDER BY period",
    )
    .bind(a.id.to_string())
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            ("day".to_owned(), 7, Some(90), 80, 1),
            ("hour5".to_owned(), 5, Some(40), 70, 1),
            ("week".to_owned(), 100, None, 80, 1)
        ]
    );
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = 'core_account_limits'")
            .fetch_one(p)
            .await
            .unwrap();
    assert_eq!(left, 0);
    // The audit rows come from the startup step, once: one per converted limit, then the staging
    // table goes and a second run writes nothing.
    assert_eq!(
        crate::store::accounts::audit_retired_limits(p)
            .await
            .unwrap(),
        6
    );
    assert_eq!(
        crate::store::accounts::audit_retired_limits(p)
            .await
            .unwrap(),
        0
    );
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'account.limit_cleared' ORDER BY seq",
    )
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(rows.len(), 6, "{rows:?}");
    assert!(
        rows.iter()
            .any(|d| d.contains("\"window_secs\":1000") && d.contains("\"became\":\"hour5\""))
    );
    assert!(
        rows.iter()
            .any(|d| d.contains("\"window_secs\":172800") && d.contains("\"became\":\"day\""))
    );
}
