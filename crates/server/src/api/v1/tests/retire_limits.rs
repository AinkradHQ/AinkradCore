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
    // Five hours of tokens and messages merge into one hour5 budget; a day of messages stands alone;
    // a 1000-second window has no budget period and is dropped.
    for (unit, win, cap, warn) in [
        ("tokens", 18000, 500, Some(70)),
        ("messages", 18000, 40, None),
        ("messages", 86400, 90, None),
        ("tokens", 1000, 5, None),
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
    let rows: Vec<(String, i64, Option<i64>, i64)> = sqlx::query_as(
        "SELECT period, token_cap, message_cap, warn_at_percent FROM core_budgets \
         WHERE subject_kind = 'account' AND subject_id = ? ORDER BY period",
    )
    .bind(a.id.to_string())
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            ("day".to_owned(), 0, Some(90), 80),
            ("hour5".to_owned(), 500, Some(40), 70)
        ]
    );
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = 'core_account_limits'")
            .fetch_one(p)
            .await
            .unwrap();
    assert_eq!(left, 0);
}
