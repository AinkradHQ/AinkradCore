//! E7 closeout: removing an account with Undo. The delete hides the account at once and keeps its key
//! for 10 seconds; a restore within the window brings it back as it was; the window's end wipes it.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::accounts as acc;
use crate::store::pools as pl;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

fn later(secs: i64) -> String {
    iso_of_unix(unix_secs(NOW).unwrap() + secs)
}

async fn count(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_delete_hides_the_account_at_once_and_a_restore_brings_it_back_with_its_seat() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    let pool = pl::create(p, "main", "anthropic", &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    pl::add_member(p, pool.id, a.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    acc::set_state(p, a.id, "cooling", Some("r"), None, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let uri = format!("/api/v1/accounts/{}", a.id);
    let (st, b) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!((st, &b["deleted"]), (StatusCode::OK, &json!(true)), "{b}");
    assert!(b["undo_until"].as_str().is_some(), "{b}");
    // Gone to every reader and to the allocator's seat list, but the key is still stored.
    assert!(acc::list(p).await.unwrap().is_empty());
    let (st, _) = send(&fx.app, req(Method::GET, &uri, Some(&fx.dev), None)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert!(pl::get(p, pool.id).await.unwrap().members.is_empty());
    let kept = "SELECT count(*) FROM core_secrets WHERE name LIKE 'acct.%'";
    assert_eq!(count(&fx, kept).await, 1);
    // A second delete finds nothing.
    let (st, _) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // Undo: the state and the seat are back.
    let (st, b) = send(
        &fx.app,
        req(Method::POST, &format!("{uri}/restore"), Some(&fx.dev), None),
    )
    .await;
    assert_eq!((st, &b["restored"]), (StatusCode::OK, &json!(true)), "{b}");
    let back = acc::get(p, a.id).await.unwrap();
    assert_eq!(back.state, "cooling");
    assert_eq!(pl::get(p, pool.id).await.unwrap().members, [a.id]);
    let (st, _) = send(
        &fx.app,
        req(Method::POST, &format!("{uri}/restore"), Some(&fx.dev), None),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "nothing left to restore");
}

#[tokio::test]
async fn the_window_ends_with_a_real_wipe_and_a_late_restore_is_refused() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    acc::soft_delete(p, a.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    // Inside the window nothing is wiped.
    assert_eq!(acc::wipe_due(p, &later(9), false).await.unwrap(), 0);
    // At 10 s the window is over: no restore, and the sweep wipes key and row.
    let late = acc::restore(p, a.id, &fx.dev.id, BY, &later(10)).await;
    assert!(late.is_err());
    assert_eq!(acc::wipe_due(p, &later(10), false).await.unwrap(), 1);
    assert_eq!(count(&fx, "SELECT count(*) FROM core_accounts").await, 0);
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM core_secrets WHERE name LIKE 'acct.%'"
        )
        .await,
        0
    );
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action IN ('account.deleted', 'account.wiped') ORDER BY seq",
    )
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(actions, ["account.deleted", "account.wiped"]);
    let all: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(p)
        .await
        .unwrap();
    assert!(all.iter().all(|d| !d.contains(V1)));
}

#[tokio::test]
async fn a_stop_wipes_every_removed_account_inside_its_window_and_a_bound_login_stays_owed_to_its_runner()
 {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    sqlx::query(
        "INSERT INTO core_account_bound (account_id, runner, home, created_at) VALUES (?, 'rn_1', 'lg_1', ?)",
    )
    .bind(a.id)
    .bind(NOW)
    .execute(p)
    .await
    .unwrap();
    acc::soft_delete(p, a.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(acc::wipe_due(p, NOW, true).await.unwrap(), 1);
    let online = vec!["rn_1".to_owned()];
    assert!(
        acc::pending_wipes(p, &[]).await.unwrap().is_empty(),
        "an away runner is skipped"
    );
    let owed = acc::pending_wipes(p, &online).await.unwrap();
    assert_eq!(
        owed.iter()
            .map(|w| (w.runner.as_str(), w.home.as_str()))
            .collect::<Vec<_>>(),
        [("rn_1", "lg_1")]
    );
    // The runner is offline: the row stays and counts the try; once it confirms, the row goes.
    acc::wipe_tried(p, owed[0].id).await.unwrap();
    assert_eq!(acc::pending_wipes(p, &online).await.unwrap().len(), 1);
    acc::wipe_done(p, owed[0].id).await.unwrap();
    assert!(acc::pending_wipes(p, &online).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_restore_that_raced_the_sweep_wins_and_the_queue_asks_the_least_tried_first() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    acc::soft_delete(p, a.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    // The sweep listed the account as due, then the user restored it inside the window's last tick:
    // the delete re-checks under its own transaction and wipes nothing.
    acc::restore(p, a.id, &fx.dev.id, BY, &later(9))
        .await
        .unwrap();
    let cutoff = later(100);
    assert!(!acc::wipe_one(p, a.id, &cutoff, false).await.unwrap());
    assert!(!acc::wipe_one(p, a.id, &cutoff, true).await.unwrap());
    assert_eq!(count(&fx, "SELECT count(*) FROM core_accounts").await, 1);
    // The owed wipes: fewest tries first, then the oldest.
    for (home, tries, at) in [
        ("lg_old", 3, "2026-10-22T09:00:00.000Z"),
        ("lg_new", 0, NOW),
        ("lg_mid", 0, "2026-10-22T09:30:00.000Z"),
    ] {
        sqlx::query("INSERT INTO core_account_wipes (runner, home, created_at, tries) VALUES ('rn_1', ?, ?, ?)")
            .bind(home)
            .bind(at)
            .bind(tries)
            .execute(p)
            .await
            .unwrap();
    }
    let owed = acc::pending_wipes(p, &["rn_1".to_owned()]).await.unwrap();
    let order: Vec<&str> = owed.iter().map(|w| w.home.as_str()).collect();
    assert_eq!(order, ["lg_mid", "lg_new", "lg_old"]);
}
