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
    let owed = acc::pending_wipes(p).await.unwrap();
    assert_eq!(
        owed.iter()
            .map(|w| (w.runner.as_str(), w.home.as_str()))
            .collect::<Vec<_>>(),
        [("rn_1", "lg_1")]
    );
    // The runner is offline: the row stays and counts the try; once it confirms, the row goes.
    acc::wipe_tried(p, owed[0].id).await.unwrap();
    assert_eq!(acc::pending_wipes(p).await.unwrap().len(), 1);
    acc::wipe_done(p, owed[0].id).await.unwrap();
    assert!(acc::pending_wipes(p).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_bound_login_that_finished_on_the_runner_but_was_not_stored_owes_its_home_a_wipe() {
    use crate::store::logins::{self, Change};
    let (fx, _vm, _s) = setup().await;
    let p = &fx.app.pool;
    let n = unix_secs(NOW).unwrap();
    let mut made = Vec::new();
    for label in ["no-key", "cancelled"] {
        let l = logins::create(p, ("codex-sub", label, "rn_1"), &fx.dev.id, BY, n)
            .await
            .unwrap();
        logins::step(
            p,
            &l.id,
            &["starting"],
            "open_url",
            &Change::default(),
            BY,
            n,
        )
        .await
        .unwrap();
        made.push(l);
    }
    // No master key loaded (the fixture has none): the account cannot be stored.
    crate::agents::login::store_bound(&fx.app, &made[0]).await;
    // Cancelled while the runner finished: the step to `storing` is refused.
    logins::step(
        p,
        &made[1].id,
        &["open_url"],
        "cancelled",
        &Change::default(),
        BY,
        n,
    )
    .await
    .unwrap();
    crate::agents::login::store_bound(&fx.app, &made[1]).await;
    let mut owed: Vec<_> = acc::pending_wipes(p)
        .await
        .unwrap()
        .into_iter()
        .map(|w| (w.runner, w.home))
        .collect();
    let mut want: Vec<_> = made
        .iter()
        .map(|l| ("rn_1".to_owned(), l.id.clone()))
        .collect();
    owed.sort();
    want.sort();
    assert_eq!(owed, want);
}

#[tokio::test]
async fn a_removed_account_cannot_be_put_in_a_hidden_order_pool() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    acc::soft_delete(p, a.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let mut tx = crate::store::begin_write(p).await.unwrap();
    let got = crate::store::chains::order::pool_for(&mut tx, 1, a.id, &fx.dev.id, BY, NOW).await;
    assert!(got.is_err(), "a removed account has no order pool");
}
