//! Account pools and bindings (KAN-431): a pool holds one provider's accounts in order, a
//! provider has one default, an agent's binding beats the default, and every change is audited.

use ainkrad_core::settings::{Key, Scope};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::accounts as acc;
use crate::store::pools as pl;
use crate::store::secrets::Error;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

async fn account(fx: &Fx, provider: &str, label: &str) -> i64 {
    let s = SecretBox::new(&[7; 32]);
    let new = acc::NewAccount {
        provider,
        label,
        value: "throwaway-pool-value-5a91c3d4",
        runners: &[],
        cap: None,
    };
    acc::create(&fx.app.pool, &s, &new, &fx.dev.id, BY, NOW)
        .await
        .unwrap()
        .id
}

async fn setup() -> Fx {
    let fx = fx().await;
    crate::store::settings::set(&fx.app.pool, Key::SecretsMode, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    fx
}

#[tokio::test]
async fn a_pool_keeps_one_providers_accounts_in_order() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, b, c) = (
        account(&fx, "anthropic", "a").await,
        account(&fx, "anthropic", "b").await,
        account(&fx, "anthropic", "c").await,
    );
    let o = account(&fx, "openai", "o").await;
    let pool = pl::create(p, "claude-main", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    for id in [b, a, c] {
        pl::add_member(p, pool.id, id, "d_x", BY, NOW)
            .await
            .unwrap();
    }
    assert_eq!(pl::get(p, pool.id).await.unwrap().members, [b, a, c]);
    assert_eq!(
        code(pl::add_member(p, pool.id, o, "d_x", BY, NOW).await),
        "bad_request",
        "never across providers"
    );
    assert_eq!(
        code(pl::add_member(p, pool.id, a, "d_x", BY, NOW).await),
        "conflict"
    );
    assert_eq!(
        code(pl::add_member(p, pool.id, 999, "d_x", BY, NOW).await),
        "not_found"
    );
    let after = pl::remove_member(p, pool.id, b, "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(after.members, [a, c]);
    let pos: Vec<i64> =
        sqlx::query_scalar("SELECT position FROM core_pool_members ORDER BY position")
            .fetch_all(p)
            .await
            .unwrap();
    assert_eq!(pos, [0, 1], "no gap after a removal");
    assert_eq!(
        code(pl::remove_member(p, pool.id, b, "d_x", BY, NOW).await),
        "not_found"
    );
    // An account may sit in several pools; deleting it empties its seats.
    let other = pl::create(p, "spare", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    pl::add_member(p, other.id, a, "d_x", BY, NOW)
        .await
        .unwrap();
    acc::delete(p, a, "d_x", BY).await.unwrap();
    assert_eq!(pl::get(p, pool.id).await.unwrap().members, [c]);
    assert!(pl::get(p, other.id).await.unwrap().members.is_empty());
}

async fn bound(p: &sqlx::SqlitePool, agent: &str) -> Vec<(String, i64)> {
    pl::list_bindings(p)
        .await
        .unwrap()
        .into_iter()
        .filter(|b| b.agent == agent)
        .map(|b| (b.provider, b.pool_id))
        .collect()
}

#[tokio::test]
async fn an_agents_binding_replaces_per_provider_and_unbinds() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let main = pl::create(p, "main", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    let side = pl::create(p, "side", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    assert!(bound(p, "ag1").await.is_empty());
    pl::bind(p, "ag1", side.id, "d_x", BY, NOW).await.unwrap();
    assert_eq!(bound(p, "ag1").await, [("anthropic".to_owned(), side.id)]);
    // Rebinding replaces; unbinding drops; a second unbind is not_found.
    pl::bind(p, "ag1", main.id, "d_x", BY, NOW).await.unwrap();
    assert_eq!(bound(p, "ag1").await, [("anthropic".to_owned(), main.id)]);
    pl::unbind(p, "ag1", "anthropic", "d_x", BY).await.unwrap();
    assert!(bound(p, "ag1").await.is_empty());
    assert_eq!(
        code(pl::unbind(p, "ag1", "anthropic", "d_x", BY).await),
        "not_found"
    );
    assert_eq!(
        code(pl::bind(p, "bad agent!", side.id, "d_x", BY, NOW).await),
        "bad_request"
    );
}

#[tokio::test]
async fn one_default_per_provider_and_the_default_is_not_deleted() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let one = pl::create(p, "one", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    let two = pl::create(p, "two", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    pl::set_default(p, one.id, "d_x", BY, NOW).await.unwrap();
    pl::set_default(p, two.id, "d_x", BY, NOW).await.unwrap();
    let all = pl::list(p).await.unwrap();
    assert_eq!(
        all.iter()
            .filter(|x| x.is_default)
            .map(|x| x.id)
            .collect::<Vec<_>>(),
        [two.id]
    );
    assert_eq!(code(pl::delete(p, two.id, "d_x", BY).await), "conflict");
    pl::bind(p, "ag1", one.id, "d_x", BY, NOW).await.unwrap();
    pl::delete(p, one.id, "d_x", BY).await.unwrap();
    assert!(
        pl::list_bindings(p).await.unwrap().is_empty(),
        "its binding went with it"
    );
    // The database itself refuses a second default.
    let id = pl::create(p, "three", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap()
        .id;
    assert!(
        sqlx::query("UPDATE core_pools SET is_default = 1 WHERE id = ?")
            .bind(id)
            .execute(p)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn names_are_validated_unique_and_bounded_and_every_change_is_audited() {
    let fx = setup().await;
    let p = &fx.app.pool;
    assert_eq!(
        code(pl::create(p, "Bad Name", "anthropic", "d_x", BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        code(pl::create(p, "ok", "openrouter", "d_x", BY, NOW).await),
        "bad_request"
    );
    let a = account(&fx, "google", "g").await;
    let pool = pl::create(p, "ok", "google", "d_x", BY, NOW).await.unwrap();
    assert_eq!(
        code(pl::create(p, "ok", "google", "d_x", BY, NOW).await),
        "conflict"
    );
    pl::add_member(p, pool.id, a, "d_x", BY, NOW).await.unwrap();
    pl::set_default(p, pool.id, "d_x", BY, NOW).await.unwrap();
    pl::bind(p, "ag1", pool.id, "d_x", BY, NOW).await.unwrap();
    pl::unbind(p, "ag1", "google", "d_x", BY).await.unwrap();
    pl::remove_member(p, pool.id, a, "d_x", BY, NOW)
        .await
        .unwrap();
    let other = pl::create(p, "other", "google", "d_x", BY, NOW)
        .await
        .unwrap();
    pl::delete(p, other.id, "d_x", BY).await.unwrap();
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'pool.%' ORDER BY seq",
    )
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "pool.created",
            "pool.member_added",
            "pool.default_set",
            "pool.bound",
            "pool.unbound",
            "pool.member_removed",
            "pool.created",
            "pool.deleted"
        ]
    );
    for i in 0..63 {
        pl::create(p, &format!("p{i}"), "google", "d_x", BY, NOW)
            .await
            .unwrap();
    }
    assert_eq!(
        code(pl::create(p, "one-more", "google", "d_x", BY, NOW).await),
        "limit_reached"
    );
}

/// Review: deleting an account takes its seats with it and leaves a gap; the next member must
/// still get a free, last position (a count would tie), the order must hold, and the deletion's
/// audit row must name the pools that lost the account.
#[tokio::test]
async fn deleting_an_account_leaves_no_tied_seats_and_audits_the_pools() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, b, c, d) = (
        account(&fx, "anthropic", "a").await,
        account(&fx, "anthropic", "b").await,
        account(&fx, "anthropic", "c").await,
        account(&fx, "anthropic", "d").await,
    );
    let pool = pl::create(p, "claude-main", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    let other = pl::create(p, "claude-spare", "anthropic", "d_x", BY, NOW)
        .await
        .unwrap();
    for id in [a, b, c] {
        pl::add_member(p, pool.id, id, "d_x", BY, NOW)
            .await
            .unwrap();
    }
    pl::add_member(p, other.id, a, "d_x", BY, NOW)
        .await
        .unwrap();
    acc::delete(p, a, "d_x", BY).await.unwrap();
    // `a` held seat 0: the remaining seats are 1 and 2, so a count of members (2) would have
    // handed the next account seat 2 and tied it with `c`.
    pl::add_member(p, pool.id, d, "d_x", BY, NOW).await.unwrap();
    assert_eq!(pl::get(p, pool.id).await.unwrap().members, [b, c, d]);
    let seats: Vec<i64> = sqlx::query_scalar(
        "SELECT position FROM core_pool_members WHERE pool_id = ? ORDER BY position",
    )
    .bind(pool.id)
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(seats.len(), 3);
    assert!(seats.windows(2).all(|w| w[0] < w[1]), "{seats:?}");
    // The database refuses a tie outright.
    let tie = sqlx::query(
        "UPDATE core_pool_members SET position = ? WHERE pool_id = ? AND account_id = ?",
    )
    .bind(seats[0])
    .bind(pool.id)
    .bind(d)
    .execute(p)
    .await;
    assert!(tie.is_err(), "positions tied");
    // Removing a member still closes the gap without tripping the unique seats.
    pl::remove_member(p, pool.id, b, "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(pl::get(p, pool.id).await.unwrap().members, [c, d]);
    // The audit row of the deletion names both pools that held `a`.
    let details: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'account.deleted'")
            .fetch_one(p)
            .await
            .unwrap();
    let v: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(
        v["pools"],
        serde_json::json!([pool.id, other.id]),
        "{details}"
    );
}
