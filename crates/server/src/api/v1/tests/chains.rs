//! Fallback chains (S5; design 2026-11-06 §4.1, §4.5): every validation rule, the order of the
//! entries, the table constraints, the deletion rules, a session's snapshot, the resolution order,
//! and the audit of every write.

use super::*;
use crate::store::chains::{self as ch, EntrySpec};
use crate::store::pools as pl;
use crate::store::prices;
use crate::store::secrets::Error;

pub(super) const BY: ainkrad_core::audit::AuditActor = super::super::BY;

pub(super) fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

/// A fixture with a priced `claude-sonnet` for anthropic and `gpt-test` for openai.
pub(super) async fn setup() -> Fx {
    let fx = fx().await;
    for (provider, model) in [("anthropic", "claude-sonnet"), ("openai", "gpt-test")] {
        prices::set(
            &fx.app.pool,
            provider,
            model,
            [3, 15, 1],
            "2026-11-01T00:00:00Z",
            "d_x",
            BY,
            NOW,
        )
        .await
        .unwrap();
    }
    fx
}

pub(super) async fn pool(fx: &Fx, name: &str, provider: &str) -> i64 {
    pl::create(&fx.app.pool, name, provider, "d_x", BY, NOW)
        .await
        .unwrap()
        .id
}

pub(super) fn spec(pool: i64) -> EntrySpec<'static> {
    EntrySpec {
        pool,
        model: None,
        harness: None,
    }
}

pub(super) async fn make(fx: &Fx, name: &str, pools: &[i64]) -> ch::Chain {
    let specs: Vec<_> = pools.iter().map(|p| spec(*p)).collect();
    ch::create(&fx.app.pool, 1, name, &specs, "d_x", BY, NOW)
        .await
        .unwrap()
}

pub(super) fn order(c: &ch::Chain) -> Vec<i64> {
    c.entries.iter().map(|e| e.pool).collect()
}

async fn new(
    p: &sqlx::SqlitePool,
    name: &str,
    specs: &[EntrySpec<'_>],
) -> Result<ch::Chain, Error> {
    ch::create(p, 1, name, specs, "d_x", BY, NOW).await
}

#[tokio::test]
async fn each_validation_rule_refuses() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, b, o, g) = (
        pool(&fx, "api-a", "anthropic").await,
        pool(&fx, "api-b", "anthropic").await,
        pool(&fx, "oai", "openai").await,
        pool(&fx, "goog", "google").await,
    );
    let (s1, s2) = (
        pool(&fx, "sub-1", "claude-sub").await,
        pool(&fx, "sub-2", "claude-sub").await,
    );
    // 1 to 4 entries.
    assert_eq!(code(new(p, "c0", &[]).await), "bad_request");
    let five = [spec(a), spec(b), spec(o), spec(g), spec(s1)];
    assert_eq!(code(new(p, "c5", &five).await), "bad_request");
    assert!(new(p, "c4", &five[..4]).await.is_ok());
    // No pool twice; the pool must exist.
    assert_eq!(
        code(new(p, "twice", &[spec(a), spec(a)]).await),
        "bad_request"
    );
    assert_eq!(code(new(p, "ghost", &[spec(9999)]).await), "not_found");
    // At most one subscription per chain, but one beside API keys is fine.
    assert_eq!(
        code(new(p, "subs", &[spec(s1), spec(s2)]).await),
        "bad_request"
    );
    assert!(new(p, "sub-then-key", &[spec(s1), spec(a)]).await.is_ok());
    // The harness, when named, is the pool's own.
    let wrong = EntrySpec {
        harness: Some("codex"),
        ..spec(a)
    };
    assert_eq!(code(new(p, "wrong-harness", &[wrong]).await), "bad_request");
    let right = EntrySpec {
        harness: Some("codex"),
        ..spec(o)
    };
    assert!(new(p, "right-harness", &[right]).await.is_ok());
    // A model is a valid id, and an API-key pool's model has a price.
    let priced = EntrySpec {
        model: Some("claude-sonnet"),
        ..spec(b)
    };
    let unpriced = EntrySpec {
        model: Some("claude-unlisted"),
        ..spec(b)
    };
    let shapeless = EntrySpec {
        model: Some("bad model!"),
        ..spec(b)
    };
    assert!(new(p, "priced", &[priced]).await.is_ok());
    assert_eq!(code(new(p, "unpriced", &[unpriced]).await), "bad_request");
    assert_eq!(code(new(p, "shapeless", &[shapeless]).await), "bad_request");
    // A subscription's model needs no price.
    let plan = EntrySpec {
        model: Some("opus"),
        ..spec(s2)
    };
    assert!(new(p, "plan-model", &[plan]).await.is_ok());
    // Names: shape and uniqueness.
    assert_eq!(code(new(p, "Bad Name", &[spec(a)]).await), "bad_request");
    assert_eq!(code(new(p, "c4", &[spec(a)]).await), "conflict");
    // Another user's pool.
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(p)
        .await
        .unwrap();
    sqlx::query("UPDATE core_pools SET user_id = 2 WHERE id = ?")
        .bind(g)
        .execute(p)
        .await
        .unwrap();
    assert_eq!(code(new(p, "theirs", &[spec(g)]).await), "bad_request");
    assert!(
        ch::create(p, 2, "theirs", &[spec(g)], "d_x", BY, NOW)
            .await
            .is_ok()
    );
    assert_eq!(
        code(ch::create(p, 2, "mixed", &[spec(g), spec(a)], "d_x", BY, NOW).await),
        "bad_request"
    );
}

#[tokio::test]
async fn update_runs_the_same_rules_and_keeps_the_old_list_when_refused() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, o) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "o", "openai").await,
    );
    let (s1, s2) = (
        pool(&fx, "s1", "claude-sub").await,
        pool(&fx, "s2", "claude-sub").await,
    );
    let c = make(&fx, "main", &[s1, a]).await;
    let bad = [spec(s1), spec(s2)];
    assert_eq!(
        code(ch::update(p, c.id, "main", &bad, "d_x", BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        order(&ch::get(p, c.id).await.unwrap()),
        [s1, a],
        "unchanged"
    );
    make(&fx, "other", &[o]).await;
    assert_eq!(
        code(ch::update(p, c.id, "other", &[spec(a)], "d_x", BY, NOW).await),
        "conflict"
    );
    let u = ch::update(
        p,
        c.id,
        "renamed",
        &[spec(o), spec(a), spec(s1)],
        "d_x",
        BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!((u.name.as_str(), order(&u)), ("renamed", vec![o, a, s1]));
    assert_eq!(
        code(ch::update(p, 9999, "x", &[spec(a)], "d_x", BY, NOW).await),
        "not_found"
    );
}

/// Every ordering of four pools (one a subscription, three of two providers) loads back in the
/// order written, positions run 0..n, and the entry carries its pool's provider and harness.
#[tokio::test]
async fn every_ordering_loads_back_as_written() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let ids = [
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "o", "openai").await,
        pool(&fx, "g", "google").await,
        pool(&fx, "s", "claude-sub").await,
    ];
    let mut perms: Vec<Vec<usize>> = vec![vec![]];
    for _ in 0..4 {
        perms = perms
            .into_iter()
            .flat_map(|prefix| {
                let rest: Vec<Vec<usize>> = (0..4)
                    .filter(|i| !prefix.contains(i))
                    .map(|i| [prefix.clone(), vec![i]].concat())
                    .collect();
                rest
            })
            .collect();
    }
    assert_eq!(perms.len(), 24);
    for (n, perm) in perms.iter().enumerate() {
        let want: Vec<i64> = perm.iter().map(|i| ids[*i]).collect();
        let c = make(&fx, &format!("p{n}"), &want).await;
        assert_eq!(order(&c), want);
        let mut conn = p.acquire().await.unwrap();
        assert_eq!(order_of(&ch::load(&mut conn, c.id).await.unwrap()), want);
        let pos: Vec<i64> = sqlx::query_scalar(
            "SELECT position FROM core_chain_entries WHERE chain_id = ? ORDER BY position",
        )
        .bind(c.id)
        .fetch_all(p)
        .await
        .unwrap();
        assert_eq!(pos, [0, 1, 2, 3]);
        let by_provider: Vec<(&str, &str)> = c
            .entries
            .iter()
            .map(|e| (e.provider.as_str(), e.harness.as_str()))
            .collect();
        for (e, (prov, harness)) in c.entries.iter().zip(by_provider) {
            let want = match prov {
                "anthropic" | "claude-sub" => "claude",
                "openai" => "codex",
                _ => "agy",
            };
            assert_eq!(harness, want, "{}", e.provider);
        }
        // Reversing through `update` reverses the stored order.
        let rev: Vec<_> = want.iter().rev().map(|x| spec(*x)).collect();
        let u = ch::update(p, c.id, &format!("p{n}"), &rev, "d_x", BY, NOW)
            .await
            .unwrap();
        assert_eq!(order(&u), want.iter().rev().copied().collect::<Vec<_>>());
    }
}

pub(super) fn order_of(e: &[ch::ChainEntry]) -> Vec<i64> {
    e.iter().map(|e| e.pool).collect()
}

#[tokio::test]
async fn the_tables_refuse_what_the_store_would() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, b) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "b", "anthropic").await,
    );
    let c = make(&fx, "main", &[a]).await;
    let ins = |pos: i64, pool: i64| {
        let p = p.clone();
        let id = c.id;
        async move {
            sqlx::query(
                "INSERT INTO core_chain_entries (chain_id, position, pool_id) VALUES (?, ?, ?)",
            )
            .bind(id)
            .bind(pos)
            .bind(pool)
            .execute(&p)
            .await
        }
    };
    assert!(ins(0, b).await.is_err(), "duplicate position");
    assert!(ins(1, a).await.is_err(), "duplicate pool");
    assert!(ins(4, b).await.is_err(), "position past 3");
    assert!(ins(-1, b).await.is_err(), "negative position");
    assert!(ins(1, b).await.is_ok());
    // A second default per user is refused by the index; a RESTRICTed pool by the foreign key.
    let d = make(&fx, "second", &[b]).await;
    sqlx::query("UPDATE core_chains SET is_default = 1 WHERE id = ?")
        .bind(c.id)
        .execute(p)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE core_chains SET is_default = 1 WHERE id = ?")
            .bind(d.id)
            .execute(p)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM core_pools WHERE id = ?")
            .bind(a)
            .execute(p)
            .await
            .is_err(),
        "RESTRICT"
    );
}

#[tokio::test]
async fn a_pool_in_a_chain_is_not_deleted_and_the_refusal_names_the_chain() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, b) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "b", "anthropic").await,
    );
    let c = make(&fx, "fallback-one", &[a, b]).await;
    match pl::delete(p, a, "d_x", BY).await {
        Err(Error::Refused { code, message }) => {
            assert_eq!(code, "conflict");
            assert!(message.contains("fallback-one"), "{message}");
        }
        _ => panic!("deleted a pool a chain names"),
    }
    ch::delete(p, c.id, "d_x", BY).await.unwrap();
    pl::delete(p, a, "d_x", BY).await.unwrap();
}

#[tokio::test]
async fn deleting_an_account_leaves_the_chain_and_an_empty_pool_in_it() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    // The account model deletes seats, never entries: nothing about a chain changes with it.
    sqlx::query("DELETE FROM core_pool_members WHERE pool_id = ?")
        .bind(a)
        .execute(p)
        .await
        .unwrap();
    assert_eq!(order(&ch::get(p, c.id).await.unwrap()), [a]);
}

#[tokio::test]
async fn every_write_is_audited_without_a_value() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, o) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "o", "openai").await,
    );
    let c = make(&fx, "main", &[a]).await;
    ch::update(p, c.id, "main", &[spec(a), spec(o)], "d_x", BY, NOW)
        .await
        .unwrap();
    ch::set_default(p, c.id, "d_x", BY, NOW).await.unwrap();
    ch::bind(p, "ag", c.id, "d_x", BY, NOW).await.unwrap();
    ch::unbind(p, 1, "ag", "d_x", BY).await.unwrap();
    ch::delete(p, c.id, "d_x", BY).await.unwrap();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, details FROM audit_events WHERE action LIKE 'chain.%' ORDER BY seq",
    )
    .fetch_all(p)
    .await
    .unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        actions,
        [
            "chain.created",
            "chain.updated",
            "chain.default_set",
            "chain.bound",
            "chain.unbound",
            "chain.deleted"
        ]
    );
    let updated: serde_json::Value = serde_json::from_str(&rows[1].1).unwrap();
    assert_eq!(updated["from"].as_array().unwrap().len(), 1);
    assert_eq!(updated["to"].as_array().unwrap().len(), 2);
    for (_, d) in &rows {
        assert!(d.contains("d_x"), "{d}");
    }
}

async fn make_named(fx: &Fx, name: &str, pool: i64) -> Result<ch::Chain, Error> {
    ch::create(&fx.app.pool, 1, name, &[spec(pool)], "d_x", BY, NOW).await
}

#[tokio::test]
async fn at_most_sixty_four_chains() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    for i in 0..64 {
        make_named(&fx, &format!("n{i}"), a).await.unwrap();
    }
    assert_eq!(code(make_named(&fx, "one-more", a).await), "limit_reached");
}

/// 0026 on a database that already has 0025: undoing it drops only its own tables and columns
/// (`agent`, `chain_id`), leaves the allocator's (`chain`, `chain_pos`, `account_id`, ...) and their
/// data, and applying it again restores them.
#[tokio::test]
async fn the_migration_goes_down_and_up_over_the_allocators_columns() {
    use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};
    let fx = setup().await;
    let p = &fx.app.pool;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let policy = serde_json::json!({});
    let new = crate::store::agents::NewSession {
        runner: &fx.dev.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let s = crate::store::agents::create(p, &new, BY, NOW)
        .await
        .unwrap();
    let snapshot = serde_json::to_string(&c.entries).unwrap();
    sqlx::query(
        "UPDATE core_agent_sessions SET chain = ?, chain_pos = 0, chain_id = ?, agent = 'ag' \
         WHERE id = ?",
    )
    .bind(&snapshot)
    .bind(c.id)
    .bind(&s.id)
    .execute(p)
    .await
    .unwrap();
    let columns = |p: sqlx::SqlitePool| async move {
        sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_table_info('core_agent_sessions') \
             WHERE name IN ('chain', 'chain_pos', 'account_id', 'waiting', 'tried_accounts', \
                            'chain_id', 'agent') ORDER BY name",
        )
        .fetch_all(&p)
        .await
        .unwrap()
    };
    let all = columns(p.clone()).await;
    assert_eq!(all.len(), 7, "{all:?}");
    undo(p, CORE, CORE_MIGRATIONS, 25).await.unwrap();
    assert_eq!(
        columns(p.clone()).await,
        [
            "account_id",
            "chain",
            "chain_pos",
            "tried_accounts",
            "waiting"
        ]
    );
    let kept: Option<String> =
        sqlx::query_scalar("SELECT chain FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(p)
            .await
            .unwrap();
    assert_eq!(
        kept.as_deref(),
        Some(snapshot.as_str()),
        "the allocator's data survives"
    );
    for t in ["core_chains", "core_chain_entries", "core_chain_bindings"] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = ?")
            .bind(t)
            .fetch_one(p)
            .await
            .unwrap();
        assert_eq!(n, 0, "{t}");
    }
    migrate_core(p).await.unwrap();
    assert_eq!(columns(p.clone()).await, all);
    let again: Option<String> =
        sqlx::query_scalar("SELECT chain FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(p)
            .await
            .unwrap();
    assert_eq!(again.as_deref(), Some(snapshot.as_str()));
}
