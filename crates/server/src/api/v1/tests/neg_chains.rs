//! S8, chain validation fuzz: random entry lists, written and rewritten for two users, against an
//! oracle written from the design (§4.1) and not from the code. A list is accepted exactly when it has
//! 1 to 4 entries, no pool twice, only the chain user's pools, and at most one subscription. After
//! every write, whatever was accepted or refused, every stored chain holds the rules (never an
//! invalid chain, never across users, never two subscriptions), and a refused rewrite left the old list.
//!
//! The seed is in every message; `NEG_SEED=<n>` replays one seed.

use super::chains::{BY, pool, setup, spec};
use super::neg_rng::{Rng, seeds};
use super::*;
use crate::store::chains::{self as ch, EntrySpec};

async fn sweep(fx: &Fx, ctx: &str) {
    let owners: Vec<(i64, i64, String)> =
        sqlx::query_as("SELECT id, user_id, provider FROM core_pools")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    for c in ch::list(&fx.app.pool).await.unwrap() {
        let n = c.entries.len();
        assert!((1..=4).contains(&n), "a chain of {n} entries, {ctx}");
        let mut seen = Vec::new();
        let mut subs = 0;
        for e in &c.entries {
            assert!(!seen.contains(&e.pool), "a pool twice in {}, {ctx}", c.name);
            seen.push(e.pool);
            let (_, owner, provider) = owners
                .iter()
                .find(|o| o.0 == e.pool)
                .expect("the pool exists");
            assert_eq!(
                *owner, c.user_id,
                "a chain names another user's pool, {ctx}"
            );
            assert_eq!(&e.provider, provider, "{ctx}");
            subs += i32::from(provider == "claude-sub");
        }
        assert!(subs <= 1, "two subscriptions in {}, {ctx}", c.name);
    }
}

#[tokio::test]
async fn neg_random_entry_lists_never_make_an_invalid_chain_or_cross_users() {
    for seed in seeds(&[1, 2, 3, 4, 5]) {
        let mut rng = Rng(seed);
        let fx = setup().await;
        let p = &fx.app.pool;
        sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
            .execute(p)
            .await
            .unwrap();
        // (pool, owner, is a subscription)
        let mut pools: Vec<(i64, i64, bool)> = Vec::new();
        for (i, provider) in [
            "anthropic",
            "anthropic",
            "openai",
            "google",
            "claude-sub",
            "claude-sub",
            "claude-sub",
        ]
        .iter()
        .enumerate()
        {
            for (user, tag) in [(1, "a"), (2, "b")] {
                let id = pool(&fx, &format!("{tag}{i}"), provider).await;
                sqlx::query("UPDATE core_pools SET user_id = ? WHERE id = ?")
                    .bind(user)
                    .bind(id)
                    .execute(p)
                    .await
                    .unwrap();
                pools.push((id, user, *provider == "claude-sub"));
            }
        }
        let mut chains: Vec<(i64, i64)> = Vec::new();
        let (mut accepted, mut refused) = (0, 0);
        for step in 0..120 {
            let ctx = format!("seed {seed} step {step}");
            let user = 1 + rng.below(2) as i64;
            // Mostly the user's own pools, so most lists are worth accepting; sometimes any.
            let own: Vec<i64> = pools.iter().filter(|p| p.1 == user).map(|p| p.0).collect();
            let any: Vec<i64> = pools.iter().map(|p| p.0).collect();
            let from = if rng.below(5) == 0 { &any } else { &own };
            let list: Vec<i64> = (0..rng.below(6))
                .map(|_| from[rng.below(from.len())])
                .collect();
            let specs: Vec<EntrySpec<'_>> = list.iter().map(|id| spec(*id)).collect();
            let kind = |id: &i64| pools.iter().find(|p| p.0 == *id).unwrap();
            let mut distinct = list.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let valid_for = |owner: i64| {
                (1..=4).contains(&list.len())
                    && distinct.len() == list.len()
                    && list.iter().all(|id| kind(id).1 == owner)
                    && list.iter().filter(|id| kind(id).2).count() <= 1
            };
            let update = !chains.is_empty() && rng.below(2) == 0;
            let got = if update {
                let (id, owner) = chains[rng.below(chains.len())];
                let before = ch::get(p, id).await.unwrap();
                let got = ch::update(p, id, &before.name, &specs, "d_x", BY, NOW).await;
                // The rules are the chain's own user's, not the caller's.
                let valid = valid_for(owner);
                assert_eq!(
                    got.is_ok(),
                    valid,
                    "update {list:?} of {id}: {:?}, {ctx}",
                    got.as_ref().err()
                );
                if got.is_err() {
                    assert_eq!(
                        ch::get(p, id).await.unwrap().entries,
                        before.entries,
                        "a refusal changed it, {ctx}"
                    );
                }
                got.is_ok()
            } else {
                let name = format!("c{step}");
                let got = ch::create(p, user, &name, &specs, "d_x", BY, NOW).await;
                assert_eq!(
                    got.is_ok(),
                    valid_for(user),
                    "create {list:?} for {user}: {:?}, {ctx}",
                    got.as_ref().err()
                );
                if let Ok(c) = &got {
                    chains.push((c.id, user));
                }
                got.is_ok()
            };
            if got {
                accepted += 1
            } else {
                refused += 1
            }
            sweep(&fx, &ctx).await;
        }
        assert!(
            accepted > 10 && refused > 10,
            "seed {seed}: {accepted} accepted, {refused} refused"
        );
    }
}
