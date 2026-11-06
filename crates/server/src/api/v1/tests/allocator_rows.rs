//! What the allocator writes and releases (KAN-437 S4): the row a pick leaves (one account
//! secret, the gateway account an API key needs), a repeated or rolled-back pick that takes no
//! second hold, the re-picks a launch may ask for, and the guard that keeps a chain row from
//! launching before it has its account.

use super::allocator::{P, p, took, w};
use super::health::at;
use super::*;
use crate::store::agents::{self as store, SessionSecret};
use crate::store::alloc;
use crate::store::budgets;
use crate::store::{accounts as acc, begin_write};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

#[tokio::test]
async fn a_pick_writes_the_row_and_a_subscription_is_never_beside_another_account() {
    let w = w().await;
    let (key, plan) = (w.acct("key").await, w.sub("plan").await);
    let git = SessionSecret {
        name: "git.token".to_owned(),
        var: "GIT_TOKEN".to_owned(),
    };
    let old = SessionSecret {
        name: key.secret_name.clone(),
        var: "ANTHROPIC_API_KEY".to_owned(),
    };
    let chain = [
        w.pool("plan", "claude-sub", &[plan.id]).await,
        w.keys("keys", &[key.id]).await,
    ];
    let s = w.session(&chain, &[old, git.clone()]).await;
    let got = took(w.pick(&s.id, &chain, &at(5)).await);
    let row = store::get(&w.fx.app.pool, &s.id).await.unwrap().unwrap();
    let names: Vec<&str> = row.secrets.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(names, ["git.token", plan.secret_name.as_str()]);
    assert_eq!(row.secrets[1].var, "CLAUDE_CODE_OAUTH_TOKEN");
    assert_eq!((row.gateway_account_id, got.gateway), (None, false));
    let (account, pos): (i64, i64) =
        sqlx::query_as("SELECT account_id, chain_pos FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert_eq!((account, pos), (plan.id, 0));
    let last = acc::get(&w.fx.app.pool, plan.id)
        .await
        .unwrap()
        .last_used_at;
    assert_eq!(last.as_deref(), Some(at(5).as_str()));
    // An API key: gateway account set, equal to the secret's own id (what the grant demands).
    let s2 = w.session(&chain, &[]).await;
    let used = P {
        used: &[plan.id],
        ..p()
    };
    let got = took(w.pick_p(&s2.id, &chain, &at(6), used).await);
    let row = store::get(&w.fx.app.pool, &s2.id).await.unwrap().unwrap();
    assert_eq!((got.gateway, row.gateway_account_id), (true, Some(key.id)));
    assert_eq!(
        crate::store::gateway::account_secret(&row.secrets[0].name),
        Some(("anthropic", key.id))
    );
    assert_eq!((row.harness.as_str(), got.pos), ("claude", 1));
}

#[tokio::test]
async fn a_repeated_pick_gives_the_same_account_and_a_rolled_back_one_leaves_nothing() {
    let w = w().await;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    let pool_entry = w.keys("main", &[a.id, b.id]).await;
    let subject = pool_entry.pool.to_string();
    let budget = budgets::NewBudget {
        kind: "pool",
        subject: &subject,
        company: None,
        period: "day",
        token_cap: 100_000_000,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    };
    budgets::set(&w.fx.app.pool, &budget, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let chain = [pool_entry];
    let s = w.session(&chain, &[]).await;
    let holds = "SELECT count(*) FROM core_budget_holds WHERE session = ?";
    // Rolled back: no account, no hold, no use.
    let dry = P {
        commit: false,
        ..p()
    };
    took(w.pick_p(&s.id, &chain, NOW, dry).await);
    assert_eq!(w.count(holds, &s.id).await, 0);
    let used: Option<String> =
        sqlx::query_scalar("SELECT last_used_at FROM core_accounts WHERE id = ?")
            .bind(a.id)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(used, None);
    // Committed, then repeated (a retry): the same account, the same single hold, no second use.
    let first = took(w.pick(&s.id, &chain, &at(1)).await);
    assert_eq!(w.count(holds, &s.id).await, 1);
    let again = took(w.pick(&s.id, &chain, &at(9)).await);
    assert_eq!(
        (again.account, w.count(holds, &s.id).await),
        (first.account, 1)
    );
    let last = acc::get(&w.fx.app.pool, first.account)
        .await
        .unwrap()
        .last_used_at;
    assert_eq!(last.as_deref(), Some(at(1).as_str()));
}

#[tokio::test]
async fn a_retreat_gives_the_hold_back_and_the_account_is_tried_at_most_twice() {
    let w = w().await;
    let ids = [
        w.acct("a").await.id,
        w.acct("b").await.id,
        w.acct("c").await.id,
    ];
    let chain = [w.keys("main", &ids).await];
    let s = w.session(&chain, &[]).await;
    let pool = &w.fx.app.pool;
    let mut tried: Vec<i64> = Vec::new();
    for want in ids {
        let got = took(
            w.pick_p(
                &s.id,
                &chain,
                NOW,
                P {
                    used: &tried,
                    ..p()
                },
            )
            .await,
        )
        .account;
        assert_eq!(got, want);
        let mut tx = begin_write(pool).await.unwrap();
        let back = alloc::retreat_in(&mut tx, &s.id).await.unwrap();
        tx.commit().await.unwrap();
        match back {
            Some(t) => tried = t,
            None => assert_eq!(tried.len(), alloc::MAX_REPICKS),
        }
    }
    assert_eq!(tried, [ids[0], ids[1]]);
    let row: (Option<i64>, String) =
        sqlx::query_as("SELECT account_id, tried_accounts FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(row.0, Some(ids[2]), "the third stays: no more re-picks");
}

#[tokio::test]
async fn a_chain_row_is_not_launchable_until_the_copy_in_hand_names_its_account() {
    let w = w().await;
    let a = w.acct("a").await;
    let chain = [w.keys("main", &[a.id]).await];
    let pool = &w.fx.app.pool;
    let plain = w.session(&[], &[]).await;
    sqlx::query("UPDATE core_agent_sessions SET chain = NULL WHERE id = ?")
        .bind(&plain.id)
        .execute(pool)
        .await
        .unwrap();
    let s = w.session(&chain, &[]).await;
    assert!(alloc::unassigned(pool, &s.id, &[]).await.unwrap());
    took(w.pick(&s.id, &chain, NOW).await);
    // A copy read before the pick finished still has no account: it must not start.
    assert!(alloc::unassigned(pool, &s.id, &s.secrets).await.unwrap());
    let fresh = store::get(pool, &s.id).await.unwrap().unwrap();
    assert!(
        !alloc::unassigned(pool, &s.id, &fresh.secrets)
            .await
            .unwrap()
    );
    // A session that names its account itself (no chain) is never held back.
    assert!(!alloc::unassigned(pool, &plain.id, &[]).await.unwrap());
}

#[tokio::test]
async fn a_session_that_has_run_never_leaves_its_account() {
    let w = w().await;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    let chain = [w.keys("main", &[a.id, b.id]).await];
    let pool = &w.fx.app.pool;
    for how in ["interrupted", "started", "woken"] {
        let s = w.session(&chain, &[]).await;
        let first = took(w.pick(&s.id, &chain, NOW).await).account;
        match how {
            "interrupted" => store::set_state(pool, &s.id, "interrupted", "t", false, NOW)
                .await
                .unwrap(),
            "started" => {
                sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h_1' WHERE id = ?")
                    .bind(&s.id)
                    .execute(pool)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::query("UPDATE core_agent_sessions SET last_seq = 4 WHERE id = ?")
                    .bind(&s.id)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
        let mut tx = begin_write(pool).await.unwrap();
        assert_eq!(
            alloc::retreat_in(&mut tx, &s.id).await.unwrap(),
            None,
            "{how}"
        );
        tx.commit().await.unwrap();
        let held: Option<i64> =
            sqlx::query_scalar("SELECT account_id FROM core_agent_sessions WHERE id = ?")
                .bind(&s.id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(held, Some(first), "{how}");
    }
}
