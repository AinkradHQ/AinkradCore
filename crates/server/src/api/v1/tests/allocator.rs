//! The account allocator (KAN-437 S4; design §5, §16): the choice inside a pool (least loaded, then
//! least recently used, then seat), the cap under concurrent picks (I4), the user check (I5), the
//! runner's scope, `used_accounts`, what the pick writes, and that a rolled-back or repeated pick
//! takes no second hold. The states that keep an account out, the budgets and the wait are in
//! `allocator_states`.

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::json;
use sqlx::SqlitePool;

use super::accounts_store::{make, setup};
use super::health::at;
use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::agents::{self as store, NewSession, SessionSecret};
use crate::store::alloc::{self, Ask, Entry, LOST_AFTER_SECS, Outcome, Picked, WAIT_MAX_SECS};
use crate::store::health::{self, Signal};
use crate::store::pools as pl;
use crate::store::{accounts as acc, begin_write, settings};

pub(super) const BY: ainkrad_core::audit::AuditActor = super::super::BY;
pub(super) const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";

pub(super) struct W {
    pub fx: Fx,
    pub vm: TestDevice,
    pub sealer: SecretBox,
}

pub(super) async fn w() -> W {
    let (fx, vm, sealer) = setup().await;
    W { fx, vm, sealer }
}

/// Who asks, what they have used and skip.
pub(super) struct P<'a> {
    pub user: i64,
    pub used: &'a [i64],
    pub skip: &'a [i64],
    pub from: usize,
    pub commit: bool,
}

pub(super) const fn p() -> P<'static> {
    P {
        user: 1,
        used: &[],
        skip: &[],
        from: 0,
        commit: true,
    }
}

pub(super) fn took(o: Outcome) -> Picked {
    match o {
        Outcome::Picked(p) => p,
        other => panic!("not picked: {other:?}"),
    }
}

pub(super) async fn pick_owned(
    pool: SqlitePool,
    runner: String,
    session: String,
    chain: Vec<Entry>,
    now: String,
    p: (i64, Vec<i64>, Vec<i64>, usize, bool),
) -> Outcome {
    let min = |_: &Entry| 0u64;
    let serves = |_: &Entry| -> Option<String> { None };
    let ask = Ask {
        session: &session,
        runner: &runner,
        user: p.0,
        chain: &chain,
        from_pos: p.3,
        used_accounts: &p.1,
        skip_pools: &p.2,
        min_turn: &min,
        serves: &serves,
        wait_max_secs: WAIT_MAX_SECS,
        lost_after_secs: LOST_AFTER_SECS,
    };
    let mut tx = begin_write(&pool).await.unwrap();
    let o = alloc::pick_in(&mut tx, &ask, &now).await.unwrap();
    if p.4 {
        tx.commit().await.unwrap();
    }
    o
}

impl W {
    pub async fn acct(&self, label: &str) -> acc::Account {
        let value = format!("throwaway-account-value-{label}-5a91c3");
        make(
            &self.fx,
            &self.sealer,
            label,
            &value,
            std::slice::from_ref(&self.vm.id),
        )
        .await
    }

    pub async fn sub(&self, label: &str) -> acc::Account {
        let gate = settings::set(
            &self.fx.app.pool,
            ainkrad_core::settings::Key::SecretsProviderAccounts,
            ainkrad_core::settings::Scope::Server,
            "1",
            BY,
            NOW,
        );
        gate.await.unwrap();
        let new = acc::NewAccount {
            provider: "claude-sub",
            label,
            value: TOKEN,
            runners: std::slice::from_ref(&self.vm.id),
            cap: None,
        };
        let by = &self.fx.dev.id;
        let sealer = &self.sealer;
        acc::create_by(&self.fx.app.pool, sealer, &new, "subscription", by, BY, NOW)
            .await
            .unwrap()
    }

    /// A pool of `provider` holding `accounts` in order, as a chain entry.
    pub async fn pool(&self, name: &str, provider: &str, accounts: &[i64]) -> Entry {
        let by = &self.fx.dev.id;
        let pool = &self.fx.app.pool;
        let made = pl::create(pool, name, provider, by, BY, NOW).await.unwrap();
        for a in accounts {
            pl::add_member(pool, made.id, *a, by, BY, NOW)
                .await
                .unwrap();
        }
        Entry {
            pool: made.id,
            provider: provider.to_owned(),
            harness: "claude".to_owned(),
            model: None,
        }
    }

    pub async fn keys(&self, name: &str, accounts: &[i64]) -> Entry {
        self.pool(name, "anthropic", accounts).await
    }

    /// A `starting` session of the chain, with `secrets` of its own.
    pub async fn session(&self, chain: &[Entry], secrets: &[SessionSecret]) -> store::Session {
        let policy = json!({"mode": "ask", "min_isolation": "process"});
        let new = NewSession {
            runner: &self.vm.id,
            harness: "claude",
            model: None,
            prompt: None,
            workspace: None,
            policy: &policy,
            secrets,
            created_by: &self.fx.dev.id,
        };
        let s = store::create(&self.fx.app.pool, &new, BY, NOW)
            .await
            .unwrap();
        sqlx::query("UPDATE core_agent_sessions SET chain = ? WHERE id = ?")
            .bind(json!(chain).to_string())
            .bind(&s.id)
            .execute(&self.fx.app.pool)
            .await
            .unwrap();
        s
    }

    pub async fn pick_p(&self, s: &str, chain: &[Entry], now: &str, p: P<'_>) -> Outcome {
        let args = (p.user, p.used.to_vec(), p.skip.to_vec(), p.from, p.commit);
        let (pool, runner) = (self.fx.app.pool.clone(), self.vm.id.clone());
        pick_owned(
            pool,
            runner,
            s.to_owned(),
            chain.to_vec(),
            now.to_owned(),
            args,
        )
        .await
    }

    pub async fn pick(&self, s: &str, chain: &[Entry], now: &str) -> Outcome {
        self.pick_p(s, chain, now, p()).await
    }

    pub async fn signal(
        &self,
        account: i64,
        status: UpstreamStatus,
        retry: Option<u64>,
        now: &str,
    ) {
        let mut tx = begin_write(&self.fx.app.pool).await.unwrap();
        let sig = Signal::Gateway {
            status,
            retry_after: retry,
            reset_at: None,
        };
        health::on_signal(&mut tx, account, "as_signal", sig, now)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    pub async fn end(&self, id: &str, now: &str) {
        let done = json!({"kind": "succeeded"});
        store::end(&self.fx.app.pool, id, "ended", &done, now)
            .await
            .unwrap();
    }

    pub async fn count(&self, sql: &str, bind: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .bind(bind)
            .fetch_one(&self.fx.app.pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn least_loaded_then_least_recently_used_then_seat() {
    let w = w().await;
    let ids = [
        w.acct("a").await.id,
        w.acct("b").await.id,
        w.acct("c").await.id,
    ];
    let chain = [w.keys("main", &ids).await];
    let mut got = Vec::new();
    for i in 0..4 {
        let s = w.session(&chain, &[]).await;
        got.push(took(w.pick(&s.id, &chain, &at(i)).await).account);
    }
    // Idle accounts in seat order, then every load is one and the oldest use goes first.
    assert_eq!(got, [ids[0], ids[1], ids[2], ids[0]]);
}

#[tokio::test]
async fn an_idle_pool_rotates_so_nothing_starves() {
    let w = w().await;
    let ids = [
        w.acct("a").await.id,
        w.acct("b").await.id,
        w.acct("c").await.id,
    ];
    let chain = [w.keys("main", &ids).await];
    let mut got = Vec::new();
    for i in 0..9 {
        let s = w.session(&chain, &[]).await;
        got.push(took(w.pick(&s.id, &chain, &at(i * 10)).await).account);
        w.end(&s.id, &at(i * 10 + 1)).await;
    }
    let want: Vec<i64> = (0..9).map(|i| ids[i % 3]).collect();
    assert_eq!(got, want);
}

#[tokio::test]
async fn fifty_concurrent_picks_never_take_more_than_the_cap() {
    let w = w().await;
    let a = w.acct("a").await;
    acc::set_cap(&w.fx.app.pool, a.id, 3, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let chain = vec![w.keys("main", &[a.id]).await];
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let s = w.session(&chain, &[]).await;
        let args = (1, vec![], vec![], 0, true);
        let (pool, runner) = (w.fx.app.pool.clone(), w.vm.id.clone());
        tasks.push(tokio::spawn(pick_owned(
            pool,
            runner,
            s.id,
            chain.clone(),
            NOW.to_owned(),
            args,
        )));
    }
    let mut picked = 0;
    for t in tasks {
        picked += i32::from(matches!(t.await.unwrap(), Outcome::Picked(_)));
    }
    assert_eq!(picked, 3);
    let live =
        "SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND state = 'starting'";
    assert_eq!(w.count(live, &a.id.to_string()).await, 3);
}

#[tokio::test]
async fn a_cap_of_zero_is_off_and_an_interrupted_session_holds_its_slot_until_lost_after() {
    let w = w().await;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    acc::set_cap(&w.fx.app.pool, b.id, 1, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    acc::set_cap(&w.fx.app.pool, a.id, 0, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let off = [w.keys("off", &[a.id]).await];
    for _ in 0..6 {
        let s = w.session(&off, &[]).await;
        assert_eq!(took(w.pick(&s.id, &off, NOW).await).account, a.id);
    }
    let one = [w.keys("one", &[b.id]).await];
    let held = w.session(&one, &[]).await;
    took(w.pick(&held.id, &one, NOW).await);
    store::set_state(&w.fx.app.pool, &held.id, "interrupted", "test", false, NOW)
        .await
        .unwrap();
    let next = w.session(&one, &[]).await;
    let soon = at(LOST_AFTER_SECS - 1);
    assert!(matches!(
        w.pick(&next.id, &one, &soon).await,
        Outcome::Exhausted(_)
    ));
    let late = at(LOST_AFTER_SECS + 1);
    assert_eq!(took(w.pick(&next.id, &one, &late).await).account, b.id);
}

#[tokio::test]
async fn an_account_of_another_user_is_never_picked() {
    let w = w().await;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&w.fx.app.pool)
        .await
        .unwrap();
    let (mine, theirs) = (w.acct("mine").await, w.acct("theirs").await);
    let sub = w.sub("their-plan").await;
    for id in [theirs.id, sub.id] {
        sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
            .bind(id)
            .execute(&w.fx.app.pool)
            .await
            .unwrap();
    }
    // The other user's account has the lower seat and no load, and still is not offered.
    let mixed = [w.keys("mixed", &[theirs.id, mine.id]).await];
    let s = w.session(&mixed, &[]).await;
    assert_eq!(took(w.pick(&s.id, &mixed, NOW).await).account, mine.id);
    let plan = [w.pool("plan", "claude-sub", &[sub.id]).await];
    let s = w.session(&plan, &[]).await;
    assert!(matches!(
        w.pick(&s.id, &plan, NOW).await,
        Outcome::Exhausted(_)
    ));
    let as_second = P { user: 2, ..p() };
    took(w.pick_p(&s.id, &plan, NOW, as_second).await);
    let s2 = w.session(&mixed, &[]).await;
    let as_second = P { user: 2, ..p() };
    assert_eq!(
        took(w.pick_p(&s2.id, &mixed, NOW, as_second).await).account,
        theirs.id
    );
}

#[tokio::test]
async fn an_account_the_runner_may_not_be_leased_is_never_picked() {
    let w = w().await;
    let other = super::secrets::runner(&w.fx, "other").await;
    let a = make(
        &w.fx,
        &w.sealer,
        "elsewhere",
        "throwaway-account-value-x-5a91c3",
        std::slice::from_ref(&other.id),
    )
    .await;
    let none = make(
        &w.fx,
        &w.sealer,
        "nowhere",
        "throwaway-account-value-y-5a91c3",
        &[],
    )
    .await;
    let chain = [w.keys("main", &[a.id, none.id]).await];
    let s = w.session(&chain, &[]).await;
    match w.pick(&s.id, &chain, NOW).await {
        Outcome::Exhausted(r) => assert!(r[0].1.contains("2 not leasable to this runner"), "{r:?}"),
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn used_accounts_are_left_out_and_the_chain_starts_at_from_pos() {
    let w = w().await;
    let (a, b, c) = (w.acct("a").await, w.acct("b").await, w.acct("c").await);
    let chain = [
        w.keys("one", &[a.id, b.id]).await,
        w.keys("two", &[c.id]).await,
    ];
    let s = w.session(&chain, &[]).await;
    let used = P {
        used: &[a.id],
        commit: false,
        ..p()
    };
    assert_eq!(took(w.pick_p(&s.id, &chain, NOW, used).await).account, b.id);
    let used = P {
        used: &[a.id, b.id],
        commit: false,
        ..p()
    };
    let got = took(w.pick_p(&s.id, &chain, NOW, used).await);
    assert_eq!((got.account, got.pos), (c.id, 1));
    let used = P {
        used: &[a.id, b.id, c.id],
        commit: false,
        ..p()
    };
    assert!(matches!(
        w.pick_p(&s.id, &chain, NOW, used).await,
        Outcome::Exhausted(_)
    ));
    // Forward only: from the second entry the first is never looked at.
    let from = P {
        from: 1,
        commit: false,
        ..p()
    };
    assert_eq!(took(w.pick_p(&s.id, &chain, NOW, from).await).account, c.id);
}
