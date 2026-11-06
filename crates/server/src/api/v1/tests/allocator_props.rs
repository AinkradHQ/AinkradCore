//! A seeded random walk over the allocator with a clock the test moves (KAN-437 S4 property
//! test; a plain LCG, so no dependency and a failing seed reproduces). Steps: pick, end, interrupt,
//! gateway signal, advance the clock, set a cap, disable or enable an account. After every step:
//! no session holds two account secrets, no chain session holds another user's account; and right
//! after a pick, the account is the asker's, `active`, not in `used_accounts`, and its live count
//! is within its cap.

use ainkrad_proto::v2::UpstreamStatus;

use super::allocator::{P, W, took, w};
use super::health::at;
use crate::store::accounts as acc;
use crate::store::agents as store;
use crate::store::alloc::{Entry, LOST_AFTER_SECS, Outcome};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from((self.0 >> 33) % n as u64).unwrap()
    }
}

async fn mk(w: &W, accounts: &mut Vec<i64>, label: &str) -> i64 {
    let id = w.acct(label).await.id;
    accounts.push(id);
    id
}

struct Sim {
    w: W,
    rng: Rng,
    chains: [Vec<Entry>; 2],
    accounts: Vec<i64>,
    sessions: Vec<(String, i64)>,
    t: i64,
    picked: u32,
}

impl Sim {
    async fn new(seed: u64) -> Self {
        let w = w().await;
        sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
            .execute(&w.fx.app.pool)
            .await
            .unwrap();
        let mut accounts = Vec::new();
        let (a1, a2) = (
            mk(&w, &mut accounts, "a1").await,
            mk(&w, &mut accounts, "a2").await,
        );
        let b1 = mk(&w, &mut accounts, "b1").await;
        let (b2, b3) = (
            mk(&w, &mut accounts, "b2").await,
            mk(&w, &mut accounts, "b3").await,
        );
        let (u2x, c1) = (
            mk(&w, &mut accounts, "u2x").await,
            mk(&w, &mut accounts, "c1").await,
        );
        let plan = w.sub("plan").await;
        accounts.push(plan.id);
        for id in [u2x, c1] {
            sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
                .bind(id)
                .execute(&w.fx.app.pool)
                .await
                .unwrap();
        }
        let p1 = w.keys("p1", &[a1, u2x, a2]).await;
        let p2 = w.keys("p2", &[b1, b2, b3]).await;
        let ps = w.pool("ps", "claude-sub", &[plan.id]).await;
        let pu = w.keys("pu", &[c1]).await;
        let chains = [vec![p1.clone(), p2, ps], vec![p1, pu]];
        Self {
            w,
            rng: Rng(seed),
            chains,
            accounts,
            sessions: Vec::new(),
            t: 0,
            picked: 0,
        }
    }

    async fn live(&self, account: i64) -> i64 {
        let floor = crate::scheduler::iso_of_unix(
            crate::scheduler::unix_secs(&at(self.t)).unwrap() - LOST_AFTER_SECS,
        );
        sqlx::query_scalar(
            "SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND (state IN \
             ('starting', 'running') OR (state = 'interrupted' AND julianday(updated_at) > \
             julianday(?)))",
        )
        .bind(account)
        .bind(floor)
        .fetch_one(&self.w.fx.app.pool)
        .await
        .unwrap()
    }

    async fn step(&mut self) {
        let (pool, now) = (self.w.fx.app.pool.clone(), at(self.t));
        let account = self.accounts[self.rng.below(self.accounts.len())];
        match self.rng.below(7) {
            0 | 1 => self.pick(&now).await,
            2 if !self.sessions.is_empty() => {
                let i = self.rng.below(self.sessions.len());
                self.w.end(&self.sessions[i].0.clone(), &now).await;
            }
            3 if !self.sessions.is_empty() => {
                let i = self.rng.below(self.sessions.len());
                let id = self.sessions[i].0.clone();
                store::set_state(&pool, &id, "interrupted", "t", false, &now)
                    .await
                    .unwrap();
            }
            4 => {
                let status = [
                    UpstreamStatus::RateLimited,
                    UpstreamStatus::Quota,
                    UpstreamStatus::ServerError,
                ][self.rng.below(3)];
                let retry = 30 + self.rng.below(1200) as u64;
                self.w.signal(account, status, Some(retry), &now).await;
            }
            5 => self.t += self.rng.below(1500) as i64,
            _ => {
                let cap = self.rng.below(4) as i64;
                acc::set_cap(&pool, account, cap, &self.w.fx.dev.id, BY, &now)
                    .await
                    .unwrap();
                let state = ["active", "active", "disabled"][self.rng.below(3)];
                let by = &self.w.fx.dev.id;
                acc::set_state(&pool, account, state, None, None, by, BY, &now)
                    .await
                    .unwrap();
            }
        }
    }

    async fn pick(&mut self, now: &str) {
        let user = 1 + self.rng.below(2);
        let chain = self.chains[user - 1].clone();
        let used: Vec<i64> = (0..self.rng.below(3))
            .map(|_| self.accounts[self.rng.below(self.accounts.len())])
            .collect();
        let s = self.w.session(&chain, &[]).await;
        sqlx::query("UPDATE core_agent_sessions SET user_id = ? WHERE id = ?")
            .bind(user as i64)
            .bind(&s.id)
            .execute(&self.w.fx.app.pool)
            .await
            .unwrap();
        let ask = P {
            user: user as i64,
            used: &used,
            ..super::allocator::p()
        };
        let got = self.w.pick_p(&s.id, &chain, now, ask).await;
        self.sessions.push((s.id.clone(), user as i64));
        if let Outcome::Picked(_) = &got {
            let p = took(got);
            self.picked += 1;
            let (owner, state, cap): (i64, String, i64) =
                sqlx::query_as("SELECT user_id, state, cap FROM core_accounts WHERE id = ?")
                    .bind(p.account)
                    .fetch_one(&self.w.fx.app.pool)
                    .await
                    .unwrap();
            assert_eq!(owner, user as i64, "another user's account");
            assert_eq!(state, "active", "an account that is not active");
            assert!(!used.contains(&p.account), "a used account");
            let live = self.live(p.account).await;
            assert!(cap == 0 || live <= cap, "{live} live on a cap of {cap}");
        }
    }

    async fn check(&self) {
        let pool = &self.w.fx.app.pool;
        let doubled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM core_agent_sessions s WHERE \
             (SELECT count(*) FROM json_each(s.secrets) j \
              WHERE json_extract(j.value, '$.name') GLOB 'acct.*') > 1",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(doubled, 0, "a session holds two accounts");
        let crossed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM core_agent_sessions s JOIN core_accounts a ON a.id = s.account_id \
             WHERE s.chain IS NOT NULL AND a.user_id != s.user_id",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(crossed, 0, "a session holds another user's account");
    }
}

#[tokio::test]
async fn a_random_walk_never_breaks_the_cap_the_user_the_state_or_one_account_per_session() {
    let mut picked = 0;
    for seed in 1..=8 {
        let mut sim = Sim::new(seed).await;
        for _ in 0..45 {
            sim.step().await;
            sim.check().await;
        }
        picked += sim.picked;
    }
    // The walk does pick: the checks above ran on real assignments.
    assert!(picked > 30, "{picked} picks");
}
