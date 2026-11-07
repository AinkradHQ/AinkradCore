//! S8, the walk: a seeded random walk over whole runs (a plain LCG, a clock the test moves) that
//! mixes every way a session's life can go: a new run, a start, an end of any class, a lost runner,
//! an interrupt, a wake and a resume (reopen), a person's cancel, a pass over the waiting attempts, a
//! settle (some moves rolled back first), a forged harness signal, a Core restart (the start-up scan,
//! run twice), and time. After EVERY step:
//!
//! - I1: a session's account, once the row names one, never changes, whatever happened to it;
//! - I2: never two live attempts of one run; I3: no account twice in a run, no step back;
//! - I4: no account has more live sessions than its cap, after a wake or a resume too;
//! - I5: no chain session holds another user's account; a session holds at most one account secret;
//! - no hold outlives its session, and a never-reopened live session of a budgeted account holds one.
//!
//! The seed is in every message; `NEG_SEED=<n>` replays one seed.

use std::collections::HashMap;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::allocator::{W, pick_owned, w};
use super::failover::{budget, mv};
use super::health::at;
use super::neg_rng::{Rng, seeds};
use crate::store::accounts as acc;
use crate::store::agents::{self as store, Woken};
use crate::store::alloc::{self, Entry, Outcome};
use crate::store::failover::{self as fo, Decision, Moved};
use crate::store::{begin_write, health};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

struct Sim {
    w: W,
    rng: Rng,
    seed: u64,
    chains: [Vec<Entry>; 2],
    caps: Vec<(i64, i64)>,
    budgeted: Vec<i64>,
    other: String,
    assigned: HashMap<String, i64>,
    reopened: Vec<String>,
    t: i64,
    runs: Vec<String>,
    step: usize,
}

impl Sim {
    async fn new(seed: u64) -> Self {
        let w = w().await;
        let pool = &w.fx.app.pool;
        sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
            .execute(pool)
            .await
            .unwrap();
        let other = super::secrets::runner(&w.fx, "second").await.id;
        sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
            .bind(&other)
            .execute(pool)
            .await
            .unwrap();
        let mut caps = Vec::new();
        let mut ids = Vec::new();
        for (label, cap) in [
            ("k1", 1),
            ("k2", 1),
            ("k3", 1),
            ("m1", 2),
            ("m2", 2),
            ("u2x", 1),
            ("c1", 2),
        ] {
            let a = w.acct(label).await;
            acc::set_cap(pool, a.id, cap, &w.fx.dev.id, BY, super::NOW)
                .await
                .unwrap();
            caps.push((a.id, cap));
            ids.push(a.id);
        }
        let plan = w.sub("plan").await;
        caps.push((plan.id, 2));
        acc::set_cap(pool, plan.id, 2, &w.fx.dev.id, BY, super::NOW)
            .await
            .unwrap();
        // Pools are the first user's; the second user's accounts sit in them too, and are never picked for the first.
        let p1 = w.keys("p1", &[ids[0], ids[1], ids[2], ids[5]]).await;
        let p2 = w.keys("p2", &[ids[3], ids[4]]).await;
        let p3 = w.pool("p3", "claude-sub", &[plan.id]).await;
        let pu = w.keys("pu", &[ids[6]]).await;
        for id in [ids[5], ids[6]] {
            sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
        budget(&w, p1.pool).await;
        let chains = [vec![p3, p1.clone(), p2], vec![p1, pu]];
        Self {
            w,
            rng: Rng(seed),
            seed,
            chains,
            caps,
            budgeted: vec![ids[0], ids[1], ids[2], ids[5]],
            other,
            assigned: HashMap::new(),
            reopened: Vec::new(),
            t: 0,
            runs: Vec::new(),
            step: 0,
        }
    }

    fn ctx(&self) -> String {
        format!("seed {} step {}", self.seed, self.step)
    }

    async fn ids(&self, filter: &str) -> Vec<String> {
        let sql = format!("SELECT id FROM core_agent_sessions WHERE {filter} ORDER BY n");
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.w.fx.app.pool)
            .await
            .unwrap()
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_one(&self.w.fx.app.pool)
            .await
            .unwrap()
    }

    fn some(&mut self, ids: &[String]) -> Option<String> {
        (!ids.is_empty()).then(|| ids[self.rng.below(ids.len())].clone())
    }

    async fn pick(&self, id: &str) -> Outcome {
        let pool = &self.w.fx.app.pool;
        let mut conn = pool.acquire().await.unwrap();
        let (used, skip) = fo::context_in(&mut conn, id).await.unwrap();
        let (chain, pos, user): (String, Option<i64>, i64) = sqlx::query_as(
            "SELECT chain, chain_pos, user_id FROM core_agent_sessions WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        drop(conn);
        let chain: Vec<Entry> = serde_json::from_str(&chain).unwrap();
        let from = usize::try_from(pos.unwrap_or(0)).unwrap();
        let args = (user, used, skip, from, true);
        let runner = self.w.vm.id.clone();
        pick_owned(pool.clone(), runner, id.to_owned(), chain, at(self.t), args).await
    }

    async fn fail_core(&self, id: &str) {
        let o = json!({"kind": "failed", "reason": "no account", "fingerprint": "core"});
        let pool = &self.w.fx.app.pool;
        store::end(pool, id, "ended", &o, &at(self.t))
            .await
            .unwrap();
    }

    async fn waiting(&mut self) {
        for id in self.ids("state = 'starting' AND account_id IS NULL").await {
            if let Outcome::Exhausted(_) = self.pick(&id).await {
                self.fail_core(&id).await;
            }
        }
    }

    async fn start_all(&mut self) {
        let pool = &self.w.fx.app.pool;
        for id in self
            .ids("state = 'starting' AND account_id IS NOT NULL AND start_sent = 0")
            .await
        {
            alloc::mark_start_sent(pool, &id).await.unwrap();
            sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h' WHERE id = ?")
                .bind(&id)
                .execute(pool)
                .await
                .unwrap();
            store::set_state(pool, &id, "running", "t", false, &at(self.t))
                .await
                .unwrap();
        }
    }

    /// One pass over the over, unsettled attempts: decide, move or settle. `redo` runs every move again.
    async fn settle(&mut self, ids: Vec<String>, rollback_some: bool, redo: bool) {
        let pool = self.w.fx.app.pool.clone();
        let mut moved = Vec::new();
        for id in ids {
            let v = fo::view(&pool, &id).await.unwrap().unwrap();
            match fo::decide(&v) {
                Decision::End(_) => fo::settle(&pool, &id).await.unwrap(),
                Decision::Move(class) => {
                    if rollback_some && self.rng.below(3) == 0 {
                        let before = self.count("SELECT count(*) FROM core_agent_sessions").await;
                        mv(&self.w, &id, &class, &at(self.t), false).await;
                        let after = self.count("SELECT count(*) FROM core_agent_sessions").await;
                        assert_eq!(
                            before,
                            after,
                            "a rolled-back move left a row, {}",
                            self.ctx()
                        );
                    }
                    mv(&self.w, &id, &class, &at(self.t), true).await;
                    moved.push((id, class));
                }
            }
        }
        if redo {
            let before = self.count("SELECT count(*) FROM core_agent_sessions").await;
            for (id, class) in moved {
                let again = mv(&self.w, &id, &class, &at(self.t), true).await;
                assert_eq!(
                    again,
                    Moved::Skipped,
                    "a second pass moved it again, {}",
                    self.ctx()
                );
            }
            let after = self.count("SELECT count(*) FROM core_agent_sessions").await;
            assert_eq!(
                before,
                after,
                "a restart pass made a second successor, {}",
                self.ctx()
            );
        }
    }

    async fn forged_signal(&mut self) {
        let account = self.caps[self.rng.below(self.caps.len())].0;
        let classes = [
            "rate_limited",
            "quota",
            "auth",
            "transient",
            "core",
            "claude:401",
        ];
        let class = classes[self.rng.below(classes.len())];
        let pool = &self.w.fx.app.pool;
        let mut tx = begin_write(pool).await.unwrap();
        let sig = health::Signal::HarnessEnd { class };
        health::on_signal(&mut tx, account, "as_forged", sig, &at(self.t))
            .await
            .unwrap();
        let gate = [UpstreamStatus::RateLimited, UpstreamStatus::ServerError][self.rng.below(2)];
        let sig = health::Signal::Gateway {
            status: gate,
            retry_after: Some(90),
            reset_at: None,
        };
        health::on_signal(&mut tx, account, "as_gw", sig, &at(self.t))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn go(&mut self) {
        let pool = self.w.fx.app.pool.clone();
        let now = at(self.t);
        match self.rng.below(13) {
            0 | 1 if self.runs.len() < 14 => {
                let user = self.rng.below(2);
                let chain = self.chains[user].clone();
                let by = [self.w.fx.dev.id.clone(), self.other.clone()][user].clone();
                let s = self.w.session_by(&chain, &[], &by).await;
                if let Outcome::Exhausted(_) = self.pick(&s.id).await {
                    self.fail_core(&s.id).await;
                }
                self.runs.push(s.id);
            }
            2 => self.start_all().await,
            3 | 4 => {
                let live = self.ids("state IN ('running', 'interrupted')").await;
                if let Some(id) = self.some(&live) {
                    let outcomes: [Value; 7] = [
                        json!({"kind": "succeeded"}),
                        json!({"kind": "failed", "reason": "x", "fingerprint": "rate_limited"}),
                        json!({"kind": "failed", "reason": "x", "fingerprint": "quota"}),
                        json!({"kind": "failed", "reason": "x", "fingerprint": "auth"}),
                        json!({"kind": "failed", "reason": "x", "fingerprint": "transient"}),
                        json!({"kind": "cancelled", "reason": "x"}),
                        json!({"kind": "failed", "reason": "x", "fingerprint": "core"}),
                    ];
                    let o = &outcomes[self.rng.below(outcomes.len())];
                    store::end(&pool, &id, "ended", o, &now).await.unwrap();
                }
            }
            5 => {
                let ids = fo::unfinished(&pool).await.unwrap();
                self.settle(ids, true, false).await;
            }
            6 => self.waiting().await,
            7 => {
                if let Some(id) = self.some(&self.runs.clone()) {
                    let newest = fo::cancel_run(&pool, &id).await.unwrap().newest;
                    if !alloc::end_unstarted(&pool, &newest, &now).await.unwrap() {
                        let o = json!({"kind": "cancelled", "reason": "person"});
                        store::end(&pool, &newest, "ended", &o, &now).await.unwrap();
                    }
                }
            }
            8 => {
                // A wake: of anything a client could wake, and the ones it could not.
                let ids = self.ids("state IN ('ended', 'lost', 'interrupted')").await;
                if let Some(id) = self.some(&ids)
                    && store::wake(&pool, &id, Some("more"), &now).await.unwrap() == Woken::Reopened
                {
                    self.reopened.push(id);
                }
            }
            9 => {
                let ids = self.ids("state IN ('lost', 'interrupted')").await;
                if let Some(id) = self.some(&ids)
                    && store::reopen(&pool, &id, &now).await.unwrap()
                {
                    self.reopened.push(id);
                }
            }
            10 => {
                let running = self.ids("state = 'running'").await;
                if let Some(id) = self.some(&running) {
                    if self.rng.below(2) == 0 {
                        store::end(&pool, &id, "lost", &json!({"kind": "lost"}), &now)
                            .await
                            .unwrap();
                    } else {
                        store::set_state(&pool, &id, "interrupted", "t", false, &now)
                            .await
                            .unwrap();
                    }
                }
            }
            11 => {
                // A Core restart: the start-up scan, twice.
                let ids = fo::unfinished_since(&pool, &at(self.t - 900))
                    .await
                    .unwrap();
                self.settle(ids, false, true).await;
            }
            _ => match self.rng.below(3) {
                0 => self.forged_signal().await,
                _ => self.t += self.rng.int(1, 900),
            },
        }
    }

    async fn check(&mut self) {
        let ctx = self.ctx();
        let pool = &self.w.fx.app.pool;
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT id, account_id FROM core_agent_sessions WHERE account_id IS NOT NULL",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        for (id, account) in rows {
            let first = *self.assigned.entry(id.clone()).or_insert(account);
            assert_eq!(first, account, "I1: {id} changed its account, {ctx}");
        }
        let live = "state NOT IN ('ended', 'lost')";
        let two = format!(
            "SELECT count(*) FROM (SELECT 1 FROM core_agent_sessions WHERE {live} GROUP BY coalesce(run_id, id) HAVING count(*) > 1)"
        );
        assert_eq!(
            self.count(&two).await,
            0,
            "I2: two live attempts of a run, {ctx}"
        );
        for (a, cap) in &self.caps {
            let sql = format!(
                "SELECT count(*) FROM core_agent_sessions WHERE account_id = {a} AND state IN ('starting', 'running', 'interrupted')"
            );
            let n = self.count(&sql).await;
            assert!(n <= *cap, "I4: account {a} has {n} of {cap}, {ctx}");
        }
        let twice = "SELECT count(*) FROM (SELECT 1 FROM core_agent_sessions WHERE account_id IS NOT NULL GROUP BY coalesce(run_id, id), account_id HAVING count(*) > 1)";
        assert_eq!(
            self.count(twice).await,
            0,
            "I3: a run used an account twice, {ctx}"
        );
        let back = "SELECT count(*) FROM core_agent_sessions c JOIN core_agent_sessions p ON p.id = c.failover_of WHERE c.chain_pos < p.chain_pos";
        assert_eq!(self.count(back).await, 0, "I3: a run went back, {ctx}");
        let hops = format!(
            "SELECT count(*) FROM core_agent_sessions WHERE attempt > {}",
            fo::MAX_HOPS
        );
        assert_eq!(self.count(&hops).await, 0, "too many hops, {ctx}");
        let crossed = "SELECT count(*) FROM core_agent_sessions s JOIN core_accounts a ON a.id = s.account_id WHERE s.chain IS NOT NULL AND a.user_id != s.user_id";
        assert_eq!(
            self.count(crossed).await,
            0,
            "I5: another user's account, {ctx}"
        );
        let doubled = "SELECT count(*) FROM core_agent_sessions s WHERE (SELECT count(*) FROM json_each(s.secrets) j WHERE json_extract(j.value, '$.name') GLOB 'acct.*') > 1";
        assert_eq!(
            self.count(doubled).await,
            0,
            "a session holds two accounts, {ctx}"
        );
        let leaked = "SELECT count(*) FROM core_budget_holds h LEFT JOIN core_agent_sessions s ON s.id = h.session WHERE s.id IS NULL OR s.state IN ('ended', 'lost') OR s.account_id IS NULL";
        assert_eq!(
            self.count(leaked).await,
            0,
            "a hold outlived its session, {ctx}"
        );
        let ids = self
            .budgeted
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT id FROM core_agent_sessions WHERE {live} AND account_id IN ({ids})");
        for id in self.ids(&format!("{live} AND account_id IN ({ids})")).await {
            if self.reopened.contains(&id) {
                continue;
            }
            let n = self
                .count(&format!(
                    "SELECT count(*) FROM core_budget_holds WHERE session = '{id}'"
                ))
                .await;
            assert_eq!(
                n, 1,
                "a live session of a budgeted account holds one ({sql}), {ctx}"
            );
        }
    }

    async fn drain(&mut self) {
        for _ in 0..60 {
            self.t += 2000;
            self.step += 1;
            self.waiting().await;
            self.start_all().await;
            for id in self.ids("state IN ('running', 'interrupted')").await {
                let o = json!({"kind": "succeeded"});
                store::end(&self.w.fx.app.pool, &id, "ended", &o, &at(self.t))
                    .await
                    .unwrap();
            }
            let ids = fo::unfinished(&self.w.fx.app.pool).await.unwrap();
            self.settle(ids, false, false).await;
            self.check().await;
            if self.ids("state NOT IN ('ended', 'lost')").await.is_empty() {
                break;
            }
        }
        let ctx = self.ctx();
        assert!(
            self.ids("state NOT IN ('ended', 'lost')").await.is_empty(),
            "a run never ends, {ctx}"
        );
        assert!(
            fo::unfinished(&self.w.fx.app.pool)
                .await
                .unwrap()
                .is_empty(),
            "unsettled, {ctx}"
        );
        assert_eq!(
            self.count("SELECT count(*) FROM core_budget_holds").await,
            0,
            "a hold is left, {ctx}"
        );
    }
}

#[tokio::test]
async fn neg_a_random_walk_keeps_one_account_per_session_the_cap_the_user_and_every_hold() {
    for seed in seeds(&[3, 11, 29, 404, 7_777, 31_337]) {
        let mut sim = Sim::new(seed).await;
        for step in 0..90 {
            sim.step = step;
            sim.go().await;
            sim.check().await;
        }
        sim.drain().await;
    }
}
