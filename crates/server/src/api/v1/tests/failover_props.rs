//! A seeded random walk over whole runs (KAN-438 S6 property test; a plain LCG so a failing seed
//! reproduces, and a clock the test moves). Steps: a new run, a start, an end with a random
//! outcome, a settle of every over attempt (some first rolled back), a pass over the waiting
//! attempts, a person's cancel, and time. After every step:
//!
//! - never two live attempts of one run (I2), never an account over its cap (I4);
//! - a run never uses an account twice and its chain position never goes back (I3);
//! - no run has more than `MAX_HOPS` new attempts;
//! - a hold belongs to a live session that holds an account of a budgeted pool: no hold leaks on any
//!   path (a rolled-back move, a cancel, an exhausted chain, an end).
//!
//! At the end the clock runs past every wait and every run ends: nothing is live, held or unsettled.

use serde_json::{Value, json};

use super::allocator::{W, pick_owned, w};
use super::failover::{budget, mv};
use super::health::at;
use crate::store::accounts as acc;
use crate::store::agents as store;
use crate::store::alloc::{self, Entry, Outcome};
use crate::store::failover::{self as fo, Decision};

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

struct Sim {
    w: W,
    rng: Rng,
    chains: [Vec<Entry>; 2],
    caps: Vec<(i64, i64)>,
    budgeted: Vec<i64>,
    t: i64,
    runs: Vec<String>,
}

impl Sim {
    async fn new(seed: u64) -> Self {
        let w = w().await;
        let (by, pool) = (&w.fx.dev.id, &w.fx.app.pool);
        let mut caps = Vec::new();
        let mut keys = Vec::new();
        for (label, cap) in [("k1", 1), ("k2", 1), ("k3", 1), ("m1", 2), ("m2", 2)] {
            let a = w.acct(label).await;
            acc::set_cap(pool, a.id, cap, by, BY, super::NOW)
                .await
                .unwrap();
            caps.push((a.id, cap));
            keys.push(a.id);
        }
        let plan = w.sub("plan").await;
        caps.push((plan.id, 4));
        let p1 = w.keys("p1", &keys[..3]).await;
        let p2 = w.keys("p2", &keys[3..]).await;
        let p3 = w.pool("p3", "claude-sub", &[plan.id]).await;
        budget(&w, p1.pool).await;
        let budgeted = keys[..3].to_vec();
        let chains = [vec![p1.clone(), p2.clone()], vec![p3, p1, p2]];
        Self {
            w,
            rng: Rng(seed),
            chains,
            caps,
            budgeted,
            t: 0,
            runs: Vec::new(),
        }
    }

    async fn rows(&self, sql: &str) -> Vec<(String, String, i64)> {
        sqlx::query_as(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_all(&self.w.fx.app.pool)
            .await
            .unwrap()
    }

    /// The allocator's pick for an attempt, as the supervisor runs it: with its run's context.
    async fn pick(&self, id: &str, chain: &[Entry]) -> Outcome {
        let pool = &self.w.fx.app.pool;
        let mut conn = pool.acquire().await.unwrap();
        let (used, skip) = fo::context_in(&mut conn, id).await.unwrap();
        let pos: Option<i64> =
            sqlx::query_scalar("SELECT chain_pos FROM core_agent_sessions WHERE id = ?")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        drop(conn);
        let args = (
            1,
            used,
            skip,
            usize::try_from(pos.unwrap_or(0)).unwrap(),
            true,
        );
        pick_owned(
            pool.clone(),
            self.w.vm.id.clone(),
            id.to_owned(),
            chain.to_vec(),
            at(self.t),
            args,
        )
        .await
    }

    async fn chain_of(&self, id: &str) -> Vec<Entry> {
        let j: String = sqlx::query_scalar("SELECT chain FROM core_agent_sessions WHERE id = ?")
            .bind(id)
            .fetch_one(&self.w.fx.app.pool)
            .await
            .unwrap();
        serde_json::from_str(&j).unwrap()
    }

    async fn fail_core(&self, id: &str) {
        let o = json!({"kind": "failed", "reason": "no account", "fingerprint": "core"});
        store::end(&self.w.fx.app.pool, id, "ended", &o, &at(self.t))
            .await
            .unwrap();
    }

    async fn step(&mut self) {
        let pool = self.w.fx.app.pool.clone();
        match self.rng.below(7) {
            0 if self.runs.len() < 12 => {
                let chain = self.chains[self.rng.below(2)].clone();
                let s = self.w.session(&chain, &[]).await;
                if let Outcome::Exhausted(_) = self.pick(&s.id, &chain).await {
                    self.fail_core(&s.id).await;
                }
                self.runs.push(s.id);
            }
            1 => {
                for (id,) in self
                    .one("state = 'starting' AND account_id IS NOT NULL AND start_sent = 0")
                    .await
                {
                    alloc::mark_start_sent(&pool, &id).await.unwrap();
                    store::set_state(&pool, &id, "running", "t", false, &at(self.t))
                        .await
                        .unwrap();
                }
            }
            2 => {
                let outcomes: [Value; 7] = [
                    json!({"kind": "succeeded"}),
                    json!({"kind": "failed", "reason": "x", "fingerprint": "rate_limited"}),
                    json!({"kind": "failed", "reason": "x", "fingerprint": "quota"}),
                    json!({"kind": "failed", "reason": "x", "fingerprint": "auth"}),
                    json!({"kind": "failed", "reason": "x", "fingerprint": "transient"}),
                    json!({"kind": "cancelled", "reason": "x"}),
                    json!({"kind": "failed", "reason": "x", "fingerprint": "model_unavailable"}),
                ];
                let live = self.one("state = 'running'").await;
                if let Some((id,)) = live.get(self.rng.below(live.len().max(1))) {
                    let o = &outcomes[self.rng.below(outcomes.len())];
                    store::end(&pool, id, "ended", o, &at(self.t))
                        .await
                        .unwrap();
                }
            }
            3 => self.settle().await,
            4 => self.waiting().await,
            5 => {
                let id = self
                    .runs
                    .get(self.rng.below(self.runs.len().max(1)))
                    .cloned();
                if let Some(id) = id {
                    let newest = fo::cancel_run(&pool, &id).await.unwrap();
                    if !alloc::end_unstarted(&pool, &newest, &at(self.t))
                        .await
                        .unwrap()
                    {
                        let o = json!({"kind": "cancelled", "reason": "person"});
                        store::end(&pool, &newest, "ended", &o, &at(self.t))
                            .await
                            .unwrap();
                    }
                }
            }
            _ => self.t += 1 + i64::try_from(self.rng.below(700)).unwrap(),
        }
    }

    async fn one(&self, filter: &str) -> Vec<(String,)> {
        let sql = format!("SELECT id FROM core_agent_sessions WHERE {filter} ORDER BY n");
        sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.w.fx.app.pool)
            .await
            .unwrap()
    }

    /// Every over attempt whose failover is unsettled: decide, move or settle (some moves rolled back first).
    async fn settle(&mut self) {
        let pool = self.w.fx.app.pool.clone();
        for id in fo::unfinished(&pool).await.unwrap() {
            let v = fo::view(&pool, &id).await.unwrap().unwrap();
            match fo::decide(&v) {
                Decision::End(_) => fo::settle(&pool, &id).await.unwrap(),
                Decision::Move(class) => {
                    if self.rng.below(3) == 0 {
                        let before = self.count("SELECT count(*) FROM core_agent_sessions").await;
                        mv(&self.w, &id, &class, &at(self.t), false).await;
                        assert_eq!(
                            self.count("SELECT count(*) FROM core_agent_sessions").await,
                            before,
                            "a rollback leaves a row"
                        );
                    }
                    mv(&self.w, &id, &class, &at(self.t), true).await;
                }
            }
        }
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_one(&self.w.fx.app.pool)
            .await
            .unwrap()
    }

    /// The supervisor's pass over attempts that wait for an account.
    async fn waiting(&mut self) {
        for (id,) in self.one("state = 'starting' AND account_id IS NULL").await {
            let chain = self.chain_of(&id).await;
            if let Outcome::Exhausted(_) = self.pick(&id, &chain).await {
                self.fail_core(&id).await;
            }
        }
    }

    async fn check(&self, seed: u64, step: usize) {
        let ctx = format!("seed {seed} step {step}");
        let live = "state NOT IN ('ended', 'lost')";
        let sql = format!(
            "SELECT coalesce(run_id, id), '', count(*) FROM core_agent_sessions WHERE {live} GROUP BY 1 HAVING count(*) > 1"
        );
        assert!(
            self.rows(&sql).await.is_empty(),
            "two live attempts of a run, {ctx}"
        );
        for (a, cap) in &self.caps {
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND state IN ('starting', 'running', 'interrupted')")
                .bind(a).fetch_one(&self.w.fx.app.pool).await.unwrap();
            assert!(n <= *cap, "account {a} has {n} of {cap}, {ctx}");
        }
        let twice = "SELECT coalesce(run_id, id), '', count(*) FROM core_agent_sessions WHERE account_id IS NOT NULL GROUP BY coalesce(run_id, id), account_id HAVING count(*) > 1";
        assert!(
            self.rows(twice).await.is_empty(),
            "a run used an account twice, {ctx}"
        );
        let back = "SELECT c.id, '', 0 FROM core_agent_sessions c JOIN core_agent_sessions p ON p.id = c.failover_of WHERE c.chain_pos < p.chain_pos";
        assert!(
            self.rows(back).await.is_empty(),
            "a run went back along its chain, {ctx}"
        );
        let hops = format!(
            "SELECT id, '', attempt FROM core_agent_sessions WHERE attempt > {}",
            fo::MAX_HOPS
        );
        assert!(self.rows(&hops).await.is_empty(), "too many hops, {ctx}");
        let leaked = "SELECT h.session, '', 0 FROM core_budget_holds h LEFT JOIN core_agent_sessions s ON s.id = h.session WHERE s.id IS NULL OR s.state IN ('ended', 'lost') OR s.account_id IS NULL";
        assert!(
            self.rows(leaked).await.is_empty(),
            "a hold outlived its session or holds no account, {ctx}"
        );
        let ids = self
            .budgeted
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT count(*) FROM core_agent_sessions WHERE {live} AND account_id IN ({ids})"
        );
        let held = self
            .count("SELECT count(DISTINCT session) FROM core_budget_holds")
            .await;
        assert_eq!(
            held,
            self.count(&sql).await,
            "a live session on a budgeted pool must hold exactly one, {ctx}"
        );
    }

    async fn drain(&mut self, seed: u64) {
        for round in 0..40 {
            self.t += 2000;
            self.waiting().await;
            for (id,) in self
                .one("state = 'starting' AND account_id IS NOT NULL")
                .await
            {
                alloc::mark_start_sent(&self.w.fx.app.pool, &id)
                    .await
                    .unwrap();
                store::set_state(&self.w.fx.app.pool, &id, "running", "t", false, &at(self.t))
                    .await
                    .unwrap();
            }
            for (id,) in self.one("state = 'running'").await {
                let o = json!({"kind": "succeeded"});
                store::end(&self.w.fx.app.pool, &id, "ended", &o, &at(self.t))
                    .await
                    .unwrap();
            }
            self.settle().await;
            self.check(seed, 1000 + round).await;
            if self.one("state NOT IN ('ended', 'lost')").await.is_empty()
                && fo::unfinished(&self.w.fx.app.pool)
                    .await
                    .unwrap()
                    .is_empty()
            {
                break;
            }
        }
        assert!(
            self.one("state NOT IN ('ended', 'lost')").await.is_empty(),
            "seed {seed}: a run never ends"
        );
        assert!(
            fo::unfinished(&self.w.fx.app.pool)
                .await
                .unwrap()
                .is_empty(),
            "seed {seed}: an unsettled attempt"
        );
        assert_eq!(
            self.count("SELECT count(*) FROM core_budget_holds").await,
            0,
            "seed {seed}: a hold is left"
        );
    }
}

#[tokio::test]
async fn a_seeded_walk_over_runs_keeps_every_invariant_and_every_run_ends() {
    for seed in [1_u64, 7, 42, 1234, 99_999] {
        let mut sim = Sim::new(seed).await;
        for step in 0..70 {
            sim.step().await;
            sim.check(seed, step).await;
        }
        sim.drain(seed).await;
    }
}
