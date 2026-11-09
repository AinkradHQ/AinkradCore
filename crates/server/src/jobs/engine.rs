//! The engine that fires and runs jobs (E2-11.1): each tick queues what is due, claims what is
//! ready and runs it on its own task, so a long job never holds up the others.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::task::JoinSet;

use super::store::{self, Claimed};
use super::{Job, JobHandler, Run};
use crate::module::Module;
use crate::scheduler::Clock;

/// The engine's knobs.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Time between ticks. A wake waits at most this long.
    // ponytail: polling; a `Notify` from `wake` if sub-second latency ever matters.
    pub every: Duration,
    /// How long a claim holds a run without a heartbeat.
    pub lease_secs: i64,
    /// How often a running job extends its lease: well inside `lease_secs`.
    pub heartbeat: Duration,
    /// Runs in flight at once.
    pub max_parallel: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            every: Duration::from_secs(1),
            lease_secs: 60,
            heartbeat: Duration::from_secs(20),
            max_parallel: 8,
        }
    }
}

type Handlers = HashMap<(String, String), Arc<dyn JobHandler>>;

pub struct Engine {
    pool: SqlitePool,
    clock: Arc<dyn Clock + Send + Sync>,
    handlers: Handlers,
    /// Names this process's claims; a new one per start, so a restart cannot settle a run an
    /// earlier process claimed.
    holder: String,
    config: Config,
}

impl Engine {
    /// An engine for the jobs of `modules`. `jobs::register` must have recorded them.
    pub fn new(
        pool: SqlitePool,
        clock: Arc<dyn Clock + Send + Sync>,
        modules: &[Arc<dyn Module>],
        config: Config,
    ) -> Arc<Self> {
        let mut handlers = Handlers::new();
        for m in modules {
            for Job { name, handler, .. } in m.jobs() {
                handlers.insert((m.id().to_owned(), name.to_owned()), handler);
            }
        }
        Arc::new(Self {
            pool,
            clock,
            handlers,
            holder: crate::auth::crypto::random_id("h_"),
            config,
        })
    }

    /// One pass: queue what is due, claim what is ready (up to the free slots), start it on
    /// `running`. Returns how many runs started.
    pub async fn tick_into(
        self: &Arc<Self>,
        running: &mut JoinSet<()>,
    ) -> Result<usize, sqlx::Error> {
        let now = self.clock.now();
        store::fire_due(&self.pool, &now).await?;
        let free = self.config.max_parallel.saturating_sub(running.len());
        let claims = match free {
            0 => vec![],
            n => store::claim(&self.pool, &now, &self.holder, self.config.lease_secs, n).await?,
        };
        let started = claims.len();
        for c in claims {
            running.spawn(Arc::clone(self).execute(c));
        }
        store::prune(&self.pool, &now, 500).await?;
        Ok(started)
    }

    /// [`Engine::tick_into`] and wait for what it started: what tests and one-off passes use.
    pub async fn tick(self: &Arc<Self>) -> Result<usize, sqlx::Error> {
        let mut running = JoinSet::new();
        let started = self.tick_into(&mut running).await?;
        while running.join_next().await.is_some() {}
        Ok(started)
    }

    /// Ticks every `config.every` until `shutdown` completes, then gives what is running ten
    /// seconds to finish; a run cut off keeps its lease and is retried when it expires.
    pub async fn run(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut every = tokio::time::interval(self.config.every);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut running = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                Some(_) = running.join_next(), if !running.is_empty() => {}
                _ = every.tick() => {
                    if let Err(e) = self.tick_into(&mut running).await {
                        eprintln!("ainkrad-core-server: job tick failed: {e}");
                    }
                }
            }
        }
        let drain = async { while running.join_next().await.is_some() {} };
        let _ = tokio::time::timeout(Duration::from_secs(10), drain).await;
    }

    /// Runs one claimed run to its end, keeping its lease alive meanwhile.
    async fn execute(self: Arc<Self>, c: Claimed) {
        let result = match self.handlers.get(&(c.run.owner.clone(), c.run.job.clone())) {
            None => Err("no handler for this job in this build".to_owned()),
            Some(handler) => self.work(handler, &c.run).await,
        };
        let now = self.clock.now();
        match store::finish(&self.pool, &now, &self.holder, &c, &result).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(run = c.run.id, "job run lost its lease; not settled"),
            Err(e) => tracing::warn!(run = c.run.id, error = %e, "settling a job run failed"),
        }
    }

    async fn work(&self, handler: &Arc<dyn JobHandler>, run: &Run) -> Result<(), String> {
        let work = handler.run(run);
        tokio::pin!(work);
        let mut beat = tokio::time::interval(self.config.heartbeat);
        beat.tick().await;
        loop {
            tokio::select! {
                result = &mut work => return result,
                _ = beat.tick() => {
                    let now = self.clock.now();
                    let kept = store::heartbeat(&self.pool, &now, &self.holder, run.id, self.config.lease_secs);
                    match kept.await {
                        Ok(true) => {}
                        Ok(false) => tracing::warn!(run = run.id, "job run lost its lease"),
                        Err(e) => tracing::warn!(run = run.id, error = %e, "job heartbeat failed"),
                    }
                }
            }
        }
    }
}
