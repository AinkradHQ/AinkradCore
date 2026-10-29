//! Warm harness servers (E15.6, pain #2): after a run that succeeded, a long-lived harness
//! (`Harness::LONG_LIVED`: OpenCode `serve`, Codex `app-server`) is kept idle instead of
//! stopped, and the next run with the same key opens a new session on it (`Harness::renew`):
//! a fresh context, without the process start. The key is everything fixed when the process
//! started: agent, harness, program, config dir, environment (an account's token only as a
//! hash) and which run files it reads. At most `runner.warm_max` are kept; the oldest goes, and
//! any idle for `runner.warm_idle_secs` is stopped by the runner's clean-up pass (E15.9). A warm
//! process works from the work root, not a worktree, which may be removed while it idles.

use std::any::Any;
use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ainkrad_harness::{Harness, Spec};

use crate::Job;

/// An idle harness process of any adapter.
trait Idle: Send {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
    fn stop(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

impl<H: Harness> Idle for H {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }

    fn stop(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            Harness::stop(*self).await;
        })
    }
}

/// An idle process under its key, and when it went idle.
type Kept = (String, Box<dyn Idle>, Instant);

/// The idle processes, oldest first.
#[derive(Default)]
pub(crate) struct Warm(Mutex<Vec<Kept>>);

impl Warm {
    /// The idle process kept under `key`, if any.
    pub fn take<H: Harness>(&self, key: &str) -> Option<H> {
        let mut idle = self.0.lock().expect("warm lock");
        let at = idle.iter().position(|(k, ..)| k == key)?;
        let (_, h, _) = idle.remove(at);
        h.into_any().downcast::<H>().ok().map(|h| *h)
    }

    /// Keeps `h` idle under `key`, stopping the oldest beyond `max` (all of them at 0).
    pub async fn keep<H: Harness>(&self, key: String, h: H, max: usize) {
        let evicted: Vec<Box<dyn Idle>> = {
            let mut idle = self.0.lock().expect("warm lock");
            idle.push((key, Box::new(h), Instant::now()));
            let over = idle.len().saturating_sub(max);
            idle.drain(..over).map(|(_, h, _)| h).collect()
        };
        for h in evicted {
            h.stop().await;
        }
    }

    /// Stops every process idle for `max` or longer.
    pub async fn evict_idle(&self, max: Duration) {
        let evicted: Vec<Box<dyn Idle>> = {
            let mut idle = self.0.lock().expect("warm lock");
            let (old, kept) = idle.drain(..).partition(|(.., at)| at.elapsed() >= max);
            *idle = kept;
            old.into_iter().map(|(_, h, _)| h).collect()
        };
        for h in evicted {
            tracing::info!("a warm harness idled past its limit; stopping it");
            h.stop().await;
        }
    }

    /// How many are idle.
    pub fn len(&self) -> usize {
        self.0.lock().expect("warm lock").len()
    }
}

/// What a process for `job` with `spec` was started with, as a reuse key.
pub(crate) fn key(job: &Job, spec: &Spec) -> String {
    let mut env = DefaultHasher::new();
    spec.env_allow.hash(&mut env);
    spec.env.hash(&mut env);
    format!(
        "{}|{}|{:?}|{}|{:x}|{:?}|{:?}",
        job.agent,
        job.harness,
        spec.program,
        spec.config_dir.display(),
        env.finish(),
        spec.mcp_config,
        spec.instructions
    )
}
