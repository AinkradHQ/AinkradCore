//! Name lookups for the egress proxy: the host's resolver, bounded per run and across runs.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Addresses taken from one answer.
pub const MAX_ANSWERS: usize = 16;
/// Lookups in flight across every run.
const GLOBAL_LOOKUPS: usize = 8;
/// Lookups one run may have in flight, so one run's connections cannot take every slot.
const RUN_LOOKUPS: usize = 2;
/// How long a lookup waits for a free slot before it is refused.
const LOOKUP_WAIT: Duration = Duration::from_millis(300);

pub type Answers<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Looks a name up. Only the proxy, outside the sandbox, ever holds one.
pub trait Resolve: Send + Sync {
    fn resolve<'a>(&'a self, name: &'a str) -> Answers<'a>;
}

/// The host's resolver.
pub struct System;

impl Resolve for System {
    fn resolve<'a>(&'a self, name: &'a str) -> Answers<'a> {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name, 0)).await?;
            Ok(found.map(|a| a.ip()).take(MAX_ANSWERS).collect())
        })
    }
}

fn global() -> Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(GLOBAL_LOOKUPS)))
        .clone()
}

/// Bounds another resolver with a per-run limit and the global one, each waited for briefly (a
/// lookup is a blocking `getaddrinfo` that a timeout cannot cancel). The permits move into the
/// lookup's task, so a lookup the caller gave up on keeps its slots until it really ends, and a
/// flood of lookups for a name whose server never answers cannot use up the blocking threads.
pub struct Limited {
    inner: Arc<dyn Resolve>,
    run: Arc<Semaphore>,
    wait: Duration,
}

impl Limited {
    pub fn new(inner: Arc<dyn Resolve>, per_run: usize, wait: Duration) -> Limited {
        Limited {
            inner,
            run: Arc::new(Semaphore::new(per_run)),
            wait,
        }
    }

    /// The host's resolver with the standard limits, for one run.
    pub fn system() -> Limited {
        Limited::new(Arc::new(System), RUN_LOOKUPS, LOOKUP_WAIT)
    }
}

impl Resolve for Limited {
    fn resolve<'a>(&'a self, name: &'a str) -> Answers<'a> {
        Box::pin(async move {
            let busy = || io::Error::other("too many lookups in flight");
            let mine = timeout(self.wait, self.run.clone().acquire_owned())
                .await
                .map_err(|_| busy())?
                .map_err(|_| busy())?;
            let all = timeout(self.wait, global().acquire_owned())
                .await
                .map_err(|_| busy())?
                .map_err(|_| busy())?;
            let (inner, name) = (self.inner.clone(), name.to_owned());
            tokio::spawn(async move {
                let _held = (mine, all);
                inner.resolve(&name).await
            })
            .await
            .map_err(|_| io::Error::other("lookup task ended"))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Notify;

    /// Answers once released; counts the lookups that reached it.
    struct Gate {
        open: Notify,
        seen: std::sync::atomic::AtomicUsize,
    }

    impl Resolve for Gate {
        fn resolve<'a>(&'a self, _: &'a str) -> Answers<'a> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                self.open.notified().await;
                Ok(vec![IpAddr::from([127, 0, 0, 1])])
            })
        }
    }

    struct Quick;
    impl Resolve for Quick {
        fn resolve<'a>(&'a self, _: &'a str) -> Answers<'a> {
            Box::pin(async { Ok(vec![IpAddr::from([127, 0, 0, 1])]) })
        }
    }

    fn gate() -> Arc<Gate> {
        Arc::new(Gate {
            open: Notify::new(),
            seen: Default::default(),
        })
    }

    #[tokio::test]
    async fn one_run_filling_its_lookups_does_not_fail_another_runs() {
        let stuck = gate();
        let a = Arc::new(Limited::new(stuck.clone(), 2, Duration::from_millis(100)));
        let b = Limited::new(Arc::new(Quick), 2, Duration::from_millis(100));
        let held: Vec<_> = (0..2)
            .map(|_| {
                let a = a.clone();
                tokio::spawn(async move { a.resolve("a.test").await })
            })
            .collect();
        while stuck.seen.load(std::sync::atomic::Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Run A is at its limit: its next lookup is refused after the short wait, without
        // reaching the resolver ...
        assert!(a.resolve("a.test").await.is_err());
        assert_eq!(stuck.seen.load(std::sync::atomic::Ordering::SeqCst), 2);
        // ... and run B is untouched.
        for _ in 0..5 {
            assert!(b.resolve("b.test").await.is_ok());
        }
        stuck.open.notify_waiters();
        for h in held {
            assert!(h.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn a_lookup_waits_briefly_for_a_slot_instead_of_failing_at_once() {
        let slow = gate();
        let a = Arc::new(Limited::new(slow.clone(), 1, Duration::from_secs(5)));
        let first = tokio::spawn({
            let a = a.clone();
            async move { a.resolve("a.test").await }
        });
        while slow.seen.load(std::sync::atomic::Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let second = tokio::spawn({
            let a = a.clone();
            async move { a.resolve("a.test").await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        slow.open.notify_one();
        assert!(first.await.unwrap().is_ok());
        // The slot came free inside the wait: the second lookup reached the resolver.
        while slow.seen.load(std::sync::atomic::Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        slow.open.notify_one();
        assert!(second.await.unwrap().is_ok());
    }
}
