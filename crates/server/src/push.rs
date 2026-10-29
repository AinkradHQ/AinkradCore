//! Push notifications (E10.4, decision #14): what the admin must act on reaches the app's
//! devices even when it is closed. The pusher tails the event log (`store::events`) from a
//! stored cursor, so no write path has to remember to push and a restart neither repeats nor
//! skips one.
//!
//! Which events are pushed is not the platform's call: a [`Classifier`] decides, brought by
//! the module whose events they are; the platform's own, [`Silent`], pushes nothing. Each push
//! goes to every live device with a push token, through a [`Notifier`]: [`LogNotifier`] by
//! default, [`apns::ApnsNotifier`] when the server has an APNs key.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use sqlx::SqlitePool;

use crate::store::events::{StoredEvent, last_event_seq, list_events};
use crate::store::gov::{PushTarget, push_cursor, push_targets, set_push_cursor};

pub mod apns;

/// One push: a title and body for people, and what it is about for the app.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The app's category, as the classifier names it.
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    /// What the app opens, e.g. `{"seq": …}`.
    pub data: Value,
}

pub type Sent<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Delivers a notification to one device.
pub trait Notifier: Send + Sync {
    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a>;
}

/// Logs instead of pushing: the default until an APNs key is configured.
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a> {
        tracing::info!(device = to.device.0, kind = n.kind, title = %n.title, "push (log only)");
        Box::pin(async { Ok(()) })
    }
}

/// Decides the push an event calls for, if any.
pub trait Classifier: Send + Sync {
    fn notification(&self, e: &StoredEvent) -> Option<Notification>;
}

/// Pushes nothing: the platform's default until a module brings its rules.
pub struct Silent;

impl Classifier for Silent {
    fn notification(&self, _: &StoredEvent) -> Option<Notification> {
        None
    }
}

/// Tails the event log and pushes what needs the admin.
pub struct Pusher {
    pub pool: SqlitePool,
    pub notifier: Arc<dyn Notifier>,
    pub classifier: Arc<dyn Classifier>,
    pub every: Duration,
}

/// Events read per tick.
const PAGE: u32 = 200;

impl Pusher {
    /// Pushes everything since the stored cursor; returns how many notifications went out.
    /// The first tick ever starts at the newest event: history is not pushed.
    pub async fn tick(&self) -> Result<usize, sqlx::Error> {
        let mut out = vec![];
        let mut after = match push_cursor(&self.pool).await? {
            Some(after) => after,
            None => last_event_seq(&self.pool).await?,
        };
        loop {
            let page = list_events(&self.pool, after, PAGE).await?;
            let Some(last) = page.last().map(|e| e.seq) else {
                break;
            };
            out.extend(page.iter().filter_map(|e| self.classifier.notification(e)));
            after = last;
            if page.len() < PAGE as usize {
                break;
            }
        }
        set_push_cursor(&self.pool, after).await?;

        let targets = push_targets(&self.pool).await?;
        for n in &out {
            for to in &targets {
                // ponytail: a failed push is logged, not retried; a retry queue if pushes
                // ever matter more than the app's own inbox.
                if let Err(e) = self.notifier.send(to, n).await {
                    tracing::warn!(device = to.device.0, error = %e, "push failed");
                }
            }
        }
        Ok(out.len())
    }

    /// Ticks every `every` until `shutdown` completes.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut every = tokio::time::interval(self.every);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                _ = every.tick() => {
                    if let Err(e) = self.tick().await {
                        eprintln!("ainkrad-core-server: push tick failed: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
