//! Push notifications (E10.4, decision #14): what the admin must act on reaches the app's
//! devices even when it is closed. The pusher tails the event log (`store::events`) from a
//! stored cursor, so no write path has to remember to push and a restart neither repeats nor
//! skips one; it also checks the stuck detector each tick.
//!
//! Triggers: a new approval (`approval.pending`), an issue blocked (`issue.blocked`), the loop
//! breaker escalating a failing run (`loop_breaker.tripped`), a provider account near or at a usage
//! limit (`account.warning`, `account.limited`, E15.2) or dropped by its provider too often
//! (`account.unhealthy`, E15.4), an issue its automatic repairs gave up on (`repair.exhausted`,
//! E15.8), a runner whose disk is full (`runner.disk_full`, E15.9) or that the admin asked to wake
//! (`runner.wake_requested` "now", decision #35: the Mac app keeps the machine awake when it gets
//! it) or is back after one (`runner.back`), an agent's question for the admin (`question.asked`,
//! E15.11), and an issue newly stuck (`stuck_report`). Each goes to every live device with a push
//! token, through a [`Notifier`]: [`LogNotifier`] by default, [`apns::ApnsNotifier`] when the
//! server has an APNs key.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::scheduler::Clock;
use crate::store::events::{StoredEvent, What, last_event_seq, list_events};
use crate::store::exec::stuck_report;
use crate::store::gov::{PushTarget, push_cursor, push_targets, set_push_cursor};

pub mod apns;

/// One push: a title and body for people, and what it is about for the app.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// `approval`, `blocked`, `escalation`, `account`, `runner`, `question` or `stuck`: the app's
    /// category.
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    /// The app opens this: `{"issue_id": …}`, `{"approval_id": …}`, `{"seq": …}`.
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

/// The push an event calls for, if any.
pub fn notification(e: &StoredEvent) -> Option<Notification> {
    let What::Audit {
        action,
        entity,
        details,
        run_id,
        ..
    } = &e.what
    else {
        return None;
    };
    let id = entity.as_ref().map(|(_, id)| *id);
    let (kind, title, body, data) = match action.as_str() {
        "approval.pending" => (
            "approval",
            "Approval needed".to_owned(),
            match details["kind"].as_str() {
                Some(kind) => format!("A {} waits on you", kind.replace('_', " ")),
                None => "An approval waits on you".to_owned(),
            },
            json!({"approval_id": id}),
        ),
        "issue.blocked" => (
            "blocked",
            "Issue blocked".to_owned(),
            format!("Issue {} is blocked", id.unwrap_or_default()),
            json!({"issue_id": id}),
        ),
        "loop_breaker.tripped" => (
            "escalation",
            "Run keeps failing".to_owned(),
            "The loop breaker stopped a run that failed the same way again".to_owned(),
            json!({"run_id": run_id, "issue_id": id}),
        ),
        "repair.exhausted" => (
            "escalation",
            "Issue needs you".to_owned(),
            format!(
                "Automatic repairs of issue {} gave up; it waits on you",
                id.unwrap_or_default()
            ),
            json!({"issue_id": id}),
        ),
        // The Mac app keeps its machine awake (`caffeinate`) when it gets this (decision #35).
        // "Run when I'm back" pushes nothing now; its runner's return does.
        "runner.wake_requested" if details["mode"] == "when_back" => return None,
        "runner.back" => (
            "runner",
            "Runner back".to_owned(),
            format!(
                "Runner {} is back; its queued work runs now",
                details["name"].as_str().unwrap_or("?")
            ),
            json!({"runner_id": id}),
        ),
        "runner.wake_requested" => (
            "runner",
            "Wake your Mac".to_owned(),
            format!(
                "Runner {} has work waiting; keep it awake",
                details["name"].as_str().unwrap_or("?")
            ),
            json!({"runner_id": id, "wake": true}),
        ),
        "runner.disk_full" => (
            "runner",
            "Runner disk full".to_owned(),
            format!(
                "Runner {} is over its disk cap with nothing left to evict",
                id.unwrap_or_default()
            ),
            json!({"runner_id": id}),
        ),
        "account.unhealthy" => (
            "account",
            "Account unhealthy".to_owned(),
            format!(
                "Account {}: the provider dropped {} turns; its runs fall back",
                id.unwrap_or_default(),
                details["drops"]
            ),
            json!({"account_id": id}),
        ),
        "account.warning" | "account.limited" => (
            "account",
            if action == "account.warning" {
                "Account near its limit".to_owned()
            } else {
                "Account at its limit".to_owned()
            },
            match (details["window"].as_str(), details["unit"].as_str()) {
                (Some(window), _) => format!(
                    "Account {} at {}% of its {window} window",
                    id.unwrap_or_default(),
                    details["percent"]
                ),
                (None, Some(unit)) => format!(
                    "Account {}: {} of {} {unit}",
                    id.unwrap_or_default(),
                    details["used"],
                    details["max"]
                ),
                _ => format!("Account {} is limited", id.unwrap_or_default()),
            },
            json!({"account_id": id}),
        ),
        "question.asked" => (
            "question",
            "Question for you".to_owned(),
            format!(
                "Agent {} asks: {}",
                details["agent"],
                details["question"]
                    .as_str()
                    .unwrap_or_default()
                    .chars()
                    .take(140)
                    .collect::<String>()
            ),
            json!({"question_id": id, "issue_id": details["issue"],
                   "requirement_id": details["requirement"]}),
        ),
        _ => return None,
    };
    let mut data = data;
    data["seq"] = e.seq.into();
    Some(Notification {
        kind,
        title,
        body,
        data,
    })
}

/// Tails the event log and pushes what needs the admin.
pub struct Pusher {
    pub pool: SqlitePool,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock + Send + Sync>,
    pub every: Duration,
}

/// Events read per tick.
const PAGE: u32 = 200;

impl Pusher {
    /// Pushes everything since the stored cursor, then newly stuck issues; returns how many
    /// notifications went out. The first tick ever starts at the newest event, and the
    /// first tick of a process counts what is stuck already as seen (`stuck` is `None`):
    /// history is not pushed.
    pub async fn tick(
        &self,
        stuck: &mut Option<HashSet<(i64, String)>>,
    ) -> Result<usize, sqlx::Error> {
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
            out.extend(page.iter().filter_map(notification));
            after = last;
            if page.len() < PAGE as usize {
                break;
            }
        }
        set_push_cursor(&self.pool, after).await?;

        let now: HashSet<(i64, String)> = stuck_report(&self.pool, &self.clock.now())
            .await?
            .into_iter()
            .filter_map(|s| Some((s.issue_id?.0, s.kind.as_str().to_owned())))
            .collect();
        if let Some(seen) = stuck.as_ref() {
            // ponytail: stuck issues already pushed are remembered per process; a restart
            // re-arms them silently rather than pushing them again.
            for (issue, kind) in now.difference(seen) {
                out.push(Notification {
                    kind: "stuck",
                    title: "Issue stuck".to_owned(),
                    body: format!("Issue {issue} is stuck: {}", kind.replace('_', " ")),
                    data: json!({"issue_id": issue}),
                });
            }
        }
        *stuck = Some(now);

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
        let mut stuck = None;
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                _ = every.tick() => {
                    if let Err(e) = self.tick(&mut stuck).await {
                        eprintln!("ainkrad-core-server: push tick failed: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
