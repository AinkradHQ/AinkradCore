//! The notifications service (E10.4, E2-12): what the admin must act on reaches the app's
//! devices even when it is closed. The pusher tails the event log (`store::events`) from a
//! stored cursor, so no write path has to remember to push and a restart neither repeats nor
//! skips one; a service that already knows what happened (a terminal exited) calls
//! [`Pusher::deliver`] itself.
//!
//! Which events are pushed is not the platform's call: a [`Classifier`] decides, brought by
//! the module whose events they are; the platform's own, [`Silent`], pushes nothing.
//!
//! A notification leaves through a [`PushProvider`], one per push service a device can
//! register a token for: [`apns::ApnsNotifier`] (APNs over HTTP/2), [`LogProvider`] when the
//! server has no key, and the stubs for FCM and web push ([`stub`]). Before that it passes the
//! rules of [`policy`]: only ids in its payload, only the devices whose scopes allow it, one
//! merged push for a burst, a ceiling per device. Each attempt is a `notify.delivery` event; a
//! token the provider calls dead, or one that keeps failing, is removed.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::scheduler::Clock;
use crate::store::events::{StoredEvent, append, last_event_seq, list_events};
use crate::store::gov::{
    PushTarget, TokenResult, note_result, push_cursor, push_targets, set_push_cursor,
};
use crate::store::{audit, begin_write};

pub mod apns;
pub mod modules;
pub mod policy;
pub mod stub;

/// Consecutive failed deliveries after which a token is removed.
pub const MAX_FAILURES: i64 = 5;

/// One push: a title and body for people, and what it is about for the app.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The app's category, as the classifier names it.
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    /// What the app opens: ids only (`policy::clean` drops the rest), e.g. `{"approval_id": "a1"}`.
    pub data: Value,
    /// The scope a device needs to be sent it (`admin` always qualifies).
    pub scope: &'static str,
    /// Notifications with the same key in one pass merge into one.
    pub collapse: Option<String>,
}

impl Notification {
    pub fn new(
        kind: &'static str,
        scope: &'static str,
        title: &str,
        body: &str,
        data: Value,
    ) -> Self {
        Self {
            kind,
            title: title.to_owned(),
            body: body.to_owned(),
            data,
            scope,
            collapse: None,
        }
    }

    fn platform(kind: &'static str, scope: &'static str, title: &str, data: Value) -> Self {
        Self {
            collapse: Some(kind.to_owned()),
            ..Self::new(kind, scope, title, "", data)
        }
    }

    /// An approval waits on someone with `approve`; the id says which.
    pub fn approval_needed(approval_id: &str) -> Self {
        let data = json!({"approval_id": approval_id});
        Self::platform("approval_needed", "approve", "Approval needed", data)
    }

    /// A terminal exited; its id and exit code, never its output (`terminal` scope).
    pub fn terminal_exited(terminal_id: &str, exit_code: Option<i32>) -> Self {
        let data = json!({"terminal_id": terminal_id, "exit_code": exit_code});
        Self::platform("terminal_exited", "terminal", "Terminal exited", data)
    }

    /// An agent session finished (`agent` scope).
    pub fn agent_finished(session_id: &str) -> Self {
        let data = json!({"session_id": session_id});
        Self::platform("agent_finished", "agent", "Agent finished", data)
    }
}

/// Why a send failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// The provider says this token is dead: it is removed.
    InvalidToken(String),
    /// Anything else that went wrong; the token goes after [`MAX_FAILURES`] in a row.
    Failed(String),
    /// The provider has no transport yet ([`stub`]); the token is left alone.
    Unsupported,
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken(why) | Self::Failed(why) => f.write_str(why),
            Self::Unsupported => f.write_str("no transport for this provider yet"),
        }
    }
}

pub type Sent<'a> = Pin<Box<dyn Future<Output = Result<(), PushError>> + Send + 'a>>;

/// Delivers a notification to one device through one push service.
pub trait PushProvider: Send + Sync {
    /// The provider's name as tokens are registered under it: `apns`, `fcm`, `webpush`.
    fn name(&self) -> &'static str;

    /// Whether this provider sends to tokens registered under `provider`.
    fn handles(&self, provider: &str) -> bool {
        self.name() == provider
    }

    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a>;
}

/// Logs instead of pushing: the default until an APNs key is configured. It takes every token.
pub struct LogProvider;

impl PushProvider for LogProvider {
    fn name(&self) -> &'static str {
        "log"
    }

    fn handles(&self, _: &str) -> bool {
        true
    }

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

/// The platform's own pushes (E2-08.4): an agent's tool call waiting on a decision (to devices
/// with `approve`), and an agent session over (`agent`). Ids only, as every push.
pub struct Platform;

impl Classifier for Platform {
    fn notification(&self, e: &StoredEvent) -> Option<Notification> {
        let p = &e.payload.0;
        let session = p["session"].as_str()?;
        match e.kind.as_str() {
            "agent.approval_requested" => {
                let data = json!({"session_id": session, "approval_id": p["request"].as_str()?});
                Some(Notification {
                    collapse: Some(format!("approval:{session}")),
                    ..Notification::new("approval_needed", "approve", "Approval needed", "", data)
                })
            }
            "agent.ended" => Some(Notification::agent_finished(session)),
            _ => None,
        }
    }
}

/// Tails the event log and pushes what needs the admin.
pub struct Pusher {
    pub pool: SqlitePool,
    pub providers: Vec<Arc<dyn PushProvider>>,
    pub classifier: Arc<dyn Classifier>,
    pub every: Duration,
    pub clock: Arc<dyn Clock + Send + Sync>,
    limiter: policy::Limiter,
}

/// Events read per tick.
const PAGE: u32 = 200;

impl Pusher {
    pub fn new(
        pool: SqlitePool,
        providers: Vec<Arc<dyn PushProvider>>,
        classifier: Arc<dyn Classifier>,
        every: Duration,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            pool,
            providers,
            classifier,
            every,
            clock,
            limiter: policy::Limiter::default(),
        }
    }

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
        self.deliver(out).await
    }

    /// Sends `notifications` to the devices that may have them: cleaned, merged by `collapse`,
    /// within each device's ceiling. Returns how many (after merging) were sent.
    // ponytail: a failed push is counted against its token, not retried; a retry queue (on the
    // scheduler's jobs) if pushes ever matter more than the app's own inbox.
    pub async fn deliver(&self, notifications: Vec<Notification>) -> Result<usize, sqlx::Error> {
        let all = policy::coalesce(notifications.into_iter().map(policy::clean).collect());
        if all.is_empty() {
            return Ok(0);
        }
        let targets = push_targets(&self.pool).await?;
        for n in &all {
            for to in targets.iter().filter(|t| policy::may_receive(t, n.scope)) {
                let Some(provider) = self.providers.iter().find(|p| p.handles(&to.provider)) else {
                    tracing::debug!(provider = %to.provider, "no push provider for this token");
                    continue;
                };
                if !self.limiter.allow(to.device.0, self.clock.unix()) {
                    tracing::warn!(
                        device = to.device.0,
                        kind = n.kind,
                        "push rate limit: dropped"
                    );
                    continue;
                }
                let result = provider.send(to, n).await;
                if let Err(e) = self.record(to, n, &result).await {
                    tracing::warn!(device = to.device.0, error = %e, "recording a push failed");
                }
            }
        }
        Ok(all.len())
    }

    /// The delivery event, and the token's fate, in one transaction.
    async fn record(
        &self,
        to: &PushTarget,
        n: &Notification,
        result: &Result<(), PushError>,
    ) -> Result<(), sqlx::Error> {
        let (status, token) = match result {
            Ok(()) => ("sent", TokenResult::Delivered),
            Err(PushError::InvalidToken(_)) => ("invalid_token", TokenResult::Invalid),
            Err(PushError::Failed(_)) => ("failed", TokenResult::Failed),
            Err(PushError::Unsupported) => ("unsupported", TokenResult::Delivered),
        };
        let mut tx = begin_write(&self.pool).await?;
        let pruned = note_result(&mut tx, to, token, MAX_FAILURES).await?;
        let mut event = json!({
            "device": to.device_id, "provider": to.provider, "kind": n.kind,
            "status": status, "pruned": pruned,
        });
        if let Err(PushError::Failed(why) | PushError::InvalidToken(why)) = result {
            event["reason"] = json!(why.chars().take(120).collect::<String>());
        }
        append(&mut tx, "notify.delivery", &event).await?;
        if pruned {
            let details =
                json!({"device": to.device_id, "provider": to.provider, "reason": status});
            let entry = NewAuditEvent {
                actor: AuditActor::System,
                action: "notify.token_pruned".to_owned(),
                entity: Some(AuditEntity {
                    kind: "device".to_owned(),
                    id: to.device.0,
                }),
                details: details.to_string(),
            };
            audit::append(&mut tx, &entry).await?;
        }
        tx.commit().await
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

/// Providers by name, for `serve`: APNs when it has a key, else the log.
pub fn providers(apns: Option<apns::ApnsNotifier>) -> Vec<Arc<dyn PushProvider>> {
    let mut all: Vec<Arc<dyn PushProvider>> = vec![];
    match apns {
        Some(a) => all.push(Arc::new(a)),
        None => all.push(Arc::new(LogProvider)),
    }
    all.push(Arc::new(stub::Unimplemented("fcm")));
    all.push(Arc::new(stub::Unimplemented("webpush")));
    all
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_apns;
#[cfg(test)]
mod tests_modules;
