//! The Core-held approval of a risky Code Mode call (E6.2, plan P9). The dispatcher parks the
//! call as a row, raises the same `agent.approval_requested` event a harness approval does (so
//! phones are pushed and the App reloads), and waits. `decideAgentApproval` resolves the row when
//! its request id is `cm_…`: the gate already asked for the `approve` scope and a live step-up.
//! One approval lets exactly one execution run, of the call it was asked for (bound to a hash of
//! its operation and arguments); denied, unanswered, ended and lost ones never run anything.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_proto::redact::Redactor;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tokio::sync::Notify;

use super::CallState;
use crate::api::App;
use crate::store::connections::access;

/// A Core-held approval's request id starts with this; a harness's never does.
pub const PREFIX: &str = "cm_";

/// Approvals older than this are dropped when the next one is made.
const KEEP_SECS: i64 = 86_400;
/// Longest text of one argument shown on an approval card.
const SHOWN: usize = 200;

/// How the wait for a person ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Allowed, by this device.
    Approved(String),
    Denied,
    Timeout,
    /// The session ended while it waited.
    Ended,
}

/// What `decide` found.
#[derive(Debug, PartialEq, Eq)]
pub enum Decided {
    Done,
    /// No such approval of this session.
    Unknown,
    /// Decided, expired, ended or lost already: nothing waits for it.
    Closed,
}

/// A parked approval as the App lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub id: String,
    /// `ainkrad.<op>`: what the card names.
    pub tool: String,
    /// The operation in plain words.
    pub summary: String,
    /// The arguments, redacted and shortened.
    pub args: Value,
    pub reason: String,
    /// Unix seconds.
    pub created_at: i64,
    pub expires_at: i64,
}

/// `args` as an approval card may show them: secrets redacted, long texts cut, the whole bounded.
pub fn shown(args: &Value) -> Value {
    fn cut(v: &mut Value) {
        match v {
            Value::String(s) if s.chars().count() > SHOWN => {
                *s = s.chars().take(SHOWN).chain("…".chars()).collect();
            }
            Value::Array(a) => a.iter_mut().for_each(cut),
            Value::Object(m) => m.values_mut().for_each(cut),
            _ => {}
        }
    }
    let mut v = args.clone();
    Redactor::new().json(&mut v);
    cut(&mut v);
    if v.to_string().len() > 2048 {
        return json!({"truncated": true});
    }
    v
}

/// The call is waiting: a notify the decision wakes, in the registry until dropped.
pub struct Waiting<'a>(&'a CallState, String, pub Arc<Notify>);

impl<'a> Waiting<'a> {
    pub fn new(state: &'a CallState, id: &str) -> Self {
        let n = Arc::new(Notify::new());
        state
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_owned(), n.clone());
        Self(state, id.to_owned(), n)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.1);
    }
}

/// Parks a call: a `pending` row and the request event, in one transaction. Returns the request id.
///
/// # Errors
///
/// A store failure.
pub async fn create(
    app: &App,
    (id, session): (&str, &str),
    (op, summary, args, reason): (&str, &str, &Value, &str),
    args_sha256: &str,
    ttl: i64,
) -> Result<(), sqlx::Error> {
    let now = app.clock.unix();
    let mut tx = crate::store::begin_write(&app.pool).await?;
    sqlx::query("DELETE FROM core_code_mode_approvals WHERE created_at < ?")
        .bind(now - KEEP_SECS)
        .execute(&mut *tx)
        .await?;
    let card = json!({"text": summary, "args": shown(args)});
    sqlx::query(
        "INSERT INTO core_code_mode_approvals \
         (id, user_id, session, op, reason, summary, args_sha256, state, created_at, expires_at) \
         VALUES (?1, (SELECT user_id FROM core_agent_sessions WHERE id = ?2), ?2, ?3, ?4, ?5, ?6, \
         'pending', ?7, ?8)",
    )
    .bind(id)
    .bind(session)
    .bind(op)
    .bind(reason)
    .bind(card.to_string())
    .bind(args_sha256)
    .bind(now)
    .bind(now + ttl)
    .execute(&mut *tx)
    .await?;
    let input = json!({"summary": summary, "args": shown(args), "reason": reason});
    let payload = json!({"session": session, "request": id, "tool": format!("ainkrad.{op}"),
        "input": input});
    crate::store::events::append(&mut tx, "agent.approval_requested", &payload).await?;
    tx.commit().await
}

/// A fresh request id.
pub fn new_id() -> String {
    crate::auth::crypto::random_id(PREFIX)
}

async fn state_of(pool: &SqlitePool, id: &str) -> Result<(String, Option<String>), sqlx::Error> {
    sqlx::query_as("SELECT state, decided_by FROM core_code_mode_approvals WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
}

async fn close(pool: &SqlitePool, id: &str, to: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE core_code_mode_approvals SET state = ? WHERE id = ? AND state = 'pending'")
        .bind(to)
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// Waits for the person, at most `ttl` seconds, and no longer than the session lives.
///
/// # Errors
///
/// A store failure.
pub async fn wait(
    app: &App,
    waiting: &Waiting<'_>,
    (id, session, runner): (&str, &str, &str),
    ttl: Duration,
) -> Result<Outcome, sqlx::Error> {
    let deadline = Instant::now() + ttl;
    loop {
        let (state, by) = state_of(&app.pool, id).await?;
        match state.as_str() {
            "approved" => return Ok(Outcome::Approved(by.unwrap_or_default())),
            "denied" => return Ok(Outcome::Denied),
            "pending" => {}
            _ => return Ok(Outcome::Ended),
        }
        let live = access::load(&app.pool, session)
            .await?
            .is_some_and(|a| a.live && a.runner == runner);
        if !live {
            close(&app.pool, id, "ended").await?;
            continue;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            close(&app.pool, id, "expired").await?;
            // A decision in the last instant still counts.
            let (state, by) = state_of(&app.pool, id).await?;
            return Ok(match state.as_str() {
                "approved" => Outcome::Approved(by.unwrap_or_default()),
                "denied" => Outcome::Denied,
                _ => Outcome::Timeout,
            });
        }
        tokio::select! {
            () = waiting.2.notified() => {}
            () = tokio::time::sleep(left.min(Duration::from_secs(2))) => {}
        }
    }
}

/// Spends an approval: true exactly once, and only for the arguments it was asked for.
///
/// # Errors
///
/// A store failure.
pub async fn consume(
    pool: &SqlitePool,
    id: &str,
    session: &str,
    args_sha256: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE core_code_mode_approvals SET state = 'used' \
         WHERE id = ? AND session = ? AND args_sha256 = ? AND state = 'approved'",
    )
    .bind(id)
    .bind(session)
    .bind(args_sha256)
    .execute(pool)
    .await
    .map(|r| r.rows_affected() == 1)
}

/// A person's decision on `request` of `session`, made by `device` (who already passed the gate).
///
/// # Errors
///
/// A store failure.
pub async fn decide(
    app: &App,
    session: &str,
    request: &str,
    approved: bool,
    device: &str,
) -> Result<Decided, sqlx::Error> {
    let now = app.clock.unix();
    let waiter = app
        .code_mode
        .waiting
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(request)
        .cloned();
    if waiter.is_none() {
        // Nothing waits for it (the Core restarted while it was parked): it is never run now.
        sqlx::query(
            "UPDATE core_code_mode_approvals SET state = 'lost' \
             WHERE id = ? AND session = ? AND state = 'pending'",
        )
        .bind(request)
        .bind(session)
        .execute(&app.pool)
        .await?;
    }
    let changed = sqlx::query(
        "UPDATE core_code_mode_approvals SET state = ?, decided_by = ?, decided_at = ? \
         WHERE id = ? AND session = ? AND state = 'pending' AND expires_at > ?",
    )
    .bind(if approved { "approved" } else { "denied" })
    .bind(device)
    .bind(now)
    .bind(request)
    .bind(session)
    .bind(now)
    .execute(&app.pool)
    .await?
    .rows_affected();
    if changed == 1 {
        if let Some(w) = waiter {
            w.notify_one();
        }
        return Ok(Decided::Done);
    }
    let known: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM core_code_mode_approvals WHERE id = ? AND session = ?")
            .bind(request)
            .bind(session)
            .fetch_optional(&app.pool)
            .await?;
    Ok(if known.is_some() {
        Decided::Closed
    } else {
        Decided::Unknown
    })
}

/// The approvals of `session` that wait for a person now.
///
/// # Errors
///
/// A store failure.
pub async fn pending(app: &App, session: &str) -> Result<Vec<Pending>, sqlx::Error> {
    let rows: Vec<(String, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, op, summary, reason, created_at, expires_at FROM core_code_mode_approvals \
         WHERE session = ? AND state = 'pending' AND expires_at > ? ORDER BY created_at, id",
    )
    .bind(session)
    .bind(app.clock.unix())
    .fetch_all(&app.pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|r| {
            // Only a call that is really waiting (not one the Core lost across a restart).
            app.code_mode
                .waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&r.0)
        })
        .map(|(id, op, card, reason, at, until)| {
            let card: Value = serde_json::from_str(&card).unwrap_or(Value::Null);
            Pending {
                id,
                tool: format!("ainkrad.{op}"),
                summary: card["text"].as_str().unwrap_or_default().to_owned(),
                args: card["args"].clone(),
                reason,
                created_at: at,
                expires_at: until,
            }
        })
        .collect())
}
