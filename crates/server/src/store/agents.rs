//! Agent sessions (E2-08, P2.7, migration `0009`): the session rows and their transcripts.
//!
//! - A transcript entry is stored once per `(session, seq)`: a batch the runner resends after a
//!   lost answer, or after a Core restart, changes nothing it already holds. Only the run of
//!   entries that continues the stored `last_seq` is taken, so the stored transcript never has
//!   a hole (the runner marks one it could not avoid with an explicit `gap` entry).
//! - Every write appends its `agent.*` events in the same transaction (`store::events`): the
//!   transcript as `agent.transcript` (seq range, never content), a tool approval as
//!   `agent.approval_requested`, an end as `agent.ended`.
//! - The client-facing actions (create, message, decision, cancel, kill, resume) are audited
//!   by the API, naming the session, never its prompt, messages or secrets.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_proto::runner::Tokens;
use ainkrad_proto::v2::{AgentEvents, AgentState, TranscriptEntry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::events;

/// Entries kept per session; past it the runner's answers are no longer stored (and the
/// session is ended). ponytail: a ceiling, not a rotation; per-session retention when a real
/// transcript gets near it.
pub const MAX_TRANSCRIPT: u64 = 200_000;
const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// A secret a session is leased at each start: by name, delivered under `var`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSecret {
    pub name: String,
    pub var: String,
}

/// A session as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub n: i64,
    pub id: String,
    pub runner: String,
    pub harness: String,
    pub model: Option<String>,
    pub prompt: Option<String>,
    pub workspace: Option<Value>,
    pub policy: Value,
    pub secrets: Vec<SessionSecret>,
    /// `starting`, `running`, `interrupted`, `ended`, `lost`.
    pub state: String,
    pub harness_session: Option<String>,
    pub outcome: Option<Value>,
    pub last_seq: i64,
    pub usage: Tokens,
    pub resumes: i64,
    pub created_by: String,
    /// The module that created and drives it (`agents::create_for_module`); none for a client's.
    pub owner_module: Option<String>,
    /// What that module calls it (`run:12`): a pointer, never a credential.
    pub owner_ref: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub ended_at: Option<String>,
}

impl Session {
    pub fn live(&self) -> bool {
        !matches!(self.state.as_str(), "ended" | "lost")
    }
}

/// What a new session is made of.
pub struct NewSession<'a> {
    pub runner: &'a str,
    pub harness: &'a str,
    pub model: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub workspace: Option<&'a Value>,
    pub policy: &'a Value,
    pub secrets: &'a [SessionSecret],
    pub created_by: &'a str,
}

const COLUMNS: &str = "n, id, runner, harness, model, prompt, workspace, policy, secrets, state, \
    harness_session, outcome, last_seq, tokens_in, tokens_out, cache_read, cache_write, \
    cost_usd_micros, resumes, created_by, owner_module, owner_ref, created_at, updated_at, ended_at";

fn of(r: &sqlx::sqlite::SqliteRow) -> Result<Session, sqlx::Error> {
    let json = |col: &str| -> Result<Option<Value>, sqlx::Error> {
        Ok(r.try_get::<Option<String>, _>(col)?
            .and_then(|s| serde_json::from_str(&s).ok()))
    };
    let n = |col: &str| -> Result<u64, sqlx::Error> {
        Ok(u64::try_from(r.try_get::<i64, _>(col)?).unwrap_or(0))
    };
    Ok(Session {
        n: r.try_get("n")?,
        id: r.try_get("id")?,
        runner: r.try_get("runner")?,
        harness: r.try_get("harness")?,
        model: r.try_get("model")?,
        prompt: r.try_get("prompt")?,
        workspace: json("workspace")?,
        policy: json("policy")?.unwrap_or_else(|| json!({})),
        secrets: json("secrets")?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default(),
        state: r.try_get("state")?,
        harness_session: r.try_get("harness_session")?,
        outcome: json("outcome")?,
        last_seq: r.try_get("last_seq")?,
        usage: Tokens {
            input: n("tokens_in")?,
            output: n("tokens_out")?,
            cache_read: n("cache_read")?,
            cache_write: n("cache_write")?,
            cost_usd_micros: r
                .try_get::<Option<i64>, _>("cost_usd_micros")?
                .and_then(|c| u64::try_from(c).ok()),
        },
        resumes: r.try_get("resumes")?,
        created_by: r.try_get("created_by")?,
        owner_module: r.try_get("owner_module")?,
        owner_ref: r.try_get("owner_ref")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
        ended_at: r.try_get("ended_at")?,
    })
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<Session>, sqlx::Error> {
    let q = format!("SELECT {COLUMNS} FROM core_agent_sessions WHERE id = ?");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .as_ref()
        .map(of)
        .transpose()
}

/// Newest first, below row `before` (none: from the newest), at most `limit`.
pub async fn list(
    pool: &SqlitePool,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<Session>, sqlx::Error> {
    let q =
        format!("SELECT {COLUMNS} FROM core_agent_sessions WHERE n < ? ORDER BY n DESC LIMIT ?");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(before.unwrap_or(i64::MAX))
        .bind(limit)
        .fetch_all(pool)
        .await?
        .iter()
        .map(of)
        .collect()
}

/// Every session not over (`ended`, `lost`): what a starting Core supervises again.
pub async fn live(pool: &SqlitePool) -> Result<Vec<Session>, sqlx::Error> {
    let q = format!(
        "SELECT {COLUMNS} FROM core_agent_sessions WHERE state NOT IN ('ended', 'lost') ORDER BY n"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .fetch_all(pool)
        .await?
        .iter()
        .map(of)
        .collect()
}

/// Sessions of `runner` that hold one of its slots (not over), with their harness.
pub async fn on_runner(pool: &SqlitePool, runner: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT harness FROM core_agent_sessions WHERE runner = ? AND state NOT IN ('ended', 'lost')",
    )
    .bind(runner)
    .fetch_all(pool)
    .await
}

/// Appends one `agent.*` event about `session`.
async fn emit(conn: &mut SqliteConnection, kind: &str, payload: Value) -> Result<(), sqlx::Error> {
    events::append(conn, kind, &payload).await.map(drop)
}

/// Audits `action` on the session (row `n`) by `by_device`, with `details`.
pub async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    n: i64,
    mut details: Value,
    by_device: &str,
) -> Result<(), sqlx::Error> {
    details["by_device"] = json!(by_device);
    let e = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "agent_session".to_owned(),
            id: n,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &e).await.map(drop)
}

/// Stores a new session as `starting`, audited `agent.created`, with its `agent.created` event.
pub async fn create(
    pool: &SqlitePool,
    new: &NewSession<'_>,
    actor: AuditActor,
    now: &str,
) -> Result<Session, sqlx::Error> {
    create_owned(pool, new, None, actor, now).await
}

/// [`create`] for a session `owner` (a module id) will drive.
pub async fn create_owned(
    pool: &SqlitePool,
    new: &NewSession<'_>,
    owner: Option<&str>,
    actor: AuditActor,
    now: &str,
) -> Result<Session, sqlx::Error> {
    create_owned_ref(pool, new, owner, None, actor, now).await
}

/// [`create_owned`] with the owner's pointer to it (`owner_ref`).
pub async fn create_owned_ref(
    pool: &SqlitePool,
    new: &NewSession<'_>,
    owner: Option<&str>,
    owner_ref: Option<&str>,
    actor: AuditActor,
    now: &str,
) -> Result<Session, sqlx::Error> {
    let id = crate::auth::crypto::random_id("as_");
    let mut tx = super::begin_write(pool).await?;
    let n: i64 = sqlx::query_scalar(
        "INSERT INTO core_agent_sessions (id, runner, harness, model, prompt, workspace, policy, \
         secrets, state, created_by, created_at, updated_at, owner_module, owner_ref) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?, ?, ?, ?) RETURNING n",
    )
    .bind(&id)
    .bind(new.runner)
    .bind(new.harness)
    .bind(new.model)
    .bind(new.prompt)
    .bind(new.workspace.map(Value::to_string))
    .bind(new.policy.to_string())
    .bind(serde_json::to_string(new.secrets).expect("names serialize"))
    .bind(new.created_by)
    .bind(now)
    .bind(now)
    .bind(owner)
    .bind(owner_ref)
    .fetch_one(&mut *tx)
    .await?;
    let names: Vec<&str> = new.secrets.iter().map(|s| s.name.as_str()).collect();
    let about = json!({"session": id, "runner": new.runner, "harness": new.harness});
    let mut details = about.clone();
    // Names only; not under a key the log redactor takes for a secret.
    details["leased"] = json!(names);
    audit(&mut tx, actor, "agent.created", n, details, new.created_by).await?;
    emit(&mut tx, "agent.created", about).await?;
    tx.commit().await?;
    Ok(get(pool, &id).await?.expect("just stored"))
}

/// Moves the session to `state` (a resume counted when `resumed`); `agent.state` with why.
pub async fn set_state(
    pool: &SqlitePool,
    id: &str,
    state: &str,
    why: &str,
    resumed: bool,
    now: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let changed = sqlx::query(
        "UPDATE core_agent_sessions SET state = ?, resumes = resumes + ?, updated_at = ? \
         WHERE id = ? AND state NOT IN ('ended', 'lost') AND state != ?",
    )
    .bind(state)
    .bind(i64::from(resumed))
    .bind(now)
    .bind(id)
    .bind(state)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        emit(
            &mut tx,
            "agent.state",
            json!({"session": id, "state": state, "reason": why}),
        )
        .await?;
    }
    tx.commit().await
}

/// Ends the session with `outcome` (if it is not over): `agent.ended`.
pub async fn end(
    pool: &SqlitePool,
    id: &str,
    state: &str,
    outcome: &Value,
    now: &str,
) -> Result<bool, sqlx::Error> {
    // What the runner or the Core says about the end is shown to `read` devices (a module's run
    // list): a harness error may echo a value, so the key shapes are redacted as in a transcript.
    let mut outcome = outcome.clone();
    ainkrad_proto::redact::Redactor::new().json(&mut outcome);
    let outcome = &outcome;
    let mut tx = super::begin_write(pool).await?;
    let changed = sqlx::query(
        "UPDATE core_agent_sessions SET state = ?, outcome = ?, updated_at = ?, ended_at = ? \
         WHERE id = ? AND state NOT IN ('ended', 'lost')",
    )
    .bind(state)
    .bind(outcome.to_string())
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        let kind = outcome["kind"].as_str().unwrap_or(state);
        emit(
            &mut tx,
            "agent.ended",
            json!({"session": id, "state": state, "outcome": kind}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(changed > 0)
}

/// Takes a runner's answer about the session: the entries continuing the stored transcript,
/// the harness's session id and the usage so far. Returns the stored `last_seq`.
pub async fn apply(
    pool: &SqlitePool,
    id: &str,
    ev: &AgentEvents,
    now: &str,
) -> Result<u64, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let last: i64 = sqlx::query_scalar("SELECT last_seq FROM core_agent_sessions WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let mut last = u64::try_from(last).unwrap_or(0);
    let from = last + 1;
    for e in &ev.entries {
        if e.seq <= last {
            continue; // held already: a resend
        }
        let gap = e.body["type"] == "gap"
            && e.body["from"].as_u64() == Some(last + 1)
            && e.seq >= e.body["to"].as_u64().unwrap_or(e.seq);
        if (!gap && e.seq != last + 1) || last >= MAX_TRANSCRIPT {
            break; // a hole: the rest waits for the next read, from `last`
        }
        insert(&mut tx, id, e).await?;
        last = e.seq;
        if e.body["type"] == "approval_request" {
            let payload = json!({"session": id, "request": e.body["id"], "tool": e.body["tool"]});
            emit(&mut tx, "agent.approval_requested", payload).await?;
        }
    }
    if last >= from {
        emit(
            &mut tx,
            "agent.transcript",
            json!({"session": id, "from": from, "to": last}),
        )
        .await?;
    }
    let u = ev.usage.unwrap_or_default();
    let i = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    sqlx::query(
        "UPDATE core_agent_sessions SET last_seq = ?, \
         harness_session = coalesce(?, harness_session), \
         tokens_in = max(tokens_in, ?), tokens_out = max(tokens_out, ?), \
         cache_read = max(cache_read, ?), cache_write = max(cache_write, ?), \
         cost_usd_micros = coalesce(?, cost_usd_micros), updated_at = ? WHERE id = ?",
    )
    .bind(i(last))
    .bind(&ev.harness_session)
    .bind(i(u.input))
    .bind(i(u.output))
    .bind(i(u.cache_read))
    .bind(i(u.cache_write))
    .bind(u.cost_usd_micros.map(i))
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(last)
}

async fn insert(
    conn: &mut SqliteConnection,
    id: &str,
    e: &TranscriptEntry,
) -> Result<(), sqlx::Error> {
    // The runner redacted it with the session's secrets; the key shapes once more here.
    let mut body = e.body.clone();
    ainkrad_proto::redact::Redactor::new().json(&mut body);
    if body.to_string().len() > MAX_ENTRY_BYTES {
        body = json!({"type": "truncated", "original_seq": e.seq});
    }
    sqlx::query(
        "INSERT OR IGNORE INTO core_agent_transcript (session, seq, at, body) VALUES (?, ?, ?, ?)",
    )
    .bind(id)
    .bind(i64::try_from(e.seq).unwrap_or(i64::MAX))
    .bind(e.at)
    .bind(body.to_string())
    .execute(conn)
    .await
    .map(drop)
}

/// Entries with `seq` above `after`, oldest first, at most `limit`.
pub async fn transcript(
    pool: &SqlitePool,
    id: &str,
    after: i64,
    limit: u32,
) -> Result<Vec<TranscriptEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT seq, at, body FROM core_agent_transcript WHERE session = ? AND seq > ? \
         ORDER BY seq LIMIT ?",
    )
    .bind(id)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(TranscriptEntry {
                seq: u64::try_from(r.try_get::<i64, _>("seq")?).unwrap_or(0),
                at: r.try_get("at")?,
                body: serde_json::from_str(&r.try_get::<String, _>("body")?).unwrap_or(Value::Null),
            })
        })
        .collect()
}

/// `state` as the runner reports it, as stored.
pub fn runner_state(s: AgentState) -> &'static str {
    match s {
        AgentState::Running => "running",
        AgentState::Ended => "ended",
        AgentState::Interrupted => "interrupted",
        AgentState::Unknown => "running",
    }
}

/// A client's action on the session: audited `action` by `by_device` with `details`, and the
/// `event` (if any) with the same details, in one write.
pub async fn action(
    pool: &SqlitePool,
    s: &Session,
    actor: AuditActor,
    action: &str,
    event: Option<&str>,
    details: Value,
    by_device: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let mut details = details;
    details["session"] = json!(s.id);
    if let Some(kind) = event {
        emit(&mut tx, kind, details.clone()).await?;
    }
    audit(&mut tx, actor, action, s.n, details, by_device).await?;
    tx.commit().await
}

/// A `lost` or `interrupted` session back to `interrupted`, for its supervisor to resume.
pub async fn reopen(pool: &SqlitePool, id: &str, now: &str) -> Result<bool, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let changed = sqlx::query(
        "UPDATE core_agent_sessions SET state = 'interrupted', outcome = NULL, ended_at = NULL, \
         updated_at = ? WHERE id = ? AND state IN ('lost', 'interrupted')",
    )
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(changed > 0)
}

/// What [`wake`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Woken {
    /// Back to `interrupted`: its supervisor continues the harness's own session.
    Reopened,
    /// Still `starting` or `running`: not idle yet, try again later.
    Busy,
    /// Nothing to wake: no such session, a module's, or over for good (failed, cancelled).
    Gone,
}

impl Session {
    /// Whether a wake can ever get this session going: it is not over, or it was lost, or it
    /// finished a turn (`succeeded`) and kept the harness's own session to continue.
    pub fn wakeable(&self) -> bool {
        self.owner_module.is_none()
            && (self.live()
                || self.state == "lost"
                || (self.harness_session.is_some()
                    && self
                        .outcome
                        .as_ref()
                        .is_some_and(|o| o["kind"] == "succeeded")))
    }
}

/// Wakes an idle session of a client: a `lost` or `succeeded` one goes back to `interrupted`
/// (an `interrupted` one stays), with `text` as the prompt of its next turn. One write; a
/// module's session is never touched (its routes drive it).
pub async fn wake(
    pool: &SqlitePool,
    id: &str,
    text: Option<&str>,
    now: &str,
) -> Result<Woken, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let found: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT state, harness_session, outcome, owner_module FROM core_agent_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((state, harness, outcome, owner)) = found else {
        return Ok(Woken::Gone);
    };
    let succeeded = outcome
        .and_then(|o| serde_json::from_str::<Value>(&o).ok())
        .is_some_and(|o| o["kind"] == "succeeded");
    match state.as_str() {
        _ if owner.is_some() => return Ok(Woken::Gone),
        "starting" | "running" => return Ok(Woken::Busy),
        "interrupted" | "lost" => {}
        "ended" if succeeded && harness.is_some() => {}
        _ => return Ok(Woken::Gone),
    }
    sqlx::query(
        "UPDATE core_agent_sessions SET state = 'interrupted', outcome = NULL, ended_at = NULL, \
         prompt = coalesce(?, prompt), updated_at = ? WHERE id = ?",
    )
    .bind(text)
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if state != "interrupted" {
        let payload = json!({"session": id, "state": "interrupted", "reason": "woken"});
        emit(&mut tx, "agent.state", payload).await?;
    }
    tx.commit().await?;
    Ok(Woken::Reopened)
}
