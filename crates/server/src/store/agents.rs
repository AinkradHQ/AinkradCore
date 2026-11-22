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

use ainkrad_core::audit::{AuditActor, AuditEntity, AuditOrigin, NewAuditEvent, OriginKind};
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
    /// The project it was started for (P3-02); its workspace is that project's repos.
    pub project_id: Option<i64>,
    /// The module that created and drives it (`agents::create_for_module`); none for a client's.
    pub owner_module: Option<String>,
    /// What that module calls it (`run:12`): a pointer, never a credential.
    pub owner_ref: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub ended_at: Option<String>,
    /// The account whose key the runner's auth gateway serves this session (KAN-435): written by the
    /// Core at create from its own account row. Its ledger rows come from the gateway's reports.
    pub gateway_account_id: Option<i64>,
    /// The newest gateway report recorded in the ledger: what the next `agent.read` acknowledges.
    pub gw_seq: i64,
    /// The epoch of the report `gw_seq` belongs to.
    pub gw_epoch: i64,
    /// Why a hard-stop budget ran out for the session; the Core stops it (`agents::gateway`).
    pub gw_stop: Option<String>,
    /// When (unix seconds) the Core told the runner to refuse and cancel it.
    pub gw_stopped_at: Option<i64>,
    /// A live conversation (N41): the harness stays up after an answer.
    pub conversation: bool,
    /// Since when (unix seconds) a `running` live session waits for its user; none while it works.
    pub waiting_since: Option<i64>,
    /// A message waiting for the supervisor to deliver once the runner runs the session again.
    pub pending: Option<String>,
    /// A short name: the first message's start until someone sets one.
    pub title: Option<String>,
    /// The absolute folder its harness works in on its runner, as the runner reported it.
    pub folder: Option<String>,
    /// The running turn's cost so far in micro-dollars (`turn_cost`); none when no turn runs or
    /// its model has no price.
    pub turn_cost_micros: Option<i64>,
    /// That cost counts the harness's mid-turn reports, which undercount (`turn_cost`).
    pub turn_cost_approx: bool,
}

/// The longest title, in characters.
pub const MAX_TITLE: usize = 60;

/// The title a first message gives: its first line, cut to [`MAX_TITLE`] characters.
pub fn title_of(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(line.chars().take(MAX_TITLE).collect())
}

impl Session {
    pub fn live(&self) -> bool {
        !matches!(self.state.as_str(), "ended" | "lost")
    }

    /// The state clients see: a live session idle between answers is `waiting` (stored `running`).
    pub fn api_state(&self) -> &str {
        match (self.state.as_str(), self.waiting_since) {
            ("running", Some(_)) => "waiting",
            (state, _) => state,
        }
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
    cost_usd_micros, resumes, created_by, owner_module, owner_ref, created_at, updated_at, ended_at, \
    gateway_account_id, gw_seq, gw_epoch, gw_stop, gw_stopped_at, live, waiting_since, pending, title, folder, \
    turn_cost_micros, turn_cost_approx, project_id";

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
        project_id: r.try_get("project_id")?,
        owner_module: r.try_get("owner_module")?,
        owner_ref: r.try_get("owner_ref")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
        ended_at: r.try_get("ended_at")?,
        gateway_account_id: r.try_get("gateway_account_id")?,
        gw_seq: r.try_get("gw_seq")?,
        gw_epoch: r.try_get("gw_epoch")?,
        gw_stop: r.try_get("gw_stop")?,
        gw_stopped_at: r.try_get("gw_stopped_at")?,
        conversation: r.try_get::<i64, _>("live")? != 0,
        waiting_since: r.try_get("waiting_since")?,
        pending: r.try_get("pending")?,
        title: r.try_get("title")?,
        folder: r.try_get("folder")?,
        turn_cost_micros: r.try_get("turn_cost_micros")?,
        turn_cost_approx: r.try_get::<i64, _>("turn_cost_approx")? != 0,
    })
}

/// Ties session `id` to `project`, before it starts (P3-02). Only a session that is still
/// `starting` and has no project yet takes one.
pub async fn set_project(pool: &SqlitePool, id: &str, project: i64) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE core_agent_sessions SET project_id = ? \
         WHERE id = ? AND project_id IS NULL AND state = 'starting'",
    )
    .bind(project)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
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

/// What an AI session does starts with the session; its root is what started the session (the
/// origin the Core stamped on its row, E1-3). `by` is its id (`as_…`) or its row number.
pub async fn session_origin(
    conn: &mut SqliteConnection,
    by: Result<&str, i64>,
) -> Option<AuditOrigin> {
    let (id, root, root_ref): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT id, origin_root, origin_root_ref FROM core_agent_sessions \
         WHERE (?1 IS NOT NULL AND id = ?1) OR (?2 IS NOT NULL AND n = ?2)",
    )
    .bind(by.ok())
    .bind(by.err())
    .fetch_optional(conn)
    .await
    .ok()??;
    let root_kind = root
        .and_then(|k| OriginKind::parse(&k))
        .unwrap_or(OriginKind::System);
    Some(AuditOrigin {
        kind: OriginKind::AiSession,
        reference: Some(id),
        root_kind,
        root_reference: root_ref,
    })
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
    // Moved by the runner or the Core on its own (no person's request in force): the session
    // is the origin. A person's stop keeps its person.
    let ambient = super::audit::origin::current();
    let origin = match ambient.kind {
        OriginKind::System => session_origin(&mut *conn, Err(n)).await.unwrap_or(ambient),
        _ => ambient,
    };
    super::audit::append_as(conn, &e, origin).await.map(drop)
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
    let mut tx = super::begin_write(pool).await?;
    let id = create_in(&mut tx, new, owner, owner_ref, actor, now).await?;
    tx.commit().await?;
    Ok(get(pool, &id).await?.expect("just stored"))
}

/// [`create_owned_ref`] inside the caller's write transaction (`chains::create_session` assigns the
/// chain in the same one); returns the new id.
pub(super) async fn create_in(
    tx: &mut sqlx::SqliteConnection,
    new: &NewSession<'_>,
    owner: Option<&str>,
    owner_ref: Option<&str>,
    actor: AuditActor,
    now: &str,
) -> Result<String, sqlx::Error> {
    let id = crate::auth::crypto::session_id();
    let origin = super::audit::origin::current();
    // The account a gateway serves is the Core's own row behind the secret's name, nothing a caller
    // or a runner says; no such row leaves it NULL and the launch refuses the session.
    let gateway_secret = super::gateway::gateway_secret(new.secrets).map(|s| s.name.as_str());
    // The account it holds, whatever its delivery: what the allocator's cap counts (S4).
    let account_secret = new
        .secrets
        .iter()
        .find(|s| super::gateway::account_secret(&s.name).is_some())
        .map(|s| s.name.as_str());
    let n: i64 = sqlx::query_scalar(
        "INSERT INTO core_agent_sessions (id, runner, harness, model, prompt, workspace, policy, \
         secrets, state, created_by, created_at, updated_at, owner_module, owner_ref, \
         gateway_account_id, account_id, user_id, origin, origin_ref, origin_root, origin_root_ref) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?, ?, ?, ?, \
         (SELECT id FROM core_accounts WHERE secret_name = ?), \
         (SELECT id FROM core_accounts WHERE secret_name = ?), \
         coalesce((SELECT user_id FROM core_devices WHERE id = ?), 1), ?, ?, ?, ?) RETURNING n",
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
    .bind(gateway_secret)
    .bind(account_secret)
    .bind(new.created_by)
    // The Core stamps what started the session (E1-3); no caller or runner field reaches it.
    .bind(origin.kind.as_str())
    .bind(&origin.reference)
    .bind(origin.root_kind.as_str())
    .bind(&origin.root_reference)
    .fetch_one(&mut *tx)
    .await?;
    let names: Vec<&str> = new.secrets.iter().map(|s| s.name.as_str()).collect();
    let about = json!({"session": id, "runner": new.runner, "harness": new.harness});
    let mut details = about.clone();
    // Names only; not under a key the log redactor takes for a secret.
    details["leased"] = json!(names);
    audit(tx, actor, "agent.created", n, details, new.created_by).await?;
    emit(tx, "agent.created", about).await?;
    Ok(id)
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
        "UPDATE core_agent_sessions SET state = ?, resumes = resumes + ?, updated_at = ?, \
         waiting_since = NULL, upstream_class = iif(? != 0, NULL, upstream_class) \
         WHERE id = ? AND state NOT IN ('ended', 'lost') AND state != ?",
    )
    .bind(state)
    .bind(i64::from(resumed))
    .bind(now)
    .bind(i64::from(resumed))
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
        "UPDATE core_agent_sessions SET state = ?, outcome = ?, updated_at = ?, ended_at = ?, \
         waiting_since = NULL, pending = NULL WHERE id = ? AND state NOT IN ('ended', 'lost')",
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
        // A budget hold is for a live session: what it did not spend goes back.
        super::budgets::guard::release_in(&mut tx, id).await?;
        super::health::on_end(&mut tx, id, outcome, now).await?;
        // A lost session never moves a run (the runner's failure, not the account's): settled with the end.
        if state == "lost" {
            sqlx::query("UPDATE core_agent_sessions SET failover_done = 1 WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
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
    apply_quiet(pool, id, ev, now, &Default::default()).await
}

/// [`apply`], but an `approval_request` whose id is in `quiet` raises no `agent.approval_requested`
/// event: the Core is about to decide it by a project rule, so nobody is asked.
pub async fn apply_quiet(
    pool: &SqlitePool,
    id: &str,
    ev: &AgentEvents,
    now: &str,
    quiet: &std::collections::HashSet<String>,
) -> Result<u64, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let last: i64 = sqlx::query_scalar("SELECT last_seq FROM core_agent_sessions WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let gateway = super::gateway::absorb(&mut tx, id, &ev.gateway, now).await?;
    super::health::on_plan_limit(&mut tx, id, ev.plan_limit.as_ref(), now).await?;
    // The model the harness says it runs, before the meter prices or labels this read's usage.
    let ran = ev.entries.iter().rev().find_map(|e| {
        (e.body["type"] == "session_started")
            .then(|| e.body["model"].as_str())
            .flatten()
            .filter(|m| super::prices::valid_model(m))
    });
    if let Some(model) = ran {
        sqlx::query("UPDATE core_agent_sessions SET harness_model = ? WHERE id = ?")
            .bind(model)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let gateway =
        gateway || super::usage_meter::record(&mut tx, id, ev.usage, gateway, now).await?;
    let mut last = u64::try_from(last).unwrap_or(0);
    let stored = last;
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
        let silent = e.body["id"].as_str().is_some_and(|r| quiet.contains(r));
        if e.body["type"] == "approval_request" && !silent {
            let payload = json!({"session": id, "request": e.body["id"], "tool": e.body["tool"]});
            emit(&mut tx, "agent.approval_requested", payload).await?;
        }
    }
    if last >= from {
        turn_cost(&mut tx, id, &ev.entries[..], from, last).await?;
        emit(
            &mut tx,
            "agent.transcript",
            json!({"session": id, "from": from, "to": last}),
        )
        .await?;
    }
    // A live session's idle state, as the runner says it: every change comes with an entry (`waiting`,
    // `message`), so an answer older than what is stored (a late read) never turns it back.
    if ev.last_seq >= stored {
        set_idle(&mut tx, id, ev.state, now).await?;
    }
    // A ledger-written session's usage columns (gateway, meter) are the ledger's: its harness's
    // own meter is display-only, and nothing here may overwrite them.
    let u = if gateway {
        Tokens::default()
    } else {
        ev.usage.unwrap_or_default()
    };
    let i = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    sqlx::query(
        "UPDATE core_agent_sessions SET last_seq = ?, \
         harness_session = coalesce(?, harness_session), folder = coalesce(?, folder), \
         tokens_in = max(tokens_in, ?), tokens_out = max(tokens_out, ?), \
         cache_read = max(cache_read, ?), cache_write = max(cache_write, ?), \
         cost_usd_micros = coalesce(?, cost_usd_micros), updated_at = ? WHERE id = ?",
    )
    .bind(i(last))
    .bind(&ev.harness_session)
    .bind(&ev.folder)
    .bind(i(u.input))
    .bind(i(u.output))
    .bind(i(u.cache_read))
    .bind(i(u.cache_write))
    .bind(u.cost_usd_micros.map(i))
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    // E15-2: a built-in runner's folder that is its place in the workspace is the Core's own.
    let bound = match &ev.folder {
        Some(f) => crate::workspace::adopt::bind_folder(&mut tx, id, f).await?,
        None => None,
    };
    tx.commit().await?;
    if let Some(folder) = bound {
        crate::workspace::adopt::baseline(id.to_owned(), folder);
    }
    Ok(last)
}

/// The running turn's cost (E6), from the newest of the stored entries `from..=to` that says
/// something about it: a `user_message` starts a turn at 0, a `usage_so_far` (the harness's tokens
/// of the turn so far) is priced with the price book for the session's harness's provider and its
/// model (none without a price), and a `turn_ended`, `waiting` or `ended` clears it. The
/// `agent.transcript` event of the same write tells clients to read it again.
///
/// Approximate for Claude Code, whose mid-turn reports count an answer's output tokens at its
/// start (`ainkrad_harness::Meter`); the others report each finished step's tokens. Cache reads and
/// writes are priced at the book's one cache rate, as the ledger does (`usage_meter`).
async fn turn_cost(
    tx: &mut SqliteConnection,
    id: &str,
    entries: &[TranscriptEntry],
    from: u64,
    to: u64,
) -> Result<(), sqlx::Error> {
    let Some(e) = entries.iter().rev().find(|e| {
        (from..=to).contains(&e.seq)
            && matches!(
                e.body["type"].as_str(),
                Some("usage_so_far" | "user_message" | "turn_ended" | "waiting" | "ended")
            )
    }) else {
        return Ok(());
    };
    let row = sqlx::query("SELECT harness, model FROM core_agent_sessions WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let harness: String = row.try_get("harness")?;
    let model: Option<String> = row.try_get("model")?;
    let n = |k: &str| i64::try_from(e.body[k].as_u64().unwrap_or(0)).unwrap_or(i64::MAX);
    let cost = match e.body["type"].as_str() {
        Some("user_message") => Some(0),
        Some("usage_so_far") => {
            let rates = match (ainkrad_proto::v2::harness_provider(&harness), &model) {
                (Some(p), Some(m)) => super::prices::rates_in(tx, p, m).await?,
                _ => None,
            };
            let cache = n("cache_read").saturating_add(n("cache_write"));
            rates.and_then(|r| r.cost(n("input"), n("output"), cache))
        }
        _ => None,
    };
    sqlx::query(
        "UPDATE core_agent_sessions SET turn_cost_micros = ?, turn_cost_approx = ? WHERE id = ?",
    )
    .bind(cost)
    .bind(cost.is_some() && harness == "claude" && e.body["type"] == "usage_so_far")
    .bind(id)
    .execute(&mut *tx)
    .await
    .map(drop)
}

/// Moves a `running` live session between working and `waiting` (`agent.state` says so).
async fn set_idle(
    tx: &mut SqliteConnection,
    id: &str,
    state: AgentState,
    now: &str,
) -> Result<(), sqlx::Error> {
    let (query, name, why) = match state {
        AgentState::Waiting => (
            sqlx::query(
                "UPDATE core_agent_sessions SET waiting_since = CAST(strftime('%s', ?) AS INTEGER) \
                 WHERE id = ? AND state = 'running' AND live = 1 AND waiting_since IS NULL",
            )
            .bind(now)
            .bind(id),
            "waiting",
            "turn_ended",
        ),
        AgentState::Running => (
            sqlx::query(
                "UPDATE core_agent_sessions SET waiting_since = NULL \
                 WHERE id = ? AND state = 'running' AND waiting_since IS NOT NULL",
            )
            .bind(id),
            "running",
            "message",
        ),
        _ => return Ok(()),
    };
    let changed = query.execute(&mut *tx).await?.rows_affected();
    if changed > 0 {
        let payload = json!({"session": id, "state": name, "reason": why});
        emit(tx, "agent.state", payload).await?;
    }
    Ok(())
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

/// Whether the transcript of `id` has a sub-agent's tool call `call` (Claude Code's `Task` or
/// `Agent`) with no result yet.
pub async fn subagent_running(
    pool: &SqlitePool,
    id: &str,
    call: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM core_agent_transcript WHERE session = ?1 \
           AND json_extract(body, '$.type') = 'tool_use' AND json_extract(body, '$.id') = ?2 \
           AND json_extract(body, '$.name') IN ('Task', 'Agent')) \
         AND NOT EXISTS (SELECT 1 FROM core_agent_transcript WHERE session = ?1 \
           AND json_extract(body, '$.type') = 'tool_result' AND json_extract(body, '$.id') = ?2)",
    )
    .bind(id)
    .bind(call)
    .fetch_one(pool)
    .await
}

/// Raises `agent.approval_requested` for a request the Core had silenced (`apply_quiet`) and then
/// could not decide by its rule: it goes to the person after all.
pub async fn raise_request(pool: &SqlitePool, payload: Value) -> Result<(), sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    emit(&mut tx, "agent.approval_requested", payload).await?;
    tx.commit().await
}

/// The `approval_request` entry `request` of session `id`: its `tool` and `input`.
pub async fn approval_request(
    pool: &SqlitePool,
    id: &str,
    request: &str,
) -> Result<Option<Value>, sqlx::Error> {
    let body: Option<String> = sqlx::query_scalar(
        "SELECT body FROM core_agent_transcript WHERE session = ?1 \
           AND json_extract(body, '$.type') = 'approval_request' \
           AND json_extract(body, '$.id') = ?2 ORDER BY seq DESC LIMIT 1",
    )
    .bind(id)
    .bind(request)
    .fetch_optional(pool)
    .await?;
    Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
}

/// The file-edit `tool_use` entries of session `id` (they carry `edit`), newest first, at most
/// 2000, leaving out a call that ended in an error (it changed nothing, or was denied).
pub async fn file_edits(pool: &SqlitePool, id: &str) -> Result<Vec<Value>, sqlx::Error> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT t.body FROM core_agent_transcript t WHERE t.session = ?1 \
           AND json_extract(t.body, '$.type') = 'tool_use' \
           AND json_extract(t.body, '$.edit') IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM core_agent_transcript r WHERE r.session = ?1 \
             AND json_extract(r.body, '$.type') = 'tool_result' \
             AND json_extract(r.body, '$.id') = json_extract(t.body, '$.id') \
             AND json_extract(r.body, '$.status') = 'error') \
         ORDER BY t.seq DESC LIMIT 2000",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|b| serde_json::from_str(b).ok())
        .collect())
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

/// Replaces what a session said, and its first message, with a placeholder (C-08): the Brain
/// keeps the real text inside a room's file, so the Core's copy must not hold it. Entry numbers
/// and the count stay, so a reader still replays without a gap.
pub async fn seal(pool: &SqlitePool, id: &str) -> Result<u64, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let n = sqlx::query(
        "UPDATE core_agent_transcript SET body = '{\"sealed\":true}' WHERE session = ?",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE core_agent_sessions SET prompt = NULL, title = 'Brain distillation' WHERE id = ?",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(n)
}

/// `state` as the runner reports it, as stored.
pub fn runner_state(s: AgentState) -> &'static str {
    match s {
        AgentState::Running | AgentState::Waiting => "running",
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
    // A chain session takes its account's slot again, or stays lost (the cap, KAN-437).
    if !super::alloc::may_return_in(&mut tx, id).await? {
        return Ok(false);
    }
    super::alloc::stamp_account_in(&mut tx, id).await?;
    let changed = sqlx::query(
        "UPDATE core_agent_sessions SET state = 'interrupted', outcome = NULL, ended_at = NULL, \
         failover_done = 0, failover_class = NULL, upstream_class = NULL, updated_at = ? \
         WHERE id = ? AND state IN ('lost', 'interrupted')",
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
    wake_with(pool, id, text, &[], now).await
}

/// [`wake`], and a live session's pending message names `attachments` (E4): they are marked
/// pending in the same write, the ones of an earlier pending message no longer.
pub async fn wake_with(
    pool: &SqlitePool,
    id: &str,
    text: Option<&str>,
    attachments: &[String],
    now: &str,
) -> Result<Woken, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    // state, harness session, outcome, owner module
    type Found = (String, Option<String>, Option<String>, Option<String>);
    let found: Option<Found> = sqlx::query_as(
        "SELECT state, harness_session, outcome, owner_module FROM core_agent_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((state, harness, outcome, owner)) = found else {
        return Ok(Woken::Gone);
    };
    // An attempt a failover replaced is never brought back: the run lives on in its successor.
    if super::failover::has_successor_in(&mut tx, id).await? {
        return Ok(Woken::Gone);
    }
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
    // Not over its account's cap (it queues: the wake job asks again), and counted by it from now on.
    if !super::alloc::may_return_in(&mut tx, id).await? {
        return Ok(Woken::Busy);
    }
    super::alloc::stamp_account_in(&mut tx, id).await?;
    // A live session's text is its next message, delivered once the runner runs it again; the
    // session's own first prompt is never sent twice.
    sqlx::query(
        "UPDATE core_agent_sessions SET state = 'interrupted', outcome = NULL, ended_at = NULL, \
         failover_done = 0, failover_class = NULL, upstream_class = NULL, waiting_since = NULL, \
         prompt = iif(live = 1, prompt, coalesce(?1, prompt)), \
         pending = iif(live = 1, coalesce(?1, pending), pending), updated_at = ?2 \
         WHERE id = ?3",
    )
    .bind(text)
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if text.is_some() {
        sqlx::query(
            "UPDATE core_agent_attachments SET pending = (id IN (SELECT value FROM json_each(?1))) \
             WHERE session = ?2 AND (SELECT live FROM core_agent_sessions WHERE id = ?2) = 1",
        )
        .bind(serde_json::to_string(attachments).expect("ids serialize"))
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    if state != "interrupted" {
        let payload = json!({"session": id, "state": "interrupted", "reason": "woken"});
        emit(&mut tx, "agent.state", payload).await?;
    }
    tx.commit().await?;
    Ok(Woken::Reopened)
}

/// Marks a just-created client session as a live conversation and gives it its title.
/// Why the Core placed session `id` where it did (E15 `place_reason`).
pub async fn set_place_reason(
    pool: &SqlitePool,
    id: &str,
    reason: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE core_agent_sessions SET place_reason = ? WHERE id = ?")
        .bind(reason)
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

pub async fn configure(
    pool: &SqlitePool,
    id: &str,
    live: bool,
    title: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE core_agent_sessions SET live = ?, title = ? WHERE id = ?")
        .bind(i64::from(live))
        .bind(title)
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// Sets the title; whether the session exists. An empty title clears it.
pub async fn set_title(pool: &SqlitePool, id: &str, title: &str) -> Result<bool, sqlx::Error> {
    let title = Some(title.trim()).filter(|t| !t.is_empty());
    sqlx::query("UPDATE core_agent_sessions SET title = ? WHERE id = ?")
        .bind(title)
        .bind(id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() > 0)
}

/// Replaces a session's policy (`setAgentSessionMode`): every later start of it runs under this one.
pub async fn set_policy(pool: &SqlitePool, id: &str, policy: &Value) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE core_agent_sessions SET policy = ? WHERE id = ?")
        .bind(policy.to_string())
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// Gives a session with no title the start of its first message.
pub async fn title_from_first_message(
    pool: &SqlitePool,
    id: &str,
    text: &str,
) -> Result<(), sqlx::Error> {
    let Some(title) = title_of(text) else {
        return Ok(());
    };
    sqlx::query("UPDATE core_agent_sessions SET title = ? WHERE id = ? AND title IS NULL")
        .bind(title)
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// Forgets the pending message `text` once it is delivered.
/// Its attachments (E4) are no longer pending with it.
pub async fn clear_pending(pool: &SqlitePool, id: &str, text: &str) -> Result<(), sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let cleared =
        sqlx::query("UPDATE core_agent_sessions SET pending = NULL WHERE id = ? AND pending = ?")
            .bind(id)
            .bind(text)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if cleared > 0 {
        sqlx::query("UPDATE core_agent_attachments SET pending = 0 WHERE session = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}
