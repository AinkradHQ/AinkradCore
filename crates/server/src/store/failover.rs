//! Failover execution's rows (KAN-438 part B, S6; design `2026-11-06-core-account-scheduler` §8).
//! When an attempt cannot go on for an account reason, the run gets a NEW session (a successor
//! attempt), never a new account on the old one (I1): [`move_in`] ends nothing and rewrites
//! nothing of the old attempt, it inserts the successor and lets the allocator pick for it.
//!
//! - **One write.** The claim on the old attempt, the successor's insert, the pick, the successor's
//!   budget hold and its assignment are the caller's ONE write transaction (I4). A rollback leaves
//!   no successor and no hold; a commit leaves both.
//! - **Exactly once.** `failover_done` is claimed in that transaction, and `failover_of` is unique,
//!   so a second supervisor, a retry or a restart that finds the same ended attempt does nothing.
//!   A crash between the end of the attempt and the commit leaves the attempt unsettled, and the
//!   start-up scan ([`unfinished`]) finishes it.
//! - **A wait is bounded.** The successor row exists before its pick, so a wait is recorded on it
//!   (`waiting.since`) like any other and ends `wait_max` after its first. Nothing waits for ever.
//! - **Forward only (I3).** The pick starts at the old attempt's chain position and leaves out every
//!   account the run has used; hops are capped ([`MAX_HOPS`]) and the Core-wide rate is bounded
//!   ([`PER_WINDOW`] in [`WINDOW_SECS`]).
//! - **Events.** The successor is audited `agent.created` with a `failover` block (names and ids,
//!   never a value), a provider or harness change is an `agent.state` note, and every move or end of
//!   a run raises `account.failover` (`notice`); the storm guard raises `alarm.raised` once a window.

use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

use super::alloc::{self, Ask, Entry, Outcome, Picked};
use super::{agents as sessions, budgets::guard, events};
use crate::scheduler::{iso_of_unix, unix_secs};

mod decide;
mod notice;
mod run;
pub use decide::*;
pub use run::*;

/// New attempts a run may have: the default of `scheduler.max_hops` (0 turns failover off).
pub const MAX_HOPS: i64 = 4;
/// Failovers one user's runs start in [`WINDOW_SECS`]: the default of `scheduler.failovers_per_10min`.
pub const PER_WINDOW: i64 = 10;
pub const WINDOW_SECS: i64 = 600;
/// The one line a restarted attempt's prompt starts with: its workspace may hold the old one's work.
pub const NOTE: &str =
    "A previous attempt stopped (account failover); the workspace may hold its partial changes.";
const MAX_PROMPT: usize = 64 * 1024;

/// What the failover reads of an attempt's row.
#[derive(Debug, Clone)]
pub struct View {
    pub id: String,
    pub n: i64,
    pub state: String,
    pub runner: String,
    pub user: i64,
    /// The first attempt's id.
    pub run: String,
    pub attempt: i64,
    pub chain: Option<Vec<Entry>>,
    pub pos: Option<usize>,
    pub account: Option<i64>,
    pub outcome: Option<Value>,
    pub class: Option<String>,
    pub done: bool,
    pub upstream: Option<String>,
    pub gw_stop: Option<String>,
    /// The budget the stop names (`pool:12`, `account:5`); `None` for a ceiling or a session limit.
    pub budget: Option<BudgetStop>,
    /// Served by the auth gateway: its own reports are the authority for what went wrong.
    pub gateway: bool,
    pub module: bool,
    pub skip_pools: Vec<i64>,
    pub created_by: String,
}

pub async fn view_in(conn: &mut SqliteConnection, id: &str) -> Result<Option<View>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT n, state, runner, user_id, coalesce(run_id, id) AS run, attempt, chain, chain_pos, \
         account_id, outcome, failover_class, failover_done, upstream_class, gw_stop, gw_stop_budget, \
         gateway_account_id, owner_module, skip_pools, created_by \
         FROM core_agent_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?
    else {
        return Ok(None);
    };
    let json = |c: &str| -> Result<Option<Value>, sqlx::Error> {
        Ok(r.try_get::<Option<String>, _>(c)?
            .and_then(|s| serde_json::from_str(&s).ok()))
    };
    Ok(Some(View {
        id: id.to_owned(),
        n: r.try_get("n")?,
        state: r.try_get("state")?,
        runner: r.try_get("runner")?,
        user: r.try_get("user_id")?,
        run: r.try_get("run")?,
        attempt: r.try_get("attempt")?,
        chain: r
            .try_get::<Option<String>, _>("chain")?
            .map(|j| serde_json::from_str(&j).unwrap_or_default()),
        pos: r
            .try_get::<Option<i64>, _>("chain_pos")?
            .and_then(|p| usize::try_from(p).ok()),
        account: r.try_get("account_id")?,
        outcome: json("outcome")?,
        class: r.try_get("failover_class")?,
        done: r.try_get::<i64, _>("failover_done")? != 0,
        upstream: r.try_get("upstream_class")?,
        gw_stop: r.try_get("gw_stop")?,
        budget: r
            .try_get::<Option<String>, _>("gw_stop_budget")?
            .as_deref()
            .and_then(budget_stop),
        gateway: r.try_get::<Option<i64>, _>("gateway_account_id")?.is_some(),
        module: r.try_get::<Option<String>, _>("owner_module")?.is_some(),
        skip_pools: json("skip_pools")?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default(),
        created_by: r.try_get("created_by")?,
    }))
}

pub async fn view(pool: &sqlx::sqlite::SqlitePool, id: &str) -> Result<Option<View>, sqlx::Error> {
    view_in(&mut *pool.acquire().await?, id).await
}

/// What [`move_in`] needs from the service around it.
pub struct Ctx<'a> {
    pub now: &'a str,
    pub min_turn: &'a (dyn Fn(&Entry) -> u64 + Sync),
    pub serves: &'a (dyn Fn(&Entry) -> Option<String> + Sync),
    pub wait_max_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Moved {
    /// Nothing to do: the attempt is not over, is settled already, or has no chain.
    Skipped,
    /// A successor exists. `picked` is `None` while it waits for an account (its own wait is
    /// recorded on its row and bounded by `wait_max`).
    To {
        session: String,
        picked: Option<Picked>,
    },
    /// The run ends with this attempt: why, and one reason per chain entry looked at.
    Ended {
        why: String,
        reasons: Vec<(usize, String)>,
    },
}

/// Moves the run of the over attempt `old` along its chain, in the caller's write transaction:
/// claims the attempt, starts the successor and picks its account. The caller commits (or rolls
/// back, which undoes every part of it).
pub async fn move_in(
    conn: &mut SqliteConnection,
    old: &str,
    class: &str,
    cx: &Ctx<'_>,
) -> Result<Moved, sqlx::Error> {
    let Some(v) = view_in(conn, old).await? else {
        return Ok(Moved::Skipped);
    };
    let (Some(chain), Some(now_u)) = (v.chain.clone(), unix_secs(cx.now)) else {
        return Ok(Moved::Skipped);
    };
    if v.module || v.done || !matches!(v.state.as_str(), "ended" | "lost") {
        return Ok(Moved::Skipped);
    }
    // The claim: whoever commits it first moves the run; the others find it settled.
    let claimed = sqlx::query(
        "UPDATE core_agent_sessions SET failover_done = 1, failover_class = coalesce(failover_class, ?) \
         WHERE id = ? AND failover_done = 0 AND state IN ('ended', 'lost')",
    )
    .bind(class)
    .bind(old)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if claimed == 0 || has_successor_in(conn, old).await? {
        return Ok(Moved::Skipped);
    }
    let (max_hops, per_window) = notice::limits(conn).await?;
    if max_hops == 0 {
        return ended(
            conn,
            &v,
            class,
            "failover is off (scheduler.max_hops 0)",
            vec![],
        )
        .await;
    }
    if v.attempt + 1 > max_hops {
        let why = "hop cap: the run has used its attempts";
        return ended(conn, &v, class, why, vec![]).await;
    }
    let since = iso_of_unix(now_u - WINDOW_SECS);
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_agent_sessions WHERE failover_of IS NOT NULL \
         AND user_id = ? AND julianday(created_at) > julianday(?)",
    )
    .bind(v.user)
    .bind(&since)
    .fetch_one(&mut *conn)
    .await?;
    if recent >= per_window {
        notice::storm(conn, v.user, recent, per_window, now_u).await?;
        return ended(conn, &v, class, "failover storm guard", vec![]).await;
    }
    let mut skip = v.skip_pools.clone();
    if let Some(BudgetStop::Pool(p)) = v.budget
        && !skip.contains(&p)
    {
        skip.push(p);
    }
    let new = insert_successor(conn, &v, &skip, cx.now).await?;
    let (used, skip) = context_in(conn, &new).await?;
    let from = v.pos.unwrap_or(0);
    let ask = Ask {
        session: &new,
        runner: &v.runner,
        user: v.user,
        chain: &chain,
        from_pos: from,
        used_accounts: &used,
        skip_pools: &skip,
        min_turn: cx.min_turn,
        serves: cx.serves,
        wait_max_secs: cx.wait_max_secs,
    };
    let picked = match alloc::pick_in(conn, &ask, cx.now).await? {
        Outcome::Picked(p) => Some(p),
        Outcome::Wait { .. } => None,
        gone @ (Outcome::Gone | Outcome::Exhausted(_)) => {
            let reasons = match gone {
                Outcome::Exhausted(r) => r,
                _ => vec![(from, "the run cannot move on".to_owned())],
            };
            // No attempt after all: the row goes, and no hold was taken (a pick that gives up
            // holds nothing; released anyway).
            guard::release_in(conn, &new).await?;
            sqlx::query("DELETE FROM core_agent_sessions WHERE id = ?")
                .bind(&new)
                .execute(&mut *conn)
                .await?;
            return ended(conn, &v, class, "no account is available", reasons).await;
        }
    };
    announce(conn, &v, &new, class, picked.as_ref(), &chain).await?;
    Ok(Moved::To {
        session: new,
        picked,
    })
}

/// The run ends with `old`: the reasons go on its outcome, where the person reads why.
async fn ended(
    conn: &mut SqliteConnection,
    v: &View,
    class: &str,
    why: &str,
    reasons: Vec<(usize, String)>,
) -> Result<Moved, sqlx::Error> {
    let old = v.id.as_str();
    let said: Vec<String> = reasons
        .iter()
        .map(|(p, r)| format!("entry {}: {r}", p + 1))
        .collect();
    let note = json!({"result": "ended", "why": why, "reasons": said}).to_string();
    sqlx::query(
        "UPDATE core_agent_sessions SET outcome = json_set(coalesce(outcome, '{}'), '$.failover', \
         json(?)) WHERE id = ?",
    )
    .bind(note)
    .bind(old)
    .execute(&mut *conn)
    .await?;
    notice::failover(conn, v, class, None, None).await?;
    Ok(Moved::Ended {
        why: why.to_owned(),
        reasons,
    })
}

/// Inserts the successor: the old attempt's task, runner, workspace and policy, none of its
/// account (the pick gives it one), at the old attempt's chain position.
async fn insert_successor(
    conn: &mut SqliteConnection,
    v: &View,
    skip: &[i64],
    now: &str,
) -> Result<String, sqlx::Error> {
    let r = sqlx::query(
        "SELECT harness, model, prompt, workspace, policy, secrets, agent, chain_id, chain \
         FROM core_agent_sessions WHERE id = ?",
    )
    .bind(&v.id)
    .fetch_one(&mut *conn)
    .await?;
    let mut secrets: Vec<sessions::SessionSecret> =
        serde_json::from_str(&r.try_get::<String, _>("secrets")?).unwrap_or_default();
    secrets.retain(|s| !s.name.starts_with(super::secrets::ACCOUNT_PREFIX));
    let prompt: Option<String> = r.try_get("prompt")?;
    let prompt =
        prompt.map(
            |p| match p.starts_with(NOTE) || p.len() + NOTE.len() + 2 > MAX_PROMPT {
                true => p,
                false => format!("{NOTE}\n\n{p}"),
            },
        );
    let id = crate::auth::crypto::random_id("as_");
    sqlx::query(
        "INSERT INTO core_agent_sessions (id, runner, harness, model, prompt, workspace, policy, \
         secrets, state, created_by, created_at, updated_at, user_id, agent, chain_id, chain, \
         chain_pos, run_id, attempt, failover_of, skip_pools) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&v.runner)
    .bind(r.try_get::<String, _>("harness")?)
    .bind(r.try_get::<Option<String>, _>("model")?)
    .bind(prompt)
    .bind(r.try_get::<Option<String>, _>("workspace")?)
    .bind(r.try_get::<String, _>("policy")?)
    .bind(serde_json::to_string(&secrets).expect("names serialize"))
    .bind(&v.created_by)
    .bind(now)
    .bind(now)
    .bind(v.user)
    .bind(r.try_get::<Option<String>, _>("agent")?)
    .bind(r.try_get::<Option<i64>, _>("chain_id")?)
    .bind(r.try_get::<Option<String>, _>("chain")?)
    .bind(v.pos.and_then(|p| i64::try_from(p).ok()))
    .bind(&v.run)
    .bind(v.attempt + 1)
    .bind(&v.id)
    .bind(json!(skip).to_string())
    .execute(conn)
    .await?;
    Ok(id)
}

/// The audit row and events of a move that made a successor.
async fn announce(
    conn: &mut SqliteConnection,
    v: &View,
    new: &str,
    class: &str,
    picked: Option<&Picked>,
    chain: &[Entry],
) -> Result<(), sqlx::Error> {
    let was = v.pos.and_then(|p| chain.get(p));
    let n: i64 = sqlx::query_scalar("SELECT n FROM core_agent_sessions WHERE id = ?")
        .bind(new)
        .fetch_one(&mut *conn)
        .await?;
    let failover = json!({"run": v.run, "from_session": v.id, "from_account": v.account,
        "from_pool": was.map(|e| e.pool), "to_account": picked.map(|p| p.account),
        "to_pool": picked.map(|p| p.pool), "class": class, "hop": v.attempt + 1});
    let harness = picked.map_or_else(
        || was.map(|e| e.harness.clone()),
        |p| Some(p.harness.clone()),
    );
    let details = json!({"session": new, "runner": v.runner, "harness": harness,
        "leased": picked.map(|p| vec![p.secret.name.clone()]).unwrap_or_default(),
        "failover": failover});
    sessions::audit(
        conn,
        AuditActor::System,
        "agent.created",
        n,
        details,
        &v.created_by,
    )
    .await?;
    let about = json!({"session": new, "runner": v.runner, "harness": harness});
    events::append(conn, "agent.created", &about).await?;
    notice::failover(conn, v, class, Some(new), picked).await?;
    if let (Some(p), Some(was)) = (picked, was)
        && (was.provider != p.provider || was.harness != p.harness)
    {
        let note = json!({"session": new, "state": "starting", "reason": "failover",
            "from": {"provider": was.provider, "harness": was.harness},
            "to": {"provider": p.provider, "harness": p.harness}});
        events::append(conn, "agent.state", &note).await?;
    }
    Ok(())
}
