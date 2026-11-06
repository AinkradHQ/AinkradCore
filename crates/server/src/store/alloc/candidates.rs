//! Which accounts of an entry's pool may take the session, and why the others may not.

use sqlx::{Row, SqliteConnection};

use super::{Ask, Entry};
use crate::scheduler::unix_secs;
use crate::store::account_keys::subscription_provider;
use crate::store::budgets::guard;
use crate::store::gateway::{self as gw, MIN_CEILING_TOKENS};
use crate::store::{health, providers, secrets};

pub(super) struct Cand {
    pub id: i64,
    pub secret: String,
    pub seat: i64,
    pub live: i64,
    pub last: Option<String>,
}

/// How many accounts of the pool each filter turned away.
#[derive(Default)]
pub(super) struct Tally {
    used: u32,
    other_user: u32,
    not_leasable: u32,
    cooling: u32,
    unavailable: u32,
    auth_pending: u32,
    at_cap: u32,
    no_room: u32,
    pub hold_denied: u32,
}

impl Tally {
    /// Counts only, so the text can never carry an account's label.
    pub fn text(&self) -> String {
        let parts = [
            (self.used, "already used by this run"),
            (self.other_user, "of another user or provider"),
            (self.not_leasable, "not leasable to this runner"),
            (self.cooling, "cooling or limited"),
            (self.unavailable, "disabled, held or unhealthy"),
            (self.auth_pending, "an auth failure is being confirmed"),
            (self.at_cap, "at its session cap"),
            (self.no_room, "out of budget"),
            (self.hold_denied, "its budget hold was denied"),
        ];
        let said: Vec<String> = parts
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, w)| format!("{n} {w}"))
            .collect();
        match said.is_empty() {
            true => "the pool has no accounts".to_owned(),
            false => said.join(", "),
        }
    }
}

pub(super) struct Found {
    pub ready: Vec<Cand>,
    /// An account that could take the session is at its cap: a slot may free soon.
    pub full: bool,
    pub tally: Tally,
    /// The earliest end (unix seconds) of a window that is cooling an account the session could
    /// otherwise use.
    pub until: Option<i64>,
}

/// The variable the entry's account secret is delivered in, or why the entry cannot run: its
/// provider is gone, or its harness is not the provider's own.
pub(super) async fn auth_var(
    conn: &mut SqliteConnection,
    e: &Entry,
) -> Result<Result<String, String>, sqlx::Error> {
    Ok(match providers::get_in(conn, &e.provider).await {
        Ok(d) if d.harness == e.harness => Ok(d.auth_var),
        Ok(_) => Err("the entry's harness is not its provider's".to_owned()),
        Err(secrets::Error::Db(e)) => return Err(e),
        Err(_) => Err("the entry's provider is gone".to_owned()),
    })
}

/// Whether the budgets of the account and its pools leave room for one turn of `min_turn`
/// micro-dollars. A subscription (`plan`) bills no dollars: its dollar budgets do not apply, its
/// token budgets do.
pub async fn room_in(
    conn: &mut SqliteConnection,
    account: i64,
    session: &str,
    plan: bool,
    min_turn: u64,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let owned = gw::subjects_of(conn, account).await?;
    let standings = guard::standings_for(conn, &gw::refs(&owned), now, session, true).await?;
    let (tokens, usd) = gw::room(&standings);
    Ok(tokens.is_none_or(|t| t >= MIN_CEILING_TOKENS)
        && (plan || usd.is_none_or(|u| u >= min_turn)))
}

pub(super) async fn of_entry(
    conn: &mut SqliteConnection,
    ask: &Ask<'_>,
    e: &Entry,
    now: &str,
    now_u: i64,
) -> Result<Found, sqlx::Error> {
    let seats: Vec<i64> =
        sqlx::query_scalar("SELECT account_id FROM core_pool_members WHERE pool_id = ?")
            .bind(e.pool)
            .fetch_all(&mut *conn)
            .await?;
    // Recovery is lazy: a window that has ended is over before any account is judged.
    for id in seats {
        health::recover_in(conn, id, now).await?;
    }
    let sql = format!(
        "SELECT a.id, a.user_id, a.provider, a.secret_name, a.state, a.state_reason, \
         a.state_until, a.cap, a.last_used_at, m.position AS seat, \
         EXISTS (SELECT 1 FROM core_secrets s, json_each(s.runners) j \
                 WHERE s.name = a.secret_name AND j.value = ?2) AS leasable, \
         (SELECT count(*) FROM core_agent_sessions x WHERE x.account_id = a.id AND x.id != ?3 \
          AND x.state IN ({})) AS live \
         FROM core_pool_members m JOIN core_accounts a ON a.id = m.account_id \
         WHERE m.pool_id = ?1 ORDER BY m.position",
        super::live::HOLDING
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(e.pool)
        .bind(ask.runner)
        .bind(ask.session)
        .fetch_all(&mut *conn)
        .await?;
    let mut out = Found {
        ready: Vec::new(),
        full: false,
        tally: Tally::default(),
        until: None,
    };
    for r in &rows {
        let id: i64 = r.try_get("id")?;
        let (state, reason): (String, Option<String>) =
            (r.try_get("state")?, r.try_get("state_reason")?);
        let until = r
            .try_get::<Option<String>, _>("state_until")?
            .as_deref()
            .and_then(unix_secs);
        let (cap, live): (i64, i64) = (r.try_get("cap")?, r.try_get("live")?);
        let t = &mut out.tally;
        if ask.used_accounts.contains(&id) {
            t.used += 1;
        } else if r.try_get::<i64, _>("user_id")? != ask.user
            || r.try_get::<String, _>("provider")? != e.provider
        {
            t.other_user += 1;
        } else if r.try_get::<i64, _>("leasable")? == 0 {
            t.not_leasable += 1;
        } else if state != "active" {
            // Only a window this module's own signals opened ends by itself.
            let timed = matches!(
                reason.as_deref(),
                Some("rate_limited" | "upstream_errors" | "quota")
            );
            match until.filter(|u| timed && *u > now_u) {
                Some(u) => {
                    t.cooling += 1;
                    out.until = Some(out.until.map_or(u, |o| o.min(u)));
                }
                None => t.unavailable += 1,
            }
        } else if gw::pending_auth_in(conn, id).await?.is_some() {
            out.tally.auth_pending += 1;
        } else if cap > 0 && live >= cap {
            out.tally.at_cap += 1;
        } else if !room_in(
            conn,
            id,
            ask.session,
            subscription_provider(&e.provider),
            (ask.min_turn)(e),
            now,
        )
        .await?
        {
            out.tally.no_room += 1;
        } else {
            out.ready.push(Cand {
                id,
                secret: r.try_get("secret_name")?,
                seat: r.try_get("seat")?,
                live,
                last: r.try_get("last_used_at")?,
            });
        }
    }
    out.full = out.tally.at_cap > 0;
    Ok(out)
}
