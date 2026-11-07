//! The events a failover raises (design `2026-11-06-core-account-scheduler` §13, S7), written in
//! the transaction of the move or the end they describe, from what the move already records. Ids and
//! fixed codes only; never a label, a key or a word from upstream.
//!
//! - `account.failover {run, user, from_session, to_session, from_account, to_account, from_pool,
//!   to_pool, class, hop}`: the run moved to `to_session`, or ended (`to_session` and `to_account`
//!   null: the chain has nothing left, the hop cap or the storm guard). `to_account` is also null
//!   while the successor waits for an account.
//! - `alarm.raised {alarm: "failover_storm", value, threshold, user}`: the rate bound on ONE user's
//!   failovers stopped a run of that user from moving, once per window and user (the alarm is
//!   pushed to that user's admin devices only).

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core::settings::{Key, Scope};
use serde_json::json;
use sqlx::SqliteConnection;

use super::{MAX_HOPS, PER_WINDOW, Picked, View, WINDOW_SECS, events};
use crate::scheduler::iso_of_unix;
use crate::store::{audit, settings};

/// `scheduler.max_hops` and `scheduler.failovers_per_10min`, read at each move.
pub(super) async fn limits(conn: &mut SqliteConnection) -> Result<(i64, i64), sqlx::Error> {
    let at = Scope::Server;
    let hops = settings::value_in(conn, Key::SchedulerMaxHops, at).await;
    let rate = settings::value_in(conn, Key::SchedulerFailoversPer10Min, at).await;
    Ok((hops.unwrap_or(MAX_HOPS), rate.unwrap_or(PER_WINDOW)))
}

/// `account.failover` for the move of `v` (to `to`, picked or waiting) or the end of its run.
pub(super) async fn failover(
    conn: &mut SqliteConnection,
    v: &View,
    class: &str,
    to: Option<&str>,
    picked: Option<&Picked>,
) -> Result<(), sqlx::Error> {
    let was = v.chain.as_ref().and_then(|c| v.pos.and_then(|p| c.get(p)));
    let payload = json!({"run": v.run, "user": v.user, "from_session": v.id, "to_session": to,
        "from_account": v.account, "to_account": picked.map(|p| p.account),
        "from_pool": was.map(|e| e.pool), "to_pool": picked.map(|p| p.pool),
        "class": class, "hop": v.attempt + 1});
    events::append(conn, "account.failover", &payload)
        .await
        .map(drop)
}

/// The storm guard refused a move of `user`'s run: `alarm.raised`, once per window and user.
pub(super) async fn storm(
    conn: &mut SqliteConnection,
    user: i64,
    value: i64,
    threshold: i64,
    now_u: i64,
) -> Result<(), sqlx::Error> {
    let since = iso_of_unix(now_u - WINDOW_SECS);
    let raised: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'alarm.raised' \
         AND json_extract(details, '$.alarm') = 'failover_storm' \
         AND json_extract(details, '$.user') = ? AND julianday(at) > julianday(?)",
    )
    .bind(user)
    .bind(since)
    .fetch_one(&mut *conn)
    .await?;
    if raised > 0 {
        return Ok(());
    }
    let payload = json!({"alarm": "failover_storm", "value": value, "threshold": threshold,
        "user": user});
    let row = NewAuditEvent {
        actor: AuditActor::System,
        action: "alarm.raised".to_owned(),
        entity: None,
        details: payload.to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, "alarm.raised", &payload)
        .await
        .map(drop)
}
