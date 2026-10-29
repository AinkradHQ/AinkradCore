//! A device's view of the event log (E1-04.3): only the kinds its scopes may see
//! (`store::kinds`), numbered **gap-free over that view**, so a device can neither read a hidden
//! event nor learn from the numbering that one exists, how many there are, or when they landed.
//!
//! Each event carries the running totals of every visibility scope at its append
//! (`event_views`, migration `0004`). A view's seq for an event is the sum of the totals of
//! the scopes it holds: it rises by one at each visible event and stays put at a hidden one. A
//! view holding every visibility scope numbers exactly as the global seq does.
//!
//! - The cursor a client sends (`after`, `Last-Event-ID`) and every number it gets back (each
//!   event's `seq`, the head, the retention floor) are in its view. [`resume`] turns a view
//!   cursor into the global position it stands for, by binary search over the totals (each step
//!   an indexed point read); reading on from there filters by scope.
//! - A cursor means one view. When a device's scopes change its sockets close with 4003
//!   (handshake spec §10); its client re-syncs from `GET /api/v1/events/latest` as after a 410.

use sqlx::AssertSqlSafe;
use sqlx::sqlite::{SqliteConnection, SqlitePool};

use super::{MAX_EVENTS, PastRetention, StoredEvent, floor_in};
use crate::store::kinds::VISIBLE;

/// Which visibility scopes a device holds, in [`VISIBLE`]'s order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View([bool; 5]);

impl View {
    /// The view of a device with `scopes`.
    pub fn of(scopes: &[String]) -> Self {
        Self(VISIBLE.map(|v| scopes.iter().any(|s| s == v)))
    }

    /// Every visibility scope: numbered as the global seq.
    pub fn all() -> Self {
        Self([true; 5])
    }

    /// The view's seq over a row of running totals (`n_read`, … columns), as SQL.
    fn seq_expr(&self) -> String {
        let terms: Vec<String> = VISIBLE
            .iter()
            .zip(self.0)
            .filter(|(_, on)| *on)
            .map(|(s, _)| format!("n_{s}"))
            .collect();
        match terms.is_empty() {
            true => "0".to_owned(),
            false => terms.join(" + "),
        }
    }

    /// The scopes it sees, as an SQL list of literals (constants, never input).
    fn scopes_sql(&self) -> String {
        let on: Vec<String> = VISIBLE
            .iter()
            .zip(self.0)
            .filter(|(_, on)| *on)
            .map(|(s, _)| format!("'{s}'"))
            .collect();
        match on.is_empty() {
            true => "('')".to_owned(),
            false => format!("({})", on.join(", ")),
        }
    }
}

/// The view's seq at the event `seq` (its totals there); 0 when there is no such row (`seq` 0).
async fn seq_at(conn: &mut SqliteConnection, view: View, seq: i64) -> Result<i64, sqlx::Error> {
    let q = format!("SELECT {} FROM event_views WHERE seq = ?", view.seq_expr());
    let got: Option<i64> = sqlx::query_scalar(AssertSqlSafe(q))
        .bind(seq)
        .fetch_optional(conn)
        .await?;
    Ok(got.unwrap_or(0))
}

/// The view's retention floor: its seq at the global floor.
async fn floor_of(conn: &mut SqliteConnection, view: View) -> Result<(i64, i64), sqlx::Error> {
    let global = floor_in(conn).await?;
    Ok((global, seq_at(conn, view, global).await?))
}

/// The view's head (its newest seq, 0 when it has seen nothing) and its retention floor.
pub async fn head(pool: &SqlitePool, view: View) -> Result<(i64, i64), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let q = format!("SELECT {} FROM event_counts", view.seq_expr());
    let head: i64 = sqlx::query_scalar(AssertSqlSafe(q))
        .fetch_one(&mut *tx)
        .await?;
    let (_, floor) = floor_of(&mut tx, view).await?;
    tx.commit().await?;
    Ok((head, floor))
}

/// The global seq the view cursor `after` stands for: the newest event whose view seq is at most
/// `after` (so reading on after it returns the view's events above `after`), or
/// [`PastRetention`] (in the view's numbers) when `after` is below the view's floor.
pub async fn resume(
    conn: &mut SqliteConnection,
    view: View,
    after: i64,
) -> Result<Result<i64, PastRetention>, sqlx::Error> {
    let (mut lo, floor) = floor_of(conn, view).await?;
    if after < floor {
        return Ok(Err(PastRetention { floor }));
    }
    let q = format!(
        "SELECT seq, {} FROM event_views WHERE seq >= ? ORDER BY seq LIMIT 1",
        view.seq_expr()
    );
    let top: Option<i64> = sqlx::query_scalar("SELECT max(seq) FROM event_views")
        .fetch_one(&mut *conn)
        .await?;
    let Some(top) = top.filter(|t| *t > lo) else {
        return Ok(Ok(lo));
    };
    if seq_at(conn, view, top).await? <= after {
        return Ok(Ok(top));
    }
    // Rows at or below `lo` are at most `after`; rows at or above `hi` are above it.
    let mut hi = top;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        let first: Option<(i64, i64)> = sqlx::query_as(AssertSqlSafe(q.clone()))
            .bind(mid)
            .fetch_optional(&mut *conn)
            .await?;
        match first {
            Some((seq, v)) if v <= after => lo = seq,
            _ => hi = mid,
        }
    }
    Ok(Ok(lo))
}

/// A page of a view.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    /// The view's events, each with the global seq it stands at.
    pub events: Vec<(i64, StoredEvent)>,
    /// How far the log was examined: on a short page, the snapshot's newest global seq (hidden
    /// events up to it need not be scanned again); on a full page, its last event's.
    pub scanned_to: i64,
}

/// Up to `limit` (at most [`MAX_EVENTS`]) of the view's events after the global seq `after`,
/// oldest first, each numbered in the view; or [`PastRetention`] (in the view's numbers) when
/// some were trimmed. Read it in one snapshot (a transaction).
pub async fn read(
    conn: &mut SqliteConnection,
    view: View,
    after: i64,
    limit: u32,
) -> Result<Result<Page, PastRetention>, sqlx::Error> {
    let (global, floor) = floor_of(conn, view).await?;
    if after < global {
        return Ok(Err(PastRetention { floor }));
    }
    let q = format!(
        // Walks `event_views` by seq and stops at the limit (`+` keeps SQLite from sorting
        // every visible row first).
        "SELECT e.seq, e.at, e.kind, e.payload, {} AS vseq FROM event_views v \
         JOIN events e ON e.seq = v.seq \
         WHERE v.seq > ? AND +v.scope IN {} ORDER BY v.seq LIMIT ?",
        view.seq_expr(),
        view.scopes_sql()
    );
    let rows: Vec<(
        i64,
        String,
        String,
        sqlx::types::Json<serde_json::Value>,
        i64,
    )> = sqlx::query_as(AssertSqlSafe(q))
        .bind(after)
        .bind(limit.min(MAX_EVENTS))
        .fetch_all(&mut *conn)
        .await?;
    let scanned_to = match rows.len() < limit.min(MAX_EVENTS) as usize {
        true => {
            sqlx::query_scalar("SELECT max(?, coalesce(max(seq), 0)) FROM events")
                .bind(after)
                .fetch_one(&mut *conn)
                .await?
        }
        false => rows.last().map_or(after, |r| r.0),
    };
    let events = rows
        .into_iter()
        .map(|(global, at, kind, payload, seq)| {
            (
                global,
                StoredEvent {
                    seq,
                    at,
                    kind,
                    payload,
                },
            )
        })
        .collect();
    Ok(Ok(Page { events, scanned_to }))
}

/// A client's HTTP replay: the view's events after its view cursor `after`, in one snapshot.
pub async fn replay(
    pool: &SqlitePool,
    view: View,
    after: i64,
    limit: u32,
) -> Result<Result<Vec<StoredEvent>, PastRetention>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let got = match resume(&mut tx, view, after).await? {
        Ok(global) => read(&mut tx, view, global, limit)
            .await?
            .map(|page| page.events.into_iter().map(|(_, e)| e).collect()),
        Err(past) => Err(past),
    };
    tx.commit().await?;
    Ok(got)
}

#[cfg(test)]
mod tests;
