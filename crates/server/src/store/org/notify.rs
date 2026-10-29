//! Notification preferences per company (parity API B2): which event goes to which channel,
//! quiet hours, and what breaks through them. A pair with no stored choice has its default
//! (`ops::notify_default`). Audited as `notifications.updated`; `notifications.test` is the
//! event a test emits. Both are events on the stream.
//!
//! ponytail: the push sender does not consult these yet; wire it where pushes are chosen.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ops::{BREAKTHROUGHS, NOTIFY_CHANNELS, NOTIFY_EVENTS, notify_default};
use ainkrad_core::org::CompanyId;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row};

use super::service::append_org_event;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quiet {
    /// Minutes from midnight; the window wraps past midnight when start is after end.
    pub start: i64,
    pub end: i64,
    pub on: bool,
    pub breakthrough: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notifications {
    /// Every (event, channel, on), events in `NOTIFY_EVENTS` order.
    pub matrix: Vec<(String, String, bool)>,
    pub quiet: Quiet,
}

/// What a change sets: the listed pairs, and the quiet hours' fields given.
#[derive(Debug, Clone, Default)]
pub struct NotificationsChange {
    pub matrix: Vec<(String, String, bool)>,
    pub quiet_start: Option<i64>,
    pub quiet_end: Option<i64>,
    pub quiet_on: Option<bool>,
    pub breakthrough: Option<String>,
}

pub async fn notifications(pool: &SqlitePool, company: CompanyId) -> Result<Notifications, Error> {
    let chosen =
        sqlx::query("SELECT event, channel, enabled FROM notification_prefs WHERE company_id = ?")
            .bind(company.0)
            .fetch_all(pool)
            .await?;
    let mut matrix = vec![];
    for event in NOTIFY_EVENTS {
        for channel in NOTIFY_CHANNELS {
            let on = chosen
                .iter()
                .find(|r| {
                    r.try_get::<String, _>("event").is_ok_and(|e| e == event)
                        && r.try_get::<String, _>("channel")
                            .is_ok_and(|c| c == channel)
                })
                .map_or(Ok(notify_default(event, channel)), |r| r.try_get("enabled"))?;
            matrix.push((event.to_owned(), channel.to_owned(), on));
        }
    }
    let quiet = sqlx::query(
        "SELECT quiet_start, quiet_end, quiet_on, breakthrough FROM notification_quiet \
         WHERE company_id = ?",
    )
    .bind(company.0)
    .fetch_optional(pool)
    .await?;
    let quiet = match quiet {
        Some(r) => Quiet {
            start: r.try_get("quiet_start")?,
            end: r.try_get("quiet_end")?,
            on: r.try_get("quiet_on")?,
            breakthrough: r.try_get("breakthrough")?,
        },
        None => Quiet {
            start: 1320,
            end: 420,
            on: false,
            breakthrough: "stalled".to_owned(),
        },
    };
    Ok(Notifications { matrix, quiet })
}

fn invalid(why: String) -> Error {
    Error::InvalidArgument(why)
}

/// Applies `c` and appends `notifications.updated`; unknown events, channels or breakthroughs
/// and times outside 0-1439 are `InvalidArgument`.
pub async fn set_notifications(
    pool: &SqlitePool,
    company: CompanyId,
    c: &NotificationsChange,
    actor: AuditActor,
) -> Result<Notifications, Error> {
    for (event, channel, _) in &c.matrix {
        if !NOTIFY_EVENTS.contains(&event.as_str()) || !NOTIFY_CHANNELS.contains(&channel.as_str())
        {
            return Err(invalid(format!("no such notification {event}/{channel}")));
        }
    }
    if c.quiet_start
        .iter()
        .chain(&c.quiet_end)
        .any(|m| !(0..1440).contains(m))
    {
        return Err(invalid(
            "quiet hours are minutes from midnight, 0-1439".to_owned(),
        ));
    }
    if c.breakthrough
        .as_deref()
        .is_some_and(|b| !BREAKTHROUGHS.contains(&b))
    {
        return Err(invalid(format!("breakthrough is one of {BREAKTHROUGHS:?}")));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    for (event, channel, on) in &c.matrix {
        sqlx::query(
            "INSERT INTO notification_prefs (company_id, event, channel, enabled) \
             VALUES (?, ?, ?, ?) ON CONFLICT (company_id, event, channel) \
             DO UPDATE SET enabled = excluded.enabled",
        )
        .bind(company.0)
        .bind(event)
        .bind(channel)
        .bind(on)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO notification_quiet (company_id, quiet_start, quiet_end, quiet_on, breakthrough) \
         VALUES (?1, coalesce(?2, 1320), coalesce(?3, 420), coalesce(?4, 0), \
             coalesce(?5, 'stalled')) \
         ON CONFLICT (company_id) DO UPDATE SET \
             quiet_start = coalesce(?2, quiet_start), quiet_end = coalesce(?3, quiet_end), \
             quiet_on = coalesce(?4, quiet_on), breakthrough = coalesce(?5, breakthrough)",
    )
    .bind(company.0)
    .bind(c.quiet_start)
    .bind(c.quiet_end)
    .bind(c.quiet_on)
    .bind(&c.breakthrough)
    .execute(&mut *tx)
    .await?;
    let d = json!({"matrix": c.matrix.iter().map(|(e, ch, on)| format!("{e}/{ch}={on}")).collect::<Vec<_>>(),
                   "quiet_start": c.quiet_start, "quiet_end": c.quiet_end,
                   "quiet_on": c.quiet_on, "breakthrough": c.breakthrough});
    let by = ("company", company.0);
    append_org_event(&mut tx, company, actor, "notifications.updated", by, d).await?;
    tx.commit().await?;
    notifications(pool, company).await
}

/// Appends `notifications.test` for the company and returns its sequence number: the event a
/// device shows as a sample notification.
pub async fn test_notification(
    pool: &SqlitePool,
    company: CompanyId,
    actor: AuditActor,
) -> Result<i64, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let d = json!({"event": "approval_waiting", "summary": "A test notification"});
    let by = ("company", company.0);
    append_org_event(&mut tx, company, actor, "notifications.test", by, d).await?;
    let seq: i64 = sqlx::query_scalar("SELECT max(seq) FROM audit_events")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(seq)
}
