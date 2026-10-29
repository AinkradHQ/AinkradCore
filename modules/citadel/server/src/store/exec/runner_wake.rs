//! Waking a sleeping runner (decision #35, the "Why stuck" screen's "Wake my Mac" and "Run when
//! I'm back"). The server cannot reach a sleeping machine, and a runner cannot wake its own:
//! these are intents, recorded on the runner until it next connects and pushed to the admin's
//! devices, where the Mac app keeps its machine awake (`caffeinate`) or tells the admin it is
//! back. Nothing pretends to wake anything.
//!
//! - `now` ("Wake my Mac"): audited as `runner.wake_requested`, pushed at once.
//! - `when_back` ("Run when I'm back"): audited as `runner.wake_requested`, not pushed; the work
//!   waits in the queue.
//!
//! Either way, the wakes only that runner can serve are not stuck while the intent stands (the
//! repairs would otherwise drop them), and when it next says hello the intent is cleared and
//! `runner.back` is audited, which pushes.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;

use super::*;
use crate::store::audit;

/// When the admin wants the runner: `now` or `when_back`.
pub const WAKE_MODES: &[&str] = &["now", "when_back"];

async fn record(
    conn: &mut sqlx::SqliteConnection,
    actor: AuditActor,
    action: &str,
    runner: RunnerId,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "runner".to_owned(),
            id: runner.0,
        }),
        company_id: None,
        run_id: None,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

/// Records the admin's wish to have the runner back, `mode` one of `WAKE_MODES`, as `actor`.
/// `None`: no such runner; `Err(InvalidArgument)`: an unknown mode.
pub async fn request_wake(
    pool: &SqlitePool,
    runner: RunnerId,
    mode: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Option<Runner>, Error> {
    if !WAKE_MODES.contains(&mode) {
        let why = format!("unknown wake mode {mode:?}: now or when_back");
        return Err(Error::InvalidArgument(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let found = sqlx::query(concat!(
        "UPDATE runners SET wake_requested_at = ?, wake_mode = ? WHERE id = ? RETURNING ",
        runner_columns!()
    ))
    .bind(now)
    .bind(mode)
    .bind(runner.0)
    .fetch_optional(&mut *tx)
    .await?
    .map(super::runner)
    .transpose()?;
    let Some(r) = found else {
        return Ok(None);
    };
    let details = json!({"name": r.name, "status": r.status.as_str(), "mode": mode, "at": now});
    record(&mut tx, actor, "runner.wake_requested", runner, details).await?;
    tx.commit().await?;
    Ok(Some(r))
}

/// The runner connected: a wake the admin asked for is done, audited as `runner.back` by the
/// system with how it was asked (which pushes).
pub async fn runner_woke(pool: &SqlitePool, runner: RunnerId) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let asked: Option<(String, Option<String>)> = sqlx::query_as(
        "UPDATE runners SET wake_requested_at = NULL, wake_mode = NULL \
         WHERE id = ? AND wake_requested_at IS NOT NULL RETURNING name, wake_mode",
    )
    .bind(runner.0)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((name, mode)) = asked {
        let details = json!({"name": name, "mode": mode});
        record(&mut tx, AuditActor::System, "runner.back", runner, details).await?;
    }
    tx.commit().await
}
