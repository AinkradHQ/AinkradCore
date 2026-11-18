//! What the Brain gave each AI session (`brain_session_loaded`, Brain v2 B5-02). Every op that hands
//! record text to a session writes here (`record`); the no-echo guard (`echo.rs`) cuts those bodies
//! out of the session's transcript, and merge-on-save (`merge::reinforce`) never counts that
//! session as a new origin of a record it was given.
//!
//! Security model: ids only, never text. The session id comes from the dispatcher's caller, never
//! from input, and `room` is the room the op already resolved through `access`.

use std::collections::{HashMap, HashSet};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::store::begin_write;

/// Notes that `session` was given records `ids` of `room`. A repeat is a no-op.
pub(crate) async fn record(
    app: &App,
    session: &str,
    room: &str,
    ids: &[String],
) -> Result<(), ApiError> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut tx = begin_write(&app.pool).await?;
    for id in ids {
        sqlx::query(
            "INSERT OR IGNORE INTO brain_session_loaded (session, room, record) VALUES (?, ?, ?)",
        )
        .bind(session)
        .bind(room)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Record id to the sessions that were given it, for one room.
pub(crate) async fn of_room(
    app: &App,
    room: &str,
) -> Result<HashMap<String, HashSet<String>>, ApiError> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT record, session FROM brain_session_loaded WHERE room = ?")
            .bind(room)
            .fetch_all(&app.pool)
            .await?;
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for (record, session) in rows {
        out.entry(record).or_default().insert(session);
    }
    Ok(out)
}
