//! The event a change of a connection's health raises (C5), written in the transaction of the
//! change, beside its `connection.state_set` audit row: `connection.health {connection, user,
//! kind, state, reason}`. Ids and fixed codes only: never the name or label (text a person typed),
//! an identity, a credential or an upstream's words. `state` is the new health state (`active`,
//! `cooling`, `limited`, `unhealthy`, `disabled`); `reason` a fixed code (`rate_limited`, `quota`,
//! `upstream_errors`, `auth_suspected`, `auth_failed`, `recovered`, `auth_cleared`).

use serde_json::{Value, json};
use sqlx::SqliteConnection;

use crate::store::events;

/// Appends the `connection.health` event for a `connection.state_set` row's `details`
/// (`to` and `reason`). A row that says neither raises none.
pub(crate) async fn raised(
    conn: &mut SqliteConnection,
    id: i64,
    details: &Value,
) -> Result<(), sqlx::Error> {
    let (Some(state), Some(reason)) = (details["to"].as_str(), details["reason"].as_str()) else {
        return Ok(());
    };
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT user_id, kind FROM core_connections WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((user, kind)) = row else {
        return Ok(());
    };
    let payload = json!({"connection": id, "user": user, "kind": kind, "state": state,
                         "reason": reason});
    events::append(conn, "connection.health", &payload)
        .await
        .map(drop)
}
