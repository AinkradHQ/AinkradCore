//! A connection suspended for a reason only a person can end. Today one: `needs_mode_2`, a
//! rotating token (Slack) that Core renewed but cannot store below `secrets.mode` 2, because the
//! gate refuses the new token's shape. The service has already rotated its refresh token, so the
//! old credential is spent: the connection stays out of use (`unhealthy`, no timer, no counted
//! failure, no `auth_suspected` test loop) until a credential is stored again (a sign-in), which
//! clears it.

use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::health::sys_audit;
use crate::store::secrets::Error;

pub const NEEDS_MODE_2: &str = "needs_mode_2";

/// Suspends workspace `ws`'s connection `id` as `needs_mode_2` (audited as
/// `connection.state_set`, which raises the `connection.health` event); whether it did. From any
/// state but `disabled` (an admin's switch stays): a cooling or `auth_suspected` connection whose
/// refresh token was spent is as stranded as an active one, and its pending auth test is dropped.
/// One already suspended is left as it is.
pub async fn needs_mode_2(pool: &SqlitePool, ws: i64, id: i64, now: &str) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let was: Option<(String, String)> = sqlx::query_as(
        "SELECT name, status FROM core_connections WHERE id = ? AND user_id = ? \
         AND status != 'disabled' AND coalesce(state_reason, '') != ?",
    )
    .bind(id)
    .bind(ws)
    .bind(NEEDS_MODE_2)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((name, from)) = was else {
        return Ok(false);
    };
    sqlx::query(
        "UPDATE core_connections SET status = 'unhealthy', state_reason = ?, state_until = NULL, \
         auth_pending = 0, auth_tries = 0, updated_at = ? WHERE id = ?",
    )
    .bind(NEEDS_MODE_2)
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let details = json!({"name": name, "from": from, "to": "unhealthy", "reason": NEEDS_MODE_2,
        "until": null, "source": "upstream", "class": null});
    sys_audit(&mut tx, "connection.state_set", id, details).await?;
    tx.commit().await?;
    Ok(true)
}
