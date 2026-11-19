//! The model ids a provider listed for an account (E7-3, D-19): fetched through a runner's gateway
//! when a preset's key is added or checked (`agents::gateway::test`), kept so the app can offer
//! them. Ids only. The ids are the provider's text, so each is filtered here before it is kept.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::secrets::Error;

/// The most ids kept for one account.
pub const MAX_KEPT: usize = 512;

/// The ids of `listed` that may be kept: a plain model id once, not a provider-side routing
/// suffix (`providers::rules::model_problem`), at most [`MAX_KEPT`].
pub fn clean(listed: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in listed {
        if out.len() >= MAX_KEPT {
            break;
        }
        if super::prices::valid_model(&id)
            && super::provider_rules::model_problem(&id).is_none()
            && !out.contains(&id)
        {
            out.push(id);
        }
    }
    out
}

/// Replaces account `id`'s list (an empty list is not kept: a failed read never wipes a good one).
pub async fn save(
    pool: &SqlitePool,
    id: i64,
    listed: Vec<String>,
    now: &str,
) -> Result<usize, sqlx::Error> {
    let ids = clean(listed);
    if ids.is_empty() {
        return Ok(0);
    }
    sqlx::query(
        "INSERT INTO core_account_models (account_id, models, fetched_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(account_id) DO UPDATE SET models = ?2, fetched_at = ?3",
    )
    .bind(id)
    .bind(serde_json::json!(ids).to_string())
    .bind(now)
    .execute(pool)
    .await?;
    Ok(ids.len())
}

/// Account `id`'s kept list and when it was read; empty when none was.
pub async fn get(pool: &SqlitePool, id: i64) -> Result<(Vec<String>, Option<String>), sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT models, fetched_at FROM core_account_models WHERE account_id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map_or((Vec::new(), None), |(m, at)| {
        (serde_json::from_str(&m).unwrap_or_default(), Some(at))
    }))
}

/// The models switched off for account `id` (the rest are allowed).
pub async fn denied(pool: &SqlitePool, id: i64) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT model FROM core_account_model_denied WHERE account_id = ? ORDER BY model",
    )
    .bind(id)
    .fetch_all(pool)
    .await
}

/// Allows or switches off `model` for account `id` (`account.model_allowed_set`, no value in it).
pub async fn set_allowed(
    pool: &SqlitePool,
    id: i64,
    model: &str,
    allowed: bool,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(), Error> {
    if !super::prices::valid_model(model) {
        return Err(Error::Refused {
            code: "bad_request",
            message: "a model id is 1 to 80 of [A-Za-z0-9._:/-]".to_owned(),
        });
    }
    let mut tx = super::begin_write(pool).await?;
    let a = super::accounts::find(&mut tx, id).await?;
    if allowed {
        sqlx::query("DELETE FROM core_account_model_denied WHERE account_id = ? AND model = ?")
            .bind(id)
            .bind(model)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query(
            "INSERT OR IGNORE INTO core_account_model_denied (account_id, model, denied_at) \
             VALUES (?, ?, ?)",
        )
        .bind(id)
        .bind(model)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    super::accounts::audit(
        &mut tx,
        actor,
        "account.model_allowed_set",
        id,
        json!({"label": a.label, "model": model, "allowed": allowed, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Whether account `id` has `model` switched off.
pub async fn is_denied(
    conn: &mut SqliteConnection,
    id: i64,
    model: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM core_account_model_denied WHERE account_id = ? AND model = ?)",
    )
    .bind(id)
    .bind(model)
    .fetch_one(conn)
    .await
}

/// Whether `pool` has members and every one of them has `model` switched off: no account of the
/// pool may serve it. A pool with no member is not refused here (the allocator skips it).
pub async fn pool_refuses(
    conn: &mut SqliteConnection,
    pool: i64,
    model: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) > 0 AND COUNT(*) = SUM(EXISTS(SELECT 1 FROM core_account_model_denied d \
         WHERE d.account_id = m.account_id AND d.model = ?)) \
         FROM core_pool_members m WHERE m.pool_id = ?",
    )
    .bind(model)
    .bind(pool)
    .fetch_one(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::clean;

    #[test]
    fn only_plain_unique_ids_are_kept_and_the_list_is_bounded() {
        let listed = ["a/b", "a/b", "m:online", "bad id", "", "ok-1.5", "x\n"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(clean(listed), ["a/b", "ok-1.5"]);
        let many: Vec<String> = (0..1000).map(|i| format!("m{i}")).collect();
        assert_eq!(clean(many).len(), super::MAX_KEPT);
    }
}
