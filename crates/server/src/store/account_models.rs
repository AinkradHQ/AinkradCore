//! The model ids a provider listed for an account (E7-3, D-19): fetched through a runner's gateway
//! when a preset's key is added or checked (`agents::gateway::test`), kept so the app can offer
//! them. Ids only. The ids are the provider's text, so each is filtered here before it is kept.

use sqlx::sqlite::SqlitePool;

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
