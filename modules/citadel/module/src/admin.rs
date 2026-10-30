//! Non-secret Citadel bootstrap. The Core's admin command can call this module hook when modules
//! are wired into the CLI; applying the same seed twice is intentionally idempotent.

use serde::Deserialize;
use sqlx::{Error, SqlitePool};

#[derive(Debug, Deserialize)]
pub struct Seed {
    #[serde(default)]
    pub companies: Vec<CompanySeed>,
}

#[derive(Debug, Deserialize)]
pub struct CompanySeed {
    pub name: String,
    #[serde(default = "own")]
    pub kind: String,
}

fn own() -> String {
    "own".to_owned()
}

pub async fn apply_seed(
    pool: &SqlitePool,
    text: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let seed: Seed = toml::from_str(text).map_err(|e| format!("invalid Citadel seed: {e}"))?;
    let mut changed = 0;
    for company in seed.companies {
        if !matches!(company.kind.as_str(), "own" | "client") || company.name.trim().is_empty() {
            return Err("seed company has an invalid name or kind".into());
        }
        let result = sqlx::query(
            "INSERT INTO citadel_companies (name, kind) SELECT ?1, ?2 \
             WHERE NOT EXISTS (SELECT 1 FROM citadel_companies WHERE name = ?1)",
        )
        .bind(company.name.trim())
        .bind(company.kind)
        .execute(pool)
        .await?;
        changed += result.rows_affected() as usize;
    }
    Ok(changed)
}

pub async fn apply_seed_file(
    pool: &SqlitePool,
    path: &std::path::Path,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let text = tokio::fs::read_to_string(path).await?;
    apply_seed(pool, &text).await
}

pub fn database_error(e: Error) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_seed_is_idempotent_and_refuses_a_bad_kind() {
        let db = crate::testing::db().await;
        let seed = "[[companies]]\nname = \"Ainkrad\"\nkind = \"own\"\n";
        assert_eq!(apply_seed(&db.pool, seed).await.unwrap(), 1);
        assert_eq!(
            apply_seed(&db.pool, seed).await.unwrap(),
            0,
            "a second apply changes nothing"
        );
        let bad = "[[companies]]\nname = \"X\"\nkind = \"evil\"\n";
        assert!(apply_seed(&db.pool, bad).await.is_err());
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_companies")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }
}
