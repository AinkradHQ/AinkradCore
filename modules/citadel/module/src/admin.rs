//! Non-secret Citadel bootstrap, run by the Core's module admin hook (`Module::admin`):
//! `ainkrad-core-citadel citadel seed <db> <file>`. Applying the same seed twice is idempotent.

use serde::Deserialize;
use sqlx::{Error, SqlitePool};

/// The seed carries names and kinds only. An unknown field (a `password`, a `token`) is refused,
/// so no seed can smuggle a credential in; credentials go through the Core's secrets broker.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    #[serde(default)]
    pub companies: Vec<CompanySeed>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanySeed {
    pub name: String,
    #[serde(default = "own")]
    pub kind: String,
}

fn own() -> String {
    "own".to_owned()
}

/// The most a seed file may be.
const MAX_SEED_BYTES: u64 = 64 * 1024;

/// Applies the seed in one transaction (all or nothing); returns how many rows it added.
pub async fn apply_seed(
    pool: &SqlitePool,
    text: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let seed: Seed = toml::from_str(text).map_err(|e| format!("invalid Citadel seed: {e}"))?;
    for company in &seed.companies {
        if !matches!(company.kind.as_str(), "own" | "client") || company.name.trim().is_empty() {
            return Err("seed company has an invalid name or kind".into());
        }
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let mut changed = 0;
    for company in seed.companies {
        let result = sqlx::query(
            "INSERT INTO citadel_companies (name, kind) SELECT ?1, ?2 \
             WHERE NOT EXISTS (SELECT 1 FROM citadel_companies WHERE name = ?1)",
        )
        .bind(company.name.trim())
        .bind(company.kind)
        .execute(&mut *tx)
        .await?;
        changed += result.rows_affected() as usize;
    }
    tx.commit().await?;
    Ok(changed)
}

pub async fn apply_seed_file(
    pool: &SqlitePool,
    path: &std::path::Path,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    if tokio::fs::metadata(path).await?.len() > MAX_SEED_BYTES {
        return Err(format!("seed file is over {MAX_SEED_BYTES} bytes").into());
    }
    let text = tokio::fs::read_to_string(path).await?;
    apply_seed(pool, &text).await
}

/// `ainkrad-core-citadel citadel seed <db> <file>`: the Core hook (`Module::admin`). Audited as
/// the system, with the count only.
pub async fn seed_command(pool: &SqlitePool, args: &[&str]) -> Result<String, String> {
    let [file] = args else {
        return Err("usage: citadel seed <db> <seed file>".to_owned());
    };
    let added = apply_seed_file(pool, std::path::Path::new(file))
        .await
        .map_err(|e| e.to_string())?;
    let entry = ainkrad_core::audit::NewAuditEvent {
        actor: ainkrad_core::audit::AuditActor::System,
        action: "citadel.seed.applied".to_owned(),
        entity: None,
        details: serde_json::json!({"added": added}).to_string(),
    };
    ainkrad_core_server::store::audit::append_one(pool, &entry)
        .await
        .map_err(|e| e.to_string())?;
    Ok(format!("seed applied: {added} added"))
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
        for smuggled in [
            "[[companies]]\nname = \"X\"\npassword = \"hunter2\"\n",
            "token = \"abc\"\n[[companies]]\nname = \"X\"\n",
        ] {
            assert!(
                apply_seed(&db.pool, smuggled).await.is_err(),
                "no credentials in a seed"
            );
        }
        // One bad row rolls the whole seed back.
        let mixed =
            "[[companies]]\nname = \"Good\"\n[[companies]]\nname = \"Bad\"\nkind = \"evil\"\n";
        assert!(apply_seed(&db.pool, mixed).await.is_err());
        let bad = "[[companies]]\nname = \"X\"\nkind = \"evil\"\n";
        assert!(apply_seed(&db.pool, bad).await.is_err());
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_companies")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }
}
