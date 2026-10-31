//! Non-secret Citadel bootstrap, run by the Core's module admin hook (`Module::admin`):
//! `ainkrad-core-citadel citadel seed <db> <file>`. Applying the same seed twice is idempotent.

use serde::Deserialize;
use sqlx::SqlitePool;

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

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// The seed text, parsed and checked. The error never quotes the text (a seed pointed at the
/// wrong file must not echo it).
fn parse(text: &str) -> Result<Seed, BoxErr> {
    let seed: Seed =
        toml::from_str(text).map_err(|e| format!("invalid Citadel seed: {}", e.message()))?;
    for company in &seed.companies {
        if !matches!(company.kind.as_str(), "own" | "client") || company.name.trim().is_empty() {
            return Err("seed company has an invalid name or kind".into());
        }
    }
    Ok(seed)
}

async fn insert(tx: &mut sqlx::SqliteConnection, seed: Seed) -> Result<usize, BoxErr> {
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
    Ok(changed)
}

/// Applies the seed in one transaction (all or nothing); returns how many rows it added.
pub async fn apply_seed(pool: &SqlitePool, text: &str) -> Result<usize, BoxErr> {
    let seed = parse(text)?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let changed = insert(&mut tx, seed).await?;
    tx.commit().await?;
    Ok(changed)
}

/// The text of a regular file of at most `MAX_SEED_BYTES`. A FIFO, a device (`/dev/zero`) or a
/// link to one is refused before it is opened, and the read is bounded whatever the size says.
pub fn read_seed(path: &std::path::Path) -> Result<String, BoxErr> {
    use std::io::Read;
    if !std::fs::metadata(path)?.is_file() {
        return Err("seed is not a regular file".into());
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("seed is not a regular file".into());
    }
    let mut text = String::new();
    file.take(MAX_SEED_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_SEED_BYTES {
        return Err(format!("seed file is over {MAX_SEED_BYTES} bytes").into());
    }
    Ok(text)
}

pub async fn apply_seed_file(pool: &SqlitePool, path: &std::path::Path) -> Result<usize, BoxErr> {
    apply_seed(pool, &read_seed(path)?).await
}

/// `ainkrad-core-citadel citadel seed <db> <file>`: the Core hook (`Module::admin`). The audit
/// row (the system, the count and the size) is written in the seed's own transaction.
pub async fn seed_command(pool: &SqlitePool, args: &[&str]) -> Result<String, String> {
    let [file] = args else {
        return Err("usage: citadel seed <db> <seed file>".to_owned());
    };
    let run = async {
        let text = read_seed(std::path::Path::new(file))?;
        let seed = parse(&text)?;
        let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
        let added = insert(&mut tx, seed).await?;
        let entry = ainkrad_core::audit::NewAuditEvent {
            actor: ainkrad_core::audit::AuditActor::System,
            action: "citadel.seed.applied".to_owned(),
            entity: None,
            details: serde_json::json!({"added": added, "bytes": text.len()}).to_string(),
        };
        ainkrad_core_server::store::audit::append(&mut tx, &entry).await?;
        tx.commit().await?;
        Ok::<_, BoxErr>(added)
    };
    let added = run.await.map_err(|e| e.to_string())?;
    Ok(format!("seed applied: {added} added"))
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

    #[test]
    fn the_seed_file_is_a_bounded_regular_file() {
        let dir = std::env::temp_dir().join(format!("citadel-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok.toml");
        std::fs::write(&ok, "[[companies]]\nname = \"A\"\n").unwrap();
        assert!(read_seed(&ok).is_ok());
        let big = dir.join("big.toml");
        std::fs::write(&big, "#".repeat(MAX_SEED_BYTES as usize + 1)).unwrap();
        assert!(read_seed(&big).is_err(), "one byte over");
        std::fs::write(&big, "#".repeat(MAX_SEED_BYTES as usize)).unwrap();
        assert!(read_seed(&big).is_ok(), "exactly the cap");
        // Devices, FIFOs and links to them are never read.
        assert!(read_seed(std::path::Path::new("/dev/zero")).is_err());
        let link = dir.join("zero.toml");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_seed(&link).is_err());
        let fifo = dir.join("fifo.toml");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        assert!(
            read_seed(&fifo).is_err(),
            "a FIFO is refused without blocking"
        );
        assert!(read_seed(&dir).is_err(), "a directory");
        // The parse error does not echo the file.
        let text = "password = \"hunter2-secret\"\n";
        let e = parse(text).unwrap_err().to_string();
        assert!(!e.contains("hunter2"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
