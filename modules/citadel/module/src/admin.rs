//! Non-secret Citadel bootstrap, run by the Core's module admin hook (`Module::admin`):
//! `ainkrad-core-citadel citadel seed <db> <file>`. Applying the same seed twice is idempotent.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::SqlitePool;
use utoipa::ToSchema;

/// The seed carries names and kinds only. An unknown field (a `password`, a `token`) is refused,
/// so no seed can smuggle a credential in; credentials go through the Core's secrets broker.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    #[serde(default)]
    #[schema(max_items = 500)]
    pub companies: Vec<CompanySeed>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CompanySeed {
    #[schema(min_length = 1, max_length = 200)]
    pub name: String,
    #[serde(default)]
    pub kind: SeedKind,
}

/// The kind of a seeded company.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeedKind {
    #[default]
    Own,
    Client,
}

impl SeedKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Client => "client",
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The most a seed file may be.
const MAX_SEED_BYTES: u64 = 64 * 1024;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// The seed text, parsed and checked. The error never quotes the text (a seed pointed at the
/// wrong file must not echo it).
fn parse(text: &str) -> Result<Seed, BoxErr> {
    let seed: Seed =
        toml::from_str(text).map_err(|e| format!("invalid Citadel seed: {}", e.message()))?;
    check(&seed)?;
    Ok(seed)
}

/// The most companies one seed may name.
pub const MAX_COMPANIES: usize = 500;

/// The seed's rows are well formed (shared by the file and the endpoint).
pub(crate) fn check(seed: &Seed) -> Result<(), BoxErr> {
    if seed.companies.len() > MAX_COMPANIES {
        return Err(format!("seed names more than {MAX_COMPANIES} companies").into());
    }
    for company in &seed.companies {
        if company.name.trim().is_empty() || company.name.len() > 200 {
            return Err("seed company has an invalid name or kind".into());
        }
    }
    Ok(())
}

/// Rows added, and companies named in the seed that already exist under another kind (left as
/// they are, and counted so the operator is told).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub added: usize,
    pub kind_mismatch: usize,
}

/// Adds the missing companies and appends `company.created` for each, as the normal path does
/// (`add_company_with`), so live clients see them.
async fn insert(
    tx: &mut sqlx::SqliteConnection,
    seed: Seed,
    actor: ainkrad_core::audit::AuditActor,
) -> Result<Applied, BoxErr> {
    let mut applied = Applied::default();
    for company in seed.companies {
        let name = company.name.trim();
        let kind = company.kind.as_str();
        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO citadel_companies (name, kind) SELECT ?1, ?2 \
             WHERE NOT EXISTS (SELECT 1 FROM citadel_companies WHERE name = ?1) RETURNING id",
        )
        .bind(name)
        .bind(kind)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(id) = id {
            applied.added += 1;
            crate::store::org::chart::append_org_event(
                tx,
                crate::domain::org::CompanyId(id),
                actor,
                "company.created",
                ("company", id),
                serde_json::json!({"name": name, "kind": kind}),
            )
            .await?;
        } else {
            let existing: String =
                sqlx::query_scalar("SELECT kind FROM citadel_companies WHERE name = ?")
                    .bind(name)
                    .fetch_one(&mut *tx)
                    .await?;
            applied.kind_mismatch += usize::from(existing != kind);
        }
    }
    Ok(applied)
}

/// Tests only: applies the seed with no audit row. Nothing outside this file may apply a seed
/// except through `apply_audited`.
#[cfg(test)]
async fn apply_seed(pool: &SqlitePool, text: &str) -> Result<usize, BoxErr> {
    let seed = parse(text)?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let applied = insert(&mut tx, seed, ainkrad_core::audit::AuditActor::System).await?;
    tx.commit().await?;
    Ok(applied.added)
}

/// The text of a regular file of at most `MAX_SEED_BYTES`. A FIFO, a device (`/dev/zero`) or a
/// link to one is refused before it is opened, and the read is bounded whatever the size says.
#[cfg(test)]
fn read_seed(path: &std::path::Path) -> Result<String, BoxErr> {
    read_seed_owned(path).map(|(text, _)| text)
}

/// `read_seed` and the uid that owns the file (the audit row records it).
fn read_seed_owned(path: &std::path::Path) -> Result<(String, u32), BoxErr> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if !std::fs::metadata(path)?.is_file() {
        return Err("seed is not a regular file".into());
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("seed is not a regular file".into());
    }
    let uid = file.metadata()?.uid();
    let mut text = String::new();
    file.take(MAX_SEED_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_SEED_BYTES {
        return Err(format!("seed file is over {MAX_SEED_BYTES} bytes").into());
    }
    Ok((text, uid))
}

/// Applies a checked seed in one transaction with its audit row (`citadel.seed.applied`): the
/// counts plus `extra` (where it came from), never a name or any text of the seed.
pub(crate) async fn apply_audited(
    pool: &SqlitePool,
    seed: Seed,
    actor: ainkrad_core::audit::AuditActor,
    extra: serde_json::Value,
) -> Result<Applied, BoxErr> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let applied = insert(&mut tx, seed, actor).await?;
    let mut details = extra;
    details["added"] = applied.added.into();
    details["kind_mismatch"] = applied.kind_mismatch.into();
    let entry = ainkrad_core::audit::NewAuditEvent {
        actor,
        action: "citadel.seed.applied".to_owned(),
        entity: None,
        details: details.to_string(),
    };
    ainkrad_core_server::store::audit::append(&mut tx, &entry).await?;
    tx.commit().await?;
    Ok(applied)
}

/// `ainkrad-core-citadel citadel seed <db> <file>`: the Core hook (`Module::admin`). The audit
/// row is written in the seed's own transaction and holds counts, the size, the SHA-256 of the
/// file and the uid that owns it: never a name or any of the file's text.
pub async fn seed_command(pool: &SqlitePool, args: &[&str]) -> Result<String, String> {
    let [file] = args else {
        return Err("usage: citadel seed <db> <seed file>".to_owned());
    };
    let run = async {
        let (text, uid) = read_seed_owned(std::path::Path::new(file))?;
        let seed = parse(&text)?;
        let sha256 = hex(&sha2::Sha256::digest(text.as_bytes()));
        apply_audited(
            pool,
            seed,
            ainkrad_core::audit::AuditActor::System,
            serde_json::json!({"bytes": text.len(), "sha256": sha256, "file_uid": uid}),
        )
        .await
    };
    let applied = run.await.map_err(|e| e.to_string())?;
    let note = match applied.kind_mismatch {
        0 => String::new(),
        n => format!(", {n} left as they are (a different kind already exists)"),
    };
    Ok(format!("seed applied: {} added{note}", applied.added))
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

    #[tokio::test]
    async fn the_seed_audit_row_holds_a_hash_and_a_uid_and_no_content() {
        use std::os::unix::fs::MetadataExt;
        let db = crate::testing::db().await;
        let dir = std::env::temp_dir().join(format!("citadel-seed-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("seed.toml");
        let text = "[[companies]]\nname = \"Distinctive Name Ltd\"\nkind = \"own\"\n";
        std::fs::write(&file, text).unwrap();
        seed_command(&db.pool, &[file.to_str().unwrap()])
            .await
            .unwrap();
        // The same name under another kind is reported, not silently skipped.
        let other = dir.join("other.toml");
        std::fs::write(
            &other,
            "[[companies]]\nname = \"Distinctive Name Ltd\"\nkind = \"client\"\n",
        )
        .unwrap();
        let said = seed_command(&db.pool, &[other.to_str().unwrap()])
            .await
            .unwrap();
        assert!(said.contains("1 left as they are"), "{said}");
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT details FROM audit_events WHERE action = 'citadel.seed.applied' ORDER BY seq",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        let first: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
        assert_eq!(first["sha256"], hex(&sha2::Sha256::digest(text.as_bytes())));
        assert_eq!(first["file_uid"], std::fs::metadata(&file).unwrap().uid());
        assert_eq!(first["added"], 1);
        let second: serde_json::Value = serde_json::from_str(&rows[1]).unwrap();
        assert_eq!(second["kind_mismatch"], 1);
        for row in &rows {
            assert!(!row.contains("Distinctive"), "no content in the row: {row}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
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
