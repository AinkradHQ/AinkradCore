//! The Decisions cache (§2.3, §2.4): `core_decision_cache` holds scores under a key that is a hash
//! of everything the answer depends on, so a row holds no text. The TTL is per consumer
//! (`decisions.<consumer>.ttl_secs`); expired rows are deleted with every write, so no scheduler
//! pass is needed.

use std::collections::{BTreeMap, HashMap};

use sqlx::sqlite::SqlitePool;

use crate::scheduler::iso_of_unix;
use crate::store;

/// A cache key.
pub type Key = [u8; 32];

fn field(h: &mut blake3::Hasher, bytes: &[u8]) {
    // Length-prefixed, so ("ab", "c") and ("a", "bc") hash apart.
    h.update(&(bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn map(h: &mut blake3::Hasher, m: &BTreeMap<String, String>) {
    h.update(&(m.len() as u64).to_be_bytes());
    for (k, v) in m {
        field(h, k.as_bytes());
        field(h, v.as_bytes());
    }
}

/// The hash of the shared (already redacted) context: one per request, part of every key.
pub fn context_hash(context: &BTreeMap<String, String>) -> Key {
    let mut h = blake3::Hasher::new();
    map(&mut h, context);
    *h.finalize().as_bytes()
}

/// The key of one question: consumer, provider, options, redacted text, redacted facts and the
/// context hash, as blake3 (spec §2.3; `core_decision_cache.key` is a 32-byte blob).
pub fn key(
    consumer: &str,
    provider: &str,
    options: &[String],
    text: &str,
    facts: &BTreeMap<String, String>,
    context: &Key,
) -> Key {
    let mut h = blake3::Hasher::new();
    field(&mut h, consumer.as_bytes());
    field(&mut h, provider.as_bytes());
    h.update(&(options.len() as u64).to_be_bytes());
    for o in options {
        field(&mut h, o.as_bytes());
    }
    field(&mut h, text.as_bytes());
    map(&mut h, facts);
    h.update(context);
    *h.finalize().as_bytes()
}

/// The live rows among `keys`, as `(option, score)` pairs in the order they were stored.
pub async fn get_many(
    pool: &SqlitePool,
    keys: &[Key],
    now: &str,
) -> Result<HashMap<Key, Vec<(String, f32)>>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let mut out = HashMap::new();
    for key in keys {
        let row: Option<String> = sqlx::query_scalar(
            "SELECT scores FROM core_decision_cache WHERE key = ? AND expires_at > ?",
        )
        .bind(&key[..])
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(scores) = row.and_then(|s| serde_json::from_str(&s).ok()) {
            out.insert(*key, scores);
        }
    }
    Ok(out)
}

/// Stores `rows` for `ttl_secs` from `now_unix`, and deletes what has expired.
pub async fn put_many(
    pool: &SqlitePool,
    consumer: &str,
    provider: &str,
    rows: &[(Key, Vec<(String, f32)>)],
    now_unix: i64,
    ttl_secs: i64,
) -> Result<(), sqlx::Error> {
    let (now, until) = (iso_of_unix(now_unix), iso_of_unix(now_unix + ttl_secs));
    let mut tx = store::begin_write(pool).await?;
    sqlx::query("DELETE FROM core_decision_cache WHERE expires_at <= ?")
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    for (key, scores) in rows {
        sqlx::query(
            "INSERT OR REPLACE INTO core_decision_cache \
             (key, consumer, scores, provider, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&key[..])
        .bind(consumer)
        .bind(serde_json::to_string(scores).unwrap_or_else(|_| "[]".to_owned()))
        .bind(provider)
        .bind(&now)
        .bind(&until)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(v: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("cwd".to_owned(), v.to_owned())])
    }

    #[test]
    fn a_key_depends_on_every_part_and_on_where_a_field_ends() {
        let opts = ["light".to_owned(), "heavy".to_owned()];
        let ctx = context_hash(&BTreeMap::new());
        let base = key(
            "heavy_job",
            "gemini-decision-1",
            &opts,
            "cargo build",
            &facts("$WS"),
            &ctx,
        );
        assert_eq!(
            base,
            key(
                "heavy_job",
                "gemini-decision-1",
                &opts,
                "cargo build",
                &facts("$WS"),
                &ctx
            )
        );
        let others = [
            key(
                "brain_sort",
                "gemini-decision-1",
                &opts,
                "cargo build",
                &facts("$WS"),
                &ctx,
            ),
            key(
                "heavy_job",
                "other",
                &opts,
                "cargo build",
                &facts("$WS"),
                &ctx,
            ),
            key(
                "heavy_job",
                "gemini-decision-1",
                &opts[..1],
                "cargo build",
                &facts("$WS"),
                &ctx,
            ),
            key(
                "heavy_job",
                "gemini-decision-1",
                &opts,
                "cargo test",
                &facts("$WS"),
                &ctx,
            ),
            key(
                "heavy_job",
                "gemini-decision-1",
                &opts,
                "cargo build",
                &facts("~"),
                &ctx,
            ),
            key(
                "heavy_job",
                "gemini-decision-1",
                &opts,
                "cargo build",
                &facts("$WS"),
                &context_hash(&facts("x")),
            ),
            // The boundary between fields moves the bytes, not the key's inputs.
            key(
                "heavy_jo",
                "bgemini-decision-1",
                &opts,
                "cargo build",
                &facts("$WS"),
                &ctx,
            ),
        ];
        for (i, k) in others.iter().enumerate() {
            assert_ne!(*k, base, "{i}");
        }
    }
}
