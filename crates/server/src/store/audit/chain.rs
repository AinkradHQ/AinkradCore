//! The audit hash chain (E1-10.1) and its JSONL export (E1-10.3).
//!
//! A row's `hash` is the SHA-256 of its canonical form: the compact JSON array
//! `[seq, at, user_id, actor_kind, actor_id, action, entity_kind, entity_id, details, prev_hash]`,
//! where `details` is the stored text (never re-serialised, so key order cannot drift) and
//! `prev_hash` the previous row's hash in lowercase hex (64 zeros for the first chained row).
//!
//! `verify` walks the rows in seq order and names the first bad seq: a missing seq, a `prev_hash`
//! that is not the row before's, a `hash` that is not its fields', or an unchained row after the
//! chain began. Rows from before the chain (migration `0002`) have no hash and are only counted.
//! A deleted newest row breaks no link; on the database `verify_db` also checks the head against
//! `sqlite_sequence`, but a deleted tail with that counter reset as well goes unnoticed until the
//! chain head is anchored off-box (E1-10.4).

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnection, SqlitePool};

/// One audit row as chained and exported: one JSON object per line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct ChainRow {
    pub seq: i64,
    pub at: String,
    pub user_id: i64,
    pub actor_kind: String,
    pub actor_id: Option<i64>,
    pub action: String,
    pub entity_kind: Option<String>,
    pub entity_id: Option<i64>,
    /// The stored JSON text, as it was hashed.
    pub details: String,
    /// Lowercase hex; absent on rows from before the chain.
    pub prev_hash: Option<String>,
    pub hash: Option<String>,
}

/// The `prev_hash` of the first chained row.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash of `row` chained after `prev` (hex), as bytes.
pub fn digest(row: &ChainRow, prev: &str) -> [u8; 32] {
    let canonical = json!([
        row.seq,
        row.at,
        row.user_id,
        row.actor_kind,
        row.actor_id,
        row.action,
        row.entity_kind,
        row.entity_id,
        row.details,
        prev
    ]);
    Sha256::digest(canonical.to_string().as_bytes()).into()
}

/// What a whole, unbroken chain looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub rows: u64,
    /// Rows from before the chain began.
    pub unchained: u64,
    /// The newest row's seq and hash.
    pub head: Option<(i64, String)>,
}

/// The first bad row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broken {
    pub seq: i64,
    pub why: String,
}

impl std::fmt::Display for Broken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit chain broken at seq {}: {}", self.seq, self.why)
    }
}

impl std::error::Error for Broken {}

/// Checks rows fed in seq order.
#[derive(Debug, Default)]
pub struct Verifier {
    done: Option<Verified>,
}

impl Verifier {
    pub fn push(&mut self, row: &ChainRow) -> Result<(), Broken> {
        let bad = |why: String| Broken { seq: row.seq, why };
        let state = self.done.get_or_insert(Verified {
            rows: 0,
            unchained: 0,
            head: None,
        });
        let want = state.head.as_ref().map_or(1, |h| h.0 + 1);
        if row.seq != want {
            return Err(bad(format!("seq {want} is missing")));
        }
        let chained = state.rows > state.unchained;
        let Some(hash) = &row.hash else {
            if chained {
                return Err(bad("unchained row after the chain began".to_owned()));
            }
            state.rows += 1;
            state.unchained += 1;
            state.head = Some((row.seq, String::new()));
            return Ok(());
        };
        let prev = match &state.head {
            Some((_, h)) if chained => h.as_str(),
            _ => GENESIS,
        };
        if row.prev_hash.as_deref() != Some(prev) {
            return Err(bad(
                "prev_hash is not the hash of the row before (a row was changed or removed)"
                    .to_owned(),
            ));
        }
        if *hash != hex(&digest(row, prev)) {
            return Err(bad(
                "hash does not match the row (the row was changed)".to_owned()
            ));
        }
        state.rows += 1;
        state.head = Some((row.seq, hash.clone()));
        Ok(())
    }

    pub fn finish(self) -> Verified {
        self.done.unwrap_or(Verified {
            rows: 0,
            unchained: 0,
            head: None,
        })
    }
}

/// Every audit row, oldest first, `PAGE` at a time. Pass a transaction's connection, so every
/// page comes from one snapshot while the server keeps appending.
async fn each_row(
    conn: &mut SqliteConnection,
    mut f: impl FnMut(ChainRow) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    const PAGE: i64 = 1000;
    let mut after = 0;
    loop {
        let rows: Vec<ChainRow> = sqlx::query_as(
            "SELECT seq, at, user_id, actor_kind, actor_id, action, entity_kind, entity_id, \
             details, iif(prev_hash IS NULL, NULL, lower(hex(prev_hash))) AS prev_hash, \
             iif(hash IS NULL, NULL, lower(hex(hash))) AS hash \
             FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?",
        )
        .bind(after)
        .bind(PAGE)
        .fetch_all(&mut *conn)
        .await?;
        let last = rows.len() < PAGE as usize;
        for row in rows {
            after = row.seq;
            f(row)?;
        }
        if last {
            return Ok(());
        }
    }
}

/// Verifies the database's chain, in one read snapshot (a live server may be appending). The
/// outer error is a database failure, the inner the first bad row.
pub async fn verify_db(pool: &SqlitePool) -> Result<Result<Verified, Broken>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut v = Verifier::default();
    let mut broken = None;
    let walked = each_row(&mut tx, |row| {
        if broken.is_none()
            && let Err(b) = v.push(&row)
        {
            broken = Some(b);
        }
        Ok(())
    })
    .await
    .map_err(|e| sqlx::Error::Protocol(e.to_string()));
    walked?;
    if let Some(b) = broken {
        return Ok(Err(b));
    }
    let done = v.finish();
    let handed_out: i64 = sqlx::query_scalar(
        "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'), 0)",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let head = done.head.as_ref().map_or(0, |h| h.0);
    if handed_out > head {
        return Ok(Err(Broken {
            seq: head + 1,
            why: format!("rows {} to {handed_out} are missing", head + 1),
        }));
    }
    Ok(Ok(done))
}

/// Writes every audit row as one JSON line, from one read snapshot; returns how many.
pub async fn export(
    pool: &SqlitePool,
    out: &mut impl Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut tx = pool.begin().await?;
    let mut n = 0;
    each_row(&mut tx, |row| {
        serde_json::to_writer(&mut *out, &row)?;
        out.write_all(b"\n")?;
        n += 1;
        Ok(())
    })
    .await?;
    out.flush()?;
    Ok(n)
}

/// Verifies an export on its own, without the database.
pub fn verify_export(input: impl BufRead) -> Result<Verified, Box<dyn std::error::Error>> {
    let mut v = Verifier::default();
    for (n, line) in input.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: ChainRow =
            serde_json::from_str(&line).map_err(|e| format!("line {}: {e}", n + 1))?;
        v.push(&row)?;
    }
    Ok(v.finish())
}

#[cfg(test)]
mod tests;
