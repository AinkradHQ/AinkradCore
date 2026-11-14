//! Idempotency of Code Mode writes (E6.3, plan P7): the same write sent again by the same session
//! inside the window returns the FIRST result and runs nothing, so a model that retries a whole
//! script never writes twice. The key is `key` when the call names one, else a hash of the
//! operation and its canonical arguments; either way only a hash is stored, never an argument.

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use super::CallState;

/// What the store says about a write about to run.
#[derive(Debug, PartialEq)]
pub enum Begin {
    /// Nobody did it: run it (the claim is made).
    Fresh,
    /// Done inside the window: the first result.
    Replay(Value),
    /// The same write is running now.
    Busy,
    /// A claim with no result that nothing is running: it timed out, or the Core restarted in
    /// the middle. Whether it took effect is not known, so it is not run again unasked.
    Unknown,
    /// The key was used for another operation.
    Conflict,
}

/// Arguments in one spelling whatever the order of their keys.
fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::from(k.as_str()), canonical(&m[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

/// The stored key of a write: a hash, so no argument is kept in clear.
pub fn key_hash(session: &str, op: &str, args: &Value, key: Option<&str>) -> String {
    let text = match key {
        Some(k) => format!("k\0{session}\0{k}"),
        None => format!("d\0{session}\0{op}\0{}", canonical(args)),
    };
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Keeps a claim's "running now" mark for as long as the call lives.
pub struct Live<'a>(&'a CallState, (String, String));

impl<'a> Live<'a> {
    pub fn new(state: &'a CallState, session: &str, hash: &str) -> Self {
        let id = (session.to_owned(), hash.to_owned());
        state
            .idem
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone());
        Self(state, id)
    }
}

impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.0
            .idem
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.1);
    }
}

/// Claims `hash` for `op`, or says why not. Claims older than `window` seconds are gone first.
/// `repeat` takes the claim over whatever is there (an identical write the caller means twice).
///
/// # Errors
///
/// A store failure.
pub async fn begin(
    pool: &SqlitePool,
    state: &CallState,
    (session, hash, op): (&str, &str, &str),
    (now, window): (i64, i64),
    repeat: bool,
) -> Result<Begin, sqlx::Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    sqlx::query("DELETE FROM core_code_mode_idem WHERE at < ?")
        .bind(now - window)
        .execute(&mut *tx)
        .await?;
    let sql = if repeat {
        "INSERT OR REPLACE INTO core_code_mode_idem (user_id, session, key_hash, op, result, at) \
         VALUES ((SELECT user_id FROM core_agent_sessions WHERE id = ?1), ?1, ?2, ?3, NULL, ?4)"
    } else {
        "INSERT OR IGNORE INTO core_code_mode_idem (user_id, session, key_hash, op, result, at) \
         VALUES ((SELECT user_id FROM core_agent_sessions WHERE id = ?1), ?1, ?2, ?3, NULL, ?4)"
    };
    let claimed = sqlx::query(sql)
        .bind(session)
        .bind(hash)
        .bind(op)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if claimed == 1 {
        tx.commit().await?;
        return Ok(Begin::Fresh);
    }
    let (was, result): (String, Option<String>) = sqlx::query_as(
        "SELECT op, result FROM core_code_mode_idem WHERE session = ? AND key_hash = ?",
    )
    .bind(session)
    .bind(hash)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(if was != op {
        Begin::Conflict
    } else if let Some(r) = result {
        Begin::Replay(serde_json::from_str(&r).unwrap_or(Value::Null))
    } else if state
        .idem
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&(session.to_owned(), hash.to_owned()))
    {
        Begin::Busy
    } else {
        Begin::Unknown
    })
}

/// Records the first result of the claim.
///
/// # Errors
///
/// A store failure.
pub async fn finish(
    pool: &SqlitePool,
    session: &str,
    hash: &str,
    result: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE core_code_mode_idem SET result = ? WHERE session = ? AND key_hash = ?")
        .bind(result.to_string())
        .bind(session)
        .bind(hash)
        .execute(pool)
        .await
        .map(drop)
}

/// Drops a claim whose write did not happen (refused, denied, failed before any effect), so the
/// same call may be tried again.
pub async fn forget(pool: &SqlitePool, session: &str, hash: &str) {
    let _ = sqlx::query("DELETE FROM core_code_mode_idem WHERE session = ? AND key_hash = ?")
        .bind(session)
        .bind(hash)
        .execute(pool)
        .await;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_key_ignores_argument_order_and_is_never_the_arguments() {
        let a = key_hash(
            "as_1",
            "op",
            &json!({"a": 1, "b": {"x": [1, 2], "y": 2}}),
            None,
        );
        let b = key_hash(
            "as_1",
            "op",
            &json!({"b": {"y": 2, "x": [1, 2]}, "a": 1}),
            None,
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(
            a,
            key_hash(
                "as_2",
                "op",
                &json!({"a": 1, "b": {"x": [1, 2], "y": 2}}),
                None
            )
        );
        assert_ne!(a, key_hash("as_1", "op", &json!({"a": 2}), None));
        // A named key replaces the arguments.
        let k1 = key_hash("as_1", "op", &json!({"a": 1}), Some("k"));
        assert_eq!(k1, key_hash("as_1", "op", &json!({"a": 9}), Some("k")));
        assert_ne!(k1, a);
    }
}
