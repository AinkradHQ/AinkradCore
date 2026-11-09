//! Publishing by path (E15.12): the file is in the run's worktree, on its runner. The MCP call
//! files a read (`request_read`); the runner answers with the content or why not
//! (`finish_read`), which is left in `incoming/read-<id>` under the artifacts dir. The MCP call
//! waits for that (`read_outcome`), then publishes it.
//!
//! `take_reads` (the runner's connection hands pending reads over, for runs whose lease that
//! runner holds) reads the lease table and comes with the run engine (S7).

use super::*;

/// A path the agent may name: relative, plain parts, no `.` or `..`, at most 1024 bytes.
pub fn worktree_path_ok(path: &str) -> bool {
    path.len() <= 1024
        && !path.starts_with('/')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

/// Where a read's content waits under `root`.
pub fn incoming_path(root: &Path, read: i64) -> PathBuf {
    root.join("incoming").join(format!("read-{read}"))
}

/// Files a read of `path` (at most `max_bytes`) from `run`'s worktree; its id.
pub async fn request_read(
    pool: &SqlitePool,
    run: RunId,
    path: &str,
    max_bytes: u64,
) -> Result<i64, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let id = sqlx::query_scalar(
        "INSERT INTO citadel_artifact_reads (run_id, path, max_bytes) VALUES (?, ?, ?) \
         RETURNING id",
    )
    .bind(run.0)
    .bind(path)
    .bind(max_bytes as i64)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// A read for a runner: (read, run, path, max bytes).
pub type FileRead = (i64, i64, String, u64);

/// Ends a read: `Ok` once its content is in `incoming_path`, or why it failed.
pub async fn finish_read(
    pool: &SqlitePool,
    read: i64,
    outcome: Result<(), String>,
) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let (state, error) = match outcome {
        Ok(()) => ("done", None),
        Err(why) => ("failed", Some(why)),
    };
    sqlx::query(
        "UPDATE citadel_artifact_reads SET state = ?, error = ? WHERE id = ? \
         AND state IN ('pending', 'sent')",
    )
    .bind(state)
    .bind(error)
    .bind(read)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// A read's state and error: `pending`, `sent`, `done` or `failed`.
pub async fn read_outcome(pool: &SqlitePool, read: i64) -> Result<(String, Option<String>), Error> {
    sqlx::query_as("SELECT state, error FROM citadel_artifact_reads WHERE id = ?")
        .bind(read)
        .fetch_one(pool)
        .await
}
