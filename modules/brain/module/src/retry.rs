//! When a room whose distil failed is tried again: a short, growing wait counted from its latest
//! failure, by how many distils failed in a row (since its last finished one). One rule for the
//! automatic triggers (`auto_distil::queue`) and for what the Learn screen says (`learning`).

use ainkrad_core_server::scheduler::unix_secs;
use sqlx::SqliteConnection;

/// The wait after the 1st, 2nd, 3rd, 4th and every later failure in a row.
pub(crate) const FAIL_BACKOFF_SECS: [i64; 5] = [2 * 60, 5 * 60, 15 * 60, 3600, 6 * 3600];

/// The wait after `failures` failures in a row (at least one).
pub(crate) fn backoff_secs(failures: i64) -> i64 {
    let i = usize::try_from(failures.max(1) - 1).unwrap_or(usize::MAX);
    FAIL_BACKOFF_SECS[i.min(FAIL_BACKOFF_SECS.len() - 1)]
}

/// The unix time `room` may be distilled again, when its latest distils failed; `None` when the
/// latest one did not fail (or none ran).
pub(crate) async fn retry_at(
    conn: &mut SqliteConnection,
    room: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let (n, last): (i64, Option<String>) = sqlx::query_as(
        "SELECT count(*), max(updated_at) FROM brain_distils WHERE room = ?1 AND state = 'failed' \
         AND updated_at > coalesce((SELECT max(updated_at) FROM brain_distils WHERE room = ?1 AND state = 'done'), '')",
    )
    .bind(room)
    .fetch_one(conn)
    .await?;
    Ok(last
        .as_deref()
        .and_then(unix_secs)
        .filter(|_| n > 0)
        .map(|t| t + backoff_secs(n)))
}

#[cfg(test)]
mod tests {
    use super::backoff_secs;

    #[test]
    fn the_wait_grows_from_two_minutes_to_six_hours() {
        let got: Vec<i64> = (1..=7).map(backoff_secs).collect();
        assert_eq!(got, [120, 300, 900, 3600, 21_600, 21_600, 21_600]);
        assert_eq!(backoff_secs(0), 120, "a count under one is one");
    }
}
