//! Where a runner-bound subscription account's login lives (E7-4, E7-5, E7-5b): one runner, one
//! home key. The Core records only that, never a credential; the broker secret holds a marker.

use sqlx::SqliteConnection;

/// The runner and home of a bound account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub runner: String,
    pub home: String,
}

/// Account `id`'s runner and home, or `None` for an account that is not runner-bound.
pub async fn of(conn: &mut SqliteConnection, id: i64) -> Result<Option<Bound>, sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT runner, home FROM core_account_bound WHERE account_id = ?")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    Ok(row.map(|(runner, home)| Bound { runner, home }))
}

/// The bound account named by session secret `name` (`acct.<provider>.<id>`), if it is one.
pub async fn of_secret(
    conn: &mut SqliteConnection,
    name: &str,
) -> Result<Option<Bound>, sqlx::Error> {
    match super::gateway::account_secret(name) {
        Some((_, id)) => of(conn, id).await,
        None => Ok(None),
    }
}
