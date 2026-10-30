//! Governance repositories (slice S5): the approvals service (E7.1) in `approvals`; budgets and
//! their running spend (E7.2) in `budgets`; prices and billing (E7.3) in `ledger`; skills and
//! knowledge entries in `library`.
//!
//! Not here: accounts, devices and pairing (S9, the platform), the per-task cost report and the
//! run-based ledger reads (S7: they read the run tables).
//!
//! `update_*` / `delete_*` return `false` when no row matched. Same-company rules are
//! enforced by triggers at insert and surface as `Error::Database`.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::UserId as CoreUserId;
use sqlx::sqlite::SqliteRow;
use sqlx::{Error, Row, SqliteConnection};

use crate::domain::work::UserId;

mod approvals;
mod budgets;
mod ledger;
mod library;
pub use approvals::*;
pub use budgets::*;
pub use ledger::*;
pub use library::*;

fn id_column(row: &SqliteRow, column: &str) -> Result<Option<i64>, Error> {
    row.try_get(column)
}

/// The audit actor for the person `u`.
pub(crate) fn user_actor(u: UserId) -> AuditActor {
    AuditActor::User(CoreUserId(u.0))
}

/// Server-wide setting `name` read inside the caller's transaction.
// ponytail: server-wide until the Core settings store has company/project scopes; the monolith
// read its project's or company's override here.
pub(crate) async fn setting_in(conn: &mut SqliteConnection, name: &str) -> Result<i64, Error> {
    crate::settings::handle()
        .get_in(conn, name)
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))
}

#[cfg(test)]
mod tests;
