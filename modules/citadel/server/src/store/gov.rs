//! Governance repository: the provider account pool (E15.1) in `accounts`; the approvals service (E7.1) in `approvals`; budgets and their
//! running spend (E7.2) in `budgets`; prices, billing and cost reports (E7.3) in `ledger`, and per task (E15.5) in `tasks`; skills, knowledge entries and device keys in `library`; issuing,
//! authorizing and revoking device keys (E10.3) in `devices`.
//!
//! `update_*` / `delete_*` return `false` when no row matched. Same-company rules are
//! enforced by triggers at insert and surface as `Error::Database`.

use sqlx::sqlite::SqliteRow;
use sqlx::{Error, Row};

mod accounts;
mod approvals;
mod budgets;
mod devices;
mod ledger;
mod library;
mod pairing;
mod tasks;
pub use accounts::*;
pub use approvals::*;
pub use budgets::*;
pub use devices::*;
pub use ledger::*;
pub use library::*;
pub use pairing::*;
pub use tasks::*;

fn id_column(row: &SqliteRow, column: &str) -> Result<Option<i64>, Error> {
    row.try_get(column)
}

#[cfg(test)]
mod tests;
