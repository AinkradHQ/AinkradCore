//! Provider drops per account (E15.4). A run whose turn the provider dropped resumes its
//! session inside the run; each drop is counted against the account it works as
//! (`account_events`, kind `drop`), with the resume's prompt as a message.
//! `account.drop_threshold` drops within `account.drop_window_secs` turn the account
//! `unhealthy` (`account.unhealthy`) for `account.unhealthy_secs` (the account's settings,
//! E15.17): dispatch skips it, and runs on it fall back (E15.3). `refresh_in` restores it.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::RunId;
use ainkrad_core::gov::{AccountId, AccountStatus};
use ainkrad_core::org::CompanyId;
use ainkrad_core::settings::{Key, Scope};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::{Mark, mark_in, record_message_in, window_text};
use crate::store::audit;
use crate::store::settings::value_in;

/// The account's drops in its `account.drop_window_secs` ending at `now`, and that window.
pub(crate) async fn drops_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    now: &str,
) -> Result<(i64, i64), Error> {
    drops_over_in(conn, account, Key::DropWindowSecs, now).await
}

/// The account's drops in the window setting `window` (`account.drop_window_secs`, or the
/// app's `account.drop_display_window_secs`) ending at `now`, and that window.
pub(crate) async fn drops_over_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    window: Key,
    now: &str,
) -> Result<(i64, i64), Error> {
    let window = value_in(conn, window, Scope::Account(account)).await?;
    let drops = sqlx::query_scalar(
        "SELECT count(*) FROM account_events WHERE account_id = ?1 AND kind = 'drop' \
         AND julianday(at) > julianday(?2) - ?3 / 86400.0",
    )
    .bind(account.0)
    .bind(now)
    .bind(window)
    .fetch_one(&mut *conn)
    .await?;
    Ok((drops, window))
}

/// Records that the provider dropped `run`'s turn (`reason`) and the run resumed: appends
/// `run.provider_dropped`, counts the drop and the resume's prompt against the run's account,
/// and marks the account unhealthy once it has dropped `account.drop_threshold` times in the
/// window.
pub async fn record_drop(
    pool: &SqlitePool,
    run: RunId,
    reason: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (account, company): (Option<i64>, i64) = sqlx::query_as(
        "SELECT r.account_id, a.company_id FROM runs r JOIN agents a ON a.id = r.agent_id \
         WHERE r.id = ?",
    )
    .bind(run.0)
    .fetch_one(&mut *tx)
    .await?;
    let event = NewAuditEvent {
        actor,
        action: "run.provider_dropped".to_owned(),
        entity: Some(AuditEntity {
            kind: "run".to_owned(),
            id: run.0,
        }),
        company_id: Some(CompanyId(company)),
        run_id: Some(run),
        details: json!({"reason": reason, "account": account}).to_string(),
    };
    audit::append(&mut *tx, &event).await?;
    if let Some(account) = account.map(AccountId) {
        sqlx::query(
            "INSERT INTO account_events (account_id, run_id, kind, at) VALUES (?, ?, 'drop', ?)",
        )
        .bind(account.0)
        .bind(run.0)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        record_message_in(&mut tx, account, run.0, now).await?;
        let (drops, window) = drops_in(&mut tx, account, now).await?;
        let at = Scope::Account(account);
        if drops >= value_in(&mut tx, Key::DropThreshold, at).await? {
            let sick = value_in(&mut tx, Key::UnhealthySecs, at).await?;
            let until: String = sqlx::query_scalar(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', julianday(?) + ? / 86400.0)",
            )
            .bind(now)
            .bind(sick)
            .fetch_one(&mut *tx)
            .await?;
            let why = format!(
                "the provider dropped {drops} turns in {}",
                window_text(window)
            );
            let mark = Mark {
                to: AccountStatus::Unhealthy,
                reason: Some(&why),
                until: Some(&until),
                action: "account.unhealthy",
                details: json!({"drops": drops, "window_secs": window, "unhealthy_secs": sick,
                                "until": until, "last": reason}),
            };
            mark_in(&mut tx, account, &[AccountStatus::Active], mark).await?;
        }
    }
    tx.commit().await
}
