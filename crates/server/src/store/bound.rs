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

/// The file name a Core-held login is stored under in the vault (a `file` secret: a bundle of
/// several JSON files is over the text limit and holds more than one token).
pub const HELD_FILE: &str = "login.json";

/// Whether account `id` of `provider` has its login in the Core's vault, lent per session: a
/// Claude plan always, a Codex or OpenCode plan once it has no runner-bound record.
pub async fn held_by_core(
    conn: &mut SqliteConnection,
    provider: &str,
    id: i64,
) -> Result<bool, sqlx::Error> {
    if super::account_keys::subscription_provider(provider)
        && ainkrad_proto::v2::bound_harness(provider).is_none()
    {
        return Ok(true);
    }
    Ok(ainkrad_proto::v2::lendable(provider) && of(conn, id).await?.is_none())
}

/// Seals `bundle` (a login's credential files, `parse_bundle`-checked by the caller) as account
/// `a`'s value, scoped to every active runner, and drops its runner-bound record in the same
/// transaction. Returns the record it had (its home is then owed a wipe by the caller), or `None`
/// for an account already held by the Core (a write-back). Audited `secret.rotated`, plus
/// `account.moved_to_core` for a move.
pub async fn hold(
    pool: &sqlx::SqlitePool,
    sealer: &crate::ops::secretbox::SecretBox,
    a: &super::accounts::Account,
    bundle: &str,
    by_device: &str,
    actor: ainkrad_core::audit::AuditActor,
    now: &str,
) -> Result<Option<Bound>, super::secrets::Error> {
    use base64::Engine;
    let value = zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bundle));
    let runners = super::logins::active_runners(pool).await?;
    let mut tx = super::begin_write(pool).await?;
    let was = of(&mut tx, a.id).await?;
    let new = super::secrets::NewValue {
        value: &value,
        runners: Some(&runners),
        delivery: Some("env"),
        kind: Some("file"),
        file_name: Some(HELD_FILE),
        file_mode: Some(0o600),
        ..Default::default()
    };
    super::secrets::rotate_in(&mut tx, sealer, &a.secret_name, &new, by_device, actor, now).await?;
    if let Some(b) = &was {
        sqlx::query("DELETE FROM core_account_bound WHERE account_id = ?")
            .bind(a.id)
            .execute(&mut *tx)
            .await?;
        super::accounts::audit(
            &mut tx,
            actor,
            "account.moved_to_core",
            a.id,
            serde_json::json!({"from_runner": b.runner, "by_device": by_device}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(was)
}

/// Adds each of `runners` (online, active) to the scope of every account the Core holds the login
/// of, so any runner can be lent it. Writes only where a runner is missing. ponytail: a changed
/// scope drops the secret's unredeemed leases (`set_runners_in`), so a start racing a runner's
/// first connection retries; a scope-only add without that drop if it ever matters.
pub async fn widen(
    pool: &sqlx::SqlitePool,
    runners: &[String],
    now: &str,
) -> Result<(), super::secrets::Error> {
    if runners.is_empty() {
        return Ok(());
    }
    let active = super::logins::active_runners(pool).await?;
    let wanted: Vec<&String> = runners.iter().filter(|r| active.contains(r)).collect();
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT a.id, a.provider, a.secret_name, s.runners FROM core_accounts a \
         JOIN core_secrets s ON s.name = a.secret_name WHERE a.deleted_at IS NULL",
    )
    .fetch_all(pool)
    .await?;
    for (id, provider, name, scope) in rows {
        let mut have: Vec<String> = serde_json::from_str(&scope).unwrap_or_default();
        if wanted.iter().all(|r| have.contains(r)) {
            continue;
        }
        let mut conn = pool.acquire().await?;
        if !held_by_core(&mut conn, &provider, id).await? {
            continue;
        }
        drop(conn);
        have.retain(|r| active.contains(r));
        let add: Vec<String> = wanted
            .iter()
            .filter(|r| !have.contains(r))
            .map(|r| (*r).clone())
            .collect();
        have.extend(add);
        let mut tx = super::begin_write(pool).await?;
        super::secrets::set_runners_in(
            &mut tx,
            &name,
            &have,
            "core",
            ainkrad_core::audit::AuditActor::System,
            now,
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}
