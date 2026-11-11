//! Storing an account with its key (split from `accounts`): [`create`] and [`create_by`].

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::{
    Account, DEFAULT_CAP, NewAccount, audit, check_cap, find, refused, tail_of, valid_label,
};
use crate::ops::secretbox::SecretBox;
use crate::store::placement::Placement;
use crate::store::secrets::{self, Error, NewValue};

/// Stores an account and its key together. `owner` is the storing device; `actor` is audited.
pub async fn create(
    pool: &SqlitePool,
    sealer: &SecretBox,
    new: &NewAccount<'_>,
    owner: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    create_by(pool, sealer, new, "key", owner, actor, now).await
}

/// [`create`], naming how the key came (`key`: pasted, `subscription`: a login), which the audit
/// row records.
pub async fn create_by(
    pool: &SqlitePool,
    sealer: &SecretBox,
    new: &NewAccount<'_>,
    method: &str,
    owner: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    create_inner(pool, sealer, new, method, owner, actor, now, None)
        .await
        .map(|(a, _)| a)
}

/// [`create_by`], and in the same transaction the account goes into its pool and the pool into a
/// chain (`placement`). Returns the account, its pool and the chain that took the pool.
#[allow(clippy::too_many_arguments)]
pub async fn create_placed(
    pool: &SqlitePool,
    sealer: &SecretBox,
    new: &NewAccount<'_>,
    method: &str,
    owner: &str,
    actor: AuditActor,
    now: &str,
    placement: &Placement,
) -> Result<(Account, (i64, Option<i64>)), Error> {
    let (a, placed) = create_inner(
        pool,
        sealer,
        new,
        method,
        owner,
        actor,
        now,
        Some(placement),
    )
    .await?;
    Ok((a, placed.expect("a placement was asked for")))
}

#[allow(clippy::too_many_arguments)]
async fn create_inner(
    pool: &SqlitePool,
    sealer: &SecretBox,
    new: &NewAccount<'_>,
    method: &str,
    owner: &str,
    actor: AuditActor,
    now: &str,
    placement: Option<&Placement>,
) -> Result<(Account, Option<(i64, Option<i64>)>), Error> {
    if !valid_label(new.label) {
        return refused("bad_request", "a label is [a-z][a-z0-9._-]{0,63}");
    }
    let cap = new.cap.unwrap_or(DEFAULT_CAP);
    check_cap(cap)?;
    // A pasted key often carries a trailing newline: neither the sealed value nor the tail keeps it.
    let key = new.value.trim();
    let mut tx = crate::store::begin_write(pool).await?;
    let def = match crate::store::providers::get_in(&mut tx, new.provider).await {
        Err(Error::Refused {
            code: "not_found", ..
        }) => {
            return refused(
                "bad_request",
                "provider is a built-in or a stored definition",
            );
        }
        found => found?,
    };
    if let Some(why) = crate::store::account_keys::holds_keys_problem(&def) {
        return refused("bad_request", why);
    }
    let base_url = def.base_url;
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_accounts WHERE label = ?")
        .bind(new.label)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        return refused("conflict", "an account of that label exists");
    }
    // The secret's name needs the row's id, so the row goes in first and the name follows, in
    // the same transaction; nothing outside it ever sees the placeholder.
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_accounts (provider, label, secret_name, masked_tail, base_url, cap, \
         owner, created_at, updated_at) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(new.provider)
    .bind(new.label)
    .bind(tail_of(key))
    .bind(&base_url)
    .bind(cap)
    .bind(owner)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let name = format!("{}{}.{id}", secrets::ACCOUNT_PREFIX, new.provider);
    let value = NewValue {
        value: key,
        runners: Some(new.runners),
        delivery: Some("env"),
    };
    secrets::create_in(&mut tx, sealer, &name, &value, owner, actor, now).await?;
    sqlx::query("UPDATE core_accounts SET secret_name = ? WHERE id = ?")
        .bind(&name)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "account.created",
        id,
        json!({"provider": new.provider, "label": new.label, "cap": cap,
               "base_url": base_url, "runners": new.runners, "by_device": owner,
               "method": method}),
    )
    .await?;
    let a = find(&mut tx, id).await?;
    let placed = match placement {
        Some(p) => Some(crate::store::placement::place(&mut tx, &a, p, owner, actor, now).await?),
        None => None,
    };
    tx.commit().await?;
    Ok((a, placed))
}
