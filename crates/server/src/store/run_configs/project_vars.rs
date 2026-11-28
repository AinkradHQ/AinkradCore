//! Project-level variables of a run environment (API 112; table `core_run_env_vars`). Same rules
//! as a configuration's variables (a plain value without `${`, or the name of one of the project's
//! secrets; a secret's value is never stored here), kept per project and environment instead of per
//! configuration. A start lays them over the spec's service, and a configuration's own variables
//! over them.

use std::collections::BTreeSet;

use serde_json::json;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;

use super::{MAX_VARS, Var, key_problem, known_env, note, refused, value_problem};
use crate::store::project_secrets;
use crate::store::projects::{self, Who};
use crate::store::secrets::Error;

/// The variables of an environment of the project, by key.
pub async fn project_vars(pool: &SqlitePool, project: i64, env: &str) -> Result<Vec<Var>, Error> {
    let rows = sqlx::query(
        "SELECT key, value, secret FROM core_run_env_vars WHERE project_id = ? AND env = ? \
         ORDER BY key",
    )
    .bind(project)
    .bind(env)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            Ok(Var {
                key: r.try_get("key")?,
                value: r.try_get("value")?,
                secret: r.try_get("secret")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?)
}

/// Sets (or replaces) one variable: a plain `value`, or a `secret` of the project. Exactly one.
pub async fn set_project_var(
    pool: &SqlitePool,
    project: i64,
    env: &str,
    key: &str,
    value: Option<&str>,
    secret: Option<&str>,
    who: Who<'_>,
) -> Result<Var, Error> {
    known_env(pool, project, env).await?;
    if let Some(why) = key_problem(key) {
        return refused("bad_request", why);
    }
    match (value, secret) {
        (Some(v), None) => {
            if let Some(why) = value_problem(v) {
                return refused("bad_request", why);
            }
        }
        (None, Some(s)) => {
            let p = projects::get(&mut *pool.acquire().await?, project).await?;
            let want = BTreeSet::from([s.to_owned()]);
            project_secrets::check_refs(&mut *pool.acquire().await?, &p, &want).await?;
        }
        _ => return refused("bad_request", "give a value or a secret, not both"),
    }
    let mut tx = crate::store::begin_write(pool).await?;
    if projects::get(&mut tx, project).await?.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_run_env_vars WHERE project_id = ? AND env = ? AND key != ?",
    )
    .bind(project)
    .bind(env)
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    if n >= MAX_VARS {
        return refused("limit_reached", "an environment has at most 64 variables");
    }
    sqlx::query(
        "INSERT INTO core_run_env_vars (project_id, env, key, value, secret) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (project_id, env, key) DO UPDATE SET \
         value = excluded.value, secret = excluded.secret",
    )
    .bind(project)
    .bind(env)
    .bind(key)
    .bind(value)
    .bind(secret)
    .execute(&mut *tx)
    .await?;
    note(
        &mut tx,
        who,
        project,
        json!({"what": "env_var_set", "env": env, "key": key, "secret": secret}),
    )
    .await?;
    tx.commit().await?;
    Ok(Var {
        key: key.to_owned(),
        value: value.map(str::to_owned),
        secret: secret.map(str::to_owned),
    })
}

pub async fn delete_project_var(
    pool: &SqlitePool,
    project: i64,
    env: &str,
    key: &str,
    who: Who<'_>,
) -> Result<(), Error> {
    known_env(pool, project, env).await?;
    let mut tx = crate::store::begin_write(pool).await?;
    let done =
        sqlx::query("DELETE FROM core_run_env_vars WHERE project_id = ? AND env = ? AND key = ?")
            .bind(project)
            .bind(env)
            .bind(key)
            .execute(&mut *tx)
            .await?;
    if done.rows_affected() == 0 {
        return refused("not_found", "no such variable");
    }
    note(
        &mut tx,
        who,
        project,
        json!({"what": "env_var_deleted", "env": env, "key": key}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
