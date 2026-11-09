//! Runner admin from the app (protocol 1.20), mirroring `citadel-server runner add|revoke`:
//! register (its key returned once), drain (it takes no new run; its runs finish) and undrain,
//! remove (refused while it holds live runs), and the admin's Power Nap preference for it, each
//! audited. Also what a runner reports of itself (`RunnerInfo`, its harness versions), kept on
//! its row like its disk report.

use std::collections::{BTreeMap, HashMap};

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_proto::runner::RunnerInfo;
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;

async fn record(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    runner: RunnerId,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "runner".to_owned(),
            id: runner.0,
        }),
        company_id: None,
        run_id: None,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

async fn runner_in(conn: &mut SqliteConnection, id: RunnerId) -> Result<Option<Runner>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        runner_columns!(),
        " FROM runners WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(runner)
    .transpose()
}

/// Registers an `offline` runner with a fresh key, audited as `runner.registered`: the runner
/// and its key, returned here once and never stored. A taken name is a constraint error.
pub async fn add_runner(
    pool: &SqlitePool,
    r: &NewRunner,
    actor: AuditActor,
) -> Result<(Runner, String), Error> {
    let key = random_key("cit_runner_")?;
    let mut tx = crate::store::begin_write(pool).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO runners (name, key_hash, tags) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(&r.name)
    .bind(key_hash(&key))
    .bind(Json(&r.tags))
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"name": r.name, "tags": r.tags});
    record(&mut tx, actor, "runner.registered", RunnerId(id), details).await?;
    let added = runner_in(&mut tx, RunnerId(id)).await?;
    tx.commit().await?;
    Ok((added.ok_or(Error::RowNotFound)?, key))
}

/// Drains the runner (`drain`) or takes it back (`!drain`), audited as `runner.drained` /
/// `runner.undrained` when it changes. `None`: no such runner.
pub async fn drain_runner(
    pool: &SqlitePool,
    id: RunnerId,
    drain: bool,
    actor: AuditActor,
    now: &str,
) -> Result<Option<Runner>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(before) = runner_in(&mut tx, id).await? else {
        return Ok(None);
    };
    if before.drained_at.is_some() != drain {
        sqlx::query("UPDATE runners SET drained_at = ? WHERE id = ?")
            .bind(drain.then_some(now))
            .bind(id.0)
            .execute(&mut *tx)
            .await?;
        let action = if drain {
            "runner.drained"
        } else {
            "runner.undrained"
        };
        record(&mut tx, actor, action, id, json!({"at": now})).await?;
    }
    let after = runner_in(&mut tx, id).await?;
    tx.commit().await?;
    Ok(after)
}

/// Sets the admin's Power Nap preference for the runner, audited as `runner.power_nap` when it
/// changes; its connection pushes it (`Prefs`). `None`: no such runner.
pub async fn set_power_nap(
    pool: &SqlitePool,
    id: RunnerId,
    on: bool,
    actor: AuditActor,
) -> Result<Option<Runner>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(before) = runner_in(&mut tx, id).await? else {
        return Ok(None);
    };
    if before.power_nap != Some(on) {
        sqlx::query("UPDATE runners SET power_nap = ? WHERE id = ?")
            .bind(on)
            .bind(id.0)
            .execute(&mut *tx)
            .await?;
        let details = json!({"power_nap": on, "was": before.power_nap});
        record(&mut tx, actor, "runner.power_nap", id, details).await?;
    }
    let after = runner_in(&mut tx, id).await?;
    tx.commit().await?;
    Ok(after)
}

/// `runner`'s claimed and running runs, with their issues: (run, issue), oldest first.
pub async fn live_runs(
    pool: &SqlitePool,
    runner: RunnerId,
) -> Result<Vec<(i64, Option<i64>)>, Error> {
    let live = sqlx::query_as(
        "SELECT id, issue_id FROM runs WHERE runner_id = ? AND state IN ('claimed', 'running') \
         ORDER BY id",
    )
    .bind(runner.0)
    .fetch_all(pool)
    .await?;
    Ok(live)
}

/// Deletes a runner that holds no claimed or running run, audited as `runner.removed` when
/// `actor` is given; its ended runs stay, with no runner. Refused, not reaped: deleting a
/// runner says nothing about whether it is still working, so its runs end the normal way.
pub async fn remove_runner(
    pool: &SqlitePool,
    id: RunnerId,
    actor: Option<AuditActor>,
) -> Result<bool, DeleteRunnerError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let live: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM runs WHERE runner_id = ? AND state IN ('claimed', 'running') \
         ORDER BY id",
    )
    .bind(id.0)
    .fetch_all(&mut *tx)
    .await?;
    if !live.is_empty() {
        return Err(DeleteRunnerError::LiveRuns(
            live.into_iter().map(RunId).collect(),
        ));
    }
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM runners WHERE id = ? RETURNING name")
            .bind(id.0)
            .fetch_optional(&mut *tx)
            .await?;
    if let (Some(name), Some(actor)) = (&name, actor) {
        record(&mut tx, actor, "runner.removed", id, json!({"name": name})).await?;
    }
    tx.commit().await?;
    Ok(name.is_some())
}

/// What a runner last reported of itself.
#[derive(Debug, Clone, Default)]
pub struct RunnerState {
    pub info: Option<RunnerInfo>,
    pub info_at: Option<String>,
    /// Harness → version, from its last `Hello`.
    pub harnesses: BTreeMap<String, String>,
    /// Its operating system and architecture (1.25), when it said.
    pub os: Option<String>,
    pub arch: Option<String>,
}

/// Stores the runner's `os` and `arch` when it gave them (a `Hello` or a probe).
pub async fn record_platform(
    pool: &SqlitePool,
    runner: RunnerId,
    os: Option<&str>,
    arch: Option<&str>,
) -> Result<(), Error> {
    sqlx::query("UPDATE runners SET os = coalesce(?, os), arch = coalesce(?, arch) WHERE id = ?")
        .bind(os)
        .bind(arch)
        .bind(runner.0)
        .execute(pool)
        .await
        .map(drop)
}

/// Stores the runner's `info` at `now`, and its `harnesses` when given (a `Hello`).
pub async fn record_info(
    pool: &SqlitePool,
    runner: RunnerId,
    info: &RunnerInfo,
    harnesses: Option<&BTreeMap<String, String>>,
    now: &str,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    sqlx::query(
        "UPDATE runners SET info = ?, info_at = ?, harnesses = coalesce(?, harnesses) \
         WHERE id = ?",
    )
    .bind(Json(info))
    .bind(now)
    .bind(harnesses.map(Json))
    .bind(runner.0)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Every runner's reported state, by runner id.
pub async fn runner_states(pool: &SqlitePool) -> Result<HashMap<i64, RunnerState>, Error> {
    type Row = (
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> =
        sqlx::query_as("SELECT id, info, info_at, harnesses, os, arch FROM runners")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, info, info_at, harnesses, os, arch)| {
            let state = RunnerState {
                info: info.and_then(|i| serde_json::from_str(&i).ok()),
                info_at,
                harnesses: harnesses
                    .and_then(|h| serde_json::from_str(&h).ok())
                    .unwrap_or_default(),
                os,
                arch,
            };
            (id, state)
        })
        .collect())
}
