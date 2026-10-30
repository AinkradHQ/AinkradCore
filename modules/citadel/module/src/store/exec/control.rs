//! The admin's controls over a run: cancel, kill and message, and the engine's switch. Cancel and
//! kill stop the run's session (through the platform, which checks the session is the module's);
//! the run ends `cancelled` only once the runner has acknowledged, so a harness that is still
//! working never has its run marked over (and its checkout released under it). A runner that
//! cannot be reached leaves `cancel_requested_at` set, and `reconcile` asks again.

use ainkrad_core_server::api::App;
use serde_json::json;

use super::*;
use crate::domain::exec::RunEvent;
use crate::store::audit::{self, Event};

#[derive(Debug)]
pub enum ControlError {
    NotFound,
    /// The run is over (or, to message it, not running).
    NotLive(RunState),
    /// The runner did not take it: the request is kept and retried.
    Unreachable(String),
    Db(Error),
}

impl From<Error> for ControlError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<TransitionError> for ControlError {
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::NotFound => Self::NotFound,
            TransitionError::Illegal(_) | TransitionError::Conflict => {
                Self::NotLive(RunState::Failed)
            }
            TransitionError::Db(e) => Self::Db(e),
        }
    }
}

async fn audited(
    pool: &SqlitePool,
    run: &Run,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let company = run_company(pool, run.id).await?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let mut e = Event::new(SYSTEM, action)
        .entity("run", run.id.0)
        .run(run.id.0)
        .details(details);
    if let Some(c) = company {
        e = e.company(c);
    }
    audit::append(&mut tx, e).await?;
    tx.commit().await
}

/// Stops the run (`kill`: its harness is killed now, else it finishes its tool call first).
/// `by` is the device that asked, in the audit row only. A run with no session yet is
/// cancelled at once. Whatever the harness was doing, a run over stays over: 409 (`NotLive`).
pub async fn stop_run<H: Host>(
    app: &App,
    host: &H,
    id: RunId,
    kill: bool,
    by: &str,
    now: &str,
) -> Result<Run, ControlError> {
    let run = get_run(&app.pool, id)
        .await?
        .ok_or(ControlError::NotFound)?;
    if run.state.is_terminal() {
        return Err(ControlError::NotLive(run.state));
    }
    let word = if kill { "killed" } else { "cancelled" };
    sqlx::query("UPDATE citadel_runs SET cancel_requested_at = coalesce(cancel_requested_at, ?) WHERE id = ?")
        .bind(now)
        .bind(id.0)
        .execute(&app.pool)
        .await?;
    if let Some(session) = &run.session_id {
        let live = ainkrad_core_server::store::agents::get(&app.pool, session)
            .await?
            .is_some_and(|s| s.live());
        if live
            && let Err(why) = host
                .instruct(app, session, Instruction::Stop { kill })
                .await
        {
            tracing::warn!(
                run = id.0,
                why,
                "a stop was not taken; reconcile asks again"
            );
            return Err(ControlError::Unreachable(why));
        }
    }
    let cancel = RunEvent::Cancel {
        reason: format!("{word} by the admin"),
    };
    let ended = transition_run(&app.pool, id, SYSTEM, &cancel, now).await?;
    audited(
        &app.pool,
        &ended,
        if kill { "run.killed" } else { "run.cancelled" },
        json!({"by_device": by}),
    )
    .await?;
    Ok(ended)
}

/// Gives a running run's harness its next turn. Audited with the message's length only.
pub async fn message_run<H: Host>(
    app: &App,
    host: &H,
    id: RunId,
    text: &str,
    by: &str,
) -> Result<(), ControlError> {
    let run = get_run(&app.pool, id)
        .await?
        .ok_or(ControlError::NotFound)?;
    let (RunState::Running, Some(session)) = (run.state, &run.session_id) else {
        return Err(ControlError::NotLive(run.state));
    };
    host.instruct(app, session, Instruction::Send(text.to_owned()))
        .await
        .map_err(ControlError::Unreachable)?;
    audited(
        &app.pool,
        &run,
        "run.messaged",
        json!({"bytes": text.len(), "by_device": by}),
    )
    .await?;
    Ok(())
}

/// Switches the engine on or off. On, the engine starts sessions without a client in hand, as
/// `by_device` (the device that stepped up to say so): the operator's standing authorisation.
pub async fn set_engine(
    pool: &SqlitePool,
    enabled: bool,
    by_device: &str,
    now: &str,
) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    sqlx::query(
        "INSERT INTO citadel_engine (id, enabled, by_device, updated_at) VALUES (1, ?1, ?2, ?3) \
         ON CONFLICT (id) DO UPDATE SET enabled = ?1, by_device = ?2, updated_at = ?3",
    )
    .bind(enabled)
    .bind(by_device)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let action = if enabled {
        "engine.enabled"
    } else {
        "engine.disabled"
    };
    audit::append(
        &mut tx,
        Event::new(SYSTEM, action).details(json!({"by_device": by_device})),
    )
    .await?;
    tx.commit().await
}
