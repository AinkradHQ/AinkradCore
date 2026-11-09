//! How the Core ends a session on its own: the kill before an end, the acknowledgement read after
//! it, and the end of a client session whose creator device was revoked (B-M1b).

use super::*;

/// What the supervisor does about a session whose creator may be revoked.
pub(super) enum Revoked {
    /// The creator is fine, or the session is not a client's: nothing to do.
    No,
    /// The session is over (or settled): the supervisor returns.
    Over,
    /// The runner did not answer; tried again at the next pass, until it is gone or `lost_after`.
    Retry,
}

/// Best effort, before the Core ends a session itself: tells the runner to kill it so a harness that
/// may still run stops spending, and stores the runner's answer (the gateway's final reports, the
/// usage). `Ok(held)`: the stored transcript length, when the runner answered; `None` when there is
/// nothing to ask (no elevation) or the runner does not know the session. `Err`: it did not get
/// through. Never logs a value.
pub(super) async fn stop_for_end(app: &App, s: &Session) -> Result<Option<u64>, ()> {
    let Some(proof) = app.agents.elevated.lock().unwrap().get(&s.id).copied() else {
        return Ok(None);
    };
    let stop = Command::AgentStop(ainkrad_proto::v2::AgentStop {
        session: s.id.clone(),
        kill: true,
    });
    match ask(app, &s.runner, stop, app.agents.config.answer, Some(proof)).await {
        Ok(ev) => match store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await {
            Ok(held) => Ok(Some(held)),
            Err(e) => {
                tracing::warn!(session = s.id, error = %e, "storing the answer to a kill failed");
                Err(())
            }
        },
        Err(e) if e.code == ErrorCode::InvalidArgs => Ok(None),
        Err(e) => {
            tracing::warn!(session = s.id, code = ?e.code, "the kill before an end did not get through");
            Err(())
        }
    }
}

/// The read after a session's end: the runner may drop its copy (the Core holds all of it), and
/// what this last answer carries is stored too: the gateway's final reports (the requests a stop
/// aborted, charged approximately) may come only with it.
pub(super) async fn acknowledge(app: &App, s: &Session, held: u64) -> Result<(), sqlx::Error> {
    let ack = Command::AgentRead(AgentRead {
        gw_after: crate::store::gateway::ack_after(&app.pool, &s.id).await?,
        session: s.id.clone(),
        after: held,
        wait_ms: None,
    });
    if let Ok(ev) = ask(app, &s.runner, ack, app.agents.config.answer, None).await {
        store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    }
    Ok(())
}

/// A client session does not outlive the device that created it. A module's session is the
/// module's to stop; one created by its own runner is ended by the runner's revocation.
pub(super) async fn creator_revoked(
    app: &App,
    s: &Session,
    away: &mut Option<tokio::time::Instant>,
) -> Revoked {
    use crate::auth::{DeviceNow, device_now};
    if s.owner_module.is_some()
        || s.created_by == s.runner
        || device_now(&app.pool, &s.created_by, None).await != DeviceNow::Gone
    {
        return Revoked::No;
    }
    let now = app.clock.now();
    let why = "its creator was revoked";
    // A chain session that never reached its runner has nothing to kill.
    let ended = match crate::store::alloc::end_unstarted_why(&app.pool, &s.id, &now, why).await {
        Ok(true) => true,
        _ => match stop_for_end(app, s).await {
            Ok(held) => {
                let outcome = json!({"kind": "failed", "reason": "the session's creator device was revoked", "fingerprint": "core"});
                let done = store::end(&app.pool, &s.id, "ended", &outcome, &now).await;
                if done.is_ok()
                    && let Some(held) = held
                {
                    let _ = acknowledge(app, s, held).await;
                }
                done.is_ok()
            }
            Err(()) => false,
        },
    };
    if ended {
        if let Err(e) = crate::store::failover::settle(&app.pool, &s.id).await {
            tracing::error!(session = s.id, error = %e, "settling a failover failed");
        }
        app.agents.leases.lock().unwrap().remove(&s.id);
        return Revoked::Over;
    }
    // The runner is gone for good, or has been away too long: the session is lost now, as in the
    // supervisor's own runner checks.
    let gone = device_now(&app.pool, &s.runner, None).await == DeviceNow::Gone;
    let since = *away.get_or_insert_with(tokio::time::Instant::now);
    if gone || since.elapsed() >= app.agents.config.lost_after {
        let reason = if gone {
            "the runner was revoked"
        } else {
            "the runner never came back"
        };
        let outcome = json!({"kind": "lost", "reason": reason});
        if store::end(&app.pool, &s.id, "lost", &outcome, &now)
            .await
            .is_ok()
        {
            return Revoked::Over;
        }
    }
    Revoked::Retry
}
