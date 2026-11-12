//! Live AI sessions (N41), the supervisor's part: delivers a message that waited for the runner to
//! run its session again, and ends a session whose user has not come back for
//! `agents.idle_end_secs`. A `waiting` session still holds its runner slot and its account's cap
//! (its stored state is `running`), which is what the idle end bounds.

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::AgentSend;

use super::*;

/// What the supervisor does before it reads a `running` session. `true`: the session was ended
/// here (the next pass settles it).
pub(crate) async fn before_read(app: &App, s: &Session) -> Result<bool, Refusal> {
    if let Some(text) = s.pending.as_ref().filter(|_| s.state == "running") {
        deliver(app, s, text).await?;
    }
    idle_end(app, s).await
}

/// Sends the pending message to the runner's session, once, then forgets it.
async fn deliver(app: &App, s: &Session, text: &str) -> Result<(), Refusal> {
    let proof = app.agents.elevated.lock().unwrap().get(&s.id).copied();
    let send = Command::AgentSend(AgentSend {
        session: s.id.clone(),
        text: text.to_owned(),
    });
    let ev = ask(app, &s.runner, send, app.agents.config.answer, proof).await?;
    store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    store::clear_pending(&app.pool, &s.id, text).await?;
    Ok(())
}

async fn idle_end(app: &App, s: &Session) -> Result<bool, Refusal> {
    let Some(since) = s
        .waiting_since
        .filter(|_| s.state == "running" && s.pending.is_none())
    else {
        return Ok(false);
    };
    let secs = crate::store::settings::value(&app.pool, Key::AgentsIdleEndSecs, Scope::Server)
        .await
        .unwrap_or(7_200);
    if app.clock.unix() - since < secs {
        return Ok(false);
    }
    let Ok(held) = ending::stop_for_end(app, s).await else {
        return Ok(false); // the runner did not answer: tried again at the next pass
    };
    let outcome = json!({"kind": "succeeded", "reason": "idle_timeout"});
    if store::end(&app.pool, &s.id, "ended", &outcome, &app.clock.now()).await?
        && let Some(held) = held
    {
        ending::acknowledge(app, s, held).await?;
    }
    Ok(true)
}
