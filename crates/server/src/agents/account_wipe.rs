//! The real wipe of a removed account (E7 closeout): when the 10 second Undo window ends the Core
//! deletes the key and the row (`accounts::wipe_due`), and asks the runner of a runner-bound account
//! to delete the login in its home (`login.wipe`). A runner that is offline, or does not offer the
//! op, keeps its row in `core_account_wipes` and is asked again on the next pass.

use std::time::Duration;

use ainkrad_proto::v2::{Body, Command, LoginWipe, Reply, bound_key_ok};

use crate::api::App;
use crate::store::accounts;

/// How often removed accounts past their window are wiped and owed runner wipes are sent.
const EVERY: Duration = Duration::from_secs(2);

/// One pass. `all` wipes every removed account now (the Core is stopping), window or not.
pub async fn sweep(app: &App, all: bool) {
    if let Err(e) = accounts::wipe_due(&app.pool, &app.clock.now(), all).await {
        tracing::warn!(error = %e, "wiping removed accounts");
    }
    send_wipes(app).await;
}

/// Asks each owed runner to wipe its home; the row goes only once the runner says it is done.
async fn send_wipes(app: &App) {
    let owed = match accounts::pending_wipes(&app.pool).await {
        Ok(o) => o,
        Err(e) => return tracing::warn!(error = %e, "listing the owed runner wipes"),
    };
    for w in owed {
        // Never send a key the runner would refuse, and never retry it.
        let done = !bound_key_ok(&w.home) || asked(app, &w.runner, &w.home).await;
        let stored = match done {
            true => accounts::wipe_done(&app.pool, w.id).await,
            false => accounts::wipe_tried(&app.pool, w.id).await,
        };
        if let Err(e) = stored {
            tracing::warn!(error = %e, "recording a runner wipe");
        }
    }
}

/// Whether the runner confirmed the wipe of `home`.
async fn asked(app: &App, runner: &str, home: &str) -> bool {
    let cmd = Command::LoginWipe(LoginWipe {
        home: home.to_owned(),
    });
    let Ok(sent) = app.hub.dispatch_login(runner, cmd) else {
        return false;
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(10), sent.outcome()).await,
        Ok(Ok(Body::Result(Reply::LoginResult(r)))) if r.done && r.error.is_none()
    )
}

/// `sweep` every [`EVERY`] until the Core stops; the first pass at once, so a row left past its
/// window by the last run is wiped at start.
pub async fn sweep_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let mut tick = tokio::time::interval(EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = crate::api::stopping(&mut closing) => return,
            _ = tick.tick() => sweep(&app, false).await,
        }
    }
}
