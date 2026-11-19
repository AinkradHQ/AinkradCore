//! Restart-if-it-stops (Core 0.10, E11-3): a run of a configuration with `restart` on that ended
//! as a `crash` is started again after a growing pause, at most [`MAX_RETRIES`] times within
//! [`WINDOW_SECS`]; then the Core gives up and emits `project.run_gave_up`. A run a person
//! stopped (`user`), the idle stop and a replaced run never restart, nor does a start that failed
//! (`start_failed`): only a run that came up and then fell over.
//!
//! SECURITY: starting a run needs a step-up a person gave. A restart starts the same
//! configuration in the same environment that person started, so it reuses that proof
//! (`Hub::continue_run_elevation`); it can start nothing else.
//!
//! The pass is stateless: a crashed run with no newer run of its configuration is due when its
//! pause has passed, and its restart is the newer run. Only the give-up is remembered, in this
//! process, so one crash loop emits one event.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use super::{Link, StartOpts, begin_start_with, drive_start, system};
use crate::api::App;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::runs::{self, Run};

pub const MAX_RETRIES: i64 = 5;
pub const WINDOW_SECS: i64 = 600;
const BASE_SECS: i64 = 2;
const CAP_SECS: i64 = 60;

/// What to do with a crashed run.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Wait,
    Restart,
    GiveUp,
}

/// The pause after the `crashes`-th crash in the window (the one just ended counts): 2, 4, 8,
/// 16, 32, then at most 60 seconds.
pub fn delay_secs(crashes: i64) -> i64 {
    (BASE_SECS << (crashes - 1).clamp(0, 5)).min(CAP_SECS)
}

pub fn verdict(crashes: i64, since_stop_secs: i64) -> Verdict {
    if crashes > MAX_RETRIES {
        Verdict::GiveUp
    } else if since_stop_secs >= delay_secs(crashes) {
        Verdict::Restart
    } else {
        Verdict::Wait
    }
}

static GAVE_UP: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);

/// One look at the crashed runs of configurations that want a restart.
pub async fn pass(app: &App, link: &dyn Link) {
    let unix = app.clock.unix();
    let since = iso_of_unix(unix - WINDOW_SECS);
    let Ok(due) = runs::crashed_to_restart(&app.pool, &since).await else {
        return;
    };
    for r in due {
        let Some(cid) = r.config_id else { continue };
        let Ok(crashes) = runs::crashes_since(&app.pool, r.project_id, cid, &since).await else {
            continue;
        };
        let gone = r.stopped_at.as_deref().and_then(unix_secs).unwrap_or(unix);
        match verdict(crashes, unix - gone) {
            Verdict::Wait => {}
            Verdict::GiveUp => give_up(app, &r, crashes).await,
            Verdict::Restart => restart(app, link, &r, cid).await,
        }
    }
}

async fn give_up(app: &App, r: &Run, crashes: i64) {
    if !GAVE_UP.lock().unwrap().insert(r.id.clone()) {
        return;
    }
    if let Err(e) = runs::gave_up(&app.pool, r, crashes, MAX_RETRIES).await {
        tracing::warn!(run = r.id, error = %e, "recording that a restart gave up failed");
    }
}

async fn restart(app: &App, link: &dyn Link, r: &Run, config: i64) {
    let now = app.clock.now();
    let opts = StartOpts {
        config: Some(config),
        environment: r.environment.clone(),
    };
    match begin_start_with(app, link, r.project_id, &opts, system(&now)).await {
        Ok(p) => drive_start(app, link, p, app.hub.continue_run_elevation()).await,
        // Already live again, archived, or the configuration is gone: nothing to restart.
        Err(e) => tracing::info!(run = r.id, error = %e, "a restart was not started"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pause_doubles_and_stops_at_a_minute() {
        let d: Vec<i64> = (1..=8).map(delay_secs).collect();
        assert_eq!(d, [2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(delay_secs(0), 2);
    }

    #[test]
    fn a_crash_waits_out_its_pause_then_restarts() {
        assert_eq!(verdict(1, 1), Verdict::Wait);
        assert_eq!(verdict(1, 2), Verdict::Restart);
        assert_eq!(verdict(3, 7), Verdict::Wait);
        assert_eq!(verdict(3, 8), Verdict::Restart);
    }

    #[test]
    fn it_gives_up_after_five_restarts() {
        assert_eq!(verdict(MAX_RETRIES, 60), Verdict::Restart);
        assert_eq!(verdict(MAX_RETRIES + 1, 0), Verdict::GiveUp);
        assert_eq!(verdict(MAX_RETRIES + 1, 600), Verdict::GiveUp);
    }
}
