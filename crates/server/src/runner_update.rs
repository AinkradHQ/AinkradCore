//! E12-4: runners update to the Core's version by themselves, one at a time, only when idle.
//!
//! Every ten minutes the Core looks at its online runners. One that is behind this Core, on Linux, with nothing in flight, and
//! not asked in the last hour gets `runner.update` (the same op as `POST /runners/{id}/update`, which an admin sends with a
//! step-up). The runner only drops a request file; its root-side updater (`scripts/release/update.sh runner`) verifies the
//! signed manifest, installs a newer signed release, restarts the runner and rolls the binaries back when it does not stay
//! up. Mac runners update with the app and are never asked.
//!
//! ponytail: "idle" is the Core's view (no command in flight). A task placed in the second between the check and the restart
//! is cut by the restart like any runner restart; a runner-side check would need the agent and run drivers' counters.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use crate::api::App;

const EVERY: Duration = Duration::from_secs(600);
/// A runner is asked at most once per this many seconds.
const COOLDOWN: i64 = 3600;
/// A runner counts as "updating" for this long after it was asked (until it reconnects on the new version).
const UPDATING_FOR: i64 = 900;

static ASKED: LazyLock<Mutex<HashMap<String, i64>>> = LazyLock::new(Mutex::default);

/// `a.b.c` as numbers, ignoring a suffix.
pub fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v
        .split(['-', '+'])
        .next()?
        .split('.')
        .map(|p| p.parse().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// Should this runner be asked to update now?
pub fn wants_update(
    runner_version: &str,
    core_version: &str,
    os: Option<&str>,
    online: bool,
    load: usize,
) -> bool {
    online
        && load == 0
        && os != Some("macos")
        && matches!((semver(runner_version), semver(core_version)), (Some(r), Some(c)) if r < c)
}

/// The oldest runner version this Core still works with. Below it the runner is reported `update_required`.
pub const MIN_RUNNER: &str = "0.9.0";
/// The oldest app this Core still works with (the app checks the same number against itself).
pub const MIN_APP: &str = "0.10.0";

pub fn runner_too_old(runner_version: &str) -> bool {
    matches!((semver(runner_version), semver(MIN_RUNNER)), (Some(r), Some(m)) if r < m)
}

/// Unix seconds by the system clock (the one clock this module uses, in the sweep and in the routes).
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Marks `runner` as asked now.
pub fn note_asked(runner: &str, now: i64) {
    ASKED.lock().unwrap().insert(runner.to_owned(), now);
}

/// Asked in the last few minutes, so the app can show "updating".
pub fn is_updating(runner: &str, now: i64) -> bool {
    ASKED
        .lock()
        .unwrap()
        .get(runner)
        .is_some_and(|t| now - t < UPDATING_FOR)
}

fn due(runner: &str, now: i64) -> bool {
    ASKED
        .lock()
        .unwrap()
        .get(runner)
        .is_none_or(|t| now - t >= COOLDOWN)
}

async fn sweep(app: &App) {
    let core = env!("CARGO_PKG_VERSION");
    let now = unix_now();
    for (id, st) in app.hub.runners() {
        if !wants_update(&st.version, core, st.os.as_deref(), st.online, st.load) || !due(&id, now)
        {
            continue;
        }
        note_asked(&id, now);
        match app.hub.dispatch_runner_update(&id, core) {
            Ok(sent) => match tokio::time::timeout(Duration::from_secs(20), sent.outcome()).await {
                Ok(Ok(_)) => tracing::info!(runner = %id, to = core, "asked a runner to update"),
                _ => tracing::warn!(runner = %id, "a runner did not accept its update"),
            },
            Err(e) => {
                tracing::warn!(runner = %id, code = ?e.code, "could not ask a runner to update")
            }
        }
    }
}

/// Looks every ten minutes (after a first wait) until the Core stops.
pub async fn sweep_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(120),
        EVERY,
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => sweep(&app).await,
            () = crate::api::stopping(&mut closing) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_idle_online_linux_runner_behind_the_core_is_asked() {
        assert!(wants_update("0.10.0", "0.10.1", Some("linux"), true, 0));
        assert!(
            !wants_update("0.10.1", "0.10.1", Some("linux"), true, 0),
            "current"
        );
        assert!(
            !wants_update("0.11.0", "0.10.1", Some("linux"), true, 0),
            "never a downgrade"
        );
        assert!(
            !wants_update("0.10.0", "0.10.1", Some("linux"), true, 2),
            "busy"
        );
        assert!(
            !wants_update("0.10.0", "0.10.1", Some("linux"), false, 0),
            "offline"
        );
        assert!(
            !wants_update("0.10.0", "0.10.1", Some("macos"), true, 0),
            "a Mac runner updates with the app"
        );
        assert!(!wants_update("junk", "0.10.1", Some("linux"), true, 0));
    }

    #[test]
    fn the_min_runner_floor_and_the_cooldown() {
        assert!(runner_too_old("0.8.9") && !runner_too_old("0.9.0") && !runner_too_old("junk"));
        assert!(due("rx", 5_000));
        note_asked("rx", 5_000);
        assert!(!due("rx", 5_000 + COOLDOWN - 1) && due("rx", 5_000 + COOLDOWN));
        assert!(is_updating("rx", 5_100) && !is_updating("rx", 5_000 + UPDATING_FOR));
    }
}
