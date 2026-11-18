//! Who may read a Core repo copy (Projects P3-02).
//!
//! Security model:
//! - A copy is served to a runner device only while the Core has leased it that repo. The lease
//!   is per (device, repo id): granted when a session of the repo's project is launched on that
//!   device (`for_session`), never asked for by the runner, never carried by it: the Core only
//!   remembers it, so a runner cannot forge, extend or pass one on. One lease per runner per
//!   repo; a second session of the project on the same runner renews it.
//! - It is short (`LEASE_SECS`), ends with its session (`release_session`) and lives in memory: a Core restart drops every lease, and the
//!   launch that follows (a restart or resume re-launches the session) grants it again. A
//!   lease is no standing right: a runner is trusted compute, but a project's code is read only
//!   by a runner that was given one of its sessions.
//! - A lease opens nothing by itself: `servable` also requires the repo to exist and its
//!   project to be ACTIVE, at every request, so archiving a project (or removing the repo)
//!   closes its copy at once. Every refusal is the same 404 `no such repo`: no runner can tell
//!   a repo it holds no lease for from one that does not exist, or probe ids across projects.
//! - A session may only lease repos of its own project (`for_session` checks each id against the
//!   project the session was created for), so `Workspace.mirror` ids a client or module wrote
//!   into a workspace open nothing.
//! - The serving itself stays read-only (`upload-pack` only), as in the parent module.

use super::{Mirrors, Refused, Target, key_of_target, refresh, target};
use crate::api::App;
use crate::store::projects as store;

/// How long a lease lasts. It must outlast the runner relay's 30-minute clone limit
/// (`runner::workspace::relay`), or a slow clone loses its lease mid-way; ending the session
/// revokes it sooner (`release_session`).
pub const LEASE_SECS: i64 = 45 * 60;

/// The most leases held at once (device x repo); expired ones are dropped first.
const MAX_LEASES: usize = 4096;

impl Mirrors {
    /// Leases repo `repo` (its mirror `key`: project and remote) to `device` until
    /// `now + LEASE_SECS`, renewing one it holds. A lease names the key, so a repo id that is
    /// recycled for another project or remote inherits nothing. `Err` when the table is full of
    /// live leases: the launch must fail with that reason, never go on without its copy.
    pub fn grant(&self, device: &str, repo: i64, key: &str, now: i64) -> Result<(), String> {
        let mut leases = self.leases.lock().expect("leases");
        if leases.len() >= MAX_LEASES {
            leases.retain(|_, (until, _)| *until > now);
        }
        if leases.len() >= MAX_LEASES && !leases.contains_key(&(device.to_owned(), repo)) {
            return Err("too many repo copies are leased at once: try again shortly".to_owned());
        }
        leases.insert(
            (device.to_owned(), repo),
            (now + LEASE_SECS, key.to_owned()),
        );
        Ok(())
    }

    fn revoke(&self, device: &str, repo: i64) {
        self.leases
            .lock()
            .expect("leases")
            .remove(&(device.to_owned(), repo));
    }

    /// Ends `device`'s lease on each of `repos` now (a project run ended: P5-05). One lease is
    /// per (device, repo), so this also ends a session's on the same runner; that session has
    /// cloned at launch, and a resume or restart leases again.
    pub fn revoke(&self, device: &str, repos: &[i64]) {
        let mut leases = self.leases.lock().expect("leases");
        for &repo in repos {
            leases.remove(&(device.to_owned(), repo));
        }
    }

    fn holds(&self, device: &str, repo: i64, key: &str, now: i64) -> bool {
        let leases = self.leases.lock().expect("leases");
        (leases.get(&(device.to_owned(), repo))).is_some_and(|(until, k)| *until > now && k == key)
    }
}

/// What `repo`'s mirror must have been made for, if `device` may be served it now: it holds a
/// live lease and the repo's project is active. `None` is the one answer for everything else.
pub async fn servable(
    app: &App,
    mirrors: &Mirrors,
    device: &str,
    repo: i64,
) -> Result<Option<String>, sqlx::Error> {
    let now = app.clock.unix();
    Ok(target(&app.pool, repo)
        .await?
        .filter(|t: &Target| t.active)
        .map(|t| key_of_target(&t))
        .filter(|key| mirrors.holds(device, repo, key, now)))
}

/// Gets the copies of `repos` ready for a session of `project` launched on `device`: each must be
/// a repo of that active project; each is fetched now (`refresh`, so the session starts from the
/// remote's head; a failed fetch keeps the older head) and must hold a copy; then the device is
/// leased each. `Err` is why the session cannot start.
pub async fn for_session(
    app: &App,
    device: &str,
    project: i64,
    repos: &[i64],
) -> Result<(), String> {
    let mirrors = app
        .mirrors
        .as_ref()
        .ok_or("this Core keeps no repo copies")?;
    let mut keys = Vec::with_capacity(repos.len());
    for &repo in repos {
        let t = target(&app.pool, repo).await.map_err(|e| e.to_string())?;
        match t.filter(|t| t.project == project && t.active) {
            Some(t) => keys.push(key_of_target(&t)),
            None => {
                return Err(format!(
                    "repo {repo} is not a repo of the session's active project"
                ));
            }
        }
    }
    let fetched = futures_util::future::join_all(repos.iter().map(|&r| refresh(app, r))).await;
    for (&repo, fetched) in repos.iter().zip(fetched) {
        if let Err(r) = fetched
            && r != Refused::Off
        {
            return Err(format!("repo {repo} could not be fetched: {r:?}"));
        }
        let m = store::mirror(&app.pool, repo)
            .await
            .map_err(|e| e.to_string())?;
        if m.as_ref().and_then(|m| m.head.as_ref()).is_none() {
            let why = m.and_then(|m| m.error).unwrap_or_default();
            return Err(format!("the Core has no copy of repo {repo} yet: {why}"));
        }
    }
    let now = app.clock.unix();
    for (&repo, key) in repos.iter().zip(&keys) {
        mirrors.grant(device, repo, key, now)?;
    }
    Ok(())
}

/// Takes back the leases a session that is over held: its runner's (device, repo) leases for the
/// repos of its workspace, unless another live session of the same project runs on that runner
/// (it needs them). Called where a supervisor finds the session over and where a launch fails.
pub async fn release_session(app: &App, s: &crate::store::agents::Session) {
    let (Some(mirrors), Some(project)) = (app.mirrors.as_ref(), s.project_id) else {
        return;
    };
    let Some(w) = s
        .workspace
        .as_ref()
        .and_then(|w| serde_json::from_value::<ainkrad_proto::runner::Workspace>(w.clone()).ok())
    else {
        return;
    };
    let busy: Result<i64, _> = sqlx::query_scalar(
        "SELECT count(*) FROM core_agent_sessions WHERE runner = ? AND project_id = ? \
         AND id != ? AND state NOT IN ('ended', 'lost')",
    )
    .bind(&s.runner)
    .bind(project)
    .bind(&s.id)
    .fetch_one(&app.pool)
    .await;
    // On a read failure the leases stay: they expire on their own.
    if busy == Ok(0) {
        for repo in std::iter::once(&w).chain(&w.also).filter_map(|w| w.mirror) {
            mirrors.revoke(&s.runner, repo);
        }
    }
}

/// Leases `repo` to `device` as a launch would, without the fetch (tests).
#[cfg(test)]
pub(crate) async fn grant_now(app: &App, device: &str, repo: i64) {
    let t = target(&app.pool, repo).await.unwrap().expect("a repo");
    let mirrors = app.mirrors.as_ref().expect("mirrors");
    mirrors
        .grant(device, repo, &key_of_target(&t), app.clock.unix())
        .expect("a lease");
}
