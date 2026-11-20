//! Adoption and the watch supervisor (E15-2, spec 4.2).
//!
//! At the first start of a Core that has the workspace, every LIVE session on a remote runner
//! becomes an `overflow` session: it gets its `ws_path` in the workspace and its runner folder
//! stays the writer, streamed to the Core by `sync.watch` as soon as that runner advertises
//! `sync`. A session that already ended keeps `ws_path` NULL: the old `agent.files/revert/write/
//! docs` runner ops serve it until 0.11. Adoption is idempotent (it only touches rows with no
//! `ws_path`), so it simply runs at every start.
//!
//! The supervisor then keeps a watch open for each overflow session whose runner can sync, and
//! finishes it (final diff, `sync.drop`) once the session is over.

use std::path::PathBuf;
use std::time::Duration;

use ainkrad_core::ids::UserId;
use ainkrad_proto::v2::{CAP_SYNC, OP_SYNC_WATCH};
use sqlx::{SqliteConnection, SqlitePool};

use super::paths::{DEFAULT_ROOT, SessionKey, Workspace};
use super::rules::Rules;
use super::watch::{self, WatchArgs};
use crate::api::App;
use crate::scheduler::Clock;
use crate::store::gov;

/// `place_reason` of a session that overflowed to a runner.
pub const OVERFLOW: &str = "overflow";
/// How long a session's watch lease lasts before the supervisor renews it.
const LEASE_SECS: i64 = 3600;

/// The workspace this Core uses: `AINKRAD_WORKSPACE_ROOT` (the `workspace.root` setting) or the
/// installer's `/var/lib/ainkrad-ws`.
pub fn workspace() -> Workspace {
    Workspace::new(std::env::var("AINKRAD_WORKSPACE_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.into()))
}

/// The folder a session's files are in on the Core, when it has one (`ws_path`), else `None`: a
/// legacy session, served by its runner.
pub async fn ws_path(pool: &SqlitePool, session: &str) -> Result<Option<PathBuf>, sqlx::Error> {
    let p: Option<Option<String>> =
        sqlx::query_scalar("SELECT ws_path FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(pool)
            .await?;
    Ok(p.flatten().map(PathBuf::from))
}

/// Whether `session` runs on a runner and is synced to the Core by watch.
pub async fn is_overflow(pool: &SqlitePool, session: &str) -> Result<bool, sqlx::Error> {
    let r: Option<Option<String>> =
        sqlx::query_scalar("SELECT place_reason FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(pool)
            .await?;
    Ok(r.flatten().as_deref() == Some(OVERFLOW))
}

/// The built-in runner's device ids (the Core's own host).
async fn built_in(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? \
         AND device_id IS NOT NULL",
    )
    .bind(gov::LOCAL_ENROL_SAS)
    .fetch_all(pool)
    .await
}

/// Moves every live session on a remote runner into the workspace as `overflow`. Returns how many.
pub async fn adopt(pool: &SqlitePool, ws: &Workspace) -> Result<usize, sqlx::Error> {
    let core = built_in(pool).await?;
    let rows: Vec<(String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, runner, user_id, project_id FROM core_agent_sessions \
         WHERE state NOT IN ('ended', 'lost') AND ws_path IS NULL",
    )
    .fetch_all(pool)
    .await?;
    let mut n = 0;
    for (id, runner, user, project) in rows {
        if core.contains(&runner) {
            continue;
        }
        let key = SessionKey {
            id: &id,
            user: UserId(user),
            project,
        };
        let Some(dir) = ws.session_dir(&key) else {
            continue;
        };
        sqlx::query(
            "UPDATE core_agent_sessions SET ws_path = ?, place_reason = ? \
             WHERE id = ? AND ws_path IS NULL",
        )
        .bind(dir.to_string_lossy().as_ref())
        .bind(OVERFLOW)
        .bind(&id)
        .execute(pool)
        .await?;
        n += 1;
    }
    Ok(n)
}

/// Opens a watch for each overflow session that has none and whose runner is online and lists
/// `sync`; finishes the watch of each session that is over.
pub async fn tick(app: &App) -> Result<(), sqlx::Error> {
    let rows: Vec<(String, String, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT id, runner, ws_path, project_id, state FROM core_agent_sessions \
         WHERE place_reason = ? AND ws_path IS NOT NULL",
    )
    .bind(OVERFLOW)
    .fetch_all(&app.pool)
    .await?;
    let runners = app.hub.runners();
    let now = app.clock.now();
    let now = crate::scheduler::unix_secs(&now).unwrap_or(0);
    for (id, runner, path, project, state) in rows {
        let live = !matches!(state.as_str(), "ended" | "lost");
        let watching = app.hub.sync.watches.get(&id);
        if !live {
            if watching.is_some() {
                if let Err(e) = watch::finish(&app.hub, &id).await {
                    tracing::warn!(session = %id, error = %e, "the final sync of a session failed");
                }
            }
            continue;
        }
        let syncs = runners.get(&runner).is_some_and(|r| {
            r.online
                && r.drivers.iter().any(|d| {
                    d.name == CAP_SYNC
                        || d.commands
                            .iter()
                            .any(|c| c == CAP_SYNC || c == OP_SYNC_WATCH)
                })
        });
        let running = watching.as_ref().is_some_and(|w| w.is_live());
        if !syncs || running {
            continue;
        }
        // A watch that is not live is replaced (its task ended without a clean finish).
        if watching.is_some() {
            let _ = watch::finish(&app.hub, &id).await;
        }
        let project = project.unwrap_or(0);
        let lease = app
            .hub
            .sync
            .leases
            .issue(&runner, project, &id, LEASE_SECS, now);
        let args = WatchArgs {
            device: runner,
            session: id.clone(),
            project,
            lease,
            root: PathBuf::from(path),
            rules: Rules::default(),
        };
        if let Err(e) = watch::start(&app.hub, args) {
            tracing::warn!(session = %id, error = %e, "a session watch did not start");
        }
    }
    Ok(())
}

/// The supervisor: adopts once, then every few seconds keeps the watches right.
pub async fn supervise(app: App) {
    match adopt(&app.pool, &workspace()).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            sessions = n,
            "live remote sessions adopted into the workspace"
        ),
        Err(e) => tracing::warn!(error = %e, "workspace adoption failed"),
    }
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if let Err(e) = tick(&app).await {
            tracing::warn!(error = %e, "the workspace supervisor failed a pass");
        }
    }
}

/// The runner reported `id`'s folder. When the session is the built-in runner's and the folder is
/// exactly its place in the workspace (`session_dir`), the folder is the Core's own: `ws_path` is
/// set (spec 4.1, "the Core checks that this matches the runner's `meta.folder`"). A folder
/// anywhere else leaves `ws_path` NULL and the session keeps being served by its runner.
/// Returns the folder when this call bound it.
pub async fn bind_folder(
    conn: &mut SqliteConnection,
    id: &str,
    reported: &str,
) -> Result<Option<PathBuf>, sqlx::Error> {
    let row: Option<(String, i64, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT runner, user_id, project_id, ws_path FROM core_agent_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((runner, user, project, None)) = row else {
        return Ok(None);
    };
    let core: Vec<String> = sqlx::query_scalar(
        "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? \
         AND device_id IS NOT NULL",
    )
    .bind(gov::LOCAL_ENROL_SAS)
    .fetch_all(&mut *conn)
    .await?;
    let key = SessionKey {
        id,
        user: UserId(user),
        project,
    };
    let want = workspace().session_dir(&key);
    if !core.contains(&runner)
        || want.as_deref().map(|p| p.to_string_lossy()).as_deref() != Some(reported)
    {
        return Ok(None);
    }
    sqlx::query("UPDATE core_agent_sessions SET ws_path = ? WHERE id = ? AND ws_path IS NULL")
        .bind(reported)
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(want)
}

/// Takes the documents baseline of a session whose folder was just bound (off the async
/// threads: it walks the folder).
pub fn baseline(session: String, folder: PathBuf) {
    tokio::task::spawn_blocking(move || {
        let Ok(tree) = super::fs::Tree::open(&folder) else {
            return;
        };
        if let Err(e) = super::docs::take_baseline(workspace().root(), &session, &tree) {
            tracing::debug!(session, error = %e, "the documents baseline was not taken");
        }
    });
}

/// The folder an `agent.start` to `runner` names (`AgentStart::folder`): the session's place in the
/// workspace when `runner` is the built-in one, else `None` and the runner picks its own.
pub async fn core_folder(
    pool: &SqlitePool,
    session: &str,
    runner: &str,
) -> Result<Option<String>, sqlx::Error> {
    if !built_in(pool).await?.iter().any(|r| r == runner) {
        return Ok(None);
    }
    let row: Option<(i64, Option<i64>)> =
        sqlx::query_as("SELECT user_id, project_id FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(pool)
            .await?;
    let Some((user, project)) = row else {
        return Ok(None);
    };
    let key = SessionKey {
        id: session,
        user: UserId(user),
        project,
    };
    Ok(workspace()
        .session_dir(&key)
        .map(|p| p.to_string_lossy().into_owned()))
}
