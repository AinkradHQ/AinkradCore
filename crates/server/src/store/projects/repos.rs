//! A project's git repos and their mirrors (split from the parent module).

use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use ainkrad_proto::runner::{branch_name_ok, repo_url_problem};

use super::{Error, Mirror, Repo, Who, get, record, refused, repos};

fn repo_name_ok(name: &str) -> bool {
    (1..=100).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Adds a repo to an active project. The first one is primary; `primary` makes a later one
/// primary (the old one steps down).
pub async fn add_repo(
    pool: &SqlitePool,
    project_id: i64,
    name: &str,
    remote_url: &str,
    default_branch: &str,
    primary: bool,
    who: Who<'_>,
) -> Result<Repo, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let r = add_repo_in(
        &mut tx,
        project_id,
        (name, remote_url, default_branch),
        primary,
        who,
    )
    .await?;
    tx.commit().await?;
    Ok(r)
}

/// [`add_repo`] inside the caller's write transaction.
pub(super) async fn add_repo_in(
    tx: &mut SqliteConnection,
    project_id: i64,
    (name, remote_url, default_branch): (&str, &str, &str),
    primary: bool,
    who: Who<'_>,
) -> Result<Repo, Error> {
    if !repo_name_ok(name) {
        return refused(
            "bad_request",
            "a repo name is 1-100 of [A-Za-z0-9._-], not starting with . or -",
        );
    }
    if let Some(why) = repo_url_problem(remote_url) {
        return refused("bad_request", &why);
    }
    if !branch_name_ok(default_branch) {
        return refused("bad_request", "bad default branch name");
    }
    if get(tx, project_id).await?.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let dup: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_project_repos WHERE project_id = ? AND (name = ? OR remote_url = ?)",
    )
    .bind(project_id)
    .bind(name)
    .bind(remote_url)
    .fetch_one(&mut *tx)
    .await?;
    if dup > 0 {
        return refused("conflict", "the project has a repo of that name or remote");
    }
    let first = repos(tx, project_id).await?.is_empty();
    let primary = primary || first;
    if primary {
        sqlx::query("UPDATE core_project_repos SET is_primary = 0 WHERE project_id = ?")
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(project_id)
    .bind(name)
    .bind(remote_url)
    .bind(default_branch)
    .bind(primary)
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"repo": name, "primary": primary, "by_device": who.by_device});
    record(
        tx,
        who.actor,
        "project.repo_added",
        project_id,
        details,
        false,
    )
    .await?;
    let r = repos(tx, project_id)
        .await?
        .into_iter()
        .find(|r| r.id == id);
    r.ok_or_else(|| Error::Db(sqlx::Error::RowNotFound))
}

/// Removes a repo (and its mirror row). The primary goes last: while others remain, name a new
/// primary first.
pub async fn remove_repo(
    pool: &SqlitePool,
    project_id: i64,
    repo_id: i64,
    who: Who<'_>,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    if get(&mut tx, project_id).await?.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let all = repos(&mut tx, project_id).await?;
    let Some(old) = all.iter().find(|r| r.id == repo_id) else {
        return refused("not_found", "no such repo in the project");
    };
    if old.is_primary && all.len() > 1 {
        return refused(
            "conflict",
            "set another repo primary before removing this one",
        );
    }
    sqlx::query("DELETE FROM core_project_repos WHERE id = ?")
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"repo": old.name, "by_device": who.by_device});
    record(
        &mut tx,
        who.actor,
        "project.repo_removed",
        project_id,
        details,
        false,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Makes `repo_id` the project's one primary repo.
pub async fn set_primary(
    pool: &SqlitePool,
    project_id: i64,
    repo_id: i64,
    who: Who<'_>,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    if get(&mut tx, project_id).await?.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let all = repos(&mut tx, project_id).await?;
    let Some(new) = all.iter().find(|r| r.id == repo_id) else {
        return refused("not_found", "no such repo in the project");
    };
    // Clear first: the partial unique index is checked per row, not per statement.
    sqlx::query("UPDATE core_project_repos SET is_primary = 0 WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE core_project_repos SET is_primary = 1 WHERE id = ?")
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"repo": new.name, "by_device": who.by_device});
    record(
        &mut tx,
        who.actor,
        "project.repo_primary_set",
        project_id,
        details,
        false,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Makes `branch` the repo's branch (`default_branch`: what the copy's HEAD, a run and a
/// session check out), audited as `project.repo_branch_set`. The caller checked the copy has it.
pub async fn set_branch(
    pool: &SqlitePool,
    project_id: i64,
    repo_id: i64,
    branch: &str,
    who: Who<'_>,
) -> Result<(), Error> {
    if !branch_name_ok(branch) {
        return refused("bad_request", "bad branch name");
    }
    let mut tx = crate::store::begin_write(pool).await?;
    if get(&mut tx, project_id).await?.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let all = repos(&mut tx, project_id).await?;
    let Some(r) = all.iter().find(|r| r.id == repo_id) else {
        return refused("not_found", "no such repo in the project");
    };
    sqlx::query("UPDATE core_project_repos SET default_branch = ? WHERE id = ?")
        .bind(branch)
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"repo": r.name, "from": r.default_branch, "branch": branch,
                         "by_device": who.by_device});
    record(
        &mut tx,
        who.actor,
        "project.repo_branch_set",
        project_id,
        details,
        false,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Records the state of a repo's mirror on the Core machine: the head it fetched, or why it could
/// not. Not audited: a fetch is routine, like a usage tick.
pub async fn set_mirror(
    pool: &SqlitePool,
    repo_id: i64,
    head: Option<&str>,
    fetched_at: Option<&str>,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    let state = if error.is_some() { "failed" } else { "ready" };
    let kept = (head, fetched_at);
    set_mirror_state(pool, repo_id, (state, None), kept, (error, None)).await
}

/// [`set_mirror`] with the explicit `state` (`fetching`, `ready`, `failed`) and the classified
/// `reason` of a failure. A fetch is marked `fetching` first (with its `started_at`); the older
/// head and time are passed in again. Every change of state is emitted as `project.mirror_changed`
/// (a payload of ids and words: no URL, no token).
pub async fn set_mirror_state(
    pool: &SqlitePool,
    repo_id: i64,
    (state, started_at): (&str, Option<&str>),
    (head, fetched_at): (Option<&str>, Option<&str>),
    (error, reason): (Option<&str>, Option<&str>),
) -> Result<(), sqlx::Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let project: Option<i64> =
        sqlx::query_scalar("SELECT project_id FROM core_project_repos WHERE id = ?")
            .bind(repo_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(project) = project else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO core_project_mirrors (repo_id, head, fetched_at, error, state, reason, started_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (repo_id) DO UPDATE SET head = excluded.head, \
         fetched_at = excluded.fetched_at, error = excluded.error, state = excluded.state, \
         reason = excluded.reason, started_at = excluded.started_at",
    )
    .bind(repo_id)
    .bind(head)
    .bind(fetched_at)
    .bind(error)
    .bind(state)
    .bind(reason)
    .bind(started_at)
    .execute(&mut *tx)
    .await?;
    let payload = json!({"id": project, "repo": repo_id, "state": state, "reason": reason});
    crate::store::events::append(&mut tx, "project.mirror_changed", &payload).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn mirror(pool: &SqlitePool, repo_id: i64) -> Result<Option<Mirror>, sqlx::Error> {
    mirror_in(&mut *pool.acquire().await?, repo_id).await
}

/// [`mirror`] on a connection the caller already holds. Asking the pool for a second connection
/// while holding one starves a small pool: a few such callers at once wait on each other.
pub async fn mirror_in(
    conn: &mut SqliteConnection,
    repo_id: i64,
) -> Result<Option<Mirror>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT repo_id, head, fetched_at, error, state, reason, started_at \
         FROM core_project_mirrors WHERE repo_id = ?",
    )
    .bind(repo_id)
    .fetch_optional(conn)
    .await?;
    row.map(|r| {
        Ok(Mirror {
            repo_id: r.try_get("repo_id")?,
            head: r.try_get("head")?,
            fetched_at: r.try_get("fetched_at")?,
            error: r.try_get("error")?,
            state: r.try_get("state")?,
            reason: r.try_get("reason")?,
            started_at: r.try_get("started_at")?,
        })
    })
    .transpose()
}
