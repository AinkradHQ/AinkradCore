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

/// Records the state of a repo's mirror on the Core machine: the head it fetched, or why it could
/// not. Not audited: a fetch is routine, like a usage tick.
pub async fn set_mirror(
    pool: &SqlitePool,
    repo_id: i64,
    head: Option<&str>,
    fetched_at: Option<&str>,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO core_project_mirrors (repo_id, head, fetched_at, error) VALUES (?, ?, ?, ?) \
         ON CONFLICT (repo_id) DO UPDATE SET head = excluded.head, \
         fetched_at = excluded.fetched_at, error = excluded.error",
    )
    .bind(repo_id)
    .bind(head)
    .bind(fetched_at)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mirror(pool: &SqlitePool, repo_id: i64) -> Result<Option<Mirror>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT repo_id, head, fetched_at, error FROM core_project_mirrors WHERE repo_id = ?",
    )
    .bind(repo_id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(Mirror {
            repo_id: r.try_get("repo_id")?,
            head: r.try_get("head")?,
            fetched_at: r.try_get("fetched_at")?,
            error: r.try_get("error")?,
        })
    })
    .transpose()
}
