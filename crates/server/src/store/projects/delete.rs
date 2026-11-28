//! Deleting a project for good (API 112): the second step after archiving. One write transaction
//! removes the project and what hangs off it; the caller removes the mirror folders (the ids come
//! back) and the Brain drops its link when it reads the `project.deleted` event. AI sessions of
//! the project stay as history, no longer tied to it.

use serde_json::json;
use sqlx::SqlitePool;

use super::{Error, Who, get, record, refused, repos};
use crate::store::secrets;

/// Deletes archived project `id`; returns the ids of its repos, whose mirror folders are now
/// orphans. 409 `project_running` while a run or a task job of it is live, 409 `not_archived`
/// unless it is archived, 404 for no such project. Audited and emitted as `project.deleted`.
pub async fn delete(pool: &SqlitePool, id: i64, who: Who<'_>) -> Result<Vec<i64>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let p = get(&mut tx, id).await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_project_runs WHERE project_id = ?1 \
                 AND state IN ('starting', 'running', 'stopping')) \
              + (SELECT count(*) FROM core_hw_jobs WHERE project_id = ?1 \
                 AND state IN ('queued', 'syncing', 'running'))",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if live > 0 {
        return refused(
            "project_running",
            "stop the project's run before deleting it",
        );
    }
    if p.state != "archived" {
        return refused("not_archived", "archive the project first, then delete it");
    }
    let repo_ids: Vec<i64> = repos(&mut tx, id)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();
    // The secrets go through the secrets store, so each deletion is audited and its leases end.
    if let Some(group) = p.secret_group {
        let names: Vec<String> =
            sqlx::query_scalar("SELECT name FROM core_secrets WHERE group_id = ?")
                .bind(group)
                .fetch_all(&mut *tx)
                .await?;
        for n in &names {
            secrets::delete_in(&mut tx, n, who.by_device, who.actor).await?;
        }
    }
    for sql in [
        "DELETE FROM core_hw_jobs WHERE project_id = ?1",
        "DELETE FROM core_run_vars WHERE config_id IN \
         (SELECT id FROM core_run_configs WHERE project_id = ?1)",
        "DELETE FROM core_run_configs WHERE project_id = ?1",
        "DELETE FROM core_run_env_vars WHERE project_id = ?1",
        "DELETE FROM core_run_envs WHERE project_id = ?1",
        "DELETE FROM core_project_runs WHERE project_id = ?1",
        "DELETE FROM core_project_run_specs WHERE project_id = ?1",
        "DELETE FROM core_approval_rules WHERE project_id = ?1",
        "DELETE FROM core_cmd_history WHERE project_id = ?1",
        "DELETE FROM core_hw_cache WHERE project_id = ?1",
        "DELETE FROM core_project_mirrors WHERE repo_id IN \
         (SELECT id FROM core_project_repos WHERE project_id = ?1)",
        "DELETE FROM core_project_repos WHERE project_id = ?1",
        "UPDATE core_agent_sessions SET project_id = NULL WHERE project_id = ?1",
        "DELETE FROM core_projects WHERE id = ?1",
    ] {
        sqlx::query(sql).bind(id).execute(&mut *tx).await?;
    }
    if let Some(group) = p.secret_group {
        sqlx::query("DELETE FROM core_secret_groups WHERE id = ?")
            .bind(group)
            .execute(&mut *tx)
            .await?;
    }
    let details = json!({"slug": p.slug, "name": p.name, "repos": repo_ids.len(),
                         "by_device": who.by_device});
    record(&mut tx, who.actor, "project.deleted", id, details, true).await?;
    tx.commit().await?;
    Ok(repo_ids)
}
