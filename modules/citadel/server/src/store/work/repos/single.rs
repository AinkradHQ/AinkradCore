//! The single-repo calls (E3.7), on a project's primary repo.

use super::*;

/// Sets the project's primary repo's URL and default branch, adding it (named after the
/// project key) when the project has none. A URL holding credentials or looking like an
/// option, or a bad branch name, is `Error::InvalidArgument`.
pub async fn set_project_repo(pool: &SqlitePool, r: &ProjectRepo) -> Result<(), Error> {
    if let Some(why) = repo_url_problem(&r.url) {
        return Err(invalid(why));
    }
    if !branch_name_ok(&r.default_branch) {
        return Err(invalid(format!("bad branch name {:?}", r.default_branch)));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let updated = sqlx::query(
        "UPDATE project_repos SET url = ?, default_branch = ? WHERE project_id = ? AND is_primary = 1",
    )
    .bind(&r.url)
    .bind(&r.default_branch)
    .bind(r.project_id.0)
    .execute(&mut *tx)
    .await
    .map_err(unique("a repo with that URL"))?;
    if updated.rows_affected() == 0 {
        sqlx::query(
            "INSERT INTO project_repos (project_id, name, url, default_branch, is_primary) \
             SELECT id, lower(key), ?, ?, 1 FROM projects WHERE id = ?",
        )
        .bind(&r.url)
        .bind(&r.default_branch)
        .bind(r.project_id.0)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

fn single(r: Repo) -> ProjectRepo {
    ProjectRepo {
        project_id: r.project_id,
        url: r.url,
        default_branch: r.default_branch,
    }
}

/// The project's primary repo.
pub async fn get_project_repo(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Option<ProjectRepo>, Error> {
    let all = list_repos(pool, project).await?;
    Ok(all.into_iter().find(|r| r.primary).map(single))
}

/// The first repo the issue touches with its key (`CIT-12`); `None` when its
/// project has no repo or the issue is gone.
pub async fn issue_repo(
    pool: &SqlitePool,
    issue: IssueId,
) -> Result<Option<(ProjectRepo, String)>, Error> {
    let Some(key) = issue_key(pool, issue).await? else {
        return Ok(None);
    };
    let first = issue_repos(pool, issue).await?.into_iter().next();
    Ok(first.map(|r| (single(r), key)))
}
