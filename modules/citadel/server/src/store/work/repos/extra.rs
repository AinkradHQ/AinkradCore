//! What a repo shows beyond its row (API minor 18): its stack, and the issues using it now.

use sqlx::{Error, SqlitePool};

use super::ProjectId;

/// The stack of each of the project's repos, `(repo id, stack)`.
pub async fn repo_stacks(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Vec<(i64, String)>, Error> {
    sqlx::query_as("SELECT id, stack FROM project_repos WHERE project_id = ?")
        .bind(project.0)
        .fetch_all(pool)
        .await
}

/// Sets repo `id`'s stack ("Swift", "Rust · Node"); `false` when it is gone.
pub async fn set_repo_stack(pool: &SqlitePool, id: i64, stack: &str) -> Result<bool, Error> {
    let stack = stack.trim();
    if stack.chars().count() > 200 || stack.contains('\n') {
        return Err(Error::InvalidArgument(
            "a stack is one line of at most 200 characters".into(),
        ));
    }
    sqlx::query("UPDATE project_repos SET stack = ? WHERE id = ?")
        .bind(stack)
        .bind(id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() > 0)
}

/// The keys of the issues working a repo now, `(repo id, key)`, by number: those in progress or in
/// review that it is approved for, or, with none approved, the primary repo.
pub async fn repos_in_use(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Vec<(i64, String)>, Error> {
    sqlx::query_as(
        "SELECT r.id, p.key || '-' || i.number FROM project_repos r \
         JOIN issues i ON i.project_id = r.project_id JOIN projects p ON p.id = r.project_id \
         WHERE r.project_id = ?1 AND i.state IN ('in_progress', 'in_review') \
         AND (EXISTS (SELECT 1 FROM issue_repos x WHERE x.issue_id = i.id AND x.repo_id = r.id \
                 AND x.state = 'approved') \
             OR (r.is_primary = 1 AND NOT EXISTS (SELECT 1 FROM issue_repos x \
                 WHERE x.issue_id = i.id AND x.state = 'approved'))) \
         ORDER BY i.number",
    )
    .bind(project.0)
    .fetch_all(pool)
    .await
}
