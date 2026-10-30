//! Comments: an issue's thread, idempotent per (issue, key).

use super::*;

macro_rules! comment_columns {
    () => {
        "id, issue_id, author_agent_id, author_user_id, body, run_id, idempotency_key"
    };
}

fn comment(row: SqliteRow) -> Result<Comment, Error> {
    Ok(Comment {
        id: CommentId(row.try_get("id")?),
        issue_id: IssueId(row.try_get("issue_id")?),
        author: actor(&row, "author_agent_id", "author_user_id")?
            .ok_or_else(|| Error::ColumnNotFound("author_agent_id".to_owned()))?,
        body: row.try_get("body")?,
        run_id: row.try_get::<Option<i64>, _>("run_id")?.map(RunId),
        idempotency_key: row.try_get("idempotency_key")?,
    })
}

/// Idempotent per (issue, key): a repeat returns the first comment unchanged.
pub async fn create_comment(pool: &SqlitePool, c: &NewComment) -> Result<Comment, Error> {
    let (agent, user) = actor_columns(Some(c.author));
    let inserted = sqlx::query(concat!(
        "INSERT INTO citadel_comments \
         (issue_id, author_agent_id, author_user_id, body, run_id, idempotency_key) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (issue_id, idempotency_key) DO NOTHING RETURNING ",
        comment_columns!()
    ))
    .bind(c.issue_id.0)
    .bind(agent)
    .bind(user)
    .bind(&c.body)
    .bind(c.run_id.map(|r| r.0))
    .bind(&c.idempotency_key)
    .fetch_optional(pool)
    .await?;
    let row = match inserted {
        Some(row) => row,
        None => {
            sqlx::query(concat!(
                "SELECT ",
                comment_columns!(),
                " FROM citadel_comments WHERE issue_id = ? AND idempotency_key = ?"
            ))
            .bind(c.issue_id.0)
            .bind(&c.idempotency_key)
            .fetch_one(pool)
            .await?
        }
    };
    comment(row)
}

pub async fn get_comment(pool: &SqlitePool, id: CommentId) -> Result<Option<Comment>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        comment_columns!(),
        " FROM citadel_comments WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(comment)
    .transpose()
}

/// The issue's thread, oldest first.
pub async fn list_comments(pool: &SqlitePool, issue_id: IssueId) -> Result<Vec<Comment>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        comment_columns!(),
        " FROM citadel_comments WHERE issue_id = ? ORDER BY id"
    ))
    .bind(issue_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(comment)
    .collect()
}

/// Edits the body only.
pub async fn update_comment(pool: &SqlitePool, c: &Comment) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_comments SET body = ? WHERE id = ?")
        .bind(&c.body)
        .bind(c.id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_comment(pool: &SqlitePool, id: CommentId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_comments WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}
