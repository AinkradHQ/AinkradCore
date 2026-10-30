//! What a run is told, and where it works: the agent's standing instructions, the issue and the
//! reason it was woken, and the project's repos as the session's workspace. Never a credential:
//! the prompt is stored with the session.

use ainkrad_proto::runner::{Policy, Workspace};
use serde_json::{Value, json};
use sqlx::{Error, SqliteConnection};

use super::*;
use crate::store::work::issue_branch_in;

/// The most of an issue's body a prompt carries.
const BODY_MAX: usize = 16 * 1024;

pub(super) struct Brief {
    pub prompt: String,
    pub workspace: Option<Value>,
    pub policy: Value,
}

fn cut(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// The brief of a run of `agent` on `issue`, woken because of `reason`.
pub(super) async fn brief(
    conn: &mut SqliteConnection,
    agent: AgentId,
    issue: Option<IssueId>,
    reason: &str,
) -> Result<Brief, Error> {
    let (name, role, instructions, guidelines, sandbox): (
        String,
        String,
        String,
        String,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT name, role, instructions, guidelines, sandbox FROM citadel_agents WHERE id = ?",
    )
    .bind(agent.0)
    .fetch_one(&mut *conn)
    .await?;
    let mut prompt = format!("You are {name}, {role}.\n");
    if !instructions.trim().is_empty() {
        prompt.push_str(&format!("\n{}\n", instructions.trim()));
    }
    let rules: Vec<String> = serde_json::from_str(&guidelines).unwrap_or_default();
    for rule in rules {
        prompt.push_str(&format!("- {rule}\n"));
    }
    prompt.push_str(&format!("\nYou were woken: {reason}\n"));
    let mut workspace = None;
    if let Some(issue) = issue {
        let row: Option<(String, String, String, String, i64)> = sqlx::query_as(
            "SELECT p.key || '-' || i.number, i.title, i.body, i.state, i.project_id \
             FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
        )
        .bind(issue.0)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some((key, title, body, state, project)) = row {
            prompt.push_str(&format!(
                "\nIssue {key} ({state}): {title}\n\n{}\n",
                cut(&body, BODY_MAX)
            ));
            workspace = workspace_in(conn, issue, project).await?;
        }
    }
    // Never full-auto: a tool outside the allowlist asks (and is decided as an approval).
    let mode = match sandbox.as_deref() {
        Some("workspace-write") => "accept_edits",
        _ => "ask",
    };
    let mut policy = json!(Policy::default());
    policy["mode"] = json!(mode);
    Ok(Brief {
        prompt,
        workspace,
        policy,
    })
}

async fn workspace_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
    project: i64,
) -> Result<Option<Value>, Error> {
    let repos: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT name, url, default_branch FROM citadel_project_repos WHERE project_id = ? \
         ORDER BY is_primary DESC, position, id",
    )
    .bind(project)
    .fetch_all(&mut *conn)
    .await?;
    let Some(branch) = issue_branch_in(conn, issue).await? else {
        return Ok(None);
    };
    let mut all = repos.into_iter().map(|(name, repo, base)| Workspace {
        repo,
        base,
        branch: branch.clone(),
        push: false,
        name,
        also: vec![],
        expected_head: None,
    });
    Ok(all.next().map(|mut first| {
        first.also = all.collect();
        json!(first)
    }))
}

#[cfg(test)]
mod tests {
    use super::cut;

    #[test]
    fn a_long_body_is_cut_on_a_character_boundary() {
        assert_eq!(cut("héllo", 2), "hé");
        assert_eq!(cut("abc", 10), "abc");
    }
}
