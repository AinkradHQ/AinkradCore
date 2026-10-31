//! Applying what changed in Linear: a linked issue's fields that won (`pull`), and an issue
//! nobody in Citadel has yet (`import`).

use super::*;

/// A Linear issue's change to apply to its Citadel issue: the fields that won.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pull {
    pub title: Option<String>,
    pub body: Option<String>,
    /// A Linear state type.
    pub state: Option<String>,
    /// Fields both sides changed: (field, which side won).
    pub conflicts: Vec<(&'static str, &'static str)>,
}

/// Applies `p` to `issue` by the system, in one transaction: title and body, the state through
/// the engine's transitions, the next actor; the snapshot takes what was applied. A state the
/// engine cannot reach is not applied, and the snapshot keeps the issue's own, so the next push
/// restores it in Linear (audited `linear.state_refused`). Each conflict is audited
/// `linear.conflict`, the pull `linear.pulled`.
pub async fn pull(pool: &SqlitePool, issue: IssueId, p: &Pull) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let (company, linear) = linked(&mut tx, issue).await?;
    let mut synced = sqlx::query("SELECT * FROM citadel_linear_issues WHERE issue_id = ?")
        .bind(issue.0)
        .fetch_one(&mut *tx)
        .await
        .and_then(link)?
        .synced;
    let system = AuditActor::System;
    let entity = ("issue", issue.0);
    for (field, won) in &p.conflicts {
        let details = json!({"linear": linear, "field": field, "won": won});
        append(&mut tx, company, system, "linear.conflict", entity, details).await?;
    }
    let mut fields = vec![];
    if p.title.is_some() || p.body.is_some() {
        let current = issue_in(&mut tx, issue).await?.ok_or(Error::RowNotFound)?;
        let title = p.title.clone().unwrap_or(current.title);
        let body = p.body.clone().unwrap_or(current.body);
        sqlx::query("UPDATE citadel_issues SET title = ?, body = ? WHERE id = ?")
            .bind(&title)
            .bind(&body)
            .bind(issue.0)
            .execute(&mut *tx)
            .await?;
        if p.title.is_some() {
            fields.push("title");
            synced.title = title;
        }
        if p.body.is_some() {
            fields.push("body");
            synced.body = body;
        }
    }
    if let Some(to) = &p.state {
        let current = issue_in(&mut tx, issue).await?.ok_or(Error::RowNotFound)?;
        let steps = path(current.state, to).ok_or(());
        let mut moved = steps.is_ok();
        for step in steps.unwrap_or_default() {
            match transition_issue_in(&mut tx, issue, &step, system).await {
                Ok(_) => {}
                Err(IssueTransitionError::Db(e)) => return Err(e),
                Err(_) => {
                    moved = false;
                    break;
                }
            }
        }
        let now = issue_in(&mut tx, issue).await?.ok_or(Error::RowNotFound)?;
        // Refused, the snapshot takes Linear's state, so the issue's own differs from it and
        // the next push puts it back in Linear.
        synced.state = if moved {
            state_kind(now.state).to_owned()
        } else {
            to.clone()
        };
        if moved {
            fields.push("state");
        } else {
            let details = json!({"linear": linear, "wanted": to,
                                 "kept": now.state.as_str()});
            append(
                &mut tx,
                company,
                system,
                "linear.state_refused",
                entity,
                details,
            )
            .await?;
        }
    }
    snapshot(&mut tx, issue, &synced).await?;
    let details = json!({"linear": linear, "fields": fields});
    append(&mut tx, company, system, "linear.pulled", entity, details).await?;
    tx.commit().await
}

/// A Linear issue nobody in Citadel has yet: a new task in the project, waiting on the admin,
/// in the state its Linear state type maps to, linked with both sides' state; audited
/// `linear.imported`. Its id.
pub async fn import(
    pool: &SqlitePool,
    project: ProjectId,
    linear_id: &str,
    identifier: &str,
    title: &str,
    body: &str,
    kind: &str,
) -> Result<IssueId, Error> {
    let state = match kind {
        "backlog" => IssueState::Backlog,
        // Finished history is recorded as it is; nothing is reviewed or merged for it.
        "completed" => IssueState::Done,
        "canceled" => IssueState::Cancelled,
        // Linear does not start work here: a started issue arrives as todo, waiting on the
        // admin, who starts it (or hands it to an agent) in Citadel; the next push says so.
        _ => IssueState::Todo,
    };
    let (title, body) = (clip(title, 200), clip(body, 20_000));
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let new = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: title.clone(),
        body: body.clone(),
        state,
        owner: None,
        next_actor: (!state.is_terminal()).then_some(NextActor::Human(ESCALATION_USER)),
        points: None,
        sprint_id: None,
    };
    let created = create_issue_in(&mut tx, &new).await?;
    // Linear's own state: where Citadel did not follow it, the next push says so in Linear.
    let synced = Synced {
        title,
        body,
        state: kind.to_owned(),
        assignee: None,
    };
    insert_link(&mut tx, created.id, linear_id, identifier, &synced).await?;
    let company = company_of(&mut tx, project).await?;
    let details = json!({"linear": identifier});
    let entity = ("issue", created.id.0);
    append(
        &mut tx,
        company,
        AuditActor::System,
        "linear.imported",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(created.id)
}
