//! Editing an issue's own fields (API minor 18): title, body, kind, priority level, criteria.

use crate::domain::work::{Criterion, IssueKind, PriorityLevel};
use ainkrad_core::audit::AuditActor;

use super::checkout::{append_issue_event, issue_in};
use super::*;

/// The most acceptance criteria an issue holds, and the longest one.
const MAX_CRITERIA: usize = 100;
const MAX_CRITERION: usize = 500;

/// The fields to change; `None` keeps a field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssuePatch {
    pub title: Option<String>,
    pub body: Option<String>,
    pub kind: Option<IssueKind>,
    pub priority_level: Option<PriorityLevel>,
    /// Replaces the whole list.
    pub criteria: Option<Vec<Criterion>>,
}

/// `all` trimmed, or `Error::InvalidArgument` when there are too many or one is empty or long.
pub(crate) fn clean_criteria(all: &[Criterion]) -> Result<Vec<Criterion>, Error> {
    if all.len() > MAX_CRITERIA
        || all
            .iter()
            .any(|c| c.text.trim().is_empty() || c.text.len() > MAX_CRITERION)
    {
        return Err(invalid(&format!(
            "at most {MAX_CRITERIA} criteria of 1 to {MAX_CRITERION} characters"
        )));
    }
    Ok(all
        .iter()
        .map(|c| Criterion {
            text: c.text.trim().to_owned(),
            done: c.done,
        })
        .collect())
}

fn invalid(why: &str) -> Error {
    Error::InvalidArgument(why.to_owned())
}

/// Applies `p` and appends `issue.updated` (the `fields` changed, and a kind or priority
/// level's `from` and `to`) by `actor`, in one `BEGIN IMMEDIATE` transaction; nothing changed,
/// nothing audited. The `priority` flag follows the level (true from `high`). A subtask stays a
/// subtask and no other issue becomes one (`Error::InvalidArgument`, as for an empty title or
/// criterion); `None`: no such issue.
pub async fn patch_issue(
    pool: &SqlitePool,
    id: IssueId,
    p: &IssuePatch,
    actor: AuditActor,
) -> Result<Option<Issue>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let Some(mut i) = issue_in(&mut tx, id).await? else {
        return Ok(None);
    };
    let mut fields = vec![];
    let mut details = serde_json::Map::new();
    if let Some(title) = p.title.as_deref().map(str::trim) {
        if title.is_empty() {
            return Err(invalid("an issue needs a title"));
        }
        if title != i.title {
            i.title = title.to_owned();
            fields.push("title");
        }
    }
    if let Some(body) = p.body.as_ref().filter(|b| **b != i.body) {
        i.body.clone_from(body);
        fields.push("body");
    }
    if let Some(kind) = p.kind.filter(|k| *k != i.kind) {
        if kind == IssueKind::Subtask || i.kind == IssueKind::Subtask {
            return Err(invalid(
                "a subtask stays a subtask, and no other issue becomes one",
            ));
        }
        details.insert(
            "kind".into(),
            serde_json::json!({"from": i.kind.as_str(), "to": kind.as_str()}),
        );
        i.kind = kind;
        fields.push("kind");
    }
    if let Some(level) = p.priority_level.filter(|l| *l != i.priority_level) {
        let (from, to) = (i.priority_level.as_str(), level.as_str());
        details.insert(
            "priority_level".into(),
            serde_json::json!({"from": from, "to": to}),
        );
        i.priority_level = level;
        i.priority = level.is_high();
        fields.push("priority_level");
    }
    if let Some(all) = p.criteria.as_ref() {
        let all = clean_criteria(all)?;
        if all != i.criteria {
            i.criteria = all;
            fields.push("criteria");
        }
    }
    if fields.is_empty() {
        return Ok(Some(i));
    }
    let row = sqlx::query(concat!(
        "UPDATE citadel_issues SET title = ?, body = ?, kind = ?, priority_level = ?, priority = ?, \
         criteria = ? WHERE id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(&i.title)
    .bind(&i.body)
    .bind(i.kind.as_str())
    .bind(i.priority_level.as_str())
    .bind(i.priority)
    .bind(criteria_json(&i.criteria))
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    let updated = issue(row)?;
    details.insert("fields".into(), serde_json::json!(fields));
    let details = serde_json::Value::Object(details).to_string();
    append_issue_event(&mut tx, &updated, actor, "issue.updated", None, details).await?;
    tx.commit().await?;
    Ok(Some(updated))
}

/// The fields of an epic to change; `None` keeps a field, `Some(None)` clears an optional one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpicPatch {
    pub title: Option<String>,
    pub status: Option<crate::domain::work::EpicStatus>,
    pub color: Option<Option<String>>,
    pub starts_on: Option<Option<String>>,
    pub ends_on: Option<Option<String>>,
    pub requirement_id: Option<Option<crate::domain::work::RequirementId>>,
}

/// Applies `p` to the epic and appends `epic.updated` (the `fields` changed) by `actor`, in one
/// `BEGIN IMMEDIATE` transaction. A colour that is not `#rrggbb`, a date that is not a
/// `YYYY-MM-DD` day, an end before the start, an empty title, or a requirement of another company
/// is `Error::InvalidArgument`; `None`: no such epic.
pub async fn patch_epic(
    pool: &SqlitePool,
    id: crate::domain::work::EpicId,
    p: &EpicPatch,
    actor: AuditActor,
) -> Result<Option<crate::domain::work::Epic>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let Some(mut e) = crate::store::work::get_epic_in(&mut tx, id).await? else {
        return Ok(None);
    };
    let mut fields = vec![];
    if let Some(title) = p.title.as_deref().map(str::trim) {
        if title.is_empty() {
            return Err(invalid("an epic needs a title"));
        }
        if title != e.title {
            e.title = title.to_owned();
            fields.push("title");
        }
    }
    if let Some(status) = p.status.filter(|s| *s != e.status) {
        e.status = status;
        fields.push("status");
    }
    if let Some(color) = p.color.as_ref().filter(|c| **c != e.color) {
        if color
            .as_deref()
            .is_some_and(|c| !crate::domain::work::is_hex_color(c))
        {
            return Err(invalid("a colour is #rrggbb"));
        }
        e.color.clone_from(color);
        fields.push("color");
    }
    for (new, old, name) in [
        (&p.starts_on, &mut e.starts_on, "starts_on"),
        (&p.ends_on, &mut e.ends_on, "ends_on"),
    ] {
        if let Some(day) = new.as_ref().filter(|d| **d != *old) {
            if let Some(day) = day {
                let ok: bool = sqlx::query_scalar("SELECT date(?1) IS ?1")
                    .bind(day)
                    .fetch_one(&mut *tx)
                    .await?;
                if !ok {
                    return Err(invalid(&format!("{name} is a YYYY-MM-DD day")));
                }
            }
            old.clone_from(day);
            fields.push(name);
        }
    }
    if let (Some(from), Some(to)) = (&e.starts_on, &e.ends_on)
        && to < from
    {
        return Err(invalid("an epic cannot end before it starts"));
    }
    if let Some(req) = p.requirement_id.filter(|r| *r != e.requirement_id) {
        if let Some(r) = req {
            let ours: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM citadel_requirements r JOIN citadel_projects p \
                 ON p.company_id = r.company_id WHERE r.id = ? AND p.id = ?)",
            )
            .bind(r.0)
            .bind(e.project_id.0)
            .fetch_one(&mut *tx)
            .await?;
            if !ours {
                return Err(invalid("the requirement is not in the epic's company"));
            }
        }
        e.requirement_id = req;
        fields.push("requirement_id");
    }
    if fields.is_empty() {
        return Ok(Some(e));
    }
    sqlx::query(
        "UPDATE citadel_epics SET title = ?, status = ?, color = ?, starts_on = ?, ends_on = ?, \
         requirement_id = ? WHERE id = ?",
    )
    .bind(&e.title)
    .bind(e.status.as_str())
    .bind(&e.color)
    .bind(&e.starts_on)
    .bind(&e.ends_on)
    .bind(e.requirement_id.map(|r| r.0))
    .bind(id.0)
    .execute(&mut *tx)
    .await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(e.project_id.0)
        .fetch_one(&mut *tx)
        .await?;
    let details = serde_json::json!({"fields": fields, "title": e.title});
    crate::store::audit::append(
        &mut tx,
        crate::store::audit::Event::new(actor, "epic.updated")
            .entity("epic", id.0)
            .company(company)
            .details(details),
    )
    .await?;
    tx.commit().await?;
    Ok(Some(e))
}
