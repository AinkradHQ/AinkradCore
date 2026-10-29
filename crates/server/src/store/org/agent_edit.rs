//! Editing an agent (API minor 17): role, description, harness, model, effort, sandbox, runner
//! tags, reporting line, instructions and guidelines, checked in core (`AgentChange::invalid`) and
//! applied in one `BEGIN IMMEDIATE` transaction, audited as `agent.updated`.

use std::str::FromStr;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{AgentChange, AgentStatus, UnknownVariant};
use serde_json::{Map, Value, json};
use sqlx::sqlite::SqliteRow;
use sqlx::{Error, Row};

use super::service::{append_org_event, check_manager_in};
use super::*;

/// An optional enum column: `None` while NULL.
pub(super) fn opt_text<T: FromStr<Err = UnknownVariant>>(
    row: &SqliteRow,
    column: &str,
) -> Result<Option<T>, Error> {
    let value: Option<String> = row.try_get(column)?;
    value
        .map(|v| {
            v.parse().map_err(|e| Error::ColumnDecode {
                index: column.to_owned(),
                source: Box::new(e),
            })
        })
        .transpose()
}

/// Applies `c` to the agent and appends `agent.updated` by `actor`; its details name the
/// `fields` changed, and the new value of each short one. A terminated agent is refused
/// (`OrgError::Terminated`), a bad change is `InvalidArgument`, a manager of another company
/// `OtherCompany`, one that reports to the agent `Cycle`.
pub async fn edit_agent(
    pool: &SqlitePool,
    id: AgentId,
    c: &AgentChange,
    actor: AuditActor,
) -> Result<Agent, OrgError> {
    if let Some(why) = c.invalid() {
        return Err(Error::InvalidArgument(why).into());
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let mut a = get_agent_in(&mut tx, id).await?.ok_or(OrgError::NotFound)?;
    if a.status == AgentStatus::Terminated {
        return Err(OrgError::Terminated);
    }
    if let Some(m) = c.reports_to {
        check_manager_in(&mut tx, id, a.company_id.0, m).await?;
        a.reports_to = m;
    }
    let mut set = Map::new();
    if let Some(v) = &c.role {
        a.role = v.trim().to_owned();
        set.insert("role".into(), json!(a.role));
    }
    if let Some(v) = c.harness {
        a.harness = v;
        set.insert("harness".into(), json!(v.as_str()));
    }
    if let Some(v) = &c.model {
        a.model = v.trim().to_owned();
        set.insert("model".into(), json!(a.model));
    }
    if let Some(v) = c.effort {
        a.profile.effort = v;
        set.insert("effort".into(), json!(v.map(|e| e.as_str())));
    }
    if let Some(v) = c.sandbox {
        a.profile.sandbox = v;
        set.insert("sandbox".into(), json!(v.map(|s| s.as_str())));
    }
    if let Some(v) = &c.runner_tags {
        a.runner_tags = v.clone();
        set.insert("runner_tags".into(), json!(v));
    }
    if let Some(m) = c.reports_to {
        set.insert("reports_to".into(), json!(m.map(|m| m.0)));
    }
    let mut fields: Vec<String> = set.keys().cloned().collect();
    if let Some(v) = &c.description {
        a.profile.description.clone_from(v);
        fields.push("description".to_owned());
    }
    if let Some(v) = &c.instructions {
        a.profile.instructions.clone_from(v);
        fields.push("instructions".to_owned());
    }
    if let Some(v) = &c.guidelines {
        a.profile.guidelines.clone_from(v);
        fields.push("guidelines".to_owned());
    }
    let p = &a.profile;
    let row = sqlx::query(concat!(
        "UPDATE agents SET role = ?, harness = ?, model = ?, runner_tags = ?, reports_to = ?, \
         description = ?, effort = ?, sandbox = ?, instructions = ?, guidelines = ? \
         WHERE id = ? RETURNING ",
        agent_columns!()
    ))
    .bind(&a.role)
    .bind(a.harness.as_str())
    .bind(&a.model)
    .bind(Json(&a.runner_tags))
    .bind(a.reports_to.map(|m| m.0))
    .bind(&p.description)
    .bind(p.effort.map(|e| e.as_str()))
    .bind(p.sandbox.map(|s| s.as_str()))
    .bind(&p.instructions)
    .bind(Json(&p.guidelines))
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    let updated = agent(row)?;
    let mut details = Value::Object(set);
    details["fields"] = json!(fields);
    let entity = ("agent", id.0);
    append_org_event(
        &mut tx,
        a.company_id,
        actor,
        "agent.updated",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(updated)
}

/// The agent `id` inside the caller's transaction.
pub(crate) async fn get_agent_in(
    conn: &mut sqlx::SqliteConnection,
    id: AgentId,
) -> Result<Option<Agent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        agent_columns!(),
        " FROM agents WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(agent)
    .transpose()
}
