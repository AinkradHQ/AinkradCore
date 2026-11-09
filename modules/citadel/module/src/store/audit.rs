//! The one way the module appends an audit row, for every slice. The Core's audit event has an
//! actor, an action, an entity and a JSON `details`; the monolith's also had `company_id` and
//! `run_id` columns, which here are keys of `details` (a reader filters with `json_extract`).
//! Every action is `citadel.<action>` and must be declared in `kinds::AUDIT_ACTIONS`.
//!
//! As in the monolith, every `issue.*` event about an issue also says which project it is in
//! (`project_id`), so a client reloads one project whichever write path appended it.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core_server::store::audit;
use serde_json::{Value, json};
use sqlx::{Error, SqliteConnection};

/// An audit row before it is appended; `action` is the monolith's name (`issue.created`), the
/// `citadel.` prefix is added here.
pub struct Event<'a> {
    pub actor: AuditActor,
    pub action: &'a str,
    /// The changed row: its kind (`issue`) and id.
    pub entity: Option<(&'a str, i64)>,
    pub company: Option<i64>,
    pub run: Option<i64>,
    /// A JSON object; anything else is kept under `value`.
    pub details: Value,
}

impl<'a> Event<'a> {
    /// A row by `actor` for `action` with no entity, company, run or details yet.
    pub fn new(actor: AuditActor, action: &'a str) -> Self {
        Self {
            actor,
            action,
            entity: None,
            company: None,
            run: None,
            details: json!({}),
        }
    }

    pub fn entity(mut self, kind: &'a str, id: i64) -> Self {
        self.entity = Some((kind, id));
        self
    }

    pub fn company(mut self, id: i64) -> Self {
        self.company = Some(id);
        self
    }

    pub fn run(mut self, id: i64) -> Self {
        self.run = Some(id);
        self
    }

    pub fn details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
}

/// Appends `e` on `conn` (pass `&mut *tx` inside a write transaction).
pub async fn append(conn: &mut SqliteConnection, e: Event<'_>) -> Result<(), Error> {
    append_seq(conn, e).await.map(drop)
}

/// [`append`], returning the row's sequence number (a wake's idempotency key names it).
pub async fn append_seq(conn: &mut SqliteConnection, e: Event<'_>) -> Result<i64, Error> {
    let mut details = match e.details {
        Value::Object(o) => o,
        other => [("value".to_owned(), other)].into_iter().collect(),
    };
    if let Some(c) = e.company {
        details.entry("company_id").or_insert(json!(c));
    }
    if let Some(r) = e.run {
        details.entry("run_id").or_insert(json!(r));
    }
    if let (true, Some(("issue", id))) = (e.action.starts_with("issue."), e.entity) {
        let project: Option<i64> =
            sqlx::query_scalar("SELECT project_id FROM citadel_issues WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some(p) = project {
            details.entry("project_id").or_insert(json!(p));
        }
    }
    let event = NewAuditEvent {
        actor: e.actor,
        action: format!("citadel.{}", e.action),
        entity: e.entity.map(|(kind, id)| AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        details: Value::Object(details).to_string(),
    };
    audit::append(conn, &event).await.map(|row| row.seq.0)
}
