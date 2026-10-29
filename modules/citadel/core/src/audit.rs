//! Audit log: an append-only record of who did what to which row (brainstorm §7).
//! Every write path from E2 on appends here, inside its own transaction.
//!
//! Timestamps are ISO-8601 text, as stored. Ids are plain values: an event outlives the
//! entity, company and run it names.

use crate::exec::{RunId, RunnerId};
use crate::org::{AgentId, CompanyId, id};
use crate::work::UserId;

id!(AuditSeq);

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditActor {
    User(UserId),
    Agent(AgentId),
    Runner(RunnerId),
    System,
}

impl AuditActor {
    /// Storage form: kind text and the actor's id (none for the system).
    pub fn parts(self) -> (&'static str, Option<i64>) {
        match self {
            Self::User(id) => ("user", Some(id.0)),
            Self::Agent(id) => ("agent", Some(id.0)),
            Self::Runner(id) => ("runner", Some(id.0)),
            Self::System => ("system", None),
        }
    }

    /// The inverse of [`parts`](Self::parts); `None` for an unknown or inconsistent pair.
    pub fn from_parts(kind: &str, id: Option<i64>) -> Option<Self> {
        Some(match (kind, id) {
            ("user", Some(id)) => Self::User(UserId(id)),
            ("agent", Some(id)) => Self::Agent(AgentId(id)),
            ("runner", Some(id)) => Self::Runner(RunnerId(id)),
            ("system", None) => Self::System,
            _ => return None,
        })
    }
}

/// The row an event is about, e.g. `("issue", 42)`. Kind is lowercase snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditEntity {
    pub kind: String,
    pub id: i64,
}

/// An event before it is appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    pub actor: AuditActor,
    /// Dotted lowercase, e.g. `issue.state_changed`.
    pub action: String,
    pub entity: Option<AuditEntity>,
    pub company_id: Option<CompanyId>,
    pub run_id: Option<RunId>,
    /// Must be valid JSON.
    pub details: String,
}

/// Immutable once appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Strictly increasing in append order.
    pub seq: AuditSeq,
    pub at: String,
    pub actor: AuditActor,
    pub action: String,
    pub entity: Option<AuditEntity>,
    pub company_id: Option<CompanyId>,
    pub run_id: Option<RunId>,
    pub details: String,
}

/// Narrows an audit listing; a `None` field matches every event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub company_id: Option<CompanyId>,
    pub run_id: Option<RunId>,
    pub entity: Option<AuditEntity>,
    pub actor: Option<AuditActor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_round_trips_through_parts() {
        for a in [
            AuditActor::User(UserId(1)),
            AuditActor::Agent(AgentId(2)),
            AuditActor::Runner(RunnerId(3)),
            AuditActor::System,
        ] {
            let (kind, id) = a.parts();
            assert_eq!(AuditActor::from_parts(kind, id), Some(a));
        }
        assert_eq!(AuditActor::from_parts("system", Some(1)), None);
        assert_eq!(AuditActor::from_parts("agent", None), None);
        assert_eq!(AuditActor::from_parts("robot", Some(1)), None);
    }
}
