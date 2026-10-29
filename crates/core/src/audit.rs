//! Audit log: an append-only record of who did what to which row (brainstorm §7).
//! Every write path appends here, inside its own transaction.
//!
//! Timestamps are ISO-8601 text, as stored. Ids are plain values: an event outlives the
//! entity it names.

use crate::ids::{UserId, id};

id!(AuditSeq);

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditActor {
    User(UserId),
    System,
}

impl AuditActor {
    /// Storage form: kind text and the actor's id (none for the system).
    pub fn parts(self) -> (&'static str, Option<i64>) {
        match self {
            Self::User(id) => ("user", Some(id.0)),
            Self::System => ("system", None),
        }
    }

    /// The inverse of [`parts`](Self::parts); `None` for an unknown or inconsistent pair.
    pub fn from_parts(kind: &str, id: Option<i64>) -> Option<Self> {
        Some(match (kind, id) {
            ("user", Some(id)) => Self::User(UserId(id)),
            ("system", None) => Self::System,
            _ => return None,
        })
    }
}

/// The row an event is about, e.g. `("device_key", 42)`. Kind is lowercase snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditEntity {
    pub kind: String,
    pub id: i64,
}

/// An event before it is appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    pub actor: AuditActor,
    /// Dotted lowercase, e.g. `device_key.revoked`.
    pub action: String,
    pub entity: Option<AuditEntity>,
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
    pub details: String,
}

/// Narrows an audit listing; a `None` field matches every event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub entity: Option<AuditEntity>,
    pub actor: Option<AuditActor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_round_trips_through_parts() {
        for a in [AuditActor::User(UserId(1)), AuditActor::System] {
            let (kind, id) = a.parts();
            assert_eq!(AuditActor::from_parts(kind, id), Some(a));
        }
        assert_eq!(AuditActor::from_parts("system", Some(1)), None);
        assert_eq!(AuditActor::from_parts("user", None), None);
        assert_eq!(AuditActor::from_parts("robot", Some(1)), None);
    }
}
