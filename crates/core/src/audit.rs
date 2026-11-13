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

/// What started an action (E1): who or what was at the start of it, not who clicked last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginKind {
    /// A person, through a paired device (`reference` = the device id).
    Person,
    /// A scheduled job (`reference` = its name).
    Schedule,
    /// A Brain import (set by the Brain module).
    BrainImport,
    /// Brain distillation (set by the Brain module).
    BrainDistil,
    /// An AI session (`reference` = its id); the root says who started the session.
    AiSession,
    /// An AI session handing work to another (reserved: set when hand-off exists).
    Handoff,
    /// The Core on its own: startup, sweeps, recovery.
    System,
}

impl OriginKind {
    pub const ALL: [Self; 7] = [
        Self::Person,
        Self::Schedule,
        Self::BrainImport,
        Self::BrainDistil,
        Self::AiSession,
        Self::Handoff,
        Self::System,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Schedule => "schedule",
            Self::BrainImport => "brain_import",
            Self::BrainDistil => "brain_distil",
            Self::AiSession => "ai_session",
            Self::Handoff => "handoff",
            Self::System => "system",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// The origin of one action and the root of its chain (the first link: what a person or
/// schedule started). For a first link, root and origin are the same.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditOrigin {
    pub kind: OriginKind,
    pub reference: Option<String>,
    pub root_kind: OriginKind,
    pub root_reference: Option<String>,
}

impl AuditOrigin {
    /// A first link: its own root.
    pub fn new(kind: OriginKind, reference: Option<String>) -> Self {
        Self {
            kind,
            root_kind: kind,
            root_reference: reference.clone(),
            reference,
        }
    }

    /// A later link that keeps `self`'s root: `self` started something that `kind` carried on.
    pub fn then(&self, kind: OriginKind, reference: Option<String>) -> Self {
        Self {
            kind,
            reference,
            root_kind: self.root_kind,
            root_reference: self.root_reference.clone(),
        }
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
    /// What started it; `None` on rows from before origins (shown as unknown).
    pub origin: Option<AuditOrigin>,
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
    fn origin_kinds_round_trip_and_root_is_kept() {
        for k in OriginKind::ALL {
            assert_eq!(OriginKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(OriginKind::parse("robot"), None);
        let p = AuditOrigin::new(OriginKind::Person, Some("d_1".into()));
        let s = p.then(OriginKind::AiSession, Some("as_1".into()));
        assert_eq!(
            (s.root_kind, s.root_reference.as_deref()),
            (OriginKind::Person, Some("d_1"))
        );
        assert_eq!(
            s.then(OriginKind::Handoff, None).root_kind,
            OriginKind::Person
        );
    }

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
