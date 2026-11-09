//! The pushes a connection's health calls for (C5, CN5). Pushed, to the `admin` devices of the
//! user the event names (and to no one when it names none), only when the person has to act:
//! `connection.health` with reason `auth_suspected` (the service may have refused the sign-in: a
//! test decides) as `connection_health`, and `auth_failed` (confirmed: sign in again) as
//! `connection_failed`. Every other health change (a cooldown the Core waits out, a recovery) is
//! in-app only. The notification is a fixed title and the connection's id: never its name, an
//! identity, a token or a word the service said.

use serde_json::json;

use super::Notification;
use crate::store::events::StoredEvent;

pub(super) fn notification(e: &StoredEvent) -> Option<Notification> {
    let p = &e.payload.0;
    let user = p["user"].as_i64()?;
    let connection = p["connection"].as_i64()?;
    let (kind, title) = match (e.kind.as_str(), p["reason"].as_str()) {
        ("connection.health", Some("auth_suspected")) => {
            ("connection_health", "A connection needs a check")
        }
        ("connection.health", Some("auth_failed")) => (
            "connection_failed",
            "A connection needs you to sign in again",
        ),
        _ => return None,
    };
    Some(Notification {
        collapse: Some(format!("{kind}:{connection}")),
        user: Some(user),
        ..Notification::new(kind, "admin", title, "", json!({"connection": connection}))
    })
}
