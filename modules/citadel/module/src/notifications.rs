//! Citadel's event-to-push policy for the Core notifications service. Payloads contain ids only;
//! the Core policy performs the final scope filtering and redaction before delivery.

use ainkrad_core_server::push::{Classifier, Notification};
use ainkrad_core_server::store::events::StoredEvent;
use serde_json::json;

/// The pushes Citadel may raise and the scope a device needs for each (`Module::notification_kinds`).
pub const KINDS: &[(&str, &str)] = &[
    ("citadel.approval_needed", "approve"),
    ("citadel.issue_blocked", "read"),
    ("citadel.loop_breaker", "read"),
    ("citadel.repair_exhausted", "read"),
];

#[derive(Debug, Default, Clone, Copy)]
pub struct Citadel;

impl Classifier for Citadel {
    fn notification(&self, event: &StoredEvent) -> Option<Notification> {
        let payload = &event.payload.0;
        let id = payload["entity_id"].as_i64()?;
        match event.kind.as_str() {
            "audit" if payload["action"] == "citadel.approval.pending" => Some(Notification::new(
                "citadel.approval_needed",
                "approve",
                "Approval needed",
                "",
                json!({"approval_id": id}),
            )),
            "audit" if payload["action"] == "citadel.issue.blocked" => Some(Notification::new(
                "citadel.issue_blocked",
                "read",
                "Issue blocked",
                "",
                json!({"issue_id": id}),
            )),
            "audit" if payload["action"] == "citadel.loop_breaker.tripped" => {
                Some(Notification::new(
                    "citadel.loop_breaker",
                    "read",
                    "Run stopped",
                    "",
                    json!({"issue_id": id}),
                ))
            }
            "audit" if payload["action"] == "citadel.repair.exhausted" => Some(Notification::new(
                "citadel.repair_exhausted",
                "read",
                "Repair exhausted",
                "",
                json!({"issue_id": id}),
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::types::Json;

    #[test]
    fn citadel_notifications_carry_ids_but_no_event_details() {
        let event = StoredEvent {
            seq: 1,
            kind: "audit".to_owned(),
            payload: Json(serde_json::json!({
                "action": "citadel.approval.pending", "entity_id": 9,
                "details": {"secret": "must-not-leave"}
            })),
            at: "2026-10-30T00:00:00.000Z".to_owned(),
        };
        let n = Citadel.notification(&event).unwrap();
        assert_eq!(n.data, json!({"approval_id": 9}));
        assert!(!n.data.to_string().contains("must-not-leave"));
    }

    #[test]
    fn the_core_confines_citadel_pushes_to_its_declared_kinds_and_scopes() {
        use ainkrad_core_server::module::Module;
        use ainkrad_core_server::push::Classifier;
        use ainkrad_core_server::push::modules::Modules;
        use std::sync::Arc;
        let core = Modules(Arc::from(vec![Arc::new(crate::Citadel) as Arc<dyn Module>]));
        let audit = |action: &str, payload: serde_json::Value| {
            let mut p = payload;
            p["action"] = action.into();
            StoredEvent {
                seq: 1,
                kind: "audit".to_owned(),
                payload: Json(p),
                at: "2026-10-30T00:00:00.000Z".to_owned(),
            }
        };
        let id = json!({"entity_id": 7, "details": {"prompt": "terminal $ secret", "token": "x"}});
        for (action, kind, scope) in [
            (
                "citadel.approval.pending",
                "citadel.approval_needed",
                "approve",
            ),
            ("citadel.issue.blocked", "citadel.issue_blocked", "read"),
            (
                "citadel.loop_breaker.tripped",
                "citadel.loop_breaker",
                "read",
            ),
            (
                "citadel.repair.exhausted",
                "citadel.repair_exhausted",
                "read",
            ),
        ] {
            assert!(KINDS.contains(&(kind, scope)));
            let n = core.notification(&audit(action, id.clone())).expect(action);
            assert_eq!((n.kind, n.scope), (kind, scope));
            assert_eq!(n.data.as_object().unwrap().len(), 1, "one id, nothing else");
            assert!(!n.data.to_string().contains("secret"));
        }
        // Not Citadel's, or nothing to point at: no push.
        assert!(
            core.notification(&audit("citadel.issue.created", id.clone()))
                .is_none()
        );
        assert!(core.notification(&audit("thing.blocked", id)).is_none());
        assert!(
            core.notification(&audit("citadel.issue.blocked", json!({})))
                .is_none()
        );
    }
}
