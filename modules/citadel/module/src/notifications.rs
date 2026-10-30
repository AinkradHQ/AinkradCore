//! Citadel's event-to-push policy for the Core notifications service. Payloads contain ids only;
//! the Core policy performs the final scope filtering and redaction before delivery.

use ainkrad_core_server::push::{Classifier, Notification};
use ainkrad_core_server::store::events::StoredEvent;
use serde_json::json;

#[derive(Debug, Default, Clone, Copy)]
pub struct Citadel;

impl Classifier for Citadel {
    fn notification(&self, event: &StoredEvent) -> Option<Notification> {
        let payload = &event.payload.0;
        let id = payload["entity_id"].as_i64()?;
        match event.kind.as_str() {
            "audit" if payload["action"] == "citadel.approval.pending" => Some(Notification::new(
                "approval_needed",
                "approve",
                "Approval needed",
                "",
                json!({"approval_id": id}),
            )),
            "audit" if payload["action"] == "citadel.issue.blocked" => Some(Notification::new(
                "issue_blocked",
                "read",
                "Issue blocked",
                "",
                json!({"issue_id": id}),
            )),
            "audit" if payload["action"] == "citadel.loop_breaker.tripped" => {
                Some(Notification::new(
                    "loop_breaker",
                    "read",
                    "Run stopped",
                    "",
                    json!({"issue_id": id}),
                ))
            }
            "audit" if payload["action"] == "citadel.repair.exhausted" => Some(Notification::new(
                "repair_exhausted",
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
}
