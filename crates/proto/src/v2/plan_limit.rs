//! A harness's plan-limit snapshot (KAN-436 S2; design `2026-11-06-core-account-scheduler` §7.2).
//!
//! A subscription account has no gateway, so its only early warning is what the harness itself
//! reports: Claude's `rate_limit_event` (status, and one window per plan limit with its
//! utilisation and reset time). The runner keeps the latest one and sends it in
//! `AgentEvents::plan_limit`, so the Core can cool the account before the run dies.
//!
//! It is the harness's own structured event, never text the agent wrote, and still only a hint:
//! the Core may cool or exclude an account from it, never disable one or move money.
//!
//! A runner lists [`CAP_PLAN_LIMIT`] among its agent driver's commands when it sends the field;
//! one that does not never sends it, and an older Core ignores it (a plain optional field).

use serde::{Deserialize, Serialize};

/// The command an agent driver lists when its runner reports plan limits.
pub const CAP_PLAN_LIMIT: &str = "plan-limit";

/// The latest plan-limit event of a session, overwritten by each newer one (no sequence number).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanLimit {
    /// The harness's own word: `allowed`, `allowed_warning`, `rejected`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<PlanWindow>,
}

/// One plan window, e.g. Claude's `five_hour` and `seven_day`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanWindow {
    pub name: String,
    /// A fraction of the window's limit: 0.0 to 1.0, and past it at the limit.
    pub utilization: f64,
    /// When the window resets, in seconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{AgentEvents, AgentState};
    use serde_json::json;

    fn events(plan_limit: Option<PlanLimit>) -> AgentEvents {
        AgentEvents {
            session: "as_a".to_owned(),
            state: AgentState::Running,
            last_seq: 0,
            entries: vec![],
            harness_session: None,
            usage: None,
            outcome: None,
            gateway: vec![],
            plan_limit,
        }
    }

    fn snapshot() -> PlanLimit {
        PlanLimit {
            status: "rejected".to_owned(),
            windows: vec![
                PlanWindow {
                    name: "five_hour".to_owned(),
                    utilization: 1.0,
                    resets_at: Some(1792608000),
                },
                PlanWindow {
                    name: "seven_day".to_owned(),
                    utilization: 0.4,
                    resets_at: None,
                },
            ],
        }
    }

    #[test]
    fn it_round_trips_and_is_absent_when_empty() {
        let ev = events(Some(snapshot()));
        let wire = serde_json::to_string(&ev).unwrap();
        assert_eq!(serde_json::from_str::<AgentEvents>(&wire).unwrap(), ev);
        let plain = serde_json::to_value(events(None)).unwrap();
        assert!(plain.get("plan_limit").is_none(), "{plain}");
        let bare = serde_json::to_value(PlanLimit {
            windows: vec![],
            ..snapshot()
        })
        .unwrap();
        assert_eq!(bare, json!({"status": "rejected"}));
    }

    /// An older runner never sends it, and an older Core (a struct without the field) ignores it.
    #[test]
    fn old_peers_are_unaffected() {
        let old_runner = json!({"session": "as_a", "state": "running", "last_seq": 0});
        let ev: AgentEvents = serde_json::from_value(old_runner).unwrap();
        assert!(ev.plan_limit.is_none());
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldEvents {
            session: String,
            state: AgentState,
            last_seq: u64,
            #[serde(default)]
            entries: Vec<serde_json::Value>,
        }
        let wire = serde_json::to_string(&events(Some(snapshot()))).unwrap();
        let old: OldEvents = serde_json::from_str(&wire).unwrap();
        assert_eq!(old.session, "as_a");
        // A window without a reset, as a harness may report.
        let w: PlanWindow =
            serde_json::from_value(json!({"name": "w", "utilization": 0.5})).unwrap();
        assert_eq!(w.resets_at, None);
    }
}
