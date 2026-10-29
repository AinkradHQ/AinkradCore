//! Permission escalations on a runner connection (E3.10).

use ainkrad_core::exec::RunState;
use ainkrad_core::gov::{ApprovalId, ApprovalStatus};
use serde_json::Value;

use super::{Session, cancel, error};
use crate::store::exec::{allowed_by_rule, escalate};
use crate::store::gov::get_approval;
use ainkrad_proto::runner::ServerMessage;

/// An escalation this connection waits on.
pub(super) struct Waiting {
    approval: ApprovalId,
    run: i64,
    id: String,
}

impl Session {
    /// Opens (or finds) the approval for request `id` of `run`, and waits on it.
    pub(super) async fn escalate(
        &mut self,
        run: i64,
        id: String,
        tool: &str,
        input: &Value,
        timeout_secs: Option<u64>,
    ) -> Option<ServerMessage> {
        let current = match self.own(run).await {
            Ok(r) => r,
            Err(reply) => return Some(*reply),
        };
        if current.state != RunState::Running {
            return Some(cancel(run, format!("run is {}", current.state.as_str())));
        }
        let now = self.now();
        // "Allow for this issue" (decision #34): a live rule answers at once.
        match allowed_by_rule(&self.app.pool, &current, &id, tool, input, &now).await {
            Ok(Some(rule)) => {
                tracing::info!(run, tool, %rule, "allowed by the issue's rule");
                let reply = Some(format!("allowed for this issue ({rule})"));
                let approved = true;
                return Some(ServerMessage::Approval {
                    run,
                    id,
                    approved,
                    reply,
                });
            }
            Ok(None) => {}
            Err(e) => return Some(error(e.to_string())),
        }
        match escalate(
            &self.app.pool,
            &current,
            &id,
            tool,
            input,
            timeout_secs,
            &now,
        )
        .await
        {
            Ok(approval) => {
                tracing::info!(run, approval = approval.0, tool, "permission escalated");
                if !self.waiting.iter().any(|w| w.approval == approval) {
                    self.waiting.push(Waiting { approval, run, id });
                }
                None
            }
            Err(e) => Some(error(e.to_string())),
        }
    }

    /// The answers to escalations decided since the last look.
    pub(super) async fn decided(&mut self) -> Vec<ServerMessage> {
        let mut answers = vec![];
        let mut still = vec![];
        for w in std::mem::take(&mut self.waiting) {
            match get_approval(&self.app.pool, w.approval).await {
                Ok(Some(a)) if a.status != ApprovalStatus::Pending => {
                    answers.push(ServerMessage::Approval {
                        run: w.run,
                        id: w.id,
                        approved: a.status == ApprovalStatus::Approved,
                        reply: a.reply,
                    });
                }
                // Deleted: nobody will decide it; the runner's timeout denies it.
                Ok(None) => {}
                Ok(Some(_)) => still.push(w),
                Err(e) => {
                    tracing::error!(approval = w.approval.0, error = %e, "reading an approval failed");
                    still.push(w);
                }
            }
        }
        self.waiting = still;
        answers
    }
}
