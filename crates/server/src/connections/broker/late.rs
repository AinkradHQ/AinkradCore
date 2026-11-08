//! A call that outlives its caller's wait, and what a finished call tells the gate and health.

use std::sync::Arc;

use sqlx::sqlite::SqlitePool;

use super::{gate, health, run};
use crate::connections::adapter::Registry;
use crate::store::connections::resolve::{self, Context};

pub(super) async fn after(
    gate: &gate::Gate,
    pool: &SqlitePool,
    now: &str,
    (user, agent, id): (i64, Option<&str>, i64),
    ran: &run::Ran,
) {
    if let Some((remaining, reset, retry)) = ran.quota {
        gate.note_upstream(id, remaining, reset, retry);
    }
    // Only a call that reached the service says anything about it: a refusal of ours, and an
    // end the adapter says is not about the credential or the service (a 404, a refused
    // input, a huge answer), tell health nothing at all.
    let feed = ran.out.as_ref().err().and_then(|f| f.feed.as_ref());
    if (ran.out.is_ok() || feed.is_some())
        && let Err(e) = health::forward(pool, user, id, agent, feed, now).await
    {
        tracing::warn!(error = %e, "telling a connection's health failed");
    }
}

/// A write whose caller stopped waiting: it finishes here, tells health, and is audited.
pub(super) struct Late {
    pub(super) pool: SqlitePool,
    pub(super) reg: Registry,
    pub(super) gate: Arc<gate::Gate>,
    pub(super) now: String,
    pub(super) user: i64,
    pub(super) agent: Option<String>,
    pub(super) session: String,
    pub(super) allowlist: Option<Vec<String>>,
    pub(super) connection: i64,
    pub(super) kind: &'static str,
    pub(super) cap: &'static str,
    pub(super) op: String,
}

impl Late {
    pub(super) async fn finish(self, task: tokio::task::JoinHandle<run::Ran>) {
        let Ok(ran) = task.await else { return };
        after(
            &self.gate,
            &self.pool,
            &self.now,
            (self.user, self.agent.as_deref(), self.connection),
            &ran,
        )
        .await;
        let (result, code) = match &ran.out {
            Ok(_) => ("ok", "late_ok".to_owned()),
            Err(f) => (f.result, format!("late_{}", f.code)),
        };
        let cx = Context {
            workspace: self.user,
            user: self.user,
            role: "member",
            agent: self.agent.as_deref(),
            session: Some(&self.session),
            capability: self.cap,
            operation: Some(&self.op),
            resource: None,
            allowlist: self.allowlist.as_deref(),
        };
        let rec = resolve::record_use(
            &self.pool,
            &self.reg,
            Some(self.connection),
            self.kind,
            (&self.op, result, Some(&code)),
            &cx,
        )
        .await;
        if let Err(e) = rec {
            tracing::error!(error = ?e, "recording a late connection use failed");
        }
    }
}
