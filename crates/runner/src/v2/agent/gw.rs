//! The driver's side of the auth gateway (KAN-435 G4): the reports a session's gateway makes,
//! kept on a channel and a numbering of their own, and the ops that reach a live gateway.
//!
//! - **Reports** (`Reports`): numbered `gw_seq` from 1 by the driver, in the order they arrive.
//!   They are written to `<dir>/<session>/gateway.jsonl` (0600) before they are kept in memory, so
//!   a runner restart does not lose spend, held until the Core acknowledges them (`gw_after`), and
//!   sent with every answer. They are never entries of the transcript: only the gateway task
//!   feeds them, and the harness's output has no path in.
//! - **Fail closed.** At [`MAX_HELD`] unacknowledged reports the gateway refuses new requests
//!   (429) until the Core catches up; a report is never dropped to make room.
//! - **`agent.limit`** moves a live session's ceiling; one that arrives while the gateway is
//!   still being opened is applied as it is installed.
//! - **`gateway.test`** is the one-shot request behind `POST /accounts/{id}/test`.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

use ainkrad_proto::v2::{
    AgentEvents, AgentLimit, CAP_GATEWAY, ErrorCode, GatewayReport, GatewayTest, GatewayTested,
    StreamError,
};
use serde_json::json;
use tokio::sync::mpsc::UnboundedReceiver;

use super::*;
use crate::gateway::{Event, check, dial::Dialer, meter::Meter};

/// Unacknowledged reports a session may hold before its gateway stops admitting requests.
pub(super) const MAX_HELD: usize = 10_000;

fn path(cfg: &AgentConfig, session: &str) -> PathBuf {
    cfg.dir.join(session).join("gateway.jsonl")
}

#[derive(Default)]
pub(super) struct Reports {
    /// Unacknowledged, oldest first.
    held: VecDeque<GatewayReport>,
    /// The newest `gw_seq` there is.
    last: u64,
    /// The newest `gw_seq` an answer carried.
    shown: u64,
}

impl Reports {
    /// The reports a restart finds: those the Core has not acknowledged.
    pub(super) fn load(cfg: &AgentConfig, session: &str, meta: &Meta) -> Reports {
        let text = std::fs::read_to_string(path(cfg, session)).unwrap_or_default();
        let held: VecDeque<GatewayReport> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<GatewayReport>(l).ok())
            .filter(|r| r.gw_seq > meta.gw_acked)
            .collect();
        let last = held.back().map_or(meta.gw_acked, |r| r.gw_seq);
        Reports {
            held,
            last,
            shown: 0,
        }
    }

    fn push(&mut self, cfg: &AgentConfig, session: &str, mut report: GatewayReport) {
        self.last += 1;
        report.gw_seq = self.last;
        let line = serde_json::to_string(&report).expect("a report serializes") + "\n";
        let written = secrets::private_dir(&cfg.dir.join(session))
            .and_then(|()| secrets::private_file(&path(cfg, session), true))
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = written {
            tracing::error!(session, error = %e, "appending a gateway report failed");
        }
        self.held.push_back(report);
    }

    pub(super) fn fresh(&self) -> bool {
        self.last > self.shown
    }

    pub(super) fn mark_shown(&mut self) {
        self.shown = self.last;
    }

    /// The reports to send now: the oldest unacknowledged, at most one read's worth.
    pub(super) fn batch(&self) -> Vec<GatewayReport> {
        self.held.iter().take(256).cloned().collect()
    }

    fn full(&self) -> bool {
        self.held.len() >= MAX_HELD
    }
}

/// The Core holds the reports up to `after`: those are dropped here (and noted in the state).
pub(super) fn ack(cfg: &AgentConfig, session: &str, live: &mut Live, after: u64) {
    let after = after.min(live.reports.last);
    if after > live.meta.gw_acked {
        while live.reports.held.front().is_some_and(|r| r.gw_seq <= after) {
            live.reports.held.pop_front();
        }
        live.meta.gw_acked = after;
        save_meta(cfg, session, &live.meta);
        if let Some(g) = live.gateway.as_ref() {
            g.meter().set_unreported(live.reports.full());
        }
    }
    // Everything delivered and nothing more to come: the file goes, the state stays.
    if live.meta.state == AgentState::Ended && live.reports.held.is_empty() {
        let _ = std::fs::remove_file(path(cfg, session));
    }
}

impl AgentDriver {
    /// Hands what a session's gateway reports to the session, as it arrives. It ends when the
    /// gateway and every request it was serving are gone, so the reports of requests a stop
    /// aborted (charged as approximate) still arrive.
    pub(super) fn forward_gateway(
        self: &Arc<Self>,
        session: &str,
        mut events: UnboundedReceiver<Event>,
        meter: Arc<Meter>,
    ) {
        let (me, session) = (Arc::clone(self), session.to_owned());
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                me.with(&session, |live, cfg, s| match event {
                    Event::Report(report) => {
                        live.reports.push(cfg, s, report);
                        meter.set_unreported(live.reports.full());
                    }
                    Event::Closed(why) => {
                        // Said in the transcript, not silent; the harness sees refused connections.
                        live.gateway = None;
                        let entry = json!({"type": "gateway_closed", "reason": why});
                        push(cfg, s, live, entry);
                    }
                });
            }
        });
    }

    /// A stop was seen before the harness started: the run ends as cancelled and starts nothing.
    pub(super) async fn stopped_before_start(&self, session: &str, run: i64, cleanup: bool) {
        if cleanup {
            self.harness.cleanup_agent_workspace(session, run).await;
        }
        self.harness.session_env(run, None);
        let why = "stopped before the harness started".to_owned();
        self.end(session, Outcome::Cancelled { reason: why });
    }

    pub(super) fn is_stopped(&self, session: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(session)
            .is_some_and(|l| l.stopped)
    }

    fn offers_gateway(&self) -> Result<(), StreamError> {
        self.sandbox
            .capabilities()
            .contains(&CAP_GATEWAY)
            .then_some(())
            .ok_or_else(|| {
                refuse(
                    ErrorCode::UnsupportedCommand,
                    "this runner does not offer the auth gateway",
                )
            })
    }

    /// `agent.limit`: the session's ceiling becomes `req.ceiling` (an absolute total, spent
    /// included; `u64::MAX` lifts it). A zero in either dimension refuses every request from now on
    /// and aborts the open streams. The session's answer carries the reports not yet acknowledged.
    pub fn limit(&self, req: AgentLimit) -> Result<AgentEvents, StreamError> {
        self.offers_gateway()?;
        let answer = {
            let mut all = self.sessions.lock().unwrap();
            let live = all.get_mut(&req.session).ok_or_else(no_session)?;
            if live.meta.state != AgentState::Running {
                return Err(refuse(ErrorCode::InvalidArgs, "the session is not running"));
            }
            match live.gateway.as_ref() {
                Some(g) => g.meter().set_ceiling(req.ceiling),
                // Its gateway is still being opened: the limit is applied when it is installed.
                None if live.granted && !live.stopped => live.pending_limit = Some(req.ceiling),
                None if live.granted => {}
                None => {
                    return Err(refuse(
                        ErrorCode::InvalidArgs,
                        "the session has no auth gateway",
                    ));
                }
            }
            events(&req.session, live, live.meta.last_seq)
        };
        self.changed.notify_waiters();
        Ok(answer)
    }

    /// `gateway.test`: redeems the lease, checks the key against its host, makes one free
    /// request, and answers with the status class and the latency.
    pub async fn gateway_test(&self, req: GatewayTest) -> Result<GatewayTested, StreamError> {
        self.offers_gateway()?;
        let own = crate::egress::host_addresses()
            .map_err(|e| refuse(ErrorCode::Internal, format!("the gateway test: {e}")))?;
        let dialer = Arc::new(Dialer::new(own).with_total(Duration::from_secs(30)));
        self.gateway_test_with(req, dialer).await
    }

    pub(super) async fn gateway_test_with(
        &self,
        req: GatewayTest,
        dialer: Arc<Dialer>,
    ) -> Result<GatewayTested, StreamError> {
        check::run(&req, self.redeem.as_ref(), dialer)
            .await
            .map_err(|why| refuse(ErrorCode::InvalidArgs, why))
    }
}

// Linux only, as the gateway's first release is: a macOS temp dir is too long for the socket path.
#[cfg(all(test, target_os = "linux"))]
mod tests;
