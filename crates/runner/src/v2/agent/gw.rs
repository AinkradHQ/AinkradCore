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
use std::fs::File;
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

/// Why a session that holds a gateway grant may not also hold a provider-account secret, in any
/// delivery mode (env, file, askpass): the gateway exists so the key is never in the sandbox, and
/// a second copy under the writable secrets dir would put it there (spec 4.3). `granted` is each
/// redeemed secret's name and variable. Checked once the names are known (a lease is opaque until
/// redeemed) and before anything is written or the gateway's own lease is redeemed.
pub(super) fn account_conflict(
    has_gateway: bool,
    granted: &[(String, String)],
) -> Option<&'static str> {
    (has_gateway
        && granted
            .iter()
            .any(|(name, _)| name.starts_with(ainkrad_proto::v2::ACCOUNT_PREFIX)))
    .then_some("a session served by the gateway may not also hold a provider-account secret")
}

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
    /// `gateway.jsonl`, open for appending (opened once: no directory work per report).
    file: Option<File>,
    /// Lines in the file the Core has acknowledged since it was last rewritten.
    stale: usize,
    /// A report could not be written: nothing more is admitted, for good (a number is never
    /// reused, and a report the disk does not hold is not one a restart can resend).
    broken: bool,
}

/// Acknowledged lines the file keeps before it is rewritten without them.
const COMPACT_AT: usize = 256;

impl Reports {
    /// The reports a restart finds: those the Core has not acknowledged.
    pub(super) fn load(cfg: &AgentConfig, session: &str, meta: &Meta) -> Reports {
        let text = std::fs::read_to_string(path(cfg, session)).unwrap_or_default();
        let all: Vec<GatewayReport> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<GatewayReport>(l).ok())
            .collect();
        let held: VecDeque<GatewayReport> = all
            .iter()
            .filter(|r| r.gw_seq > meta.gw_acked)
            .cloned()
            .collect();
        let last = all.last().map_or(0, |r| r.gw_seq).max(meta.gw_acked);
        Reports {
            stale: all.len() - held.len(),
            held,
            last,
            ..Reports::default()
        }
    }

    fn append(&mut self, cfg: &AgentConfig, session: &str, line: &str) -> std::io::Result<()> {
        if self.file.is_none() {
            self.file = Some(secrets::private_file(&path(cfg, session), true)?);
        }
        let f = self.file.as_mut().expect("opened above");
        f.write_all(line.as_bytes())
    }

    /// Numbers a report (`gw_seq`, and the `epoch` it was made under), writes it, and holds it.
    pub(super) fn push(
        &mut self,
        cfg: &AgentConfig,
        session: &str,
        epoch: u32,
        mut report: GatewayReport,
    ) {
        self.last += 1;
        report.gw_seq = self.last;
        report.epoch = epoch;
        let line = serde_json::to_string(&report).expect("a report serializes") + "\n";
        if let Err(e) = self.append(cfg, session, &line) {
            tracing::error!(session, error = %e, "appending a gateway report failed; the gateway stops admitting requests");
            self.broken = true;
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

    /// The gateway must not admit requests: the Core is too far behind, or a write failed.
    pub(super) fn full(&self) -> bool {
        self.broken || self.held.len() >= MAX_HELD
    }

    /// Drops the reports the Core acknowledged from memory.
    fn drop_acked(&mut self, after: u64) {
        while self.held.front().is_some_and(|r| r.gw_seq <= after) {
            self.held.pop_front();
            self.stale += 1;
        }
    }

    /// Rewrites the file without the acknowledged reports once enough pile up. Only after the
    /// acknowledgement is saved in the session's state: a crash in between leaves lines the
    /// state already counts as acknowledged, never a file whose numbers could be reused.
    fn compact(&mut self, cfg: &AgentConfig, session: &str) {
        if self.stale >= COMPACT_AT || (self.held.is_empty() && self.stale > 0) {
            let text: String = self
                .held
                .iter()
                .map(|r| serde_json::to_string(r).expect("a report serializes") + "\n")
                .collect();
            let tmp = path(cfg, session).with_extension("jsonl.tmp");
            let done = secrets::private_file(&tmp, false)
                .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
                .and_then(|()| std::fs::rename(&tmp, path(cfg, session)));
            match done {
                Ok(()) => {
                    self.file = None; // the old file is gone: open the new one on the next append
                    self.stale = 0;
                }
                Err(e) => {
                    tracing::error!(session, error = %e, "compacting the gateway reports failed")
                }
            }
        }
    }
}

/// The Core holds the reports up to `after`: those are dropped here (and noted in the state).
pub(super) fn ack(cfg: &AgentConfig, session: &str, live: &mut Live, after: u64) {
    let after = after.min(live.reports.last);
    if after > live.meta.gw_acked {
        live.reports.drop_acked(after);
        live.meta.gw_acked = after;
        // The acknowledgement is on disk before the report file is touched, so a crash can never
        // leave the file shorter than the numbers the state says were used.
        save_meta(cfg, session, &live.meta);
        live.reports.compact(cfg, session);
        if let Some(g) = live.gateway.as_ref() {
            g.meter().set_unreported(live.reports.full());
        }
    }
    // Everything delivered and nothing more to come: the file goes, the state stays.
    if live.meta.state == AgentState::Ended && live.reports.held.is_empty() {
        live.reports.file = None;
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
        epoch: u32,
    ) {
        let (me, session) = (Arc::clone(self), session.to_owned());
        self.with(&session, |live, _, _| live.gw_forwarding = true);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                me.with(&session, |live, cfg, s| match event {
                    Event::Report(report) => {
                        // The epoch of the start the gateway was opened under, not whatever the
                        // session has become by the time the report arrives.
                        live.reports.push(cfg, s, epoch, report);
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
            // Every report is in: an ended session may now say so.
            me.with(&session, |live, _, _| live.gw_forwarding = false);
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
            if !super::holds_slot(live.meta.state) {
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
