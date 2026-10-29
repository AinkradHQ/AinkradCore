//! What a runner says of itself (1.20): its `RunnerInfo` from `Hello` and `Status` is stored;
//! the admin's log requests go out as `ReadLog` and come back as `LogTail`, redacted again
//! here; the admin's Power Nap preference goes out in `Welcome` and, when it changes, `Prefs`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use citadel_core::exec::{RunnerId, RunnerStatus};
use ainkrad_proto::runner::{RunnerInfo, ServerMessage};
use tokio::sync::oneshot;

use super::Session;
use crate::store::exec::{get_runner, record_info, record_platform};

/// A log tail, or why not.
pub type Tail = Result<Vec<String>, String>;

/// Log tails the admin asked for, waiting for their runners (in memory: a tail is only worth
/// having while someone waits for it).
#[derive(Default)]
pub struct LogTails {
    next: AtomicI64,
    asked: Mutex<HashMap<RunnerId, Vec<(i64, u32)>>>,
    waiting: Mutex<HashMap<i64, oneshot::Sender<Tail>>>,
}

impl LogTails {
    /// Asks `runner` for its last `lines` lines: the request and where the answer comes.
    pub fn ask(&self, runner: RunnerId, lines: u32) -> (i64, oneshot::Receiver<Tail>) {
        let request = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().unwrap().insert(request, tx);
        let mut asked = self.asked.lock().unwrap();
        asked.entry(runner).or_default().push((request, lines));
        (request, rx)
    }

    /// Gives up on `request` (its caller stopped waiting).
    pub fn forget(&self, request: i64) {
        self.waiting.lock().unwrap().remove(&request);
        for list in self.asked.lock().unwrap().values_mut() {
            list.retain(|(r, _)| *r != request);
        }
    }

    fn take(&self, runner: RunnerId) -> Vec<(i64, u32)> {
        self.asked
            .lock()
            .unwrap()
            .remove(&runner)
            .unwrap_or_default()
    }

    fn answer(&self, request: i64, tail: Tail) {
        if let Some(tx) = self.waiting.lock().unwrap().remove(&request) {
            let _ = tx.send(tail);
        }
    }
}

/// Why a probe came to nothing.
#[derive(Debug)]
pub enum ProbeFail {
    /// The runner speaks a protocol older than 1.25.
    TooOld,
    /// It could not look.
    Failed(String),
}

/// Probes the admin asked for, waiting for their runners (in memory, like `LogTails`).
#[derive(Default)]
pub struct Probes {
    next: AtomicI64,
    asked: Mutex<HashMap<RunnerId, Vec<i64>>>,
    waiting: Mutex<HashMap<i64, oneshot::Sender<Result<(), ProbeFail>>>>,
}

impl Probes {
    /// Asks `runner` to probe itself: the request and where the answer comes.
    pub fn ask(&self, runner: RunnerId) -> (i64, oneshot::Receiver<Result<(), ProbeFail>>) {
        let request = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().unwrap().insert(request, tx);
        self.asked
            .lock()
            .unwrap()
            .entry(runner)
            .or_default()
            .push(request);
        (request, rx)
    }

    /// Gives up on `request` (its caller stopped waiting).
    pub fn forget(&self, request: i64) {
        self.waiting.lock().unwrap().remove(&request);
        for list in self.asked.lock().unwrap().values_mut() {
            list.retain(|r| *r != request);
        }
    }

    fn take(&self, runner: RunnerId) -> Vec<i64> {
        self.asked
            .lock()
            .unwrap()
            .remove(&runner)
            .unwrap_or_default()
    }

    fn answer(&self, request: i64, result: Result<(), ProbeFail>) {
        if let Some(tx) = self.waiting.lock().unwrap().remove(&request) {
            let _ = tx.send(result);
        }
    }
}

impl Session {
    /// Stores what the runner reported of itself.
    pub(super) async fn info(
        &self,
        info: &RunnerInfo,
        harnesses: Option<&BTreeMap<String, String>>,
    ) {
        let now = self.now();
        if let Err(e) = record_info(&self.app.pool, self.runner.id, info, harnesses, &now).await {
            tracing::error!(error = %e, "recording the runner's state failed");
        }
    }

    /// The log requests for this runner, as `ReadLog`s; an older runner's fail at once. Then
    /// its Power Nap preference, if the admin changed it since it was last sent.
    pub(super) async fn asks(&mut self) -> Vec<ServerMessage> {
        let mut out = vec![];
        for (request, lines) in self.app.log_tails.take(self.runner.id) {
            match self.speaks_1_20 {
                true => out.push(ServerMessage::ReadLog { request, lines }),
                false => {
                    let why = "the runner is too old to send its log (protocol 1.20)";
                    self.app.log_tails.answer(request, Err(why.to_owned()));
                }
            }
        }
        for request in self.app.probes.take(self.runner.id) {
            match self.speaks_1_25 {
                true => out.push(ServerMessage::Probe { request }),
                false => self.app.probes.answer(request, Err(ProbeFail::TooOld)),
            }
        }
        if self.speaks_1_20
            && let Ok(Some(r)) = get_runner(&self.app.pool, self.runner.id).await
            && let Some(power_nap) = r.power_nap.filter(|p| Some(*p) != self.power_nap_sent)
        {
            self.power_nap_sent = Some(power_nap);
            out.push(ServerMessage::Prefs { power_nap });
        }
        out
    }

    /// The runner's answer to `Probe` `request`: what it found is stored and judged as a `Hello`'s
    /// is (which harnesses get work, whether it is healthy), then the asker is told.
    pub(super) async fn probed(
        &mut self,
        request: i64,
        harnesses: BTreeMap<String, String>,
        info: &RunnerInfo,
        platform: (Option<&str>, Option<&str>),
        error: Option<String>,
    ) {
        if let Some(why) = error {
            let why = self.redactor.text(&why);
            return self.app.probes.answer(request, Err(ProbeFail::Failed(why)));
        }
        self.info(info, Some(&harnesses)).await;
        let _ = record_platform(&self.app.pool, self.runner.id, platform.0, platform.1).await;
        let policy = super::harness_policy(&self.app.pool, self.runner.id).await;
        let (offered, refused, _) = super::judge(&harnesses, &policy);
        self.harnesses = offered;
        let (status, reason) = match refused.is_empty() {
            true => (RunnerStatus::Online, None),
            false => (RunnerStatus::Unhealthy, Some(refused.join("; "))),
        };
        self.set_status(status, reason, Some(self.now())).await;
        self.app.probes.answer(request, Ok(()));
    }

    /// The runner's answer to `ReadLog` `request`, redacted again.
    pub(super) fn log_tail(&self, request: i64, lines: Vec<String>, error: Option<String>) {
        let tail = match error {
            Some(why) => Err(self.redactor.text(&why)),
            None => Ok(lines.iter().map(|l| self.redactor.text(l)).collect()),
        };
        self.app.log_tails.answer(request, tail);
    }
}
