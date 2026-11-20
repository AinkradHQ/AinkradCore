//! A heavy job's live side (E15-3): its frames for followers (replayed up to [`REPLAY_BYTES`]) and
//! the signals and cancel they send.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{broadcast, mpsc};

/// Frames kept for a late follower, at most.
const REPLAY_BYTES: usize = 4 * 1024 * 1024;

/// What a follower may ask of a job.
pub(super) enum Ctl {
    Signal(&'static str),
    Cancel,
}

/// One live job's frames and controls.
pub struct Live {
    pub(super) frames: Mutex<(Vec<String>, usize)>,
    pub(super) tx: broadcast::Sender<String>,
    pub(super) ctl: mpsc::UnboundedSender<Ctl>,
    pub(super) done: AtomicBool,
}

impl Live {
    pub(super) fn push(&self, v: Value) {
        let line = format!("{v}\n");
        let mut f = self.frames.lock().unwrap();
        f.1 += line.len();
        f.0.push(line.clone());
        while f.1 > REPLAY_BYTES && f.0.len() > 1 {
            let gone = f.0.remove(0);
            f.1 -= gone.len();
        }
        // Sent under the lock so a follower's replay and subscription meet without a gap.
        let _ = self.tx.send(line);
    }

    /// The frames so far, and a receiver for the rest.
    pub fn subscribe(&self) -> (Vec<String>, broadcast::Receiver<String>) {
        let f = self.frames.lock().unwrap();
        (f.0.clone(), self.tx.subscribe())
    }

    /// Whether the job has ended (its frames are final).
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }
}

pub(super) fn registry() -> &'static Mutex<HashMap<String, Arc<Live>>> {
    static R: OnceLock<Mutex<HashMap<String, Arc<Live>>>> = OnceLock::new();
    R.get_or_init(Mutex::default)
}

/// A job's frames, while it runs and shortly after.
pub fn get(id: &str) -> Option<Arc<Live>> {
    registry().lock().unwrap().get(id).cloned()
}

/// Sends `INT`, `TERM`, `HUP` (as TERM) or `KILL` to a live job. `false`: no such live job.
pub fn signal(id: &str, sig: &str) -> bool {
    let sig = match sig {
        "INT" => "INT",
        "KILL" => "KILL",
        _ => "TERM",
    };
    get(id).is_some_and(|l| !l.is_done() && l.ctl.send(Ctl::Signal(sig)).is_ok())
}

/// Cancels a live job: TERM, then KILL after ten seconds; nothing is synced back.
pub fn cancel(id: &str) -> bool {
    get(id).is_some_and(|l| !l.is_done() && l.ctl.send(Ctl::Cancel).is_ok())
}

/// A job's frames as lines: `head` first (what a late follower missed, or the verdict), then every
/// frame as it arrives, ending after the last one once the job is done.
pub fn lines(live: Arc<Live>, head: Vec<String>) -> impl futures_util::Stream<Item = String> {
    let (replay, rx) = live.subscribe();
    let queue: std::collections::VecDeque<String> = head.into_iter().chain(replay).collect();
    futures_util::stream::unfold((queue, rx, live), |(mut q, mut rx, live)| async move {
        loop {
            if let Some(l) = q.pop_front() {
                return Some((l, (q, rx, live)));
            }
            match rx.try_recv() {
                Ok(l) => return Some((l, (q, rx, live))),
                Err(broadcast::error::TryRecvError::Empty) if live.is_done() => return None,
                Err(broadcast::error::TryRecvError::Closed) => return None,
                // Behind: the next frames are the ones that are left.
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(broadcast::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
}
