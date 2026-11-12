//! The admin's controls of a running job (1.19, decision #34): a pause, and messages for its
//! harness, and a new permission policy (1.24). The daemon puts them here (`Executor::control`); the run's turn loop takes them.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use ainkrad_proto::runner::Policy;

use crate::Control;

#[derive(Default)]
pub(super) struct Inbox {
    pause: AtomicBool,
    /// The run is a live conversation (`Control::Live`).
    live: AtomicBool,
    /// The running turn is to be stopped (`Control::Interrupt`).
    interrupt: AtomicBool,
    messages: Mutex<VecDeque<(i64, String)>>,
    /// The run's policy since the admin changed it; `None`, its `Assign`'s.
    policy: Mutex<Option<Policy>>,
    /// Wakes the turn loop when something arrives.
    pub arrived: Notify,
}

impl Inbox {
    pub fn put(&self, control: Control) {
        match control {
            Control::Policy(policy) => *self.policy.lock().expect("inbox lock") = Some(policy),
            Control::Pause => self.pause.store(true, Ordering::SeqCst),
            Control::Live => self.live.store(true, Ordering::SeqCst),
            Control::Interrupt => self.interrupt.store(true, Ordering::SeqCst),
            Control::Message { id, text } => {
                let mut messages = self.messages.lock().expect("inbox lock");
                if !messages.iter().any(|(seen, _)| *seen == id) {
                    messages.push_back((id, text));
                }
            }
        }
        self.arrived.notify_one();
    }

    pub fn paused(&self) -> bool {
        self.pause.load(Ordering::SeqCst)
    }

    pub fn live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// Whether a turn stop was asked since the last call (and forgets it).
    pub fn take_interrupt(&self) -> bool {
        self.interrupt.swap(false, Ordering::SeqCst)
    }

    /// The run's policy now: the latest update, else `assigned`.
    pub fn policy(&self, assigned: &Policy) -> Policy {
        let policy = self.policy.lock().expect("inbox lock");
        policy.as_ref().unwrap_or(assigned).clone()
    }

    /// The oldest message not yet given to the harness.
    pub fn take_message(&self) -> Option<(i64, String)> {
        self.messages.lock().expect("inbox lock").pop_front()
    }
}
