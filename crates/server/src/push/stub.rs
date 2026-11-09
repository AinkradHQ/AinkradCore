//! FCM and web push (E5/E7) are interfaces only here: a registered token for either provider
//! is stored, and this stub is what stands in for its transport until one exists.
//!
//! To add one: implement [`PushProvider`] with `name()` `"fcm"` or `"webpush"` (see
//! [`super::apns::ApnsNotifier`] for the shape: build the request, map the provider's answer to
//! [`PushError`] so a dead token is `InvalidToken` and gets pruned), and put it in the
//! `providers` list `serve` hands the [`super::Pusher`]. Nothing else changes. [`Fake`] is the
//! test double the suite runs the whole path against.

use std::collections::HashMap;
use std::sync::Mutex;

use super::{Notification, PushError, PushProvider, Sent};
use crate::store::gov::PushTarget;

/// A provider with no transport yet: every send is `Unsupported`, which neither counts against
/// the token nor prunes it.
pub struct Unimplemented(pub &'static str);

impl PushProvider for Unimplemented {
    fn name(&self) -> &'static str {
        self.0
    }

    fn send<'a>(&'a self, _: &'a PushTarget, _: &'a Notification) -> Sent<'a> {
        Box::pin(async { Err(PushError::Unsupported) })
    }
}

/// Records what it is asked to send, and fails the tokens it is told to.
pub struct Fake {
    pub provider: &'static str,
    pub sent: Mutex<Vec<(String, Notification)>>,
    /// Token -> what a send to it answers; absent means delivered.
    pub answers: Mutex<HashMap<String, PushError>>,
}

impl Fake {
    pub fn new(provider: &'static str) -> Self {
        Self {
            provider,
            sent: Mutex::default(),
            answers: Mutex::default(),
        }
    }

    pub fn take(&self) -> Vec<(String, Notification)> {
        std::mem::take(&mut self.sent.lock().unwrap())
    }
}

impl PushProvider for Fake {
    fn name(&self) -> &'static str {
        self.provider
    }

    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a> {
        self.sent
            .lock()
            .unwrap()
            .push((to.device_id.clone(), n.clone()));
        let answer = self.answers.lock().unwrap().get(&to.token).cloned();
        Box::pin(async move { answer.map_or(Ok(()), Err) })
    }
}
