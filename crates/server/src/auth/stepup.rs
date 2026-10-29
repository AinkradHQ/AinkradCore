//! Step-up (handshake spec §8, E1-09.3): a routine signature proves nothing new, because every
//! request carries one, so a device elevates with its **second** key, the step-up key the OS
//! releases only after Face ID, Touch ID or the passcode. It signs
//! `AINKRAD-STEPUP-V1` LF `<core_fp>` LF `<device_id>` LF `<session_id>` LF `<challenge>` (no
//! trailing newline), where the challenge is one the Core issued for that very session.
//!
//! - **Bounded storage:** a session holds at most one live challenge (60 s, single use); a new
//!   one replaces it. Sessions are capped per device, and only the device itself (with a valid
//!   routine signature) can ask, so nobody can evict another device's challenge.
//! - **One critical section, drop-safe:** the budget check, taking the challenge and the verify
//!   run synchronously in [`Auth::prove_stepup`] with no `.await`, and the attempt counts as a
//!   failure until it verifies. A request dropped half-way leaves no slot held and nothing
//!   elevated. The caller audits `auth.step_up` and only then sets the elevation, so a drop in
//!   between leaves "audited, not elevated", never the reverse.
//! - **Budgets:** per device here ([`STEP_UP`] failures per window, in memory), persisted as
//!   `stepup:<device>` (`store::gov::STEP_UP`, survives a restart, audited at lock time), and per
//!   address through `AddressFailures`. A step-up failure is authenticated (the routine
//!   signature verified), so a per-device key is safe: only the device can spend it.
//! - **Uniform:** no step-up key, an unknown, used, expired or other session's challenge, and a
//!   bad signature are one answer (`step_up_failed`), each after one signature verify (a dummy
//!   one when there is nothing to check) and no sooner than the gate's `FAIL_FLOOR`.
//! - **The host's socket** (`ip:local`) is never refused by the address budget
//!   (`AddressFailures`), so outside traffic cannot stop the operator stepping up.

use std::collections::HashMap;
use std::sync::Mutex;

use super::{Auth, CHALLENGE_SECS, crypto};
use crate::store::gov::{Device, STEP_UP};

/// The domain separation string of a step-up proof.
pub const DOMAIN: &str = "AINKRAD-STEPUP-V1";

/// The exact bytes the step-up key signs.
pub fn message(core_fp: &str, device: &str, session: &str, challenge: &str) -> Vec<u8> {
    format!("{DOMAIN}\n{core_fp}\n{device}\n{session}\n{challenge}").into_bytes()
}

/// What a step-up proof came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    Verified,
    Failed,
    /// The device's (or address's) failure budget is spent: nothing was evaluated.
    Throttled,
}

/// Devices tracked before windows that are over are swept.
pub const FAILURES_MAX: usize = 4096;

/// Failed proofs per device in this process: (failures, window start). Only an authenticated
/// device makes an entry, so it is bounded by the device table; past [`FAILURES_MAX`] the
/// entries whose window is over are dropped.
#[derive(Default)]
pub struct StepUpFailures(Mutex<HashMap<String, (i64, i64)>>);

impl StepUpFailures {
    /// Counts an attempt as a failure up front; `false` when the budget is spent.
    fn take(&self, device: &str, now: i64) -> bool {
        let mut all = self.0.lock().unwrap();
        if all.len() >= FAILURES_MAX {
            all.retain(|_, (_, start)| now - *start < STEP_UP.window);
        }
        let slot = all.entry(device.to_owned()).or_insert((0, now));
        if now - slot.1 >= STEP_UP.window {
            *slot = (0, now);
        }
        let ok = slot.0 < STEP_UP.threshold;
        slot.0 += i64::from(ok);
        ok
    }

    /// Gives back an attempt that verified.
    fn give_back(&self, device: &str) {
        if let Some(slot) = self.0.lock().unwrap().get_mut(device) {
            slot.0 = (slot.0 - 1).max(0);
        }
    }

    /// Forgets the device's failures (a lockout cleared by an admin).
    pub fn clear(&self, device: &str) {
        self.0.lock().unwrap().remove(device);
    }
}

impl Auth {
    /// A new step-up challenge for `session` of `device`, replacing its previous one; `None`
    /// when the session is gone.
    pub fn stepup_challenge(&self, session: &str, device: &str, now: i64) -> Option<String> {
        let mut all = self.sessions.lock().unwrap();
        let s = all
            .get_mut(session)
            .filter(|s| s.device == device && s.expires > now)?;
        let c = crypto::b64(&crypto::random::<32>());
        s.stepup_challenge = Some((c.clone(), now + CHALLENGE_SECS));
        Some(c)
    }

    /// Checks a step-up proof by `device` on `session` from `addr`: the budgets, then the
    /// session's challenge (spent whatever happens next), then the step-up key's signature.
    /// Synchronous on purpose (see the module docs). Does not elevate: see [`Auth::elevate`].
    pub fn prove_stepup(
        &self,
        addr: &str,
        device: &Device,
        session: &str,
        challenge: &str,
        sig: Option<&[u8]>,
        now: i64,
    ) -> Proof {
        if !self.stepup_failures.take(&device.id, now) {
            return Proof::Throttled;
        }
        let live = {
            let mut all = self.sessions.lock().unwrap();
            all.get_mut(session)
                .filter(|s| s.device == device.id && s.expires > now)
                .and_then(|s| s.stepup_challenge.take())
                .is_some_and(|(c, exp)| exp > now && c.as_bytes() == challenge.as_bytes())
        };
        let m = message(&self.identity.fp, &device.id, session, challenge);
        // One verify whatever failed first, so every refusal costs the same.
        let ok = match (live, &device.stepup_spki, sig) {
            (true, Some(key), Some(sig)) => crypto::verify(key, &m, sig),
            _ => {
                crypto::dummy_verify(&m, sig.unwrap_or(&[0; 64]));
                false
            }
        };
        if ok {
            self.stepup_failures.give_back(&device.id);
            return Proof::Verified;
        }
        // The address budget is shared with the gate's authentication failures.
        if !self.failures.count(addr, now) {
            return Proof::Throttled;
        }
        Proof::Failed
    }

    /// Elevates `session` of `device` until `until`, replacing any elevation it had (a new one
    /// never stacks). `false` when the session is gone.
    pub fn elevate(&self, session: &str, device: &str, until: i64) -> bool {
        let mut all = self.sessions.lock().unwrap();
        match all.get_mut(session).filter(|s| s.device == device) {
            Some(s) => {
                s.elevated_until = Some(until);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
