//! One-time WebSocket tickets (handshake spec §10, E1-08.5). A browser cannot sign an upgrade
//! request (it sets no headers on one), so it asks for a ticket over a signed request and
//! offers it in `Sec-WebSocket-Protocol: ainkrad.v1, ainkrad-ticket.<ticket>`.
//!
//! A ticket is 128 random bits, good once, for [`TICKET_SECS`], for the event stream only, and
//! bound to the device and session that asked; it is spent when looked up, whatever comes
//! next. At most [`PER_SESSION`] are live per session (a new one replaces that session's
//! oldest, so no session evicts another's), and a session gets [`PER_SESSION_BURST`] at once
//! and one every 6 s after. A revocation drops the device's tickets with its sessions.

use super::{Auth, crypto};

pub const TICKET_SECS: i64 = 30;
/// Live tickets per session.
pub const PER_SESSION: usize = 4;
pub const PER_SESSION_BURST: u32 = 10;
pub const PER_SESSION_PER_SEC: f64 = 10.0 / 60.0;

pub(super) struct Ticket {
    pub(super) device: String,
    session: String,
    expires: i64,
    order: u64,
}

impl Auth {
    /// A ticket for `session` of `device`; `None` when the session is gone.
    pub fn issue_ticket(&self, device: &str, session: &str, now: i64) -> Option<String> {
        self.session(session, device, now)?;
        let t = crypto::b64(&crypto::random::<16>());
        let mut all = self.tickets.lock().unwrap();
        all.retain(|_, t| t.expires > now);
        let mut mine: Vec<(u64, String)> = all
            .iter()
            .filter(|(_, t)| t.session == session)
            .map(|(k, t)| (t.order, k.clone()))
            .collect();
        if mine.len() >= PER_SESSION {
            mine.sort();
            for (_, k) in &mine[..=mine.len() - PER_SESSION] {
                all.remove(k);
            }
        }
        let order = self
            .issued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ticket = Ticket {
            device: device.to_owned(),
            session: session.to_owned(),
            expires: now + TICKET_SECS,
            order,
        };
        all.insert(t.clone(), ticket);
        Some(t)
    }

    /// Spends `ticket`: the device and session it was issued to, if it is live and that session
    /// still is.
    pub fn take_ticket(&self, ticket: &str, now: i64) -> Option<(String, super::Session)> {
        let t = self.tickets.lock().unwrap().remove(ticket)?;
        if t.expires <= now {
            return None;
        }
        let s = self.session(&t.session, &t.device, now)?;
        Some((t.device, s))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::Identity;

    #[test]
    fn tickets_are_single_use_short_lived_bound_and_capped() {
        let a = Auth::new(Arc::new(Identity::ephemeral()));
        let s = a.issue_session("d_a", 0).id;
        assert!(
            a.issue_ticket("d_b", &s, 0).is_none(),
            "another device's session"
        );
        let t = a.issue_ticket("d_a", &s, 0).unwrap();
        let (d, got) = a.take_ticket(&t, 1).unwrap();
        assert_eq!((d.as_str(), got.id.as_str()), ("d_a", s.as_str()));
        assert!(a.take_ticket(&t, 1).is_none(), "replayed");
        let t = a.issue_ticket("d_a", &s, 0).unwrap();
        assert!(a.take_ticket(&t, TICKET_SECS).is_none(), "expired");
        let first = a.issue_ticket("d_a", &s, 100).unwrap();
        let other = a.issue_session("d_c", 100).id;
        let theirs = a.issue_ticket("d_c", &other, 100).unwrap();
        for _ in 0..PER_SESSION {
            a.issue_ticket("d_a", &s, 100).unwrap();
        }
        assert!(
            a.take_ticket(&first, 101).is_none(),
            "the session's oldest went"
        );
        assert!(
            a.take_ticket(&theirs, 101).is_some(),
            "never another session's"
        );
        // A ticket whose session was pushed out by newer ones is dead too.
        let t = a.issue_ticket("d_a", &s, 100).unwrap();
        for i in 0..crate::auth::SESSIONS_PER_DEVICE as i64 {
            a.issue_session("d_a", 101 + i);
        }
        assert!(a.take_ticket(&t, 200).is_none(), "its session is gone");
        let s = a.issue_session("d_a", 300).id;
        let t = a.issue_ticket("d_a", &s, 300).unwrap();
        a.revoked("d_a");
        assert!(a.take_ticket(&t, 301).is_none(), "revoked");
    }
}
