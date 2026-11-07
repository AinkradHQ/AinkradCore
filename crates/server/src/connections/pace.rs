//! How often connections may be tested through the API (C5): a test is one real request to the
//! service with the connection's own credential, and its answer can disable the connection, so
//! an admin device in a loop must not be able to rate-limit GitHub or Jira, keep a connection
//! cooling, or spend its budget. A connection may be tested once every [`MIN_GAP_SECS`], and one
//! user [`PER_USER`] times in [`WINDOW_SECS`]. Kept in memory against the Core's own clock; a
//! refused test records nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const MIN_GAP_SECS: i64 = 10;
pub const PER_USER: usize = 30;
pub const WINDOW_SECS: i64 = 600;

#[derive(Default)]
struct Seen {
    /// The last test of each connection (ids are unique across workspaces).
    last: HashMap<i64, i64>,
    /// The tests of each user inside the window.
    users: HashMap<i64, VecDeque<i64>>,
}

#[derive(Default)]
pub struct Pace(Mutex<Seen>);

impl Pace {
    /// Takes a test of connection `id` by `user` at `now` (unix seconds), or says how many
    /// seconds to wait.
    pub fn admit(&self, user: i64, id: i64, now: i64) -> Result<(), u64> {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        s.last.retain(|_, t| now - *t < MIN_GAP_SECS);
        let wait = |secs: i64| u64::try_from(secs).unwrap_or(1).max(1);
        if let Some(t) = s.last.get(&id) {
            return Err(wait(MIN_GAP_SECS - (now - t)));
        }
        let q = s.users.entry(user).or_default();
        while q.front().is_some_and(|t| now - *t >= WINDOW_SECS) {
            q.pop_front();
        }
        if q.len() >= PER_USER {
            let first = q.front().copied().unwrap_or(now);
            return Err(wait(WINDOW_SECS - (now - first)));
        }
        q.push_back(now);
        s.last.insert(id, now);
        s.users.retain(|_, q| !q.is_empty());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_waits_its_gap_and_a_user_its_window() {
        let p = Pace::default();
        assert_eq!(p.admit(1, 5, 1000), Ok(()));
        assert_eq!(p.admit(1, 5, 1003), Err(7), "the gap, in seconds left");
        assert_eq!(p.admit(1, 6, 1003), Ok(()), "another connection is its own");
        assert_eq!(p.admit(1, 5, 1010), Ok(()));
        // 30 in the window, then refused until the first one leaves it.
        let p = Pace::default();
        for n in 0..PER_USER as i64 {
            assert_eq!(p.admit(2, 100 + n, 5000), Ok(()), "{n}");
        }
        assert_eq!(p.admit(2, 999, 5001), Err(599));
        assert_eq!(
            p.admit(3, 999, 5001),
            Ok(()),
            "another user is not held back"
        );
        assert_eq!(p.admit(2, 999, 5600), Ok(()));
    }
}
