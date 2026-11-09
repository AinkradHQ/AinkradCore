//! A session's spend against its ceiling (KAN-435 G4, spec 4.7). The gateway enforces the ceiling
//! itself, so the Core's round trip is never on the critical path:
//!
//! - **Reserve.** Before a request is sent, an upper bound of its cost is held against the
//!   ceiling (input = body bytes / 3, output = the request's max output tokens, priced from the
//!   grant). A request the ceiling cannot cover is refused without contacting the upstream.
//! - **Settle.** When the reply ends (or is cut, or dropped), the hold is replaced by what was
//!   spent. Spent only goes up.
//! - **Cut.** While a reply streams, its running cost is checked against what the ceiling leaves
//!   after everything spent and every other request's hold; past it, the stream is cut.
//! - **Limit.** `agent.limit` replaces the ceiling at any time. A zero in either dimension
//!   refuses every request from then on and aborts the open streams.
//!
//! The ceiling is an absolute total for the session, spent included; "no ceiling" is `u64::MAX`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::{Ceiling, ModelPrice};
use tokio::sync::watch;

use super::usage::Usage;

/// What something costs against a ceiling: tokens (all four kinds) and micro-dollars.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Cost {
    pub tokens: u64,
    pub usd: u64,
}

impl Cost {
    fn plus(self, o: Cost) -> Cost {
        Cost {
            tokens: self.tokens.saturating_add(o.tokens),
            usd: self.usd.saturating_add(o.usd),
        }
    }

    fn minus(self, o: Cost) -> Cost {
        Cost {
            tokens: self.tokens.saturating_sub(o.tokens),
            usd: self.usd.saturating_sub(o.usd),
        }
    }
}

const MILLION: u128 = 1_000_000;

fn usd(tokens: u64, per_million: u64) -> u128 {
    u128::from(tokens) * u128::from(per_million)
}

fn micros(sum: u128) -> u64 {
    u64::try_from(sum.div_ceil(MILLION)).unwrap_or(u64::MAX)
}

/// What `u` costs at `p`, rounded up.
pub(crate) fn cost_of(p: &ModelPrice, u: &Usage) -> Cost {
    let sum = usd(u.input, p.input)
        + usd(u.output, p.output)
        + usd(u.cache_read, p.cache_read)
        + usd(u.cache_write, p.cache_write);
    Cost {
        tokens: ainkrad_proto::v2::ceiling_tokens(u.input, u.output, u.cache_read, u.cache_write),
        usd: micros(sum),
    }
}

/// The most a request can cost: its body read as input (priced at the dearer of plain input and a
/// cache write), plus `max_out` tokens of output.
pub(crate) fn estimate(p: &ModelPrice, body_len: usize, max_out: u64) -> (Usage, Cost) {
    let input = (body_len as u64).div_ceil(3);
    let sum = usd(input, p.input.max(p.cache_write)) + usd(max_out, p.output);
    (
        Usage {
            input,
            output: max_out,
            ..Usage::default()
        },
        Cost {
            tokens: input.saturating_add(max_out),
            usd: micros(sum),
        },
    )
}

struct State {
    ceiling: Ceiling,
    spent: Cost,
    held: Cost,
}

pub struct Meter {
    st: Mutex<State>,
    prices: Vec<ModelPrice>,
    /// Bumped when the ceiling changes: open streams look again.
    changed: watch::Sender<u64>,
    /// The Core has not acknowledged the reports it holds: nothing more is spent (fail closed,
    /// never a dropped usage report).
    unreported: AtomicBool,
    /// The upstream refused the key: nothing more is sent with it.
    auth_failed: AtomicBool,
}

/// Why a request was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denied {
    Ceiling,
    Unreported,
    /// The upstream answered 401/403 to this session's key.
    AuthFailed,
}

impl Meter {
    pub(crate) fn new(ceiling: Ceiling, prices: Vec<ModelPrice>) -> Meter {
        Meter {
            st: Mutex::new(State {
                ceiling,
                spent: Cost::default(),
                held: Cost::default(),
            }),
            prices,
            changed: watch::channel(0).0,
            unreported: AtomicBool::new(false),
            auth_failed: AtomicBool::new(false),
        }
    }

    pub(crate) fn price(&self, model: &str) -> Option<&ModelPrice> {
        self.prices.iter().find(|p| p.model == model)
    }

    /// The Core holds too many reports it has not acknowledged: refuse requests until it does
    /// (a usage report is never dropped to make room).
    pub fn set_unreported(&self, on: bool) {
        self.unreported.store(on, Ordering::SeqCst);
    }

    /// Replaces the ceiling (`agent.limit`).
    pub fn set_ceiling(&self, c: Ceiling) {
        self.st.lock().expect("meter lock").ceiling = c;
        self.changed.send_modify(|n| *n += 1);
    }

    pub fn ceiling(&self) -> Ceiling {
        self.st.lock().expect("meter lock").ceiling
    }

    /// Tokens and micro-dollars settled so far.
    pub fn spent(&self) -> (u64, u64) {
        let s = self.st.lock().expect("meter lock").spent;
        (s.tokens, s.usd)
    }

    fn is_stopped(c: &Ceiling) -> bool {
        c.tokens == 0 || c.usd_micros == 0
    }

    /// Resolves once the ceiling is zero in a dimension: every request is refused and open
    /// streams are aborted.
    pub(crate) async fn stopped(&self) {
        let mut rx = self.changed.subscribe();
        loop {
            if Meter::is_stopped(&self.ceiling()) {
                return;
            }
            if rx.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }

    /// Holds `est` against the ceiling, or says why not.
    pub(crate) fn reserve(self: &Arc<Self>, est: Cost) -> Result<Reservation, Denied> {
        if self.auth_failed.load(Ordering::SeqCst) {
            return Err(Denied::AuthFailed);
        }
        if self.unreported.load(Ordering::SeqCst) {
            return Err(Denied::Unreported);
        }
        let mut s = self.st.lock().expect("meter lock");
        let after = s.spent.plus(s.held).plus(est);
        if Meter::is_stopped(&s.ceiling)
            || after.tokens > s.ceiling.tokens
            || after.usd > s.ceiling.usd_micros
        {
            return Err(Denied::Ceiling);
        }
        s.held = s.held.plus(est);
        Ok(Reservation {
            meter: self.clone(),
            held: est,
            done: false,
        })
    }
}

/// A request's hold. Released when it is settled or dropped.
pub(crate) struct Reservation {
    meter: Arc<Meter>,
    held: Cost,
    done: bool,
}

impl Reservation {
    /// The request's running cost is past what the ceiling leaves it: the sum of what was
    /// spent, what every other request holds, and `running`.
    pub(crate) fn exceeded(&self, running: Cost) -> bool {
        let s = self.meter.st.lock().expect("meter lock");
        let others = s.spent.plus(s.held.minus(self.held)).plus(running);
        Meter::is_stopped(&s.ceiling)
            || others.tokens > s.ceiling.tokens
            || others.usd > s.ceiling.usd_micros
    }

    /// The upstream refused the key: no more requests this session (no retry storm).
    pub(crate) fn fail_auth(&self) {
        self.meter.auth_failed.store(true, Ordering::SeqCst);
    }

    /// Replaces the hold with what was spent.
    pub(crate) fn settle(&mut self, spent: Cost) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let mut s = self.meter.st.lock().expect("meter lock");
        s.held = s.held.minus(self.held);
        s.spent = s.spent.plus(spent);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.settle(Cost::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price() -> ModelPrice {
        ModelPrice {
            model: "m".to_owned(),
            input: 3_000_000,
            output: 15_000_000,
            cache_read: 300_000,
            cache_write: 3_750_000,
        }
    }

    fn meter(tokens: u64, usd_micros: u64) -> Arc<Meter> {
        Arc::new(Meter::new(Ceiling { tokens, usd_micros }, vec![price()]))
    }

    #[test]
    fn a_cost_is_the_price_per_million_rounded_up() {
        let u = Usage {
            input: 1,
            output: 1,
            cache_read: 1,
            cache_write: 1,
        };
        // 3 + 15 + 0.3 + 3.75 micro-dollars, rounded up.
        assert_eq!(cost_of(&price(), &u), Cost { tokens: 4, usd: 23 });
        let (_, est) = estimate(&price(), 300, 1000);
        // 100 input tokens at the cache-write price (the dearer) + 1000 output.
        assert_eq!(est.tokens, 1100);
        assert_eq!(est.usd, 375 + 15_000);
    }

    #[test]
    fn a_hold_the_ceiling_cannot_cover_is_refused_and_released_holds_free_it() {
        let m = meter(1000, 1_000_000);
        let a = m
            .reserve(Cost {
                tokens: 600,
                usd: 10,
            })
            .unwrap();
        assert_eq!(
            m.reserve(Cost {
                tokens: 600,
                usd: 10
            })
            .err(),
            Some(Denied::Ceiling)
        );
        drop(a);
        let mut b = m
            .reserve(Cost {
                tokens: 600,
                usd: 10,
            })
            .unwrap();
        b.settle(Cost {
            tokens: 500,
            usd: 5,
        });
        assert_eq!(m.spent(), (500, 5));
        // Spent counts: 500 + 600 is over.
        assert!(
            m.reserve(Cost {
                tokens: 600,
                usd: 1
            })
            .is_err()
        );
        assert!(
            m.reserve(Cost {
                tokens: 500,
                usd: 1
            })
            .is_ok()
        );
    }

    #[test]
    fn a_stream_is_cut_past_what_the_ceiling_leaves_it() {
        let m = meter(1000, 1_000_000);
        let r = m
            .reserve(Cost {
                tokens: 400,
                usd: 10,
            })
            .unwrap();
        let _other = m
            .reserve(Cost {
                tokens: 300,
                usd: 10,
            })
            .unwrap();
        assert!(!r.exceeded(Cost {
            tokens: 700,
            usd: 10
        }));
        assert!(r.exceeded(Cost {
            tokens: 701,
            usd: 10
        }));
        m.set_ceiling(Ceiling {
            tokens: 0,
            usd_micros: 0,
        });
        assert!(r.exceeded(Cost::default()), "a zero ceiling stops all");
        assert_eq!(
            m.reserve(Cost::default()).err(),
            Some(Denied::Ceiling),
            "and admits nothing"
        );
    }

    #[test]
    fn unacknowledged_reports_fail_closed() {
        let m = Arc::new(Meter::new(
            Ceiling {
                tokens: 10,
                usd_micros: 10,
            },
            vec![],
        ));
        assert!(m.reserve(Cost::default()).is_ok());
        m.set_unreported(true);
        assert_eq!(m.reserve(Cost::default()).err(), Some(Denied::Unreported));
        m.set_unreported(false);
        assert!(m.reserve(Cost::default()).is_ok());
    }

    #[test]
    fn a_refused_key_stops_every_later_request() {
        let m = meter(1000, 1000);
        let r = m.reserve(Cost::default()).unwrap();
        r.fail_auth();
        assert_eq!(m.reserve(Cost::default()).err(), Some(Denied::AuthFailed));
    }

    #[tokio::test]
    async fn a_zero_ceiling_wakes_the_waiters() {
        let m = meter(10, 10);
        let waiter = tokio::spawn({
            let m = m.clone();
            async move { m.stopped().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        m.set_ceiling(Ceiling {
            tokens: 0,
            usd_micros: 0,
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
    }
}
