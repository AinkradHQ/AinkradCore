//! One request's account with the meter (KAN-435 G4): the reservation, the reply's scan, and the
//! one report it ends in. Every way a request can end after the upstream was opened (the reply
//! finished, broke, was cut at the ceiling, the harness went away, the gateway was dropped)
//! settles the hold and emits exactly one report, because the guard does it from `Drop` if
//! nothing else did.

use ainkrad_proto::v2::{GatewayReport, GatewayReportKind, ModelPrice, UpstreamStatus, Wire};

use super::dial::{DialError, Opened, Stream};
use super::meter::{Reservation, cost_of};
use super::status;
use super::usage::{Scan, Usage};
use super::{Event, Events};

/// A report with no tokens: the upstream's signal, or a request that never got an answer.
pub(super) fn signal(
    status: UpstreamStatus,
    retry: Option<u64>,
    reset: Option<String>,
) -> GatewayReport {
    GatewayReport {
        gw_seq: 0, // the driver numbers it, and sets the epoch
        epoch: 0,
        kind: GatewayReportKind::Upstream,
        model: None,
        input: 0,
        output: 0,
        cache_read: 0,
        cache_write: 0,
        status,
        approximate: false,
        reported_usd_micros: None,
        retry_after: retry,
        reset_at: reset,
    }
}

/// The head of the reply, once it is read.
struct Reply {
    http: u16,
    retry_after: Option<u64>,
    reset_at: Option<String>,
    /// The start of a non-2xx body, for its error type.
    error: Vec<u8>,
}

/// A request's account with the meter. It exists from before the upstream is dialled: once the
/// body may have been sent, anything that ends the request without a reply (a dial error after
/// the write, a head that never came, an abort) is charged as the estimate it was held at, never
/// as nothing. `free` is a request that costs nothing (`count_tokens`): it is held at nothing,
/// settles at nothing and reports no usage.
pub(super) struct Charge {
    res: Reservation,
    events: Events,
    model: String,
    price: ModelPrice,
    /// What the request was held at: its input estimate and its output cap.
    est: Usage,
    wire: Wire,
    free: bool,
    scan: Scan,
    reply: Option<Reply>,
    done: bool,
}

impl Charge {
    pub(super) fn new(
        res: Reservation,
        events: Events,
        model: String,
        price: ModelPrice,
        est: Usage,
        wire: Wire,
        free: bool,
    ) -> Charge {
        Charge {
            res,
            events,
            model,
            price,
            est,
            wire,
            free,
            scan: Scan::new(wire, None),
            reply: None,
            done: false,
        }
    }

    /// The reply's head is here.
    pub(super) fn attach(&mut self, up: &Opened<Stream>) {
        let content_type = up
            .headers
            .iter()
            .find(|(n, _)| n == "content-type")
            .map(|(_, v)| v.as_str());
        self.scan = Scan::new(self.wire, content_type);
        self.reply = Some(Reply {
            http: up.status,
            retry_after: status::retry_after(&up.headers),
            reset_at: status::reset_at(&up.headers),
            error: Vec::new(),
        });
    }

    /// The upstream was not opened. An error that came before anything was sent costs nothing and
    /// is the upstream's signal; one that may have come after the body was written
    /// ([`DialError::Upstream`]) is charged as the estimate.
    pub(super) fn dial_failed(&mut self, e: DialError) {
        if e == DialError::Upstream {
            return self.end(false);
        }
        if !std::mem::replace(&mut self.done, true) {
            self.res.settle(Default::default());
            let _ = self
                .events
                .send(Event::Report(signal(status::of_dial(e), None, None)));
        }
    }

    fn ok(&self) -> bool {
        self.reply
            .as_ref()
            .is_some_and(|r| (200..300).contains(&r.http))
    }

    /// A piece of the reply went by.
    pub(super) fn feed(&mut self, piece: &[u8]) {
        if self.ok() {
            self.scan.feed(piece);
        } else if let Some(r) = self.reply.as_mut() {
            let room = status::PROBE_BYTES.saturating_sub(r.error.len());
            r.error.extend_from_slice(&piece[..piece.len().min(room)]);
        }
    }

    /// The reply has cost more than the ceiling leaves it.
    pub(super) fn exceeded(&self) -> bool {
        self.ok()
            && !self.free
            && self
                .res
                .exceeded(cost_of(&self.price, &self.scan.running(self.est.input)))
    }

    /// Settles the hold and sends the report. `clean`: the reply ended as its framing says.
    /// Idempotent: the first call counts.
    pub(super) fn end(&mut self, clean: bool) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let report = match self.reply.take() {
            // No reply: the request may have been served, and is charged as the estimate.
            None if self.free => return self.res.settle(Default::default()),
            None => {
                self.res.settle(cost_of(&self.price, &self.est));
                self.usage_report(self.est, true, UpstreamStatus::Unreachable)
            }
            Some(r) if (200..300).contains(&r.http) => {
                if self.free {
                    return self.res.settle(Default::default());
                }
                self.scan.finish();
                let (usage, approximate) = match (clean, self.scan.exact()) {
                    (true, Some(u)) => (u, false),
                    _ => (self.scan.running(self.est.input), true),
                };
                self.res.settle(cost_of(&self.price, &usage));
                self.usage_report(usage, approximate, UpstreamStatus::Ok)
            }
            Some(r) => {
                self.res.settle(Default::default());
                let class = status::of_http(r.http, &r.error);
                if class == UpstreamStatus::AuthFailed {
                    // The key does not work: nothing more is sent with it this session.
                    self.res.fail_auth();
                }
                signal(class, r.retry_after, r.reset_at)
            }
        };
        let _ = self.events.send(Event::Report(report));
    }

    fn usage_report(&self, u: Usage, approximate: bool, status: UpstreamStatus) -> GatewayReport {
        GatewayReport {
            kind: GatewayReportKind::Usage,
            model: Some(self.model.clone()),
            input: u.input,
            output: u.output,
            cache_read: u.cache_read,
            cache_write: u.cache_write,
            approximate,
            ..signal(status, None, None)
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.end(false);
    }
}
