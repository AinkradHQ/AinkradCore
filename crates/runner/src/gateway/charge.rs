//! One request's account with the meter (KAN-435 G4): the reservation, the reply's scan, and the
//! one report it ends in. Every way a request can end after the upstream was opened (the reply
//! finished, broke, was cut at the ceiling, the harness went away, the gateway was dropped)
//! settles the hold and emits exactly one report, because the guard does it from `Drop` if
//! nothing else did.

use ainkrad_proto::v2::{GatewayReport, GatewayReportKind, ModelPrice, UpstreamStatus, Wire};

use super::dial::{Opened, Stream};
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
        gw_seq: 0, // the driver numbers it
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

pub(super) struct Charge {
    res: Reservation,
    events: Events,
    model: String,
    price: ModelPrice,
    /// The request's input as estimated, used when the reply never says.
    est_in: u64,
    scan: Scan,
    http: u16,
    retry_after: Option<u64>,
    reset_at: Option<String>,
    /// The start of a non-2xx body, for its error type.
    error: Vec<u8>,
    done: bool,
}

impl Charge {
    pub(super) fn new(
        res: Reservation,
        events: Events,
        model: String,
        price: ModelPrice,
        est_in: u64,
        wire: Wire,
        up: &Opened<Stream>,
    ) -> Charge {
        let headers = &up.headers;
        let content_type = headers
            .iter()
            .find(|(n, _)| n == "content-type")
            .map(|(_, v)| v.as_str());
        Charge {
            res,
            events,
            model,
            price,
            est_in,
            scan: Scan::new(wire, content_type),
            http: up.status,
            retry_after: status::retry_after(headers),
            reset_at: status::reset_at(headers),
            error: Vec::new(),
            done: false,
        }
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.http)
    }

    /// A piece of the reply went by.
    pub(super) fn feed(&mut self, piece: &[u8]) {
        if self.ok() {
            self.scan.feed(piece);
        } else {
            let room = status::PROBE_BYTES.saturating_sub(self.error.len());
            self.error
                .extend_from_slice(&piece[..piece.len().min(room)]);
        }
    }

    /// The reply has cost more than the ceiling leaves it.
    pub(super) fn exceeded(&self) -> bool {
        self.ok()
            && self
                .res
                .exceeded(cost_of(&self.price, &self.scan.running(self.est_in)))
    }

    /// Settles the hold and sends the report. `clean`: the reply ended as its framing says.
    /// Idempotent: the first call counts.
    pub(super) fn end(&mut self, clean: bool) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let report = if self.ok() {
            self.scan.finish();
            let (usage, approximate) = match self.scan.reported() {
                Some(u) if clean && !self.scan.overflowed() => (u, false),
                _ => (self.scan.running(self.est_in), true),
            };
            self.res.settle(cost_of(&self.price, &usage));
            self.usage_report(usage, approximate)
        } else {
            self.res.settle(Default::default());
            signal(
                status::of_http(self.http, &self.error),
                self.retry_after,
                self.reset_at.take(),
            )
        };
        let _ = self.events.send(Event::Report(report));
    }

    fn usage_report(&self, u: Usage, approximate: bool) -> GatewayReport {
        GatewayReport {
            kind: GatewayReportKind::Usage,
            model: Some(self.model.clone()),
            input: u.input,
            output: u.output,
            cache_read: u.cache_read,
            cache_write: u.cache_write,
            approximate,
            ..signal(UpstreamStatus::Ok, None, None)
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.end(false);
    }
}
