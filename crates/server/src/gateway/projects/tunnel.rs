//! A WebSocket carried end to end, and when it is cut.

use std::sync::Arc;
use std::time::Duration;

use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::time::Instant;

use super::{Host, Permit, TICK, WS_IDLE, WS_LIFE};
use crate::store::{projects, runs};

/// An open WebSocket: what it was opened for, and the places it holds.
pub(super) struct Open {
    pub(super) label: String,
    pub(super) project: i64,
    pub(super) run: String,
    pub(super) _permit: Arc<Permit>,
}

/// Whether the project still serves this WebSocket: active, exposed, and the same run running.
/// A failed lookup closes it.
async fn still_served(h: &Host, open: &Open) -> bool {
    let pool = &h.app.pool;
    let project = projects::for_host(pool, &open.label).await;
    if !matches!(project, Ok(Some(p)) if p.id == open.project) {
        return false;
    }
    matches!(runs::live(pool, open.project).await,
             Ok(Some(r)) if r.id == open.run && r.state == "running")
}

/// A WebSocket's bytes both ways, until either side closes, nothing moves for [`WS_IDLE`], it has
/// been open [`WS_LIFE`], the project stops serving it ([`still_served`], every [`TICK`]) or serve
/// stops. Bytes moving push the idle stop back.
pub(super) async fn tunnel(h: Arc<Host>, open: Open, client: OnUpgrade, upstream: OnUpgrade) {
    let (Ok(client), Ok(upstream)) = tokio::join!(client, upstream) else {
        return;
    };
    let mut client = TokioIo::new(client);
    let (mut upstream, activity) = crate::gateway::idle::wrap(TokioIo::new(upstream));
    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    tokio::pin!(copy);
    let end = tokio::time::sleep(WS_LIFE);
    tokio::pin!(end);
    let mut closing = h.app.closing.subscribe();
    let mut tick = tokio::time::interval(TICK);
    let mut seen = activity.deadline(Duration::ZERO);
    loop {
        tokio::select! {
            _ = &mut copy => return,
            () = &mut end => return,
            () = crate::api::stopping(&mut closing) => return,
            _ = tick.tick() => {
                if !still_served(&h, &open).await {
                    return;
                }
                let moved = activity.deadline(Duration::ZERO);
                if moved > seen {
                    seen = moved;
                    h.touch(open.project).await;
                } else if moved + WS_IDLE <= Instant::now() {
                    return;
                }
            }
        }
    }
}
