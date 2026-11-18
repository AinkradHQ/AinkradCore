//! PR 324 review: port streams are a driver of their own, one `run.status` per run per second
//! serves all its streams, and helper failures reach the Core as fixed text.
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{OP_PORT_OPEN, OP_RUN_STATUS, OP_RUN_STOP};

use super::*;

fn driver() -> RunDriver {
    let redeem: Redeem = Arc::new(|_| Box::pin(async { Err("none".to_owned()) }));
    // `/` exists, so the driver is on offer; it is no helper socket, so any call to it fails.
    RunDriver::new("/", redeem, "/nonexistent")
}

#[test]
fn port_open_is_its_own_capped_driver() {
    let d = driver();
    let run = d.info().unwrap();
    let port = d.port_info().unwrap();
    assert!(run.commands.iter().all(|c| c != OP_PORT_OPEN));
    assert!(
        run.commands
            .iter()
            .any(|c| c == OP_RUN_STOP || c == OP_RUN_STATUS)
    );
    assert_eq!(port.commands, [OP_PORT_OPEN]);
    assert_eq!(run.streams, None, "run control keeps its own pool");
    let cap = port.streams.expect("port streams are counted apart");
    assert!(cap > 0 && (cap as usize) < super::super::session::MAX_HELD);
}

fn seed(d: &RunDriver, run: &str, e: StatusEntry) {
    let slot = Arc::new(tokio::sync::Mutex::new(Some(e)));
    d.status.lock().unwrap().insert(run.into(), slot);
}

#[tokio::test]
async fn a_fresh_status_is_shared_and_a_stale_one_is_refetched() {
    let d = driver();
    let fresh = RunList::default();
    seed(&d, "r1", (Instant::now(), Ok(fresh.clone())));
    assert_eq!(
        d.runs_cached("r1").await,
        Ok(fresh),
        "served from the cache"
    );
    let old = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    seed(&d, "r2", (old, Ok(RunList::default())));
    // `/` is not a helper socket: the refetch fails, so the stale Ok was not served.
    assert!(d.runs_cached("r2").await.is_err());
}

#[test]
fn helper_failures_are_a_fixed_text() {
    let e = helper_failed("test", "connect /run/ainkrad/helper.sock: secret detail");
    assert_eq!(e.code, ErrorCode::Internal);
    assert!(!e.message.contains("secret detail"), "{}", e.message);
}
