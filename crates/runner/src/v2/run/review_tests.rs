//! PR 321 review: a runner that cannot clone refuses a `from_core` start before a secret lease is
//! redeemed, a run driver answers an unknown command as unsupported, and `run_caps` carries
//! `can_clone` (default off for an older runner's hello).
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_proto::v2::{Command, ErrorCode, RunCaps, RunStart};

use super::*;

fn start_from_core() -> RunStart {
    serde_json::from_value(serde_json::json!({
        "run": "r_1", "project": 1,
        "spec": {"services": {"web": {"build": {"repo": "web"}}}},
        "limits": {"cpus": 1.0, "memory_mb": 512, "pids": 100},
        "checkouts": [{"repo": "web", "dir": "",
                       "from_core": {"mirror": 7, "remote": "https://github.com/acme/web.git",
                                     "base": "main"}}],
        "secrets": [{"name": "k", "lease": "l_1"}]
    }))
    .unwrap()
}

#[tokio::test]
async fn no_clone_ability_is_refused_before_any_lease_is_redeemed() {
    let redeemed = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&redeemed);
    let redeem: Redeem = Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err("none".to_owned()) })
    });
    let d = RunDriver::new("/nonexistent/run.sock", redeem, "/nonexistent");
    let e = d.can_clone(&start_from_core()).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert_eq!(redeemed.load(Ordering::SeqCst), 0);
    // A start that clones nothing is not refused.
    let mut plain = start_from_core();
    plain.checkouts.clear();
    assert!(d.can_clone(&plain).is_ok());
}

#[tokio::test]
async fn an_unknown_command_is_unsupported_not_invalid() {
    let redeem: Redeem = Arc::new(|_| Box::pin(async { Err("none".to_owned()) }));
    let d = RunDriver::new("/nonexistent/run.sock", redeem, "/nonexistent");
    let e = d.handle(Command::Noop).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCommand);
}

#[test]
fn can_clone_defaults_off_for_an_older_hello() {
    let caps: RunCaps = serde_json::from_str(r#"{"cpus":2,"mem_mb":1024,"isolate":true}"#).unwrap();
    assert!(!caps.can_clone);
}
