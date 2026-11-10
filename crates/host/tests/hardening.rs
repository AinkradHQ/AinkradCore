//! Review findings F1-F7 and the weak-test additions: each test here fails without its fix.
// The helper is Linux only (SO_PEERCRED, systemd): on other hosts these tests do not exist.
#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::*;
use serde_json::json;

/// F1: uid `ainkrad` can flood refusals until `actions.log` has rotated twice. The record of a
/// root action must still be findable.
#[test]
fn a_refusal_flood_cannot_rotate_away_a_restart_record() {
    let fx = Fx::new();
    let id = fx.id();
    assert_eq!(fx.send(&fx.line(&id, "restart_core", "{}"))["ok"], true);
    for _ in 0..30_000 {
        fx.raw(br#"{"v":1}"#, true);
    }
    let len = |n: &str| {
        std::fs::metadata(fx.state().join(n))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    assert!(len("actions.log.1") > 0, "the flood did rotate actions.log");
    let shared = format!(
        "{}{}",
        std::fs::read_to_string(fx.state().join("actions.log.1")).unwrap(),
        fx.log()
    );
    assert!(
        !shared.contains(&id),
        "the shared log lost the line, as expected"
    );
    let kept = std::fs::read_to_string(fx.state().join("mutations.log")).unwrap();
    assert!(
        kept.contains(" accepted restart_core ") && kept.contains(&id),
        "{kept}"
    );
}

/// F2: the budget counts the JSON-escaped size, so a page of quotes does not overflow the cap.
#[test]
fn a_quote_heavy_page_stays_under_the_wire_cap() {
    let fx = Fx::new();
    *fx.fake.journal.lock().unwrap() = (0..500)
        .map(|i| (format!("c{i}"), "6".to_owned(), json!("\"".repeat(4000))))
        .collect();
    let v = fx.call("logs", r#"{"unit":"core","lines":500}"#);
    assert_eq!(
        v["ok"],
        true,
        "{}",
        &v.to_string()[..200.min(v.to_string().len())]
    );
    assert!(v.to_string().len() <= 512 * 1024);
    assert!(v["result"]["next_before"].is_string());
    // Control bytes become six bytes each on the wire.
    *fx.fake.journal.lock().unwrap() = (0..500)
        .map(|i| (format!("c{i}"), "6".to_owned(), json!("\u{1}".repeat(3000))))
        .collect();
    assert_eq!(
        fx.call("logs", r#"{"unit":"core","lines":500}"#)["ok"],
        true
    );
}

/// F3: a PEM block that opened just before the page (in the lookahead entry) is masked.
#[test]
fn a_pem_block_that_opened_before_the_page_is_masked() {
    let fx = Fx::new();
    let mut entries: Vec<serde_json::Value> = (0..14).map(|i| json!(format!("line {i}"))).collect();
    entries.push(json!("-----BEGIN PRIVATE KEY-----"));
    entries.extend((0..3).map(|i| json!(format!("zq{i}"))));
    entries.push(json!("-----END PRIVATE KEY-----"));
    entries.extend((0..6).map(|i| json!(format!("after {i}"))));
    put(&fx, entries);
    // 24 entries, newest 10 are 14..23 and the lookahead is entry 13.. here BEGIN is entry 14.
    let v = fx.call("logs", r#"{"unit":"core","lines":10}"#);
    let t = texts(&v);
    assert!(!t.iter().any(|l| l.starts_with("zq")), "{t:?}");
    // Page two ends right at the opening line.
    let before = v["result"]["next_before"].as_str().unwrap().to_owned();
    let p = format!(r#"{{"unit":"core","lines":3,"before":"{before}"}}"#);
    assert!(
        !texts(&fx.call("logs", &p))
            .iter()
            .any(|l| l.starts_with("zq"))
    );
}

fn put(fx: &Fx, entries: Vec<serde_json::Value>) {
    *fx.fake.journal.lock().unwrap() = entries
        .into_iter()
        .enumerate()
        .map(|(i, m)| (format!("c{i}"), "6".to_owned(), m))
        .collect();
}

fn texts(v: &serde_json::Value) -> Vec<String> {
    v["result"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["text"].as_str().unwrap().to_owned())
        .collect()
}

/// F6: parallel instances serialise on one lock, so no count is lost: 160 calls, exactly 120 pass.
#[test]
fn read_limits_hold_under_parallel_instances() {
    let fx = Fx::new();
    let ok = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for _ in 0..20 {
                    if fx.call("status", "{}")["ok"] == true {
                        ok.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
        }
    });
    assert_eq!(ok.load(std::sync::atomic::Ordering::SeqCst), 120);
}

#[test]
fn status_is_120_per_minute_and_logs_60_per_minute() {
    let fx = Fx::new();
    fx.fake.fill_journal(2);
    for _ in 0..120 {
        assert_eq!(fx.call("status", "{}")["ok"], true);
    }
    let v = fx.call("status", "{}");
    assert_eq!(
        (v["code"].as_str(), v["retry_after"].as_u64()),
        (Some("rate_limited"), Some(60))
    );
    for _ in 0..60 {
        assert_eq!(
            fx.call("logs", r#"{"unit":"core"}"#)["ok"],
            true,
            "logs have their own budget"
        );
    }
    assert_eq!(fx.code("logs", r#"{"unit":"core"}"#), "rate_limited");
    fx.at(61);
    assert_eq!(
        fx.call("status", "{}")["ok"],
        true,
        "the minute rolled over"
    );
    assert_eq!(fx.call("logs", r#"{"unit":"core"}"#)["ok"], true);
    // A bad reads.json never refuses a read.
    std::fs::write(fx.state().join("reads.json"), b"garbage").unwrap();
    assert_eq!(fx.call("status", "{}")["ok"], true);
}

/// F7: a clock that stepped back must not lock restarts out for as long as the step.
#[test]
fn a_clock_stepped_back_does_not_block_restarts() {
    let fx = Fx::new();
    fx.at(100_000);
    assert_eq!(fx.call("restart_core", "{}")["ok"], true);
    fx.at(0); // back by more than a day
    assert_eq!(
        fx.call("restart_core", "{}")["ok"],
        true,
        "the future entry is dropped"
    );
    // A little skew counts as "now" rather than being dropped.
    fx.at(10);
    assert_eq!(fx.code("restart_core", "{}"), "rate_limited");
    // The dedupe record of a future request is ignored too.
    let id = fx.id();
    fx.at(500_000);
    assert_eq!(fx.send(&fx.line(&id, "restart_core", "{}"))["ok"], true);
    fx.at(1_000);
    assert_eq!(fx.send(&fx.line(&id, "restart_core", "{}"))["ok"], true);
    assert_eq!(
        fx.fake.restarts(),
        4,
        "the repeat was a new request, not a dedupe"
    );
}

/// A line of exactly 4096 bytes is accepted; 4097 is not.
#[test]
fn the_request_cap_is_exactly_4096_bytes() {
    let fx = Fx::new();
    let base = fx.line(&fx.id(), "status", "{}");
    for (len, want) in [(4096, true), (4097, false)] {
        let mut line = base.clone();
        line.resize(len, b' ');
        let (out, _) = fx.raw(&line, true);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["ok"] == true, want, "{len}: {v}");
    }
}

/// The owner check without root: a file or directory owned by anyone but `owner_uid` is unsafe.
#[test]
fn the_owner_uid_check_works_without_root() {
    let mut fx = Fx::new();
    let body = "#!/bin/sh\n";
    let sha = put_bin(&fx, "ainkrad-runner", body);
    manifest(&fx, &[("ainkrad-runner", "1", &sha, body.len())]);
    let v = fx.call("status", "{}");
    assert_eq!(v["result"]["binaries"][0]["state"], "ok");
    fx.ctx.owner_uid = ainkrad_sys::getuid() + 1; // "root" is somebody else
    fx.clear_reads();
    let v = fx.call("status", "{}");
    assert_eq!(v["result"]["binaries"][0]["state"], "unsafe");
    assert_eq!(v["result"]["bin_dir_safe"], false);
    let m = std::fs::metadata(fx.bin()).unwrap();
    assert_eq!(m.permissions().mode() & 0o022, 0);
}
