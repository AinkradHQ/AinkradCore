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

/// A closed stderr (EPIPE) must not panic the helper, and a restart that did run must be recorded.
/// The scenario runs in a child test process whose stderr is a pipe with no reader.
#[test]
fn a_closed_stderr_never_panics_or_leaves_a_false_accepted() {
    if std::env::var("HOST_STDERR_CLOSED").is_ok() {
        let fx = Fx::new();
        let id = fx.id();
        assert_eq!(fx.send(&fx.line(&id, "restart_core", "{}"))["ok"], true);
        assert_eq!(fx.fake.restarts(), 1);
        let kept = std::fs::read_to_string(fx.state().join("mutations.log")).unwrap();
        assert!(
            kept.contains(" accepted restart_core ") && kept.contains(&id),
            "{kept}"
        );
        // And when the record cannot be written, a repeat must not read "accepted" either.
        std::fs::remove_file(fx.state().join("mutations.log")).unwrap();
        std::fs::create_dir(fx.state().join("mutations.log")).unwrap();
        fx.at(120);
        let id2 = fx.id();
        assert_eq!(
            fx.send(&fx.line(&id2, "restart_core", "{}"))["code"],
            "state_unavailable"
        );
        assert_eq!(
            fx.send(&fx.line(&id2, "restart_core", "{}"))["code"],
            "failed"
        );
        assert_eq!(fx.fake.restarts(), 1);
        return;
    }
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_closed_stderr_never_panics_or_leaves_a_false_accepted",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("HOST_STDERR_CLOSED", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(writer)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The in-app `helper` view lists root-action records from `mutations.log`, even when the shared
/// log has lost them, and a line that is in both logs is listed once.
#[test]
fn the_helper_view_shows_mutations_log_and_lists_a_shared_line_once() {
    let fx = Fx::new();
    let line = format!(
        "1 {T0} accepted restart_core peer=1 id={} claimed_by_core=d_x#1\n",
        fx.id()
    );
    std::fs::write(fx.state().join("mutations.log"), &line).unwrap();
    let v = fx.call("logs", r#"{"unit":"helper"}"#);
    assert_eq!(texts(&v).len(), 1, "{v}");
    assert!(texts(&v)[0].starts_with("accepted restart_core "));
    std::fs::write(fx.state().join("actions.log"), line.replacen("1 ", "7 ", 1)).unwrap();
    assert_eq!(texts(&fx.call("logs", r#"{"unit":"helper"}"#)).len(), 1);
    // Paging uses its own cursor format.
    let v = fx.call("logs", r#"{"unit":"helper","lines":1}"#);
    assert!(v["result"].get("next_before").is_none());
}

/// A state directory that is not root-only (or sits under a writable parent) refuses mutations,
/// and `status` says so.
#[test]
fn an_unsafe_state_directory_refuses_mutations_and_is_reported() {
    let fx = Fx::new();
    assert_eq!(fx.call("status", "{}")["result"]["state_dir_safe"], true);
    let st = std::fs::Permissions::from_mode;
    std::fs::set_permissions(fx.state(), st(0o750)).unwrap();
    assert_eq!(fx.code("restart_core", "{}"), "state_unavailable");
    assert_eq!(fx.call("status", "{}")["result"]["state_dir_safe"], false);
    std::fs::set_permissions(fx.state(), st(0o700)).unwrap();
    std::fs::set_permissions(fx.dir.path(), st(0o777)).unwrap();
    assert_eq!(fx.code("restart_core", "{}"), "state_unavailable");
    std::fs::set_permissions(fx.dir.path(), st(0o700)).unwrap();
    // Owned by someone else than the owner uid.
    let mut other = Fx::new();
    other.ctx.owner_uid = ainkrad_sys::getuid() + 1;
    assert_eq!(other.code("restart_core", "{}"), "state_unavailable");
    assert_eq!(fx.fake.restarts() + other.fake.restarts(), 0);
    assert_eq!(fx.call("restart_core", "{}")["ok"], true, "safe again");
}

/// Repeats of a request leave no trace: no growth of any log.
#[test]
fn repeats_are_silent() {
    let fx = Fx::new();
    let id = fx.id();
    fx.send(&fx.line(&id, "restart_core", "{}"));
    let size = || {
        std::fs::metadata(fx.state().join("mutations.log"))
            .unwrap()
            .len()
    };
    let before = (size(), fx.log().len());
    for _ in 0..50 {
        assert_eq!(fx.send(&fx.line(&id, "restart_core", "{}"))["ok"], true);
    }
    assert_eq!((size(), fx.log().len()), before);
}

/// One enormous line is cut before redaction, so it costs bounded time, and what was cut is masked.
#[test]
fn an_enormous_log_line_is_cut_before_it_is_redacted() {
    let fx = Fx::new();
    let huge = format!("password:\"{}", "\\".repeat(2 << 20));
    let more = format!("{} sk-ant-api03-{}", "word ".repeat(30_000), "Z".repeat(40));
    put(&fx, vec![json!(huge), json!(more)]);
    let started = std::time::Instant::now();
    let v = fx.call("logs", r#"{"unit":"core"}"#);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    let t = texts(&v);
    assert_eq!(t[0], "password:[redacted:password]");
    assert!(!t[1].contains("ZZZZ"));
}
