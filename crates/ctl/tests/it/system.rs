//! `system show | restart | logs` against a fake Core that answers the contract's shapes
//! (`/api/v1/system/…`): the output of each command, the body and query it sent, the step-up on
//! the runner logs, a 429's wait, and wrong usage (which sends nothing).

use std::process::Output;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use crate::common::*;
use crate::scheduler_fake::{body_json, device, prelude, refusal};

static ELEVATED: AtomicBool = AtomicBool::new(false);

fn core(method: &str, path: &str, body: &str) -> (u16, String) {
    if let Some(a) = prelude(method, path, body) {
        if path == "/api/v1/auth/step-up" {
            ELEVATED.store(true, Ordering::SeqCst);
        }
        return a;
    }
    match (method, path) {
        ("GET", "/api/v1/system/host") => (
            200,
            json!({"helper": "present", "host_id": "h_abc", "manifest": "ok", "bin_dir_safe": true,
                "binaries": [{"name": "ainkrad-core-server", "version": "0.1.0",
                              "sha256_12": "0123456789ab", "state": "ok"}],
                "units": {"core": {"state": "active", "sub": "running",
                                   "since": "Tue 2026-11-10 10:00:00 UTC", "restarts": 0}}})
            .to_string(),
        ),
        ("POST", "/api/v1/system/restart") => match body_json(body)["target"].as_str() {
            Some("core") => (202, json!({"request_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"}).to_string()),
            Some("runner") => refusal(429, "rate_limited", "too many requests; retry later"),
            _ => refusal(400, "bad_request", "no"),
        },
        ("GET", "/api/v1/system/logs/runner") if !ELEVATED.load(Ordering::SeqCst) => {
            refusal(403, "step_up_required", "elevate first")
        }
        ("GET", p) if p.starts_with("/api/v1/system/logs/") => (
            200,
            json!({"lines": [{"at": "2026-11-10T10:00:00.000Z", "level": "info", "text": "started"}],
                   "next_before": "s=abc;i=1"})
            .to_string(),
        ),
        _ => (500, "{}".into()),
    }
}

fn run_ctl(ks: &str, words: &[&str]) -> Output {
    ctl(&args(&[&s(&["--keystore", ks]), &s(words)]))
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn show_restart_and_logs_say_what_the_core_said() {
    let (fake, ks) = device("sys-basic", core, true);
    let o = run_ctl(&ks, &["system", "show"]);
    assert!(o.status.success(), "{o:?}");
    let text = stdout(&o);
    assert!(
        text.starts_with("helper\tpresent\nhost_id\th_abc\nmanifest\tok\n"),
        "{text}"
    );
    assert!(
        text.contains("ainkrad-core-server\t0.1.0\t0123456789ab\tok"),
        "{text}"
    );
    assert!(
        text.contains("core\tactive/running\tsince Tue 2026-11-10 10:00:00 UTC\trestarts 0"),
        "{text}"
    );

    let o = run_ctl(&ks, &["system", "restart", "core"]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), "accepted 01ARZ3NDEKTSV4RRFFQ69G5FAV\n");
    let sent = fake
        .requests()
        .into_iter()
        .find(|r| r.starts_with("post /api/v1/system/restart "))
        .unwrap();
    assert_eq!(
        body_json(sent.rsplit("\r\n").next().unwrap()),
        json!({"target": "core"})
    );

    // The helper's limit: the Core's 429 and its Retry-After, in plain words.
    let o = run_ctl(&ks, &["system", "restart", "runner"]);
    assert!(
        !o.status.success() && err(&o).contains("try again in 7 s"),
        "{o:?}"
    );

    let o = run_ctl(
        &ks,
        &["system", "logs", "core", "-n", "5", "--before", "s=abc;i=1"],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        "2026-11-10T10:00:00.000Z info started\nolder: --before s=abc;i=1\n"
    );
    let line = fake
        .requests()
        .into_iter()
        .find(|r| r.starts_with("get /api/v1/system/logs/core"))
        .unwrap();
    assert!(
        line.starts_with("get /api/v1/system/logs/core?lines=5&before=s%3dabc%3bi%3d1 ")
            || line.starts_with("get /api/v1/system/logs/core?lines=5&before=s%3Dabc%3Bi%3D1 "),
        "{line}"
    );
    let o = run_ctl(&ks, &["--json", "system", "logs", "helper"]);
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["next_before"], "s=abc;i=1");
}

#[test]
fn the_runner_logs_elevate_once_and_a_device_without_a_key_is_told() {
    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("sys-step", core, true);
    let o = run_ctl(&ks, &["system", "logs", "runner"]);
    assert!(o.status.success(), "{o:?}");
    let hits = |line: &str| {
        fake.requests()
            .iter()
            .filter(|r| r.starts_with(line))
            .count()
    };
    assert_eq!(hits("get /api/v1/system/logs/runner"), 2);
    assert_eq!(hits("post /api/v1/auth/step-up "), 1);

    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("sys-nokey", core, false);
    let o = run_ctl(&ks, &["system", "logs", "runner"]);
    assert_eq!(o.status.code(), Some(9), "{o:?}");
    assert!(err(&o).contains("no step-up key"), "{o:?}");
    assert_eq!(
        fake.requests()
            .iter()
            .filter(|r| r.starts_with("get /api/v1/system/logs/runner"))
            .count(),
        1
    );
}

#[test]
fn wrong_usage_sends_nothing() {
    let (fake, ks) = device("sys-usage", core, false);
    for w in [
        &["system"][..],
        &["system", "restart"],
        &["system", "restart", "all"],
        &["system", "logs"],
        &["system", "logs", "kernel"],
        &["system", "logs", "core", "-n", "0"],
        &["system", "logs", "core", "-n", "501"],
        &["system", "logs", "core", "--before", "-r"],
        &["system", "logs", "core", "--before", "a b"],
    ] {
        let o = run_ctl(&ks, w);
        assert_eq!(o.status.code(), Some(2), "{w:?}: {o:?}");
        assert!(stdout(&o).is_empty(), "{w:?}");
    }
    assert_eq!(fake.requests().len(), 0, "nor a handshake");
}
