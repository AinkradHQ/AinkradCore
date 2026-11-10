//! Restart actions: rate limits, dedupe, the lock, fail-closed state, and the log.
mod common;

use common::*;

const CORE: [&str; 3] = ["--no-block", "restart", "ainkrad-core.service"];

#[test]
fn restart_core_runs_one_fixed_argv_and_answers_accepted() {
    let fx = Fx::new();
    let v = fx.call("restart_core", "{}");
    assert_eq!(
        (v["ok"].clone(), v["result"]["accepted"].clone()),
        (true.into(), true.into())
    );
    assert_eq!(fx.fake.argv(), vec![CORE.map(String::from).to_vec()]);
    assert_eq!(fx.fake.programs(), ["/usr/bin/systemctl"]);
    let log = fx.log();
    assert!(
        log.contains(" accepted restart_core ") && log.contains("claimed_by_core=d_test-1#42"),
        "{log}"
    );
}

#[test]
fn restart_core_is_rate_limited_and_the_limit_survives_a_restart_of_the_helper() {
    let mut fx = Fx::new();
    assert_eq!(fx.call("restart_core", "{}")["ok"], true);
    // At once: 60 s minimum between two.
    let v = fx.call("restart_core", "{}");
    assert_eq!(
        (v["code"].as_str(), v["retry_after"].as_u64()),
        (Some("rate_limited"), Some(60))
    );
    fx.at(45);
    assert_eq!(fx.call("restart_core", "{}")["retry_after"], 15);
    fx = fx.again(); // "a Core restart or a wiped Core home resets nothing": only files carry state
    fx.at(60);
    assert_eq!(fx.call("restart_core", "{}")["ok"], true);
    fx.at(120);
    assert_eq!(fx.call("restart_core", "{}")["ok"], true);
    // The fourth inside 10 minutes.
    fx.at(180);
    let v = fx.call("restart_core", "{}");
    assert_eq!(
        (v["code"].as_str(), v["retry_after"].as_u64()),
        (Some("rate_limited"), Some(420))
    );
    fx.at(601);
    assert_eq!(
        fx.call("restart_core", "{}")["ok"],
        true,
        "the first aged out"
    );
    assert_eq!(fx.fake.restarts(), 3, "since the helper restarted");
}

#[test]
fn restart_runner_needs_the_runner_installed_and_allows_six_per_ten_minutes() {
    let fx = Fx::new();
    assert_eq!(fx.code("restart_runner", "{}"), "not_installed");
    assert_eq!(fx.fake.restarts(), 0);
    assert!(
        !fx.state().join("limits.json").exists(),
        "a refusal costs no budget"
    );
    fx.fake.load("ainkrad-runner.service");
    for i in 0..6 {
        fx.at(i);
        assert_eq!(fx.call("restart_runner", "{}")["ok"], true, "{i}");
    }
    fx.at(7);
    let v = fx.call("restart_runner", "{}");
    assert_eq!(
        (v["code"].as_str(), v["retry_after"].as_u64()),
        (Some("rate_limited"), Some(593))
    );
    assert!(
        fx.fake.argv().contains(
            &["--no-block", "restart", "ainkrad-runner.service"]
                .map(String::from)
                .to_vec()
        )
    );
}

#[test]
fn a_repeated_id_returns_the_stored_result_and_does_nothing_again() {
    let fx = Fx::new();
    let id = fx.id();
    let first = fx.send(&fx.line(&id, "restart_core", "{}"));
    fx.at(5);
    let second = fx.send(&fx.line(&id, "restart_core", "{}"));
    assert_eq!(first, second);
    assert_eq!(fx.fake.restarts(), 1);
    assert!(fx.log().contains(" deduped restart_core "));
    // The same id for another action is not a repeat.
    let other = fx.send(&fx.line(&id, "restart_runner", "{}"));
    assert_eq!(other["code"], "bad_request");
    // After the window it is a new request (and the rate limit decides).
    fx.at(700);
    assert_eq!(fx.send(&fx.line(&id, "restart_core", "{}"))["ok"], true);
    assert_eq!(fx.fake.restarts(), 2);
}

#[test]
fn reads_are_never_deduped() {
    let fx = Fx::new();
    let id = fx.id();
    for _ in 0..2 {
        assert_eq!(fx.send(&fx.line(&id, "status", "{}"))["ok"], true);
    }
    let shows = fx.fake.argv().iter().filter(|a| a[0] == "show").count();
    assert_eq!(shows, 6, "three units, twice");
}

#[test]
fn a_failed_systemctl_is_failed_and_a_repeat_says_so() {
    let fx = Fx::new();
    *fx.fake.restart_fails.lock().unwrap() = true;
    let id = fx.id();
    assert_eq!(
        fx.send(&fx.line(&id, "restart_core", "{}"))["code"],
        "failed"
    );
    assert_eq!(
        fx.send(&fx.line(&id, "restart_core", "{}"))["code"],
        "failed"
    );
    assert_eq!(fx.fake.restarts(), 1);
    assert!(fx.log().contains(" failed restart_core "));
}

#[test]
fn a_held_lock_is_busy_and_reads_still_work() {
    let fx = Fx::new();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(fx.state().join("lock"))
        .unwrap();
    lock.try_lock().unwrap();
    assert_eq!(fx.code("restart_core", "{}"), "busy");
    assert_eq!(fx.fake.restarts(), 0);
    assert_eq!(fx.call("status", "{}")["ok"], true);
    drop(lock);
    assert_eq!(fx.call("restart_core", "{}")["ok"], true);
}

#[test]
fn a_corrupt_limits_file_fails_closed_and_is_never_reset() {
    let fx = Fx::new();
    let path = fx.state().join("limits.json");
    for bad in [
        &b"{not json"[..],
        b"",
        b"{\"v\":1,\"restarts\":{},\"done\":[],\"extra\":1}",
        &vec![b' '; 300_000],
    ] {
        std::fs::write(&path, bad).unwrap();
        assert_eq!(fx.code("restart_core", "{}"), "state_unavailable");
        assert_eq!(fx.code("restart_runner", "{}"), "state_unavailable");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bad,
            "the bad copy is left alone"
        );
        // Reads work.
        assert_eq!(fx.call("status", "{}")["ok"], true);
    }
    fx.fake.fill_journal(3);
    assert_eq!(fx.call("logs", r#"{"unit":"core"}"#)["ok"], true);
    assert_eq!(fx.fake.restarts(), 0);
    // A symlink in its place is not followed either.
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", &path).unwrap();
    assert_eq!(fx.code("restart_core", "{}"), "state_unavailable");
    // Recovery is `rm`: then it works.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(fx.call("restart_core", "{}")["ok"], true);
}

#[test]
fn an_unwritable_limits_file_or_log_fails_closed_before_anything_runs() {
    let fx = Fx::new();
    // The temp file's place is a directory: the write fails for root and non-root alike.
    std::fs::create_dir(fx.state().join("limits.json.tmp")).unwrap();
    assert_eq!(fx.code("restart_core", "{}"), "state_unavailable");
    assert_eq!(fx.fake.restarts(), 0);
    assert!(!fx.state().join("limits.json").exists());
    assert_eq!(fx.call("status", "{}")["ok"], true, "reads still work");
    std::fs::remove_dir(fx.state().join("limits.json.tmp")).unwrap();

    // No unlogged root action: an actions.log that cannot be appended refuses a restart.
    let _ = std::fs::remove_file(fx.state().join("actions.log"));
    std::fs::create_dir(fx.state().join("actions.log")).unwrap();
    let v = fx.call("restart_core", "{}");
    assert_eq!(v["code"], "state_unavailable");
    assert_eq!(fx.fake.restarts(), 0);
}

#[test]
fn a_missing_state_directory_refuses_mutations_and_still_answers_reads() {
    let mut fx = Fx::new();
    fx.ctx.state_dir = fx.dir.path().join("nowhere");
    assert_eq!(fx.code("restart_core", "{}"), "state_unavailable");
    assert_eq!(fx.call("status", "{}")["ok"], true);
}

#[test]
fn actions_log_is_capped_rotated_and_holds_no_successful_read() {
    let fx = Fx::new();
    fx.fake.fill_journal(3);
    assert_eq!(fx.call("status", "{}")["ok"], true);
    assert_eq!(fx.call("logs", r#"{"unit":"core"}"#)["ok"], true);
    assert_eq!(fx.log(), "", "successful reads leave no trace");
    let junk = br#"{"v":1}"#;
    for _ in 0..20_000 {
        fx.raw(junk, true);
    }
    let len = |n: &str| {
        std::fs::metadata(fx.state().join(n))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    assert!(len("actions.log") <= 1 << 20 && len("actions.log") > 0);
    assert!(
        len("actions.log.1") <= 1 << 20 && len("actions.log.1") > 0,
        "rotated once"
    );
    assert!(
        !fx.state().join("actions.log.2").exists(),
        "two generations, no more"
    );
    let all = format!(
        "{}{}",
        std::fs::read_to_string(fx.state().join("actions.log.1")).unwrap(),
        fx.log()
    );
    assert!(!all.contains(" ok status") && !all.contains(" ok logs"));
    // Sequence numbers keep rising across the rotation.
    let seqs: Vec<u64> = all
        .lines()
        .map(|l| l.split(' ').next().unwrap().parse().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "contiguous");
    assert_eq!(*seqs.last().unwrap(), 20_000);
}

#[test]
fn the_helper_log_pages_over_actions_log_and_its_rotation() {
    let fx = Fx::new();
    for i in 0..25 {
        fx.at(i);
        fx.raw(br#"{"v":1}"#, true);
    }
    let mut seen = Vec::new();
    let mut before: Option<String> = None;
    for page in 0..3 {
        let p = match &before {
            None => r#"{"unit":"helper","lines":10}"#.to_string(),
            Some(c) => format!(r#"{{"unit":"helper","lines":10,"before":"{c}"}}"#),
        };
        let v = fx.call("logs", &p);
        let lines = v["result"]["lines"].as_array().unwrap();
        assert_eq!(lines.len(), if page == 2 { 5 } else { 10 }, "page {page}");
        seen.extend(
            lines
                .iter()
                .rev()
                .map(|l| l["text"].as_str().unwrap().to_owned()),
        );
        before = v["result"]["next_before"].as_str().map(str::to_owned);
        assert_eq!(before.is_some(), page < 2);
    }
    assert_eq!(seen.len(), 25, "no entry repeated or skipped");
    assert_eq!(
        fx.code("logs", r#"{"unit":"helper","before":"s=1"}"#),
        "bad_request"
    );
}
