//! `chains`, the scheduler fields on `agent run|show`, `account` and `setting`, against a fake
//! Core that answers the contract's shapes (S7, `api/openapi.json`) and records every request:
//! the output of each command, the body it sent, how a 400/404/409 is said, the step-up flow,
//! JSON mode and wrong usage (which must send nothing).

use std::process::Output;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::common::*;
use crate::fake::Fake;
use crate::scheduler_fake::{
    CHAIN, DEVICE, ELEVATED, GATED, SESSION, body_json, core, device, gated,
};

fn run(ks: &str, words: &[&str]) -> Output {
    ctl(&args(&[&s(&["--keystore", ks]), &s(words)]))
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The JSON body of the first recorded request that starts with `line` (lower-cased head).
fn sent(fake: &Fake, line: &str) -> Value {
    sent_nth(fake, line, 0)
}

fn sent_nth(fake: &Fake, line: &str, n: usize) -> Value {
    let all = fake.requests();
    let r = all
        .iter()
        .filter(|r| r.starts_with(line))
        .nth(n)
        .unwrap_or_else(|| panic!("no #{n} `{line}` in {all:#?}"));
    // The head ends with CRLF and the body follows it.
    body_json(r.rsplit("\r\n").next().unwrap_or_default())
}

fn api_requests(fake: &Fake) -> usize {
    fake.requests()
        .iter()
        .filter(|r| r.contains(" /api/v1/"))
        .count()
}

const ROW: &str = "1\tmain\tdefault\t2 entries\t2026-11-06T01:00:00.000Z\n";
const ENTRIES: &str =
    "  [0]\tpool 2\tanthropic\tclaude\tsonnet-x\n  [1]\tpool 5\topenai\tcodex\tdefault\n";

#[test]
fn chains_read_commands_print_the_golden_output() {
    let (_fake, ks) = device("ch-read", core, false);
    let ok = |w: &[&str]| {
        let o = run(&ks, w);
        assert!(o.status.success(), "{w:?}: {o:?}");
        stdout(&o)
    };
    assert_eq!(ok(&["chains", "ls"]), ROW);
    assert_eq!(ok(&["chains", "list"]), ROW);
    assert_eq!(ok(&["chains", "show", "1"]), format!("{ROW}{ENTRIES}"));
    assert_eq!(ok(&["chain", "show", "1"]), format!("{ROW}{ENTRIES}"));
    assert_eq!(ok(&["chains", "bindings"]), "bot\tchain 1\n");
}

#[test]
fn chains_write_commands_send_the_entries_and_say_what_they_did() {
    let (fake, ks) = device("ch-write", core, false);
    let ok = |w: &[&str]| {
        let o = run(&ks, w);
        assert!(o.status.success(), "{w:?}: {o:?}");
        stdout(&o)
    };
    assert_eq!(
        ok(&["chains", "create", "main", "2:sonnet-x", "5"]),
        format!("{ROW}{ENTRIES}")
    );
    assert_eq!(
        sent(&fake, "post /api/v1/chains "),
        json!({"name": "main", "entries": [{"pool": 2, "model": "sonnet-x"}, {"pool": 5}]})
    );
    assert_eq!(
        ok(&["chains", "update", "1", "main", "5:m:2"]),
        format!("{ROW}{ENTRIES}")
    );
    assert_eq!(
        sent(&fake, "put /api/v1/chains/1 "),
        json!({"name": "main", "entries": [{"pool": 5, "model": "m:2"}]})
    );
    assert_eq!(ok(&["chains", "default", "1"]), format!("{ROW}{ENTRIES}"));
    assert_eq!(ok(&["chains", "delete", "1"]), "deleted chain 1\n");
    assert_eq!(
        ok(&["chains", "bind", "bot", "1"]),
        "bound agent bot to chain 1\n"
    );
    assert_eq!(
        sent(&fake, "put /api/v1/chains/bindings/bot "),
        json!({"chain": 1})
    );
    assert_eq!(ok(&["chains", "unbind", "bot"]), "unbound agent bot\n");
}

#[test]
fn a_400_404_409_is_said_plainly_and_exits_4() {
    let (_fake, ks) = device("ch-err", core, false);
    for (w, say) in [
        (
            &["chains", "create", "dup", "2"][..],
            "409 conflict: creating chain \"dup\": a chain of that name exists",
        ),
        (
            &["chains", "create", "bad", "2", "5"],
            "400 bad_request: creating chain \"bad\": a pool is in the chain twice",
        ),
        (
            // An empty reason still reads as a sentence.
            &["chains", "create", "ghost", "2"],
            "404 not_found: creating chain \"ghost\": not found",
        ),
        (
            &["chains", "show", "404"],
            "404 not_found: chain 404: no such chain",
        ),
        (
            &["chains", "delete", "404"],
            "404 not_found: deleting chain 404: no such chain",
        ),
        (
            &["chains", "delete", "2"],
            "409 conflict: deleting chain 2: 1 live session(s) walk the chain",
        ),
        (
            &["chains", "unbind", "none"],
            "404 not_found: unbinding agent none: that agent has no binding",
        ),
    ] {
        let o = run(&ks, w);
        assert_eq!(o.status.code(), Some(4), "{w:?}: {o:?}");
        assert_eq!(err(&o), format!("ainkradctl: {say}\n"), "{w:?}");
        assert!(stdout(&o).is_empty());
    }
}

#[test]
fn wrong_usage_exits_2_and_sends_nothing() {
    let (fake, ks) = device("ch-usage", core, false);
    for w in [
        &["chains"][..],
        &["chains", "nope"],
        &["chains", "create", "main"],
        &["chains", "create", "main", "x"],
        &["chains", "create", "main", "2:"],
        &["chains", "update", "1", "main"],
        &["chains", "show", "abc"],
        &["chains", "show", "0"],
        &["chains", "delete"],
        &["chains", "bind", "a/b", "1"],
        &["chains", "bind", "bot", "x"],
        &["chains", "unbind", "../x"],
        &["agent", "run", DEVICE],
        &["agent", "run", DEVICE, "--chain", "x"],
        &["agent", "run", DEVICE, "--agent", "a/b"],
        &["account", "show", "x"],
        &["account", "nope"],
        &["setting", "set", "scheduler.max_hops", "many"],
        &["setting", "get", "../x"],
        &["setting", "set", "scheduler.max_hops"],
    ] {
        let o = run(&ks, w);
        assert_eq!(o.status.code(), Some(2), "{w:?}: {o:?}");
        assert!(!err(&o).is_empty() && stdout(&o).is_empty(), "{w:?}");
    }
    assert_eq!(api_requests(&fake), 0, "usage errors reach no route");
    assert_eq!(fake.requests().len(), 0, "nor a handshake");
}

#[test]
fn a_step_up_is_done_once_and_the_write_retried_once() {
    let (fake, ks) = device("ch-step", gated, true);
    let o = run(&ks, &["chains", "create", "main", "2"]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), format!("{ROW}{ENTRIES}"));
    let hits = |line: &str| {
        fake.requests()
            .iter()
            .filter(|r| r.starts_with(line))
            .count()
    };
    assert_eq!(hits("post /api/v1/chains "), 2);
    assert_eq!(hits("post /api/v1/auth/step-up "), 1);
    assert_eq!(GATED.load(Ordering::SeqCst), 2);

    // A device with no step-up key: exit 9, the write tried once, no step-up sent.
    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("ch-nokey", gated, false);
    let o = run(&ks, &["chains", "create", "main", "2"]);
    assert_eq!(o.status.code(), Some(9), "{o:?}");
    assert!(err(&o).contains("no step-up key"), "{o:?}");
    let hits = |line: &str| {
        fake.requests()
            .iter()
            .filter(|r| r.starts_with(line))
            .count()
    };
    assert_eq!(hits("post /api/v1/chains "), 1);
    assert_eq!(hits("post /api/v1/auth/step-up "), 0);
}

#[test]
fn json_mode_prints_the_cores_json_untouched() {
    let (_fake, ks) = device("ch-json", core, false);
    let json_of = |w: &[&str]| -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(w);
        let o = run(&ks, &all);
        assert!(o.status.success(), "{w:?}: {o:?}");
        serde_json::from_str(&stdout(&o)).unwrap_or_else(|e| panic!("{w:?}: {e}: {o:?}"))
    };
    let chain: Value = serde_json::from_str(CHAIN).unwrap();
    assert_eq!(json_of(&["chains", "ls"]), json!([chain]));
    assert_eq!(json_of(&["chains", "show", "1"]), chain);
    assert_eq!(
        json_of(&["chains", "delete", "1"]),
        json!({"deleted": true})
    );
    assert_eq!(
        json_of(&["chains", "bindings"]),
        json!([{"agent": "bot", "chain": 1}])
    );
    assert_eq!(
        json_of(&["chains", "bind", "bot", "1"]),
        json!({"agent": "bot", "chain": 1})
    );
    assert_eq!(json_of(&["agent", "show", SESSION])["chain_id"], json!(1));
    assert_eq!(json_of(&["account", "show", "7"])["live"], json!(2));
    assert_eq!(
        json_of(&["setting", "ls", "scheduler."])
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        json_of(&["setting", "get", "scheduler.max_hops"])["value"],
        json!(3)
    );
}

#[test]
fn agent_run_with_a_chain_names_no_harness_and_plain_runs_are_unchanged() {
    let (fake, ks) = device("ch-run", core, false);
    let o = run(
        &ks,
        &["agent", "run", DEVICE, "fix", "the", "bug", "--chain", "1"],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent(&fake, "post /api/v1/agent-sessions "),
        json!({"runner": DEVICE, "chain": 1, "prompt": "fix the bug"})
    );
    let o = run(
        &ks,
        &["agent", "start", DEVICE, "--chain", "1", "--agent", "bot"],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent_nth(&fake, "post /api/v1/agent-sessions ", 1),
        json!({"runner": DEVICE, "chain": 1, "agent": "bot"})
    );
    let o = run(&ks, &["agents", "run", DEVICE, "--agent", "bot"]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent_nth(&fake, "post /api/v1/agent-sessions ", 2),
        json!({"runner": DEVICE, "agent": "bot"})
    );

    // Plain: the harness is the first word after the runner, as before.
    let (fake, ks) = device("ch-plain", core, false);
    let o = run(&ks, &["agent", "run", DEVICE, "claude", "hello", "there"]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent(&fake, "post /api/v1/agent-sessions "),
        json!({"runner": DEVICE, "harness": "claude", "prompt": "hello there"})
    );
    assert!(
        stdout(&o).starts_with(&format!("{SESSION}\tstarting\tclaude\t{DEVICE}\t")),
        "{o:?}"
    );
}

#[test]
fn agent_show_prints_the_scheduler_fields_after_the_row() {
    let (_fake, ks) = device("ch-show", core, false);
    let o = run(&ks, &["agent", "show", SESSION]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        format!(
            "{SESSION}\tstarting\tclaude\t{DEVICE}\tseq 1\ttokens 0/0\t2026-11-06T00:00:00.000Z\n\
agent bot\n\
chain 1 position 1\n\
\x20  [0]\tpool 2\tanthropic\tclaude\tsonnet-x\n\
>  [1]\tpool 5\topenai\tcodex\tdefault\n\
account 9\n\
waiting until 2026-11-06T00:10:00.000Z since 2026-11-06T00:00:00.000Z: every account is cooling\n\
repicked 1\n\
upstream_class rate_limited\n\
1\t\"hello\"\n"
        )
    );
}

#[test]
fn accounts_show_their_live_count_and_health() {
    let (_fake, ks) = device("ch-acct", core, false);
    let o = run(&ks, &["account", "ls"]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        "7\tanthropic\twork\tcooling\tlive 2/3\tfail 1 auth 0\n8\topenai\thome\tactive\tlive 0/-\tfail 0 auth 0\n"
    );
    let o = run(&ks, &["accounts", "show", "7"]);
    assert_eq!(
        stdout(&o),
        "7\tanthropic\twork\tcooling\tlive 2/3\tfail 1 auth 0\n\
state_reason rate_limited until 2026-11-06T02:00:00.000Z\n\
last_success 2026-11-06T01:30:00.000Z\n\
upstream_class rate_limited\n"
    );
}

#[test]
fn scheduler_settings_are_read_and_set_through_the_core() {
    let (fake, ks) = device("ch-set", core, false);
    let o = run(&ks, &["setting", "ls", "scheduler."]);
    assert_eq!(
        stdout(&o),
        "scheduler.max_hops\t3 count\t(default 3, 0..8)\tdefault\n\
scheduler.wait_max_secs\t600 seconds\t(default 900, 1..86400)\tserver\n"
    );
    let o = run(&ks, &["settings", "set", "scheduler.max_hops", "3"]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        sent(&fake, "put /api/v1/settings/server/scheduler.max_hops "),
        json!({"value": 3})
    );
    // The range is the Core's: a value out of it is the Core's refusal, not ctl's.
    let o = run(&ks, &["setting", "set", "scheduler.max_hops", "9"]);
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert!(
        err(&o).contains("400 out_of_bounds: scheduler.max_hops is 0 to 8"),
        "{o:?}"
    );
    let o = run(&ks, &["setting", "get", "nope"]);
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    let o = run(&ks, &["setting", "reset", "scheduler.max_hops"]);
    assert!(o.status.success(), "{o:?}");
    let deleted = "delete /api/v1/settings/server/scheduler.max_hops ";
    assert!(fake.requests().iter().any(|r| r.starts_with(deleted)));
}
