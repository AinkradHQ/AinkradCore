//! `logs`: fixed argv, the cursor, paging, and redaction of what comes back.
mod common;

use ainkrad_proto::redact::PLANTED;
use common::*;
use serde_json::{Value, json};

fn texts(v: &Value) -> Vec<String> {
    v["result"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["text"].as_str().unwrap().to_owned())
        .collect()
}

fn s(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}

#[test]
fn the_argv_is_fixed_and_the_cursor_is_one_element() {
    let fx = Fx::new();
    fx.fake.fill_journal(30);
    fx.call("logs", r#"{"unit":"core"}"#);
    fx.call("logs", r#"{"unit":"runner","lines":5}"#);
    fx.call("logs", r#"{"unit":"backup","lines":500,"before":"c9"}"#);
    let argv = fx.fake.argv();
    assert_eq!(
        argv[0],
        s(&[
            "-u",
            "ainkrad-core.service",
            "-o",
            "json",
            "--no-pager",
            "-n",
            "201"
        ])
    );
    assert_eq!(
        argv[1],
        s(&[
            "-u",
            "ainkrad-runner.service",
            "-o",
            "json",
            "--no-pager",
            "-n",
            "6"
        ])
    );
    assert_eq!(
        argv[2],
        s(&[
            "-u",
            "ainkrad-backup.service",
            "-o",
            "json",
            "--no-pager",
            "-n",
            "501",
            "-r",
            "--cursor=c9"
        ])
    );
    assert_eq!(fx.fake.programs(), ["/usr/bin/journalctl"; 3]);
    assert!(fx.log().is_empty(), "reads leave no trace");
}

#[test]
fn a_bad_cursor_or_unit_never_reaches_journalctl() {
    let fx = Fx::new();
    fx.fake.fill_journal(3);
    for p in [
        r#"{"unit":"core","before":"-r"}"#,
        r#"{"unit":"core","before":"--cursor-file=/etc/shadow"}"#,
        r#"{"unit":"core","before":"-"}"#,
        r#"{"unit":"core","before":"a;b c"}"#,
        r#"{"unit":"ssh"}"#,
        r#"{"unit":"core","lines":0}"#,
        r#"{"unit":"core","lines":501}"#,
    ] {
        assert_eq!(fx.code("logs", p), "bad_request", "{p}");
    }
    assert!(fx.fake.calls.lock().unwrap().is_empty());
}

#[test]
fn three_pages_neither_repeat_nor_skip() {
    let fx = Fx::new();
    fx.fake.fill_journal(25);
    let mut seen: Vec<String> = Vec::new();
    let mut before: Option<String> = None;
    for page in 0..3 {
        let p = match &before {
            None => r#"{"unit":"core","lines":10}"#.to_string(),
            Some(c) => format!(r#"{{"unit":"core","lines":10,"before":"{c}"}}"#),
        };
        let v = fx.call("logs", &p);
        let mut t = texts(&v);
        assert_eq!(t.len(), if page == 2 { 5 } else { 10 }, "page {page}");
        t.reverse();
        seen.extend(t);
        before = v["result"]["next_before"].as_str().map(str::to_owned);
        assert_eq!(before.is_some(), page < 2, "page {page}: {v}");
    }
    let want: Vec<String> = (0..25).rev().map(|i| format!("line {i}")).collect();
    assert_eq!(seen, want, "newest first across pages, every line once");
    // Each page is oldest-first within itself, newest at the bottom.
    let first = texts(&fx.call("logs", r#"{"unit":"core","lines":3}"#));
    assert_eq!(first, ["line 22", "line 23", "line 24"]);
    // A short journal has nothing older.
    fx.fake.fill_journal(2);
    assert!(
        fx.call("logs", r#"{"unit":"core","lines":10}"#)["result"]
            .get("next_before")
            .is_none()
    );
}

#[test]
fn a_failing_journalctl_is_failed() {
    let fx = Fx::new();
    *fx.fake.journal_fails.lock().unwrap() = true;
    assert_eq!(fx.code("logs", r#"{"unit":"core"}"#), "failed");
    assert!(fx.log().contains(" refused logs ") && fx.log().contains("code=failed"));
}

fn put(fx: &Fx, entries: Vec<Value>) {
    *fx.fake.journal.lock().unwrap() = entries
        .into_iter()
        .enumerate()
        .map(|(i, m)| (format!("c{i}"), "6".into(), m))
        .collect();
}

fn all(fx: &Fx) -> Vec<String> {
    texts(&fx.call("logs", r#"{"unit":"core","lines":500}"#))
}

#[test]
fn every_secret_shape_and_connection_token_is_masked() {
    let fx = Fx::new();
    let mut entries: Vec<Value> = PLANTED
        .iter()
        .map(|(_, secret)| json!(format!("connected with {secret} ok")))
        .collect();
    entries.push(json!(r#"{"level":"INFO","fields":{"message":"hello","access_token":"abc123","connection":{"password":"pw1"}}}"#));
    entries.push(json!("login failed password=hunter22 user=bob"));
    put(&fx, entries);
    let out = all(&fx);
    for ((kind, secret), line) in PLANTED.iter().zip(&out) {
        assert_eq!(
            line,
            &format!("connected with [redacted:{kind}] ok"),
            "{secret}"
        );
    }
    let n = PLANTED.len();
    assert!(
        !out[n].contains("abc123") && !out[n].contains("pw1"),
        "{}",
        out[n]
    );
    assert_eq!(
        out[n + 1],
        "login failed password=[redacted:password] user=bob"
    );
}

#[test]
fn a_pem_block_is_masked_across_journal_entries() {
    let fx = Fx::new();
    put(
        &fx,
        vec![
            json!("starting"),
            json!("-----BEGIN RSA PRIVATE KEY-----"),
            json!("MIIEowIBAAKCAQEAxJ8sampleSampleSampleSampleSample0123456789abcd"),
            json!("short tail line"),
            json!("-----END RSA PRIVATE KEY-----"),
            json!("done"),
        ],
    );
    let out = all(&fx);
    assert_eq!(
        out,
        [
            "starting",
            "[redacted:pem_block]",
            "[redacted:pem_block]",
            "[redacted:pem_block]",
            "[redacted:pem_block]",
            "done"
        ]
    );
    // No END in the page: masked to the end of the page.
    put(
        &fx,
        vec![
            json!("a"),
            json!("-----BEGIN PRIVATE KEY-----"),
            json!("x"),
            json!("y"),
        ],
    );
    assert_eq!(
        all(&fx),
        [
            "a",
            "[redacted:pem_block]",
            "[redacted:pem_block]",
            "[redacted:pem_block]"
        ]
    );
}

#[test]
fn a_secret_across_the_per_line_cap_is_masked_before_the_cut() {
    let fx = Fx::new();
    let secret = format!("sk-ant-api03-{}", "Z".repeat(60));
    put(
        &fx,
        [4090, 4080, 4070, 4060, 4000]
            .iter()
            .map(|pad| json!(format!("{} {secret} end", "p".repeat(*pad))))
            .collect(),
    );
    for line in all(&fx) {
        assert!(
            !line.contains("sk-ant") && !line.contains("ZZZZ"),
            "{}",
            &line[line.len().saturating_sub(40)..]
        );
        assert!(line.len() <= 4096 + 4);
    }
}

#[test]
fn a_non_utf8_message_array_is_decoded_lossily_never_passed_on() {
    let fx = Fx::new();
    let mut bytes: Vec<u8> = b"bad \xff\xfe bytes ghp_".to_vec();
    bytes.extend_from_slice(&[b'a'; 40]);
    put(
        &fx,
        vec![
            json!(bytes),
            json!(null),
            json!(42),
            json!([104, 105, 300, "x"]),
        ],
    );
    let out = all(&fx);
    assert_eq!(out[0], "bad \u{fffd}\u{fffd} bytes [redacted:github_token]");
    assert_eq!(out[1], "");
    assert_eq!(out[2], "42");
    assert_eq!(out[3], "hi");
    let raw = fx.call("logs", r#"{"unit":"core"}"#).to_string();
    assert!(!raw.contains("[98,97,100"), "no raw array");
}

#[test]
fn the_answer_stays_under_the_wire_cap_and_pages_on() {
    let fx = Fx::new();
    put(
        &fx,
        (0..500)
            .map(|i| json!(format!("{i}:{}", "w".repeat(3000))))
            .collect(),
    );
    let v = fx.call("logs", r#"{"unit":"core","lines":500}"#);
    assert!(v.to_string().len() < 512 * 1024);
    let n = texts(&v).len();
    assert!(n < 500 && n > 100, "{n}");
    assert!(
        v["result"]["next_before"].is_string(),
        "the rest is one page away"
    );
}

#[test]
fn levels_and_times_are_mapped() {
    let fx = Fx::new();
    *fx.fake.journal.lock().unwrap() = vec![
        ("c0".into(), "3".into(), json!("e")),
        ("c1".into(), "4".into(), json!("w")),
        ("c2".into(), "7".into(), json!("d")),
        ("c3".into(), "6".into(), json!("i")),
    ];
    let v = fx.call("logs", r#"{"unit":"core"}"#);
    let levels: Vec<&str> = v["result"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["level"].as_str().unwrap())
        .collect();
    assert_eq!(levels, ["error", "warn", "debug", "info"]);
    assert!(
        v["result"]["lines"][0]["at"]
            .as_str()
            .unwrap()
            .starts_with("2026-11-06T")
    );
}
