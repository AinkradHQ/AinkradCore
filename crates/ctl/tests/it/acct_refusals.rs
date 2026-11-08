//! Account, pool and budget refusals said plainly, wrong usage (exit 2, nothing sent) and the
//! step-up flow, against the fake Core of `acct_fake`.

use std::sync::atomic::Ordering;

use crate::acct_cli::{fails, run};
use crate::acct_fake::*;
use crate::common::*;
use crate::connections_fake::{matching, text};
use crate::scheduler_fake::device;

#[test]
fn refusals_are_said_plainly_with_the_exit_code_of_a_refusal() {
    let (_fake, ks) = device("ac-refuse", accounts, false);
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["account", "add", "anthropic"],
            "REJECT-1",
            "400 bad_request: adding an account for anthropic: that key is not shaped like an anthropic key",
        ),
        (
            &["account", "add", "anthropic", "--label", "dup"],
            "sk-x",
            "409 conflict: adding an account for anthropic: an account labelled dup exists",
        ),
        (
            &["account", "add", "anthropic", "--label", "full"],
            "sk-x",
            "409 limit_reached: adding an account for anthropic: the account limit is reached",
        ),
        (
            &["account", "state", "9", "bogus"],
            "",
            "400 bad_request: setting account 9 bogus: no such state",
        ),
        (
            &["account", "cap", "9", "99"],
            "",
            "400 bad_request: setting the cap of account 9: the cap is 0 to 64",
        ),
        (
            &["account", "rm", "404"],
            "",
            "404 not_found: removing account 404: no such account",
        ),
        (
            &["account", "test", "11"],
            "",
            "429 rate_limited: testing account 11: too soon, wait 7 s and try again",
        ),
        (
            &["account", "test", "12"],
            "",
            "409 no_runner: testing account 12: no runner is online in the key's scope",
        ),
        (
            &["account", "login", "claude-sub", "--label", "norunner"],
            "",
            "409 no_runner: signing in to claude-sub: no runner is ready with the claude harness and sign-in support",
        ),
        (
            &["pool", "add", "2", "8"],
            "",
            "400 bad_request: adding account 8 to pool 2: account 8 is an openai account, pool 2 is anthropic's",
        ),
        (
            &["pool", "add", "3", "10"],
            "",
            "409 conflict: adding account 10 to pool 3: a subscription account is always alone in its pool: pool 3 already has one",
        ),
        (
            &["pool", "create", "dup", "anthropic"],
            "",
            "409 conflict: creating pool dup: a pool named dup exists",
        ),
        (
            &["pool", "rm", "2"],
            "",
            "409 conflict: removing pool 2: pool 2 is used by chain 1",
        ),
        (
            &["budget", "set", "bogus", "9", "month", "--tokens", "1"],
            "",
            "400 bad_request: setting the month budget of bogus 9: no such kind",
        ),
    ];
    for (words, stdin, want) in cases {
        let err = fails(&ks, words, stdin, 4);
        assert_eq!(err, format!("ainkradctl: {want}\n"), "{words:?}");
    }
    // The Core echoing the key back: it is blanked.
    let err = fails(&ks, &["account", "add", "anthropic"], "ECHO-key-1", 4);
    assert_eq!(
        err,
        "ainkradctl: 400 bad_request: adding an account for anthropic: odd key ***\n"
    );
    let err = fails(&ks, &["account", "rotate", "9"], "ECHO-key-2", 4);
    assert!(
        err.contains("odd key ***") && !err.contains("ECHO-key-2"),
        "{err}"
    );
}

#[test]
fn wrong_usage_exits_2_and_sends_nothing() {
    let (fake, ks) = device("ac-usage", accounts, false);
    let cases: &[(&[&str], &str)] = &[
        (&["account", "nope"], ""),
        (&["account", "add"], "k"),
        (&["account", "add", "Bad/Provider"], "k"),
        (&["account", "add", "anthropic"], ""),
        (&["account", "add", "anthropic"], "\n"),
        (
            &[
                "account",
                "add",
                "anthropic",
                "--key-file",
                "/nonexistent/x",
            ],
            "",
        ),
        (&["account", "add", "anthropic", "--cap", "x"], "k"),
        (&["account", "add", "anthropic", "--cap", "-1"], "k"),
        (
            &["account", "add", "anthropic", "--base-url", "https://x"],
            "k",
        ),
        (&["account", "state", "9"], ""),
        (&["account", "state", "0", "active"], ""),
        (&["account", "state", "x", "active"], ""),
        (&["account", "state", "9", "../x"], ""),
        (&["account", "cap", "9"], ""),
        (&["account", "cap", "9", "many"], ""),
        (&["account", "limit", "set", "9", "tokens", "18000"], ""),
        (&["account", "limit", "set", "9", "tok/ens", "1", "2"], ""),
        (&["account", "limit", "clear", "9", "tokens"], ""),
        (&["account", "session-limits", "9", "--max-tokens", "x"], ""),
        (&["account", "rotate"], "k"),
        (&["account", "rm"], ""),
        (&["account", "rm", "9", "10"], ""),
        (&["account", "test", "x"], ""),
        (&["account", "costs", "--account", "x"], ""),
        (&["account", "costs", "--session", "a/b"], ""),
        (&["account", "login"], ""),
        (&["account", "login", "Bad/Provider"], ""),
        (&["pool"], ""),
        (&["pool", "show", "x"], ""),
        (&["pool", "create", "only-a-name"], ""),
        (&["pool", "create", "n", "bad/provider"], ""),
        (&["pool", "add", "2"], ""),
        (&["pool", "add", "0", "5"], ""),
        (&["pool", "remove", "2", "x"], ""),
        (&["pool", "rm", "-1"], ""),
        (&["budget", "set", "account", "9", "month"], ""),
        (&["budget", "set", "account", "9"], ""),
        (
            &["budget", "set", "account", "9", "month", "--tokens", "x"],
            "",
        ),
        (&["budget", "raise", "4"], ""),
        (&["budget", "ls", "--kind", "a/b"], ""),
        (&["budget", "rm", "x"], ""),
    ];
    for (words, stdin) in cases {
        let err = fails(&ks, words, stdin, 2);
        assert!(err.starts_with("ainkradctl: "), "{words:?}: {err}");
    }
    assert!(fake.requests().is_empty(), "{:?}", fake.requests());
}

#[test]
fn a_step_up_is_done_once_and_the_write_retried_once() {
    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("ac-step", gated, true);
    let o = run(&ks, &["account", "add", "anthropic"], "sk-x", &[]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        "9\tanthropic\tanthropic\tactive\tlive 0/4\tfail 0 auth 0\nrunners -\n"
    );
    assert_eq!(matching(&fake, "post /api/v1/accounts ").len(), 2);
    assert_eq!(matching(&fake, "post /api/v1/auth/step-up ").len(), 1);

    // No step-up key: exit 9, the write tried once, no step-up sent.
    ELEVATED.store(false, Ordering::SeqCst);
    let (fake, ks) = device("ac-nokey", gated, false);
    let o = run(&ks, &["account", "add", "anthropic"], "sk-x", &[]);
    assert_eq!(o.status.code(), Some(9), "{o:?}");
    assert!(text(&o).1.contains("no step-up key"), "{o:?}");
    assert_eq!(matching(&fake, "post /api/v1/accounts ").len(), 1);
    assert_eq!(matching(&fake, "post /api/v1/auth/step-up ").len(), 0);
}
