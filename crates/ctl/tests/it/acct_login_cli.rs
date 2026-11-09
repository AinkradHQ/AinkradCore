//! `account login` as a state machine against the fake Core (code at the prompt, from the
//! environment, refused, failed, cancelled by the Core or by Ctrl-C), and the leak test: every
//! command run with a distinctive secret, which must appear nowhere but in the body of the
//! request meant to carry it.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::json;

use crate::acct_cli::{ok, run};
use crate::acct_fake::*;
use crate::common::*;
use crate::connections_fake::{body_of, matching, text};
use crate::scheduler_fake::device;

const OK_OUT: &str = "starting the sign-in on runner d_runner1\n\
open this address and sign in: https://claude.example/oauth/authorize?x=1\n\
the code is with the runner, waiting for the sign-in to finish\n\
storing the account\n";

fn login(
    ks: &str,
    label: &str,
    extra: &[&str],
    stdin: &str,
    env: &[(&str, &str)],
) -> std::process::Output {
    let mut w = vec!["account", "login", "claude-sub", "--label", label];
    w.extend_from_slice(extra);
    run(ks, &w, stdin, env)
}

#[test]
fn the_code_at_the_prompt_runs_the_sign_in_to_an_account() {
    let (fake, ks) = device("al-ok", accounts, false);
    let o = login(
        &ks,
        "ok",
        &["--runner", "d_runner1"],
        "CODE-ABCD-1234\n",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(stdout(&o), format!("{OK_OUT}signed in: account 11 (ok)\n"));
    let (out, err) = text(&o);
    assert!(err.contains("paste the approval code"), "{err}");
    assert!(!format!("{out}{err}").contains("CODE-ABCD-1234"));
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/accounts/logins ")[0]),
        json!({"provider": "claude-sub", "label": "ok", "runner": "d_runner1"})
    );
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/accounts/logins/al_ok/code ")[0]),
        json!({"code": "CODE-ABCD-1234"})
    );
    assert!(matching(&fake, "delete /api/v1/accounts/logins/").is_empty());
}

#[test]
fn the_code_can_come_from_the_environment_and_the_label_defaults_to_the_provider() {
    let (fake, ks) = device("al-env", accounts, false);
    let o = login(
        &ks,
        "ok_env",
        &[],
        "",
        &[("AINKRAD_ACCOUNT_CODE", "CODE-ENV-12345")],
    );
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).ends_with("signed in: account 11 (ok_env)\n"));
    assert!(!text(&o).1.contains("paste the approval code"));
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/accounts/logins/al_ok_env/code ")[0]),
        json!({"code": "CODE-ENV-12345"})
    );
    let o = run(
        &ks,
        &["account", "login", "claude-sub"],
        "CODE-ABCD-1234\n",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/accounts/logins ")[1]),
        json!({"provider": "claude-sub", "label": "claude-sub"})
    );
}

#[test]
fn json_mode_prints_one_sign_in_per_step() {
    let (_fake, ks) = device("al-json", accounts, false);
    let o = run(
        &ks,
        &[
            "--json",
            "account",
            "login",
            "claude-sub",
            "--label",
            "ok_json",
        ],
        "CODE-ABCD-1234\n",
        &[],
    );
    assert!(o.status.success(), "{o:?}");
    let steps: Vec<String> = stdout(&o)
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["state"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        steps,
        ["starting", "open_url", "waiting_code", "storing", "done"]
    );
}

#[test]
fn a_sign_in_that_ends_without_an_account_is_exit_4_with_the_reason() {
    let (fake, ks) = device("al-end", accounts, false);
    let o = login(&ks, "failed", &[], "CODE-ABCD-1234\n", &[]);
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert!(
        text(&o).1.ends_with("ainkradctl: failed: the provider refused the code; run `account login claude-sub` again\n"),
        "{o:?}"
    );
    assert!(stdout(&o).starts_with(OK_OUT.lines().next().unwrap()));
    // The Core ended it itself (expired, cancelled): the same, with its reason.
    let o = login(&ks, "cored", &[], "", &[]);
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    assert!(
        text(&o)
            .1
            .contains("cancelled: cancelled; run `account login claude-sub` again"),
        "{o:?}"
    );
    assert!(matching(&fake, "delete /api/v1/accounts/logins/").is_empty());
}

#[test]
fn a_code_the_core_refuses_or_of_the_wrong_shape_drops_the_sign_in() {
    let (fake, ks) = device("al-bad", accounts, false);
    // The Core refuses it (and echoes it): said plainly, blanked, the sign-in dropped.
    let o = login(&ks, "ok_wrong", &[], "WRONG-LEAK-CODE-1\n", &[]);
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    let (out, err) = text(&o);
    assert!(
        err.ends_with(
            "ainkradctl: 400 bad_request: signing in to claude-sub: the provider refused ***\n"
        ),
        "{err}"
    );
    assert!(!format!("{out}{err}").contains("WRONG-LEAK-CODE-1"));
    assert_eq!(
        matching(&fake, "delete /api/v1/accounts/logins/al_ok_wrong ").len(),
        1
    );
    // A shape the contract refuses is not sent; none at all is the same.
    for (label, stdin) in [("ok_short", "short\n"), ("ok_none", "")] {
        let o = login(&ks, label, &[], stdin, &[]);
        assert_eq!(o.status.code(), Some(2), "{o:?}");
        assert!(
            text(&o)
                .1
                .contains("approval code is missing or not the shape"),
            "{o:?}"
        );
        assert!(!text(&o).1.contains("short"));
        assert!(
            matching(
                &fake,
                &format!("post /api/v1/accounts/logins/al_{label}/code ")
            )
            .is_empty()
        );
        assert_eq!(
            matching(
                &fake,
                &format!("delete /api/v1/accounts/logins/al_{label} ")
            )
            .len(),
            1
        );
    }
}

#[test]
fn ctrl_c_at_the_code_prompt_cancels_the_sign_in_at_the_core() {
    let (fake, ks) = device("al-cancel", accounts, false);
    let mut child = Command::new(CTL)
        .args([
            "--keystore",
            &ks,
            "account",
            "login",
            "claude-sub",
            "--label",
            "ok_cancel",
        ])
        .env("AINKRAD_STEPUP_PASSPHRASE_FILE", passphrase_file())
        .env_remove("AINKRAD_ACCOUNT_CODE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Stdin stays open: the prompt is waiting on it.
    let _keep_open = child.stdin.take().unwrap();
    let mut lines = Lines::of(child.stdout.take().unwrap());
    while let Some(l) = lines.next(Duration::from_secs(20)) {
        if l.starts_with("open this address") {
            break;
        }
    }
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(130), "{err}");
    assert!(err.contains("cancelled"), "{err}");
    assert_eq!(
        matching(&fake, "delete /api/v1/accounts/logins/al_ok_cancel ").len(),
        1
    );
}

/// A command's words, its stdin and the environment it gets.
type Run<'a> = (Vec<&'a str>, String, Vec<(&'a str, String)>);

#[test]
fn no_secret_is_printed_or_sent_anywhere_but_the_request_that_carries_it() {
    let (fake, ks) = device("al-leak", accounts, false);
    let key = |n: u8| format!("sk-LEAK_{n}_Zx9Qm4Tr7Vb2");
    let file = std::path::Path::new(&ks).parent().unwrap().join("key.txt");
    std::fs::write(&file, format!("{}\n", key(2))).unwrap();
    let argv = "sk-LEAK_4_Zx9Qm4Tr7Vb2";
    let none = || String::new();

    let runs: Vec<Run> = vec![
        (vec!["account", "add", "anthropic"], key(1), vec![]),
        (
            vec![
                "account",
                "add",
                "anthropic",
                "--key-file",
                file.to_str().unwrap(),
            ],
            none(),
            vec![],
        ),
        (
            vec!["account", "add", "anthropic"],
            none(),
            vec![("AINKRAD_ACCOUNT_KEY", key(3))],
        ),
        (
            vec!["account", "add", "anthropic", "--key", argv],
            none(),
            vec![],
        ),
        (
            vec!["account", "add", "anthropic"],
            "ECHO-LEAK_5_Zx9Qm4Tr7Vb2".into(),
            vec![],
        ),
        (vec!["account", "rotate", "9"], key(6), vec![]),
        (
            vec!["account", "rotate", "9", "--runners", "d_runner1"],
            "ECHO-LEAK_7_Zx9Qm4Tr7Vb2".into(),
            vec![],
        ),
        (
            vec!["--json", "account", "add", "anthropic"],
            key(8),
            vec![],
        ),
        (vec!["account", "ls"], none(), vec![]),
        (vec!["account", "show", "7"], none(), vec![]),
        (vec!["--json", "account", "show", "7"], none(), vec![]),
        (vec!["account", "providers"], none(), vec![]),
        (vec!["account", "usage"], none(), vec![]),
        (vec!["account", "costs"], none(), vec![]),
        (vec!["account", "test", "9"], none(), vec![]),
        (vec!["account", "state", "9", "disabled"], none(), vec![]),
        (vec!["account", "rm", "9"], none(), vec![]),
        (vec!["pool", "ls"], none(), vec![]),
        (vec!["pool", "show", "2"], none(), vec![]),
        (vec!["budget", "ls"], none(), vec![]),
    ];
    let mut printed = String::new();
    for (words, stdin, env) in &runs {
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let o = run(&ks, words, stdin, &env);
        printed.push_str(&format!(
            "{}{}",
            stdout(&o),
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    // Sign-in codes: at the prompt, from the environment, and echoed back by the Core.
    let codes = [
        "CODE_LEAK_9_Pa6Rs0Ue4Gt",
        "CODE_LEAK_10_Pa6Rs0Ue4Gt",
        "WRONG-CODE_LEAK_11_Pa6Rs0Ue4Gt",
    ];
    for (label, stdin, env) in [
        ("ok_leak9", format!("{}\n", codes[0]), vec![]),
        (
            "ok_leak10",
            String::new(),
            vec![("AINKRAD_ACCOUNT_CODE", codes[1])],
        ),
        ("ok_leak11", format!("{}\n", codes[2]), vec![]),
    ] {
        let o = login(&ks, label, &[], &stdin, &env);
        printed.push_str(&format!(
            "{}{}",
            stdout(&o),
            String::from_utf8_lossy(&o.stderr)
        ));
    }
    assert!(ok(&ks, &["account", "ls"]).contains("work"));

    let secrets = [
        key(1),
        key(2),
        key(3),
        argv.into(),
        "LEAK_5_Zx9Qm4Tr7Vb2".into(),
        key(6),
        "LEAK_7_Zx9Qm4Tr7Vb2".into(),
        key(8),
        codes[0].into(),
        codes[1].into(),
        codes[2].into(),
    ];
    for s in &secrets {
        assert!(!printed.contains(s.as_str()), "{s} was printed:\n{printed}");
    }
    assert!(printed.contains("warning: --key puts the API key"));

    // Sent: only inside the body of the request that carries it.
    let carriers = [
        "post /api/v1/accounts ",
        "put /api/v1/accounts/9/secret ",
        "post /api/v1/accounts/logins/al_ok_leak9/code ",
        "post /api/v1/accounts/logins/al_ok_leak10/code ",
        "post /api/v1/accounts/logins/al_ok_leak11/code ",
    ];
    let mut carried = 0;
    for r in fake.requests() {
        let body = r.rsplit("\r\n").next().unwrap_or_default().to_owned();
        let head = r[..r.len() - body.len()].to_owned();
        for s in &secrets {
            assert!(
                !head.to_lowercase().contains(&s.to_lowercase()),
                "{s} in a head: {head}"
            );
            if body.contains(s.as_str()) {
                assert!(
                    carriers.iter().any(|c| head.starts_with(c)),
                    "{s} in the body of {head}"
                );
                carried += 1;
            }
        }
    }
    // keys 1 to 4, ECHO 5, rotate 6, ECHO 7, json 8, codes 9, 10, 11.
    assert_eq!(carried, 11);
    // Nor on disk beside the keystore.
    for entry in std::fs::read_dir(std::path::Path::new(&ks).parent().unwrap()).unwrap() {
        let p = entry.unwrap().path();
        if p != file && p.is_file() {
            let body = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
            assert!(secrets.iter().all(|s| !body.contains(s.as_str())), "{p:?}");
        }
    }
}
