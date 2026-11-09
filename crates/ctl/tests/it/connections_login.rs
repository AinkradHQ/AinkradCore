//! `connection login` as a state machine against the fake Core (device flow, Jira with a site
//! choice, expiry, denial, failure, Ctrl-C), and the leak test: every command run with a
//! distinctive secret, which must appear nowhere but in the body of the request meant to carry it.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::json;

use crate::common::*;
use crate::connections::run;
use crate::connections_fake::*;
use crate::scheduler_fake::device;

const REDIRECT: &str = "http://127.0.0.1:47613/callback?code=CODE-SECRET&state=st1";

fn login(ks: &str, name: &str, extra: &[&str], stdin: &str) -> std::process::Output {
    let kind = if name.starts_with("jira") {
        "jira"
    } else {
        "github"
    };
    let mut w = vec!["connection", "login", kind, "--name", name];
    w.extend_from_slice(extra);
    run(ks, &w, stdin, &[])
}

const DEVICE_OUT: &str = "open this address: https://github.com/login/device\nand enter this code: ABCD-1234\nwaiting for you to approve\n";

#[test]
fn the_device_flow_prints_each_step_once_and_ends_connected() {
    let (fake, ks) = device("lg-dev", conns, false);
    let o = login(&ks, "devok", &[], "");
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        format!(
            "{DEVICE_OUT}approved, finishing the sign-in\nconnected as octocat (connection 5)\n"
        )
    );
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/connections/start ")[0]),
        json!({"kind": "github", "name": "devok"})
    );
    assert_eq!(
        matching(&fake, "get /api/v1/connections/flows/cf_devok ").len(),
        3
    );
    assert!(
        matching(&fake, "delete ").is_empty(),
        "a finished flow is not cancelled"
    );
}

#[test]
fn start_takes_the_connection_label_and_identity_confirmation() {
    let (fake, ks) = device("lg-again", conns, false);
    let o = login(
        &ks,
        "devok_again",
        &[
            "--connection",
            "3",
            "--label",
            "l",
            "--confirm-identity-change",
        ],
        "",
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/connections/start ")[0]),
        json!({"kind": "github", "name": "devok_again", "label": "l", "connection": 3, "confirm_identity_change": true})
    );
}

#[test]
fn denied_expired_and_failed_say_why_and_exit_4() {
    let (_fake, ks) = device("lg-end", conns, false);
    for (name, say) in [
        (
            "devdenied",
            "ainkradctl: denied: the github sign-in was refused, nothing was connected\n",
        ),
        (
            "devexpired",
            "ainkradctl: expired: the github sign-in ran out of time; run `connection login github` again\n",
        ),
        (
            "devfailed",
            "ainkradctl: failed: scope_missing: GitHub did not grant repo access: sign in again and allow it\n",
        ),
    ] {
        let o = login(&ks, name, &[], "");
        assert_eq!(o.status.code(), Some(4), "{name}: {o:?}");
        assert_eq!(text(&o).1, say, "{name}");
        assert!(stdout(&o).starts_with("open this address: "), "{name}");
    }
}

#[test]
fn json_mode_prints_one_flow_per_step() {
    let (_fake, ks) = device("lg-json", conns, false);
    let o = login(&ks, "devok_json", &["--json"], "");
    assert!(o.status.success(), "{o:?}");
    let steps: Vec<String> = stdout(&o)
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["step"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(steps, ["waiting", "approved", "connected"]);
}

const SITES_OUT: &str = "choose a site:\n  1\tAcme\thttps://acme.atlassian.example\tcloud-1\n  2\tBeta\thttps://beta.atlassian.example\tcloud-2\n";
const JIRA_OUT: &str = "open this address and sign in: https://auth.atlassian.example/authorize?x=1\nwaiting for you to approve\n";

#[test]
fn jira_with_the_redirect_and_a_site_given_runs_without_a_prompt() {
    let (fake, ks) = device("lg-jira", conns, false);
    let o = login(
        &ks,
        "jiraok",
        &["--callback-url", REDIRECT, "--site", "beta"],
        "",
    );
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        stdout(&o),
        format!(
            "{JIRA_OUT}{SITES_OUT}approved, finishing the sign-in\nconnected as me@acme (connection 6)\n"
        )
    );
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/connections/flows/cf_jiraok/callback ")[0]),
        json!({"code": "CODE-SECRET", "state": "st1"})
    );
    assert_eq!(
        body_of(&matching(&fake, "post /api/v1/connections/flows/cf_jiraok/choose ")[0]),
        json!({"site": "cloud-2"})
    );
    let o = text(&o);
    assert!(!format!("{}{}", o.0, o.1).contains("CODE-SECRET"));
}

#[test]
fn jira_asks_for_the_pasted_redirect_and_the_site() {
    let (fake, ks) = device("lg-paste", conns, false);
    let o = login(&ks, "jiraok_paste", &[], &format!("{REDIRECT}\n2\n"));
    assert!(o.status.success(), "{o:?}");
    assert!(stdout(&o).contains(SITES_OUT));
    let (out, err) = text(&o);
    assert!(
        err.contains("paste the address") && err.contains("site number or id"),
        "{err}"
    );
    assert!(!format!("{out}{err}").contains("CODE-SECRET"));
    assert_eq!(
        body_of(
            &matching(
                &fake,
                "post /api/v1/connections/flows/cf_jiraok_paste/choose "
            )[0]
        ),
        json!({"site": "cloud-2"})
    );
}

#[test]
fn a_site_that_is_not_in_the_list_drops_the_flow_and_exits_2() {
    let (fake, ks) = device("lg-nosite", conns, false);
    let o = login(
        &ks,
        "jiraok_nosite",
        &["--callback-url", REDIRECT, "--site", "gamma"],
        "",
    );
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(text(&o).1.contains("no site matches that"), "{o:?}");
    assert_eq!(
        matching(&fake, "delete /api/v1/connections/flows/cf_jiraok_nosite ").len(),
        1
    );
    assert!(
        matching(
            &fake,
            "post /api/v1/connections/flows/cf_jiraok_nosite/choose "
        )
        .is_empty()
    );
}

#[test]
fn a_redirect_for_another_sign_in_is_the_cores_plain_refusal() {
    let (fake, ks) = device("lg-state", conns, false);
    let o = login(
        &ks,
        "jiraok_state",
        &[
            "--callback-url",
            "http://127.0.0.1/cb?code=CODE-SECRET&state=other",
        ],
        "",
    );
    assert_eq!(o.status.code(), Some(4), "{o:?}");
    let (out, err) = text(&o);
    assert_eq!(
        err,
        "ainkradctl: 400 bad_state: signing in to jira: that redirect is not for this sign-in\n"
    );
    // A flow nobody can finish is not left waiting at the Core.
    assert_eq!(
        matching(&fake, "delete /api/v1/connections/flows/cf_jiraok_state ").len(),
        1
    );
    assert!(!format!("{out}{err}").contains("CODE-SECRET"));
}

/// Starts a login in the background; waits for stdout to show `until`.
fn spawn_login(ks: &str, name: &str, kind: &str) -> (std::process::Child, Lines) {
    let mut child = Command::new(CTL)
        .args([
            "--keystore",
            ks,
            "connection",
            "login",
            kind,
            "--name",
            name,
        ])
        .env("AINKRAD_STEPUP_PASSPHRASE_FILE", passphrase_file())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = Lines::of(child.stdout.take().unwrap());
    (child, lines)
}

fn interrupt(child: &std::process::Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn finish(mut child: std::process::Child) -> (Option<i32>, String) {
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    (child.wait().unwrap().code(), err)
}

#[test]
fn ctrl_c_while_polling_drops_the_flow_and_exits_130() {
    let (fake, ks) = device("lg-cancel", conns, false);
    let (child, mut lines) = spawn_login(&ks, "canceldev", "github");
    while let Some(l) = lines.next(Duration::from_secs(20)) {
        if l == "waiting for you to approve" {
            break;
        }
    }
    interrupt(&child);
    let (code, err) = finish(child);
    assert_eq!(code, Some(130), "{err}");
    assert!(err.contains("cancelled"), "{err}");
    assert_eq!(
        matching(&fake, "delete /api/v1/connections/flows/cf_canceldev ").len(),
        1
    );
}

#[test]
fn ctrl_c_at_the_paste_prompt_drops_the_flow_too() {
    let (fake, ks) = device("lg-cancel2", conns, false);
    // Stdin stays open: the prompt is waiting on it.
    let (mut child, mut lines) = spawn_login(&ks, "canceljira", "jira");
    let _keep_open = child.stdin.take().unwrap();
    while let Some(l) = lines.next(Duration::from_secs(20)) {
        if l == "waiting for you to approve" {
            break;
        }
    }
    interrupt(&child);
    let (code, err) = finish(child);
    assert_eq!(code, Some(130), "{err}");
    assert_eq!(
        matching(&fake, "delete /api/v1/connections/flows/cf_canceljira ").len(),
        1
    );
    assert!(
        matching(
            &fake,
            "post /api/v1/connections/flows/cf_canceljira/callback "
        )
        .is_empty()
    );
}

/// A command's words, its stdin and the environment it gets.
type Run<'a> = (Vec<&'a str>, String, Vec<(&'a str, String)>);

#[test]
fn no_secret_is_printed_or_sent_anywhere_but_the_request_that_carries_it() {
    let (fake, ks) = device("lg-leak", conns, false);
    let tok = |n: u8| format!("ghp_LEAK_{n}_Zx9Qm4Tr7Vb2");
    let file = std::path::Path::new(&ks)
        .parent()
        .unwrap()
        .join("token.txt");
    std::fs::write(&file, format!("{}\n", tok(2))).unwrap();
    let secret_field = "APPSECRET_Yq8Lw3Kd5Hn1";
    let code = "CODE_LEAK_Pa6Rs0Ue4Gt";

    let runs: Vec<Run> = vec![
        (vec!["connection", "add", "github"], tok(1), vec![]),
        (
            vec![
                "connection",
                "add",
                "github",
                "--token-file",
                file.to_str().unwrap(),
            ],
            String::new(),
            vec![],
        ),
        (
            vec!["connection", "add", "github"],
            String::new(),
            vec![("AINKRAD_CONNECTION_TOKEN", tok(3))],
        ),
        (
            vec![
                "connection",
                "add",
                "github",
                "--token",
                "ghp_LEAK_4_Zx9Qm4Tr7Vb2",
            ],
            String::new(),
            vec![],
        ),
        (vec!["connection", "credential", "3"], tok(5), vec![]),
        (
            vec!["connection", "add", "github"],
            "ECHO-LEAK_6_Zx9Qm4Tr7Vb2".into(),
            vec![],
        ),
        (
            vec![
                "connection",
                "app",
                "github",
                "set",
                "--field",
                "client_secret=-",
            ],
            secret_field.into(),
            vec![],
        ),
        (
            vec![
                "connection",
                "app",
                "github",
                "set",
                "--field",
                "client_secret=APPSECRET_Argv0Zz",
            ],
            String::new(),
            vec![],
        ),
        (vec!["connection", "app", "github"], String::new(), vec![]),
        (vec!["connection", "kinds"], String::new(), vec![]),
        (vec!["connection", "ls"], String::new(), vec![]),
        (vec!["connection", "show", "3"], String::new(), vec![]),
        (
            vec!["--json", "connection", "show", "3"],
            String::new(),
            vec![],
        ),
        (vec!["connection", "test", "3"], String::new(), vec![]),
        (vec!["connection", "grants", "3"], String::new(), vec![]),
        (vec!["connection", "activity", "3"], String::new(), vec![]),
        (vec!["connection", "rm", "3"], String::new(), vec![]),
        (vec!["connection", "default"], String::new(), vec![]),
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
    let o = login(
        &ks,
        "jiraok_leak",
        &[
            "--callback-url",
            &format!("http://127.0.0.1/cb?code={code}&state=st1"),
            "--site",
            "2",
        ],
        "",
    );
    printed.push_str(&format!(
        "{}{}",
        stdout(&o),
        String::from_utf8_lossy(&o.stderr)
    ));

    let secrets = [
        tok(1),
        tok(2),
        tok(3),
        "ghp_LEAK_4_Zx9Qm4Tr7Vb2".into(),
        tok(5),
        "LEAK_6_Zx9Qm4Tr7Vb2".into(),
        secret_field.into(),
        "APPSECRET_Argv0Zz".into(),
        code.into(),
    ];
    for s in &secrets {
        assert!(!printed.contains(s.as_str()), "{s} was printed:\n{printed}");
    }
    assert!(printed.contains("warning: --token") && printed.contains("is secret"));

    // Sent: only inside the body of the request that carries it.
    let carriers = [
        "post /api/v1/connections ",
        "put /api/v1/connections/3/credential ",
        "put /api/v1/connection-apps/github ",
        "post /api/v1/connections/flows/cf_jiraok_leak/callback ",
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
    // tok 1, 2, 3, 4, 5, ECHO 6, app secret, redirect code.
    assert_eq!(carried, 8);
    // Nor on disk beside the keystore.
    for entry in std::fs::read_dir(std::path::Path::new(&ks).parent().unwrap()).unwrap() {
        let p = entry.unwrap().path();
        if p != file && p.is_file() {
            let body = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
            assert!(secrets.iter().all(|s| !body.contains(s.as_str())), "{p:?}");
        }
    }
}
