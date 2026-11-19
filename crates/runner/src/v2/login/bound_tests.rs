//! E7-4: the runner-bound sign-in against a stand-in `codex` (a shell script that acts out
//! `login --device-auth`). Dummy URL, code and "credential" only; no real CLI is ever run.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    ErrorCode, LoginCancel, LoginInput, LoginScreenReq, LoginStart, LoginWait,
};

use super::bound::{BoundCli, find_device_code, find_page, signed_in};
use super::tests::Tmp;
use super::{LoginConfig, LoginDriver};

const PAGE: &str = "https://auth.openai.com/codex/device";
const CODE: &str = "K7QM-4XZP";
const FAKE_AUTH: &str = "fake-auth-json-TESTONLY";

fn cli(t: &Tmp, version: &str, body: &str) -> BoundCli {
    let p = t.file("codex");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'codex-cli {version}'; exit 0; fi\n{body}\n"
    );
    std::fs::write(&p, script).unwrap();
    BoundCli {
        harness: "codex",
        program: PathBuf::from("/bin/sh"),
        args: vec![p.display().to_string()],
        pinned: vec!["9.9.9".to_owned()],
    }
}

fn driver(t: &Tmp, body: &str) -> Arc<LoginDriver> {
    let mut cfg = LoginConfig::new(t.file("logins"), PathBuf::from("/bin/false"));
    cfg.bound = vec![cli(t, "9.9.9", body)];
    cfg.homes = t.file("homes");
    cfg.grace = Duration::from_millis(100);
    Arc::new(LoginDriver::new(cfg).unwrap())
}

fn start(id: &str, key: &str) -> LoginStart {
    LoginStart {
        login_id: id.to_owned(),
        harness: "codex".to_owned(),
        home: Some(key.to_owned()),
    }
}

fn wait(id: &str) -> LoginWait {
    LoginWait {
        login_id: id.to_owned(),
    }
}

/// Prints the page and the code, writes the "credential" into CODEX_HOME, then exits 0.
fn good() -> String {
    format!(
        r#"printf 'Open this page:\r\n  {PAGE}\r\nEnter this one-time code: {CODE}\r\n'
grep -q 'cli_auth_credentials_store = "file"' "$CODEX_HOME/config.toml" || exit 7
sleep 1
printf '{FAKE_AUTH}' > "$CODEX_HOME/auth.json"
printf 'Signed in\r\n'"#
    )
}

#[tokio::test]
async fn a_bound_sign_in_gives_the_page_and_code_then_done_and_keeps_the_login_in_its_home() {
    let t = Tmp::new();
    let d = driver(&t, &good());
    let u = d.start(start("l_1", "lg_1")).await.unwrap();
    assert_eq!(
        (u.url.as_str(), u.code.as_deref()),
        (PAGE, Some(CODE)),
        "the page and the one-time code go to the Core"
    );
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(r.done, "{:?}", r.error);
    // No token ever goes over the wire, only the flag.
    assert!(r.token.is_none() && r.error.is_none());
    // The credential is in the account's home, on the runner, and the scratch is gone.
    let home = t.file("homes").join("lg_1");
    assert_eq!(
        std::fs::read_to_string(home.join("auth.json")).unwrap(),
        FAKE_AUTH
    );
    assert!(!t.file("logins").join("l_1").exists());
}

#[tokio::test]
async fn a_cancel_wipes_the_account_home() {
    let t = Tmp::new();
    let d = driver(&t, &good().replace("sleep 1", "sleep 30"));
    d.start(start("l_1", "lg_1")).await.unwrap();
    assert!(t.file("homes").join("lg_1").exists());
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
    assert!(!t.file("homes").join("lg_1").exists());
    assert!(!t.file("logins").join("l_1").exists());
}

#[tokio::test]
async fn a_failed_exit_is_an_error_and_leaves_no_home() {
    let t = Tmp::new();
    let body = format!("printf '{PAGE}\\r\\n{CODE}\\r\\n'\nsleep 1\nexit 3");
    let d = driver(&t, &body);
    d.start(start("l_1", "lg_1")).await.unwrap();
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(!r.done);
    assert!(r.error.unwrap().contains("exited with code 3"));
    assert!(!t.file("homes").join("lg_1").exists());
}

#[tokio::test]
async fn an_unpinned_version_is_refused_and_a_bad_key_or_harness_too() {
    let t = Tmp::new();
    let mut cfg = LoginConfig::new(t.file("logins"), PathBuf::from("/bin/false"));
    cfg.bound = vec![cli(&t, "1.0.0", &good())];
    cfg.homes = t.file("homes");
    let d = Arc::new(LoginDriver::new(cfg).unwrap());
    let e = d.start(start("l_1", "lg_1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCommand);
    assert!(!t.file("homes").join("lg_1").exists());
    assert!(d.bound_supported("codex").await.is_err());

    let d = driver(&t, &good());
    for key in ["../x", "", "a/b"] {
        let e = d.start(start("l_2", key)).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs, "{key:?}");
    }
    let mut bad = start("l_2", "k");
    bad.harness = "gemini".to_owned();
    assert_eq!(d.start(bad).await.unwrap_err().code, ErrorCode::InvalidArgs);
    assert!(d.bound_supported("codex").await.is_ok());
}

#[tokio::test]
async fn a_home_that_exists_is_never_reused() {
    let t = Tmp::new();
    std::fs::create_dir_all(t.file("homes").join("lg_1")).unwrap();
    std::fs::write(t.file("homes").join("lg_1").join("auth.json"), "keep").unwrap();
    let d = driver(&t, &good());
    assert!(d.start(start("l_1", "lg_1")).await.is_err());
    // The other sign-in's login is untouched.
    assert!(t.file("homes").join("lg_1").join("auth.json").exists());
}

#[test]
fn the_device_code_and_page_are_read_from_the_screen() {
    let lines = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let l = lines(&[
        "Welcome to Codex v0.154.0",
        "1. Open this link: https://auth.openai.com/codex/device",
        "2. Enter this one-time code: K7QM-4XZP (expires in 15 minutes)",
    ]);
    assert_eq!(find_device_code(&l).as_deref(), Some("K7QM-4XZP"));
    assert_eq!(find_page(&l).as_deref(), Some(PAGE));
    // Words that are not codes: no digit, lower case, a version.
    assert_eq!(
        find_device_code(&lines(&["ONE-TIME CODE", "one-time", "0.154.0"])),
        None
    );
}

/// A stand-in `opencode`: asks for a provider, then prints a page and a code and wants the code
/// pasted back, then writes its "login" under XDG_DATA_HOME and exits 0.
fn opencode_driver(t: &Tmp) -> Arc<LoginDriver> {
    let p = t.file("opencode");
    let body = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo '9.9.9'; exit 0; fi
printf 'Select provider: '
read -r pick
printf '\r\nOpen https://github.com/login/device\r\nCode: ABCD-1234\r\nPaste code: '
read -r pasted
[ "$pasted" = "ABCD-1234" ] || exit 5
test -d "$XDG_CONFIG_HOME" && test -d "$XDG_STATE_HOME" || exit 6
printf 'fake-login-TESTONLY' > "$XDG_DATA_HOME/auth.json"
printf 'ok\r\n'
"#;
    std::fs::write(&p, body).unwrap();
    let mut cfg = LoginConfig::new(t.file("logins"), PathBuf::from("/bin/false"));
    cfg.bound = vec![BoundCli {
        harness: "opencode",
        program: PathBuf::from("/bin/sh"),
        args: vec![p.display().to_string()],
        pinned: vec!["9.9.9".to_owned()],
    }];
    cfg.homes = t.file("homes");
    cfg.grace = Duration::from_millis(100);
    cfg.enter_delay = Duration::from_millis(20);
    Arc::new(LoginDriver::new(cfg).unwrap())
}

fn opencode_start(id: &str, key: &str) -> LoginStart {
    LoginStart {
        harness: "opencode".to_owned(),
        ..start(id, key)
    }
}

#[tokio::test]
async fn a_guided_sign_in_shows_its_screen_takes_typed_lines_and_finishes_in_its_home() {
    let t = Tmp::new();
    let d = opencode_driver(&t);
    // The CLI asks a question and waits: the sign-in is handed over with no page yet.
    let u = d.start(opencode_start("l_1", "lg_1")).await.unwrap();
    assert_eq!((u.url.as_str(), u.code), ("", None));
    let s = d
        .screen(LoginScreenReq {
            login_id: "l_1".into(),
        })
        .await
        .unwrap();
    assert!(
        s.lines.iter().any(|l| l.contains("Select provider")),
        "{:?}",
        s.lines
    );
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "GitHub".into(),
    })
    .await
    .unwrap();
    // The page and the code now show on the screen.
    let mut shown = None;
    for _ in 0..60 {
        let s = d
            .screen(LoginScreenReq {
                login_id: "l_1".into(),
            })
            .await
            .unwrap();
        if s.url.is_some() && s.code.is_some() {
            shown = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let s = shown.expect("the page and the code were never shown");
    assert_eq!(
        (s.url.as_deref(), s.code.as_deref()),
        (Some("https://github.com/login/device"), Some("ABCD-1234"))
    );
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "ABCD-1234".into(),
    })
    .await
    .unwrap();
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(r.done, "{:?}", r.error);
    assert_eq!(
        std::fs::read_to_string(t.file("homes").join("lg_1/data/auth.json")).unwrap(),
        "fake-login-TESTONLY"
    );
}

#[tokio::test]
async fn a_typed_line_is_one_printable_line_and_a_codex_sign_in_is_not_guided_by_it() {
    let t = Tmp::new();
    let d = opencode_driver(&t);
    d.start(opencode_start("l_1", "lg_1")).await.unwrap();
    for bad in ["a\nb", "a\rb", "x\u{7}y", &"z".repeat(513)] {
        let e = d
            .input(LoginInput {
                login_id: "l_1".into(),
                text: bad.into(),
            })
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs, "{bad:?}");
    }
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
    assert!(!t.file("homes").join("lg_1").exists());
    // No such sign-in: nothing to type into.
    let e = d
        .input(LoginInput {
            login_id: "l_1".into(),
            text: "x".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
}

/// A stand-in `agy`: shows a page and wants the pasted code, then says it is signed in and stays up
/// (a TUI does not exit). It records HOME so the test sees the account's home was used.
fn agy_driver(t: &Tmp, said: &str) -> Arc<LoginDriver> {
    let p = t.file("agy");
    let body = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo 'agy 9.9.9'; exit 0; fi
printf 'Sign in: https://accounts.google.com/o/oauth2/auth?x=1\r\nPaste code: '
read -r pasted
[ "$pasted" = "4/0TESTONLY-code" ] || exit 5
printf '%s' "$HOME" > "$HOME/home-used"
printf '\r\n{said}\r\n'
sleep 30
"#
    );
    std::fs::write(&p, body).unwrap();
    let mut cfg = LoginConfig::new(t.file("logins"), PathBuf::from("/bin/false"));
    cfg.bound = vec![BoundCli {
        harness: "agy",
        program: PathBuf::from("/bin/sh"),
        args: vec![p.display().to_string()],
        pinned: vec!["9.9.9".to_owned()],
    }];
    cfg.homes = t.file("homes");
    cfg.grace = Duration::from_millis(100);
    cfg.enter_delay = Duration::from_millis(20);
    Arc::new(LoginDriver::new(cfg).unwrap())
}

#[tokio::test]
async fn an_antigravity_sign_in_ends_when_the_cli_says_it_is_signed_in_and_keeps_its_home() {
    let t = Tmp::new();
    let d = agy_driver(&t, "Successfully signed in as someone@example.test");
    let u = d
        .start(LoginStart {
            harness: "agy".to_owned(),
            ..start("l_1", "lg_1")
        })
        .await
        .unwrap();
    // It paused at the code prompt, so the sign-in was handed over with the page.
    assert_eq!(u.url, "https://accounts.google.com/o/oauth2/auth?x=1");
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0TESTONLY-code".into(),
    })
    .await
    .unwrap();
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(r.done, "{:?}", r.error);
    let home = t.file("homes").join("lg_1");
    assert_eq!(
        std::fs::read_to_string(home.join("home-used")).unwrap(),
        home.display().to_string()
    );
}

#[tokio::test]
async fn a_wrong_code_does_not_count_and_the_words_must_say_signed_in() {
    let t = Tmp::new();
    let d = agy_driver(&t, "Sign in failed: you are not signed in");
    d.start(LoginStart {
        harness: "agy".to_owned(),
        ..start("l_1", "lg_1")
    })
    .await
    .unwrap();
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0TESTONLY-code".into(),
    })
    .await
    .unwrap();
    // "not signed in" is not a success: the sign-in is still open, and a cancel wipes the home.
    tokio::time::sleep(Duration::from_secs(3)).await;
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
    assert!(!t.file("homes").join("lg_1").exists());
    let l = |s: &str| vec![s.to_owned()];
    assert!(signed_in(&l("Successfully signed in as a@b.test")));
    assert!(signed_in(&l("Logged in as a@b.test")));
    assert!(!signed_in(&l("You are not logged in as anyone")));
    assert!(!signed_in(&l("Sign in to continue")));
}
