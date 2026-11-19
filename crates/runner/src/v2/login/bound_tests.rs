//! E7-4: the runner-bound sign-in against a stand-in `codex` (a shell script that acts out
//! `login --device-auth`). Dummy URL, code and "credential" only; no real CLI is ever run.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ErrorCode, LoginCancel, LoginStart, LoginWait};

use super::bound::{BoundCli, find_device_code, find_page};
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
