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
    cfg.sandbox = false; // the stand-in script is under a temp dir the sandbox hides
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
    agy_driver_with(t, said, "")
}

/// [`agy_driver`] whose stand-in first runs `before` (a menu, say).
fn agy_driver_with(t: &Tmp, said: &str, before: &str) -> Arc<LoginDriver> {
    // The sign-in runs in the session sandbox: it hides the host's temp dir and binds only the
    // program's own dir. So the stand-in is the program itself, alone in a dir beside the test
    // binary (named after this test's scratch dir).
    let own = t.file("agy");
    let name = own.parent().and_then(|d| d.file_name()).unwrap();
    let dir = std::env::current_exe()
        .unwrap()
        .with_file_name(format!("{}-agy", name.to_string_lossy()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("agy");
    let body = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo 'agy 9.9.9'; exit 0; fi
{before}
printf 'Sign in: https://accounts.google.com/o/oauth2/auth?x=1\r\nPaste code: '
read -r pasted
[ "$pasted" = "4/0TESTONLY-code" ] || exit 5
printf '%s' "$HOME" > "$HOME/home-used"
printf '\r\n{said}\r\n'
sleep 30
"#
    );
    std::fs::write(&p, body).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut cfg = LoginConfig::new(t.file("logins"), PathBuf::from("/bin/false"));
    cfg.bound = vec![BoundCli {
        harness: "agy",
        program: p,
        args: vec![],
        pinned: vec!["9.9.9".to_owned()],
    }];
    // The real path: macOS's temp dir is behind the /var -> /private/var link, and the sandbox
    // grants a home by the path it resolves to.
    std::fs::create_dir_all(t.file("homes")).unwrap();
    cfg.homes = t.file("homes").canonicalize().unwrap();
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
    let home = t.file("homes").canonicalize().unwrap().join("lg_1");
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

#[test]
fn a_wipe_deletes_only_a_plain_home_under_the_homes_dir_and_never_follows_a_symlink() {
    use super::bound::wipe_home;
    let t = Tmp::new();
    let homes = t.file("homes");
    std::fs::create_dir_all(homes.join("lg_1/sub")).unwrap();
    std::fs::write(homes.join("lg_1/sub/auth.json"), FAKE_AUTH).unwrap();
    // A neighbour and an outside dir that must survive.
    std::fs::create_dir_all(homes.join("lg_2")).unwrap();
    let outside = t.file("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, homes.join("evil")).unwrap();
    assert_eq!(wipe_home(&homes, "lg_1"), Ok(()));
    assert!(!homes.join("lg_1").exists() && homes.join("lg_2").exists());
    // Already gone: still done.
    assert_eq!(wipe_home(&homes, "lg_1"), Ok(()));
    // A symlink is refused and its target stays.
    assert!(wipe_home(&homes, "evil").is_err());
    assert!(outside.exists() && homes.join("evil").exists());
    // A key that is not plain never becomes a path.
    for bad in ["", "..", "../outside", "a/b", "a.b"] {
        assert!(wipe_home(&homes, bad).is_err(), "{bad}");
    }
    assert!(outside.exists());
}

fn agy_start(id: &str, key: &str) -> LoginStart {
    LoginStart {
        harness: "agy".to_owned(),
        ..start(id, key)
    }
}

#[tokio::test]
async fn an_antigravity_sign_in_takes_only_menu_numbers_and_codes_never_free_text() {
    let t = Tmp::new();
    let d = agy_driver(&t, "Successfully signed in as someone@example.test");
    d.start(agy_start("l_1", "lg_1")).await.unwrap();
    for bad in [
        "hello",
        "rm -rf /",
        "a b",
        "123",
        "x",
        "ls",
        "4/0 TEST-code",
        "12345678\n",
        &"a".repeat(257),
    ] {
        let r = d
            .input(LoginInput {
                login_id: "l_1".into(),
                text: bad.into(),
            })
            .await;
        let refused = match r {
            Ok(r) => r.error.is_some(),
            Err(_) => true,
        };
        assert!(refused, "{bad:?} must be refused");
    }
    for ok in ["1", "12", "4/0TESTONLY-code", "abcd_EFGH-1234"] {
        assert!(ainkrad_proto::v2::agy_input_ok(ok), "{ok}");
    }
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_second_antigravity_home_is_refused_until_the_first_is_wiped_and_the_wipe_says_the_keyring_stays()
 {
    let t = Tmp::new();
    let d = agy_driver(&t, "Successfully signed in as someone@example.test");
    d.start(agy_start("l_1", "lg_1")).await.unwrap();
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0TESTONLY-code".into(),
    })
    .await
    .unwrap();
    assert!(d.wait(wait("l_1")).await.unwrap().done);
    // The home exists: another agy sign-in (a different home key) is refused.
    let e = d.start(agy_start("l_2", "lg_2")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Busy);
    assert!(!t.file("homes").join("lg_2").exists());
    // Removing the account wipes the home; the keyring cannot be cleared, and the answer says so.
    let r = d
        .wipe(ainkrad_proto::v2::LoginWipe {
            home: "lg_1".to_owned(),
        })
        .await
        .unwrap();
    assert!(r.done);
    assert_eq!(r.error.as_deref(), Some("keyring_not_cleared"));
    assert!(!t.file("homes").join("lg_1").exists());
    // Another agy sign-in may now start.
    d.start(agy_start("l_3", "lg_3")).await.unwrap();
    d.cancel(LoginCancel {
        login_id: "l_3".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wiping_a_codex_home_reports_no_keyring_note() {
    let t = Tmp::new();
    let d = driver(&t, "exit 0");
    std::fs::create_dir_all(t.file("homes").join("lg_9")).unwrap();
    let r = d
        .wipe(ainkrad_proto::v2::LoginWipe {
            home: "lg_9".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!((r.done, r.error), (true, None));
}

#[test]
fn the_antigravity_sign_in_is_wrapped_by_the_sandbox_never_run_bare() {
    let t = Tmp::new();
    let scratch = t.file("scratch");
    for d in ["home", "tmp"] {
        std::fs::create_dir_all(scratch.join(d)).unwrap();
    }
    let home = t.file("homes").join("lg_1");
    std::fs::create_dir_all(&home).unwrap();
    let (program, args) = super::agy::sandboxed(
        std::path::Path::new("/bin/sh"),
        &["-c".to_owned(), "true".to_owned()],
        &scratch,
        &home,
        &t.file("homes"),
    );
    // The sandbox's own launcher, or the fail-closed path that cannot start: never the program itself.
    assert_ne!(program, PathBuf::from("/bin/sh"));
    let name = program.display().to_string();
    assert!(
        [
            "/usr/bin/sandbox-exec",
            "/usr/bin/bwrap",
            "/nonexistent/ainkrad-sandbox-refused"
        ]
        .contains(&name.as_str()),
        "{name}"
    );
    if name != "/nonexistent/ainkrad-sandbox-refused" {
        // Writes only to the account's own home and the scratch, as the profile says.
        let joined = args.join(" ");
        assert!(joined.contains(&home.display().to_string()), "{joined}");
    }
}

#[tokio::test]
async fn the_antigravity_login_method_menu_is_answered_with_google_oauth() {
    let t = Tmp::new();
    // The stand-in exits 6 unless the menu got "1": the page is only shown after the answer.
    let menu = r#"printf 'Select login method:\r\n  1. Google OAuth\r\n  2. Use a Google Cloud project\r\n(Use Enter to select)'
read -r choice
[ "$choice" = "1" ] || exit 6"#;
    let d = agy_driver_with(&t, "Successfully signed in as someone@example.test", menu);
    let u = d.start(agy_start("l_1", "lg_1")).await.unwrap();
    assert_eq!(u.url, "https://accounts.google.com/o/oauth2/auth?x=1");
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0TESTONLY-code".into(),
    })
    .await
    .unwrap();
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(r.done, "{:?}", r.error);
}

#[test]
fn only_known_menus_are_answered() {
    use super::bound::known_menu;
    let l = |s: &[&str]| s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    let agy = l(&[
        "Select login method:",
        "  1. Google OAuth",
        "  2. Use a Google Cloud project",
    ]);
    let menu = |lines: &[String], fresh| known_menu("agy", lines, "", fresh);
    assert_eq!(menu(&agy, 3), Some(1));
    // The same words in another harness, or another menu, are the person's to answer.
    assert_eq!(known_menu("opencode", &agy, "", 3), None);
    assert_eq!(known_menu("codex", &agy, "", 3), None);
    for other in [
        &["Select provider:", "  1. Anthropic", "  2. OpenAI"][..],
        &["Select login method:", "  1. Use an API key"][..],
        &["Do you trust this folder?", "  1. Yes  2. No"][..],
    ] {
        assert_eq!(menu(&l(other), 3), None, "{other:?}");
    }
    // Only output since the last answer counts: an answered menu is not answered again.
    assert_eq!(menu(&agy, 0), None);
    let mut old = agy.clone();
    old.extend((0..20).map(|i| format!("line {i}")));
    assert_eq!(menu(&old, 23), None);
    // The error screen goes back first, even when the menu is in the same burst.
    let err = l(&[
        "Got an error: token exchange failed: oauth2: \"invalid_grant\" \"Bad Request\"",
        "Press any key to go back.",
        "Select login method:",
        "  1. Google OAuth",
    ]);
    assert_eq!(menu(&err, 4), Some(0));
    assert_eq!(menu(&err[2..], 2), Some(1));
}

/// agy's real retry screen (2026-11-25): a code from the first page fails, agy goes back to its
/// menu, and the retry prints a new page. The screen must show the NEW page.
fn retry_screen() -> Vec<String> {
    [
        "Select login method:",
        "  1. Google OAuth",
        "  2. Use a Google Cloud project",
        "Sign in: https://accounts.google.com/o/oauth2/auth?state=FIRST",
        "Paste code: 4/0FIRST-code",
        "Got an error: token exchange failed: oauth2: \"invalid_grant\" \"Bad Request\"",
        "Press any key to go back.",
        "Select login method:",
        "  1. Google OAuth",
        "  2. Use a Google Cloud project",
        "Sign in: https://accounts.google.com/o/oauth2/auth?state=SECOND",
        "Paste code: ",
    ]
    .iter()
    .map(|l| (*l).to_owned())
    .collect()
}

#[test]
fn the_screen_shows_the_newest_page_after_a_retry() {
    use super::bound::find_last_page;
    let s = retry_screen();
    assert_eq!(
        find_last_page(&s).as_deref(),
        Some("https://accounts.google.com/o/oauth2/auth?state=SECOND")
    );
    assert_eq!(
        find_last_page(&s[..4]).as_deref(),
        Some("https://accounts.google.com/o/oauth2/auth?state=FIRST")
    );
    assert_eq!(find_last_page(&s[..3]), None);
}

#[tokio::test]
async fn after_a_failed_code_antigravity_goes_back_and_the_new_page_is_shown() {
    let t = Tmp::new();
    // Attempt one: menu, page FIRST, a code that fails, the error screen. Attempt two: menu, then
    // the stand-in's own page (`x=1`, a new one) and the good code.
    let before = r#"n=FIRST
while :; do
printf 'Select login method:\r\n  1. Google OAuth\r\n  2. Use a Google Cloud project\r\n'
read -r choice
[ "$choice" = "1" ] || exit 6
[ "$n" = SECOND ] && break
printf "Sign in: https://accounts.google.com/o/oauth2/auth?state=$n\r\nPaste code: "
read -r bad
printf '\r\nGot an error: token exchange failed: oauth2: "invalid_grant" "Bad Request"\r\nPress any key to go back.'
read -r key
n=SECOND
done"#;
    let d = agy_driver_with(&t, "Successfully signed in as someone@example.test", before);
    let u = d.start(agy_start("l_1", "lg_1")).await.unwrap();
    assert!(u.url.ends_with("state=FIRST"), "{}", u.url);
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0WRONGTEST-code".into(),
    })
    .await
    .unwrap();
    // The runner presses a key, picks Google OAuth again, and the screen moves to the new page.
    let mut url = None;
    for _ in 0..100 {
        let s = d
            .screen(LoginScreenReq {
                login_id: "l_1".into(),
            })
            .await
            .unwrap();
        if s.url.as_deref().is_some_and(|u| u.ends_with("x=1")) {
            url = s.url;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(url.is_some(), "the screen never showed the new page");
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0TESTONLY-code".into(),
    })
    .await
    .unwrap();
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(r.done, "{:?}", r.error);
}

/// What agy 1.5 shows right after a good code (the owner's test, 2026-11-25): no "signed in" line,
/// its first-run theme picker. Kept free of `%`: the stand-in prints it through `printf`.
const AGY_THEME_PICKER: &str = "Authorized with the authorization code.\r\n\
    Choose a theme\r\n  tokyo night\r\n  dracula\r\n\
    func main() { fmt.Printf(\"Hello, name\") }\r\n\
    Thought Process\r\nerror: compilation failed\r\n\
    shift+up/down Navigate";

#[tokio::test]
async fn an_antigravity_sign_in_ends_at_its_theme_picker_after_the_code() {
    let t = Tmp::new();
    let d = agy_driver(&t, AGY_THEME_PICKER);
    d.start(agy_start("l_1", "lg_1")).await.unwrap();
    d.input(LoginInput {
        login_id: "l_1".into(),
        text: "4/0TESTONLY-code".into(),
    })
    .await
    .unwrap();
    let r = d.wait(wait("l_1")).await.unwrap();
    assert!(r.done, "{:?}", r.error);
    assert!(
        t.file("homes")
            .canonicalize()
            .unwrap()
            .join("lg_1")
            .exists()
    );
}

#[test]
fn agy_is_signed_in_by_its_creds_file_or_its_onboarding_after_the_code() {
    use super::agy::{creds_written, onboarded};
    let t = Tmp::new();
    let home = t.file("home");
    std::fs::create_dir_all(home.join(".gemini")).unwrap();
    assert!(!creds_written(&home));
    std::fs::write(home.join(".gemini/oauth_creds.json"), "").unwrap();
    assert!(!creds_written(&home), "an empty file is no login");
    std::fs::write(
        home.join(".gemini/oauth_creds.json"),
        "{\"fake\":\"TESTONLY\"}",
    )
    .unwrap();
    assert!(creds_written(&home));

    let l = |s: &str| s.split("\r\n").map(str::to_owned).collect::<Vec<_>>();
    assert!(onboarded(&l(AGY_THEME_PICKER), ""));
    // The login menu again, or an error after the code, is not signed in.
    let again = format!("Got an error: oauth2: \"invalid_grant\"\r\n{AGY_THEME_PICKER}");
    assert!(!onboarded(&l(&again), ""));
    let menu = "Select login method:\r\n  1. Google OAuth\r\nshift+up/down Navigate";
    assert!(!onboarded(&l(menu), ""));
    assert!(!onboarded(&l("Paste code: "), ""));
}
