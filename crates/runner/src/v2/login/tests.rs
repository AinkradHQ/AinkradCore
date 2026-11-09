//! KAN-441 L2 (L4, runner part): the driver against a stand-in `claude` (a shell script that
//! acts out `setup-token`), the parser on the awkward things a terminal does, and redaction.
//! No real token, no real `claude`: the "token" is `sk-ant-oat01-TESTONLY…` and the "code" is
//! made up.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ainkrad_proto::v2::{ErrorCode, LoginCancel, LoginCode, LoginResult, LoginStart};

use super::{LoginConfig, LoginDriver, child_env};

pub(super) const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";
pub(super) const CODE: &str = "Zq81xyAB-cdEF_77#st4te";
pub(super) const URL: &str =
    "https://claude.ai/oauth/authorize?code=true&client_id=standin&state=s1";

pub(super) struct Tmp(PathBuf);
impl Tmp {
    pub(super) fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ainkrad-login-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub(super) fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A stand-in `claude` reporting `version`; `body` is what `setup-token` does.
pub(super) fn standin(t: &Tmp, version: &str, body: &str) -> PathBuf {
    let p = t.file("claude");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '{version} (Claude Code)'; exit 0; fi\n{body}\n"
    );
    std::fs::write(&p, script).unwrap();
    p
}

/// The config that runs the stand-in through `/bin/sh` (never exec'd itself: no ETXTBSY races).
pub(super) fn config(t: &Tmp, version: &str, body: &str) -> LoginConfig {
    let mut cfg = LoginConfig::new(t.file("logins"), PathBuf::from("/bin/sh"));
    cfg.args = vec![standin(t, version, body).display().to_string()];
    cfg
}

pub(super) fn driver_with(
    t: &Tmp,
    body: &str,
    tweak: impl FnOnce(&mut LoginConfig),
) -> Arc<LoginDriver> {
    let mut cfg = config(t, "9.9.9", body);
    cfg.pinned = vec!["9.9.9".to_owned()];
    cfg.grace = Duration::from_millis(100);
    tweak(&mut cfg);
    Arc::new(LoginDriver::new(cfg).unwrap())
}

pub(super) fn driver(t: &Tmp, body: &str) -> Arc<LoginDriver> {
    driver_with(t, body, |_| {})
}

pub(super) fn start(id: &str) -> LoginStart {
    LoginStart {
        login_id: id.to_owned(),
        harness: "claude".to_owned(),
    }
}

pub(super) fn code(id: &str, c: &str) -> LoginCode {
    LoginCode {
        login_id: id.to_owned(),
        code: c.to_owned(),
    }
}

/// URL, a prompt, the code read, then the token.
pub(super) fn good(prompt: &str) -> String {
    format!(
        r#"printf '\033[1mSign in\033[0m\r\nVisit:\r\n{URL}\r\n'
printf '{prompt}'
read -r code
printf '\r\nYour token:\r\n{TOKEN}\r\n'"#
    )
}

pub(super) async fn done(d: &LoginDriver, id: &str, c: &str) -> LoginResult {
    d.code(code(id, c)).await.unwrap()
}

pub(super) fn scratch_gone(t: &Tmp, id: &str) -> bool {
    !t.file("logins").join(id).exists()
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

async fn pid_dead(file: &Path) -> bool {
    let pid: u32 = std::fs::read_to_string(file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for _ in 0..60 {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ---- the driver -------------------------------------------------------------------------

#[tokio::test]
async fn a_sign_in_gives_its_url_then_its_token_and_leaves_nothing() {
    let t = Tmp::new();
    let d = driver(&t, &good("Paste code here if prompted > "));
    let u = d.start(start("l_1")).await.unwrap();
    assert_eq!((u.login_id.as_str(), u.url.as_str()), ("l_1", URL));
    let r = done(&d, "l_1", CODE).await;
    assert_eq!(r.token.as_deref(), Some(TOKEN));
    assert_eq!(r.error, None);
    assert!(scratch_gone(&t, "l_1"));
    // The slot is free again.
    assert!(d.start(start("l_2")).await.is_ok());
    d.cancel(LoginCancel {
        login_id: "l_2".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn prompt_variants_and_a_code_sent_before_the_prompt() {
    for prompt in ["Enter the code: ", "Paste code here > ", "> ", ""] {
        let t = Tmp::new();
        // The prompt comes a second after the URL, and the code is already in by then.
        let body = good(prompt).replacen("printf '", "sleep 1; printf '", 2);
        let body = body.replacen("sleep 1; printf '\\033", "printf '\\033", 1);
        let d = driver(&t, &body);
        d.start(start("l_1")).await.unwrap();
        let r = done(&d, "l_1", CODE).await;
        assert_eq!(r.token.as_deref(), Some(TOKEN), "prompt {prompt:?}");
    }
}

#[tokio::test]
async fn the_url_printed_twice_with_colour_and_cursor_codes_is_sent_once() {
    let t = Tmp::new();
    let body = format!(
        r#"printf '\033[2K\r\033[36m{URL}\033[0m\r\n\033[1A\033[2K\r{URL}\r\n'
printf 'code> '
read -r code
printf '\033[32m{TOKEN}\033[0m\r\n'"#
    );
    let d = driver(&t, &body);
    assert_eq!(d.start(start("l_1")).await.unwrap().url, URL);
    assert_eq!(done(&d, "l_1", CODE).await.token.as_deref(), Some(TOKEN));
}

#[tokio::test]
async fn a_token_that_arrives_in_two_reads_is_whole() {
    let t = Tmp::new();
    let (a, b) = TOKEN.split_at(30);
    let body = format!(
        "printf '{URL}\\r\\nenter code: '\nread -r code\nprintf '{a}'\nsleep 0.1\nprintf '{b}\\r\\n'"
    );
    let d = driver(&t, &body);
    d.start(start("l_1")).await.unwrap();
    assert_eq!(done(&d, "l_1", CODE).await.token.as_deref(), Some(TOKEN));
}

#[tokio::test]
async fn an_unknown_version_is_refused_with_a_clear_result() {
    for (version, why) in [("2.0.1", "not a version"), ("hello", "did not report")] {
        let t = Tmp::new();
        let cfg = config(&t, version, &good("code: "));
        let d = Arc::new(LoginDriver::new(cfg).unwrap());
        let e = d.start(start("l_1")).await.unwrap_err();
        assert!(e.message.contains(why), "{}", e.message);
        // The Core can tell this from a failure of the sign-in itself, and use another runner.
        assert_eq!(e.code, ErrorCode::UnsupportedCommand);
        assert!(scratch_gone(&t, "l_1"));
        // Refused, not stuck: the slot is free.
        assert!(
            d.start(start("l_2"))
                .await
                .unwrap_err()
                .message
                .contains(why)
        );
    }
    // And the pinned list is real: what `claude --version` said on the build machine.
    assert!(super::PINNED.contains(&"2.1.318"));
}

#[tokio::test]
async fn garbage_output_and_early_endings_fail_plainly() {
    // No URL at all, and the child ends.
    let t = Tmp::new();
    let d = driver(&t, "printf 'segfault? no. just words\\r\\n'");
    let e = d.start(start("l_1")).await.unwrap_err();
    assert!(
        e.message.contains("before it showed a sign-in URL"),
        "{}",
        e.message
    );
    // No URL, and the child keeps quiet: the URL timeout.
    let t = Tmp::new();
    let d = driver_with(&t, "sleep 30", |c| {
        c.url_timeout = Duration::from_millis(400)
    });
    let e = d.start(start("l_1")).await.unwrap_err();
    assert!(
        e.message.contains("no sign-in URL in time"),
        "{}",
        e.message
    );
    assert!(scratch_gone(&t, "l_1"));
    // EOF after the code, no token.
    let t = Tmp::new();
    let d = driver(
        &t,
        &format!("printf '{URL}\\r\\ncode: '\nread -r c\nprintf 'bye\\r\\n'"),
    );
    d.start(start("l_1")).await.unwrap();
    let r = done(&d, "l_1", CODE).await;
    assert!(r.token.is_none());
    let why = r.error.unwrap();
    assert!(
        why.contains("before it printed a token") && why.contains("bye"),
        "{why}"
    );
    // A non-zero exit.
    let t = Tmp::new();
    let d = driver(
        &t,
        &format!("printf '{URL}\\r\\ncode: '\nread -r c\nexit 3"),
    );
    d.start(start("l_1")).await.unwrap();
    let why = done(&d, "l_1", CODE).await.error.unwrap();
    assert!(why.contains("exited with code 3"), "{why}");
    assert!(scratch_gone(&t, "l_1"));
}

#[tokio::test]
async fn a_hostile_url_is_passed_on_as_printed_and_never_opened() {
    let t = Tmp::new();
    let evil = "https://claude.ai.evil.example/oauth/authorize?next=http://127.0.0.1/";
    let opened = t.file("opened");
    // BROWSER is the stand-in's "browser": it records a launch; the runner sets it to `false`.
    let body = format!(
        "printf '{evil}\\r\\ncode: '\nif [ \"$BROWSER\" != /usr/bin/false ]; then echo yes > {}; fi\nread -r c",
        opened.display()
    );
    let d = driver(&t, &body);
    assert_eq!(d.start(start("l_1")).await.unwrap().url, evil);
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
    assert!(!opened.exists());
}

#[tokio::test]
async fn one_sign_in_at_a_time() {
    let t = Tmp::new();
    let d = driver(&t, &good("code: "));
    d.start(start("l_1")).await.unwrap();
    let e = d.start(start("l_2")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Busy);
    assert!(e.message.contains("already running"));
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
    assert!(d.start(start("l_2")).await.is_ok());
}

#[tokio::test]
async fn cancel_kills_the_process_tree_and_wipes_the_scratch() {
    let t = Tmp::new();
    let pids = t.file("pid");
    let body = format!(
        "sleep 300 &\necho $! > {}\nprintf '{URL}\\r\\ncode: '\nread -r c\nsleep 300",
        pids.display()
    );
    let d = driver(&t, &body);
    d.start(start("l_1")).await.unwrap();
    // A code is waiting for its answer when the cancel comes: it gets one too.
    let waiting = tokio::spawn({
        let d = Arc::clone(&d);
        async move { d.code(code("l_1", CODE)).await }
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let r = d
        .cancel(LoginCancel {
            login_id: "l_1".into(),
        })
        .await
        .unwrap();
    assert_eq!(r.error.as_deref(), Some("cancelled"));
    assert_eq!(
        waiting.await.unwrap().unwrap().error.as_deref(),
        Some("cancelled")
    );
    assert!(pid_dead(&pids).await, "the child's child is still running");
    assert!(scratch_gone(&t, "l_1"));
    // Cancelling what is gone is harmless.
    assert!(
        d.cancel(LoginCancel {
            login_id: "l_1".into()
        })
        .await
        .unwrap()
        .error
        .is_some()
    );
}

#[tokio::test]
async fn the_timeout_ends_the_sign_in_the_same_way() {
    let t = Tmp::new();
    let pids = t.file("pid");
    let body = format!(
        "sleep 300 &\necho $! > {}\nprintf '{URL}\\r\\ncode: '\nread -r c\nsleep 300",
        pids.display()
    );
    let d = driver_with(&t, &body, |c| c.timeout = Duration::from_secs(2));
    d.start(start("l_1")).await.unwrap();
    let why = done(&d, "l_1", CODE).await.error.unwrap();
    assert!(why.contains("timed out"), "{why}");
    assert!(pid_dead(&pids).await);
    assert!(scratch_gone(&t, "l_1"));
}

#[tokio::test]
async fn leftover_scratch_is_swept_when_the_driver_starts() {
    let t = Tmp::new();
    let old = t.file("logins").join("l_old").join("home");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("credentials"), "left behind").unwrap();
    let _ = driver(&t, "true");
    assert!(!t.file("logins").join("l_old").exists());
}

#[tokio::test]
async fn the_child_has_a_scrubbed_environment_and_a_private_home() {
    let t = Tmp::new();
    let dump = t.file("env");
    let body = format!(
        "env > {d}\nls -ld \"$HOME\" >> {d}\nprintf '{URL}\\r\\ncode: '\nread -r c",
        d = dump.display()
    );
    let d = driver(&t, &body);
    d.start(start("l_1")).await.unwrap();
    let seen = std::fs::read_to_string(&dump).unwrap();
    let allowed = [
        "PATH",
        "HOME",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "USER",
        "TERM",
        "COLORTERM",
        "LANG",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "CLAUDE_CONFIG_DIR",
        "BROWSER",
        "DISABLE_AUTOUPDATER",
        "PWD",
        "OLDPWD",
        "SHLVL",
        "_",
        "__CF_USER_TEXT_ENCODING",
    ];
    for l in seen
        .lines()
        .filter(|l| l.contains('=') && !l.starts_with('d'))
    {
        let name = l.split('=').next().unwrap();
        assert!(allowed.contains(&name), "unexpected variable {name}");
    }
    assert!(seen.contains("drwx------"), "HOME is 0700: {seen}");
    assert!(seen.contains("/logins/l_1/home"));
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
}

#[test]
fn child_env_drops_provider_keys_and_tokens() {
    let os = |k: &str, v: &str| (k.into(), v.into());
    let runner = vec![
        os("PATH", "/usr/bin"),
        os("HOME", "/home/someone"),
        os("ANTHROPIC_API_KEY", "planted"),
        os("CLAUDE_CODE_OAUTH_TOKEN", "planted"),
        os("OPENAI_API_KEY", "planted"),
        os("GITHUB_TOKEN", "planted"),
        os("AWS_SECRET_ACCESS_KEY", "planted"),
    ];
    let env = child_env(&runner, Path::new("/scratch/l_1"));
    assert!(!env.values().any(|v| v == "planted"), "{env:?}");
    assert_eq!(env["HOME"], "/scratch/l_1/home");
    assert_eq!(env["TMPDIR"], "/scratch/l_1/tmp");
    assert_eq!(env["BROWSER"], "/usr/bin/false");
    assert_eq!(env["PATH"], "/scratch/l_1/bin:/usr/local/bin:/usr/bin:/bin");
}

#[tokio::test]
async fn a_bad_code_never_reaches_the_pty() {
    let t = Tmp::new();
    let d = driver(&t, &good("code: "));
    d.start(start("l_1")).await.unwrap();
    for bad in [
        "short",
        "abcdefgh\r\nrm -rf /",
        "abcdefgh ijkl",
        "sk-ant-oat01-TESTONLY0123456789",
        "ab\u{0}cdefgh",
    ] {
        let e = d.code(code("l_1", bad)).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        assert!(
            !format!("{e:?}").contains(bad),
            "the error repeats the code"
        );
    }
    // And a code for another sign-in finds none.
    assert!(d.code(code("l_9", CODE)).await.is_err());
    // A second good code is told so.
    let first = tokio::spawn({
        let d = Arc::clone(&d);
        async move { done(&d, "l_1", CODE).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let r = d.code(code("l_1", "second-code-77")).await;
    if let Ok(r) = r {
        assert_eq!(r.error.as_deref(), Some("a code was already given"));
    }
    assert_eq!(first.await.unwrap().token.as_deref(), Some(TOKEN));
}

// ---- redaction ---------------------------------------------------------------------------
