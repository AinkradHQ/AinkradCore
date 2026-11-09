//! KAN-441 L2 hardening: the code and its Enter as two writes, version drift, browser stubs, the
//! sign-in URL told from a docs link, the drop guard, the start-up sweep, the answer deadline.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ErrorCode, LoginCancel};
use tokio::sync::mpsc;

use super::run::Guard;
use super::tests::{
    CODE, TOKEN, Tmp, URL, done, driver, driver_with, good, scratch_gone, standin, start,
};
use super::{LoginDriver, Msg, sweep};

/// A raw-mode TUI stand-in: reads whatever one read gives. A chunk holding the code and a CR is
/// a paste and its Enter is ignored (it hangs); the code, then the CR as a read of its own, signs in.
fn raw_tui() -> String {
    format!(
        r#"stty raw -echo
CR=$(printf '\r')
printf '{URL}\r\ncode: '
c1=$(dd bs=4096 count=1 2>/dev/null)
case "$c1" in *"$CR"*) sleep 30; exit 0;; esac
c2=$(dd bs=4096 count=1 2>/dev/null)
case "$c2" in "$CR") printf '\r\n{TOKEN}\r\n';; *) sleep 30;; esac"#
    )
}

#[tokio::test]
async fn the_code_and_its_enter_are_two_writes() {
    let t = Tmp::new();
    let d = driver(&t, &raw_tui());
    d.start(start("l_1")).await.unwrap();
    let r = done(&d, "l_1", CODE).await;
    assert_eq!(r.token.as_deref(), Some(TOKEN), "{:?}", r.error);
}

#[tokio::test]
async fn the_stand_in_does_detect_a_paste() {
    // The same stand-in, with the code and its CR in one write: the Enter is lost, no token.
    let t = Tmp::new();
    let d = driver_with(&t, &raw_tui(), |c| {
        c.enter_delay = Duration::ZERO;
        c.answer_timeout = Duration::from_secs(1);
    });
    d.start(start("l_1")).await.unwrap();
    let r = done(&d, "l_1", CODE).await;
    assert!(r.token.is_none());
    assert!(
        r.error.unwrap().contains("gave no token"),
        "a paste must not sign in"
    );
    assert!(scratch_gone(&t, "l_1"));
}

#[tokio::test]
async fn a_wrong_code_ends_in_a_failed_result_with_the_last_line_redacted() {
    let t = Tmp::new();
    let body = format!(
        "printf '{URL}\\r\\ncode: '\nread -r c\nprintf \"Invalid code $c sk-ant-api03-LEAKLEAKLEAK\\r\\n\"\nsleep 30"
    );
    let d = driver_with(&t, &body, |c| c.answer_timeout = Duration::from_secs(1));
    d.start(start("l_1")).await.unwrap();
    let why = done(&d, "l_1", CODE).await.error.unwrap();
    assert!(
        why.contains("wrong or expired") && why.contains("[redacted]"),
        "{why}"
    );
    assert!(!why.contains(CODE) && !why.contains("sk-ant-"), "{why}");
}

#[tokio::test]
async fn a_claude_that_drifted_off_the_pinned_version_is_not_offered_and_not_driven() {
    let t = Tmp::new();
    let body = format!("printf '{URL}\\r\\ncode: '\nread -r c");
    let d = driver(&t, &body);
    assert_eq!(d.supported().await.unwrap(), "9.9.9");
    // claude updates itself.
    standin(&t, "9.9.8", &body);
    let why = d.supported().await.unwrap_err();
    assert!(
        why.contains("9.9.8") && why.contains("not a version"),
        "{why}"
    );
    let e = d.start(start("l_1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCommand);
    assert!(scratch_gone(&t, "l_1"));
}

#[tokio::test]
async fn open_and_xdg_open_hit_the_stubs_and_the_path_is_fixed() {
    let t = Tmp::new();
    let dump = t.file("dump");
    let body = format!(
        "{{ command -v open; open https://example.com; echo rc=$?; command -v xdg-open; echo \"$PATH\"; }} > {} 2>&1\nprintf '{URL}\\r\\ncode: '\nread -r c",
        dump.display()
    );
    let d = driver(&t, &body);
    d.start(start("l_1")).await.unwrap();
    let seen = std::fs::read_to_string(&dump).unwrap();
    assert!(seen.contains("/logins/l_1/bin/open"), "{seen}");
    assert!(seen.contains("rc=1"), "{seen}");
    assert!(seen.contains("/logins/l_1/bin/xdg-open"), "{seen}");
    assert!(
        seen.contains("/bin:/usr/local/bin:/usr/bin:/bin\n"),
        "{seen}"
    );
    d.cancel(LoginCancel {
        login_id: "l_1".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_sign_in_url_is_told_from_a_docs_link() {
    let t = Tmp::new();
    let docs = "https://docs.example.org/claude-code/overview";
    let body = format!(
        "printf 'Help: {docs}\\r\\n{URL}\\r\\n{URL}\\r\\ncode: '\nread -r c\nprintf '{TOKEN}\\r\\n'"
    );
    let d = driver(&t, &body);
    assert_eq!(d.start(start("l_1")).await.unwrap().url, URL);
    assert_eq!(done(&d, "l_1", CODE).await.token.as_deref(), Some(TOKEN));
    // Only a docs link, then the prompt: it fails plainly.
    let t = Tmp::new();
    let body = format!("printf 'Help: {docs}\\r\\nPaste code here > '\nsleep 30");
    let d = driver(&t, &body);
    let e = d.start(start("l_1")).await.unwrap_err();
    assert!(
        e.message.contains("printed no sign-in URL"),
        "{}",
        e.message
    );
    assert!(scratch_gone(&t, "l_1"));
}

#[tokio::test]
async fn a_panic_in_the_task_still_removes_the_scratch_dir_and_the_slot() {
    let t = Tmp::new();
    let d: Arc<LoginDriver> = driver(&t, &good("code: "));
    let scratch = t.file("logins").join("l_p");
    std::fs::create_dir_all(scratch.join("home")).unwrap();
    let (tx, _rx) = mpsc::unbounded_channel::<Msg>();
    d.active.lock().unwrap().insert("l_p".to_owned(), tx);
    let guard = Guard {
        driver: Arc::clone(&d),
        id: "l_p".to_owned(),
        scratch: scratch.clone(),
    };
    let task = tokio::spawn(async move {
        let _guard = guard;
        panic!("the task dies");
    });
    assert!(task.await.unwrap_err().is_panic());
    assert!(!scratch.exists());
    assert!(d.active.lock().unwrap().is_empty());
    // The slot is free again.
    assert!(d.start(start("l_q")).await.is_ok());
    d.cancel(LoginCancel {
        login_id: "l_q".into(),
    })
    .await
    .unwrap();
}

#[test]
fn the_runner_sweeps_its_sign_in_dir_at_start_with_no_driver() {
    let t = Tmp::new();
    let state = t.file("state");
    let left = state.join("logins/l_old/home/.claude");
    std::fs::create_dir_all(&left).unwrap();
    std::fs::write(left.join("credentials"), "left behind").unwrap();
    sweep(&state);
    assert!(!state.join("logins").exists());
    // Nothing there is fine too.
    sweep(&state);
}
