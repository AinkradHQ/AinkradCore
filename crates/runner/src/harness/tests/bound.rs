//! E7-4: a runner-bound account's session runs in the account's own home, never a per-session dir.

use super::*;

fn bound(key: &str) -> Job {
    let mut j = job("codex");
    j.account = Some(ainkrad_proto::runner::Account {
        id: 0,
        label: "bound".to_owned(),
        config_dir: format!("bound/{key}"),
        credential_ref: None,
        credential_env: None,
    });
    j
}

#[test]
fn a_bound_session_uses_the_accounts_home_even_when_isolated() {
    let dir = scratch("bound-home");
    let ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    std::fs::create_dir_all(dir.join("config/bound/lg_1")).unwrap();
    let j = bound("lg_1");
    assert_eq!(ex.config_dir(&j).unwrap(), dir.join("config/bound/lg_1"));
    // An isolated session (the sandbox variable) still takes it: the login lives only there.
    ex.run_env
        .lock()
        .unwrap()
        .insert(j.run, vec![("AINKRAD_SANDBOX".to_owned(), "1".to_owned())]);
    assert_eq!(ex.config_dir(&j).unwrap(), dir.join("config/bound/lg_1"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_home_no_sign_in_made_or_a_path_is_refused() {
    let dir = scratch("bound-missing");
    let ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    let e = ex.config_dir(&bound("lg_9")).unwrap_err();
    assert!(e.contains("not on this runner"), "{e}");
    // Not a bound home: falls to the ordinary account rule, which refuses `..`.
    assert!(ex.config_dir(&bound("../x")).is_err());
    assert!(!dir.join("config/bound").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
