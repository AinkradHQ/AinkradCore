//! A gateway session through the executor (KAN-435 G6): the slot's variable marks it; it must be
//! sandboxed and have a valid port or it fails; a sandboxed one gets its Codex config in the
//! session's own home and never in the runner-wide one. (The child's environment is checked on
//! `wire` directly and, inside real bubblewrap, in `tests/gateway_netns.rs`: a sandboxed child
//! cannot be a fake script here.)

use super::env::fake_codex_recording_env;
use super::*;

fn session(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    [
        ("AINKRAD_SANDBOX_GW_SOCK", "/s/gateway.sock"),
        ("AINKRAD_SANDBOX_GW_PORT", "47833"),
    ]
    .iter()
    .chain(extra)
    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
    .collect()
}

async fn run_codex(dir: &Path, env: Vec<(String, String)>) -> (HarnessExecutor, Job, Outcome) {
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins
        .insert("codex".to_owned(), fake_codex_recording_env(dir));
    let job = Job {
        model: String::new(),
        ..job("codex")
    };
    ex.session_env(job.run, Some(env));
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    (ex, job, outcome)
}

fn failed_with(outcome: &Outcome, what: &str) {
    match outcome {
        Outcome::Failed { reason, .. } => assert!(reason.contains(what), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_gateway_session_that_is_not_sandboxed_fails_and_writes_no_config() {
    let dir = scratch("gw-unsandboxed");
    let (ex, job, outcome) =
        run_codex(&dir, session(&[("OPENAI_BASE_URL", "http://own/v1")])).await;
    failed_with(&outcome, "sandbox");
    // Neither the runner-wide home nor a session home got a config, and the harness never ran.
    for home in [dir.join("config/codex"), ex.config_dir(&job).unwrap()] {
        assert!(!home.join("config.toml").exists(), "{}", home.display());
    }
    assert!(!dir.join("env").exists(), "the harness ran");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_slot_without_a_valid_port_fails_the_session_rather_than_running_it_unwired() {
    for port in ["", "0", "x", "70000"] {
        let dir = scratch("gw-port");
        let env = vec![
            ("AINKRAD_SANDBOX".to_owned(), "1".to_owned()),
            (
                "AINKRAD_SANDBOX_GW_SOCK".to_owned(),
                "/s/gateway.sock".to_owned(),
            ),
            ("AINKRAD_SANDBOX_GW_PORT".to_owned(), port.to_owned()),
        ];
        let (_, _, outcome) = run_codex(&dir, env).await;
        failed_with(&outcome, "port");
        assert!(
            !dir.join("env").exists(),
            "the harness ran with port {port:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    // The slot with no port at all.
    let dir = scratch("gw-noport");
    let env = vec![
        ("AINKRAD_SANDBOX".to_owned(), "1".to_owned()),
        (
            "AINKRAD_SANDBOX_GW_SOCK".to_owned(),
            "/s/gateway.sock".to_owned(),
        ),
    ];
    let (_, _, outcome) = run_codex(&dir, env).await;
    failed_with(&outcome, "port");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_sandboxed_gateway_session_gets_its_config_in_its_own_home_only() {
    let dir = scratch("gw-sandboxed");
    let (ex, job, _) = run_codex(&dir, session(&[("AINKRAD_SANDBOX", "1")])).await;
    let home = ex.config_dir(&job).unwrap();
    assert!(
        home.starts_with(dir.join("config/sessions")),
        "{}",
        home.display()
    );
    let config = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert_eq!(config, crate::codex_config::gateway(47833));
    assert!(
        !dir.join("config/codex/config.toml").exists(),
        "the runner-wide Codex home was written"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_harness_with_no_wiring_is_refused_and_a_session_without_the_slot_is_untouched() {
    let dir = scratch("gw-other");
    // Not a gateway session: the environment is the session's own, as before, and no file is made.
    let (_, _, outcome) = run_codex(
        &dir,
        vec![("OPENAI_BASE_URL".to_owned(), "http://own/v1".to_owned())],
    )
    .await;
    assert_eq!(outcome, Outcome::Succeeded);
    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    assert!(
        env.lines().any(|l| l == "OPENAI_BASE_URL=http://own/v1"),
        "{env}"
    );
    assert!(!env.contains("placeholder"), "{env}");
    assert!(!dir.join("config/codex/config.toml").exists());

    // A sandboxed gateway session of a harness the gateway has no wiring for fails, naming why.
    let ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    let job = Job {
        run: 8,
        ..self::job("opencode")
    };
    ex.session_env(job.run, Some(session(&[("AINKRAD_SANDBOX", "1")])));
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    failed_with(
        &ex.run(&job, RunToken::new("t".to_owned()), tx).await,
        "no wiring",
    );
    let _ = std::fs::remove_dir_all(&dir);
}
