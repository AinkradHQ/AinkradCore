//! A gateway session's harness environment (KAN-435 G6), through the executor: the runner's
//! base URL and placeholder key reach the harness, whatever else the environment held for the
//! provider is gone, Codex gets its generated `config.toml`, and a harness with no wiring is
//! refused. (The sandbox slot's port is what marks a session as a gateway's.)

use super::env::fake_codex_recording_env;
use super::*;

const FIXTURE: &str = include_str!("../../../../harness/tests/fixtures/claude/resume.ndjson");
const PORT: &str = "47833";
/// What an agent session's grants or the runner's `--env` might have put in: none of it may stay.
const PLANTED: [(&str, &str); 6] = [
    ("ANTHROPIC_API_KEY", "planted-agent-key"),
    ("ANTHROPIC_AUTH_TOKEN", "planted-agent-token"),
    ("CLAUDE_CODE_OAUTH_TOKEN", "planted-agent-oauth"),
    ("OPENAI_BASE_URL", "http://planted.invalid/v1"),
    ("OPENAI_API_KEY", "planted-agent-openai"),
    ("GOOGLE_GEMINI_BASE_URL", "http://planted.invalid"),
];

fn slot_env() -> Vec<(String, String)> {
    [("AINKRAD_SANDBOX_GW_PORT", PORT)]
        .into_iter()
        .chain(PLANTED)
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect()
}

#[tokio::test]
async fn claude_gets_the_gateway_url_and_a_placeholder_and_nothing_else_of_the_providers() {
    let dir = scratch("gw-claude");
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!("#!/bin/sh\nenv > {d}/env\nhead -n 2 > /dev/null\ncat {d}/fixture.ndjson\n"),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    let job = job("claude");
    ex.session_env(job.run, Some(slot_env()));
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let has = |l: &str| env.lines().any(|x| x == l);
    assert!(
        has(&format!("ANTHROPIC_BASE_URL=http://127.0.0.1:{PORT}")),
        "{env}"
    );
    assert!(has("ANTHROPIC_API_KEY=placeholder"), "{env}");
    assert_eq!(env.matches("ANTHROPIC_API_KEY=").count(), 1, "{env}");
    for (name, value) in PLANTED {
        assert!(!env.contains(value), "{name} stayed: {env}");
    }
    // The slot's own variables are the sandbox's, never the harness's.
    assert!(!env.contains("AINKRAD_SANDBOX_GW"), "{env}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn codex_gets_a_generated_config_in_its_home_and_a_placeholder_key() {
    let dir = scratch("gw-codex");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins
        .insert("codex".to_owned(), fake_codex_recording_env(&dir));
    let job = Job {
        model: String::new(),
        ..job("codex")
    };
    ex.session_env(job.run, Some(slot_env()));
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    assert!(
        env.lines().any(|l| l == "OPENAI_API_KEY=placeholder"),
        "{env}"
    );
    // Codex ignores `OPENAI_BASE_URL`: the URL is in the config, and the variable is not set.
    assert!(!env.contains("OPENAI_BASE_URL"), "{env}");
    for (name, value) in PLANTED {
        assert!(!env.contains(value), "{name} stayed: {env}");
    }
    let home = dir.join("config/codex");
    assert!(
        env.lines()
            .any(|l| l == format!("CODEX_HOME={}", home.display())),
        "{env}"
    );
    let config = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert_eq!(config, crate::codex_config::gateway(47833));
    assert!(config.contains(&format!("base_url = \"http://127.0.0.1:{PORT}/v1\"")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_harness_with_no_wiring_is_refused_and_a_session_without_the_slot_is_untouched() {
    let dir = scratch("gw-other");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins
        .insert("codex".to_owned(), fake_codex_recording_env(&dir));
    // Not a gateway session: the environment is the session's own, as before.
    let job = Job {
        model: String::new(),
        ..job("codex")
    };
    ex.session_env(
        job.run,
        Some(vec![(
            "OPENAI_BASE_URL".to_owned(),
            "http://own/v1".to_owned(),
        )]),
    );
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    assert_eq!(
        ex.run(&job, RunToken::new("t".to_owned()), tx).await,
        Outcome::Succeeded
    );
    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    assert!(
        env.lines().any(|l| l == "OPENAI_BASE_URL=http://own/v1"),
        "{env}"
    );
    assert!(!env.contains("placeholder"), "{env}");
    assert!(!dir.join("config/codex/config.toml").exists());

    // A gateway session of a harness the gateway has no wiring for fails, naming why.
    let job = Job {
        run: 8,
        ..self::job("opencode")
    };
    ex.session_env(job.run, Some(slot_env()));
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    match ex.run(&job, RunToken::new("t".to_owned()), tx).await {
        Outcome::Failed { reason, .. } => assert!(reason.contains("no wiring"), "{reason}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
