//! Provider accounts on the runner (E15.1): an account's run gets its own config dir and its
//! token from the credentials dir, in the child's environment only; a missing file or a bad
//! reference fails the start with a reason that names the file.

use ainkrad_proto::runner::Account;

use super::*;

const FIXTURE: &str = include_str!("../../../../harness/tests/fixtures/claude/resume.ndjson");
const TOKEN: &str = "sk-ant-oat01-account-token-planted-5521";

fn account(credential: Option<&str>) -> Account {
    Account {
        id: 4,
        label: "claude-a".to_owned(),
        config_dir: "accounts/claude-a".to_owned(),
        credential_ref: credential.map(str::to_owned),
        credential_env: credential.map(|_| "CLAUDE_CODE_OAUTH_TOKEN".to_owned()),
    }
}

#[tokio::test]
async fn an_account_run_gets_its_config_dir_and_its_token_by_env_only() {
    let dir = scratch("account");
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nenv > {d}/env\nhead -n 2 > /dev/null\n\
             cat {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    std::fs::create_dir_all(&ex.credentials_dir).unwrap();
    std::fs::write(
        ex.credentials_dir.join("claude-a.token"),
        format!("{TOKEN}\n"),
    )
    .unwrap();

    let job = Job {
        account: Some(account(Some("claude-a.token"))),
        ..job("claude")
    };
    ex.start(&job).await.unwrap();
    assert_eq!(
        ex.run_secrets(&job),
        [("account_credential".to_owned(), TOKEN.to_owned())],
        "the token is redacted from the run's reports"
    );
    let (tx, _rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let config = format!(
        "CLAUDE_CONFIG_DIR={}",
        dir.join("config/accounts/claude-a").display()
    );
    assert!(env.lines().any(|l| l == config), "{env}");
    let token = format!("CLAUDE_CODE_OAUTH_TOKEN={TOKEN}");
    assert!(env.lines().any(|l| l == token), "the trimmed token, by env");
    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert!(!argv.contains(TOKEN), "the token went by argv");
    assert!(
        ex.run_secrets(&job).is_empty(),
        "forgotten once handed over"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_missing_credential_or_a_bad_reference_fails_clearly() {
    let dir = scratch("account-missing");
    let ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    let missing = Job {
        account: Some(account(Some("gone.token"))),
        ..job("claude")
    };
    let why = ex.start(&missing).await.unwrap_err();
    let path = ex.credentials_dir.join("gone.token");
    assert!(
        why.starts_with(&format!(
            "account claude-a: cannot read its credential file {}",
            path.display()
        )),
        "{why}"
    );
    std::fs::create_dir_all(&ex.credentials_dir).unwrap();
    std::fs::write(&path, "\n").unwrap();
    let why = ex.start(&missing).await.unwrap_err();
    assert!(why.ends_with("is empty"), "{why}");

    let escapes = |config_dir: &str, credential: &str, var: &str| Job {
        account: Some(Account {
            config_dir: config_dir.to_owned(),
            credential_ref: Some(credential.to_owned()),
            credential_env: Some(var.to_owned()),
            ..account(None)
        }),
        ..job("claude")
    };
    for bad in [
        escapes("../../home", "gone.token", "CLAUDE_CODE_OAUTH_TOKEN"),
        escapes("accounts/a", "/etc/passwd", "CLAUDE_CODE_OAUTH_TOKEN"),
        escapes("accounts/a", "gone.token", "LD_PRELOAD"),
    ] {
        let why = ex.start(&bad).await.unwrap_err();
        assert!(why.starts_with("account claude-a: "), "{why}");
    }
    // An account that logs in through its config dir needs no file.
    let login = Job {
        account: Some(account(None)),
        ..job("claude")
    };
    assert!(ex.start(&login).await.is_ok());
    assert!(dir.join("config/accounts/claude-a").is_dir());
    let _ = std::fs::remove_dir_all(&dir);
}
