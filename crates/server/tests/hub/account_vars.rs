//! The per-harness variable allowlist for provider-account secrets (KAN-429), at the Core's
//! broker: refused at create for every creator, and again at launch for a stored session,
//! before any lease is minted. The runner's own check is in `runner/src/v2/agent/tests.rs`.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents::{self as service, Invalid, validate_new};
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use serde_json::json;

use super::agents::{make_admin, run_runner, script, secret, state_of, throwaway_mode};
use super::runner::{paired, state};
use super::{Core, quick};

fn grant(name: &str, var: &str) -> SessionSecret {
    SessionSecret {
        name: name.into(),
        var: var.into(),
    }
}

fn checked(harness: &str, secrets: &[SessionSecret]) -> Result<(), Invalid> {
    // Sandboxed, as KAN-433 requires of a session holding an account secret.
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner: "d_00000000000000000000000000",
        harness,
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets,
        created_by: "d_00000000000000000000000001",
    };
    validate_new(&new, true)
}

#[test]
fn an_account_secret_is_delivered_only_under_its_harnesss_own_variable() {
    // Its own variable: accepted, per harness.
    for (harness, var) in [
        ("claude", "ANTHROPIC_API_KEY"),
        ("claude", "CLAUDE_CODE_OAUTH_TOKEN"),
        ("codex", "OPENAI_API_KEY"),
        ("codex", "CODEX_API_KEY"),
        ("agy", "GEMINI_API_KEY"),
    ] {
        let ok = checked(harness, &[grant("acct.anthropic.main", var)]);
        assert_eq!(ok, Ok(()), "{harness} {var}");
    }
    // Any other variable, another harness's, an invented one, and a harness with no allowlist.
    for (harness, var) in [
        ("claude", "HTTPS_PROXY"),
        ("claude", "ANTHROPIC_BASE_URL"),
        ("claude", "OPENAI_API_KEY"),
        ("claude", "MY_KEY"),
        ("codex", "ANTHROPIC_API_KEY"),
        ("agy", "OPENAI_BASE_URL"),
        ("fake", "ANTHROPIC_API_KEY"),
    ] {
        let Err(Invalid::Bad(why)) = checked(harness, &[grant("acct.openai.main", var)]) else {
            panic!("{harness} {var} must be refused")
        };
        assert!(why.contains("authentication variables"), "{why}");
    }
}

#[test]
fn a_session_holding_an_account_secret_may_not_redirect_traffic_with_any_other_secret() {
    let key = grant("acct.anthropic.main", "ANTHROPIC_API_KEY");
    for var in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "ANTHROPIC_BASE_URL",
        "OPENAI_API_BASE",
        "AWS_ENDPOINT",
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "GIT_SSL_NO_VERIFY",
    ] {
        let both = [key.clone(), grant("git.token", var)];
        let Err(Invalid::Bad(why)) = checked("claude", &both) else {
            panic!("{var} must be refused beside an account secret")
        };
        assert!(why.contains("redirect"), "{why}");
        // Control: the same secret without an account secret is the old rule (accepted).
        assert_eq!(checked("claude", &both[1..]), Ok(()), "{var} alone");
    }
    // Control: an ordinary variable beside the key, and a plain session, are unchanged.
    assert_eq!(
        checked("claude", &[key, grant("git.token", "GIT_TOKEN")]),
        Ok(())
    );
    assert_eq!(checked("claude", &[]), Ok(()));
}

#[tokio::test]
async fn a_stored_session_with_a_misplaced_account_secret_fails_before_any_lease() {
    let core = Core::start("acct-vars", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("acct-vars");
    let e = paired(&core, &base, None, &st).await;
    throwaway_mode(&core).await;
    secret(
        &core,
        "acct.anthropic.main",
        std::slice::from_ref(&e.device_id),
        "env",
    )
    .await;
    let r = run_runner(
        &core,
        &base,
        &st,
        script("echo started; echo \"proxy=$HTTPS_PROXY\""),
    )
    .await;
    make_admin(&core, &r.id).await;
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let misplaced = [grant("acct.anthropic.main", "HTTPS_PROXY")];
    let new = NewSession {
        runner: &r.id,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &misplaced,
        created_by: &r.id,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    let why = service::start(&core.app, &s)
        .await
        .err()
        .map(|e| service::describe(&e))
        .expect("the start must be refused");
    assert!(why.contains("authentication variables"), "{why}");
    let stored = state_of(&core, &s.id).await;
    assert!(!stored.live(), "{:?}", stored.state);
    // Nothing was leased, and so nothing was redeemed.
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    r.halt().await;
}
