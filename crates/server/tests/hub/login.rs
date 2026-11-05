//! Subscription sign-in (KAN-441 L1) through the hub with a runner played by hand: the state
//! machine from `login.start` to a stored account, the token and the code in no row, event, audit
//! entry or log line, the gates, the expiry, the cancel, and the pool rule.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key as SettingKey, Scope};
use ainkrad_core_server::agents::login;
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::store::secrets::Error;
use ainkrad_core_server::store::{accounts, gov, logins, settings};
use ainkrad_proto::v2::*;
use zeroize::Zeroizing;

use super::gateway::command;
use super::{Core, Fake, agents, quick, random32};

pub(super) const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";
pub(super) const CODE: &str = "Xy12abCD-EFgh_34#st4te";

pub(super) struct W {
    pub(super) core: Core,
    pub(super) fake: Fake,
    pub(super) runner: String,
    pub(super) who: Caller,
}

pub(super) async fn up(name: &str, login_cap: bool, narrow_gate: bool) -> W {
    let core = Core::start_agents(name, quick(), agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    if login_cap {
        commands.push(CAP_LOGIN.to_owned());
    }
    let driver = DriverInfo {
        name: AGENT_DRIVER.to_owned(),
        commands,
        capacity: 2,
        streams: Some(32),
        ..DriverInfo::default()
    };
    let auth = fake.hello(&dev, vec![driver], &random32()).await;
    fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    fake.welcome().await;
    agents::throwaway_mode(&core).await;
    if narrow_gate {
        let now = core.app.clock.now();
        let set = settings::set(
            &core.app.pool,
            SettingKey::SecretsProviderAccounts,
            Scope::Server,
            "1",
            AuditActor::System,
            &now,
        );
        set.await.unwrap();
    }
    // The device that asks is an admin, and is also the runner's owner for the account's scope.
    let admin = core.device("device", &["admin"]).await;
    let device = gov::get_device(&core.app.pool, &admin.id)
        .await
        .unwrap()
        .unwrap();
    let who = Caller {
        device,
        session: String::new(),
    };
    W {
        core,
        fake,
        runner: dev.id,
        who,
    }
}

pub(super) fn refusal<T>(r: Result<T, Error>) -> (&'static str, String) {
    match r {
        Err(Error::Refused { code, message }) => (code, message),
        Err(Error::Db(e)) => panic!("db: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

pub(super) async fn state(w: &W, id: &str) -> logins::Login {
    login::get(&w.core.app, &w.who, id).await.unwrap()
}

pub(super) async fn until(w: &W, id: &str, want: &str) -> logins::Login {
    for _ in 0..200 {
        let l = state(w, id).await;
        if l.state == want {
            return l;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("the login never reached {want}: {:?}", state(w, id).await);
}

/// Starts a sign-in and answers the runner's `login.start` with a URL; returns the login at `open_url`.
pub(super) async fn to_open_url(w: &mut W, label: &str) -> logins::Login {
    let l = login::start(&w.core.app, &w.who, "claude-sub", label, None)
        .await
        .unwrap_or_else(|e| panic!("{:?}", refusal::<()>(Err(e))));
    assert_eq!(l.state, "starting");
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::LoginStart(s) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(
        (s.login_id.as_str(), s.harness.as_str()),
        (l.id.as_str(), "claude")
    );
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginUrl(LoginUrl {
                login_id: l.id.clone(),
                url: "https://claude.ai/oauth/authorize?state=TESTONLY".to_owned(),
            })),
        )
        .await;
    until(w, &l.id, "open_url").await
}

pub(super) async fn send_code(w: &W, id: &str, code: &str) -> Result<logins::Login, Error> {
    login::code(&w.core.app, &w.who, id, Zeroizing::new(code.to_owned())).await
}

/// Everything a secret could be in: rows, events, audit details and the log.
pub(super) async fn everything(core: &Core) -> String {
    let mut all = String::new();
    for sql in [
        "SELECT payload FROM events",
        "SELECT details FROM audit_events",
        "SELECT state || ifnull(url, '') || ifnull(reason, '') || label || runner FROM core_account_logins",
        "SELECT masked_tail || secret_name FROM core_accounts",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_all(&core.app.pool)
            .await
            .unwrap();
        all.push_str(&rows.join("\n"));
    }
    all.push_str(&String::from_utf8_lossy(&super::log().0.lock().unwrap()));
    all
}

#[tokio::test]
async fn a_sign_in_runs_from_the_url_to_a_stored_account_and_no_token_leaks() {
    let mut w = up("login-ok", true, true).await;
    let l = to_open_url(&mut w, "claude-me").await;
    assert_eq!(l.runner, w.runner);
    assert!(l.url.as_deref().unwrap().starts_with("https://claude.ai/"));
    // The code is taken once, in `open_url`, and goes to the runner.
    let waiting = send_code(&w, &l.id, CODE).await.unwrap();
    assert_eq!(waiting.state, "waiting_code");
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::LoginCode(c) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(
        (c.login_id.as_str(), c.code.as_str()),
        (l.id.as_str(), CODE)
    );
    assert!(
        !format!("{c:?}").contains(CODE),
        "the Debug of a code shows it"
    );
    let (code, _) = refusal(send_code(&w, &l.id, CODE).await);
    assert_eq!(code, "login_state", "a second code is refused");
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginResult(LoginResult {
                login_id: l.id.clone(),
                token: Some(TOKEN.to_owned()),
                error: None,
            })),
        )
        .await;
    let done = until(&w, &l.id, "done").await;
    let account = accounts::get(&w.core.app.pool, done.account_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        (account.provider.as_str(), account.label.as_str()),
        ("claude-sub", "claude-me")
    );
    assert_eq!(account.runners, [w.runner.clone()]);
    assert!(account.secret_name.starts_with("acct.claude-sub."));
    // `account.created` is audited with the method, and the broker's own `secret.created` too.
    let created: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'account.created'")
            .fetch_all(&w.core.app.pool)
            .await
            .unwrap();
    assert!(
        created.len() == 1 && created[0].contains("\"method\":\"subscription\""),
        "{created:?}"
    );
    // The events a client sees.
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM events WHERE kind LIKE 'account.login.%' ORDER BY seq",
    )
    .fetch_all(&w.core.app.pool)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        [
            "account.login.started",
            "account.login.url",
            "account.login.done"
        ]
    );
    // No token, no code, anywhere.
    let all = everything(&w.core).await;
    for secret in [TOKEN, CODE, "0123456789abcdefghijklmnop"] {
        assert!(!all.contains(secret), "{secret} leaked");
    }
    // A finished login takes no code and cancels to itself.
    assert_eq!(refusal(send_code(&w, &l.id, CODE).await).0, "login_state");
    let again = login::cancel(&w.core.app, &w.who, &l.id).await.unwrap();
    assert_eq!(again.state, "done");
}

#[tokio::test]
async fn the_state_machine_refuses_out_of_order_and_foreign_requests() {
    let mut w = up("login-order", true, true).await;
    let l = login::start(&w.core.app, &w.who, "claude-sub", "early", None)
        .await
        .unwrap();
    // A code before the URL, and one of the wrong shape, never reach the runner.
    assert_eq!(refusal(send_code(&w, &l.id, CODE).await).0, "login_state");
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::LoginStart(_)));
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginUrl(LoginUrl {
                login_id: l.id.clone(),
                url: "https://claude.ai/oauth/authorize".to_owned(),
            })),
        )
        .await;
    until(&w, &l.id, "open_url").await;
    for bad in [
        "",
        "short",
        "has space in it",
        "semi;colon-code-1",
        &"a".repeat(513),
    ] {
        assert_eq!(
            refusal(send_code(&w, &l.id, bad).await).0,
            "bad_request",
            "{bad:?}"
        );
    }
    assert_eq!(
        state(&w, &l.id).await.state,
        "open_url",
        "a bad code moves nothing"
    );
    // Another device sees nothing of it.
    let other = w.core.device("device", &["admin"]).await;
    let stranger = Caller {
        device: gov::get_device(&w.core.app.pool, &other.id)
            .await
            .unwrap()
            .unwrap(),
        session: String::new(),
    };
    for r in [
        login::get(&w.core.app, &stranger, &l.id).await.map(drop),
        login::code(
            &w.core.app,
            &stranger,
            &l.id,
            Zeroizing::new(CODE.to_owned()),
        )
        .await
        .map(drop),
        login::cancel(&w.core.app, &stranger, &l.id).await.map(drop),
    ] {
        assert_eq!(refusal(r).0, "not_found");
    }
    assert_eq!(
        refusal(login::get(&w.core.app, &w.who, "lg_nope").await).0,
        "not_found"
    );
    // Cancel: the runner is told, the login is over, a code is refused.
    let c = login::cancel(&w.core.app, &w.who, &l.id).await.unwrap();
    assert_eq!(
        (c.state.as_str(), c.reason.as_deref()),
        ("cancelled", Some("cancelled"))
    );
    let (_, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::LoginCancel(x) if x.login_id == l.id));
    assert_eq!(refusal(send_code(&w, &l.id, CODE).await).0, "login_state");
    // The label is free again; a second open sign-in of one label is not.
    let again = login::start(&w.core.app, &w.who, "claude-sub", "early", None)
        .await
        .unwrap();
    assert_eq!(
        refusal(login::start(&w.core.app, &w.who, "claude-sub", "early", None).await).0,
        "conflict"
    );
    let _ = again;
}

#[tokio::test]
async fn a_runner_error_fails_the_login_with_redacted_text() {
    let mut w = up("login-fail", true, true).await;
    let l = to_open_url(&mut w, "will-fail").await;
    send_code(&w, &l.id, CODE).await.unwrap();
    let (stream, _) = command(&mut w.fake).await;
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginResult(LoginResult {
                login_id: l.id.clone(),
                token: None,
                error: Some(format!("the code was wrong ({TOKEN})")),
            })),
        )
        .await;
    let failed = until(&w, &l.id, "failed").await;
    let reason = failed.reason.unwrap();
    assert!(reason.starts_with("the code was wrong"), "{reason}");
    assert!(!reason.contains("TESTONLY0123456789"), "{reason}");
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM events WHERE kind LIKE 'account.login.%' ORDER BY seq",
    )
    .fetch_all(&w.core.app.pool)
    .await
    .unwrap();
    assert_eq!(
        kinds.last().map(String::as_str),
        Some("account.login.failed")
    );
    assert!(!everything(&w.core).await.contains("TESTONLY0123456789"));
    assert_eq!(
        accounts::list(&w.core.app.pool).await.unwrap().len(),
        0,
        "no account"
    );
}

#[tokio::test]
async fn a_sign_in_past_its_expiry_has_failed() {
    let mut w = up("login-expiry", true, true).await;
    let l = to_open_url(&mut w, "slow").await;
    let now = w.core.app.clock.unix();
    let before = logins::get(
        &w.core.app.pool,
        &l.id,
        AuditActor::System,
        now + logins::TTL_SECS - 1,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(before.state, "open_url");
    let after = logins::get(
        &w.core.app.pool,
        &l.id,
        AuditActor::System,
        now + logins::TTL_SECS + 1,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (after.state.as_str(), after.reason.as_deref()),
        ("failed", Some("expired"))
    );
    assert_eq!(refusal(send_code(&w, &l.id, CODE).await).0, "login_state");
}

#[tokio::test]
async fn a_start_is_refused_where_a_sign_in_cannot_go_or_a_gate_is_closed() {
    // No runner lists the `login` command.
    let w = up("login-norunner", false, true).await;
    let r = login::start(&w.core.app, &w.who, "claude-sub", "x", None).await;
    assert_eq!(refusal(r).0, "no_runner");
    let r = login::start(&w.core.app, &w.who, "claude-sub", "x", Some(&w.runner)).await;
    assert_eq!(refusal(r).0, "no_runner");
    // Not a subscription provider, a bad label.
    let r = login::start(&w.core.app, &w.who, "anthropic", "x", None).await;
    assert_eq!(refusal(r).0, "bad_request");
    let r = login::start(&w.core.app, &w.who, "claude-sub", "Bad Label", None).await;
    assert_eq!(refusal(r).0, "bad_request");
    // The narrow gate is off: a real token would be refused at the store, so the sign-in does not start.
    let w = up("login-gate", true, false).await;
    let r = login::start(&w.core.app, &w.who, "claude-sub", "x", None).await;
    assert_eq!(refusal(r).0, "real_secret_refused");
    // `secrets.mode` 0 refuses all of it.
    let now = w.core.app.clock.now();
    settings::set(
        &w.core.app.pool,
        SettingKey::SecretsMode,
        Scope::Server,
        "0",
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    let r = login::start(&w.core.app, &w.who, "claude-sub", "x", None).await;
    assert_eq!(refusal(r).0, "secrets_disabled");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM core_account_logins")
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap(),
        0
    );
}
