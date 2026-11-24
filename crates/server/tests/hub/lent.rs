//! Accounts on the Core (2026-11-23): a ChatGPT/OpenCode login lives in the Core's vault and is lent
//! to the runner of each session, with a runner played by hand. A new sign-in moves into the vault
//! at once; an old runner-bound account moves on "Move to Core"; Antigravity stays where it is; a
//! session is lent the login as a single-use lease and nothing else; a refreshed login comes back
//! only from the session's runner and only for the same account. Dummy values only.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key as SettingKey, Scope};
use ainkrad_core_server::agents::{self as service, lend, login};
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use ainkrad_core_server::store::{accounts, bound, gov, secrets, settings};
use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::*;

use super::gateway::{command, policy};
use super::login::{W, refusal, until};
use super::{Core, Fake, agents, quick, random32};

/// A dummy Codex login (no real token shape anywhere).
const AUTH: &str =
    r#"{"tokens":{"refresh_token":"dummy-refresh-1","access_token":"dummy-access-1"}}"#;
const AUTH_NEW: &str =
    r#"{"tokens":{"refresh_token":"dummy-refresh-2","access_token":"dummy-access-2"}}"#;

fn bundle(text: &str) -> Bundle {
    Bundle::from([("auth.json".to_owned(), text.to_owned())])
}

/// A Core with one runner that lists everything a current runner does for plans.
async fn up(name: &str, export: bool) -> W {
    let core = Core::start_agents(name, quick(), agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    fake.os = Some("linux".to_owned());
    fake.isolation = Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable));
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    commands.extend(
        [
            "egress-filter",
            CAP_SUBSCRIPTION_ENV,
            CAP_BOUND_HOME,
            CAP_LENT_HOME,
            CAP_LOGIN_WIPE,
        ]
        .map(str::to_owned),
    );
    for h in ["codex", "opencode", "agy"] {
        commands.push(format!("{CAP_LOGIN_BOUND}{h}"));
    }
    if export {
        commands.push(CAP_LOGIN_EXPORT.to_owned());
    }
    let driver = DriverInfo {
        name: AGENT_DRIVER.to_owned(),
        commands,
        capacity: 4,
        streams: Some(32),
        ..DriverInfo::default()
    };
    let auth = fake.hello(&dev, vec![driver], &random32()).await;
    fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    fake.welcome().await;
    agents::throwaway_mode(&core).await;
    agents::make_admin(&core, &dev.id).await;
    // The narrow gate: real provider-account credentials are allowed (a plan's login is one).
    settings::set(
        &core.app.pool,
        SettingKey::SecretsProviderAccounts,
        Scope::Server,
        "1",
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    let admin = core.device("device", &["admin"]).await;
    let device = gov::get_device(&core.app.pool, &admin.id)
        .await
        .unwrap()
        .unwrap();
    W {
        core,
        fake,
        runner: dev.id,
        who: Caller {
            device,
            session: String::new(),
        },
    }
}

/// A runner-bound account as an older sign-in left it (marker value, bound record).
async fn bound_account(w: &W, provider: &str, label: &str, home: &str) -> accounts::Account {
    let marker = accounts::bound_marker(home);
    let new = accounts::NewAccount {
        provider,
        label,
        value: &marker,
        runners: &[],
        cap: Some(1),
        display_name: None,
    };
    let sealer = w.core.app.secrets.as_deref().unwrap();
    accounts::create_bound(
        &w.core.app.pool,
        sealer,
        &new,
        (w.runner.as_str(), home),
        &w.runner,
        AuditActor::System,
        &w.core.app.clock.now(),
        &ainkrad_core_server::store::placement::Placement {
            user: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .0
}

/// The login on file for `a`, as the runner would be lent it.
async fn on_file(w: &W, a: &accounts::Account) -> Bundle {
    use base64::Engine;
    let sealer = w.core.app.secrets.as_deref().unwrap();
    let v = secrets::open_for_masking(
        &w.core.app.pool,
        sealer,
        std::slice::from_ref(&a.secret_name),
        "9999-12-31T00:00:00Z",
    )
    .await
    .unwrap();
    let text = base64::engine::general_purpose::STANDARD
        .decode(v[0].1.as_bytes())
        .unwrap();
    serde_json::from_slice(&text).unwrap()
}

/// Answers the runner's `login.export` for `home` with `files`.
async fn answer_export(w: &mut W, home: &str, files: &Bundle) {
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::LoginExport(e) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!((e.home.as_str(), e.harness.as_str()), (home, "codex"));
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginResult(LoginResult {
                login_id: home.to_owned(),
                token: Some(serde_json::to_string(files).unwrap()),
                error: None,
                done: true,
            })),
        )
        .await;
}

async fn held(w: &W, a: &accounts::Account) -> bool {
    let mut conn = w.core.app.pool.acquire().await.unwrap();
    bound::held_by_core(&mut conn, &a.provider, a.id)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_codex_sign_in_goes_into_the_vault_and_its_runner_home_is_owed_a_wipe() {
    let mut w = up("lent-signin", true).await;
    let second = w.core.runner().await.id;
    let l = login::start(&w.core.app, &w.who, "codex-sub", "codex-me", None, None)
        .await
        .unwrap();
    // No runner was named: the Core placed the sign-in itself.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::LoginStart(_)), "{cmd:?}");
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginUrl(LoginUrl {
                login_id: l.id.clone(),
                url: "https://auth.openai.com/codex/device".to_owned(),
                code: Some("K7QM-4XZP".to_owned()),
            })),
        )
        .await;
    until(&w, &l.id, "open_url").await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::LoginWait(_)));
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginResult(LoginResult {
                login_id: l.id.clone(),
                token: None,
                error: None,
                done: true,
            })),
        )
        .await;
    answer_export(&mut w, &l.id, &bundle(AUTH)).await;
    let done = until(&w, &l.id, "done").await;
    let a = accounts::get(&w.core.app.pool, done.account_id.unwrap())
        .await
        .unwrap();
    assert!(held(&w, &a).await, "the login is the Core's now");
    assert_eq!(on_file(&w, &a).await, bundle(AUTH));
    let mut want = vec![w.runner.clone(), second];
    want.sort();
    let mut got = a.runners.clone();
    got.sort();
    assert_eq!(got, want, "every runner may be lent it");
    assert_eq!(a.cap, 1, "one session at a time: one refresh at a time");
    let owed = accounts::pending_wipes(&w.core.app.pool, std::slice::from_ref(&w.runner))
        .await
        .unwrap();
    assert!(
        owed.iter().any(|p| p.home == l.id),
        "the runner's copy goes"
    );
    let details: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&w.core.app.pool)
        .await
        .unwrap();
    assert!(details.iter().all(|d| !d.contains("dummy-refresh")));
}

#[tokio::test]
async fn an_old_bound_account_moves_to_the_core_and_antigravity_stays() {
    let mut w = up("lent-move", true).await;
    let a = bound_account(&w, "codex-sub", "codex-old", "lg_old").await;
    assert!(!held(&w, &a).await);
    let (app, id, by) = (w.core.app.clone(), a.id, w.who.device.id.clone());
    let moving =
        tokio::spawn(async move { lend::move_to_core(&app, id, &by, AuditActor::System).await });
    answer_export(&mut w, "lg_old", &bundle(AUTH)).await;
    let moved = moving.await.unwrap().unwrap();
    assert!(held(&w, &moved).await);
    assert_eq!(on_file(&w, &moved).await, bundle(AUTH));
    let again = lend::move_to_core(&w.core.app, a.id, "d", AuditActor::System).await;
    assert_eq!(refusal(again).0, "bad_request", "already on the Core");

    let g = bound_account(&w, "agy-sub", "agy-old", "lg_agy").await;
    let r = lend::move_to_core(&w.core.app, g.id, "d", AuditActor::System).await;
    assert_eq!(refusal(r).0, "not_portable");
    assert!(!held(&w, &g).await, "it still works where it was");
}

#[tokio::test]
async fn a_runner_too_old_to_hand_the_login_over_leaves_the_account_as_it_was() {
    let w = up("lent-old-runner", false).await;
    let a = bound_account(&w, "codex-sub", "codex-x", "lg_x").await;
    let r = lend::move_to_core(&w.core.app, a.id, "d", AuditActor::System).await;
    assert_eq!(refusal(r).0, "runner_too_old");
    let mut conn = w.core.app.pool.acquire().await.unwrap();
    assert!(bound::of(&mut conn, a.id).await.unwrap().is_some());
}

/// A Core-held Codex account and a stored session of it on the runner.
async fn lent_session(w: &W) -> (accounts::Account, sessions::Session) {
    let a = bound_account(w, "codex-sub", "codex-lent", "lg_lent").await;
    let sealer = w.core.app.secrets.as_deref().unwrap();
    bound::hold(
        &w.core.app.pool,
        sealer,
        &a,
        &serde_json::to_string(&bundle(AUTH)).unwrap(),
        "d",
        AuditActor::System,
        &w.core.app.clock.now(),
    )
    .await
    .unwrap();
    let secrets = [SessionSecret {
        name: a.secret_name.clone(),
        var: "OPENAI_API_KEY".to_owned(),
    }];
    let policy = policy();
    let new = NewSession {
        runner: &w.runner,
        harness: "codex",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &w.runner,
    };
    let row = sessions::create_owned(
        &w.core.app.pool,
        &new,
        None,
        AuditActor::System,
        &w.core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&w.core.app, &row.id);
    (accounts::get(&w.core.app.pool, a.id).await.unwrap(), row)
}

#[tokio::test]
async fn a_session_is_lent_the_login_once_and_a_refresh_comes_back_only_for_the_same_account() {
    let mut w = up("lent-session", true).await;
    let (a, row) = lent_session(&w).await;
    let (app, started) = (w.core.app.clone(), row.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &started).await;
    });
    let (_, cmd) = command(&mut w.fake).await;
    let Command::AgentStart(start) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(start.home, None, "no home on the runner");
    assert!(
        start.secrets.is_empty(),
        "the login is never an env variable"
    );
    let lease = start.home_lease.expect("the login is lent");
    let sealer = w.core.app.secrets.as_deref().unwrap();
    let (now, unix) = (w.core.app.clock.now(), w.core.app.clock.unix());
    let got = secrets::redeem(
        &w.core.app.pool,
        sealer,
        &lease,
        &w.runner,
        AuditActor::System,
        &now,
        unix,
    )
    .await
    .unwrap();
    assert_eq!(got.kind, "file");
    let again = secrets::redeem(
        &w.core.app.pool,
        sealer,
        &lease,
        &w.runner,
        AuditActor::System,
        &now,
        unix,
    )
    .await;
    assert_eq!(refusal(again).0, "lease_expired", "single use");

    // Another runner, another account's login, or a file that is not the harness's: refused.
    let r = lend::take_back(&w.core.app, "d_other", &row.id, &bundle(AUTH_NEW)).await;
    assert_eq!(refusal(r).0, "not_found");
    let r = lend::take_back(
        &w.core.app,
        &w.runner,
        &row.id,
        &bundle(r#"{"someone":"else"}"#),
    )
    .await;
    assert_eq!(refusal(r).0, "bad_request");
    let stray = Bundle::from([("config.toml".to_owned(), "{}".to_owned())]);
    let r = lend::take_back(&w.core.app, &w.runner, &row.id, &stray).await;
    assert_eq!(refusal(r).0, "bad_request");
    assert_eq!(on_file(&w, &a).await, bundle(AUTH));

    // The token the harness refreshed during the session is written back to the vault.
    lend::take_back(&w.core.app, &w.runner, &row.id, &bundle(AUTH_NEW))
        .await
        .unwrap();
    assert_eq!(on_file(&w, &a).await, bundle(AUTH_NEW));
}
