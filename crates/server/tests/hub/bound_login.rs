//! E7-4: the runner-bound Codex sign-in through the hub with a runner played by hand. The login
//! stays on the runner: the Core gets the URL and a device code, then a success flag, and stores a
//! marker account pinned to that one runner. No token exists anywhere in this flow.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents::login;
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::store::{accounts, bound, gov, logins};
use ainkrad_proto::v2::*;

use super::gateway::command;
use super::login::{W, refusal, until};
use super::{Core, Fake, agents, quick, random32};

const PAGE: &str = "https://auth.openai.com/codex/device";
const DEVICE_CODE: &str = "K7QM-4XZP";

async fn up(name: &str, bound_cap: bool) -> W {
    let core = Core::start_agents(name, quick(), agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    if bound_cap {
        commands.push(format!("{CAP_LOGIN_BOUND}codex"));
        commands.push(format!("{CAP_LOGIN_BOUND}opencode"));
        commands.push(CAP_BOUND_HOME.to_owned());
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
    // No `secrets.provider_accounts`: a bound login stores no key, only a marker.
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

async fn to_open_url(w: &mut W, label: &str) -> (logins::Login, u64) {
    let l = login::start(&w.core.app, &w.who, "codex-sub", label, None)
        .await
        .unwrap_or_else(|e| panic!("{:?}", refusal::<()>(Err(e))));
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::LoginStart(s) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(s.harness, "codex");
    // The home key is the login's own id: the Core names it, the runner makes it.
    assert_eq!(s.home.as_deref(), Some(l.id.as_str()));
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginUrl(LoginUrl {
                login_id: l.id.clone(),
                url: PAGE.to_owned(),
                code: Some(DEVICE_CODE.to_owned()),
            })),
        )
        .await;
    (until(w, &l.id, "open_url").await, stream)
}

#[tokio::test]
async fn a_codex_sign_in_stores_a_marker_account_pinned_to_its_runner() {
    let mut w = up("bound-ok", true).await;
    // A second runner exists: the account must still be pinned to the first alone.
    let _second = w.core.runner().await.id;
    let (l, _) = to_open_url(&mut w, "codex-me").await;
    assert_eq!(
        (l.url.as_deref(), l.code.as_deref()),
        (Some(PAGE), Some(DEVICE_CODE))
    );
    // The Core waits for the runner's CLI to finish; the user types no code.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::LoginWait(wt) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(wt.login_id, l.id);
    let (code, _) = refusal(
        login::code(
            &w.core.app,
            &w.who,
            &l.id,
            zeroize::Zeroizing::new("ABCD-1234-xyz".to_owned()),
        )
        .await,
    );
    assert_eq!(code, "bad_request", "a bound sign-in takes no pasted code");
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
    let done = until(&w, &l.id, "done").await;
    let a = accounts::get(&w.core.app.pool, done.account_id.unwrap())
        .await
        .unwrap();
    assert_eq!(a.provider, "codex-sub");
    assert_eq!(
        a.runners,
        vec![w.runner.clone()],
        "pinned to the one runner"
    );
    assert_eq!(a.cap, 1, "one session at a time: the auth.json lock");
    let mut conn = w.core.app.pool.acquire().await.unwrap();
    let b = bound::of(&mut conn, a.id).await.unwrap().unwrap();
    assert_eq!(
        (b.runner.as_str(), b.home.as_str()),
        (w.runner.as_str(), l.id.as_str())
    );
    // The cap cannot be lifted: two sessions would refresh the same auth.json.
    let off = accounts::set_cap(
        &w.core.app.pool,
        a.id,
        0,
        "d",
        AuditActor::System,
        "2026-01-01T00:00:00Z",
    )
    .await;
    assert_eq!(refusal(off).0, "bad_request");
    // Nothing secret exists to leak, and the broker holds only the marker.
    let value: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&w.core.app.pool)
        .await
        .unwrap();
    assert!(value.iter().all(|d| !d.contains("sk-")));
}

#[tokio::test]
async fn a_failed_runner_ends_the_login_and_makes_no_account() {
    let mut w = up("bound-fail", true).await;
    let (l, _) = to_open_url(&mut w, "codex-bad").await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::LoginWait(_)));
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginResult(LoginResult {
                login_id: l.id.clone(),
                token: None,
                error: Some("codex exited with code 1 before the sign-in finished".to_owned()),
                done: false,
            })),
        )
        .await;
    let f = until(&w, &l.id, "failed").await;
    assert!(f.reason.unwrap().contains("exited with code 1"));
    assert_eq!(accounts::list(&w.core.app.pool).await.unwrap().len(), 0);
}

#[tokio::test]
async fn a_runner_without_the_bound_login_is_not_picked_and_a_foreign_page_or_code_is_refused() {
    let w = up("bound-nocap", false).await;
    let r = login::start(&w.core.app, &w.who, "codex-sub", "x", None).await;
    assert_eq!(refusal(r).0, "no_runner");

    let mut w = up("bound-badurl", true).await;
    let l = login::start(&w.core.app, &w.who, "codex-sub", "y", None)
        .await
        .unwrap();
    let (stream, _) = command(&mut w.fake).await;
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginUrl(LoginUrl {
                login_id: l.id.clone(),
                url: "https://evil.example.com/codex/device".to_owned(),
                code: Some(DEVICE_CODE.to_owned()),
            })),
        )
        .await;
    until(&w, &l.id, "failed").await;
}

#[tokio::test]
async fn an_opencode_login_is_guided_through_a_screen_and_typed_lines_and_stays_on_its_runner() {
    let mut w = up("bound-guided", true).await;
    let l = login::start(&w.core.app, &w.who, "opencode-sub", "oc", None)
        .await
        .unwrap();
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::LoginStart(st) = cmd else {
        panic!("{cmd:?}")
    };
    assert_eq!(
        (st.harness.as_str(), st.home.as_deref()),
        ("opencode", Some(l.id.as_str()))
    );
    // The CLI asked a question first: no page yet is a valid hand-over for a guided login.
    w.fake
        .send(
            stream,
            Body::Result(Reply::LoginUrl(LoginUrl {
                login_id: l.id.clone(),
                url: String::new(),
                code: None,
            })),
        )
        .await;
    let open = until(&w, &l.id, "open_url").await;
    assert_eq!(open.url, None);
    let (_wait_stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::LoginWait(_)));

    // The screen is read from the runner, redacted again, and a foreign page or a bad code dropped.
    let screen = login::screen(&w.core.app, &w.who, &l.id);
    let respond = async {
        let (st, c) = command(&mut w.fake).await;
        assert!(matches!(c, Command::LoginScreen(_)));
        w.fake
            .send(
                st,
                Body::Result(Reply::LoginScreen(LoginScreen {
                    login_id: l.id.clone(),
                    lines: vec![
                        "Select provider".to_owned(),
                        "key sk-proj-abcdefghijklmnopqrstuvwxyz0123456789".to_owned(),
                    ],
                    url: Some("https://evil.example.com/login".to_owned()),
                    code: Some("lower-case".to_owned()),
                })),
            )
            .await;
    };
    let (s, ()) = tokio::join!(screen, respond);
    let s = s.unwrap();
    assert_eq!((s.url, s.code), (None, None));
    assert!(
        s.lines.iter().all(|x| !x.contains("sk-proj-abcdefghij")),
        "{:?}",
        s.lines
    );

    // One typed line goes to the runner, once, and the Debug of it hides the text.
    let input = login::input(
        &w.core.app,
        &w.who,
        &l.id,
        zeroize::Zeroizing::new("GitHub".to_owned()),
    );
    let respond = async {
        let (st, c) = command(&mut w.fake).await;
        let Command::LoginInput(i) = c else {
            panic!("{c:?}")
        };
        assert_eq!(i.text, "GitHub");
        assert!(!format!("{i:?}").contains("GitHub"));
        w.fake
            .send(
                st,
                Body::Result(Reply::LoginResult(LoginResult {
                    login_id: i.login_id.clone(),
                    token: None,
                    error: None,
                    done: false,
                })),
            )
            .await;
    };
    let (r, ()) = tokio::join!(input, respond);
    r.unwrap();
    let (code, _) = refusal(
        login::input(
            &w.core.app,
            &w.who,
            &l.id,
            zeroize::Zeroizing::new("a\nb".to_owned()),
        )
        .await,
    );
    assert_eq!(code, "bad_request");
}

#[tokio::test]
async fn a_codex_login_has_no_screen_and_takes_no_typed_line() {
    let mut w = up("bound-codex-noscreen", true).await;
    let (l, _) = to_open_url(&mut w, "codex-x").await;
    let (c, _) = refusal(
        login::input(
            &w.core.app,
            &w.who,
            &l.id,
            zeroize::Zeroizing::new("x".to_owned()),
        )
        .await,
    );
    assert_eq!(c, "bad_request");
    assert_eq!(
        refusal(login::screen(&w.core.app, &w.who, &l.id).await).0,
        "bad_request"
    );
}
