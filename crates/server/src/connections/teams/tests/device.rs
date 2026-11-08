//! "Sign in with Microsoft": the device code flow's states (pending, slow down, expired, declined,
//! granted), what Core will show a person, the tenant it pins, and an app that is not set up.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::*;
use crate::connections::teams::{DeviceError, Pending, Step, TeamsApp, unpack};

fn code_body() -> Value {
    json!({"device_code": "GMMhmHCXhWEzkobqIHGG_EnNYYsAkukHspeYUk9E8", "user_code": "LM4FXGDPW",
        "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900, "interval": 5,
        "message": "To sign in, use a web browser to open https://evil.test and enter LM4FXGDPW"})
}

async fn started(f: &Fx) -> (crate::connections::github::device::Prompt, Pending) {
    f.fake.reply("devicecode", Reply::ok(code_body()));
    f.teams.device_start(None, Instant::now()).await.unwrap()
}

fn tokens(tid: &str) -> Value {
    json!({"token_type": "Bearer", "scope": SCOPES, "expires_in": 3599,
        "access_token": ACCESS, "refresh_token": REFRESH, "id_token": id_token(CLIENT, tid)})
}

/// A poll `secs` after the start (the interval is respected, so time is passed in).
async fn poll(f: &Fx, p: &mut Pending, at: Instant) -> Step {
    p.poll(&f.teams, at, NOW).await
}

#[tokio::test]
async fn start_shows_the_code_and_microsofts_own_page_never_its_message() {
    let f = fx(true).await;
    let (prompt, _p) = started(&f).await;
    assert_eq!(prompt.user_code, "LM4FXGDPW");
    assert_eq!(prompt.verification_uri, "https://microsoft.com/devicelogin");
    assert_eq!((prompt.interval, prompt.expires_in), (5, 900));
    let text = serde_json::to_string(&prompt).unwrap();
    assert!(
        !text.contains("GMMhm") && !text.contains("evil.test"),
        "{text}"
    );
    let sent = f.fake.last("devicecode").unwrap();
    assert_eq!(sent.params["client_id"], CLIENT);
    assert_eq!(sent.params["scope"], SCOPES);
    assert!(
        sent.path.starts_with("/organizations/oauth2/v2.0/"),
        "{}",
        sent.path
    );
    assert_eq!(
        f.fake.bad(),
        0,
        "a public client: no secret, no Authorization"
    );
}

#[tokio::test]
async fn a_reply_with_an_address_or_code_core_would_not_show_is_refused() {
    let f = fx(true).await;
    for uri in [
        "https://evil.test/devicelogin",
        "http://microsoft.com/devicelogin",
        "https://microsoft.com.evil.test/devicelogin",
        "https://evil.test/@microsoft.com",
        "https://user\u{40}microsoft.com/devicelogin",
        "https://microsoft.com:8443/devicelogin",
        "https://microsoft.com/devicelogin?x=1",
        "https://microsoft.com/devicelogin#x",
        "javascript:alert(1)",
        "microsoft.com/devicelogin",
        "",
    ] {
        let mut b = code_body();
        b["verification_uri"] = json!(uri);
        f.fake.reply("devicecode", Reply::ok(b));
        let r = f.teams.device_start(None, Instant::now()).await.map(|_| ());
        assert_eq!(r.unwrap_err(), DeviceError::BadReply, "{uri}");
    }
    for (k, v) in [
        ("user_code", json!("<script>")),
        ("user_code", json!("")),
        ("user_code", json!("A".repeat(40))),
        ("device_code", json!("")),
        ("device_code", json!("has space")),
        ("expires_in", json!(0)),
        ("expires_in", json!("900")),
    ] {
        let mut b = code_body();
        b[k] = v;
        f.fake.reply("devicecode", Reply::ok(b));
        let r = f.teams.device_start(None, Instant::now()).await.map(|_| ());
        assert_eq!(r.unwrap_err(), DeviceError::BadReply, "{k}");
    }
    f.fake.reply("devicecode", Reply::ok(json!({})));
    assert_eq!(
        f.teams
            .device_start(None, Instant::now())
            .await
            .map(|_| ())
            .unwrap_err(),
        DeviceError::BadReply
    );
}

#[tokio::test]
async fn pending_slow_down_expired_and_declined() {
    let f = fx(true).await;
    let (_, mut p) = started(&f).await;
    let t0 = Instant::now();
    f.fake
        .reply("token", Reply::entra(400, "authorization_pending"));
    // Before the interval is up: no request at all.
    assert!(matches!(poll(&f, &mut p, t0).await, Step::Wait { secs } if secs >= 1));
    assert_eq!(f.fake.count("token"), 0);
    assert!(matches!(
        poll(&f, &mut p, t0 + Duration::from_secs(6)).await,
        Step::Wait { secs: 5 }
    ));
    assert_eq!(f.fake.count("token"), 1);
    // slow_down adds five seconds to the interval, and it is kept.
    f.fake.reply("token", Reply::entra(400, "slow_down"));
    assert!(matches!(
        poll(&f, &mut p, t0 + Duration::from_secs(12)).await,
        Step::Wait { secs: 10 }
    ));
    assert!(matches!(
        poll(&f, &mut p, t0 + Duration::from_secs(20)).await,
        Step::Wait { .. }
    ));
    assert_eq!(f.fake.count("token"), 2, "the longer interval is respected");
    f.fake
        .reply("token", Reply::entra(400, "authorization_declined"));
    assert!(matches!(
        poll(&f, &mut p, t0 + Duration::from_secs(30)).await,
        Step::Denied
    ));
    assert!(matches!(
        poll(&f, &mut p, t0 + Duration::from_secs(60)).await,
        Step::Closed
    ));
    assert_eq!(f.fake.count("token"), 3, "an ended flow asks nothing more");
    // expired_token from Microsoft, and the code's own end.
    let (_, mut q) = started(&f).await;
    f.fake.reply("token", Reply::entra(400, "expired_token"));
    assert!(matches!(
        poll(&f, &mut q, Instant::now() + Duration::from_secs(6)).await,
        Step::Expired
    ));
    let (_, mut r) = started(&f).await;
    let n = f.fake.count("token");
    assert!(matches!(
        poll(&f, &mut r, Instant::now() + Duration::from_secs(901)).await,
        Step::Expired
    ));
    assert_eq!(f.fake.count("token"), n);
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_grant_becomes_a_credential_pinned_to_the_tenant_of_its_id_token() {
    let f = fx(true).await;
    let (_, mut p) = started(&f).await;
    f.fake.reply("token", Reply::ok(tokens(TENANT)));
    let Step::Granted(g) = poll(&f, &mut p, Instant::now() + Duration::from_secs(6)).await else {
        panic!("not granted");
    };
    assert_eq!(g.tenant, TENANT);
    let cred = unpack(&g.material).unwrap();
    assert_eq!((cred.tenant(), cred.refresh()), (TENANT, REFRESH));
    assert_eq!(g.material.expires_at.as_deref(), Some(at(3599).as_str()));
    let sent = f.fake.last("token").unwrap();
    assert_eq!(
        sent.params["grant_type"],
        "urn:ietf:params:oauth:grant-type:device_code"
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_grant_that_is_not_usable_is_refused() {
    let f = fx(true).await;
    let t = || Instant::now() + Duration::from_secs(6);
    let good = tokens(TENANT);
    let mut no_refresh = good.clone();
    no_refresh.as_object_mut().unwrap().remove("refresh_token");
    let mut no_id = good.clone();
    no_id.as_object_mut().unwrap().remove("id_token");
    let mut other_aud = good.clone();
    other_aud["id_token"] = json!(id_token("another-client", TENANT));
    let mut consumer = good.clone();
    consumer["id_token"] = json!(id_token(CLIENT, super::super::cred::CONSUMER_TENANT));
    let mut no_access = good.clone();
    no_access.as_object_mut().unwrap().remove("access_token");
    let mut short = good.clone();
    short["access_token"] = json!("short");
    for body in [no_refresh, no_id, other_aud, consumer, no_access, short] {
        let (_, mut p) = started(&f).await;
        f.fake.reply("token", Reply::ok(body.clone()));
        let s = poll(&f, &mut p, t()).await;
        assert!(matches!(s, Step::Failed(DeviceError::BadReply)), "{body}");
    }
}

#[tokio::test]
async fn an_app_limited_to_one_tenant_takes_no_grant_from_another() {
    let f = fx(false).await;
    f.teams
        .set_app(Some(TeamsApp::new(CLIENT, TENANT).unwrap()));
    let (_, mut p) = started(&f).await;
    assert!(
        f.fake
            .last("devicecode")
            .unwrap()
            .path
            .starts_with(&format!("/{TENANT}/"))
    );
    f.fake.reply("token", Reply::ok(tokens(OTHER_TENANT)));
    let s = poll(&f, &mut p, Instant::now() + Duration::from_secs(6)).await;
    assert!(matches!(s, Step::Failed(DeviceError::WrongTenant)));
    // A re-sign-in is started at the connection's own tenant, whatever the app's default.
    let g = fx(true).await;
    g.fake.reply("devicecode", Reply::ok(code_body()));
    g.teams
        .device_start(Some(TENANT), Instant::now())
        .await
        .unwrap();
    assert!(
        g.fake
            .last("devicecode")
            .unwrap()
            .path
            .starts_with(&format!("/{TENANT}/"))
    );
    // A hint that is not a tenant id (a name, `common`) is not put in a path.
    for hint in ["common", "contoso.onmicrosoft.com", "../x", "organizations"] {
        g.teams
            .device_start(Some(hint), Instant::now())
            .await
            .unwrap();
        assert!(
            g.fake
                .last("devicecode")
                .unwrap()
                .path
                .starts_with("/organizations/"),
            "{hint}"
        );
    }
    assert_eq!(g.fake.bad(), 0);
}

#[tokio::test]
async fn refusals_and_failures_of_the_token_endpoint() {
    let f = fx(true).await;
    let t = || Instant::now() + Duration::from_secs(6);
    for (reply, want) in [
        (
            Reply::entra(400, "invalid_client"),
            Some(DeviceError::Rejected),
        ),
        (
            Reply::entra(400, "unauthorized_client"),
            Some(DeviceError::Rejected),
        ),
        (
            Reply::entra(400, "bad_verification_code"),
            Some(DeviceError::Rejected),
        ),
        (
            Reply::entra(400, "something_else"),
            Some(DeviceError::BadReply),
        ),
        (Reply::http(400, json!(null)), Some(DeviceError::BadReply)),
        (Reply::http(429, json!({})), None),
        (Reply::http(503, json!({})), None),
    ] {
        let (_, mut p) = started(&f).await;
        f.fake.reply("token", reply.clone());
        match (poll(&f, &mut p, t()).await, want) {
            (Step::Failed(e), Some(w)) => assert_eq!(e, w, "{}", reply.status),
            (Step::Retry, None) => {}
            (s, w) => panic!(
                "{} {}: {:?}",
                reply.status,
                reply.body,
                (matches!(s, Step::Retry), w)
            ),
        }
    }
}

#[tokio::test]
async fn the_start_is_refused_without_an_app_or_when_microsoft_refuses_the_app() {
    let f = fx(false).await;
    f.fake.reply("devicecode", Reply::ok(code_body()));
    let r = f.teams.device_start(None, Instant::now()).await.map(|_| ());
    assert_eq!(r.unwrap_err(), DeviceError::NotConfigured);
    assert_eq!(f.fake.count("devicecode"), 0, "no request without an app");
    let g = fx(true).await;
    for (reply, want) in [
        (Reply::entra(400, "invalid_client"), DeviceError::Rejected),
        (
            Reply::entra(400, "unauthorized_client"),
            DeviceError::Rejected,
        ),
        (Reply::entra(400, "invalid_scope"), DeviceError::Rejected),
        (Reply::http(503, json!({})), DeviceError::Unreachable),
        (Reply::http(404, json!({})), DeviceError::Unreachable),
    ] {
        g.fake.reply("devicecode", reply);
        let r = g.teams.device_start(None, Instant::now()).await.map(|_| ());
        assert_eq!(r.unwrap_err(), want);
    }
}

#[tokio::test]
async fn the_app_takes_a_client_id_and_a_tenant_and_nothing_else() {
    assert!(TeamsApp::new(CLIENT, "organizations").is_some());
    assert!(TeamsApp::new(CLIENT, TENANT).is_some());
    for tenant in [
        "common",
        "consumers",
        "contoso.onmicrosoft.com",
        "../x",
        "",
        "9188040d-6c67-4c5b-b112-36a304b66dad",
        "2432B57B-0ABD-43DB-AA7B-16EADD115D34",
        "organizations/x",
    ] {
        assert!(TeamsApp::new(CLIENT, tenant).is_none(), "{tenant}");
    }
    let long = "a".repeat(65);
    for id in ["", " ", "has space", "a/b", "x?y", long.as_str()] {
        assert!(TeamsApp::new(id, "organizations").is_none(), "{id:?}");
    }
    let f = fx(false).await;
    assert!(!f.teams.app_configured());
    assert!(
        f.teams.set_app(TeamsApp::new(CLIENT, "organizations")),
        "a change"
    );
    assert!(
        !f.teams.set_app(TeamsApp::new(CLIENT, "organizations")),
        "no change"
    );
    assert!(f.teams.set_app(None));
    assert!(!format!("{:?}", TeamsApp::new(CLIENT, "organizations")).contains(CLIENT));
}
