use std::time::{Duration, Instant};

use super::fake::Fake;
use crate::connections::github::Outcome;
use crate::connections::github::device::{self, DeviceError, Step};

const CODE: &str = "dev-code-xyz-31337";
const TOKEN: &str = "gho_testtoken0000";
const START: &str = r#"{"device_code":"dev-code-xyz-31337","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#;

fn secs(t0: Instant, n: u64) -> Instant {
    t0 + Duration::from_secs(n)
}

#[tokio::test]
async fn the_happy_path_shows_a_code_waits_and_stores_a_token() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let t0 = Instant::now();
    fake.push(200, &[], START);
    let (prompt, mut pending) = device::start(&t, " Iv1.abc123 ", t0).await.unwrap();
    assert_eq!(prompt.user_code, "WDJB-MJHT");
    assert_eq!(prompt.verification_uri, "https://github.com/login/device");
    assert_eq!((prompt.interval, prompt.expires_in), (5, 900));
    let s = fake.seen();
    assert_eq!(
        (s[0].method.as_str(), s[0].path.as_str()),
        ("POST", "/login/device/code")
    );
    assert_eq!(s[0].body, "client_id=Iv1.abc123&scope=repo");
    assert_eq!(s[0].header("authorization"), None);
    assert_eq!(s[0].header("accept"), Some("application/json"));

    // Before the interval is up: no request.
    assert!(matches!(
        pending.poll(&t, "Iv1.abc123", secs(t0, 2)).await,
        Step::Wait { secs: 3 }
    ));
    assert_eq!(fake.seen().len(), 1);
    fake.push(200, &[], r#"{"error":"authorization_pending"}"#);
    assert!(matches!(
        pending.poll(&t, "Iv1.abc123", secs(t0, 5)).await,
        Step::Wait { secs: 5 }
    ));
    let s = fake.seen();
    assert_eq!(s[1].path, "/login/oauth/access_token");
    assert_eq!(
        s[1].body,
        format!(
            "client_id=Iv1.abc123&device_code={CODE}&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        )
    );
    // Asked again too soon: held back, no request.
    assert!(matches!(
        pending.poll(&t, "Iv1.abc123", secs(t0, 6)).await,
        Step::Wait { .. }
    ));
    assert_eq!(fake.seen().len(), 2);

    fake.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{TOKEN}","token_type":"bearer","scope":"repo"}}"#),
    );
    let Step::Granted(g) = pending.poll(&t, "Iv1.abc123", secs(t0, 10)).await else {
        panic!("not granted");
    };
    assert_eq!(g.material.access(), TOKEN);
    assert_eq!(
        (
            g.material.refresh(),
            g.material.expires_at.as_deref(),
            g.scopes.as_str()
        ),
        (None, None, "repo")
    );
}

#[tokio::test]
async fn slow_down_stretches_the_interval() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let t0 = Instant::now();
    fake.push(200, &[], START);
    let (_, mut p) = device::start(&t, "cid", t0).await.unwrap();
    fake.push(200, &[], r#"{"error":"slow_down","interval":10}"#);
    assert!(matches!(
        p.poll(&t, "cid", secs(t0, 5)).await,
        Step::Wait { secs: 10 }
    ));
    // 9 s later is still too soon; the new interval is 10 s.
    assert!(matches!(
        p.poll(&t, "cid", secs(t0, 14)).await,
        Step::Wait { secs: 1 }
    ));
    assert_eq!(fake.seen().len(), 2);
    // A slow_down without an interval adds five seconds.
    fake.push(200, &[], r#"{"error":"slow_down"}"#);
    assert!(matches!(
        p.poll(&t, "cid", secs(t0, 15)).await,
        Step::Wait { secs: 15 }
    ));
    fake.push(200, &[], &format!(r#"{{"access_token":"{TOKEN}"}}"#));
    assert!(matches!(
        p.poll(&t, "cid", secs(t0, 30)).await,
        Step::Granted(_)
    ));
}

#[tokio::test]
async fn expired_denied_and_refused_end_the_flow() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let t0 = Instant::now();
    for (reply, want) in [
        (r#"{"error":"expired_token"}"#, "expired"),
        (r#"{"error":"access_denied"}"#, "denied"),
        (r#"{"error":"incorrect_device_code"}"#, "rejected"),
    ] {
        fake.push(200, &[], START);
        let (_, mut p) = device::start(&t, "cid", t0).await.unwrap();
        fake.push(200, &[], reply);
        let got = match p.poll(&t, "cid", secs(t0, 5)).await {
            Step::Expired => "expired",
            Step::Denied => "denied",
            Step::Failed(DeviceError::Rejected) => "rejected",
            other => panic!("{other:?}"),
        };
        assert_eq!(got, want);
    }
    // Past the code's own life: expired with no request.
    fake.push(200, &[], START);
    let (_, mut p) = device::start(&t, "cid", t0).await.unwrap();
    let before = fake.seen().len();
    assert!(matches!(
        p.poll(&t, "cid", secs(t0, 901)).await,
        Step::Expired
    ));
    assert_eq!(fake.seen().len(), before);
}

#[tokio::test]
async fn an_unset_client_id_refuses_before_any_request() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let long = "x".repeat(65);
    for id in ["", "  ", "a b", "a&b=c", long.as_str()] {
        let e = device::start(&t, id, Instant::now()).await.unwrap_err();
        assert_eq!(e, DeviceError::NotConfigured, "{id:?}");
        assert_eq!(e.code(), "not_configured");
    }
    assert!(fake.seen().is_empty());
    fake.push(200, &[], r#"{"error":"device_flow_disabled"}"#);
    let e = device::start(&t, "cid", Instant::now()).await.unwrap_err();
    assert_eq!(e, DeviceError::Rejected);
}

#[tokio::test]
async fn a_start_reply_is_checked_before_a_person_is_sent_anywhere() {
    let fake = Fake::start().await;
    let t = fake.transport();
    for uri in [
        "https://evil.example/login/device",
        "https://github.com.evil.example/x",
        "http://github.com/login/device",
        "https://github.com/@evil",
    ] {
        let body = START.replace("https://github.com/login/device", uri);
        fake.push(200, &[], &body);
        let e = device::start(&t, "cid", Instant::now()).await.unwrap_err();
        assert_eq!(e, DeviceError::BadReply, "{uri}");
    }
    fake.push(200, &[], r#"{"user_code":"AB-CD"}"#);
    assert_eq!(
        device::start(&t, "cid", Instant::now()).await.unwrap_err(),
        DeviceError::BadReply
    );
    fake.push(502, &[], "");
    let e = device::start(&t, "cid", Instant::now()).await.unwrap_err();
    assert_eq!(e, DeviceError::Net(Outcome::ServerError));
    assert!(e.transient());
}

#[tokio::test]
async fn an_expiring_token_keeps_its_refresh_token_and_expiry() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let t0 = Instant::now();
    fake.push(200, &[], START);
    let (_, mut p) = device::start(&t, "cid", t0).await.unwrap();
    fake.push(200, &[], &format!(r#"{{"access_token":"{TOKEN}","refresh_token":"ghr_refresh0000","expires_in":28800,"scope":""}}"#));
    let Step::Granted(g) = p.poll(&t, "cid", secs(t0, 5)).await else {
        panic!("not granted");
    };
    assert_eq!(g.material.refresh(), Some("ghr_refresh0000"));
    assert!(g.material.expires_at.is_some());
    // A poll that fails on the wire is transient, and says so in plain words.
    fake.push(200, &[], START);
    let (_, mut p) = device::start(&t, "cid", t0).await.unwrap();
    fake.push(503, &[], "");
    let Step::Failed(e) = p.poll(&t, "cid", secs(t0, 5)).await else {
        panic!("not failed");
    };
    assert!(e.transient() && e.code() == "upstream");
}

#[tokio::test]
async fn nothing_secret_prints() {
    let fake = Fake::start().await;
    let t = fake.transport();
    let t0 = Instant::now();
    fake.push(200, &[], START);
    let (prompt, mut p) = device::start(&t, "cid", t0).await.unwrap();
    fake.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{TOKEN}","refresh_token":"ghr_refresh0000"}}"#),
    );
    let step = p.poll(&t, "cid", secs(t0, 5)).await;
    let all = format!("{p:?} {prompt:?} {step:?} {:#?}", DeviceError::Rejected);
    for secret in [CODE, TOKEN, "ghr_refresh0000"] {
        assert!(!all.contains(secret), "{all}");
    }
    assert!(!serde_json::to_string(&prompt).unwrap().contains(CODE));
}
