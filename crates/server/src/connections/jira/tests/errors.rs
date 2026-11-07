//! Where a call may go, how an upstream answer maps, and that no secret escapes.

use reqwest::Method;
use serde_json::{Value, json};

use super::*;
use std::time::Duration;

use crate::connections::adapter::{Registry, TestError};
use crate::connections::jira::http::Http;
use crate::connections::jira::{CallError, Limit};
use crate::store::connections::verdict;

async fn get(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    let args = json!({"key": "ABC-1"});
    f.jira
        .call(&f.cx(NOW), c, &Limit::any(), "jira.get_issue", &args)
        .await
}

fn issue_path() -> String {
    format!("GET {}", site_path("/issue/ABC-1"))
}

#[test]
fn production_urls_are_exactly_the_two_hosts_and_the_validated_site() {
    let jira = Jira::new(None);
    let o = cred::unpack(&oauth(ACCESS, REFRESH, 60)).unwrap();
    let want = format!("https://api.atlassian.com/ex/jira/{CLOUD}/rest/api/3/myself");
    assert_eq!(jira.url(&o, "/myself"), want);
    let b = cred::unpack(&basic()).unwrap();
    assert_eq!(
        jira.url(&b, "/myself"),
        "https://acme.atlassian.net/rest/api/3/myself"
    );
}

#[tokio::test]
async fn the_client_refuses_every_other_host_before_touching_the_network() {
    let jira = Jira::new(None);
    let at = '@';
    let fixed = [
        "https://api.atlassian.com.evil.test/x".to_owned(),
        "https://evil.api.atlassian.com/x".to_owned(),
        "https://xapi.atlassian.com/x".to_owned(),
        "https://api.atlassian.com:8443/x".to_owned(),
        "http://api.atlassian.com/x".to_owned(),
        format!("https://api.atlassian.com{at}evil.test/x"),
        format!("https://user:pw{at}api.atlassian.com/x"),
        "https://api.atlassian.com.:443/x".to_owned(),
        "https://127.0.0.1/x".to_owned(),
        "https://[::1]/x".to_owned(),
        "https://localhost/x".to_owned(),
        "https://acme.atlassian.net/x".to_owned(),
        "https://atlassian.net/x".to_owned(),
    ];
    for url in fixed {
        let r = jira.http.send(None, Method::GET, &url, None, None).await;
        assert!(
            matches!(r, Err(CallError::Refused(_))),
            "{url} -> {:?}",
            r.map(|r| r.status)
        );
    }
    // A token-auth site gets a policy of its own host: neighbours and tricks are refused.
    let site = Some("acme.atlassian.net");
    for url in [
        "https://acme.atlassian.net.evil.test/x",
        "https://other.atlassian.net/x",
        "https://evil.atlassian.net/x",
        "https://api.atlassian.com/x",
        "https://acme.atlassian.net:444/x",
        "http://acme.atlassian.net/x",
    ] {
        let r = jira.http.send(site, Method::GET, url, None, None).await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{url}");
    }
}

#[tokio::test]
async fn statuses_map_to_the_right_errors_and_health_signals() {
    let f = fx(false).await;
    let c = f.basic().await;
    let key = issue_path();
    let cases: [(u16, CallError); 6] = [
        (401, CallError::AuthFailed),
        (403, CallError::Forbidden),
        (404, CallError::NotFound),
        (500, CallError::Upstream(500)),
        (503, CallError::Upstream(503)),
        (409, CallError::BadRequest(409)),
    ];
    for (status, want) in cases {
        f.fake
            .reply(&key, status, json!({"errorMessages": ["secret detail"]}));
        let got = get(&f, &c).await.unwrap_err();
        assert_eq!(got, want, "{status}");
        assert!(
            !got.to_string().contains("secret detail"),
            "an upstream message is not repeated"
        );
    }
    f.fake.on(&key, |_| {
        Reply::json(429, json!({})).header("Retry-After", "120")
    });
    let got = get(&f, &c).await.unwrap_err();
    assert_eq!(
        got,
        CallError::RateLimited {
            retry_after: Some(120)
        }
    );
    assert_eq!(got.health().unwrap().1, Some(120));
    f.fake.on(&key, |_| {
        Reply::json(429, json!({})).header("Retry-After", "999999999")
    });
    assert_eq!(
        get(&f, &c).await.unwrap_err(),
        CallError::RateLimited {
            retry_after: Some(86_400)
        }
    );
    f.fake.on(&key, |_| {
        Reply::json(429, json!({})).header("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
    });
    assert_eq!(
        get(&f, &c).await.unwrap_err(),
        CallError::RateLimited { retry_after: None }
    );
    for (e, signal) in [
        (CallError::Forbidden, false),
        (CallError::NotFound, false),
        (CallError::BadRequest(400), false),
        (CallError::Refused("x".into()), false),
        (CallError::AuthFailed, true),
        (CallError::Upstream(502), true),
        (CallError::Network, true),
        (CallError::TooLarge, false),
        (CallError::TimedOut, false),
        (CallError::Broken, false),
    ] {
        assert_eq!(e.health().is_some(), signal, "{e}");
    }
}

#[tokio::test]
async fn a_redirect_is_the_answer_never_followed_and_a_huge_answer_is_refused() {
    let f = fx(false).await;
    let c = f.basic().await;
    let key = issue_path();
    f.fake.on(&key, |_| {
        Reply::json(302, json!({})).header("Location", "http://127.0.0.1:1/steal")
    });
    assert_eq!(get(&f, &c).await.unwrap_err(), CallError::Upstream(302));
    assert_eq!(f.fake.count(&key), 1);
    let mut big = Reply::json(200, Value::Null);
    big.raw = Some(vec![b' '; 5 * 1024 * 1024]);
    f.fake.on(&key, move |_| big.clone());
    let e = get(&f, &c).await.unwrap_err();
    assert_eq!(e, CallError::TooLarge);
    assert!(
        e.health().is_none(),
        "a long answer says nothing about the service's health"
    );
    let mut junk = Reply::json(200, Value::Null);
    junk.raw = Some(b"<html>".to_vec());
    f.fake.on(&key, move |_| junk.clone());
    assert_eq!(get(&f, &c).await.unwrap_err(), CallError::Upstream(200));
}

#[tokio::test]
async fn a_credential_test_reads_the_identity_and_only_a_sure_401_rejects() {
    let f = fx(false).await;
    let c = f.basic().await;
    let key = format!("GET {}", site_path("/myself"));
    f.fake.reply(
        &key,
        200,
        json!({"accountId": "5b10ac8d", "displayName": "Ann\u{7}Lee"}),
    );
    let who = f.cx(NOW).who;
    let done = verdict::run_test(&f.pool, &f.sealer, &f.reg, c.id, who)
        .await
        .unwrap();
    assert_eq!(
        done.identity.as_deref(),
        Some("5b10ac8d at https://acme.atlassian.net")
    );
    let me = f
        .jira
        .myself(&cred::unpack(&basic()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        (me.account_id.as_str(), me.display_name.as_str()),
        ("5b10ac8d", "AnnLee")
    );
    let test = |m: Material| {
        let jira = f.jira.clone();
        async move { jira.test(&m).await.map(|i| i.subject) }
    };
    f.fake.reply(&key, 401, json!({}));
    assert_eq!(test(basic()).await, Err(TestError::Rejected));
    // An OAuth token that has already expired being refused says nothing about the credential.
    let oauth_key = "GET /me".to_owned();
    f.fake.reply(&oauth_key, 401, json!({}));
    assert_eq!(
        test(oauth(ACCESS, REFRESH, -3600 * 24 * 365 * 10)).await,
        Err(TestError::Inconclusive)
    );
    assert_eq!(
        test(oauth(ACCESS, REFRESH, 3600 * 24 * 365 * 30)).await,
        Err(TestError::Rejected)
    );
    for status in [403, 429, 500, 404] {
        f.fake.reply(&key, status, json!({}));
        assert_eq!(
            test(basic()).await,
            Err(TestError::Inconclusive),
            "{status}"
        );
    }
    f.fake.reply(&key, 200, json!({"displayName": "no id"}));
    assert_eq!(test(basic()).await, Err(TestError::Inconclusive));
    let junk = Material::new("not a jira envelope", None, None).unwrap();
    assert_eq!(test(junk).await, Err(TestError::Inconclusive));
    let evil = Material::new(
        "token|acme.atlassian.net.evil.test|ann@example.com|tok",
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        test(evil).await,
        Err(TestError::Inconclusive),
        "a sealed host is validated again"
    );
    assert_eq!(f.fake.count(&oauth_key), 2);
}

#[tokio::test]
async fn no_secret_appears_in_an_error_a_debug_print_or_an_audit_row() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let key = format!("GET {}", oauth_path("/issue/ABC-1"));
    f.fake
        .reply(&key, 401, json!({"message": format!("bad token {ACCESS}")}));
    let args = json!({"key": "ABC-1"});
    let err = f
        .jira
        .call(&f.cx(NOW), &c, &Limit::any(), "jira.get_issue", &args)
        .await
        .unwrap_err();
    assert!(served.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    let b = f.basic_named("b2").await;
    f.fake.reply(
        &format!("GET {}", site_path("/issue/ABC-1")),
        500,
        json!({"m": API_TOKEN}),
    );
    let err2 = f
        .jira
        .call(&f.cx(NOW), &b, &Limit::any(), "jira.get_issue", &args)
        .await
        .unwrap_err();
    let m = oauth(ACCESS, REFRESH, 10);
    let flows = f.jira.start(1, REDIRECT, None).unwrap();
    let texts = [
        format!("{err} {err:?} {err2} {err2:?}"),
        format!("{m:?} {m} {:?} {:?}", cred::unpack(&m).unwrap(), f.jira.app),
        format!("{c:?} {b:?}"),
        f.audit_text().await,
        flows.authorize_url.clone(),
    ];
    for t in texts {
        for secret in [
            ACCESS,
            REFRESH,
            API_TOKEN,
            CLIENT_SECRET,
            "acc2-7f3a",
            "ref2-91c4",
            EMAIL,
        ] {
            assert!(!t.contains(secret), "{secret} leaked in {t}");
        }
    }
}

#[tokio::test]
async fn a_slow_answer_is_a_timeout_with_no_health_signal() {
    let f = fx(false).await;
    let c = f.basic().await;
    let http = Http::loopback(f.addr).with_timeout(Duration::from_millis(300));
    let jira = Jira::with(http, None);
    f.fake
        .on(&issue_path(), |_| Reply::json(200, json!({})).delayed(1500));
    let args = json!({"key": "ABC-1"});
    let e = jira
        .call(&f.cx(NOW), &c, &Limit::any(), "jira.get_issue", &args)
        .await
        .unwrap_err();
    assert_eq!(e, CallError::TimedOut);
    assert!(e.health().is_none());
}

#[tokio::test]
async fn only_a_refused_connection_is_unreachable() {
    let f = fx(false).await;
    let c = f.basic().await;
    // Nothing listens on this port: the connect fails.
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let jira = Jira::with(Http::loopback(dead), None);
    let args = json!({"key": "ABC-1"});
    let e = jira
        .call(&f.cx(NOW), &c, &Limit::any(), "jira.get_issue", &args)
        .await
        .unwrap_err();
    assert_eq!(e, CallError::Network);
    assert!(e.health().is_some());
}

#[tokio::test]
async fn the_registry_holds_the_one_instance_the_server_built() {
    let f = fx(true).await;
    let c = f.basic().await;
    f.fake.reply(
        &format!("GET {}", site_path("/myself")),
        200,
        json!({"accountId": "5b10ac8d", "displayName": "Ann"}),
    );
    // A registry built for this instance runs its test through it (the fake is only reachable
    // there); a default `builtin()` has its own, with no app and the real hosts.
    let reg = Registry::builtin_with(f.jira.clone());
    let who = f.cx(NOW).who;
    verdict::run_test(&f.pool, &f.sealer, &reg, c.id, who)
        .await
        .unwrap();
    assert_eq!(f.fake.count(&format!("GET {}", site_path("/myself"))), 1);
    let d = reg.get("jira").unwrap().descriptor();
    assert!(d.is_self_limited("jira.search_issues") && d.is_self_limited("jira.list_projects"));
    assert!(!d.is_self_limited("jira.get_issue") && !d.is_self_limited("jira.create_issue"));
    // The same instance starts a sign-in that the same instance finishes: it holds the state.
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    assert!(f.jira.flows.lock().unwrap().contains_key(&s.state));
    assert!(Registry::builtin().get("jira").is_some());
}
