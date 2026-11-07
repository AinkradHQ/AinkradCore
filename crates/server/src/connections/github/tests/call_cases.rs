use std::sync::Arc;

use serde_json::json;

use super::fake::Fake;
use crate::connections::adapter::{KindAdapter, Registry, TestError};
use crate::connections::github::http::NetError;
use crate::connections::github::{GITHUB, Github, Outcome, Transport, build};
use crate::connections::material::Material;

const TOKEN: &str = "ghp_testtoken1234";

fn gh(fake: &Fake) -> Github {
    Github::new(Arc::new(fake.transport()))
}

fn mat() -> Material {
    Material::new(TOKEN, None, None).unwrap()
}

#[tokio::test]
async fn test_reads_the_identity_scopes_and_rate_limit() {
    let fake = Fake::start().await;
    let hdr = [
        ("x-oauth-scopes", "repo, read:user"),
        ("x-ratelimit-limit", "5000"),
        ("x-ratelimit-remaining", "4999"),
        ("x-ratelimit-reset", "1800000000"),
    ];
    fake.push(200, &hdr, r#"{"login":"octo","id":583231}"#);
    let w = gh(&fake).whoami(&mat()).await.unwrap();
    assert_eq!((w.login.as_str(), w.id), ("octo", Some(583231)));
    assert_eq!(w.scopes.as_deref(), Some("repo, read:user"));
    assert_eq!(
        (w.rate.limit, w.rate.remaining, w.rate.reset),
        (Some(5000), Some(4999), Some(1_800_000_000))
    );
    let s = &fake.seen()[0];
    assert_eq!((s.method.as_str(), s.path.as_str()), ("GET", "/user"));
    assert_eq!(s.header("authorization"), Some(&*format!("Bearer {TOKEN}")));
    assert_eq!(s.header("accept"), Some("application/vnd.github+json"));
    assert_eq!(s.header("user-agent"), Some("ainkrad-core"));
    assert!(s.header("x-github-api-version").is_some());

    fake.push(200, &[], r#"{"login":"octo","id":1}"#);
    let id = gh(&fake).test(&mat()).await.unwrap();
    assert_eq!(id.subject, "octo");
}

#[tokio::test]
async fn test_tells_a_refusal_from_no_answer() {
    let fake = Fake::start().await;
    let a = gh(&fake);
    let cases = [
        (401, vec![], Err(TestError::Rejected)),
        (500, vec![], Err(TestError::Inconclusive)),
        (
            429,
            vec![("retry-after", "30")],
            Err(TestError::Inconclusive),
        ),
        (
            403,
            vec![("x-ratelimit-remaining", "0")],
            Err(TestError::Inconclusive),
        ),
    ];
    for (status, headers, want) in cases {
        fake.push(status, &headers, "{}");
        assert_eq!(a.test(&mat()).await.map(|i| i.subject), want, "{status}");
    }
    // 200 with no login is not an identity.
    fake.push(200, &[], "{}");
    assert_eq!(
        a.test(&mat()).await.map(|i| i.subject),
        Err(TestError::Inconclusive)
    );
    // Nobody listening: inconclusive, and the error says nothing of where or what.
    let dead = Github::new(Arc::new(Transport::local("http://127.0.0.1:9")));
    assert_eq!(
        dead.test(&mat()).await.map(|i| i.subject),
        Err(TestError::Inconclusive)
    );
    let e = dead.whoami(&mat()).await.unwrap_err();
    let text = format!("{e} {e:?}");
    assert!(
        !text.contains("127.0.0.1") && !text.contains(TOKEN),
        "{text}"
    );
    assert!(matches!(
        e,
        Outcome::Net(NetError::Unreachable | NetError::Timeout)
    ));
}

#[tokio::test]
async fn an_installation_token_is_named_by_its_repositories_owner() {
    let fake = Fake::start().await;
    fake.push(
        403,
        &[],
        r#"{"message":"Resource not accessible by integration"}"#,
    );
    fake.push(
        200,
        &[],
        r#"{"total_count":1,"repositories":[{"owner":{"login":"acme","id":9}}]}"#,
    );
    let w = gh(&fake).whoami(&mat()).await.unwrap();
    assert_eq!((w.login.as_str(), w.id), ("acme", Some(9)));
    assert_eq!(fake.seen()[1].path, "/installation/repositories?per_page=1");
}

#[tokio::test]
async fn execute_sends_the_built_request_and_maps_every_failure() {
    let fake = Fake::start().await;
    let a = gh(&fake);
    let get = build(
        "github.get_issue",
        &json!({"repo": "acme/web", "number": 7}),
    )
    .unwrap();
    // The token, echoed by the upstream, is cut out of the result.
    fake.push(
        200,
        &[("x-ratelimit-remaining", "10")],
        &format!(r#"{{"title":"t","note":"{TOKEN}"}}"#),
    );
    let done = a.execute(&mat(), &get).await.unwrap();
    let body = String::from_utf8(done.body).unwrap();
    assert!(
        !body.contains(TOKEN) && body.contains("[redacted]"),
        "{body}"
    );
    assert_eq!(done.rate.remaining, Some(10));
    assert_eq!(fake.seen()[0].path, "/repos/acme/web/issues/7");

    let post = build(
        "github.create_issue",
        &json!({"repo": "acme/web", "body": {"title": "x"}}),
    )
    .unwrap();
    fake.push(201, &[], "{}");
    assert_eq!(a.execute(&mat(), &post).await.unwrap().status, 201);
    let s = &fake.seen()[1];
    assert_eq!(
        (s.method.as_str(), s.header("content-type")),
        ("POST", Some("application/json"))
    );
    assert_eq!(s.body, r#"{"title":"x"}"#);

    let reset = [("retry-after", "60"), ("x-ratelimit-reset", "1800000000")];
    let cases = vec![
        (401, vec![], "auth_failed"),
        (404, vec![], "not_found"),
        (403, vec![], "forbidden"),
        (403, reset.to_vec(), "rate_limited"),
        (422, vec![], "invalid"),
        (503, vec![], "upstream"),
    ];
    for (status, headers, code) in cases {
        fake.push(status, &headers, r#"{"message":"x"}"#);
        let e = a.execute(&mat(), &get).await.unwrap_err();
        assert_eq!(e.code(), code, "{status}");
        assert!(!format!("{e} {e:?}").contains(TOKEN));
    }
    fake.push(403, &reset, "{}");
    let Outcome::RateLimited {
        retry_after,
        reset_at,
    } = a.execute(&mat(), &get).await.unwrap_err()
    else {
        panic!("not a cooldown");
    };
    assert_eq!(retry_after, Some(60));
    assert!(reset_at.is_some());
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_a_huge_body_is_cut() {
    let fake = Fake::start().await;
    let other = Fake::start().await;
    let a = gh(&fake);
    let get = build("github.get_repo", &json!({"repo": "acme/web"})).unwrap();
    let location = format!("{}/stolen", other.base);
    fake.push(302, &[("location", location.as_str())], "");
    let e = a.execute(&mat(), &get).await.unwrap_err();
    assert_eq!(e, Outcome::Unexpected);
    assert!(other.seen().is_empty(), "the redirect was followed");
    assert_eq!(fake.seen().len(), 1);

    fake.push_bytes(200, &[], vec![b'a'; 2 * 1024 * 1024 + 1]);
    let e = a.execute(&mat(), &get).await.unwrap_err();
    assert_eq!(e, Outcome::Net(NetError::TooLarge));
}

#[test]
fn the_hosts_are_exactly_github_and_the_registry_has_the_kind() {
    assert_eq!(GITHUB.hosts, ["api.github.com", "github.com"]);
    assert!(GITHUB.problem().is_none());
    assert!(
        !GITHUB.allows_host("uploads.github.com")
            && !GITHUB.allows_host("api.github.com.evil.test")
    );
    let methods: Vec<_> = GITHUB
        .auth_methods
        .iter()
        .map(|m| (m.id, m.advanced))
        .collect();
    assert_eq!(
        methods,
        [("oauth", false), ("app_install", false), ("token", true)]
    );
    assert_eq!(GITHUB.read_only(), ["read_repo"]);
    assert_eq!(
        GITHUB
            .capabilities
            .iter()
            .map(|c| c.name)
            .collect::<Vec<_>>(),
        ["read_repo", "issues_write", "pr_write", "push"]
    );
    let reg = Registry::builtin();
    assert!(reg.get("github").is_some());
    assert!(GITHUB.limit_key("repos").is_some());
    // The declared token shape is the redactor's own name for a GitHub token.
    let shaped = format!("ghp_{}", "a1B2c3D4e5".repeat(4));
    let red = ainkrad_proto::redact::Redactor::new().text(&shaped);
    assert_eq!(red, format!("[redacted:{}]", GITHUB.token_shapes[0]));
}
