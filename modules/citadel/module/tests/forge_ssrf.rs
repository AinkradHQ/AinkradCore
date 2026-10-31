//! The forge client's negative tests (S6): an API URL off the call policy, a redirect to an
//! internal server, a name that resolves to loopback, a credential outside the module's
//! namespace, a token echoed by the forge, and a host that rate limits. None of them may reach
//! an internal server, open a secret it should not, or leave the token anywhere.

mod common;
mod forge_seed;
mod gov_seed;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_providers::guard::{Lookup, Policy};
use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use citadel_module::forge::Runtime;
use forge_seed::*;

async fn serve(router: Router) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    addr
}

/// A server that counts every request and answers `status` with `body`.
fn counting(hits: &Arc<AtomicUsize>, status: StatusCode, body: &'static str) -> Router {
    let hits = hits.clone();
    Router::new().fallback(move || {
        hits.fetch_add(1, Ordering::SeqCst);
        async move { (status, body) }
    })
}

async fn used(r: &Rig) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'secret.used'")
        .fetch_one(r.pool())
        .await
        .unwrap()
}

async fn set_api(r: &Rig, url: &str) {
    sqlx::query("UPDATE citadel_project_repos SET forge_api_url = ?")
        .bind(url)
        .execute(r.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE citadel_issue_prs SET last_error = NULL")
        .execute(r.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn an_api_url_off_the_policy_is_refused_before_any_call_or_secret_open() {
    let mut r = rig().await;
    // The production policy: the only loopback server there is gets no request.
    let hits = Arc::new(AtomicUsize::new(0));
    let internal = serve(counting(&hits, StatusCode::OK, "{}")).await;
    r.rt = Runtime::new(r.pool().clone(), r.sealer.clone());
    r.requested("aaaa1111").await;
    for url in [
        format!("https://127.0.0.1:{}", internal.port()),
        format!("http://{internal}"),
        "https://169.254.169.254/latest/meta-data".to_owned(),
        "https://[::ffff:127.0.0.1]".to_owned(),
        "https://[::1]".to_owned(),
        "https://localhost".to_owned(),
        "https://2130706433".to_owned(),
        "http://api.github.com".to_owned(),
        "https://evil.example".to_owned(),
        "https://api.github.com@127.0.0.1".to_owned(),
        "https://api.github.com:8443".to_owned(),
    ] {
        set_api(&r, &url).await;
        r.sync().await;
        let pr = r.pr().await;
        let err = pr.last_error.unwrap_or_default();
        assert!(err.contains("refused"), "{url}: {err:?}");
        assert_eq!(pr.number, None, "{url}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no request reached the internal server"
    );
    assert_eq!(
        used(&r).await,
        0,
        "a refused URL never opens the credential"
    );
}

#[tokio::test]
async fn a_redirect_to_an_internal_server_is_not_followed() {
    let mut r = rig().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let internal = serve(counting(&hits, StatusCode::OK, "internal secrets")).await;
    let to = format!("http://{internal}/latest/meta-data");
    let forge = serve(Router::new().fallback(move || {
        let to = to.clone();
        async move { (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, to)]) }
    }))
    .await;
    let policy = Policy::new([]).with_test_origin(forge);
    r.rt = Runtime::with_policy(r.pool().clone(), r.sealer.clone(), policy);
    set_api(&r, &format!("http://{forge}")).await;
    r.requested("aaaa1111").await;
    r.sync().await;
    let err = r.pr().await.last_error.unwrap();
    assert!(err.contains("307"), "the redirect is the answer: {err}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the internal server was never dialed"
    );
}

#[tokio::test]
async fn a_name_that_resolves_to_loopback_is_never_dialed() {
    let mut r = rig().await;
    let looked = Arc::new(AtomicUsize::new(0));
    let seen = looked.clone();
    let lookup: Lookup = Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(vec![
                "8-8-8-8".replace('-', ".").parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ])
        })
    });
    let policy = Policy::new(["forge.test".to_owned()]).with_lookup(lookup);
    r.rt = Runtime::with_policy(r.pool().clone(), r.sealer.clone(), policy);
    set_api(&r, "https://forge.test").await;
    r.requested("aaaa1111").await;
    r.sync().await;
    let pr = r.pr().await;
    assert_eq!(pr.number, None);
    assert!(
        pr.last_error.unwrap().contains("unreachable"),
        "refused at the resolver"
    );
    assert_eq!(
        looked.load(Ordering::SeqCst),
        1,
        "the name went through the guard"
    );
}

#[tokio::test]
async fn a_credential_outside_the_modules_namespace_is_never_opened() {
    let r = rig().await;
    // A platform secret, and a missing one, named by a repo that bypassed the store's check.
    let new = ainkrad_core_server::store::secrets::NewValue {
        value: "deploy_token",
        runners: None,
        delivery: None,
    };
    ainkrad_core_server::store::secrets::create(
        r.pool(),
        &r.sealer,
        "git.deploy",
        &new,
        &r.fx.dev.id,
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    r.requested("aaaa1111").await;
    for name in ["git.deploy", "citadel.missing", "../citadel.forge"] {
        sqlx::query("UPDATE citadel_project_repos SET forge_secret = ?")
            .bind(name)
            .execute(r.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE citadel_issue_prs SET last_error = NULL")
            .execute(r.pool())
            .await
            .unwrap();
        r.sync().await;
        let err = r.pr().await.last_error.unwrap();
        assert!(err.contains("unavailable"), "{name}: {err}");
    }
    assert!(
        r.hub.lock().unwrap().requests.is_empty(),
        "nothing was called without a credential"
    );
    assert_eq!(used(&r).await, 0);
}

#[tokio::test]
async fn a_token_the_forge_echoes_is_cut_out_and_never_stored() {
    let mut r = rig().await;
    // A forge that answers 401 and repeats the Authorization header in its error body.
    let echo = serve(Router::new().fallback(|headers: HeaderMap| async move {
        let auth = headers
            .get(header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"message": format!("bad {auth}")})),
        )
    }))
    .await;
    let policy = Policy::new([]).with_test_origin(echo);
    r.rt = Runtime::with_policy(r.pool().clone(), r.sealer.clone(), policy);
    set_api(&r, &format!("http://{echo}")).await;
    r.requested("aaaa1111").await;
    r.sync().await;
    let err = r.pr().await.last_error.unwrap();
    assert!(
        err.contains("401") && err.contains("<redacted>") && !err.contains(TOKEN),
        "{err}"
    );
    // Nowhere in the database, its log or the audit trail: only the sealed copy exists.
    let all = db_bytes(&r.fx).await;
    assert!(!contains(&all, TOKEN), "the token is on disk");
    let trail: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(r.pool())
        .await
        .unwrap();
    assert!(!trail.join("\n").contains(TOKEN));
}

#[tokio::test]
async fn a_rate_limited_host_rests_and_is_not_asked_again() {
    let mut r = rig().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let busy = serve(counting(
        &hits,
        StatusCode::TOO_MANY_REQUESTS,
        r#"{"message":"API rate limit exceeded"}"#,
    ))
    .await;
    let policy = Policy::new([]).with_test_origin(busy);
    r.rt = Runtime::with_policy(r.pool().clone(), r.sealer.clone(), policy);
    set_api(&r, &format!("http://{busy}")).await;
    r.requested("aaaa1111").await;
    // A second issue with its own PR on the same repo (the same host).
    let second = gov_seed::second_issue(r.pool(), r.s.project).await;
    let pr =
        citadel_module::store::forge::request_pr(r.pool(), second, None, r.s.agent, ("Two", "b"))
            .await
            .unwrap();
    let by = citadel_module::store::forge::PushReporter {
        issue: second,
        agent: r.s.agent,
        run: None,
    };
    let payload = serde_json::json!({"type": "branch_pushed", "repo": "app", "branch": pr.head, "sha": "bbbb"});
    citadel_module::store::forge::push_reported(r.pool(), by, &payload, NOW)
        .await
        .unwrap();
    r.sync().await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the second PR waited: the host is resting"
    );
    r.sync().await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "and the next pass too");
}
