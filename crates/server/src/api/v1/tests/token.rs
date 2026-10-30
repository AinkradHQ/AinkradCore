//! The token gate (`gateway::token`, E2-13 S8): a module's declared routes answer a bearer token
//! and nothing else; every refusal is the same 401; the signed gate's tables are not involved.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Extension;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::{MethodRouter, get, post};

use super::{fx, req, send};
use crate::api::App;
use crate::api::limit::Limiter;
use crate::api::v1::Limits;
use crate::gateway::token::unsigned_routes;
use crate::module::{BoxFut, Module, TokenGrant, TokenPrincipal, TokenRoute};

const GOOD: &str = "tok_good";

struct Toy;

const ROUTES: &[TokenRoute] = &[
    TokenRoute {
        method: "POST",
        template: "/echo",
        max_body: 16,
    },
    TokenRoute {
        method: "GET",
        template: "/who/{x}",
        max_body: 1,
    },
];

impl Module for Toy {
    fn id(&self) -> &'static str {
        "toy"
    }

    fn routes(&self) -> Router<App> {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    fn token_routes(&self) -> &'static [TokenRoute] {
        ROUTES
    }

    fn token_handler(&self, method: &str, template: &str) -> Option<MethodRouter<App>> {
        match (method, template) {
            ("POST", "/echo") => Some(post(
                |Extension(p): Extension<TokenPrincipal>, body: Bytes| async move {
                    let who = p.0.downcast_ref::<String>().cloned().unwrap_or_default();
                    format!("{who}:{}", body.len())
                },
            )),
            ("GET", "/who/{x}") => {
                Some(get(|Extension(p): Extension<TokenPrincipal>| async move {
                    p.0.downcast_ref::<String>().cloned().unwrap_or_default()
                }))
            }
            _ => None,
        }
    }

    fn verify_token<'a>(&'a self, _: &'a App, token: &'a str) -> BoxFut<'a, Option<TokenGrant>> {
        Box::pin(async move {
            (token == GOOD).then(|| TokenGrant {
                principal: Arc::new("run7".to_owned()),
                key: "run:7".to_owned(),
            })
        })
    }
}

async fn app() -> (super::Fx, App) {
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Toy) as Arc<dyn Module>]);
    let app = fx.app.clone();
    (fx, app)
}

fn call(method: Method, uri: &str, bearer: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, super::HOST);
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

async fn text(app: &App, r: Request<Body>) -> (StatusCode, String, Option<String>) {
    use tower::ServiceExt;
    let res = crate::api::router(app.clone()).oneshot(r).await.unwrap();
    let status = res.status();
    let cache = res
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned(), cache)
}

const ECHO: &str = "/token/toy/v1/echo";

#[tokio::test]
async fn a_good_token_reaches_the_declared_route_and_only_it() {
    let (_fx, app) = app().await;
    let (s, body, cache) = text(&app, call(Method::POST, ECHO, Some(GOOD), "hello")).await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "run7:5"));
    assert_eq!(cache.as_deref(), Some("no-store"));
    let (s, body, _) = text(
        &app,
        call(Method::GET, "/token/toy/v1/who/abc", Some(GOOD), ""),
    )
    .await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "run7"));
    // A method the route does not declare, a path it does not declare, another module's prefix.
    for (m, uri) in [
        (Method::GET, ECHO),
        (Method::POST, "/token/toy/v1/who/abc"),
        (Method::POST, "/token/toy/v1/other"),
        (Method::POST, "/token/toy/v1/echo/extra"),
        (Method::POST, "/token/toy/v2/echo"),
        (Method::POST, "/token/nope/v1/echo"),
        (Method::POST, "/token/toy/echo"),
        (Method::POST, "/token/"),
    ] {
        let (s, _, _) = text(&app, call(m.clone(), uri, Some(GOOD), "")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {uri}");
    }
}

#[tokio::test]
async fn every_refusal_is_the_same_401() {
    let (_fx, app) = app().await;
    let mut seen = vec![];
    for bearer in [None, Some("tok_bad"), Some("TOK_UPPER"), Some("tok-dash")] {
        let r = call(Method::POST, ECHO, bearer, "x");
        seen.push(text(&app, r).await);
    }
    let bad_scheme = Request::builder()
        .method(Method::POST)
        .uri(ECHO)
        .header(header::HOST, super::HOST)
        .header(header::AUTHORIZATION, format!("Basic {GOOD}"))
        .body(Body::empty())
        .unwrap();
    seen.push(text(&app, bad_scheme).await);
    let twice = Request::builder()
        .method(Method::POST)
        .uri(ECHO)
        .header(header::HOST, super::HOST)
        .header(header::AUTHORIZATION, format!("Bearer {GOOD}"))
        .header(header::AUTHORIZATION, format!("Bearer {GOOD}"))
        .body(Body::empty())
        .unwrap();
    seen.push(text(&app, twice).await);
    let long = "a".repeat(200);
    seen.push(text(&app, call(Method::POST, ECHO, Some(&long), "")).await);
    // The same answer for every refusal (the error id is the one thing that differs).
    let shape = |body: &str| {
        let mut v: serde_json::Value = serde_json::from_str(body).unwrap();
        v.as_object_mut().unwrap().remove("error_id");
        v
    };
    for (status, body, _) in &seen {
        assert_eq!(*status, StatusCode::UNAUTHORIZED);
        assert_eq!(shape(body), shape(&seen[0].1), "one body for every refusal");
        assert!(!body.contains("tok_"), "{body}");
    }
}

#[tokio::test]
async fn browsers_cookies_queries_and_big_bodies_are_refused() {
    let (_fx, app) = app().await;
    let with = |name: &str, value: &str| {
        Request::builder()
            .method(Method::POST)
            .uri(ECHO)
            .header(header::HOST, super::HOST)
            .header(header::AUTHORIZATION, format!("Bearer {GOOD}"))
            .header(name.to_owned(), value.to_owned())
            .body(Body::empty())
            .unwrap()
    };
    // Even the Core's own origin: no page is a client of a token route.
    let own = crate::auth::web::own_origin(super::HOST);
    for (name, value) in [("origin", own.as_str()), ("origin", "https://evil.example")] {
        let (s, body, _) = text(&app, with(name, value)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{name}: {body}");
        assert!(!body.contains("access-control"));
    }
    let (s, _, _) = text(&app, with("cookie", "a=b")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = text(
        &app,
        call(Method::POST, "/token/toy/v1/echo?token=x", Some(GOOD), ""),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a token is never in a URL");
    let (s, _, _) = text(&app, call(Method::POST, ECHO, Some(GOOD), &"x".repeat(17))).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let (s, _, _) = text(&app, call(Method::POST, ECHO, Some(GOOD), &"x".repeat(16))).await;
    assert_eq!(s, StatusCode::OK);
    let wrong_host = Request::builder()
        .method(Method::POST)
        .uri(ECHO)
        .header(header::HOST, "evil.example")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(text(&app, wrong_host).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_source_that_keeps_guessing_is_locked_out_even_with_the_right_token() {
    let (_fx, app) = app().await;
    for _ in 0..20 {
        let (s, _, _) = text(&app, call(Method::POST, ECHO, Some("tok_bad"), "")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _, _) = text(&app, call(Method::POST, ECHO, Some(GOOD), "")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "locked for the source");
    // The signed API's own lockout key is not the token one.
    let locked = crate::store::gov::locked_until(&app.pool, &["ip:local"], app.clock.unix())
        .await
        .unwrap();
    assert_eq!(locked, None, "token failures do not lock the signed API");
}

#[tokio::test]
async fn a_valid_token_is_rate_limited_per_principal() {
    let (_fx, mut app) = app().await;
    app.limits = Arc::new(Limits {
        requests: Limiter::new(2, 0.001),
    });
    let one = || call(Method::POST, ECHO, Some(GOOD), "");
    assert_eq!(text(&app, one()).await.0, StatusCode::OK);
    assert_eq!(text(&app, one()).await.0, StatusCode::OK);
    assert_eq!(text(&app, one()).await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_token_opens_no_signed_route_and_a_signature_opens_no_token_route() {
    let (fx, app) = app().await;
    // The bearer on a signed route is refused before anything else (handshake spec §5.1).
    for uri in ["/api/v1/devices", "/api/v1/secrets", "/modules/toy/v1/ping"] {
        let (s, _, _) = text(&app, call(Method::GET, uri, Some(GOOD), "")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}");
    }
    // A device that signs for a token route has no bearer: the same 401.
    let (s, _) = send(&app, req(Method::POST, ECHO, Some(&fx.dev), None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The module's signed route still needs its signature.
    let (s, _) = send(&app, req(Method::GET, "/modules/toy/v1/ping", None, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// The complete list of what answers without a device signature. A new entry fails here until it
/// is reviewed (`docs`: the design of the run token).
#[tokio::test]
async fn the_unsigned_routes_are_exactly_these() {
    let (_fx, app) = app().await;
    let mut got = unsigned_routes(&app.modules);
    got.sort();
    let mut want: Vec<(String, String)> = [
        ("ANY", "/handshake"),
        ("ANY", "/pair"),
        ("ANY", "/healthz"),
        ("ANY", "/runner/v2/connect"),
        ("POST", "/token/toy/v1/echo"),
        ("GET", "/token/toy/v1/who/{x}"),
    ]
    .iter()
    .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
    .collect();
    want.sort();
    assert_eq!(got, want);
    // With no module mounted, the token prefix answers nothing.
    assert_eq!(unsigned_routes(&[]).len(), 4);
}

#[test]
#[should_panic(expected = "has no handler")]
fn a_declared_route_without_a_handler_stops_the_mount() {
    struct Bare;
    impl Module for Bare {
        fn id(&self) -> &'static str {
            "bare"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn token_routes(&self) -> &'static [TokenRoute] {
            ROUTES
        }
    }
    crate::module::validate(&Bare);
}

#[test]
fn illegal_token_declarations_stop_the_mount() {
    struct Declares(&'static [TokenRoute]);
    impl Module for Declares {
        fn id(&self) -> &'static str {
            "d"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn token_routes(&self) -> &'static [TokenRoute] {
            self.0
        }
        fn token_handler(&self, _: &str, _: &str) -> Option<MethodRouter<App>> {
            Some(get(|| async { "" }))
        }
    }
    const fn r(method: &'static str, template: &'static str, max_body: usize) -> TokenRoute {
        TokenRoute {
            method,
            template,
            max_body,
        }
    }
    static DUP: [TokenRoute; 2] = [r("GET", "/a", 1), r("GET", "/a", 1)];
    static DELETE: [TokenRoute; 1] = [r("DELETE", "/a", 1)];
    static ZERO: [TokenRoute; 1] = [r("GET", "/a", 0)];
    static HUGE: [TokenRoute; 1] = [r("GET", "/a", crate::module::MAX_TOKEN_BODY + 1)];
    static DOTS: [TokenRoute; 1] = [r("GET", "/a/../b", 1)];
    static QUERY: [TokenRoute; 1] = [r("GET", "/a?x=1", 1)];
    for bad in [
        &DUP[..],
        &DELETE[..],
        &ZERO[..],
        &HUGE[..],
        &DOTS[..],
        &QUERY[..],
    ] {
        assert!(
            std::panic::catch_unwind(|| crate::module::validate(&Declares(bad))).is_err(),
            "{bad:?}"
        );
    }
}
