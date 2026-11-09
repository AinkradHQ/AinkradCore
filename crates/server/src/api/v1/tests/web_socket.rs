//! The web client's origin and event socket (handshake spec §9, §10; E1-08.5): only the Core's
//! own origin (and configured ones) passes, before routing; no CORS answer is ever given; with no
//! cookie a request without a signature is nothing (CSRF); a browser's socket opens with a
//! one-time ticket in the subprotocol, which is single use, short-lived, bound to a live session
//! of a usable device, issued at a bounded rate, and refused from a foreign origin.

use std::time::Duration;

use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use std::sync::Arc;

use super::events::{Ws, drain, quick};
use super::passkeys::{browser, code_of, fx_pk, pair_passkey, sign_in};
use super::*;

/// `req` with an `Origin`.
fn from(origin: &str, mut r: Request<Body>) -> Request<Body> {
    r.headers_mut()
        .insert(header::ORIGIN, origin.parse().unwrap());
    r
}

#[tokio::test]
async fn only_the_cores_own_origin_passes_and_nothing_answers_cors() {
    let mut fx = fx_pk().await;
    let evil = "https://evil.test";
    let me = || req(Method::GET, "/api/v1/me", Some(&fx.dev), None);
    let (s, v) = send(&fx.app, from(evil, me())).await;
    assert_eq!(
        (s, code_of(&v)),
        (StatusCode::FORBIDDEN, "origin_refused"),
        "even signed"
    );
    let body = json!({"session_spki": "x"});
    let pre = || {
        req(
            Method::POST,
            "/handshake/passkey/options",
            None,
            Some(body.clone()),
        )
    };
    let (s, v) = send(&fx.app, from(evil, pre())).await;
    assert_eq!(
        (s, code_of(&v)),
        (StatusCode::FORBIDDEN, "origin_refused"),
        "pre-auth too"
    );
    let (s, v) = send(&fx.app, from("null", pre())).await;
    assert_eq!(code_of(&v), "origin_refused", "{s}");

    let res = router(fx.app.clone())
        .oneshot(from("https://core.test", me()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/v1/me")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "https://core.test")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let pf = router(fx.app.clone()).oneshot(preflight).await.unwrap();
    assert_eq!(
        pf.status(),
        StatusCode::UNAUTHORIZED,
        "a preflight is an unsigned request"
    );
    for r in [&res, &pf] {
        assert!(
            !r.headers()
                .keys()
                .any(|k| k.as_str().starts_with("access-control-")),
            "no CORS headers, ever"
        );
    }
    // CSRF: the own origin, but no signature (there is no cookie to ride on).
    let unsigned = req(Method::POST, "/api/v1/pairings", None, Some(json!({})));
    let (s, v) = send(&fx.app, from("https://core.test", unsigned)).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, "auth_failed"));
    // A configured extra origin passes too.
    fx.app.origins = Arc::from([
        "https://core.test".to_owned(),
        "https://app.test".to_owned(),
    ]);
    assert_eq!(
        send(&fx.app, from("https://app.test", me())).await.0,
        StatusCode::OK
    );
}

/// Opens the event socket with `ticket`, unsigned, from `origin` if any.
async fn open(app: &App, ticket: &str, origin: Option<&str>) -> Result<(Ws, String), WsError> {
    let mut r = format!("ws://{}/api/v1/events/ws", app.host)
        .into_client_request()
        .unwrap();
    let protocols = format!("ainkrad.v1, ainkrad-ticket.{ticket}");
    r.headers_mut()
        .insert("sec-websocket-protocol", protocols.parse().unwrap());
    if let Some(o) = origin {
        r.headers_mut().insert("origin", o.parse().unwrap());
    }
    let (ws, res) = connect_async(r).await?;
    let chosen = res.headers()["sec-websocket-protocol"]
        .to_str()
        .unwrap()
        .to_owned();
    Ok((ws, chosen))
}

fn status_of(e: WsError) -> StatusCode {
    match e {
        WsError::Http(r) => StatusCode::from_u16(r.status().as_u16()).unwrap(),
        other => panic!("not an HTTP refusal: {other}"),
    }
}

async fn ticket(fx: &Fx, dev: &TestDevice) -> (StatusCode, Value) {
    send(
        &fx.app,
        req(Method::POST, "/api/v1/ws-ticket", Some(dev), None),
    )
    .await
}

#[tokio::test]
async fn a_browser_socket_opens_once_per_ticket_and_closes_on_revocation() {
    let fx = fx_pk().await;
    let (mut a, id) = pair_passkey(&fx, &["read"]).await;
    let web = browser(&fx, &id);
    assert_eq!(sign_in(&fx, &mut a, &web).await.0, StatusCode::OK);
    let app = serve_with_origin(&fx).await;
    let own = app.origins[0].clone();

    let (_, t) = ticket(&fx, &web).await;
    let t = t["ticket"].as_str().unwrap().to_owned();
    // From a foreign origin the upgrade is refused before the ticket is even looked at.
    let e = open(&app, &t, Some("https://evil.test")).await.unwrap_err();
    assert_eq!(status_of(e), StatusCode::FORBIDDEN);
    let (mut ws, chosen) = open(&app, &t, Some(&own)).await.unwrap();
    assert_eq!(
        chosen, "ainkrad.v1",
        "the server answers the protocol the browser offered"
    );
    // Replayed.
    assert_eq!(
        status_of(open(&app, &t, None).await.unwrap_err()),
        StatusCode::UNAUTHORIZED
    );
    // Expired.
    let (_, late) = ticket(&fx, &web).await;
    fx.clock.advance(31);
    let late = late["ticket"].as_str().unwrap();
    assert_eq!(
        status_of(open(&app, late, None).await.unwrap_err()),
        StatusCode::UNAUTHORIZED
    );
    // Made up.
    let made_up = crate::auth::crypto::b64(&[3; 16]);
    assert_eq!(
        status_of(open(&app, &made_up, None).await.unwrap_err()),
        StatusCode::UNAUTHORIZED
    );
    // A ticket opens the event socket only.
    let (_, other) = ticket(&fx, &web).await;
    let mut r = req(Method::GET, "/api/v1/me", None, None);
    let offer = format!(
        "ainkrad.v1, ainkrad-ticket.{}",
        other["ticket"].as_str().unwrap()
    );
    r.headers_mut()
        .insert("sec-websocket-protocol", offer.parse().unwrap());
    assert_eq!(send(&fx.app, r).await.0, StatusCode::UNAUTHORIZED);

    // A ticket issued, then its device revoked: the open socket closes 4001, the ticket is dead.
    let (_, spare) = ticket(&fx, &web).await;
    let uri = format!("/api/v1/devices/{id}");
    let (s, v) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, _, close) = tokio::time::timeout(Duration::from_secs(5), drain(&mut ws))
        .await
        .expect("closed within 5 s");
    assert_eq!(close.unwrap().0, CloseCode::Library(4001));
    let spare = spare["ticket"].as_str().unwrap();
    assert_eq!(
        status_of(open(&app, spare, None).await.unwrap_err()),
        StatusCode::UNAUTHORIZED
    );
}

/// `fx`'s app on a loopback port, its own origin being `http://<that host>`.
async fn serve_with_origin(fx: &Fx) -> App {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let app = App {
        origins: Arc::from([format!("http://{host}")]),
        host,
        stream: quick(),
        ..fx.app.clone()
    };
    let service = router(app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    app
}

#[tokio::test]
async fn tickets_are_issued_at_a_bounded_rate_per_session() {
    let fx = fx_pk().await;
    let phone = fx.enroll("phone", &["read"]).await;
    for _ in 0..crate::auth::ticket::PER_SESSION_BURST {
        assert_eq!(ticket(&fx, &phone).await.0, StatusCode::OK);
    }
    let (s, v) = ticket(&fx, &phone).await;
    assert_eq!(
        (s, code_of(&v)),
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
    );
    // Another session of the same device has its own budget.
    let s2 = fx.app.auth.issue_session(&phone.id, fx.clock.unix()).id;
    phone.set_session(Some(s2));
    assert_eq!(ticket(&fx, &phone).await.0, StatusCode::OK);
    let runner = fx.enroll("runner", &["runner"]).await;
    let (s, v) = ticket(&fx, &runner).await;
    assert_eq!((s, code_of(&v)), (StatusCode::FORBIDDEN, "forbidden_scope"));
}
