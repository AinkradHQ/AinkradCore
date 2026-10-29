//! Agent avatars over the client API (decision #61): appearance and palettes, the figure's
//! state from what the agent is doing, and an uploaded image: checked, served safely,
//! revalidated by its ETag, removed, never across companies.

use ainkrad_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0";
const WEBP: &[u8] = b"RIFF\x1a\0\0\0WEBPVP8L\x0d\0\0\0\x2f\0\0\0\x10\x07\x10\x11\x11";

/// A raw request: `body` as `content_type` (if any), `headers` added.
fn raw_req(method: Method, uri: &str, fx: &Fx, body: &[u8], ct: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", fx.key));
    if let Some(ct) = ct {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

async fn raw(fx: &Fx, r: Request<Body>) -> (StatusCode, header::HeaderMap, Vec<u8>) {
    let res = router(fx.app.clone()).oneshot(r).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let body = to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn appearance_is_listed_changed_and_drawn_until_an_image_is_uploaded() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let palettes = fx.ok("/api/v1/avatars/palettes").await;
    assert_eq!(palettes.as_array().unwrap().len(), 17);
    assert_eq!(palettes[16], json!({"id": "steel", "name": "Steel"}));

    let uri = format!("/api/v1/agents/{}", a.agent.0);
    let agent = fx.ok(&uri).await;
    assert_eq!(agent["appearance"]["figure_version"], "v1");
    assert!(agent["appearance"]["palette_id"].is_string());
    assert!(agent["avatar_url"].is_null(), "no image: draw the figure");

    let set = |body: Value| {
        send(
            &fx.app,
            req(
                Method::PUT,
                &format!("{uri}/appearance"),
                Some(&fx.key),
                Some(body),
            ),
        )
    };
    let (status, got) = set(json!({"palette_id": "ember"})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["appearance"],
        json!({"figure_version": "v1", "palette_id": "ember"})
    );
    assert_eq!(
        set(json!({"palette_id": "muted"})).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, _) = set(json!({"palette_id": "aurora", "figure_version": "v9"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let chart = fx
        .ok(&format!("/api/v1/companies/{}/agents", a.company.0))
        .await;
    assert_eq!(chart[0]["appearance"]["palette_id"], "ember");
}

#[tokio::test]
async fn an_uploaded_image_is_checked_served_safely_and_reset() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/avatar", a.agent.0);
    let (status, _, _) = raw(&fx, raw_req(Method::GET, &uri, &fx, b"", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no image yet");

    let put = |body: &'static [u8], ct: Option<&'static str>| {
        raw(&fx, raw_req(Method::PUT, &uri, &fx, body, ct))
    };
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
    let refused: [(&[u8], Option<&str>, StatusCode); 6] = [
        (
            svg,
            Some("image/svg+xml"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (svg, Some("image/png"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            b"<html><script>x</script>",
            None,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            b"<html>",
            Some("text/html"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (PNG, Some("image/webp"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            b"GIF89a......",
            Some("application/octet-stream"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ];
    for (body, ct, want) in refused {
        let (status, _, got) = put(body, ct).await;
        let got: Value = serde_json::from_slice(&got).unwrap_or_default();
        assert_eq!(status, want, "{ct:?}: {got}");
    }

    let (status, _, got) = put(WEBP, Some("image/webp")).await;
    assert_eq!(status, StatusCode::OK);
    let got: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(got["avatar_url"], uri.as_str());
    let (status, _, got) = put(PNG, Some("image/png")).await;
    assert_eq!(status, StatusCode::OK);
    let agent: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(agent["avatar_url"], uri.as_str());

    let (status, h, body) = raw(&fx, raw_req(Method::GET, &uri, &fx, b"", None)).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, PNG));
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::CACHE_CONTROL], "private, no-cache");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    let etag = h[header::ETAG].to_str().unwrap().to_owned();
    let sha = crate::store::artifacts::sha256_hex(PNG);
    assert_eq!(etag, format!("\"{sha}\""));
    let mut again = raw_req(Method::GET, &uri, &fx, b"", None);
    again
        .headers_mut()
        .insert(header::IF_NONE_MATCH, etag.parse().unwrap());
    let (status, h, body) = raw(&fx, again).await;
    assert_eq!((status, body.len()), (StatusCode::NOT_MODIFIED, 0));
    assert_eq!(h[header::ETAG], etag.as_str());

    // Over the limit: refused before it is stored.
    let s = format!("/api/v1/settings/company:{}/avatar.max_bytes", a.company.0);
    let (status, _) = send(
        &fx.app,
        req(Method::PUT, &s, Some(&fx.key), Some(json!({"value": 1024}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let big: &'static [u8] = [PNG, &[0u8; 2048]].concat().leak();
    let (status, _, _) = put(big, Some("image/png")).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (status, _, got) = raw(&fx, raw_req(Method::DELETE, &uri, &fx, b"", None)).await;
    assert_eq!(status, StatusCode::OK);
    let got: Value = serde_json::from_slice(&got).unwrap();
    assert!(got["avatar_url"].is_null());
    let (status, _, _) = raw(&fx, raw_req(Method::GET, &uri, &fx, b"", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn another_companys_avatars_are_refused() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/avatar", b.agent.0);
    for m in [Method::GET, Method::PUT, Method::DELETE] {
        let mut r = raw_req(m.clone(), &uri, &fx, PNG, Some("image/png"));
        r.headers_mut()
            .insert(COMPANY_HEADER, a.company.0.to_string().parse().unwrap());
        let (status, _, _) = raw(&fx, r).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{m} as A");
    }
    let agent = fx.ok(&format!("/api/v1/agents/{}", b.agent.0)).await;
    assert!(agent["avatar_url"].is_null(), "nothing was uploaded as A");
}

#[tokio::test]
async fn the_figure_shows_what_the_agent_is_doing() {
    let fx = fx().await;
    let pool = fx.app.pool.clone();
    let a = seed(&pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}", a.agent.0);
    let state = || async { fx.ok(&uri).await["figure_state"].clone() };
    let sql = |q: &'static str| {
        let pool = pool.clone();
        async move { sqlx::query(q).execute(&pool).await.unwrap() }
    };

    assert_eq!(state().await, "thinking", "running, no output yet");
    sql("UPDATE runs SET first_token_at = '2026-10-22T09:59:00.000Z'").await;
    assert_eq!(state().await, "working");
    let ask = format!(
        "INSERT INTO questions (issue_id, agent_id, question) VALUES ({}, {}, 'Which?')",
        a.issue.0, a.agent.0
    );
    sqlx::query(sqlx::AssertSqlSafe(ask))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(state().await, "listening", "waiting on the admin");
    sql("UPDATE questions SET state = 'cancelled'").await;
    sql("UPDATE runs SET state = 'queued'").await;
    assert_eq!(state().await, "loading");
    sql(
        "UPDATE runs SET state = 'failed', terminal_reason = 'stalled', \
         ended_at = '2026-10-22T09:59:30.000Z'",
    )
    .await;
    assert_eq!(state().await, "confused");
    sql("UPDATE runs SET state = 'succeeded', terminal_reason = 'done'").await;
    assert_eq!(state().await, "success", "just finished");
    sql("UPDATE runs SET ended_at = '2026-10-22T09:00:00.000Z'").await;
    assert_eq!(state().await, "idle");
    sql("UPDATE agents SET status = 'paused'").await;
    assert_eq!(state().await, "sleepy");
    sql("UPDATE agents SET status = 'terminated'").await;
    assert_eq!(state().await, "rest");
    let chart = fx
        .ok(&format!("/api/v1/companies/{}/org", a.company.0))
        .await;
    assert_eq!(chart["agents"][0]["figure_state"], "rest");
}

#[tokio::test]
async fn a_company_logo_follows_the_avatar_rules() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/logo", a.company.0);
    let (status, _, _) = raw(&fx, raw_req(Method::GET, &uri, &fx, b"", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no logo yet");
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
    let r = raw_req(Method::PUT, &uri, &fx, svg, Some("image/svg+xml"));
    assert_eq!(raw(&fx, r).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (status, _, got) = raw(&fx, raw_req(Method::PUT, &uri, &fx, PNG, Some("image/png"))).await;
    assert_eq!(status, StatusCode::OK);
    let company: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(company["logo_url"], uri.as_str());
    let listed = fx.ok("/api/v1/companies").await;
    assert_eq!(listed[0]["logo_url"], uri.as_str());
    let (status, h, body) = raw(&fx, raw_req(Method::GET, &uri, &fx, b"", None)).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, PNG));
    let mut again = raw_req(Method::GET, &uri, &fx, b"", None);
    again
        .headers_mut()
        .insert(header::IF_NONE_MATCH, h[header::ETAG].clone());
    assert_eq!(raw(&fx, again).await.0, StatusCode::NOT_MODIFIED);

    // Another company's logo is not there for A.
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let theirs = format!("/api/v1/companies/{}/logo", b.company.0);
    let mut r = raw_req(Method::PUT, &theirs, &fx, PNG, Some("image/png"));
    r.headers_mut()
        .insert(COMPANY_HEADER, a.company.0.to_string().parse().unwrap());
    assert_eq!(raw(&fx, r).await.0, StatusCode::NOT_FOUND);

    let (status, _, got) = raw(&fx, raw_req(Method::DELETE, &uri, &fx, b"", None)).await;
    assert_eq!(status, StatusCode::OK);
    let company: Value = serde_json::from_slice(&got).unwrap();
    assert!(company["logo_url"].is_null());
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'company.logo%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(actions, ["company.logo_set", "company.logo_reset"]);
}
