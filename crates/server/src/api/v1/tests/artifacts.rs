//! Artifacts over the client API (E15.12): listed by the acting company with filters, served
//! as attachments that never run, previewed only as text or images, never across companies.

use ainkrad_core::gov::ArtifactKind;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;
use crate::store::artifacts::{NewArtifact, publish_artifact};

async fn publish(fx: &Fx, s: &Seed, name: &str, kind: ArtifactKind, bytes: &[u8]) -> i64 {
    let new = NewArtifact {
        company: s.company,
        issue: Some(s.issue),
        requirement: None,
        run: Some(s.run.id),
        agent: Some(s.agent),
        name: name.to_owned(),
        kind,
        user: None,
    };
    publish_artifact(
        &fx.app.pool,
        &fx.app.artifacts,
        &new,
        bytes,
        &Default::default(),
    )
    .await
    .unwrap()
    .id
    .0
}

fn as_company(c: CompanyId, mut r: Request<Body>) -> Request<Body> {
    r.headers_mut()
        .insert(COMPANY_HEADER, c.0.to_string().parse().unwrap());
    r
}

/// The status, headers and body of a GET.
async fn raw(fx: &Fx, r: Request<Body>) -> (StatusCode, header::HeaderMap, Vec<u8>) {
    let res = router(fx.app.clone()).oneshot(r).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let body = to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn artifacts_are_listed_served_safely_and_kept_to_their_company() {
    let fx = fx().await;
    let pool = fx.app.pool.clone();
    let a = seed(&pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&pool, "B", "BBB", ProjectMode::Kanban).await;
    let html = b"<script>alert(1)</script>";
    let page = publish(&fx, &a, "page.html", ArtifactKind::Report, html).await;
    let md = publish(&fx, &a, "qa.md", ArtifactKind::Report, b"# QA\npass").await;
    let png = publish(&fx, &a, "shot.png", ArtifactKind::Screenshot, b"\x89PNG..").await;
    let theirs = publish(&fx, &b, "theirs.md", ArtifactKind::Report, b"secret").await;

    let list = |uri: &str| as_company(a.company, req(Method::GET, uri, Some(&fx.key), None));
    let (_, mine) = send(&fx.app, list("/api/v1/artifacts")).await;
    let ids: Vec<i64> = mine["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [png, md, page], "A's, newest first");
    let (_, reports) = send(&fx.app, list("/api/v1/artifacts?kind=report&limit=1")).await;
    assert_eq!(reports["items"][0]["id"], md);
    assert_eq!(reports["next_after"], md);
    let by_agent = format!("/api/v1/artifacts?agent={}&issue={}", a.agent.0, a.issue.0);
    assert_eq!(
        send(&fx.app, list(&by_agent)).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let one = fx.ok(&format!("/api/v1/artifacts/{png}")).await;
    assert_eq!(
        (one["preview"].as_str(), one["run_id"].as_i64()),
        (Some("image"), Some(a.run.id.0))
    );

    // A download is an attachment of its stored type, never sniffed, sandboxed.
    let get = |uri: String| req(Method::GET, &uri, Some(&fx.key), None);
    let (status, h, body) = raw(&fx, get(format!("/api/v1/artifacts/{page}/content"))).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, &html[..]));
    assert_eq!(h[header::CONTENT_TYPE], "text/html");
    assert_eq!(
        h[header::CONTENT_DISPOSITION],
        "attachment; filename=\"page.html\""
    );
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    // HTML has no preview; Markdown previews as plain text; an image inline.
    let (status, _, _) = raw(&fx, get(format!("/api/v1/artifacts/{page}/preview"))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, h, body) = raw(&fx, get(format!("/api/v1/artifacts/{md}/preview"))).await;
    assert_eq!(
        (h[header::CONTENT_TYPE].to_str().unwrap(), body.as_slice()),
        ("text/plain; charset=utf-8", &b"# QA\npass"[..])
    );
    let (_, h, _) = raw(&fx, get(format!("/api/v1/artifacts/{png}/preview"))).await;
    assert_eq!(
        (
            h[header::CONTENT_TYPE].to_str().unwrap(),
            h[header::CONTENT_DISPOSITION].to_str().unwrap()
        ),
        ("image/png", "inline")
    );

    // Another company's: not there.
    for uri in [
        format!("/api/v1/artifacts/{theirs}"),
        format!("/api/v1/artifacts/{theirs}/content"),
    ] {
        let (status, _, _) = raw(&fx, as_company(a.company, get(uri.clone()))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
    }
    let usage = fx
        .ok(&format!("/api/v1/companies/{}/artifact-usage", a.company.0))
        .await;
    assert_eq!(usage["used_bytes"], (html.len() + 9 + 6) as i64);
    assert_eq!(usage["quota_bytes"], 2_000_000_000_i64);
}
