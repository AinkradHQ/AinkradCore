//! Design assets and collections through the Core's real gate (signed requests into `api::router`).
//! Each test fails if the property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::modsettings::ModuleSettings;
use ainkrad_core_server::store::projects::{self, Who};
use ainkrad_core_server::store::{connect, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use design_module::Design;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/design/v1";

struct Fx {
    app: App,
    admin: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A Core with Design migrated and mounted (or, `on = false`, a Core that does not carry it).
async fn fx_with(on: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "design-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = if on { vec![Arc::new(Design)] } else { vec![] };
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    let admin = enroll(&app, "admin", &["admin", "read"]).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    Fx { app, admin, dir }
}

async fn fx() -> Fx {
    fx_with(true).await
}

async fn enroll(app: &App, name: &str, scopes: &[&str]) -> TestDevice {
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        name,
        "device",
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    dev
}

/// Status, parsed JSON body (null when it is not JSON), raw body and headers.
async fn send(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Value, Vec<u8>, HeaderMap) {
    send_as(fx, dev, method, path, body, "application/octet-stream").await
}

async fn send_as(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
) -> (StatusCode, Value, Vec<u8>, HeaderMap) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_LENGTH, body.len());
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in dev.headers(method.as_str(), &uri, &body) {
        b = b.header(name, value);
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let raw = to_bytes(res.into_body(), 1 << 28).await.unwrap().to_vec();
    let json = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    (status, json, raw, headers)
}

async fn call(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let b = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let (s, v, _, _) = send_as(fx, &fx.admin, method, path, b, "application/json").await;
    (s, v)
}

async fn upload(fx: &Fx, query: &str, bytes: &[u8]) -> (StatusCode, Value) {
    let (s, v, _, _) = send(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/assets?{query}"),
        bytes.to_vec(),
    )
    .await;
    (s, v)
}

async fn count(fx: &Fx, table: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")); // test-only, a literal table name
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

fn png(extra: u8) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend([extra; 64]);
    v
}

async fn stored(fx: &Fx, sha: &str) -> String {
    let (s, _, raw, _) = send(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/assets/{sha}/data"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    String::from_utf8(raw).unwrap()
}

#[tokio::test]
async fn a_duplicate_upload_is_the_same_row_and_the_type_is_the_bytes() {
    let fx = fx().await;
    let (s, a) = upload(&fx, "name=logo.png", &png(1)).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(
        (&a["content_type"], &a["kind"], &a["duplicate"]),
        (&json!("image/png"), &json!("image"), &json!(false))
    );
    let (s, b) = upload(&fx, "name=other.png&kind=logo", &png(1)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (&b["sha256"], &b["name"], &b["duplicate"]),
        (&a["sha256"], &json!("logo.png"), &json!(true))
    );
    assert_eq!(count(&fx, "design_assets").await, 1);
    // The Core says what it is: MZ bytes named .png are refused, an empty body and a wrong kind too.
    for (q, body, want) in [
        (
            "name=a.png",
            b"MZ\x90\x00 not allowed".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        ("name=a.png", vec![], StatusCode::BAD_REQUEST),
        ("name=a.png&kind=font", png(2), StatusCode::BAD_REQUEST),
        ("name=a.png&kind=shot", png(2), StatusCode::BAD_REQUEST),
        ("name=%20", png(2), StatusCode::BAD_REQUEST),
        ("name=a.png&project=999", png(2), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(upload(&fx, q, &body).await.0, want, "{q}");
    }
    assert_eq!(
        count(&fx, "design_assets").await,
        1,
        "a refusal stores nothing"
    );
    let sha = a["sha256"].as_str().unwrap();
    let (s, _, raw, h) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/assets/{sha}/data"),
        vec![],
    )
    .await;
    assert_eq!((s, raw), (StatusCode::OK, png(1)));
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
}

const HOSTILE: &str = r##"<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:evil="http://evil/" width="10" height="10" onload="alert(1)">
<!-- comment -->
<script>alert(document.cookie)</script>
<foreignObject><iframe src="http://evil/"></iframe></foreignObject>
<style>@import url(http://evil/x.css); rect { fill: red }</style>
<style>rect { fill: blue }</style>
<a xlink:href="javascript:alert(1)"><rect id="a1" width="5" height="5" fill="url(http://evil/x#f)" onclick="x()"/></a>
<rect id="ok" width="5" height="5" fill="red" style="fill:url(javascript:x)" evil:x="1"/>
<use xlink:href="http://evil/s.svg#x" href="https://evil/x"/>
<use href="#ok"/>
<image href="http://evil/p.png" width="1" height="1"/>
<image href="data:image/png;base64,AAAA" width="1" height="1"/>
<animate attributeName="href" to="javascript:alert(1)"/>
<set attributeName="onload" to="alert(1)"/>
<path d="M0 0L5 5" stroke="url(#g)"/>
</svg>"##;

#[tokio::test]
async fn a_hostile_svg_is_stored_sanitised_or_refused() {
    let fx = fx().await;
    let (s, v) = upload(&fx, "name=x.svg", HOSTILE.as_bytes()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["content_type"], "image/svg+xml");
    let out = stored(&fx, v["sha256"].as_str().unwrap()).await;
    for bad in [
        "script",
        "alert",
        "onload",
        "onclick",
        "foreignObject",
        "iframe",
        "evil",
        "@import",
        "javascript",
        "<!--",
        "DOCTYPE",
        "ENTITY",
        "animate",
        "<set",
        "<a ",
        "http://evil",
        "xlink:href=\"http",
        "<?xml",
    ] {
        assert!(!out.contains(bad), "{bad} survived: {out}");
    }
    // What is static and local stays.
    for good in [
        "<rect",
        "id=\"ok\"",
        "<use href=\"#ok\"",
        "data:image/png;base64,AAAA",
        "stroke=\"url(#g)\"",
        "fill: blue",
    ] {
        assert!(out.contains(good), "{good} was lost: {out}");
    }
    assert!(out.starts_with("<svg") && out.ends_with("</svg>"), "{out}");
    // Sanitising is deterministic, so the same hostile file is the same row.
    let (_, again) = upload(&fx, "name=y.svg", HOSTILE.as_bytes()).await;
    assert_eq!(
        (&again["sha256"], &again["duplicate"]),
        (&v["sha256"], &json!(true))
    );
    // Refused: not well-formed, an unknown entity, a non-svg root, a second root, absurd depth.
    let deep = format!("<svg>{}{}</svg>", "<g>".repeat(100), "</g>".repeat(100));
    for bad in [
        "<svg><g></svg>".to_owned(),
        "<svg>&xxe;</svg>".to_owned(),
        "<html><svg/></html>".to_owned(),
        "<svg/><svg/>".to_owned(),
        "<script>alert(1)</script><svg/>".to_owned(),
        deep,
    ] {
        let (s, v) = upload(&fx, "name=bad.svg", bad.as_bytes()).await;
        assert_eq!(
            (s, &v["code"]),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &json!("unsupported_type")
            ),
            "{bad}"
        );
    }
    assert_eq!(count(&fx, "design_assets").await, 1);
}

#[tokio::test]
async fn caps_answer_413_and_store_nothing() {
    let fx = fx().await;
    let big = png(3)
        .into_iter()
        .chain(vec![0u8; 25 * 1024 * 1024])
        .collect::<Vec<u8>>();
    let (s, v) = upload(&fx, "name=big.png", &big).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::PAYLOAD_TOO_LARGE, &json!("too_large")),
        "the body ceiling"
    );
    let set = |name: &'static str, v: &'static str| {
        let pool = fx.app.pool.clone();
        async move {
            ModuleSettings::of(&Design)
                .set(
                    &pool,
                    name,
                    v,
                    AuditActor::System,
                    "2026-11-17T00:00:00.000Z",
                )
                .await
                .unwrap();
        }
    };
    set("asset.max_bytes", "100").await;
    let mut over = png(4);
    over.extend([0; 40]);
    assert_eq!(over.len(), 112);
    assert_eq!(
        upload(&fx, "name=a.png", &over).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    set("asset.max_bytes", "1000").await;
    set("library.max_bytes", "150").await;
    assert_eq!(upload(&fx, "name=a.png", &png(5)).await.0, StatusCode::OK); // 72 bytes
    assert_eq!(upload(&fx, "name=b.png", &png(6)).await.0, StatusCode::OK); // 144
    let (s, v) = upload(&fx, "name=c.png", &png(7)).await;
    assert_eq!(
        (s, &v["message"]),
        (StatusCode::PAYLOAD_TOO_LARGE, &json!("the library is full"))
    );
    // Bytes already in the library are not new bytes.
    assert_eq!(upload(&fx, "name=a.png", &png(5)).await.0, StatusCode::OK);
    assert_eq!(count(&fx, "design_assets").await, 2);
}

#[tokio::test]
async fn tags_search_delete_and_the_ref_count() {
    let fx = fx().await;
    let (_, a) = upload(&fx, "name=Hero%20photo.png", &png(1)).await;
    let (_, b) = upload(&fx, "name=icon.png&kind=icon", &png(2)).await;
    let (sa, sb) = (a["sha256"].as_str().unwrap(), b["sha256"].as_str().unwrap());
    let (s, v) = call(
        &fx,
        Method::PATCH,
        &format!("/assets/{sa}"),
        Some(json!({"tags": ["Brand", "brand", "hero"], "name": "Hero"})),
    )
    .await;
    assert_eq!(
        (s, v["tags"].clone(), &v["name"]),
        (StatusCode::OK, json!(["Brand", "hero"]), &json!("Hero"))
    );
    for (path, want) in [
        ("/assets", 2),
        ("/assets?kind=icon", 1),
        ("/assets?tag=BRAND", 1),
        ("/assets?q=ero", 1),
        ("/assets?q=%25", 0),
    ] {
        let (_, v) = call(&fx, Method::GET, path, None).await;
        assert_eq!(v.as_array().unwrap().len(), want, "{path}");
    }
    let tags: Vec<String> = (0..21).map(|i| format!("t{i}")).collect();
    assert_eq!(
        call(
            &fx,
            Method::PATCH,
            &format!("/assets/{sa}"),
            Some(json!({"tags": tags}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // A design or version using it pins it, whatever else is true.
    sqlx::query("INSERT INTO design_asset_refs (sha256, owner_kind, owner) VALUES (?, 'doc', 'dd_0000000000000000')")
        .bind(sa)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (s, v) = call(&fx, Method::DELETE, &format!("/assets/{sa}"), None).await;
    assert_eq!((s, &v["code"]), (StatusCode::CONFLICT, &json!("conflict")));
    assert_eq!(count(&fx, "design_assets").await, 2);
    // The table agrees even if a caller skipped the check.
    assert!(
        sqlx::query("DELETE FROM design_assets WHERE sha256 = ?")
            .bind(sa)
            .execute(&fx.app.pool)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM design_asset_refs")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let laptop = enroll(&fx.app, "laptop", &["admin"]).await;
    let (s, v, _, _) = send(
        &fx,
        &laptop,
        Method::DELETE,
        &format!("/assets/{sb}"),
        vec![],
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    let (_, c) = call(
        &fx,
        Method::POST,
        "/collections",
        Some(json!({"kind": "folder", "name": "F"})),
    )
    .await;
    let cid = c["id"].as_str().unwrap();
    call(
        &fx,
        Method::PUT,
        &format!("/collections/{cid}/items/{sb}"),
        Some(json!({})),
    )
    .await;
    assert_eq!(
        call(&fx, Method::DELETE, &format!("/assets/{sb}"), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(count(&fx, "design_collection_items").await, 0);
    assert_eq!(count(&fx, "design_assets").await, 1);
    assert_eq!(
        call(&fx, Method::GET, &format!("/assets/{sb}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn brand_kits_collections_and_project_links() {
    let fx = fx().await;
    let who = Who {
        by_device: "d_test",
        actor: AuditActor::System,
        now: "2026-11-17T00:00:00.000Z",
    };
    let p = projects::create(&fx.app.pool, "proj-a", "proj-a", "", "manual", who)
        .await
        .unwrap()
        .id
        .to_string();
    let mut ttf = b"\x00\x01\x00\x00".to_vec();
    ttf.extend([9; 40]);
    let (s, font) = upload(&fx, "name=Brand.ttf", &ttf).await;
    assert_eq!(
        (s, &font["kind"], &font["check_state"]),
        (StatusCode::OK, &json!("font"), &json!("pending")),
        "{font}"
    );
    let (_, logo) = upload(
        &fx,
        &format!("name=logo.png&kind=logo&project={p}"),
        &png(1),
    )
    .await;
    assert_eq!(logo["projects"], json!([p]));
    let (fs, ls) = (
        font["sha256"].as_str().unwrap(),
        logo["sha256"].as_str().unwrap(),
    );
    // M2: a font the helper has not passed is neither served nor nameable.
    let (s, _, _, _) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/assets/{fs}/data"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let kit_body = json!({"kind": "brand_kit", "name": "Acme", "colors": ["#0a84ff", "#FFF"], "fonts": [fs], "project": p});
    assert_eq!(
        call(&fx, Method::POST, "/collections", Some(kit_body.clone()))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, folder) = call(
        &fx,
        Method::POST,
        "/collections",
        Some(json!({"kind": "folder", "name": "F"})),
    )
    .await;
    let fid = folder["id"].as_str().unwrap();
    assert_eq!(
        call(
            &fx,
            Method::PUT,
            &format!("/collections/{fid}/items/{fs}"),
            Some(json!({}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // The helper (V6-01) passes it.
    sqlx::query("UPDATE design_assets SET check_state = 'ok' WHERE sha256 = ?")
        .bind(fs)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        send(
            &fx,
            &fx.admin,
            Method::GET,
            &format!("/assets/{fs}/data"),
            vec![]
        )
        .await
        .0,
        StatusCode::OK
    );
    let (s, kit) = call(&fx, Method::POST, "/collections", Some(kit_body)).await;
    assert_eq!(s, StatusCode::OK, "{kit}");
    let id = kit["id"].as_str().unwrap();
    assert_eq!(
        (&kit["fonts"], &kit["projects"]),
        (&json!([fs]), &json!([p]))
    );
    for body in [
        json!({"kind": "brand_kit", "name": "x", "colors": ["red"]}),
        json!({"kind": "brand_kit", "name": "x", "fonts": [ls]}),
        json!({"kind": "brand_kit", "name": "x", "fonts": ["00"]}),
        json!({"kind": "folder", "name": "x", "colors": ["#fff"]}),
        json!({"kind": "poster", "name": "x"}),
    ] {
        assert_eq!(
            call(&fx, Method::POST, "/collections", Some(body.clone()))
                .await
                .0,
            StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    let (s, v) = call(
        &fx,
        Method::PUT,
        &format!("/collections/{id}/items/{ls}"),
        Some(json!({"role": "logo"})),
    )
    .await;
    assert_eq!(
        (s, v["items"].clone()),
        (StatusCode::OK, json!([{"sha256": ls, "role": "logo"}]))
    );
    let (_, v) = call(&fx, Method::GET, &format!("/assets?collection={id}"), None).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (s, _) = call(
        &fx,
        Method::PUT,
        &format!("/collections/{id}/items/{}", "0".repeat(64)),
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(
        call(
            &fx,
            Method::PUT,
            &format!("/collections/{id}/projects/999"),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &fx,
            Method::DELETE,
            &format!("/collections/{id}/projects/{p}"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &fx,
            Method::DELETE,
            &format!("/collections/{id}/projects/{p}"),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &fx,
            Method::DELETE,
            &format!("/collections/{id}/items/{ls}"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    // L2: a kit that names a font keeps it from deletion.
    let (s, v) = call(&fx, Method::DELETE, &format!("/assets/{fs}"), None).await;
    assert_eq!((s, &v["code"]), (StatusCode::CONFLICT, &json!("conflict")));
    assert_eq!(
        call(&fx, Method::DELETE, &format!("/collections/{id}"), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        count(&fx, "design_assets").await,
        2,
        "deleting a collection deletes no asset"
    );
}

#[tokio::test]
async fn scopes_audit_and_the_contract() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let (_, a) = upload(&fx, "name=a.png", &png(1)).await;
    let sha = a["sha256"].as_str().unwrap();
    for path in [
        "/assets",
        &format!("/assets/{sha}"),
        &format!("/assets/{sha}/data"),
        "/collections",
    ] {
        assert_eq!(
            send(&fx, &reader, Method::GET, path, vec![]).await.0,
            StatusCode::OK,
            "{path}"
        );
    }
    let (s, v, _, _) = send(&fx, &reader, Method::POST, "/assets?name=b.png", png(2)).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
    // Audit and events carry the sha, never the name.
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action LIKE 'design.asset.%'")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(audit.len(), 1);
    assert!(
        audit[0].contains(sha) && !audit[0].contains("a.png"),
        "{audit:?}"
    );
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Design,
        )]))
        .unwrap();
    let p = &spec["paths"];
    assert_eq!(
        p["/modules/design/v1/assets/{sha}"]["delete"]["x-ainkrad-destructive"],
        true
    );
    assert_eq!(
        p["/modules/design/v1/assets"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert_eq!(
        p["/modules/design/v1/assets/{sha}/data"]["get"]["x-ainkrad-scope"],
        "read"
    );
}

fn svg_with(inner: &str) -> String {
    format!(r##"<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4">{inner}</svg>"##)
}

async fn svg_out(fx: &Fx, inner: &str) -> String {
    let (s, v) = upload(fx, "name=t.svg", svg_with(inner).as_bytes()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    stored(fx, v["sha256"].as_str().unwrap()).await
}

#[tokio::test]
async fn m1_no_css_function_or_escape_reaches_the_network() {
    let fx = fx().await;
    let out = svg_out(&fx, concat!(
        r#"<rect width="1" height="1" fill="image-set('https://evil/a.png' 1x)" filter="\75 rl(https://evil/f)" stroke="rgb(1,2,3)" transform="translate(1 2) rotate(3)"/>"#,
        r#"<rect id="q" style="background:image-set(&quot;https://evil/b.png&quot; 1x)" fill="url('#a')"/>"#,
        r#"<rect id="r" style="fill:var(--x)" fill-opacity="calc(1 + 1)"/>"#,
        "<style>rect { fill: image-set('https://evil/c.png' 1x) }</style>",
        "<style>rect { fill: \\75 rl(https://evil/d) }</style>",
        "<style>rect { fill: red }</style>",
    )).await;
    for bad in ["evil", "image-set", "\\", "var(", "calc(", "url('"] {
        assert!(!out.contains(bad), "{bad} survived: {out}");
    }
    for good in [
        "stroke=\"rgb(1,2,3)\"",
        "translate(1 2) rotate(3)",
        "fill: red",
    ] {
        assert!(out.contains(good), "{good} lost: {out}");
    }
}

#[tokio::test]
async fn l3_a_raster_that_is_also_an_svg_is_refused() {
    let fx = fx().await;
    let mut poly = png(1);
    poly.extend(b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>");
    let (s, v) = upload(&fx, "name=p.png", &poly).await;
    assert_eq!(
        (s, &v["code"]),
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &json!("unsupported_type")
        )
    );
    assert_eq!(count(&fx, "design_assets").await, 0);
}

#[tokio::test]
async fn l4_use_elements_are_capped() {
    let fx = fx().await;
    let ok = svg_with(&r##"<use href="#a"/>"##.repeat(256));
    assert_eq!(
        upload(&fx, "name=ok.svg", ok.as_bytes()).await.0,
        StatusCode::OK
    );
    let many = svg_with(&r##"<use href="#a"/>"##.repeat(257));
    assert_eq!(
        upload(&fx, "name=many.svg", many.as_bytes()).await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

fn upload_request(dev: &TestDevice, content_length: Option<usize>, body: Body) -> Request<Body> {
    let uri = format!("{BASE}/assets?name=x.png");
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header(header::HOST, HOST);
    for (name, value) in dev.headers("POST", &uri, &[]) {
        b = b.header(name, value);
    }
    if let Some(n) = content_length {
        b = b.header(header::CONTENT_LENGTH, n);
    }
    b.body(body).unwrap()
}

#[tokio::test]
async fn m3_a_bulk_upload_needs_a_length_and_takes_from_a_shared_budget() {
    let fx = fx().await;
    let call = |req: Request<Body>| {
        let app = fx.app.clone();
        async move { router(app).oneshot(req).await.unwrap().status() }
    };
    // No Content-Length (chunked): 411, before anything is read.
    assert_eq!(
        call(upload_request(&fx.admin, None, Body::from(png(1)))).await,
        StatusCode::LENGTH_REQUIRED
    );
    // Two uploads that announce 25 MiB and never finish hold 50 of the 64 MiB.
    let hold = |n| {
        let app = fx.app.clone();
        let req = upload_request(
            &fx.admin,
            Some(25 * 1024 * 1024),
            Body::from_stream(futures_util::stream::pending::<
                Result<axum::body::Bytes, std::convert::Infallible>,
            >()),
        );
        let _ = n;
        tokio::spawn(async move { router(app).oneshot(req).await })
    };
    let (h1, h2) = (hold(1), hold(2));
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // A third would need 75 MiB: refused at once, not queued.
    let third = call(upload_request(
        &fx.admin,
        Some(25 * 1024 * 1024),
        Body::empty(),
    ))
    .await;
    assert_eq!(third, StatusCode::TOO_MANY_REQUESTS);
    // A small upload still fits, and once the others are gone the budget is free again.
    h1.abort();
    h2.abort();
    let (_, _) = (h1.await.err(), h2.await.err());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (s, v) = upload(&fx, "name=ok.png", &png(1)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn l1_an_unsigned_or_unknown_caller_cannot_tell_the_upload_route_exists() {
    let fx = fx().await;
    // Unsigned, huge announced length: the same 401 every route gives.
    let anon = Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE}/assets?name=x.png"))
        .header(header::HOST, HOST)
        .header(header::CONTENT_LENGTH, 99_000_000)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(fx.app.clone()).oneshot(anon).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    // A device header that names no usable device: 401 as well, never 413 or 411.
    let uri = format!("{BASE}/assets?name=x.png");
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_LENGTH, 99_000_000);
    for (n, v) in fx.admin.headers("POST", &uri, &[]) {
        let (n, v) = (n.to_string(), v.to_string());
        let v = if n.eq_ignore_ascii_case("ainkrad-device") {
            {
                let mut id = fx.admin.id.clone();
                let last = if id.ends_with('0') { '1' } else { '0' };
                id.pop();
                id.push(last);
                id
            }
        } else {
            v
        };
        b = b.header(n, v);
    }
    let ghost = b.body(Body::empty()).unwrap();
    assert_eq!(
        router(fx.app.clone())
            .oneshot(ghost)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn l4_nested_use_chains_are_refused() {
    let fx = fx().await;
    // 85 groups of 3 uses each pointing at the previous group: under 256 uses, 3^85 instances.
    let mut chain = String::from(r#"<g id="a0"><rect width="1" height="1"/></g>"#);
    for n in 1..=85 {
        chain.push_str(&format!(
            r##"<g id="a{n}"><use href="#a{p}"/><use href="#a{p}"/><use href="#a{p}"/></g>"##,
            p = n - 1
        ));
    }
    let (s, v) = upload(&fx, "name=bomb.svg", svg_with(&chain).as_bytes()).await;
    assert_eq!(
        (s, &v["code"]),
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &json!("unsupported_type")
        )
    );
    // A use of a use, a use of an ancestor, and a forward reference are refused the same way.
    for bad in [
        r##"<use id="b" href="#a"/><use href="#b"/>"##,
        r##"<g id="a"><use href="#a"/></g>"##,
        r##"<use href="#a"/><g id="a"><g><use href="#x"/></g></g>"##,
    ] {
        assert_eq!(
            upload(&fx, "name=n.svg", svg_with(bad).as_bytes()).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{bad}"
        );
    }
    // A plain use of a plain shape stays.
    let ok = svg_with(
        r##"<defs><rect id="s" width="1" height="1"/></defs><use href="#s"/><use href="#s"/>"##,
    );
    assert_eq!(
        upload(&fx, "name=ok.svg", ok.as_bytes()).await.0,
        StatusCode::OK
    );
    assert_eq!(count(&fx, "design_assets").await, 1);
}
