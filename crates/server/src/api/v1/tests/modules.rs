//! A toy module loads through `Module` (E1-02.2) and sits behind the client gate.

use std::sync::Arc;

use axum::Router;
use axum::http::{Method, StatusCode};
use axum::routing::get;

use super::{fx, req, send};
use crate::api::App;
use crate::module::Module;

struct Ops;

impl Module for Ops {
    fn id(&self) -> &'static str {
        "ops"
    }

    fn routes(&self) -> Router<App> {
        Router::new().route("/ping", get(|| async { "pong" }))
    }
}

const PING: &str = "/modules/ops/v1/ping";

#[tokio::test]
async fn a_mounted_module_answers_behind_the_signature() {
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Ops) as Arc<dyn Module>]);

    let res = send(&fx.app, req(Method::GET, PING, Some(&fx.dev), None)).await;
    assert_eq!(res.0, StatusCode::OK);

    let stranger = fx.stranger();
    let (status, _) = send(&fx.app, req(Method::GET, PING, Some(&stranger), None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the gate covers module routes"
    );
}

#[tokio::test]
async fn an_unmounted_module_has_no_routes_and_no_scope() {
    let fx = fx().await;
    let (status, _) = send(&fx.app, req(Method::GET, PING, Some(&fx.dev), None)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no module, no declared scope"
    );
}

/// A terminal module: opening a terminal is destructive (E1-09.3's "done when", spec §8).
struct Term;

impl Module for Term {
    fn id(&self) -> &'static str {
        "term"
    }

    fn routes(&self) -> Router<App> {
        let open = axum::routing::post(|| async { "opened" });
        Router::new()
            .route("/terminals/{id}/open", open)
            .route("/terminals", get(|| async { "[]" }))
    }

    fn scope(&self) -> &'static str {
        "terminal"
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        &[("POST", "/terminals/{id}/open")]
    }
}

#[tokio::test]
async fn an_unelevated_terminal_open_is_refused_and_an_elevated_one_passes() {
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Term) as Arc<dyn Module>]);
    let mac = super::stepup::plain(&fx, "mac", &super::ALL, true).await;
    let open = "/modules/term/v1/terminals/t1/open";
    let (status, body) = send(&fx.app, req(Method::POST, open, Some(&mac), None)).await;
    assert_eq!(
        (status, &body["code"]),
        (
            StatusCode::FORBIDDEN,
            &serde_json::json!("step_up_required")
        )
    );
    let list = "/modules/term/v1/terminals";
    let (status, _) = send(&fx.app, req(Method::GET, list, Some(&mac), None)).await;
    assert_eq!(status, StatusCode::OK, "a read needs no step-up");
    assert_eq!(super::stepup::step_up(&fx, &mac).await.0, StatusCode::OK);
    let (status, _) = send(&fx.app, req(Method::POST, open, Some(&mac), None)).await;
    assert_eq!(status, StatusCode::OK);
    // A device without the module's scope is refused before elevation is even asked.
    let phone = fx.enroll("phone", &["read"]).await;
    let (status, body) = send(&fx.app, req(Method::POST, open, Some(&phone), None)).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &serde_json::json!("forbidden_scope"))
    );
}

/// A module with per-route scopes: reads for a phone, writes for an admin, the rest default.
struct Scoped(&'static str);

impl Module for Scoped {
    fn id(&self) -> &'static str {
        self.0
    }

    fn routes(&self) -> Router<App> {
        let ok = || async { "ok" };
        Router::new()
            .route("/items", get(ok).post(ok))
            .route("/items/{id}", get(ok).put(ok).delete(ok))
            .route("/items/export", get(ok))
            .route("/secret", get(ok))
            .route("/a/{x}/b", get(ok))
            .route("/a/b/{y}", get(ok))
    }

    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        &[
            ("GET", "/items", "read"),
            ("POST", "/items", "admin"),
            ("GET", "/items/{id}", "read"),
            ("PUT", "/items/{id}", "approve"),
            ("DELETE", "/items/{id}", "read"),
            ("GET", "/items/export", "admin"),
            ("GET", "/a/{x}/b", "read"),
            ("GET", "/a/b/{y}", "admin"),
        ]
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        &[("DELETE", "/items/{id}")]
    }
}

fn scoped_fx(fx: &mut super::Fx, ids: &[&'static str]) {
    let modules: Vec<Arc<dyn Module>> = ids.iter().map(|i| Arc::new(Scoped(i)) as _).collect();
    fx.app.modules = Arc::from(modules);
}

async fn status(fx: &super::Fx, dev: &super::TestDevice, m: Method, path: &str) -> StatusCode {
    send(&fx.app, req(m, path, Some(dev), None)).await.0
}

#[tokio::test]
async fn a_read_only_device_reaches_only_the_module_routes_that_declare_read() {
    let mut fx = fx().await;
    scoped_fx(&mut fx, &["sc"]);
    let phone = fx.enroll("phone", &["read"]).await;
    let (get_, post, put) = (Method::GET, Method::POST, Method::PUT);
    let b = "/modules/sc/v1";
    let ok = StatusCode::OK;
    let no = StatusCode::FORBIDDEN;
    // Declared read: through. Declared admin or approve: refused for a `read` device.
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/items")).await,
        ok
    );
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/items/7")).await,
        ok
    );
    assert_eq!(status(&fx, &phone, post, &format!("{b}/items")).await, no);
    assert_eq!(status(&fx, &phone, put, &format!("{b}/items/7")).await, no);
    // Not listed: the module-wide default (`admin`), deny by default.
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/secret")).await,
        no
    );
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/nothing-here")).await,
        no
    );
    // The literal route beats the `{id}` template that also fits it.
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/items/export")).await,
        no
    );
    // Two equally specific templates that disagree are a tie: the stricter scope (`admin`).
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/a/b/b")).await,
        no
    );
    assert_eq!(
        status(&fx, &phone, get_.clone(), &format!("{b}/a/q/b")).await,
        ok
    );
    // The admin device keeps all of it; a route is still real only if it exists.
    for p in ["/items", "/items/7", "/items/export", "/secret"] {
        assert_eq!(
            status(&fx, &fx.dev, get_.clone(), &format!("{b}{p}")).await,
            ok,
            "{p}"
        );
    }
    // Malformed prefixes never reach a module's table.
    for p in [
        "/modules/sc/v1",
        "/modules/sc/v1items",
        "/modules/sc/v2/items",
        "/modules/scx/v1/items",
        "/modules/sc",
    ] {
        assert_eq!(status(&fx, &phone, get_.clone(), p).await, no, "{p}");
    }
}

#[tokio::test]
async fn a_read_declared_destructive_route_still_needs_a_step_up() {
    let mut fx = fx().await;
    scoped_fx(&mut fx, &["sc"]);
    // `read` is enough for the scope, the elevation is not given: step_up_required.
    let phone = super::stepup::plain(&fx, "phone", &["read"], true).await;
    let (s, body) = send(
        &fx.app,
        req(Method::DELETE, "/modules/sc/v1/items/7", Some(&phone), None),
    )
    .await;
    assert_eq!(
        (s, &body["code"]),
        (
            StatusCode::FORBIDDEN,
            &serde_json::json!("step_up_required")
        )
    );
    // A device without the scope is refused on scope before elevation is asked.
    let none = fx.enroll("blind", &["agent"]).await;
    let (s, body) = send(
        &fx.app,
        req(Method::DELETE, "/modules/sc/v1/items/7", Some(&none), None),
    )
    .await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::FORBIDDEN, &serde_json::json!("forbidden_scope"))
    );
    assert_eq!(super::stepup::step_up(&fx, &phone).await.0, StatusCode::OK);
    assert_eq!(
        status(&fx, &phone, Method::DELETE, "/modules/sc/v1/items/7").await,
        StatusCode::OK
    );
}

/// A module's table only reaches its own routes: not the platform's, not another module's.
#[tokio::test]
async fn a_module_cannot_declare_scopes_for_other_modules_or_the_platform() {
    struct Grabby;
    impl Module for Grabby {
        fn id(&self) -> &'static str {
            "grab"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
            &[
                ("GET", "/api/v1/devices", "read"),
                ("GET", "/api/v1/audit", "read"),
                ("GET", "/modules/sc/v1/secret", "read"),
                ("GET", "/{x}", "read"),
            ]
        }
    }
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Scoped("sc")) as Arc<dyn Module>, Arc::new(Grabby)]);
    let phone = fx.enroll("phone", &["read"]).await;
    for p in [
        "/api/v1/devices",
        "/api/v1/audit",
        "/modules/sc/v1/secret",
        "/modules/sc/v1/items/export",
    ] {
        assert_eq!(
            status(&fx, &phone, Method::GET, p).await,
            StatusCode::FORBIDDEN,
            "{p}"
        );
    }
    // The same relative path in two modules is two routes with two tables: `grab` made `/{x}`
    // readable for itself (a 404 here: it has no routes), which did not open `sc`'s `/secret`.
    let (a, b) = (
        status(&fx, &phone, Method::GET, "/modules/sc/v1/items").await,
        status(&fx, &phone, Method::GET, "/modules/grab/v1/items").await,
    );
    assert_eq!((a, b), (StatusCode::OK, StatusCode::NOT_FOUND));
    assert_eq!(
        status(&fx, &phone, Method::GET, "/api/v1/me").await,
        StatusCode::OK
    );
}

#[test]
fn malformed_declarations_stop_the_server_at_mount() {
    struct M(
        &'static [(&'static str, &'static str, &'static str)],
        &'static str,
    );
    impl Module for M {
        fn id(&self) -> &'static str {
            "m"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
            self.0
        }
        fn scope(&self) -> &'static str {
            self.1
        }
    }
    let refused = |m: M| std::panic::catch_unwind(|| crate::module::validate(&m)).is_err();
    assert!(!refused(M(&[("GET", "/a/{id}", "read")], "admin")));
    for bad in [
        &[("GET", "/a", "root")][..],
        &[("GET", "/a", "runner")],
        &[("GET", "/a", "")],
        &[("GET", "a", "read")],
        &[("GET", "/../a", "read")],
        &[("GET", "/a//b", "read")],
        &[("GET", "/a/", "read")],
        &[("GET", "/a/{id", "read")],
        &[("GET", "/a/x{id}", "read")],
        &[("GET", "/a?x=1", "read")],
        &[("TRACE", "/a", "read")],
        &[("GET", "/a", "read"), ("GET", "/a", "admin")],
    ] {
        assert!(refused(M(bad, "admin")), "{bad:?}");
    }
    assert!(refused(M(&[], "superuser")), "an unknown module-wide scope");
}

fn toy_doc() -> serde_json::Value {
    serde_json::json!({
        "paths": {
            "/items": {
                "get": {"operationId": "sc_list_items", "responses": {"200": {"description": "ok"}},
                        "x-ainkrad-scope": "read", "security": [{}]},
                "post": {"operationId": "sc_add_item", "responses": {"200": {"description": "ok"}},
                         "x-ainkrad-destructive": false}
            },
            "/items/{id}": {
                "get": {"operationId": "sc_get_item", "responses": {"200": {"description": "ok"}}},
                "delete": {"operationId": "sc_del_item", "responses": {"204": {"description": "gone"}}}
            },
            "/secret": {"get": {"operationId": "sc_secret", "responses": {"200": {"description": "ok"}}}}
        },
        "components": {"schemas": {"ScItem": {"type": "object", "properties": {"id": {"type": "integer"}}}}}
    })
}

struct Doc(&'static str, serde_json::Value);
impl Module for Doc {
    fn id(&self) -> &'static str {
        self.0
    }
    fn routes(&self) -> Router<App> {
        Router::new()
    }
    fn openapi(&self) -> serde_json::Value {
        self.1.clone()
    }
    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        &[("GET", "/items", "read"), ("GET", "/items/{id}", "read")]
    }
    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        &[("DELETE", "/items/{id}")]
    }
}

#[test]
fn module_paths_join_the_contract_under_their_prefix_with_scopes_the_core_sets() {
    let spec: serde_json::Value = serde_json::from_str(&super::super::spec::json_for(&[Arc::new(
        Doc("sc", toy_doc()),
    )]))
    .unwrap();
    let p = &spec["paths"];
    let op = |path: &str, m: &str| p[format!("/modules/sc/v1{path}")][m].clone();
    // The scopes come from the module's tables, whatever the document said.
    assert_eq!(op("/items", "get")["x-ainkrad-scope"], "read");
    assert_eq!(op("/items", "post")["x-ainkrad-scope"], "admin");
    assert_eq!(op("/items/{id}", "get")["x-ainkrad-scope"], "read");
    assert_eq!(op("/items/{id}", "delete")["x-ainkrad-scope"], "admin");
    assert_eq!(op("/secret", "get")["x-ainkrad-scope"], "admin");
    // Destructive only where the module declares it; a written `false` does not survive.
    assert_eq!(op("/items/{id}", "delete")["x-ainkrad-destructive"], true);
    assert!(op("/items", "post").get("x-ainkrad-destructive").is_none());
    // A module cannot mark its operation pre-auth: `security` is the platform's, global.
    assert!(op("/items", "get").get("security").is_none());
    assert_eq!(
        spec["security"],
        serde_json::json!([{"device_signature": []}])
    );
    // The shared error answers apply, the schema is there, the platform's paths are intact.
    assert!(op("/items", "get")["responses"]["403"]["$ref"].is_string());
    assert!(spec["components"]["schemas"]["ScItem"].is_object());
    assert!(p["/api/v1/me"]["get"]["x-ainkrad-scope"] == "read");
    let platform: serde_json::Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    for path in platform["paths"].as_object().unwrap().keys() {
        assert!(p.get(path).is_some(), "{path} lost");
    }
}

/// Every module operation of the contract: a `read` device is refused exactly where the
/// contract's own `x-ainkrad-scope` is not `read`/`approve`, a `runner` everywhere.
#[tokio::test]
async fn the_gate_enforces_what_the_contract_says_for_every_module_operation() {
    let mut fx = fx().await;
    let module: Arc<dyn Module> = Arc::new(Doc("sc", toy_doc()));
    fx.app.modules = Arc::from([module.clone()]);
    let spec: serde_json::Value =
        serde_json::from_str(&super::super::spec::json_for(&[module])).unwrap();
    let phone = fx.enroll("phone", &["read", "approve"]).await;
    let mut n = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        if !path.starts_with("/modules/sc/v1/") {
            continue;
        }
        for (m, op) in item.as_object().unwrap() {
            let scope = op["x-ainkrad-scope"]
                .as_str()
                .expect("module op without a scope");
            let uri = path.replace("{id}", "7");
            let method: Method = m.to_uppercase().parse().unwrap();
            let (s, body) = send(&fx.app, req(method, &uri, Some(&phone), None)).await;
            let refused = s == StatusCode::FORBIDDEN && body["code"] == "forbidden_scope";
            assert_eq!(
                refused,
                !["read", "approve"].contains(&scope),
                "{m} {uri}: {s} {body}"
            );
            n += 1;
        }
    }
    assert_eq!(n, 5);
}

#[test]
#[should_panic(expected = "operationId")]
fn a_module_operation_id_that_is_taken_stops_the_contract() {
    let mut doc = toy_doc();
    doc["paths"]["/items"]["get"]["operationId"] = serde_json::json!("getMe");
    let _ = super::super::spec::json_for(&[Arc::new(Doc("sc", doc))]);
}

#[test]
#[should_panic(expected = "operationId")]
fn two_modules_cannot_share_an_operation_id() {
    let _ = super::super::spec::json_for(&[
        Arc::new(Doc("sc", toy_doc())),
        Arc::new(Doc("sd", toy_doc())),
    ]);
}

#[test]
#[should_panic(expected = "schema")]
fn a_module_schema_cannot_redefine_a_platform_one() {
    let mut doc = toy_doc();
    doc["components"]["schemas"]["ErrorBody"] = serde_json::json!({"type": "string"});
    let _ = super::super::spec::json_for(&[Arc::new(Doc("sc", doc))]);
}

struct Query(&'static str, &'static [&'static str]);
impl Module for Query {
    fn id(&self) -> &'static str {
        self.0
    }
    fn routes(&self) -> Router<App> {
        Router::new().route("/things", get(|| async { "ok" }))
    }
    fn query_names(&self) -> &'static [&'static str] {
        self.1
    }
}

/// A module's extra query names work on its own routes only, and the platform's names still
/// work everywhere; anything else is a 400.
#[tokio::test]
async fn a_module_query_name_is_allowed_on_its_own_routes_only() {
    let mut fx = fx().await;
    fx.app.modules = Arc::from([
        Arc::new(Query("qa", &["pending", "since"])) as Arc<dyn Module>,
        Arc::new(Query("qb", &[])),
    ]);
    let go = |p: &'static str| {
        let (fx, dev) = (&fx, &fx.dev);
        async move { send(&fx.app, req(Method::GET, p, Some(dev), None)).await.0 }
    };
    assert_eq!(
        go("/modules/qa/v1/things?pending=1&since=2&limit=5").await,
        StatusCode::OK
    );
    assert_eq!(
        go("/modules/qa/v1/things?pending=1&token=x").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        go("/modules/qa/v1/things?other=1").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        go("/modules/qb/v1/things?pending=1").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(go("/modules/qb/v1/things?limit=5").await, StatusCode::OK);
    assert_eq!(go("/api/v1/me?pending=1").await, StatusCode::BAD_REQUEST);
}

#[test]
fn a_query_name_that_could_carry_a_secret_is_refused_at_mount() {
    for bad in ["token", "api_key", "Pending", "x-y", ""] {
        let names: &'static [&'static str] = Box::leak(Box::new([bad]));
        let m = Query("qa", names);
        assert!(
            std::panic::catch_unwind(|| crate::module::validate(&m)).is_err(),
            "{bad:?}"
        );
    }
}

/// Defence in depth: `mount` refuses a `runner` route scope, and a gate reading an unvalidated
/// table (a test wiring `app.modules` directly) still treats it as `admin`.
#[test]
fn a_declared_runner_scope_is_never_honoured() {
    struct Runnerish;
    impl Module for Runnerish {
        fn id(&self) -> &'static str {
            "rn"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
            &[("GET", "/bad", "runner"), ("GET", "/odd", "nonsense")]
        }
    }
    use super::super::scopes::module_scope;
    assert_eq!(module_scope(&Runnerish, "GET", "/bad"), "admin");
    assert_eq!(module_scope(&Runnerish, "GET", "/odd"), "admin");
    assert!(std::panic::catch_unwind(|| crate::module::validate(&Runnerish)).is_err());
}

/// F4: a tie takes the stricter scope, even when the module-wide scope is lower than both.
#[test]
fn a_tie_resolves_to_the_stricter_scope_not_the_module_scope() {
    struct Low;
    impl Module for Low {
        fn id(&self) -> &'static str {
            "low"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn scope(&self) -> &'static str {
            "read"
        }
        fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
            &[
                ("GET", "/a/{x}/b", "admin"),
                ("GET", "/a/q/{y}", "read"),
                ("GET", "/c/{x}/d", "approve"),
                ("GET", "/c/e/{y}", "agent"),
            ]
        }
    }
    use super::super::scopes::module_scope;
    assert_eq!(module_scope(&Low, "GET", "/a/q/b"), "admin");
    assert_eq!(module_scope(&Low, "GET", "/a/q/zzz"), "read");
    // Different scopes of the same rank cannot be compared: `admin`.
    assert_eq!(module_scope(&Low, "GET", "/c/e/d"), "admin");
}

/// F5: HEAD is the GET it is served by (scope and step-up); a method no module route takes
/// needs `admin`.
#[tokio::test]
async fn head_gets_the_scope_and_step_up_of_its_get() {
    struct Ws;
    impl Module for Ws {
        fn id(&self) -> &'static str {
            "ws"
        }
        fn routes(&self) -> Router<App> {
            Router::new().route("/open", get(|| async { "ok" }))
        }
        fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
            &[("GET", "/open", "read")]
        }
        fn destructive(&self) -> &'static [(&'static str, &'static str)] {
            &[("GET", "/open")]
        }
    }
    use super::super::scopes::{module_destructive, module_scope};
    assert_eq!(module_scope(&Ws, "HEAD", "/open"), "read");
    assert!(module_destructive(&Ws, "HEAD", "/open"));
    assert_eq!(module_scope(&Ws, "OPTIONS", "/open"), "admin");
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Ws) as Arc<dyn Module>]);
    // Not elevated: a destructive GET is refused for HEAD as for GET.
    let mac = super::stepup::plain(&fx, "mac", &super::ALL, true).await;
    for m in [Method::GET, Method::HEAD] {
        let (s, _) = send(
            &fx.app,
            req(m.clone(), "/modules/ws/v1/open", Some(&mac), None),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m}");
    }
}

/// F2: a `destructive` or route-scope entry that matches no documented route stops the server
/// at start (a typo must never leave a route without its step-up); so do malformed entries.
#[test]
fn a_destructive_entry_that_matches_no_route_is_refused_at_mount() {
    struct Typo(
        &'static [(&'static str, &'static str)],
        &'static [(&'static str, &'static str, &'static str)],
    );
    impl Module for Typo {
        fn id(&self) -> &'static str {
            "ty"
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn openapi(&self) -> serde_json::Value {
            toy_doc()
        }
        fn destructive(&self) -> &'static [(&'static str, &'static str)] {
            self.0
        }
        fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
            self.1
        }
    }
    let refused = |m: Typo| std::panic::catch_unwind(|| crate::module::validate(&m)).is_err();
    assert!(!refused(Typo(
        &[("DELETE", "/items/{id}")],
        &[("GET", "/items", "read")]
    )));
    for bad in [
        &[("DELETE", "/item/{id}")][..],
        &[("DELETE", "/items/{x}")],
        &[("POST", "/items/{id}")],
        &[("TRACE", "/items")],
        &[("DELETE", "items/{id}")],
        &[("DELETE", "/items/../x")],
        &[("DELETE", "/items/{id}"), ("DELETE", "/items/{id}")],
    ] {
        assert!(refused(Typo(bad, &[])), "{bad:?}");
    }
    assert!(
        refused(Typo(&[], &[("GET", "/itemz", "read")])),
        "a dead route scope"
    );
}
