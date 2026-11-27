//! The preview proxy (API 110): a project's running app through the client API, behind the
//! device's own signature, so the app can show a PRIVATE run (`expose` off) in a web view.
//!
//! SECURITY MODEL.
//! - **Signed, every request.** `/api/v1/projects/{id}/preview/{path}` is an ordinary client route:
//!   the gate verifies the device's signature over the method, path, query and body before this
//!   runs, so there is no bearer token, cookie or link to leak. The Mac app serves the preview
//!   from its own URL scheme (`WKURLSchemeHandler`) and signs each request itself, sub-resources
//!   included; a browser cannot sign a navigation, so a page elsewhere gets 401.
//! - **Scope.** `GET` and `HEAD` need `read`: viewing the running app is the point, as the Run
//!   page already shows it (decided for #530). Any other method needs `admin`, since a form posted
//!   to the app changes the app's data. None needs a step-up.
//! - **Same target as the public link.** Only a `running` run, and only the port the run's own
//!   spec version marks `expose: true` (`web`'s, else the first service's by name), which the
//!   runner checks again. `expose` on the project is NOT required: that is the point.
//! - **Same headers as the public link** (`gateway::projects`): hop-by-hop, proxy, `X-Ainkrad-*`
//!   and the signed request's own `Ainkrad-*` headers are dropped; `X-Forwarded-*` are ours
//!   (`Host: localhost`, which development servers accept); `Set-Cookie` loses its `Domain`.
//! - **Answers stay inside the preview** ([`answer`]). All previews share the Core's host, so a
//!   cookie's `Path` is moved under `/api/v1/projects/{id}/preview` (one project's cookies never
//!   reach another's); a `Location` of `/x` becomes `<that prefix>/x`, one to the app's own
//!   `localhost` is made relative, one to any other site is refused (502 `redirect_refused`).
//!   `Cache-Control: no-store`, `Cross-Origin-Resource-Policy: same-origin` and the [`SANDBOX`]
//!   CSP are set; `Access-Control-*`, `Clear-Site-Data`, `Strict-Transport-Security`, `Alt-Svc` and
//!   `Service-Worker-Allowed` are dropped (they would act on the Core's host).
//! - **Why that CSP.** `sandbox` without `allow-same-origin` gives the document an opaque origin
//!   wherever a browser renders it, so even rendered as a page of the Core's host it reaches none
//!   of the Core's storage or signed routes, and `frame-ancestors 'none'` stops framing it.
//!   With `allow-same-origin` the sandbox would protect nothing (scripts could lift it), so that
//!   variant was not picked. The Mac app's own scheme is a separate origin already: its scheme
//!   handler drops exactly this one header value before handing the answer to the web view, so
//!   the app keeps its storage and same-origin requests there.
//! - **Limits.** The signed body cap (1 MiB), the device's request bucket, [`PER_DEVICE`] in
//!   flight per device and [`PER_PROJECT`] per project, the response head within 25 s and the
//!   whole answer within 10 minutes.
//!   Any query names pass (they are the app's, and signed). Not carried: WebSocket upgrades
//!   (a web view's scheme handler cannot carry one), CONNECT.
//! - **Not activity.** A preview does not push the idle stop back (a thumbnail would keep a run
//!   alive forever); the app says a person is looking with `POST /run/activity`.
//! - **Never under the Core's origin.** The answer is the project's own HTML: a client must not
//!   render it as a page of the Core's web origin. The Mac app renders it under its own scheme.

use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use super::super::{ApiError, Caller};
use super::num;
use crate::api::App;
use crate::gateway::projects::{PER_DEVICE, PER_PROJECT, exchange, inbound, outbound, target};
use crate::store::{projects as store, run_specs, runs};
use ainkrad_proto::v2::PortOpen;

/// The route's prefix: `/api/v1/projects/<id>/preview`.
const PREFIX: &str = "/api/v1/projects/";

/// `(project id, the project's path)` of a preview path: `/api/v1/projects/7/preview/a/b` is
/// `("7", "/a/b")`; `None` for any other path.
pub fn split(path: &str) -> Option<(&str, &str)> {
    let (id, rest) = path.strip_prefix(PREFIX)?.split_once('/')?;
    let rest = rest.strip_prefix("preview")?;
    rest.starts_with('/').then_some((id, rest))
}

/// Whether `path` is a preview route: its query is the project's, so any names pass.
pub fn is_preview(path: &str) -> bool {
    split(path).is_some()
}

fn refused(status: StatusCode, code: &'static str, why: &str) -> Response {
    ApiError::new(status, code, why).into_response()
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/preview/{path}", operation_id = "previewProject",
    tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("path" = String, Path, description = "The path on the running app, slashes included \
               (`/api/v1/projects/7/preview/` is its `/`); the query string is passed on as is")),
    responses((status = 200, description = "The running app's own answer, any status, for a \
        private run too (API 110). The same verb works for POST, PUT, PATCH, DELETE, OPTIONS \
        (scope `admin`) and HEAD. Every request, sub-resources included, is signed by the device \
        as any other; the Mac app serves it from its own URL scheme. 409 `not_running` when the \
        project has no running run (the words say why), 409 `no_preview` when no service has an \
        exposed port, 404 for no such project; 503 `busy` (with `Retry-After`) past 6 requests in \
        flight for the device or 8 for the project or the runner (`busy`); 502 \
        `runner_unreachable` when the runner cannot be reached, 504 `timeout`; 502 \
        `redirect_refused` when the app redirects to another site (504 after 25 s with no \
        answer). No WebSocket upgrade. GET and HEAD are `read` on purpose: viewing is the \
        point. Answers: `Set-Cookie` paths and `Location` are moved under \
        `/api/v1/projects/{id}/preview`; `Cache-Control: no-store`, \
        `Cross-Origin-Resource-Policy: same-origin` and the CSP `sandbox allow-scripts \
        allow-forms allow-popups allow-modals allow-downloads; frame-ancestors 'none'` are set \
        (the Mac app drops that one CSP value under its own scheme); `Access-Control-*`, \
        `Clear-Site-Data`, `Strict-Transport-Security`, `Alt-Svc` and `Service-Worker-Allowed` \
        are dropped. The client sends no `Origin` or `Authorization` (both refused) and writes \
        percent-escapes upper case")))]
pub async fn preview(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    req: Request,
) -> Response {
    forward(app, &me.device.id, req).await.unwrap_or_else(|r| r)
}

#[allow(clippy::result_large_err)]
async fn forward(app: App, device: &str, req: Request) -> Result<Response, Response> {
    let Some((id, path)) = split(req.uri().path()) else {
        return Err(ApiError::not_found("no such route").into_response());
    };
    let id = num(id, "project").map_err(IntoResponse::into_response)?;
    if req.method() == Method::CONNECT {
        let why = "CONNECT is not proxied";
        return Err(refused(StatusCode::METHOD_NOT_ALLOWED, "bad_request", why));
    }
    let db = |e: sqlx::Error| ApiError::from(e).into_response();
    let mut conn = app.pool.acquire().await.map_err(db)?;
    let project = store::get(&mut conn, id)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    drop(conn);
    let run = runs::live(&app.pool, id).await.map_err(db)?;
    let run = match run {
        Some(r) if r.state == "running" => r,
        Some(r) if r.state == "starting" => {
            let why = "the project is still starting; try again when it is running";
            return Err(refused(StatusCode::CONFLICT, "not_running", why));
        }
        _ => {
            let why = "the project is not running; start it to see its preview";
            return Err(refused(StatusCode::CONFLICT, "not_running", why));
        }
    };
    let spec = run_specs::version(&app.pool, id, run.spec_version)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    let Some((service, port)) = target(&spec.spec, None) else {
        let why = "no service of this project has an exposed port to preview";
        return Err(refused(StatusCode::CONFLICT, "no_preview", why));
    };
    let permit = app.preview.hold(project.id, device).map_err(|full| {
        let why = match full {
            "device" => {
                format!("{PER_DEVICE} preview requests of this device are in flight; try again")
            }
            _ => format!("{PER_PROJECT} preview requests of this project are in flight; try again"),
        };
        let mut r = refused(StatusCode::SERVICE_UNAVAILABLE, "busy", &why);
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        r
    })?;
    // The project sees its own path: `/preview/a?b` is `/a?b`.
    let target_uri = match req.uri().query() {
        None => path.to_owned(),
        Some(q) => format!("{path}?{q}"),
    };
    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri
        .parse::<Uri>()
        .map_err(|_| ApiError::bad_request("a bad path").into_response())?;
    let out = outbound(
        Request::from_parts(parts, body),
        "localhost",
        None,
        false,
        false,
    );
    let open = PortOpen {
        project: u64::try_from(project.id).unwrap_or(0),
        run: run.id.clone(),
        service,
        port,
    };
    let dial = app.preview.dial(&app);
    let resp = exchange(&*dial, &run.runner, open, out, permit)
        .await
        .map_err(|page| failed(page.status()))?;
    // Nobody asked for an upgrade: a 101 is not passed on.
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let why = "the project answered with an upgrade nobody asked for";
        return Err(refused(StatusCode::BAD_GATEWAY, "runner_error", why));
    }
    let mut out = inbound(resp, false);
    let prefix = format!("/api/v1/projects/{id}/preview");
    if let Err(why) = answer(out.headers_mut(), &prefix) {
        return Err(refused(StatusCode::BAD_GATEWAY, "redirect_refused", why));
    }
    Ok(out)
}

/// The Core's own JSON refusal (with `Ainkrad-Refusal`) for an exchange that failed, in place of
/// the public link's HTML page of the same status.
fn failed(status: StatusCode) -> Response {
    match status {
        StatusCode::SERVICE_UNAVAILABLE => {
            let why = "the runner is too busy to open the preview; try again";
            let mut r = refused(status, "busy", why);
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            r
        }
        StatusCode::GATEWAY_TIMEOUT => {
            let why = "the project's app did not answer in 25 seconds";
            refused(status, "timeout", why)
        }
        _ => {
            let why = "the project's runner could not be reached";
            refused(StatusCode::BAD_GATEWAY, "runner_unreachable", why)
        }
    }
}

/// What every preview answer carries: an opaque-origin sandbox, so wherever a browser renders
/// it as a page it holds no origin of the Core's (no storage, no same-origin request, no cookie
/// of it). The Mac app renders previews under its own scheme, which is its own origin: it drops
/// exactly this header value there (and keeps any CSP the project sent).
pub const SANDBOX: &str = "sandbox allow-scripts allow-forms allow-popups allow-modals \
    allow-downloads; frame-ancestors 'none'";

/// Answer headers that would act on the Core's host rather than the project's page.
const DROPPED: [&str; 4] = [
    "clear-site-data",
    "strict-transport-security",
    "alt-svc",
    "service-worker-allowed",
];

/// Makes a preview answer safe to hand out under the Core's host: a `Location` stays inside the
/// preview (`/x` is `<prefix>/x`, an absolute one to the app's own `localhost` is made relative,
/// one to anywhere else is refused: `Err`), each `Set-Cookie` gets a `Path` under `prefix` (one
/// project's cookies never reach another's preview), the headers in [`DROPPED`] and every
/// `Access-Control-*` go, and `Cache-Control: no-store`, [`SANDBOX`] and
/// `Cross-Origin-Resource-Policy: same-origin` are set.
pub fn answer(h: &mut HeaderMap, prefix: &str) -> Result<(), &'static str> {
    if let Some(loc) = h.get(header::LOCATION) {
        let loc = loc
            .to_str()
            .map_err(|_| "the app sent a redirect that is not text")?;
        let inside = |p: &str| HeaderValue::from_str(&format!("{prefix}{p}")).ok();
        let new = match scheme_or_authority(loc) {
            false if loc.starts_with('/') => inside(loc),
            // Relative to the page: it stays inside the preview by itself.
            false => Some(HeaderValue::from_str(loc).map_err(|_| "a bad redirect")?),
            true => match loc.parse::<Uri>() {
                Ok(u)
                    if matches!(u.scheme_str(), Some("http" | "https"))
                        && u.host()
                            .is_some_and(|h| h.eq_ignore_ascii_case("localhost")) =>
                {
                    inside(u.path_and_query().map_or("/", |p| p.as_str()))
                }
                _ => {
                    return Err(
                        "the app redirected to another site, which a preview does not follow",
                    );
                }
            },
        };
        let new = new.ok_or("a bad redirect")?;
        h.insert(header::LOCATION, new);
    }
    let cookies: Vec<HeaderValue> = h
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| HeaderValue::from_str(&scoped(v.to_str().ok()?, prefix)).ok())
        .collect();
    h.remove(header::SET_COOKIE);
    for c in cookies {
        h.append(header::SET_COOKIE, c);
    }
    let cors: Vec<_> = h
        .keys()
        .filter(|k| k.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for k in cors {
        h.remove(k);
    }
    for d in DROPPED {
        h.remove(d);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.append(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(SANDBOX),
    );
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    Ok(())
}

/// Whether a `Location` names a scheme (`x:` before any `/`, `?` or `#`) or an authority (`//`).
fn scheme_or_authority(loc: &str) -> bool {
    loc.starts_with("//")
        || loc
            .find(':')
            .is_some_and(|i| !loc[..i].contains(['/', '?', '#']))
}

/// A `Set-Cookie` whose `Path` is under `prefix`: `Path=/a` is `Path=<prefix>/a`; none is
/// `Path=<prefix>/`.
fn scoped(cookie: &str, prefix: &str) -> String {
    let mut found = false;
    let mut parts: Vec<String> = cookie
        .split(';')
        .enumerate()
        .map(|(i, a)| {
            let t = a.trim();
            let path = t
                .split_once('=')
                .filter(|(n, _)| i > 0 && n.trim().eq_ignore_ascii_case("path"));
            match path {
                Some((_, p)) => {
                    found = true;
                    let p = p.trim();
                    let p = if p.starts_with('/') { p } else { "/" };
                    format!(" Path={prefix}{p}")
                }
                None if i == 0 => a.to_owned(),
                None => format!(" {t}"),
            }
        })
        .collect();
    if !found {
        parts.push(format!(" Path={prefix}/"));
    }
    parts.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "/api/v1/projects/7/preview";

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(*n, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn a_cookie_is_scoped_to_its_projects_preview() {
        let mut h = headers(&[
            ("set-cookie", "sid=1; Path=/; HttpOnly"),
            ("set-cookie", "a=2; path=/admin; Secure"),
            ("set-cookie", "b=3"),
            ("set-cookie", "c=4; Path=x"),
        ]);
        answer(&mut h, P).unwrap();
        let got: Vec<&str> = h
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            got,
            [
                "sid=1; Path=/api/v1/projects/7/preview/; HttpOnly",
                "a=2; Path=/api/v1/projects/7/preview/admin; Secure",
                "b=3; Path=/api/v1/projects/7/preview/",
                "c=4; Path=/api/v1/projects/7/preview/",
            ]
        );
    }

    #[test]
    fn a_redirect_stays_inside_the_preview_or_is_refused() {
        for (loc, want) in [
            ("/login?next=/", "/api/v1/projects/7/preview/login?next=/"),
            (
                "http://localhost:3000/a?b=1",
                "/api/v1/projects/7/preview/a?b=1",
            ),
            ("https://LOCALHOST/", "/api/v1/projects/7/preview/"),
            ("next", "next"),
            ("../up", "../up"),
        ] {
            let mut h = HeaderMap::new();
            h.insert(header::LOCATION, HeaderValue::from_str(loc).unwrap());
            answer(&mut h, P).unwrap();
            assert_eq!(h[header::LOCATION], want, "{loc}");
        }
        for loc in [
            "https://evil.test/x",
            "//evil.test/x",
            "javascript:alert(1)",
            "http://localhost.evil.test/",
            "ftp://localhost/x",
        ] {
            let mut h = HeaderMap::new();
            h.insert(header::LOCATION, HeaderValue::from_str(loc).unwrap());
            assert!(answer(&mut h, P).is_err(), "{loc}");
        }
    }

    #[test]
    fn host_wide_headers_go_and_the_sandbox_is_set() {
        let mut h = headers(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
            ("clear-site-data", "\"*\""),
            ("strict-transport-security", "max-age=1"),
            ("alt-svc", "h3=\":443\""),
            ("service-worker-allowed", "/"),
            ("cache-control", "max-age=3600"),
            ("content-security-policy", "default-src 'self'"),
            ("content-type", "text/html"),
        ]);
        answer(&mut h, P).unwrap();
        let mut names: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "cache-control",
                "content-security-policy",
                "content-type",
                "cross-origin-resource-policy"
            ]
        );
        assert_eq!(h["cache-control"], "no-store");
        assert_eq!(h["cross-origin-resource-policy"], "same-origin");
        let csp: Vec<&str> = h
            .get_all("content-security-policy")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        // The project's own policy stays; ours is added.
        assert_eq!(csp, ["default-src 'self'", SANDBOX]);
        assert!(!SANDBOX.contains("allow-same-origin"));
    }

    #[test]
    fn only_a_preview_path_splits() {
        assert_eq!(split("/api/v1/projects/7/preview"), None);
        assert_eq!(split("/api/v1/projects/7/preview/"), Some(("7", "/")));
        assert_eq!(
            split("/api/v1/projects/7/preview/a/b.js"),
            Some(("7", "/a/b.js"))
        );
        for not in [
            "/api/v1/projects/7/previews",
            "/api/v1/projects/7/run",
            "/api/v1/projects/preview/x",
            "/api/v1/other/7/preview/x",
            "/modules/x/v1/projects/7/preview/x",
        ] {
            assert!(!is_preview(not), "{not}");
        }
    }
}
