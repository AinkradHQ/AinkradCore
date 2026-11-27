//! The preview proxy (API 110): a project's running app through the client API, behind the
//! device's own signature, so the app can show a PRIVATE run (`expose` off) in a web view.
//!
//! SECURITY MODEL.
//! - **Signed, every request.** `/api/v1/projects/{id}/preview/{path}` is an ordinary client route:
//!   the gate verifies the device's signature over the method, path, query and body before this
//!   runs, so there is no bearer token, cookie or link to leak. The Mac app serves the preview
//!   from its own URL scheme (`WKURLSchemeHandler`) and signs each request itself, sub-resources
//!   included; a browser cannot sign a navigation, so a page elsewhere gets 401.
//! - **Scope.** `GET` and `HEAD` need `read` (what the Run page already shows); any other method
//!   needs `admin`, since a form posted to the app changes the app's data.
//! - **Same target as the public link.** Only a `running` run, and only the port the run's own
//!   spec version marks `expose: true` (`web`'s, else the first service's by name), which the
//!   runner checks again. `expose` on the project is NOT required: that is the point.
//! - **Same headers as the public link** (`gateway::projects`): hop-by-hop, proxy, `X-Ainkrad-*`
//!   and the signed request's own `Ainkrad-*` headers are dropped; `X-Forwarded-*` are ours
//!   (`Host: localhost`, which development servers accept); `Set-Cookie` loses its `Domain`.
//! - **Limits.** The signed body cap (1 MiB), the device's request bucket, [`PER_PROJECT`] in
//!   flight per project, the response head within 25 s and the whole answer within 10 minutes.
//!   Any query names pass (they are the app's, and signed). Not carried: WebSocket upgrades
//!   (a web view's scheme handler cannot carry one), CONNECT.
//! - **Not activity.** A preview does not push the idle stop back (a thumbnail would keep a run
//!   alive forever); the app says a person is looking with `POST /run/activity`.
//! - **Never under the Core's origin.** The answer is the project's own HTML: a client must not
//!   render it as a page of the Core's web origin. The Mac app renders it under its own scheme.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use super::super::ApiError;
use super::num;
use crate::api::App;
use crate::gateway::projects::{PER_PROJECT, exchange, inbound, outbound, target};
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
        exposed port, 404 for no such project; 503 `busy` (with `Retry-After`) past 8 requests in \
        flight for the project; 502 when the runner cannot be reached, 504 when the app does not \
        answer in 25 s. No WebSocket upgrade")))]
pub async fn preview(State(app): State<App>, req: Request) -> Response {
    forward(app, req).await.unwrap_or_else(|r| r)
}

#[allow(clippy::result_large_err)]
async fn forward(app: App, req: Request) -> Result<Response, Response> {
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
    let Some(permit) = app.preview.hold(project.id) else {
        let mut r = refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            &format!("{PER_PROJECT} preview requests are in flight; try again"),
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return Err(r);
    };
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
    let resp = exchange(&*dial, &run.runner, open, out, permit).await?;
    // Nobody asked for an upgrade: a 101 is not passed on.
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let why = "the project answered with an upgrade nobody asked for";
        return Err(refused(StatusCode::BAD_GATEWAY, "runner_error", why));
    }
    Ok(inbound(resp, false))
}

#[cfg(test)]
mod tests {
    use super::*;

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
