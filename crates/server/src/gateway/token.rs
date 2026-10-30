//! The token gate: the one place a request is answered without a device signature other than the
//! pre-auth routes (`preauth`). A module declares the routes (`Module::token_routes`) and checks
//! the bearer token itself (`Module::verify_token`); this gate carries everything around it.
//!
//! A token route lives at `/token/<module id>/v1<template>`: a prefix of its own, so the signed
//! gate's deny-by-default scope tables are neither consulted nor loosened for it, and no signed
//! route is reachable through it. The route set is the module's declared list and nothing else
//! (`module::mount_token` builds the router from it; `resolve` looks the request up in it again).
//!
//! In order: an undeclared path or method is the same 401 an unsigned unknown path gets (no
//! enumeration) → the `Host` → no `Origin` and no `Cookie` (no browser reaches it; no CORS header
//! is ever sent) → a canonical path → no query string (a token is never in a URL) → exactly one
//! `Authorization: Bearer <token>` of a bounded charset → `Content-Length` within the route's cap
//! (413) → the source address's lockout (429) → the module's check. A refusal there takes at least
//! `FAIL_FLOOR`, is counted against the address (`tok:<addr>`, the `ADDRESS` rule, audited as
//! `auth.lockout`) and is one identical 401 whatever the reason. Then the principal's rate bucket
//! (429), and only now is the body read, up to the cap, so an unauthenticated request never makes
//! the server buffer it. The log carries the module and the address, never the token.

use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::v1::gate::{address, auth_failed};
use crate::api::v1::{ApiError, too_many};
use crate::api::{App, refusal};
use crate::module::{Module, TokenPrincipal, TokenRoute};
use crate::store::gov::{self, ADDRESS};

/// The prefix every token route lives under.
pub const PREFIX: &str = "/token/";

/// The least time a refused token takes, as the signed gate's (`FAIL_FLOOR`): the lookup's own
/// jitter says nothing about why it failed.
pub const FAIL_FLOOR: std::time::Duration = std::time::Duration::from_millis(50);

/// The longest bearer token accepted.
pub const TOKEN_MAX: usize = 128;

/// Whether `template` (`/a/{b}`) fits `path` segment by segment.
fn fits(template: &str, path: &str) -> bool {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(t, p)| (t.starts_with('{') && t.ends_with('}') && !p.is_empty()) || t == p)
}

/// The module and declared route a request is for, if any.
pub fn resolve<'a>(
    modules: &'a [Arc<dyn Module>],
    method: &Method,
    path: &str,
) -> Option<(&'a Arc<dyn Module>, TokenRoute)> {
    let rest = path.strip_prefix(PREFIX)?;
    let (id, sub) = rest.split_once('/')?;
    let sub = sub.strip_prefix("v1")?;
    if !sub.starts_with('/') {
        return None;
    }
    let module = modules.iter().find(|m| m.id() == id)?;
    let route = module
        .token_routes()
        .iter()
        .find(|r| r.method == method.as_str() && fits(r.template, sub))?;
    Some((module, *route))
}

/// Every request that is answered without a signature, as `(method, path)`: the pre-auth
/// prefixes (`ANY`) and the declared token routes of `modules`. The one list a review reads.
pub fn unsigned_routes(modules: &[Arc<dyn Module>]) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = crate::gateway::preauth::ALLOWED
        .iter()
        .map(|p| ("ANY".to_owned(), (*p).to_owned()))
        .collect();
    for m in modules {
        for r in m.token_routes() {
            all.push((
                r.method.to_owned(),
                format!("{PREFIX}{}/v1{}", m.id(), r.template),
            ));
        }
    }
    all
}

fn refuse(status: StatusCode, code: &'static str, why: &'static str) -> Response {
    ApiError::new(status, code, why).into_response()
}

/// A syntactically possible token: the bearer's charset and bound, nothing more.
fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let mut all = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(one), None) = (all.next(), all.next()) else {
        return None;
    };
    let token = one.to_str().ok()?.strip_prefix("Bearer ")?;
    let ok = !token.is_empty()
        && token.len() <= TOKEN_MAX
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    ok.then_some(token)
}

/// The gate for one resolved token route (`preauth::gated` calls it).
pub async fn gate(
    State(app): State<App>,
    module: Arc<dyn Module>,
    route: TokenRoute,
    req: Request,
    next: Next,
) -> Response {
    // The shared checks (Host, canonical path), on the headers without the bearer, which is
    // what this gate is for; an `Origin` of any kind is refused (no browser is a client).
    let mut plain = req.headers().clone();
    plain.remove(header::AUTHORIZATION);
    if plain.contains_key(header::ORIGIN) {
        return refuse(
            StatusCode::FORBIDDEN,
            "origin_refused",
            "no browser origin may call this",
        );
    }
    if let Some((status, code, why)) = refusal(&app, req.uri(), &plain, str::is_empty) {
        return refuse(status, code, why);
    }
    if req.headers().contains_key(header::COOKIE) {
        return refuse(StatusCode::BAD_REQUEST, "bad_request", "no cookies");
    }
    if req.uri().query().is_some() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "a token route takes no query string",
        );
    }
    let length = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<usize>().ok());
    if length.is_some_and(|n| n > route.max_body) {
        return crate::gateway::preauth::too_large();
    }
    let (mut parts, raw) = req.into_parts();
    let addr = address(&app, &parts);
    let key = format!("tok:{addr}");
    let now = app.clock.unix();
    let started = tokio::time::Instant::now();
    let token = bearer(&parts.headers).map(str::to_owned);
    let grant = match &token {
        Some(t) => module.verify_token(&app, t).await,
        None => None,
    };
    // The token is verified first and only a failure counts or is locked out: a valid token is
    // never blocked, so a flood of junk from a shared address cannot switch the route off for
    // the runs behind it.
    let Some(grant) = grant else {
        tracing::warn!(addr, module = module.id(), "token request refused");
        let resp = match gov::locked_until(&app.pool, &[&key], now).await {
            Ok(Some(until)) => too_many(std::time::Duration::from_secs((until - now).max(1) as u64)),
            Err(e) => ApiError::from(e).into_response(),
            Ok(None) if app.auth.token_failures.count(&addr, now) => {
                match gov::record_failure(&app.pool, &key, ADDRESS, now).await {
                    Ok(_) => auth_failed().into_response(),
                    Err(e) => ApiError::from(e).into_response(),
                }
            }
            Ok(None) => too_many(std::time::Duration::from_secs(ADDRESS.lock as u64)),
        };
        tokio::time::sleep_until(started + FAIL_FLOOR).await;
        return resp;
    };
    let bucket = format!("tok:{}:{}", module.id(), grant.key);
    if let Err(wait) = app.limits.requests.take(&bucket, Instant::now()) {
        return too_many(wait);
    }
    let body = match to_bytes(raw, route.max_body).await {
        Ok(b) => b,
        Err(_) => return crate::gateway::preauth::too_large(),
    };
    parts.extensions.insert(TokenPrincipal(grant.principal));
    let mut resp = next.run(Request::from_parts(parts, Body::from(body))).await;
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
