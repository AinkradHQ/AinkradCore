//! Ainkrad's OAuth apps over the API (C5): the GitHub client id, the Atlassian client id and
//! secret, the GitHub App's id and private key. Both routes are `admin`; the write is
//! destructive. A secret field is WRITE-ONLY: no response carries it, its length or a hash;
//! `set` says only that it is there. A write puts the config into force at once in the one
//! shared Jira and GitHub adapter (no second instance), which ends sign-ins started under the
//! old app. The values are sealed (`core_connection_apps`) and belong to the Core.
//!
//! The config is the Core's, not a workspace's: only the Core's owner (the admin of user 1, the
//! deployment owner) reads its fields or writes it (403 `forbidden_scope` for any other admin,
//! who reads only `configured`); a write ends the pending sign-ins of the kinds whose app
//! really changed, and no others.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;

use super::types::*;
use super::{need_admin, parse, who, workspace};
use crate::api::App;
use crate::api::v1::{ApiError, ApiResult, Caller};
use crate::connections::apps::{self as cfg, Apps, OWNER};
use crate::store::connections::apps as sealed;

fn spec(kind: &str) -> Result<&'static [cfg::Field], ApiError> {
    cfg::fields(kind).ok_or_else(|| ApiError::not_found("no such kind of connection"))
}

/// The app config is the Core's own (Ainkrad owns the OAuth apps): only the Core's owner reads
/// its fields or writes it. Any other admin reads whether it is set up.
async fn is_owner(app: &App, me: &Caller) -> Result<bool, ApiError> {
    Ok(workspace(app, me).await? == OWNER)
}

fn owner_only() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden_scope",
        "only the Core's owner changes Ainkrad's sign-in apps",
    )
}

async fn shown(app: &App, kind: &str, full: bool) -> Result<ConnectionApp, ApiError> {
    let fields = spec(kind)?;
    let set = sealed::present(&app.pool, OWNER, kind).await?;
    let values = match app.secrets.as_deref() {
        Some(sealer) => sealed::open_all(&app.pool, sealer, OWNER, kind)
            .await
            .unwrap_or_default(),
        None => Default::default(),
    };
    Ok(ConnectionApp {
        kind: kind.to_owned(),
        configured: super::configured(app, kind),
        app_install_configured: kind == "github"
            && app.connections.github().installer().configured(),
        fields: fields
            .iter()
            .filter(|_| full)
            .map(|f| ConnectionAppField {
                name: f.name.to_owned(),
                title: f.title.to_owned(),
                secret: f.secret,
                set: set.iter().any(|s| s == f.name),
                value: values
                    .get(f.name)
                    .filter(|_| !f.secret)
                    .map(|v| v.to_string()),
            })
            .collect(),
        redirect_uri: (kind == "jira" && full).then(|| {
            let port = values
                .get("loopback_port")
                .and_then(|p| p.parse().ok())
                .unwrap_or(cfg::DEFAULT_PORT);
            Apps::redirect(port)
        }),
    })
}

#[utoipa::path(get, path = "/api/v1/connection-apps/{kind}", operation_id = "getConnectionApp",
    tag = "connections", params(("kind" = String, Path, description = "`github` or `jira`")),
    responses((status = 200, description = "Whether Ainkrad's OAuth app for the kind is set up \
        on this Core, and which fields are set. A field that is no secret shows its value (the \
        client id); a secret (`client_secret`, `app_key`) only whether it is `set`, never the \
        value. For Atlassian, `redirect_uri` is the address to register with Atlassian. Only the \
        Core's owner sees the fields and the address; any other admin sees `configured` alone. \
        404 for an unknown kind", body = ConnectionApp)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(kind): Path<String>,
) -> ApiResult<ConnectionApp> {
    need_admin(&me)?;
    let full = is_owner(&app, &me).await?;
    Ok(Json(shown(&app, &kind, full).await?))
}

#[utoipa::path(put, path = "/api/v1/connection-apps/{kind}", operation_id = "setConnectionApp",
    tag = "connections", params(("kind" = String, Path, description = "`github` or `jira`")),
    request_body = SetConnectionApp,
    responses((status = 200, description = "The named fields stored sealed (a string) or \
        cleared (null), audited `connection.app_set` with the field names only; the kind's \
        adapters use the new app at once, and pending sign-ins of a kind whose app changed end \
        (`failed`, `app_changed`); those of another kind go on. 403 for an admin who is not the \
        Core's owner. \
        Changing Atlassian's client id or secret makes existing Jira sign-ins fail to renew: \
        those connections sign in again. 400 for an unknown field or a bad value (the private \
        key must parse and goes with an `app_id`); 409 `secrets_disabled` while the broker is \
        off; 503 without a master key", body = ConnectionApp)))]
pub async fn set(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(kind): Path<String>,
    body: Bytes,
) -> ApiResult<ConnectionApp> {
    let fields = spec(&kind)?;
    if !is_owner(&app, &me).await? {
        return Err(owner_only());
    }
    let b: SetConnectionApp = parse(&body)?;
    if b.fields.is_empty() {
        return Err(ApiError::bad_request("name a field to set or clear"));
    }
    for (name, value) in &b.fields {
        if !fields.iter().any(|f| f.name == name) {
            return Err(ApiError::bad_request(
                "that field does not exist for this kind",
            ));
        }
        if let Some(v) = value
            && let Some(why) = cfg::problem(&kind, name, v.trim())
        {
            return Err(ApiError::bad_request(format!("{name}: {why}")));
        }
    }
    // The private key goes with the App's id: one that is given now or already stored.
    if b.fields.get("app_key").is_some_and(Option::is_some) {
        let stored = sealed::present(&app.pool, OWNER, &kind).await?;
        let with_id = b.fields.get("app_id").is_some_and(Option::is_some)
            || stored.iter().any(|f| f == "app_id");
        if !with_id {
            return Err(ApiError::bad_request("app_key: set app_id with it"));
        }
    }
    let sealer = super::sealer(&app)?;
    let changes: Vec<(&str, Option<&str>)> = b
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_ref().map(|v| v.trim())))
        .collect();
    let now = app.clock.now();
    sealed::set(&app.pool, sealer, &kind, &changes, who(&me, OWNER, &now)).await?;
    cfg::reload(&app).await.map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the config was stored but could not be put into force",
        )
    })?;
    Ok(Json(shown(&app, &kind, true).await?))
}
