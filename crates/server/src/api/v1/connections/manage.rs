//! Making and checking connections: a pasted credential, a GitHub App installation, replacing a
//! credential, and the test. The credential comes in a request body that has no `Debug`, goes
//! into a `Material` that prints nothing, and is sealed; nothing here returns it.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::types::*;
use super::{ApiError, ApiResult, Caller, kind_of, num, one, parse, sealer, who, workspace};
use crate::api::App;
use crate::connections::adapter::{KindAdapter, TestError};
use crate::connections::github::install::InstallError;
use crate::connections::jira;
use crate::connections::linear;
use crate::connections::material::Material;
use crate::connections::slack;
use crate::connections::teams;
use crate::store::connections::verdict;
use crate::store::connections::{self as store, Who};
use crate::store::secrets::Error as StoreError;

// ----- credentials ------------------------------------------------------------------------

/// Why a pasted or minted credential was not stored.
fn install_error(e: InstallError) -> ApiError {
    match e {
        InstallError::NotConfigured => ApiError::conflict(
            "the GitHub App is not set up on this Core yet: an admin enters its id and key first",
        ),
        InstallError::Mint(o) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "upstream_failed",
            format!(
                "GitHub did not give Core a token for that installation ({})",
                o.code()
            ),
        ),
        InstallError::Store(e) => e.into(),
        InstallError::Service(why) => {
            ApiError::new(StatusCode::BAD_GATEWAY, "signin_service", why.to_owned())
        }
        InstallError::NotYours => ApiError::new(
            StatusCode::FORBIDDEN,
            "installation_not_yours",
            "This GitHub install isn't yours".to_owned(),
        ),
        InstallError::NoUserToken => {
            ApiError::conflict("sign in to GitHub first (Sign in with GitHub), then add the App")
        }
    }
}

/// What a body says about a credential.
struct Given<'a> {
    token: Option<&'a str>,
    email: Option<&'a str>,
    site: Option<&'a str>,
    installation: Option<i64>,
}

impl<'a> Given<'a> {
    fn of(
        token: &'a Option<zeroize::Zeroizing<String>>,
        email: &'a Option<String>,
        site: &'a Option<String>,
        installation: Option<i64>,
    ) -> Self {
        Self {
            token: token.as_ref().map(|t| t.as_str()),
            email: email.as_deref(),
            site: site.as_deref(),
            installation,
        }
    }
}

/// The credential a body names, for `kind` and `method`: a pasted token (GitHub), email, site
/// and API token (Jira), or a minted installation token (GitHub App). The installation id comes
/// back for the last.
async fn material_of(
    app: &App,
    user: i64,
    kind: &str,
    method: &str,
    g: Given<'_>,
) -> Result<(Material, Option<(i64, String)>), ApiError> {
    let bad = |why: &str| ApiError::bad_request(why.to_owned());
    match (kind, method) {
        ("github", "token") => {
            let t = g.token.ok_or_else(|| bad("a token is required"))?;
            let m =
                Material::new(t, None, None).ok_or_else(|| bad("that is not a usable token"))?;
            Ok((m, None))
        }
        ("jira", "token") => {
            let (Some(t), Some(email), Some(site)) = (g.token, g.email, g.site) else {
                return Err(bad("an email, a site and an API token are required"));
            };
            let host = jira::site_host_of(site.trim())
                .ok_or_else(|| bad("the site is like acme.atlassian.net"))?;
            let m = jira::token_material(&host, email.trim(), t)
                .ok_or_else(|| bad("check the email, the site and the API token"))?;
            Ok((m, None))
        }
        ("linear", "token") => {
            let t = g.token.ok_or_else(|| bad("an API key is required"))?;
            let m = linear::key_material(t).ok_or_else(|| bad("that is not a usable API key"))?;
            Ok((m, None))
        }
        ("slack", "token") => {
            let t = g.token.ok_or_else(|| bad("a bot token is required"))?;
            let m = slack::token_material(t)
                .ok_or_else(|| bad("that is not a bot token (it starts with xoxb-)"))?;
            Ok((m, None))
        }
        ("github", "app_install") => {
            let id = g
                .installation
                .filter(|i| *i > 0)
                .ok_or_else(|| bad("an installation id is required"))?;
            // An installation belongs to the first workspace that uses it: another's is refused
            // before anything is asked of GitHub.
            let holder = store::apps::claimed_by(&app.pool, id).await?;
            if holder.is_some_and(|h| h != user) {
                return Err(ApiError::conflict(
                    "that installation belongs to another workspace",
                ));
            }
            let github = app.connections.github();
            if !github.installer().has_own_key() {
                // Ainkrad's App: the sign-in service mints, after checking the install is this
                // person's.
                let sealer = sealer(app)?;
                let now = app.clock.now();
                let (m, account) = github
                    .mint_hosted(&app.pool, sealer, user, id, &now)
                    .await
                    .map_err(install_error)?;
                let account = account.unwrap_or_else(|| format!("installation-{id}"));
                return Ok((m, Some((id, account))));
            }
            let account = github
                .installation_account(id)
                .await
                .map_err(install_error)?;
            let m = github.mint(id).await.map_err(install_error)?;
            Ok((m, Some((id, account))))
        }
        _ => Err(bad("that sign-in is not made with this route")),
    }
}

#[utoipa::path(post, path = "/api/v1/connections", operation_id = "createConnection",
    tag = "connections", request_body = NewConnection,
    responses((status = 200, description = "Stored for the caller's workspace, its credential \
        sealed and tested once (audited `connection.created`, `connection.tested`). \
        `auth_method` `token` pastes a token (GitHub), or an email, a site and an API token \
        (Jira); `app_install` takes a GitHub App `installation_id`, which must exist and belong to \
        no other workspace (409). The credential is never \
        returned. 400 for a bad name, label or credential, or one the service refuses \
        (`credential_rejected`); 409 `conflict` (the name is taken), `limit_reached` or the \
        secrets gates (`secrets_disabled`, `real_secret_refused`); 502 when the service could \
        not be reached (`upstream_failed`)", body = Connection)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<Connection> {
    let b: NewConnection = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let d = kind_of(&app, &b.kind)?;
    if d.auth_method(&b.auth_method).is_none() {
        return Err(ApiError::bad_request(
            "the kind does not offer that sign-in",
        ));
    }
    let sealer = sealer(&app)?;
    let (m, installation) = material_of(
        &app,
        user,
        &b.kind,
        &b.auth_method,
        Given::of(&b.token, &b.email, &b.site, b.installation_id),
    )
    .await?;
    let now = app.clock.now();
    let who = who(&me, user, &now);
    let name = match &b.name {
        Some(n) => n.clone(),
        None => free_name(&app, user, d.kind).await?,
    };
    let new = store::NewConnection {
        kind: d.kind,
        name: &name,
        label: b.label.as_deref().unwrap_or(d.title),
        auth_method: &b.auth_method,
    };
    let reg = app.connections.registry();
    let c = store::create_with(
        &app.pool,
        sealer,
        reg,
        &new,
        &m,
        installation.as_ref().map(|(i, a)| (*i, a.as_str())),
        who,
    )
    .await?;
    drop(m);
    // Tested at once: a credential the service refuses, or cannot be asked about, is not kept.
    let tested = verdict::run_test(&app.pool, sealer, reg, c.id, who).await?;
    if tested.identity.is_none() {
        let rejected = tested.status == "disabled";
        store::delete(&app.pool, c.id, who).await?;
        return Err(match rejected {
            true => ApiError::new(
                StatusCode::BAD_REQUEST,
                "credential_rejected",
                "the service did not accept that credential; check it and try again",
            ),
            false => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "the service could not be reached to check the credential; try again",
            ),
        });
    }
    Ok(Json(one(&app, &me, user, c.id).await?))
}

async fn free_name(app: &App, user: i64, kind: &str) -> Result<String, ApiError> {
    let have = store::list(&app.pool, user, Some(kind)).await?;
    (1..100)
        .map(|n| format!("{kind}-{n}"))
        .find(|n| !have.iter().any(|c| &c.name == n))
        .ok_or_else(|| ApiError::conflict("too many connections of this kind"))
}

/// A Linear key replaces another only inside the same workspace: team keys (`ENG`) exist in every
/// workspace, so a key from another one would silently re-aim the connection's team limit at
/// someone else's teams. The new key is asked who it is first. There is no override here (the
/// request has no field for one): a person who means to change workspace makes a new connection.
async fn same_workspace(app: &App, c: &store::Connection, m: &Material) -> Result<(), ApiError> {
    let cred = linear::unpack(m)
        .ok_or_else(|| ApiError::bad_request("that is not a usable API key".to_owned()))?;
    let me = app
        .connections
        .linear()
        .viewer(&cred)
        .await
        .map_err(|e| match e {
            linear::CallError::AuthFailed => ApiError::new(
                StatusCode::BAD_REQUEST,
                "credential_rejected",
                "the service did not accept that credential; check it and try again",
            ),
            _ => ApiError::new(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "the service could not be reached to check the key; try again",
            ),
        })?;
    match linear::check_org(c.identity.as_deref(), &me.org) {
        linear::OrgCheck::Same => Ok(()),
        linear::OrgCheck::Different => Err(ApiError::new(
            StatusCode::CONFLICT,
            "different_account",
            "that key belongs to another Linear workspace than this connection's; add a new connection instead",
        )),
        linear::OrgCheck::Unknown => Err(ApiError::new(
            StatusCode::CONFLICT,
            "identity_unknown",
            "this connection has no recorded workspace to compare with; test it, or add a new connection",
        )),
    }
}

/// Checks, before a Slack token replaces a connection's, that it is a bot of the workspace the
/// connection records, by the workspace's stable id (`T…`; the name can be renamed). There is no
/// override here (the request has no field for one): a person who means to change workspace makes
/// a new connection.
async fn same_slack_workspace(
    app: &App,
    c: &store::Connection,
    m: &Material,
) -> Result<(), ApiError> {
    let me = match app.connections.slack().test(m).await {
        Ok(id) => id.subject,
        Err(TestError::Rejected) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "credential_rejected",
                "the service did not accept that credential as a bot of one workspace",
            ));
        }
        Err(TestError::Inconclusive) => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "the service could not be reached to check the token; try again",
            ));
        }
    };
    let new = slack::workspace_of(&me).unwrap_or_default();
    match slack::check_team(c.identity.as_deref(), new) {
        slack::TeamCheck::Same => Ok(()),
        slack::TeamCheck::Different => Err(ApiError::new(
            StatusCode::CONFLICT,
            "different_account",
            "that token belongs to another Slack workspace than this connection's; add a new connection instead",
        )),
        slack::TeamCheck::Unknown => Err(ApiError::new(
            StatusCode::CONFLICT,
            "identity_unknown",
            "this connection has no recorded workspace to compare with; test it, or add a new connection",
        )),
    }
}

#[utoipa::path(put, path = "/api/v1/connections/{id}/credential",
    operation_id = "replaceConnectionCredential", tag = "connections",
    params(("id" = String, Path, description = "The connection's id")),
    request_body = NewConnectionCredential,
    responses((status = 200, description = "The credential replaced (audited \
        `connection.secret_replaced`) and tested; a pending or confirmed auth failure is cleared \
        first, the test then decides. For a `token` connection a token (and for Jira an email \
        and site); for an `app_install` one an `installation_id`. A connection made by signing \
        in is refreshed by signing in again (`startConnectionFlow` with `connection`), not \
        here (400). Never returned. 404 for another workspace's", body = Connection)))]
pub async fn replace_credential(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Connection> {
    let b: NewConnectionCredential = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let id = num(&id)?;
    let c = store::get(&app.pool, user, id).await?;
    if c.auth_method == "oauth" {
        return Err(ApiError::bad_request(
            "this connection was made by signing in: sign in again instead",
        ));
    }
    let sealer = sealer(&app)?;
    let (m, installation) = material_of(
        &app,
        user,
        &c.kind,
        &c.auth_method,
        Given::of(&b.token, &b.email, &b.site, b.installation_id),
    )
    .await?;
    if c.kind == "linear" {
        same_workspace(&app, &c, &m).await?;
    }
    if c.kind == "slack" {
        same_slack_workspace(&app, &c, &m).await?;
    }
    let now = app.clock.now();
    let who = who(&me, user, &now);
    // The credential and its installation are written in one transaction: a refused claim (an
    // installation another workspace holds) leaves the old pair as it was.
    match &installation {
        Some((i, account)) => {
            let at = (*i, account.as_str());
            store::secret::replace_installed(&app.pool, sealer, id, &m, at, who).await?;
        }
        None => {
            store::secret::replace(&app.pool, sealer, id, &m, who).await?;
        }
    }
    drop(m);
    run_test(&app, id, user, who).await?;
    Ok(Json(one(&app, &me, user, id).await?))
}

/// Tests connection `id` the way its kind needs: Jira renews an OAuth token first, a GitHub App
/// connection mints a new token first when its token is near its end.
async fn run_test(app: &App, id: i64, user: i64, who: Who<'_>) -> Result<(), StoreError> {
    let sealer = app.secrets.as_ref().ok_or_else(|| StoreError::Refused {
        code: "secrets_unavailable",
        message: "this Core has no master key loaded".to_owned(),
    })?;
    let c = store::get(&app.pool, user, id).await?;
    match c.kind.as_str() {
        "jira" => {
            let cx = jira::Ctx {
                pool: &app.pool,
                sealer,
                who,
            };
            app.connections.jira().test_connection(&cx, id).await?;
        }
        "linear" => {
            let cx = linear::Ctx {
                pool: &app.pool,
                sealer,
                who,
            };
            app.connections.linear().test_connection(&cx, id).await?;
        }
        "slack" => {
            let cx = slack::Ctx {
                pool: &app.pool,
                sealer,
                who,
            };
            app.connections.slack().test_connection(&cx, id).await?;
        }
        "teams" => {
            let cx = teams::Ctx {
                pool: &app.pool,
                sealer,
                who,
            };
            app.connections.teams().test_connection(&cx, id).await?;
        }
        _ => {
            // A failed renewal leaves the old token, which the test then judges.
            let _ = app
                .connections
                .github()
                .renew_installation(&app.pool, sealer, who, id)
                .await;
            verdict::run_test(&app.pool, sealer, app.connections.registry(), id, who).await?;
        }
    }
    Ok(())
}

#[utoipa::path(post, path = "/api/v1/connections/{id}/test", operation_id = "testConnection",
    tag = "connections", params(("id" = String, Path, description = "The connection's id")),
    responses((status = 200, description = "Tested now (audited `connection.tested`, with the \
        result class only): Jira renews its token first, a GitHub App connection mints a new one \
        when the old is near its end. A pending auth failure (`state_reason` `auth_suspected`) \
        is decided by this: a service that refuses the credential disables the connection \
        (`auth_failed`: sign in again), one that accepts clears it. The connection as the test \
        left it. A connection is tested at most once every 10 seconds and a user 30 times in 10 \
        minutes: past that, 429 `rate_limited` with `Retry-After`. 404 for another \
        workspace's", body = Connection),
        (status = 429, description = "Tested too soon: wait `Retry-After` seconds")))]
pub async fn test(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> Response {
    let tested = async {
        let user = workspace(&app, &me).await?;
        let id = num(&id)?;
        store::get(&app.pool, user, id).await?;
        // A test is a real request to the service: paced per connection and per user.
        if let Err(wait) = app.conn_pace.admit(user, id, app.clock.unix()) {
            return Ok(Err(wait));
        }
        let now = app.clock.now();
        run_test(&app, id, user, who(&me, user, &now)).await?;
        Ok::<_, ApiError>(Ok(one(&app, &me, user, id).await?))
    }
    .await;
    match tested {
        Ok(Ok(c)) => Json(c).into_response(),
        Ok(Err(wait)) => crate::api::v1::too_many(std::time::Duration::from_secs(wait)),
        Err(e) => e.into_response(),
    }
}
