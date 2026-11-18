//! Host keys (Y3-01): what the Core pins for each host, and how a pin comes to be.
//!
//! Security model.
//! - A key is trusted only by a person: `trust` and `replace` go through the gate's `Trust` action,
//!   which no AI session and no prober may take, and `replace` is also a step-up route.
//! - Nothing is trusted on first sight. A terminal to a host with no trusted key goes out with an
//!   empty pin list, so the runner stops the connection before any authentication and the
//!   fingerprint it saw is stored as `seen`; a person compares it and trusts it. A key that differs
//!   from a trusted one is stored `seen` too, raises `host_key_changed`, and only `replace` (with a
//!   step-up) can make it the pin.
//! - Only a key the runner actually saw (a `seen` row) can be trusted: a person never types one.
//! - Rows hold public data only (fingerprint, state, who and when). Events carry ids, never keys.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use crate::gate::{self, Action, Principal};
use crate::hosts::{In, find};

/// One host key the Core knows for a host.
#[derive(Serialize, ToSchema)]
pub struct HostKeyView {
    /// `SHA256:` and the base64 of the key's hash, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    /// `trusted` (pinned), `seen` (offered by the host, awaiting a person) or `replaced`.
    pub state: String,
    pub first_seen: String,
    pub trusted_by: Option<String>,
    pub trusted_at: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct Pick {
    /// The fingerprint of a `seen` key of this host.
    pub fingerprint: String,
}

const ROWS: &str =
    "SELECT fingerprint, state, first_seen, trusted_by, trusted_at FROM leyline_host_keys";

fn view(r: (String, String, String, Option<String>, Option<String>)) -> HostKeyView {
    HostKeyView {
        fingerprint: r.0,
        state: r.1,
        first_seen: r.2,
        trusted_by: r.3,
        trusted_at: r.4,
    }
}

/// `SHA256:` and 43 base64 characters (no padding): what a runner reports.
pub(crate) fn fingerprint_ok(s: &str) -> bool {
    s.strip_prefix("SHA256:").is_some_and(|b| {
        b.len() == 43
            && b.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    })
}

/// The fingerprints pinned for `host`: what a terminal's hop is given as `pinned_keys`.
pub(crate) async fn trusted(
    conn: &mut SqliteConnection,
    host: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT fingerprint FROM leyline_host_keys WHERE host_id = ? AND state = 'trusted' ORDER BY fingerprint",
    )
    .bind(host)
    .fetch_all(conn)
    .await
}

/// Stores a key a runner reported (`seen`), once; `true` when it was new. A key already known in
/// any state is left as it is.
pub(crate) async fn saw(
    app: &App,
    host: &str,
    fingerprint: &str,
    changed: bool,
) -> Result<bool, ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    let new = sqlx::query(
        "INSERT OR IGNORE INTO leyline_host_keys (host_id, algo, key_b64, fingerprint, state, first_seen) \
         VALUES (?, '', '', ?, 'seen', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
    )
    .bind(host)
    .bind(fingerprint)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    // A changed key is an alert every time it is met; a first sight is noted once.
    if new || changed {
        let op = if changed { "changed" } else { "seen" };
        note(&mut tx, op, host, "leyline.hostkey").await?;
    }
    tx.commit().await?;
    Ok(new)
}

async fn note(
    conn: &mut SqliteConnection,
    op: &str,
    host: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.hostkey.{op}"),
        entity: None,
        details: json!({"host": host}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, kind, &json!({"op": op, "id": host})).await?;
    Ok(())
}

#[utoipa::path(get, path = "/hosts/{host}/host-keys", operation_id = "leylineListHostKeys", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")),
    responses((status = 200, description = "The host's keys: the pinned ones, the ones awaiting a person, the replaced ones", body = Vec<HostKeyView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Path(host): Path<String>,
) -> ApiResult<Vec<HostKeyView>> {
    let mut conn = app.pool.acquire().await?;
    let id = find(&mut conn, &host).await?;
    let rows: Vec<(String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        &format!("{ROWS} WHERE host_id = ? ORDER BY first_seen, fingerprint"),
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(rows.into_iter().map(view).collect()))
}

/// Pins a `seen` key of a host that has no pinned key yet. Person only.
///
/// # Errors
///
/// 403 `gate_refused` for anyone but a person; 404 for no such host or a key not seen; 409
/// `host_key_conflict` when the host already has a pinned key (that is `replace`).
pub async fn trust(
    app: &App,
    me: &Caller,
    host: &str,
    fingerprint: &str,
) -> Result<HostKeyView, ApiError> {
    change(app, me, host, fingerprint, false).await
}

/// Makes a `seen` key the host's only pin, the old pins `replaced`. Person only; the route also
/// needs a step-up.
///
/// # Errors
///
/// As [`trust`]; 409 when the host has no pinned key (that is `trust`).
pub async fn replace(
    app: &App,
    me: &Caller,
    host: &str,
    fingerprint: &str,
) -> Result<HostKeyView, ApiError> {
    change(app, me, host, fingerprint, true).await
}

async fn change(
    app: &App,
    me: &Caller,
    host: &str,
    fingerprint: &str,
    replacing: bool,
) -> Result<HostKeyView, ApiError> {
    let id = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, host).await?
    };
    // The gate first: an AI session or the prober is refused here, whatever the key.
    let auth = gate::authorize(app, &Principal::of(me), &id, &Action::Trust).await?;
    let done = write(app, me, &id, fingerprint, replacing).await;
    gate::finish(app, auth, done.is_ok()).await?;
    done
}

async fn write(
    app: &App,
    me: &Caller,
    id: &str,
    fingerprint: &str,
    replacing: bool,
) -> Result<HostKeyView, ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    let seen: Option<String> = sqlx::query_scalar(
        "SELECT state FROM leyline_host_keys WHERE host_id = ? AND fingerprint = ?",
    )
    .bind(id)
    .bind(fingerprint)
    .fetch_optional(&mut *tx)
    .await?;
    if seen.as_deref() != Some("seen") {
        return Err(ApiError::not_found("no such key waiting for trust"));
    }
    let pinned = trusted(&mut tx, id).await?;
    let conflict = |why: &'static str| {
        ApiError::new(axum::http::StatusCode::CONFLICT, "host_key_conflict", why)
    };
    match (replacing, pinned.is_empty()) {
        (false, false) => return Err(conflict("the host already has a trusted key; replace it")),
        (true, true) => return Err(conflict("the host has no trusted key; trust this one")),
        _ => {}
    }
    if replacing {
        sqlx::query("UPDATE leyline_host_keys SET state = 'replaced' WHERE host_id = ? AND state = 'trusted'")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE leyline_host_keys SET state = 'trusted', trusted_by = ?, \
         trusted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE host_id = ? AND fingerprint = ?",
    )
    .bind(&me.device.id)
    .bind(id)
    .bind(fingerprint)
    .execute(&mut *tx)
    .await?;
    note(
        &mut tx,
        if replacing { "replaced" } else { "trusted" },
        id,
        "leyline.hostkey",
    )
    .await?;
    let row = sqlx::query_as(&format!("{ROWS} WHERE host_id = ? AND fingerprint = ?"))
        .bind(id)
        .bind(fingerprint)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(view(row))
}

#[utoipa::path(post, path = "/hosts/{host}/host-keys/trust", operation_id = "leylineTrustHostKey", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = Pick,
    responses((status = 200, description = "The key is pinned (audited as `leyline.hostkey.trusted`); 403 `gate_refused` for an AI session; 404 for a key not seen; 409 when the host already has a pinned key", body = HostKeyView)))]
pub(crate) async fn trust_route(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<Pick>,
) -> ApiResult<HostKeyView> {
    Ok(Json(trust(&app, &me, &host, &req.fingerprint).await?))
}

#[utoipa::path(post, path = "/hosts/{host}/host-keys/replace", operation_id = "leylineReplaceHostKey", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = Pick,
    responses((status = 200, description = "The key is the host's only pin, the old ones replaced (audited as `leyline.hostkey.replaced`); needs a step-up; 409 when the host has no pinned key", body = HostKeyView)))]
pub(crate) async fn replace_route(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<Pick>,
) -> ApiResult<HostKeyView> {
    Ok(Json(replace(&app, &me, &host, &req.fingerprint).await?))
}
