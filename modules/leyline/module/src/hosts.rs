//! Hosts: list, create, read, change, delete, plus the group and tag views. A host is addressed in
//! a path by id or by label (`address::resolve`). Every refusal is a fixed sentence: nothing a
//! caller sent is ever echoed back (the one stored label in an ambiguity error excepted).

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::address::{Cand, Match, resolve};
use crate::valid;

/// A JSON body whose parse failure is one fixed sentence (serde's own text quotes the input).
pub(crate) struct In<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for In<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(v)| In(v))
            .map_err(|_| ApiError::bad_request("the request body is not valid"))
    }
}

/// `"field": null` clears; an absent field keeps.
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

const INVALID: &str = "the host is not valid";
const LIST_MAX: i64 = 500;

#[derive(Serialize, ToSchema)]
pub struct HostView {
    /// `h_` and 16 hex characters.
    pub id: String,
    /// The label; unique, case-insensitive. Addresses a host in a path when it is no id.
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    /// The key used to log in; none = a password typed in the terminal.
    pub key_id: Option<String>,
    /// Ordered jump host ids, at most 3.
    pub jump_chain: Vec<String>,
    /// Runner device id; none = the Core machine's built-in runner.
    pub via_runner: Option<String>,
    pub group: Option<String>,
    pub tags: Vec<String>,
    /// `read_only` or `ask` (`allowed` arrives with the gate story, Y4-01).
    pub ai_rule: String,
    pub record: String,
    pub health: bool,
    pub runner_device: Option<String>,
    pub os: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<HostView, sqlx::Error> {
    let text = |c: &str| r.try_get::<String, _>(c);
    let list = |c: &str| -> Result<Vec<String>, sqlx::Error> {
        Ok(serde_json::from_str(&text(c)?).unwrap_or_default())
    };
    Ok(HostView {
        id: text("id")?,
        name: text("name")?,
        address: text("address")?,
        port: u16::try_from(r.try_get::<i64, _>("port")?).unwrap_or(22),
        username: text("username")?,
        key_id: r.try_get("key_id")?,
        jump_chain: list("jump_chain")?,
        via_runner: r.try_get("via_runner")?,
        group: r.try_get("group_name")?,
        tags: list("tags")?,
        ai_rule: text("ai_rule")?,
        record: text("record")?,
        health: r.try_get::<i64, _>("health")? == 1,
        runner_device: r.try_get("runner_device")?,
        os: r.try_get("os")?,
        created_at: text("created_at")?,
        updated_at: text("updated_at")?,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct NewHost {
    pub name: String,
    pub address: String,
    pub port: Option<i64>,
    pub username: String,
    pub key_id: Option<String>,
    pub jump_chain: Option<Vec<String>>,
    pub via_runner: Option<String>,
    pub group: Option<String>,
    pub tags: Option<Vec<String>>,
    /// `read_only` or `ask` (the default).
    pub ai_rule: Option<String>,
}

/// Every field is optional; a nullable one set to `null` is cleared.
#[derive(Deserialize, ToSchema)]
pub struct HostPatch {
    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Option<i64>,
    pub username: Option<String>,
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub key_id: Option<Option<String>>,
    pub jump_chain: Option<Vec<String>>,
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub via_runner: Option<Option<String>>,
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub group: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub ai_rule: Option<String>,
}

/// A host as it is written: already merged and checked, ready to bind.
struct Fields {
    name: String,
    address: String,
    port: u16,
    username: String,
    key_id: Option<String>,
    jump_chain: Vec<String>,
    via_runner: Option<String>,
    group: Option<String>,
    tags: Vec<String>,
    ai_rule: String,
}

/// Lowercased, de-duplicated tags, or the fixed refusal.
fn norm(tags: Vec<String>) -> Result<Vec<String>, ApiError> {
    valid::tags(&tags).ok_or_else(bad)
}

fn bad() -> ApiError {
    ApiError::bad_request(INVALID)
}

impl Fields {
    /// The API layer of every rule (the table's CHECKs are the other). `own` is the host being
    /// changed, which cannot be its own jump hop.
    async fn check(&self, conn: &mut SqliteConnection, own: Option<&str>) -> Result<(), ApiError> {
        let ok = valid::label(&self.name)
            && valid::address(&self.address)
            && valid::username(&self.username)
            && self.group.as_deref().is_none_or(valid::label)
            && self.key_id.as_deref().is_none_or(valid::key_id)
            && self.via_runner.as_deref().is_none_or(valid::runner)
            && valid::tags(&self.tags).as_ref() == Some(&self.tags)
            && ["read_only", "ask"].contains(&self.ai_rule.as_str())
            && self.jump_chain.len() <= 3
            && self
                .jump_chain
                .iter()
                .all(|h| valid::host_id(h) && Some(h.as_str()) != own)
            && (1..self.jump_chain.len())
                .all(|i| !self.jump_chain[..i].contains(&self.jump_chain[i]));
        if !ok {
            return Err(bad());
        }
        if let Some(k) = &self.key_id {
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM leyline_keys WHERE id = ?")
                .bind(k)
                .fetch_one(&mut *conn)
                .await?;
            if n == 0 {
                return Err(bad());
            }
        }
        for h in &self.jump_chain {
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM leyline_hosts WHERE id = ?")
                .bind(h)
                .fetch_one(&mut *conn)
                .await?;
            if n == 0 {
                return Err(bad());
            }
        }
        Ok(())
    }
}

/// A table refusal is the second layer answering: a fixed sentence, never the database's text.
fn store_err(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::conflict("a host with that label exists")
        }
        sqlx::Error::Database(d) if d.is_check_violation() || d.is_foreign_key_violation() => bad(),
        _ => e.into(),
    }
}

async fn record(conn: &mut SqliteConnection, op: &str, id: &str) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.host.{op}"),
        entity: None,
        details: json!({"host": id}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, "leyline.host", &json!({"op": op, "id": id})).await?;
    Ok(())
}

/// The host `ident` names (id, else unique label).
async fn find(conn: &mut SqliteConnection, ident: &str) -> Result<String, ApiError> {
    let none = || ApiError::not_found("no such host");
    if ident.is_empty() || ident.len() > 256 {
        return Err(none());
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, name FROM leyline_hosts WHERE lower(id) = lower(?1) OR name = ?1 COLLATE NOCASE LIMIT 50",
    )
    .bind(ident)
    .fetch_all(conn)
    .await?;
    let cands: Vec<Cand> = rows
        .into_iter()
        .map(|(id, label)| Cand { id, label })
        .collect();
    match resolve(ident, &cands) {
        Match::One(c) => Ok(c.id.clone()),
        Match::NotFound => Err(none()),
        Match::Ambiguous { label, count } => Err(ApiError::new(
            StatusCode::CONFLICT,
            "ambiguous_host",
            format!(
                "{count} hosts share the label \"{label}\"; address the one you mean by its id"
            ),
        )),
    }
}

async fn load(conn: &mut SqliteConnection, id: &str) -> Result<HostView, ApiError> {
    let row = sqlx::query("SELECT * FROM leyline_hosts WHERE id = ?")
        .bind(id)
        .fetch_one(conn)
        .await?;
    Ok(view(&row)?)
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    group: Option<String>,
    tag: Option<String>,
}

#[utoipa::path(get, path = "/hosts", operation_id = "leylineListHosts", tag = "leyline",
    params(("group" = Option<String>, Query, description = "Only this group"),
           ("tag" = Option<String>, Query, description = "Only hosts with this tag")),
    responses((status = 200, description = "Hosts by group then label (at most 500)", body = Vec<HostView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> ApiResult<Vec<HostView>> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let rows = sqlx::query(
        "SELECT * FROM leyline_hosts \
         WHERE (?1 IS NULL OR group_name = ?1 COLLATE NOCASE) \
           AND (?2 IS NULL OR EXISTS (SELECT 1 FROM json_each(tags) WHERE value = lower(?2))) \
         ORDER BY group_name IS NULL, group_name COLLATE NOCASE, name LIMIT ?3",
    )
    .bind(q.group)
    .bind(q.tag)
    .bind(LIST_MAX)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}

#[utoipa::path(post, path = "/hosts", operation_id = "leylineCreateHost", tag = "leyline", request_body = NewHost,
    responses((status = 200, description = "The new host (audited as `leyline.host.created`)", body = HostView)))]
pub(crate) async fn create(State(app): State<App>, In(req): In<NewHost>) -> ApiResult<HostView> {
    let f = Fields {
        name: req.name,
        address: req.address,
        port: req.port.map_or(Some(22), valid::port).ok_or_else(bad)?,
        username: req.username,
        key_id: req.key_id,
        jump_chain: req.jump_chain.unwrap_or_default(),
        via_runner: req.via_runner,
        group: req.group,
        tags: norm(req.tags.unwrap_or_default())?,
        ai_rule: req.ai_rule.unwrap_or_else(|| "ask".to_owned()),
    };
    let mut tx = begin_write(&app.pool).await?;
    f.check(&mut tx, None).await?;
    let id = valid::new_id("h_");
    sqlx::query(
        "INSERT INTO leyline_hosts (id, name, address, port, username, key_id, jump_chain, via_runner, group_name, tags, ai_rule) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&f.name)
    .bind(&f.address)
    .bind(i64::from(f.port))
    .bind(&f.username)
    .bind(&f.key_id)
    .bind(json!(f.jump_chain).to_string())
    .bind(&f.via_runner)
    .bind(&f.group)
    .bind(json!(f.tags).to_string())
    .bind(&f.ai_rule)
    .execute(&mut *tx)
    .await
    .map_err(store_err)?;
    record(&mut tx, "created", &id).await?;
    let out = load(&mut tx, &id).await?;
    tx.commit().await?;
    crate::keys::sync_runners(&app).await?;
    Ok(Json(out))
}

#[utoipa::path(get, path = "/hosts/{host}", operation_id = "leylineGetHost", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")),
    responses((status = 200, description = "The host", body = HostView)))]
pub(crate) async fn get(State(app): State<App>, Path(host): Path<String>) -> ApiResult<HostView> {
    let mut conn = app.pool.acquire().await?;
    let id = find(&mut conn, &host).await?;
    Ok(Json(load(&mut conn, &id).await?))
}

#[utoipa::path(patch, path = "/hosts/{host}", operation_id = "leylinePatchHost", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = HostPatch,
    responses((status = 200, description = "The changed host (audited as `leyline.host.changed`)", body = HostView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(host): Path<String>,
    In(req): In<HostPatch>,
) -> ApiResult<HostView> {
    let mut tx = begin_write(&app.pool).await?;
    let id = find(&mut tx, &host).await?;
    let cur = load(&mut tx, &id).await?;
    let f = Fields {
        name: req.name.unwrap_or(cur.name),
        address: req.address.unwrap_or(cur.address),
        port: req
            .port
            .map_or(Some(cur.port), valid::port)
            .ok_or_else(bad)?,
        username: req.username.unwrap_or(cur.username),
        key_id: req.key_id.unwrap_or(cur.key_id),
        jump_chain: req.jump_chain.unwrap_or(cur.jump_chain),
        via_runner: req.via_runner.unwrap_or(cur.via_runner),
        group: req.group.unwrap_or(cur.group),
        tags: req.tags.map_or(Ok(cur.tags), norm)?,
        ai_rule: req.ai_rule.unwrap_or(cur.ai_rule),
    };
    f.check(&mut tx, Some(&id)).await?;
    sqlx::query(
        "UPDATE leyline_hosts SET name = ?, address = ?, port = ?, username = ?, key_id = ?, jump_chain = ?, \
         via_runner = ?, group_name = ?, tags = ?, ai_rule = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(&f.name)
    .bind(&f.address)
    .bind(i64::from(f.port))
    .bind(&f.username)
    .bind(&f.key_id)
    .bind(json!(f.jump_chain).to_string())
    .bind(&f.via_runner)
    .bind(&f.group)
    .bind(json!(f.tags).to_string())
    .bind(&f.ai_rule)
    .bind(&id)
    .execute(&mut *tx)
    .await
    .map_err(store_err)?;
    record(&mut tx, "changed", &id).await?;
    let out = load(&mut tx, &id).await?;
    tx.commit().await?;
    crate::keys::sync_runners(&app).await?;
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct Deleted {
    pub deleted: String,
}

#[utoipa::path(delete, path = "/hosts/{host}", operation_id = "leylineDeleteHost", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")),
    responses((status = 200, description = "Deleted with its pinned keys and attachments (step-up; audited as `leyline.host.deleted`); refused while another host uses it as a jump hop", body = Deleted)))]
pub(crate) async fn remove(State(app): State<App>, Path(host): Path<String>) -> ApiResult<Deleted> {
    let mut tx = begin_write(&app.pool).await?;
    let id = find(&mut tx, &host).await?;
    let used: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM leyline_hosts, json_each(jump_chain) WHERE json_each.value = ?",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;
    if used > 0 {
        return Err(ApiError::conflict("another host uses it as a jump host"));
    }
    sqlx::query("DELETE FROM leyline_hosts WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    record(&mut tx, "deleted", &id).await?;
    tx.commit().await?;
    crate::keys::sync_runners(&app).await?;
    Ok(Json(Deleted { deleted: id }))
}

#[derive(Serialize, ToSchema)]
pub struct Count {
    pub name: String,
    pub hosts: i64,
}

#[utoipa::path(get, path = "/groups", operation_id = "leylineListGroups", tag = "leyline",
    responses((status = 200, description = "Every group with its host count", body = Vec<Count>)))]
pub(crate) async fn groups(State(app): State<App>) -> ApiResult<Vec<Count>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT group_name, count(*) FROM leyline_hosts WHERE group_name IS NOT NULL \
         GROUP BY group_name COLLATE NOCASE ORDER BY group_name COLLATE NOCASE",
    )
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(name, hosts)| Count { name, hosts })
            .collect(),
    ))
}

#[utoipa::path(get, path = "/tags", operation_id = "leylineListTags", tag = "leyline",
    responses((status = 200, description = "Every tag with its host count", body = Vec<Count>)))]
pub(crate) async fn tags(State(app): State<App>) -> ApiResult<Vec<Count>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT value, count(*) FROM leyline_hosts, json_each(tags) GROUP BY value ORDER BY value",
    )
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(name, hosts)| Count { name, hosts })
            .collect(),
    ))
}
