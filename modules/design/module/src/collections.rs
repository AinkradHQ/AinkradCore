//! Collections of library assets: `folder`s and `brand_kit`s (colours, fonts and role-tagged assets such
//! as the logo). Related, not owned: links to projects as for docs. A collection holds no bytes, so
//! deleting it deletes no asset; deleting an asset leaves every collection. Refusals are fixed sentences.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::assets::{record, sha_ok};
use crate::docs::{In, project_id, some};

const MAX_COLORS: usize = 32;
const MAX_FONTS: usize = 16;

fn bad() -> ApiError {
    ApiError::bad_request("the collection is not valid")
}

fn none() -> ApiError {
    ApiError::not_found("no such collection")
}

fn new_id() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    format!(
        "dc_{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

fn id_ok(s: &str) -> bool {
    s.len() == 19 && s.starts_with("dc_") && s[3..].bytes().all(|c| c.is_ascii_hexdigit())
}

fn name_ok(s: &str) -> bool {
    (1..=100).contains(&s.chars().count()) && s == s.trim() && !s.chars().any(char::is_control)
}

/// `#rgb`, `#rrggbb` or `#rrggbbaa`.
fn color_ok(s: &str) -> bool {
    matches!(s.len(), 4 | 7 | 9)
        && s.starts_with('#')
        && s[1..].bytes().all(|c| c.is_ascii_hexdigit())
}

#[derive(Serialize, ToSchema)]
pub struct Item {
    pub sha256: String,
    /// A free label such as `logo` or `mark`.
    pub role: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CollectionView {
    /// `dc_` and 16 hex characters.
    pub id: String,
    /// `brand_kit` or `folder`.
    pub kind: String,
    pub name: String,
    /// `#rrggbb` colours of a brand kit.
    pub colors: Vec<String>,
    /// sha256 of the font assets a brand kit names.
    pub fonts: Vec<String>,
    pub items: Vec<Item>,
    pub projects: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

async fn view(conn: &mut SqliteConnection, id: &str) -> Result<CollectionView, ApiError> {
    let r = sqlx::query("SELECT * FROM design_collections WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(none)?;
    let items = sqlx::query(
        "SELECT sha256, role FROM design_collection_items WHERE collection = ? ORDER BY sha256",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|i| {
        Ok::<_, sqlx::Error>(Item {
            sha256: i.try_get("sha256")?,
            role: i.try_get("role")?,
        })
    })
    .collect::<Result<_, _>>()?;
    let projects = sqlx::query_scalar(
        "SELECT project FROM design_links WHERE item_kind = 'collection' AND item = ? \
         ORDER BY CAST(project AS INTEGER)",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    let list = |c: &str| -> Result<Vec<String>, ApiError> {
        let v: Value = serde_json::from_str(&r.try_get::<String, _>(c)?).unwrap_or(Value::Null);
        Ok(serde_json::from_value(v).unwrap_or_default())
    };
    let text = |c: &str| r.try_get::<String, _>(c);
    Ok(CollectionView {
        id: text("id")?,
        kind: text("kind")?,
        name: text("name")?,
        colors: list("colors")?,
        fonts: list("fonts")?,
        items,
        projects,
        created_by: text("created_by")?,
        created_at: text("created_at")?,
        updated_at: text("updated_at")?,
    })
}

/// Colours and fonts must be well-formed; every font must be a font asset of the library.
async fn check_kit(
    conn: &mut SqliteConnection,
    colors: &[String],
    fonts: &[String],
) -> Result<(), ApiError> {
    if colors.len() > MAX_COLORS || fonts.len() > MAX_FONTS || colors.iter().any(|c| !color_ok(c)) {
        return Err(bad());
    }
    for f in fonts {
        let kind: Option<String> =
            sqlx::query_scalar("SELECT kind FROM design_assets WHERE sha256 = ? AND library = 1")
                .bind(f)
                .fetch_optional(&mut *conn)
                .await?;
        if !sha_ok(f) || kind.as_deref() != Some("font") {
            return Err(bad());
        }
    }
    Ok(())
}

#[utoipa::path(get, path = "/collections", operation_id = "designListCollections", tag = "design",
    responses((status = 200, description = "Collections by name", body = Vec<CollectionView>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<CollectionView>> {
    let mut conn = app.pool.acquire().await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM design_collections ORDER BY name COLLATE NOCASE, id LIMIT 500",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(view(&mut conn, &id).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct NewCollection {
    /// `brand_kit` or `folder`.
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub colors: Vec<String>,
    #[serde(default)]
    pub fonts: Vec<String>,
    /// A project id to relate it to.
    pub project: Option<String>,
}

#[utoipa::path(post, path = "/collections", operation_id = "designCreateCollection", tag = "design", request_body = NewCollection,
    responses((status = 200, description = "The new collection (audited as `design.collection.created`); a folder takes no colours or fonts", body = CollectionView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<NewCollection>,
) -> ApiResult<CollectionView> {
    let kit = req.kind == "brand_kit";
    if !(kit || req.kind == "folder")
        || !name_ok(&req.name)
        || (!kit && !(req.colors.is_empty() && req.fonts.is_empty()))
    {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    check_kit(&mut tx, &req.colors, &req.fonts).await?;
    let project = match req.project.as_deref() {
        Some(p) => Some(project_id(&mut tx, p).await?),
        None => None,
    };
    let id = new_id();
    sqlx::query(
        "INSERT INTO design_collections (id, kind, name, colors, fonts, created_by) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.kind)
    .bind(&req.name)
    .bind(serde_json::to_string(&req.colors).unwrap_or_default())
    .bind(serde_json::to_string(&req.fonts).unwrap_or_default())
    .bind(format!("person:{}", me.device.id))
    .execute(&mut *tx)
    .await?;
    record(&mut tx, "collection", "created", &id, None).await?;
    if let Some(p) = &project {
        sqlx::query(
            "INSERT INTO design_links (item_kind, item, project) VALUES ('collection', ?, ?)",
        )
        .bind(&id)
        .bind(p)
        .execute(&mut *tx)
        .await?;
        record(&mut tx, "collection", "linked", &id, Some(p)).await?;
    }
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(get, path = "/collections/{id}", operation_id = "designGetCollection", tag = "design",
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "The collection with its items", body = CollectionView)))]
pub(crate) async fn get(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<CollectionView> {
    if !id_ok(&id) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(view(&mut conn, &id).await?))
}

/// Every field is optional; `colors` and `fonts` replace the whole list.
#[derive(Deserialize, ToSchema)]
pub struct CollectionPatch {
    pub name: Option<String>,
    pub colors: Option<Vec<String>>,
    pub fonts: Option<Vec<String>>,
}

#[utoipa::path(patch, path = "/collections/{id}", operation_id = "designPatchCollection", tag = "design",
    params(("id" = String, Path, description = "Collection id")), request_body = CollectionPatch,
    responses((status = 200, description = "The changed collection (audited as `design.collection.changed`)", body = CollectionView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(id): Path<String>,
    In(req): In<CollectionPatch>,
) -> ApiResult<CollectionView> {
    if !id_ok(&id) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    let cur = view(&mut tx, &id).await?;
    let name = req.name.unwrap_or(cur.name);
    let colors = req.colors.unwrap_or(cur.colors);
    let fonts = req.fonts.unwrap_or(cur.fonts);
    if !name_ok(&name) || (cur.kind == "folder" && !(colors.is_empty() && fonts.is_empty())) {
        return Err(bad());
    }
    check_kit(&mut tx, &colors, &fonts).await?;
    sqlx::query(
        "UPDATE design_collections SET name = ?, colors = ?, fonts = ?, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(&name)
    .bind(serde_json::to_string(&colors).unwrap_or_default())
    .bind(serde_json::to_string(&fonts).unwrap_or_default())
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    record(&mut tx, "collection", "changed", &id, None).await?;
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/collections/{id}", operation_id = "designDeleteCollection", tag = "design",
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "Deleted with its memberships and links, no asset is deleted (step-up; audited as `design.collection.deleted`)", body = CollectionView)))]
pub(crate) async fn delete(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<CollectionView> {
    if !id_ok(&id) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    let out = view(&mut tx, &id).await?;
    sqlx::query("DELETE FROM design_links WHERE item_kind = 'collection' AND item = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM design_collections WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    record(&mut tx, "collection", "deleted", &id, None).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct ItemBody {
    /// A free label, 1 to 32 characters; `null` clears.
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub role: Option<Option<String>>,
}

#[utoipa::path(put, path = "/collections/{id}/items/{sha}", operation_id = "designPutCollectionItem", tag = "design",
    params(("id" = String, Path, description = "Collection id"), ("sha" = String, Path, description = "sha256 of a library asset")),
    request_body = ItemBody,
    responses((status = 200, description = "The asset is in the collection with that role (audited as `design.collection.changed`); adding twice only changes the role", body = CollectionView)))]
pub(crate) async fn put_item(
    State(app): State<App>,
    Path((id, sha)): Path<(String, String)>,
    In(req): In<ItemBody>,
) -> ApiResult<CollectionView> {
    let role = req.role.flatten();
    if !id_ok(&id) {
        return Err(none());
    }
    if !sha_ok(&sha)
        || role
            .as_deref()
            .is_some_and(|r| !(1..=32).contains(&r.chars().count()))
    {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &id).await?;
    let lib: Option<i64> = sqlx::query_scalar("SELECT library FROM design_assets WHERE sha256 = ?")
        .bind(&sha)
        .fetch_optional(&mut *tx)
        .await?;
    if lib != Some(1) {
        return Err(ApiError::not_found("no such asset"));
    }
    sqlx::query(
        "INSERT INTO design_collection_items (collection, sha256, role) VALUES (?1, ?2, ?3) \
         ON CONFLICT (collection, sha256) DO UPDATE SET role = ?3",
    )
    .bind(&id)
    .bind(&sha)
    .bind(role)
    .execute(&mut *tx)
    .await?;
    record(&mut tx, "collection", "changed", &id, None).await?;
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/collections/{id}/items/{sha}", operation_id = "designRemoveCollectionItem", tag = "design",
    params(("id" = String, Path, description = "Collection id"), ("sha" = String, Path, description = "sha256 of the asset")),
    responses((status = 200, description = "Out of the collection, the asset stays (audited as `design.collection.changed`); 404 when it was not in it", body = CollectionView)))]
pub(crate) async fn remove_item(
    State(app): State<App>,
    Path((id, sha)): Path<(String, String)>,
) -> ApiResult<CollectionView> {
    if !id_ok(&id) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &id).await?;
    let gone =
        sqlx::query("DELETE FROM design_collection_items WHERE collection = ? AND sha256 = ?")
            .bind(&id)
            .bind(&sha)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found("no such item"));
    }
    record(&mut tx, "collection", "changed", &id, None).await?;
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(put, path = "/collections/{id}/projects/{project}", operation_id = "designLinkCollection", tag = "design",
    params(("id" = String, Path, description = "Collection id"), ("project" = String, Path, description = "Project id")),
    responses((status = 200, description = "Related to the project (audited as `design.collection.linked`); an unknown project is refused", body = CollectionView)))]
pub(crate) async fn link(
    State(app): State<App>,
    Path((id, project)): Path<(String, String)>,
) -> ApiResult<CollectionView> {
    if !id_ok(&id) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &id).await?;
    let p = project_id(&mut tx, &project).await?;
    let added = sqlx::query(
        "INSERT OR IGNORE INTO design_links (item_kind, item, project) VALUES ('collection', ?, ?)",
    )
    .bind(&id)
    .bind(&p)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if added > 0 {
        record(&mut tx, "collection", "linked", &id, Some(&p)).await?;
    }
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/collections/{id}/projects/{project}", operation_id = "designUnlinkCollection", tag = "design",
    params(("id" = String, Path, description = "Collection id"), ("project" = String, Path, description = "Project id")),
    responses((status = 200, description = "No longer related (audited as `design.collection.unlinked`); 404 when it was not", body = CollectionView)))]
pub(crate) async fn unlink(
    State(app): State<App>,
    Path((id, project)): Path<(String, String)>,
) -> ApiResult<CollectionView> {
    if !id_ok(&id) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &id).await?;
    let gone = sqlx::query(
        "DELETE FROM design_links WHERE item_kind = 'collection' AND item = ? AND project = ?",
    )
    .bind(&id)
    .bind(&project)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found("no such link"));
    }
    record(&mut tx, "collection", "unlinked", &id, Some(&project)).await?;
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}
