//! Relating a library asset to a project (D2: related, not owned), the same pattern as design docs.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::Json;
use axum::extract::{Path, State};

use crate::assets::{AssetView, none, record, sha_ok, view};
use crate::docs::project_id;

#[utoipa::path(put, path = "/assets/{sha}/projects/{project}", operation_id = "designLinkAsset", tag = "design",
    params(("sha" = String, Path, description = "sha256 of the asset"), ("project" = String, Path, description = "Project id")),
    responses((status = 200, description = "Related to the project (audited as `design.asset.linked`); an unknown project is refused, linking twice changes nothing", body = AssetView)))]
pub(crate) async fn link(
    State(app): State<App>,
    Path((sha, project)): Path<(String, String)>,
) -> ApiResult<AssetView> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &sha).await?;
    let p = project_id(&mut tx, &project).await?;
    let added = sqlx::query(
        "INSERT OR IGNORE INTO design_links (item_kind, item, project) VALUES ('asset', ?, ?)",
    )
    .bind(&sha)
    .bind(&p)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if added > 0 {
        record(&mut tx, "asset", "linked", &sha, Some(&p)).await?;
    }
    let out = view(&mut tx, &sha).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/assets/{sha}/projects/{project}", operation_id = "designUnlinkAsset", tag = "design",
    params(("sha" = String, Path, description = "sha256 of the asset"), ("project" = String, Path, description = "Project id")),
    responses((status = 200, description = "No longer related (audited as `design.asset.unlinked`); 404 when it was not", body = AssetView)))]
pub(crate) async fn unlink(
    State(app): State<App>,
    Path((sha, project)): Path<(String, String)>,
) -> ApiResult<AssetView> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &sha).await?;
    let gone = sqlx::query(
        "DELETE FROM design_links WHERE item_kind = 'asset' AND item = ? AND project = ?",
    )
    .bind(&sha)
    .bind(&project)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found("no such link"));
    }
    record(&mut tx, "asset", "unlinked", &sha, Some(&project)).await?;
    let out = view(&mut tx, &sha).await?;
    tx.commit().await?;
    Ok(Json(out))
}
