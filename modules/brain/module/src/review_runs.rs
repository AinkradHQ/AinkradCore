//! Review helpers for the App: the runs waiting in review (found again after a restart), and a
//! whole place moved to Unsorted in one call. Counts and ids only, no text.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use brain_model::group::UNSORTED;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::imports::{run_state, staging};
use crate::{Brain, code};

#[derive(Deserialize, IntoParams)]
pub struct RunFilter {
    /// Only runs in this state (`review`, `committed`, ...); all runs when absent.
    pub state: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RunSummary {
    pub run: String,
    pub kind: String,
    pub state: String,
    pub started_at: String,
    /// For a run in review: its places (Unsorted and merged-away rooms not counted).
    #[schema(required = false)]
    pub places: Option<i64>,
    /// For a run in review: the items waiting in Unsorted.
    #[schema(required = false)]
    pub unsorted: Option<i64>,
}

#[utoipa::path(get, path = "/imports", operation_id = "brainImports", tag = "brain",
    params(RunFilter),
    responses((status = 200, description = "The newest 50 import runs, newest first; `?state=review` lists the runs waiting for the person's review", body = Vec<RunSummary>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Query(f): Query<RunFilter>,
) -> ApiResult<Vec<RunSummary>> {
    let rows = sqlx::query(
        "SELECT id, kind, state, started_at FROM brain_import_runs WHERE ?1 IS NULL OR state = ?1 \
         ORDER BY started_at DESC, id DESC LIMIT 50",
    )
    .bind(&f.state)
    .fetch_all(&app.pool)
    .await?;
    let mut out = vec![];
    for r in rows {
        let (run, state): (String, String) = (r.try_get("id")?, r.try_get("state")?);
        let (mut places, mut unsorted) = (None, None);
        if state == "review"
            && let Ok(st) = staging(&app, &b, &run, false).await
        {
            places = sqlx::query_scalar(
                "SELECT count(*) FROM proposals p WHERE id != ?1 AND state NOT IN ('merged','refused','committed') \
                 AND EXISTS (SELECT 1 FROM items i WHERE i.proposal = p.id)",
            )
            .bind(UNSORTED)
            .fetch_one(&st)
            .await
            .ok();
            unsorted = sqlx::query_scalar("SELECT count(*) FROM items WHERE proposal = ?")
                .bind(UNSORTED)
                .fetch_one(&st)
                .await
                .ok();
            st.close().await;
        }
        out.push(RunSummary {
            run,
            kind: r.try_get("kind")?,
            state,
            started_at: r.try_get("started_at")?,
            places,
            unsorted,
        });
    }
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct Moved {
    /// Items moved to Unsorted.
    pub items: i64,
}

#[utoipa::path(post, path = "/imports/{run}/proposals/{p}/to-unsorted", operation_id = "brainProposalToUnsorted", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id")),
    responses((status = 200, description = "Moves every item of the place to Unsorted. The emptied place is dropped silently at commit (never imported, never refused). 409 when the run is not in review or the place is imported or merged", body = Moved)))]
pub(crate) async fn to_unsorted(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
) -> ApiResult<Moved> {
    if run_state(&app, &run).await?.0 != "review" {
        return Err(ApiError::conflict("the run is not in review"));
    }
    if p == UNSORTED {
        return Err(ApiError::bad_request("that is Unsorted already"));
    }
    let st = staging(&app, &b, &run, false).await?;
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM proposals WHERE id = ?")
        .bind(&p)
        .fetch_optional(&st)
        .await?;
    match state.as_deref() {
        None => return Err(ApiError::not_found("no such proposal")),
        Some("committed" | "merged") => {
            return Err(code(
                409,
                "not_editable",
                "that room is already imported or merged",
            ));
        }
        _ => {}
    }
    let mut tx = st.begin().await?;
    sqlx::query(
        "INSERT OR IGNORE INTO proposals (id, name, kind_guess, kind) VALUES (?, 'Unsorted', 'general', 'general')",
    )
    .bind(UNSORTED)
    .execute(&mut *tx)
    .await?;
    let items = sqlx::query("UPDATE items SET proposal = ? WHERE proposal = ?")
        .bind(UNSORTED)
        .bind(&p)
        .execute(&mut *tx)
        .await?
        .rows_affected() as i64;
    sqlx::query(
        "UPDATE proposals SET state = 'proposed' WHERE id = ? AND state IN ('accepted','held')",
    )
    .bind(&p)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    st.close().await;
    Ok(Json(Moved { items }))
}
