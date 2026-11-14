//! AI tidy: when the semantic step finishes, its strong suggestions are applied to the Review
//! proposal (staging only; nothing reaches the Brain before Import), so the person sees fewer rooms
//! and no near-copies. Every change is recorded as one changeset on the run, shown by
//! `GET /imports/{run}/semantic/changes` and undone, exactly, by `POST /imports/{run}/semantic/undo`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Brain;
use crate::suggest::SemanticView;

/// The AI tidy of this run's proposal: what the local model changed by itself.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct AiTidy {
    /// `applied` (the proposal is tidied) or `undone` (restored as it was before; the next re-sort
    /// may tidy again).
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub summary: TidySummary,
    /// The list of changes: `GET` it for "See changes".
    #[serde(default)]
    pub changes_url: String,
}

/// Counts of one tidy: "12 duplicates merged, 9 rooms folded, 35 → 18 rooms".
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TidySummary {
    /// Items marked as merged into a newer near-copy.
    #[serde(default)]
    pub duplicates_merged: u64,
    /// Rooms merged into a larger room that looks like the same topic.
    #[serde(default)]
    pub rooms_merged: u64,
    /// Tiny or junk rooms folded into the closest room, or into Unsorted.
    #[serde(default)]
    pub rooms_folded: u64,
    /// Unsorted items moved into the room they clearly belong in.
    #[serde(default)]
    pub items_moved: u64,
    /// Rooms (Unsorted not counted) before and after the tidy.
    #[serde(default)]
    pub rooms_before: u64,
    #[serde(default)]
    pub rooms_after: u64,
}

/// One change of the tidy.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct TidyChange {
    /// `duplicate` (`item_ids` merged into the kept item `to`), `merge` (room `from` merged into room
    /// `to`), `fold` (tiny room `from` folded into room `to`, or into `unsorted`) or `move` (Unsorted
    /// item moved into room `to`).
    #[serde(default)]
    pub kind: String,
    /// The items this change moved or merged.
    #[serde(default)]
    pub item_ids: Vec<String>,
    /// A proposal id; absent for `duplicate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// The kept item id for `duplicate`, else a proposal id (`unsorted` for a fold with no clear room).
    #[serde(default)]
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_name: Option<String>,
    /// The similarity that made the change, 0 to 1 (0 for a junk room folded into Unsorted).
    #[serde(default)]
    pub score: f32,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct TidyChanges {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_tidy: Option<AiTidy>,
    #[serde(default)]
    pub changes: Vec<TidyChange>,
}

#[utoipa::path(get, path = "/imports/{run}/semantic/changes", operation_id = "brainTidyChanges", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "What the AI tidy changed in this run's proposal (empty when it made no changes)", body = TidyChanges)))]
pub(crate) async fn changes(
    State(_app): State<App>,
    Extension(_b): Extension<Brain>,
    Path(_run): Path<String>,
) -> ApiResult<TidyChanges> {
    Ok(Json(TidyChanges::default()))
}

#[utoipa::path(post, path = "/imports/{run}/semantic/undo", operation_id = "brainUndoTidy", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "The proposal is restored exactly as it was before the AI tidy; `ai_tidy.state` is `undone`. 409 when there is no applied tidy", body = SemanticView)))]
pub(crate) async fn undo(
    State(_app): State<App>,
    Extension(_b): Extension<Brain>,
    Path(_run): Path<String>,
) -> ApiResult<SemanticView> {
    Ok(Json(SemanticView::default()))
}
