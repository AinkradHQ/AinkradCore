//! AI tidy: when the semantic step finishes, its strong suggestions are applied to the Review
//! proposal (staging only; nothing reaches the Brain before Import), so the person sees fewer rooms
//! and no near-copies. Every change is recorded as one changeset on the run, shown by
//! `GET /imports/{run}/semantic/changes` and undone, exactly, by `POST /imports/{run}/semantic/undo`.

use std::collections::HashMap;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::group::UNSORTED;
use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};
use utoipa::ToSchema;

use crate::imports::{run_state, staging};
use crate::semantic::Thresholds;
use crate::suggest::SemanticView;
use crate::{Brain, code};

mod plan;
pub(crate) use plan::{Hints, RoomIn, plan};

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
    /// The similarity that made the change, 0 to 1 (0 for a junk room folded into Unsorted, 1 for
    /// two rooms merged because their names are one name).
    #[serde(default)]
    pub score: f32,
    /// The titles of `item_ids`, in the same order (in the list of changes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_titles: Option<Vec<String>>,
    /// For `duplicate`: the kept item's title (its room is `to_name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_title: Option<String>,
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
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<TidyChanges> {
    run_state(&app, &run).await?;
    let st = staging(&app, &b, &run, false).await?;
    let ai_tidy = view(&st, &run).await?;
    let changes: Option<String> = sqlx::query_scalar("SELECT changes FROM tidy WHERE id = 1")
        .fetch_optional(&st)
        .await?;
    let mut changes: Vec<TidyChange> = changes
        .map(|c| serde_json::from_str(&c).unwrap_or_default())
        .unwrap_or_default();
    // Titles and the kept item's room, so the App needs no second read.
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT i.item_id, i.title, p.name FROM items i LEFT JOIN proposals p ON p.id = i.proposal",
    )
    .fetch_all(&st)
    .await?;
    st.close().await;
    let by: HashMap<&str, (&str, Option<&str>)> = rows
        .iter()
        .map(|(i, t, r)| (i.as_str(), (t.as_str(), r.as_deref())))
        .collect();
    let title = |id: &str| by.get(id).map_or("", |x| x.0).to_owned();
    for c in &mut changes {
        c.item_titles = Some(c.item_ids.iter().map(|i| title(i)).collect());
        if c.kind == "duplicate" {
            c.to_title = Some(title(&c.to));
            c.to_name = by.get(c.to.as_str()).and_then(|x| x.1).map(str::to_owned);
        }
    }
    Ok(Json(TidyChanges { ai_tidy, changes }))
}

#[utoipa::path(post, path = "/imports/{run}/semantic/undo", operation_id = "brainUndoTidy", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "The proposal is restored exactly as it was before the AI tidy; `ai_tidy.state` is `undone`. 409 when there is no applied tidy", body = SemanticView)))]
pub(crate) async fn undo(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<SemanticView> {
    if run_state(&app, &run).await?.0 != "review" {
        return Err(ApiError::conflict("the run is not in review"));
    }
    let st = staging(&app, &b, &run, false).await?;
    let mut tx = st.begin().await?;
    let snap: Option<String> =
        sqlx::query_scalar("SELECT snapshot FROM tidy WHERE id = 1 AND state = 'applied'")
            .fetch_optional(&mut *tx)
            .await?;
    let Some(snap) = snap else {
        return Err(code(409, "no_tidy", "there is no AI tidy to undo"));
    };
    let snap: Snapshot =
        serde_json::from_str(&snap).map_err(|e| code(500, "tidy_unreadable", e.to_string()))?;
    for (id, proposal, mark) in &snap.items {
        sqlx::query("UPDATE items SET proposal = ?, mark = ? WHERE item_id = ?")
            .bind(proposal)
            .bind(mark)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM proposals")
        .execute(&mut *tx)
        .await?;
    for p in &snap.proposals {
        sqlx::query("INSERT INTO proposals (id, name, kind_guess, kind, signals, warnings, config, state, room) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&p.id)
            .bind(&p.name)
            .bind(&p.kind_guess)
            .bind(&p.kind)
            .bind(&p.signals)
            .bind(&p.warnings)
            .bind(&p.config)
            .bind(&p.state)
            .bind(&p.room)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE tidy SET state = 'undone' WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    st.close().await;
    crate::suggest::get(State(app), Extension(b), Path(run)).await
}

fn summary(changes: &[TidyChange], before: u64, after: u64) -> TidySummary {
    let n = |k: &'static str| changes.iter().filter(move |c| c.kind == k);
    TidySummary {
        duplicates_merged: n("duplicate").map(|c| c.item_ids.len() as u64).sum(),
        rooms_merged: n("merge").count() as u64,
        rooms_folded: n("fold").count() as u64,
        items_moved: n("move").count() as u64,
        rooms_before: before,
        rooms_after: after,
    }
}

/// Rooms the Review list shows, Unsorted not counted.
async fn room_count(tx: &mut SqliteConnection) -> Result<u64, sqlx::Error> {
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM proposals WHERE state != 'merged' AND id != ?")
            .bind(UNSORTED)
            .fetch_one(tx)
            .await?;
    Ok(n as u64)
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    /// item_id, proposal, mark.
    items: Vec<(String, Option<String>, Option<String>)>,
    proposals: Vec<ProposalRow>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct ProposalRow {
    id: String,
    name: String,
    kind_guess: String,
    kind: String,
    signals: String,
    warnings: String,
    config: String,
    state: String,
    room: Option<String>,
}

/// Plans and applies the tidy inside the caller's staging transaction (the one that marks the step
/// `ready`, so the App never sees a ready step without its tidy). Staging only.
pub(crate) async fn apply(
    tx: &mut SqliteConnection,
    employers: &HashMap<String, Option<String>>,
    vecs: &HashMap<String, Vec<f32>>,
    h: &Hints<'_>,
    th: Thresholds,
) -> Result<(), ApiError> {
    let items: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT item_id, proposal, mark FROM items ORDER BY item_id")
            .fetch_all(&mut *tx)
            .await?;
    let proposals: Vec<ProposalRow> = sqlx::query_as("SELECT * FROM proposals ORDER BY id")
        .fetch_all(&mut *tx)
        .await?;
    // Only rooms nobody decided on yet: accepted, refused and held rooms stay as the person left them.
    let mut rooms: Vec<RoomIn> = proposals
        .iter()
        .filter(|p| p.state == "proposed" && p.id != UNSORTED)
        .filter_map(|p| {
            Some(RoomIn {
                id: p.id.clone(),
                name: p.name.clone(),
                employer: employers.get(&p.id)?.clone(),
                items: vec![],
            })
        })
        .collect();
    let mut unsorted = vec![];
    for (id, prop, mark) in &items {
        if mark.as_deref() == Some("refused") {
            continue;
        }
        match prop.as_deref() {
            None | Some(UNSORTED) => unsorted.push(id.clone()),
            Some(p) => {
                if let Some(r) = rooms.iter_mut().find(|r| r.id == p) {
                    r.items.push(id.clone());
                }
            }
        }
    }
    // A step over a proposal tidied already (a resumed step): Undo still goes back to before the
    // first tidy, and the changes add up.
    let prior: Option<(String, String, String)> = sqlx::query_as(
        "SELECT summary, changes, snapshot FROM tidy WHERE id = 1 AND state = 'applied'",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let mut before = room_count(tx).await?;
    let new = plan(rooms, &unsorted, vecs, h, th);
    let mut changes: Vec<TidyChange> = vec![];
    let mut snapshot = serde_json::to_string(&Snapshot { items, proposals }).expect("snapshot");
    if let Some((s, c, snap)) = prior {
        before = serde_json::from_str::<TidySummary>(&s)
            .unwrap_or_default()
            .rooms_before;
        changes = serde_json::from_str(&c).unwrap_or_default();
        snapshot = snap;
    } else if new.is_empty() {
        sqlx::query("DELETE FROM tidy").execute(&mut *tx).await?;
        return Ok(());
    }
    if new.iter().any(|c| c.to == UNSORTED) {
        sqlx::query("INSERT OR IGNORE INTO proposals (id, name, kind_guess, kind) VALUES (?, 'Unsorted', 'general', 'general')")
            .bind(UNSORTED)
            .execute(&mut *tx)
            .await?;
    }
    // In order: a room merged and then folded moves twice, so every item lands in the final room.
    for c in &new {
        match (c.kind.as_str(), &c.from) {
            ("duplicate", _) => {
                for id in &c.item_ids {
                    sqlx::query("UPDATE items SET mark = 'refused' WHERE item_id = ?")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
            ("move", _) => {
                sqlx::query("UPDATE items SET proposal = ? WHERE item_id = ?")
                    .bind(&c.to)
                    .bind(&c.item_ids[0])
                    .execute(&mut *tx)
                    .await?;
            }
            (_, Some(from)) => {
                // Every item of the room, the merged near-copies too, as the merge route does.
                sqlx::query("UPDATE items SET proposal = ? WHERE proposal = ?")
                    .bind(&c.to)
                    .bind(from)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE proposals SET state = 'merged' WHERE id = ?")
                    .bind(from)
                    .execute(&mut *tx)
                    .await?;
            }
            _ => {}
        }
    }
    changes.extend(new);
    let after = room_count(tx).await?;
    sqlx::query("INSERT OR REPLACE INTO tidy (id, state, summary, changes, snapshot) VALUES (1, 'applied', ?, ?, ?)")
        .bind(serde_json::to_string(&summary(&changes, before, after)).expect("summary"))
        .bind(serde_json::to_string(&changes).expect("changes"))
        .bind(snapshot)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// The run's tidy for `SemanticView.ai_tidy`; `None` when the last step changed nothing.
pub(crate) async fn view(st: &SqlitePool, run: &str) -> Result<Option<AiTidy>, ApiError> {
    let r: Option<(String, String)> =
        sqlx::query_as("SELECT state, summary FROM tidy WHERE id = 1")
            .fetch_optional(st)
            .await?;
    Ok(r.map(|(state, s)| AiTidy {
        state,
        summary: serde_json::from_str(&s).unwrap_or_default(),
        changes_url: format!("/modules/brain/v1/imports/{run}/semantic/changes"),
    }))
}

/// Whether an AI tidy is applied to the run's proposal now.
pub(crate) async fn applied(st: &SqlitePool) -> Result<bool, ApiError> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM tidy WHERE state = 'applied'")
        .fetch_one(st)
        .await?;
    Ok(n > 0)
}

/// Before a re-sort: the near-copies the tidy merged are items again (the new step finds them
/// anew), and the old changeset is dropped. A tidy already undone left nothing to clear.
pub(crate) async fn forget(tx: &mut SqliteConnection) -> Result<(), ApiError> {
    let r: Option<(String, String)> =
        sqlx::query_as("SELECT state, changes FROM tidy WHERE id = 1")
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((state, changes)) = r
        && state == "applied"
    {
        let changes: Vec<TidyChange> = serde_json::from_str(&changes).unwrap_or_default();
        for id in changes
            .iter()
            .filter(|c| c.kind == "duplicate")
            .flat_map(|c| &c.item_ids)
        {
            sqlx::query("UPDATE items SET mark = NULL WHERE item_id = ? AND mark = 'refused'")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("DELETE FROM tidy").execute(&mut *tx).await?;
    Ok(())
}
