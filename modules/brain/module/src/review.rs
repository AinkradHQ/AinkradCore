//! Discovery and the review of proposed rooms (E2-1..E2-3): signals and grouping run once when the
//! last collector reports; after that the user accepts, renames, merges, splits and refuses, and
//! marks items. Nothing leaves staging until commit.

use std::collections::BTreeSet;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Paging};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use brain_model::group::{UNSORTED, group};
use brain_model::item::{Author, AuthorKind, Item, Origin, SourceKind};
use brain_model::signals::{RoomKind, extract};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::imports::{record_progress, run_state, staging};
use crate::{Brain, code, rand_id, record};

const KINDS: &[&str] = &[
    "personal",
    "product",
    "employer",
    "client",
    "general",
    "global-safe",
];

#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomConfig {
    /// `approved_providers` (default) or `local_only`.
    pub allowed_models: Option<String>,
    /// Device ids that may read the room besides an admin (an admin sees every room, Q-14).
    pub readers: Option<Vec<String>>,
    pub review_days: Option<i64>,
    pub grants: Option<Vec<String>>,
}

impl RoomConfig {
    fn validate(&self) -> Result<(), ApiError> {
        let bad = |w: &str| Err(ApiError::bad_request(w.to_owned()));
        if self
            .allowed_models
            .as_deref()
            .is_some_and(|m| m != "approved_providers" && m != "local_only")
        {
            return bad("allowed_models is approved_providers or local_only");
        }
        for list in [&self.readers, &self.grants].into_iter().flatten() {
            if list.len() > 50 || list.iter().any(|x| x.is_empty() || x.len() > 100) {
                return bad("at most 50 entries of 1 to 100 characters");
            }
        }
        if self.review_days.is_some_and(|d| !(1..=3650).contains(&d)) {
            return bad("review_days is 1 to 3650");
        }
        Ok(())
    }
}

#[derive(Serialize, ToSchema)]
pub struct ProposalCard {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub kind_guess: String,
    /// `proposed`, `accepted`, `refused`, `merged`, `committed` or `held`.
    pub state: String,
    pub signals: Vec<String>,
    pub warnings: Vec<String>,
    pub item_count: i64,
    pub first: Option<String>,
    pub last: Option<String>,
    pub sample_titles: Vec<String>,
    pub config: RoomConfig,
    pub room: Option<String>,
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(30).collect()
}

fn short_hash(s: &str) -> String {
    Sha256::digest(s.as_bytes())[..3]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn proposal_id(key: &str) -> String {
    if key == UNSORTED {
        UNSORTED.to_owned()
    } else {
        format!("p-{}-{}", slug(key), short_hash(key))
    }
}

pub(crate) fn room_id(name: &str) -> String {
    format!(
        "{}-{}",
        slug(name).trim_matches('-'),
        short_hash(&name.to_lowercase())
    )
}

fn parse<T: serde::de::DeserializeOwned + Default>(s: &str) -> T {
    serde_json::from_str(s).unwrap_or_default()
}

pub(crate) fn item_of(r: &SqliteRow) -> Result<Item, sqlx::Error> {
    let kind: String = r.try_get("source_kind")?;
    let author: String = r.try_get("author_kind")?;
    let links: String = r.try_get("links")?;
    Ok(Item {
        item_id: r.try_get("item_id")?,
        source_kind: serde_json::from_value(json!(kind)).unwrap_or(SourceKind::Doc),
        content_hash: r.try_get("content_hash")?,
        origin: Origin {
            device: r.try_get("device")?,
            path: r.try_get("path")?,
            range: None,
        },
        project_hint: r.try_get("project_hint")?,
        author: Author {
            kind: serde_json::from_value(json!(author)).unwrap_or(AuthorKind::Person),
            name: r.try_get("author_name")?,
        },
        title: r.try_get("title")?,
        text: r.try_get("text")?,
        links: parse(&links),
        started_at: r.try_get("started_at")?,
        ended_at: r.try_get("ended_at")?,
    })
}

/// Runs discovery over the run's staged items and moves the run to `review`.
pub(crate) async fn discover(
    app: &App,
    b: &Brain,
    run: &str,
) -> Result<Option<crate::sync::Outcome>, ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE brain_import_runs SET state = 'discovering', stage = 'discover' WHERE id = ?",
    )
    .bind(run)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let st = staging(app, b, run, false).await?;
    let rows = sqlx::query("SELECT * FROM items ORDER BY started_at, item_id")
        .fetch_all(&st)
        .await?;
    let items: Vec<Item> = rows.iter().map(item_of).collect::<Result<_, _>>()?;
    let proposals = group(&items);
    let mut stx = st.begin().await?;
    for p in &proposals {
        let id = proposal_id(&p.key);
        sqlx::query("INSERT INTO proposals (id, name, kind_guess, kind, signals, warnings) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&id)
            .bind(&p.name)
            .bind(p.kind_guess.as_str())
            .bind(p.kind_guess.as_str())
            .bind(json!(p.signals).to_string())
            .bind(json!(p.warnings).to_string())
            .execute(&mut *stx)
            .await?;
        for item_id in &p.item_ids {
            sqlx::query("UPDATE items SET proposal = ? WHERE item_id = ?")
                .bind(&id)
                .bind(item_id)
                .execute(&mut *stx)
                .await?;
        }
    }
    stx.commit().await?;
    st.close().await;
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("UPDATE brain_import_runs SET state = 'review', stage = 'review' WHERE id = ?")
        .bind(run)
        .execute(&mut *tx)
        .await?;
    let counts = crate::imports::load_counts(app, run).await?;
    record(
        &mut tx,
        "brain.import.discovered",
        json!({"run": run, "proposals": proposals.len()}),
        None,
    )
    .await?;
    record_progress(&mut tx, run, "review", &counts).await?;
    tx.commit().await?;
    // A later run of an already-reviewed source needs no review for rooms the user accepted.
    let kind: String = sqlx::query_scalar("SELECT kind FROM brain_import_runs WHERE id = ?")
        .bind(run)
        .fetch_one(&app.pool)
        .await?;
    if kind == "incremental" {
        return Ok(Some(crate::sync::route_known(app, b, run).await?));
    }
    Ok(None)
}

/// The run must be in review: nothing is edited while collecting or after commit.
async fn review_run(app: &App, b: &Brain, run: &str) -> Result<SqlitePool, ApiError> {
    let (state, _) = run_state(app, run).await?;
    if state != "review" {
        return Err(ApiError::conflict("the run is not in review"));
    }
    staging(app, b, run, false).await
}

async fn employers(st: &SqlitePool, id: &str) -> Result<BTreeSet<&'static str>, ApiError> {
    let rows = sqlx::query("SELECT * FROM items WHERE proposal = ?")
        .bind(id)
        .fetch_all(st)
        .await?;
    let mut out = BTreeSet::new();
    for r in &rows {
        if let Some((n, RoomKind::Employer)) = extract(&item_of(r)?).company {
            out.insert(n);
        }
    }
    Ok(out)
}

/// More than one employer in a proposal: it cannot be accepted (plan §7).
pub(crate) async fn mixed(st: &SqlitePool, id: &str) -> Result<bool, ApiError> {
    Ok(employers(st, id).await?.len() > 1)
}

async fn card(st: &SqlitePool, r: &SqliteRow) -> Result<ProposalCard, ApiError> {
    let id: String = r.try_get("id")?;
    let (n, first, last): (i64, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT count(*), min(started_at), max(started_at) FROM items WHERE proposal = ?",
    )
    .bind(&id)
    .fetch_one(st)
    .await?;
    let titles: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT title FROM items WHERE proposal = ? ORDER BY started_at LIMIT 3",
    )
    .bind(&id)
    .fetch_all(st)
    .await?;
    let (sig, warn, cfg): (String, String, String) = (
        r.try_get("signals")?,
        r.try_get("warnings")?,
        r.try_get("config")?,
    );
    let mut warnings: Vec<String> = parse(&warn);
    if mixed(st, &id).await? {
        warnings.push("mixed_employers".to_owned());
    }
    Ok(ProposalCard {
        name: r.try_get("name")?,
        kind: r.try_get("kind")?,
        kind_guess: r.try_get("kind_guess")?,
        state: r.try_get("state")?,
        signals: parse(&sig),
        warnings,
        item_count: n,
        first,
        last,
        sample_titles: titles,
        config: parse(&cfg),
        room: r.try_get("room")?,
        id,
    })
}

#[utoipa::path(get, path = "/imports/{run}/proposals", operation_id = "brainProposals", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "The proposed rooms, Unsorted last", body = Vec<ProposalCard>)))]
pub(crate) async fn proposals(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<Vec<ProposalCard>> {
    run_state(&app, &run).await?;
    let st = staging(&app, &b, &run, false).await?;
    let rows = sqlx::query(
        "SELECT * FROM proposals WHERE state != 'merged' ORDER BY id = 'unsorted', lower(name)",
    )
    .fetch_all(&st)
    .await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(card(&st, r).await?);
    }
    st.close().await;
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct ItemRow {
    pub id: String,
    pub cursor: i64,
    pub title: String,
    pub started_at: String,
    pub source_kind: String,
    /// `needed`, `refused` or none.
    pub mark: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ItemPage {
    pub items: Vec<ItemRow>,
    pub next: Option<i64>,
}

#[utoipa::path(get, path = "/imports/{run}/proposals/{p}/items", operation_id = "brainProposalItems", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id"),
        ("after" = Option<i64>, Query, description = "Cursor of the last item seen"),
        ("limit" = Option<u32>, Query, description = "Page size, at most 200")),
    responses((status = 200, description = "Titles, dates and sources; text is not sent", body = ItemPage)))]
pub(crate) async fn proposal_items(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
    Query(page): Query<Paging>,
) -> ApiResult<ItemPage> {
    run_state(&app, &run).await?;
    let st = staging(&app, &b, &run, false).await?;
    let limit = i64::from(page.limit.unwrap_or(50).clamp(1, 200));
    let rows = sqlx::query(
        "SELECT rowid AS cursor, item_id, title, started_at, source_kind, mark, warnings FROM items \
         WHERE proposal = ? AND rowid > ? ORDER BY rowid LIMIT ?",
    )
    .bind(&p)
    .bind(page.after.unwrap_or(0))
    .bind(limit + 1)
    .fetch_all(&st)
    .await?;
    st.close().await;
    let mut items: Vec<ItemRow> = Vec::new();
    for r in rows.iter().take(limit as usize) {
        let w: String = r.try_get("warnings")?;
        items.push(ItemRow {
            id: r.try_get("item_id")?,
            cursor: r.try_get("cursor")?,
            title: r.try_get("title")?,
            started_at: r.try_get("started_at")?,
            source_kind: r.try_get("source_kind")?,
            mark: r.try_get("mark")?,
            warnings: parse(&w),
        });
    }
    let next = (rows.len() as i64 > limit).then(|| items.last().map_or(0, |i| i.cursor));
    Ok(Json(ItemPage { items, next }))
}

#[derive(Deserialize, ToSchema)]
pub struct ProposalPatch {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub config: Option<RoomConfig>,
    /// `accepted` or `proposed`.
    pub state: Option<String>,
}

async fn one(st: &SqlitePool, id: &str) -> Result<SqliteRow, ApiError> {
    sqlx::query("SELECT * FROM proposals WHERE id = ?")
        .bind(id)
        .fetch_optional(st)
        .await?
        .ok_or_else(|| ApiError::not_found("no such proposal"))
}

fn editable(state: &str) -> Result<(), ApiError> {
    match state {
        "committed" | "merged" => Err(ApiError::conflict(
            "that room is already imported or merged",
        )),
        _ => Ok(()),
    }
}

#[utoipa::path(patch, path = "/imports/{run}/proposals/{p}", operation_id = "brainPatchProposal", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id")),
    request_body = ProposalPatch,
    responses((status = 200, description = "The updated card", body = ProposalCard)))]
pub(crate) async fn patch_proposal(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
    Json(req): Json<ProposalPatch>,
) -> ApiResult<ProposalCard> {
    let st = review_run(&app, &b, &run).await?;
    let row = one(&st, &p).await?;
    editable(&row.try_get::<String, _>("state")?)?;
    if let Some(n) = &req.name {
        if n.trim().is_empty() || n.chars().count() > 100 {
            return Err(ApiError::bad_request("a name of 1 to 100 characters"));
        }
        sqlx::query("UPDATE proposals SET name = ? WHERE id = ?")
            .bind(n.trim())
            .bind(&p)
            .execute(&st)
            .await?;
    }
    if let Some(k) = &req.kind {
        if !KINDS.contains(&k.as_str()) {
            return Err(ApiError::bad_request("an unknown room kind"));
        }
        sqlx::query("UPDATE proposals SET kind = ? WHERE id = ?")
            .bind(k)
            .bind(&p)
            .execute(&st)
            .await?;
    }
    if let Some(c) = &req.config {
        c.validate()?;
        sqlx::query("UPDATE proposals SET config = ? WHERE id = ?")
            .bind(serde_json::to_string(c).expect("config"))
            .bind(&p)
            .execute(&st)
            .await?;
    }
    match req.state.as_deref() {
        None => {}
        Some("proposed") => {
            sqlx::query("UPDATE proposals SET state = 'proposed' WHERE id = ? AND state IN ('accepted','held')")
                .bind(&p)
                .execute(&st)
                .await?;
        }
        Some("accepted") => {
            if p == UNSORTED {
                return Err(code(
                    400,
                    "unsorted_not_a_room",
                    "Unsorted is not a room: move its items to one",
                ));
            }
            if mixed(&st, &p).await? {
                return Err(code(
                    409,
                    "mixed_employers",
                    "two employers in one room: split it first",
                ));
            }
            sqlx::query("UPDATE proposals SET state = 'accepted' WHERE id = ?")
                .bind(&p)
                .execute(&st)
                .await?;
        }
        Some(_) => return Err(ApiError::bad_request("state is accepted or proposed")),
    }
    let out = card(&st, &one(&st, &p).await?).await?;
    st.close().await;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct MergeInto {
    pub into: String,
}

#[utoipa::path(post, path = "/imports/{run}/proposals/{p}/merge", operation_id = "brainMergeProposal", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id")),
    request_body = MergeInto,
    responses((status = 200, description = "The room merged into", body = ProposalCard)))]
pub(crate) async fn merge(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
    Json(req): Json<MergeInto>,
) -> ApiResult<ProposalCard> {
    let st = review_run(&app, &b, &run).await?;
    if req.into == p || req.into == UNSORTED {
        return Err(ApiError::bad_request(
            "merge into another room, not into itself or Unsorted",
        ));
    }
    editable(&one(&st, &p).await?.try_get::<String, _>("state")?)?;
    editable(&one(&st, &req.into).await?.try_get::<String, _>("state")?)?;
    let mut tx = st.begin().await?;
    sqlx::query("UPDATE items SET proposal = ? WHERE proposal = ?")
        .bind(&req.into)
        .bind(&p)
        .execute(&mut *tx)
        .await?;
    if p == UNSORTED {
        sqlx::query("UPDATE proposals SET warnings = '[]' WHERE id = ?")
            .bind(UNSORTED)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("UPDATE proposals SET state = 'merged' WHERE id = ?")
            .bind(&p)
            .execute(&mut *tx)
            .await?;
    }
    // Both ends are reviewed again: a merged room is a new question.
    sqlx::query(
        "UPDATE proposals SET state = 'proposed' WHERE id = ? AND state IN ('accepted','held')",
    )
    .bind(&req.into)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let out = card(&st, &one(&st, &req.into).await?).await?;
    st.close().await;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct SplitItems {
    pub item_ids: Vec<String>,
    pub name: Option<String>,
}

#[utoipa::path(post, path = "/imports/{run}/proposals/{p}/split", operation_id = "brainSplitProposal", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id")),
    request_body = SplitItems,
    responses((status = 200, description = "The new room", body = ProposalCard)))]
pub(crate) async fn split(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
    Json(req): Json<SplitItems>,
) -> ApiResult<ProposalCard> {
    let st = review_run(&app, &b, &run).await?;
    let row = one(&st, &p).await?;
    editable(&row.try_get::<String, _>("state")?)?;
    if req.item_ids.is_empty() || req.item_ids.len() > 5000 {
        return Err(ApiError::bad_request("1 to 5000 item ids"));
    }
    let name = req.name.clone().unwrap_or_else(|| {
        format!(
            "{} (split)",
            row.try_get::<String, _>("name").unwrap_or_default()
        )
    });
    if name.trim().is_empty() || name.chars().count() > 100 {
        return Err(ApiError::bad_request("a name of 1 to 100 characters"));
    }
    let new_id = rand_id("p-split-");
    let mut tx = st.begin().await?;
    sqlx::query("INSERT INTO proposals (id, name, kind_guess, kind, signals, warnings) VALUES (?, ?, ?, ?, ?, '[]')")
        .bind(&new_id)
        .bind(name.trim())
        .bind(row.try_get::<String, _>("kind_guess")?)
        .bind(row.try_get::<String, _>("kind")?)
        .bind(row.try_get::<String, _>("signals")?)
        .execute(&mut *tx)
        .await?;
    for id in &req.item_ids {
        let moved = sqlx::query("UPDATE items SET proposal = ? WHERE item_id = ? AND proposal = ?")
            .bind(&new_id)
            .bind(id)
            .bind(&p)
            .execute(&mut *tx)
            .await?;
        if moved.rows_affected() != 1 {
            return Err(ApiError::bad_request("an item id is not in that room"));
        }
    }
    sqlx::query(
        "UPDATE proposals SET state = 'proposed' WHERE id = ? AND state IN ('accepted','held')",
    )
    .bind(&p)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let out = card(&st, &one(&st, &new_id).await?).await?;
    st.close().await;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/imports/{run}/proposals/{p}/refuse", operation_id = "brainRefuseProposal", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id")),
    responses((status = 200, description = "The refused room; a draft rule per folder is written (enabled at commit)", body = ProposalCard)))]
pub(crate) async fn refuse(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
) -> ApiResult<ProposalCard> {
    let st = review_run(&app, &b, &run).await?;
    let row = one(&st, &p).await?;
    editable(&row.try_get::<String, _>("state")?)?;
    let signals: Vec<String> = parse(&row.try_get::<String, _>("signals")?);
    sqlx::query("UPDATE proposals SET state = 'refused' WHERE id = ?")
        .bind(&p)
        .execute(&st)
        .await?;
    // Unsorted holds items with no folder in common, so refusing it writes no rule.
    if p != UNSORTED {
        let mut tx = begin_write(&app.pool).await?;
        for f in signals.iter().filter_map(|s| s.strip_prefix("folder:")) {
            sqlx::query(
                "INSERT OR IGNORE INTO brain_rules (kind, pattern, action, origin, enabled, reason) \
                 VALUES ('project', ?, 'refuse', 'user', 0, ?)",
            )
            .bind(f)
            .bind(format!("draft:{run}"))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    }
    let out = card(&st, &row_again(&st, &p).await?).await?;
    st.close().await;
    Ok(Json(out))
}

async fn row_again(st: &SqlitePool, id: &str) -> Result<SqliteRow, ApiError> {
    one(st, id).await
}

#[derive(Serialize, ToSchema)]
pub struct Changed {
    pub changed: u64,
}

#[derive(Deserialize, ToSchema)]
pub struct ItemsPatch {
    pub ids: Vec<String>,
    /// `needed`, `refused` or `clear`.
    pub mark: Option<String>,
    /// Move the items to this proposal.
    pub proposal: Option<String>,
}

#[utoipa::path(patch, path = "/imports/{run}/items", operation_id = "brainPatchItems", tag = "brain",
    params(("run" = String, Path, description = "Run id")), request_body = ItemsPatch,
    responses((status = 200, description = "How many items changed", body = Changed)))]
pub(crate) async fn patch_items(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
    Json(req): Json<ItemsPatch>,
) -> ApiResult<Changed> {
    let st = review_run(&app, &b, &run).await?;
    if req.ids.is_empty() || req.ids.len() > 5000 {
        return Err(ApiError::bad_request("1 to 5000 item ids"));
    }
    let mark = match req.mark.as_deref() {
        None => None,
        Some("clear") => Some(None),
        Some(m @ ("needed" | "refused")) => Some(Some(m)),
        Some(_) => return Err(ApiError::bad_request("mark is needed, refused or clear")),
    };
    if let Some(target) = &req.proposal {
        editable(&one(&st, target).await?.try_get::<String, _>("state")?)?;
    }
    let mut tx = st.begin().await?;
    let mut changed = 0u64;
    for id in &req.ids {
        let cur: Option<(Option<String>,)> =
            sqlx::query_as("SELECT proposal FROM items WHERE item_id = ?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((cur,)) = cur else {
            return Err(ApiError::bad_request("an item id is not in this run"));
        };
        if let Some(c) = &cur {
            editable(&one_tx(&mut tx, c).await?)?;
        }
        if let Some(m) = mark {
            sqlx::query("UPDATE items SET mark = ? WHERE item_id = ?")
                .bind(m)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        if let Some(target) = &req.proposal {
            sqlx::query("UPDATE items SET proposal = ? WHERE item_id = ?")
                .bind(target)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            // A changed room is reviewed again.
            sqlx::query("UPDATE proposals SET state = 'proposed' WHERE id IN (?, ?) AND state IN ('accepted','held')")
                .bind(target)
                .bind(cur.as_deref().unwrap_or(""))
                .execute(&mut *tx)
                .await?;
        }
        changed += 1;
    }
    tx.commit().await?;
    st.close().await;
    Ok(Json(Changed { changed }))
}

async fn one_tx(tx: &mut sqlx::SqliteConnection, id: &str) -> Result<String, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT state FROM proposals WHERE id = ?")
            .bind(id)
            .fetch_one(tx)
            .await?,
    )
}
