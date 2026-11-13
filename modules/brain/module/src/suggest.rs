//! The semantic step of Review: after the rule-based rooms exist, a background task asks the local
//! model for duplicates, topic rooms for Unsorted and merge hints, and keeps them in the run's
//! staging file. Review never waits for it; with no model the step is simply `off`. Every output is
//! a suggestion: accepting one goes through the existing routes (split Unsorted into a named room,
//! patch items as refused, merge).

use std::collections::{HashMap, HashSet};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::begin_write;
use ainkrad_core_server::store::modsettings::ModuleSettings;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::group::UNSORTED;
use brain_model::item::Item;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::imports::{run_state, staging};
use crate::review::item_of;
use crate::semantic::{self, Input, MIN_CLUSTER, ProposalRef, Thresholds};
use crate::{Brain, code};

#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct SemanticView {
    /// `pending` (working now), `ready` or `off` (no local model, or the step failed).
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub duplicates: Vec<DuplicateHint>,
    #[serde(default)]
    pub rooms: Vec<RoomHint>,
    #[serde(default)]
    pub merges: Vec<MergeHint>,
}

/// Items that are nearly the same text. To accept: mark `item_ids` except `keep` as refused.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DuplicateHint {
    /// The newest of the group.
    pub keep: String,
    /// Every item of the group, `keep` included.
    pub item_ids: Vec<String>,
    /// The lowest similarity inside the group, 0 to 1.
    pub score: f32,
    pub reason: String,
}

/// A topic found among the Unsorted items. To accept: split Unsorted with these `item_ids` and `name`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoomHint {
    pub name: String,
    pub keywords: Vec<String>,
    pub item_ids: Vec<String>,
    pub score: f32,
}

/// Two rooms that look like one topic; `from` is the smaller. To accept: merge `from` into `to`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MergeHint {
    /// A proposal id, or the `name` of a suggested room.
    pub from: String,
    pub to: String,
    pub from_name: Option<String>,
    pub to_name: Option<String>,
    pub score: f32,
    pub reason: String,
}

/// Starts the background step for a run in review. Returns at once; nothing happens with no model.
pub(crate) async fn start(app: &App, b: &Brain, run: &str) {
    if b.embedder().is_none() {
        return;
    }
    if !enabled(app, b).await {
        // Switched off: drop what an earlier step left and embed nothing.
        if let Ok(st) = staging(app, b, run, false).await {
            let _ = sqlx::query("UPDATE semantic SET state = 'off', body = '{}'")
                .execute(&st)
                .await;
            st.close().await;
        }
        return;
    }
    let epoch = match mark_pending(app, b, run).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(run, error = ?e, "the semantic step could not start");
            return;
        }
    };
    let (app, run) = (app.clone(), run.to_owned());
    let worker = b.clone();
    b.inner
        .sem_running
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(run.clone());
    // One worker runs the steps of every run in turn (the shared semantic service's queue).
    b.inner.sem.enqueue(async move {
        let r = work(&app, &worker, &run, epoch).await;
        worker
            .inner
            .sem_running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
        if let Err(e) = r {
            tracing::warn!(run = %run, error = ?e, "the semantic step failed");
            if let Ok(st) = staging(&app, &worker, &run, false).await {
                let _ = sqlx::query("UPDATE semantic SET state = 'off' WHERE epoch = ?")
                    .bind(epoch)
                    .execute(&st)
                    .await;
                st.close().await;
            }
        }
    });
}

/// Queues again every run in review whose step was queued or running when the Core stopped. Its
/// vectors are in the store, so it costs only what was not yet embedded.
impl Brain {
    pub async fn resume_semantic(&self) {
        let (Some(app), Some(_)) = (self.inner.app.get(), self.embedder()) else {
            return;
        };
        let runs: Vec<String> =
            sqlx::query_scalar("SELECT id FROM brain_import_runs WHERE state = 'review'")
                .fetch_all(&app.pool)
                .await
                .unwrap_or_default();
        for run in runs {
            let busy = self
                .inner
                .sem_running
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&run);
            if busy {
                continue;
            }
            let Ok(st) = staging(app, self, &run, false).await else {
                continue;
            };
            let state: Option<String> =
                sqlx::query_scalar("SELECT state FROM semantic WHERE id = 1")
                    .fetch_optional(&st)
                    .await
                    .ok()
                    .flatten();
            st.close().await;
            if state.as_deref() == Some("pending") {
                start(app, self, &run).await;
            }
        }
    }
}

/// `module.brain.semantic.enabled`; on unless the person turned it off.
pub(crate) async fn enabled(app: &App, b: &Brain) -> bool {
    ModuleSettings::of(b)
        .get(&app.pool, "semantic.enabled")
        .await
        .unwrap_or(1)
        != 0
}

async fn mark_pending(app: &App, b: &Brain, run: &str) -> Result<i64, ApiError> {
    let st = staging(app, b, run, false).await?;
    let epoch = sqlx::query_scalar(
        "INSERT INTO semantic (id, state, epoch) VALUES (1, 'pending', 1) \
         ON CONFLICT(id) DO UPDATE SET state = 'pending', epoch = epoch + 1, body = '{}' RETURNING epoch",
    )
    .fetch_one(&st)
    .await?;
    st.close().await;
    Ok(epoch)
}

async fn work(app: &App, b: &Brain, run: &str, epoch: i64) -> Result<(), ApiError> {
    let emb = b
        .embedder()
        .ok_or_else(|| code(500, "semantic_off", "no model"))?;
    let st = staging(app, b, run, false).await?;
    let rows = sqlx::query("SELECT * FROM items ORDER BY started_at, item_id")
        .fetch_all(&st)
        .await?;
    // Items the user already refused are never embedded; Unsorted items have no room.
    let mut owned: Vec<(Item, Option<String>)> = Vec::new();
    for r in &rows {
        if r.try_get::<Option<String>, _>("mark")?.as_deref() == Some("refused") {
            continue;
        }
        let room = r
            .try_get::<Option<String>, _>("proposal")?
            .filter(|p| p != UNSORTED);
        owned.push((item_of(r)?, room));
    }
    let live: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM proposals WHERE id != ? AND state NOT IN ('merged', 'refused')",
    )
    .bind(UNSORTED)
    .fetch_all(&st)
    .await?;
    st.close().await;
    let mut members: Vec<(String, Vec<String>)> = live.into_iter().map(|id| (id, vec![])).collect();
    for (item, room) in &owned {
        if let Some(m) = members.iter_mut().find(|m| Some(&m.0) == room.as_ref()) {
            m.1.push(item.item_id.clone());
        }
    }
    // Vectors of an earlier run or session come from the encrypted store, not the model.
    let model = emb.model_id().to_owned();
    let all_hashes: Vec<String> = owned.iter().map(|(i, _)| i.content_hash.clone()).collect();
    b.fill_from_store(app, &model, &all_hashes).await?;
    let before: HashSet<String> = {
        let c = b
            .inner
            .sem
            .cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        all_hashes
            .iter()
            .filter(|h| c.get(&model, h).is_some())
            .cloned()
            .collect()
    };
    b.apply_threads(app).await;
    let strength = ModuleSettings::of(b)
        .get(&app.pool, "semantic.strength")
        .await
        .unwrap_or(1);
    let th = Thresholds::for_strength(strength);
    let vectors = b.inner.sem.cache().clone();
    let (sizes, sug) = {
        let sizes: HashMap<String, usize> =
            members.iter().map(|m| (m.0.clone(), m.1.len())).collect();
        let sug = tokio::task::spawn_blocking(move || {
            let inputs: Vec<Input> = owned
                .iter()
                .map(|(item, room)| Input {
                    item,
                    room: room.as_deref(),
                })
                .collect();
            let refs: Vec<ProposalRef> = members
                .iter()
                .map(|(id, ids)| ProposalRef {
                    name: id,
                    item_ids: ids,
                })
                .collect();
            let mut cache = vectors.lock().unwrap_or_else(|e| e.into_inner());
            semantic::run(emb.as_ref(), &mut cache, &inputs, &refs, th)
        })
        .await
        .map_err(|e| code(500, "semantic_failed", e.to_string()))?
        .map_err(|e| code(500, "semantic_failed", e))?;
        (sizes, sug)
    };
    let size = |n: &str| {
        sizes.get(n).copied().unwrap_or_else(|| {
            sug.rooms
                .iter()
                .find(|r| r.name == n)
                .map_or(0, |r| r.item_ids.len())
        })
    };
    let view = SemanticView {
        state: "ready".into(),
        duplicates: sug
            .duplicates
            .iter()
            .map(|d| DuplicateHint {
                keep: d.keep.clone(),
                item_ids: std::iter::once(d.keep.clone())
                    .chain(d.duplicates.iter().cloned())
                    .collect(),
                score: d.score,
                reason: d.reason.clone(),
            })
            .collect(),
        rooms: sug
            .rooms
            .iter()
            .map(|r| RoomHint {
                name: r.name.clone(),
                keywords: r.keywords.clone(),
                item_ids: r.item_ids.clone(),
                score: r.score,
            })
            .collect(),
        merges: sug
            .merges
            .iter()
            .map(|m| {
                let (from, to) = if size(&m.a) <= size(&m.b) {
                    (&m.a, &m.b)
                } else {
                    (&m.b, &m.a)
                };
                MergeHint {
                    from: from.clone(),
                    to: to.clone(),
                    from_name: None,
                    to_name: None,
                    score: m.score,
                    reason: m.reason.clone(),
                }
            })
            .collect(),
    };
    // Save what this step embedded; items refused meanwhile are skipped (their vectors are deleted).
    let fresh: Vec<(String, Vec<f32>)> = {
        let c = b
            .inner
            .sem
            .cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut seen = HashSet::new();
        all_hashes
            .iter()
            .filter(|h| !before.contains(*h) && seen.insert(*h))
            .filter_map(|h| c.get(&model, h).map(|v| (h.clone(), v.clone())))
            .collect()
    };
    let st = staging(app, b, run, false).await?;
    let still: HashSet<String> =
        sqlx::query_scalar("SELECT content_hash FROM items WHERE mark IS NOT 'refused'")
            .fetch_all(&st)
            .await?
            .into_iter()
            .collect();
    crate::vectors::save(
        app,
        b,
        &model,
        &fresh
            .into_iter()
            .filter(|(h, _)| still.contains(h))
            .collect::<Vec<_>>(),
    )
    .await?;
    let done = sqlx::query("UPDATE semantic SET state = 'ready', body = ? WHERE epoch = ?")
        .bind(serde_json::to_string(&view).expect("suggestions"))
        .bind(epoch)
        .execute(&st)
        .await?
        .rows_affected();
    st.close().await;
    // A newer step (a re-sort) owns the row now: this one is stale and leaves no trace.
    if done == 1 {
        let mut tx = begin_write(&app.pool).await?;
        semantic::audit(&mut tx, &sug.stats).await?;
        tx.commit().await?;
    }
    Ok(())
}

/// `pending`, `ready` or `off`. A `pending` row nobody is working on (the Core restarted) is `off`.
pub(crate) async fn status(
    app: &App,
    st: &SqlitePool,
    b: &Brain,
    run: &str,
) -> Result<String, ApiError> {
    if !enabled(app, b).await {
        return Ok("off".to_owned());
    }
    let s: Option<String> = sqlx::query_scalar("SELECT state FROM semantic WHERE id = 1")
        .fetch_optional(st)
        .await?;
    Ok(match s.as_deref() {
        Some("ready") => "ready",
        Some("pending")
            if b.inner
                .sem_running
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(run) =>
        {
            "pending"
        }
        _ => "off",
    }
    .to_owned())
}

#[utoipa::path(get, path = "/imports/{run}/semantic", operation_id = "brainSemantic", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "The local model's sorting suggestions; only what still applies to the rooms as they are now", body = SemanticView)))]
pub(crate) async fn get(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<SemanticView> {
    run_state(&app, &run).await?;
    let st = staging(&app, &b, &run, false).await?;
    let state = status(&app, &st, &b, &run).await?;
    let mut v = SemanticView {
        state: state.clone(),
        ..Default::default()
    };
    if state == "ready" {
        let body: String = sqlx::query_scalar("SELECT body FROM semantic WHERE id = 1")
            .fetch_one(&st)
            .await?;
        v = serde_json::from_str(&body).unwrap_or(v);
        v.state = state;
        prune(&st, &mut v).await?;
    }
    st.close().await;
    Ok(Json(v))
}

/// Drops what the user's own edits since the step ran made stale: refused items, items moved out
/// of Unsorted, rooms merged away.
async fn prune(st: &SqlitePool, v: &mut SemanticView) -> Result<(), ApiError> {
    let rows = sqlx::query("SELECT item_id, proposal, mark FROM items")
        .fetch_all(st)
        .await?;
    let (mut refused, mut unsorted) = (HashSet::new(), HashSet::new());
    for r in &rows {
        let id: String = r.try_get("item_id")?;
        if r.try_get::<Option<String>, _>("mark")?.as_deref() == Some("refused") {
            refused.insert(id);
        } else if r
            .try_get::<Option<String>, _>("proposal")?
            .is_none_or(|p| p == UNSORTED)
        {
            unsorted.insert(id);
        }
    }
    for d in &mut v.duplicates {
        d.item_ids.retain(|i| !refused.contains(i));
    }
    v.duplicates
        .retain(|d| d.item_ids.len() >= 2 && d.item_ids.contains(&d.keep));
    for r in &mut v.rooms {
        r.item_ids.retain(|i| unsorted.contains(i));
    }
    v.rooms.retain(|r| r.item_ids.len() >= MIN_CLUSTER);
    let props: HashMap<String, (String, String)> =
        sqlx::query("SELECT id, name, state FROM proposals")
            .fetch_all(st)
            .await?
            .iter()
            .map(|r| Ok((r.try_get("id")?, (r.try_get("name")?, r.try_get("state")?))))
            .collect::<Result<_, sqlx::Error>>()?;
    let rooms: HashSet<&str> = v.rooms.iter().map(|r| r.name.as_str()).collect();
    let name_of = |id: &str| match props.get(id) {
        Some((n, s)) if s != "merged" && s != "committed" => Some(Some(n.clone())),
        Some(_) => None,
        None => rooms.contains(id).then_some(None),
    };
    let merges: Vec<MergeHint> = std::mem::take(&mut v.merges)
        .into_iter()
        .filter_map(|mut m| {
            m.from_name = name_of(&m.from)?;
            m.to_name = name_of(&m.to)?;
            Some(m)
        })
        .collect();
    v.merges = merges;
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct BrainSetting {
    /// `semantic.enabled` or `semantic.strength`.
    pub name: String,
    pub value: i64,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    pub description: String,
}

#[derive(Deserialize, ToSchema)]
pub struct BrainSettingBody {
    pub value: i64,
}

async fn setting_out(app: &App, b: &Brain, name: &str) -> Result<BrainSetting, ApiError> {
    let spec = b
        .settings()
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| ApiError::not_found("no such setting"))?;
    let value = ModuleSettings::of(b)
        .get(&app.pool, name)
        .await
        .map_err(|e| code(500, "settings_unavailable", format!("{e:?}")))?;
    Ok(BrainSetting {
        name: spec.name.to_owned(),
        value,
        default: spec.default,
        min: spec.min,
        max: spec.max,
        description: spec.description.to_owned(),
    })
}

#[utoipa::path(get, path = "/settings", operation_id = "brainSettings", tag = "brain",
    responses((status = 200, description = "The Brain's tunables with value, default and bounds: `semantic.enabled` (0 or 1) and `semantic.strength` (0 low, 1 normal, 2 high)", body = Vec<BrainSetting>)))]
pub(crate) async fn settings(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
) -> ApiResult<Vec<BrainSetting>> {
    let mut out = Vec::new();
    for s in b.settings() {
        out.push(setting_out(&app, &b, s.name).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(put, path = "/settings/{name}", operation_id = "brainSetSetting", tag = "brain",
    params(("name" = String, Path, description = "A name from `GET /settings`")),
    request_body = BrainSettingBody,
    responses((status = 200, description = "Set (audited as `setting.set`); 404 for an unknown name, 400 out of bounds. Applies from the next re-sort", body = BrainSetting)))]
pub(crate) async fn put_setting(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(name): Path<String>,
    Json(req): Json<BrainSettingBody>,
) -> ApiResult<BrainSetting> {
    use ainkrad_core_server::store::settings::SetError;
    setting_out(&app, &b, &name).await?;
    ModuleSettings::of(&b)
        .set(
            &app.pool,
            &name,
            &req.value.to_string(),
            ainkrad_core_server::api::v1::BY,
            &app.clock.now(),
        )
        .await
        .map_err(|e| match e {
            SetError::Refused(why) => ApiError::bad_request(why.to_string()),
            SetError::Db(e) => e.into(),
        })?;
    Ok(Json(setting_out(&app, &b, &name).await?))
}
