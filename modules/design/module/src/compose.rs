//! The Design composer (E11-4, D-29): "draw 3 directions". One call starts an AI session (a module
//! session like the Brain's distil, owned by no client) that answers with JSON: up to three directions, each
//! a name, a one-line summary and one screen (or, for a single direction, a flow of up to six). The Core never
//! trusts the answer (`compose_answer`): it is read leniently, every number is clamped and every colour checked,
//! and the result becomes frames on the doc's first page through the same CRDT edit as `designApply` (so the
//! model's validators and the `paused` check still apply; origin `session:<id>`). What the AI is told is
//! `compose_prompt`: the platform's rules, the linked design system's tokens, the brand kit, the screens already
//! there, and for an edit (`mode: "edit"`) the frame to change.
//!
//! The finish happens on read: the app polls `GET .../compose/{id}`, and the first poll that finds the
//! session over writes the frames (a compare-and-set on `state` makes that once). A Core restart in
//! between loses nothing: the row and the session are both stored. A compose whose AI stops answering
//! fails after six minutes (`compose_session::reap`).
//!
//! "Use this" is the app's: it deletes the other two frames with `designApply`. "Draw 3 more" and
//! "Refine" are new composes.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::agents as agent_store;
use axum::Json;
use axum::extract::{Extension, Path, State};
use design_model::Node;
use design_model::ids;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use utoipa::ToSchema;

use crate::apply::{edit_err, mint, open_actor, resolve_temps};
use crate::compose_answer::{self as answer, Dim, GAP, clip};
use crate::compose_prompt::{self as ask, brand_line, context};
use crate::compose_session::{self as session, failure_reason, launch, stage_of};
use crate::compose_system::{self, Brand};
use crate::docs::{In, doc_id_ok};
use crate::sync::{Actor, EditError, Registry};

/// The screen a compose draws unless the request gives a size: a phone.
const FRAME_W: f64 = 360.0;
const FRAME_H: f64 = 630.0;
const MIN_SIDE: f64 = 200.0;
const MAX_SIDE: f64 = 4000.0;
const MAX_PROMPT: usize = 1000;

#[derive(Deserialize, ToSchema)]
pub struct NewCompose {
    /// What to draw, 1 to 1000 characters. To refine a direction, say so here with the changes.
    pub prompt: String,
    /// How many directions to draw: 1 or 3 (default 3). An edit draws 1.
    #[serde(default)]
    #[schema(required = false)]
    pub count: Option<u8>,
    /// The screen size to draw at, each side 200 to 4000 points (default 360 x 630, a phone; an edit defaults to the
    /// frame's own size).
    #[serde(default)]
    #[schema(required = false)]
    pub size: Option<ComposeSize>,
    /// `screens` (default): draw frames. `system`: draw a design system's tokens on a `system` doc (no frames; `count`
    /// and `size` are ignored; `directions` holds one entry). `edit`: redraw the frame `frame` with the change asked
    /// for, keeping what it does not touch (one direction, a new frame beside the others).
    #[serde(default)]
    #[schema(required = false)]
    pub mode: Option<String>,
    /// With `mode: "edit"`: the node id of the frame to change (400 when the doc has no such frame).
    #[serde(default)]
    #[schema(required = false)]
    pub frame: Option<String>,
    /// The brand kit: with `mode: "system"` the palette is built from it; for screens its colours lead.
    #[serde(default)]
    #[schema(required = false)]
    pub brand: Option<Brand>,
}

#[derive(Deserialize, ToSchema)]
pub struct ComposeSize {
    pub w: f64,
    pub h: f64,
}

fn size_of(s: Option<&ComposeSize>) -> Result<Option<Dim>, ApiError> {
    let Some(s) = s else { return Ok(None) };
    let ok = |v: f64| (MIN_SIDE..=MAX_SIDE).contains(&v);
    if ok(s.w) && ok(s.h) {
        Ok(Some((s.w, s.h)))
    } else {
        Err(ApiError::bad_request("size is 200 to 4000 points"))
    }
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct Direction {
    pub name: String,
    pub summary: String,
    /// The node id of the frame drawn for it (its first screen; set once `state` is `done`).
    #[schema(required = false)]
    pub frame: Option<String>,
    /// The node ids of every screen drawn for it, in order: one, or the screens of a flow (linked in order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub screens: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
pub struct ComposeView {
    pub id: String,
    pub doc: String,
    /// `drawing`, `applying`, `done` or `failed`.
    pub state: String,
    /// Why it failed, one sentence.
    pub reason: String,
    /// The AI session doing the work (cancel it through the agent-session routes).
    #[schema(required = false)]
    pub session: Option<String>,
    /// The directions, once `done` (up to the count asked for; fewer when the AI drew fewer).
    pub directions: Vec<Direction>,
    /// While working: `thinking` (nothing written yet), `drawing` (the AI is answering) or `placing` (the frames
    /// are being written).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub stage: Option<String>,
    /// `true` when the drawing is a flow: one direction whose `screens` are linked in order.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub flow: Option<bool>,
}

fn row_view(r: &sqlx::sqlite::SqliteRow) -> Result<ComposeView, sqlx::Error> {
    let dirs: String = r.try_get("directions")?;
    let directions: Vec<Direction> = serde_json::from_str(&dirs).unwrap_or_default();
    let state: String = r.try_get("state")?;
    let flow = directions
        .iter()
        .any(|d| d.screens.as_ref().is_some_and(|s| s.len() > 1))
        .then_some(true);
    Ok(ComposeView {
        id: r.try_get("id")?,
        doc: r.try_get("doc")?,
        stage: (state == "applying").then(|| "placing".to_owned()),
        state,
        reason: r.try_get("reason")?,
        session: r.try_get("session")?,
        directions,
        flow,
    })
}

/// What the AI's answer was: frames to draw, or a design system to write.
enum Parsed {
    Screens(Vec<answer::Dir>),
    System(compose_system::Made),
}

/// Writes a design system's `token` ops to the doc in one edit (one undo step; nothing partial).
async fn write_tokens(actor: &Actor, origin: &str, ops: &[Value]) -> Result<(), EditError> {
    let ops: Vec<design_doc::Op> = serde_json::from_value(Value::Array(ops.to_vec()))
        .map_err(|e| EditError::Refused(clip(&e.to_string(), 200)))?;
    actor
        .edit(origin, |live| {
            live.apply_ops(&ops).map_err(crate::apply::doc_err)
        })
        .await
        .map(drop)
}

/// Draws the directions on the doc's first page, to the right of what is there, and links a flow's screens in
/// order. The frame ids of each direction, in screen order.
async fn draw(
    actor: &Actor,
    origin: &str,
    dirs: &[answer::Dir],
    size: Dim,
) -> Result<Vec<Vec<String>>, EditError> {
    let (frames, _) = actor
        .edit(origin, |live| {
            let doc = live.read();
            let page = ask::first_page(&doc);
            let kids: Vec<&Node> = doc
                .nodes
                .values()
                .filter(|n| page.is_some() && n.parent == page)
                .collect();
            let last = kids.iter().map(|n| n.order.as_str()).max();
            let prop = |n: &Node, k: &str| n.props.get(k).and_then(Value::as_f64).unwrap_or(0.0);
            // ponytail: appended to the right of the rightmost top-level node; no free-space search.
            let x0 = kids
                .iter()
                .map(|n| prop(n, "x") + prop(n, "w"))
                .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))))
                .map_or(0.0, |v| v + GAP);
            let built = crate::compose_build::build_ops(dirs, page.as_deref(), last, x0, size);
            let (mut ops, ids) =
                resolve_temps(built.ops, &|id| doc.nodes.contains_key(id), &mut mint)
                    .map_err(EditError::Refused)?;
            for (from, to) in &built.links {
                if let (Some(f), Some(t)) = (ids.get(from), ids.get(to)) {
                    ops.push(serde_json::json!({"op": "set", "id": f, "key": "link", "value": {"to": t}}));
                }
            }
            let ops: Vec<design_doc::Op> = serde_json::from_value(Value::Array(ops))
                .map_err(|e| EditError::Refused(clip(&e.to_string(), 200)))?;
            live.apply_ops(&ops).map_err(crate::apply::doc_err)?;
            Ok(built
                .frames
                .iter()
                .map(|fs| fs.iter().filter_map(|t| ids.get(t).cloned()).collect())
                .collect::<Vec<Vec<String>>>())
        })
        .await?;
    Ok(frames)
}

// ---- routes ----------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Screens,
    System,
    Edit,
}

/// What the request draws; refused for an unknown mode, a system on a doc that is not a `system` doc, an edit with
/// no frame id, or a bad brand kit.
fn mode_of(req: &NewCompose, kind: Option<&str>) -> Result<Mode, ApiError> {
    let mode = match req.mode.as_deref() {
        None | Some("screens") => Mode::Screens,
        Some("system") => Mode::System,
        Some("edit") => Mode::Edit,
        Some(_) => {
            return Err(ApiError::bad_request("mode is screens, system or edit"));
        }
    };
    if mode == Mode::System && kind != Some("system") {
        return Err(ApiError::bad_request(
            "a design system is drawn on a system doc",
        ));
    }
    if mode == Mode::Edit && !req.frame.as_deref().is_some_and(ids::is_node_id) {
        return Err(ApiError::bad_request("an edit names the frame to change"));
    }
    if let Some(Err(why)) = req.brand.as_ref().map(compose_system::check_brand) {
        return Err(ApiError::bad_request(why));
    }
    Ok(mode)
}

#[utoipa::path(post, path = "/docs/{doc}/compose", operation_id = "designCompose", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = NewCompose,
    responses((status = 200, description = "An AI session is drawing (`drawing`); read it with `designGetCompose` until \
        `done` (the frames are then on the canvas) or `failed`. 409 when the design is archived or a person took over, \
        when no AI account is set up, or no runner is online; 400 for an empty or over-long prompt, a bad mode, size or \
        brand kit, or an edit of a frame the design does not have; 404 for no such design. Only `design` docs (and \
        `system` docs for `mode: \"system\"`)", body = ComposeView)))]
pub(crate) async fn start(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path(doc): Path<String>,
    In(req): In<NewCompose>,
) -> ApiResult<ComposeView> {
    let want = req.prompt.trim();
    if want.is_empty() || want.chars().count() > MAX_PROMPT {
        return Err(ApiError::bad_request("the prompt is 1 to 1000 characters"));
    }
    let none = || ApiError::not_found("no such design");
    if !doc_id_ok(&doc) {
        return Err(none());
    }
    let row: Option<(String, String, i64, Option<String>)> =
        sqlx::query_as("SELECT kind, state, ai_paused, system FROM design_docs WHERE id = ?")
            .bind(&doc)
            .fetch_optional(&app.pool)
            .await?;
    let (kind, system) = match row {
        Some((k, _, _, _)) if k == "mockup" => return Err(none()),
        None => return Err(none()),
        Some((_, s, _, _)) if s != "active" => {
            return Err(ApiError::conflict("the design is archived"));
        }
        Some((_, _, 1, _)) => {
            return Err(ApiError::conflict(
                "a person took over this design; resume it before the AI draws",
            ));
        }
        Some((k, _, _, s)) => (k, s),
    };
    let mode = mode_of(&req, Some(&kind))?;
    let count = match (req.count, &mode) {
        (_, Mode::Edit) | (Some(1), _) => 1,
        (None | Some(3), _) => 3,
        (Some(_), _) => return Err(ApiError::bad_request("count is 1 or 3")),
    };
    let asked = size_of(req.size.as_ref())?;
    let (ask_text, size, frame) = if mode == Mode::System {
        let size = asked.unwrap_or((FRAME_W, FRAME_H));
        (compose_system::prompt(want, req.brand.as_ref()), size, None)
    } else {
        let edit = (mode == Mode::Edit).then(|| req.frame.clone()).flatten();
        let (mut ctx, own) =
            context(&app, &reg, &me, &doc, system.as_deref(), edit.as_deref()).await?;
        ctx.brand = req.brand.as_ref().and_then(brand_line);
        let size = asked.or(own).unwrap_or((FRAME_W, FRAME_H));
        (ask::prompt(want, count, size, &ctx), size, edit)
    };
    let session = launch(&app, &me.device.id, &ask_text).await?;
    let id = format!("dc_{}", &mint()[2..]);
    sqlx::query(
        "INSERT INTO design_composes (id, doc, session, prompt, state, created_by, count, w, h, mode, frame) \
         VALUES (?, ?, ?, ?, 'drawing', ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&doc)
    .bind(&session)
    .bind(want)
    .bind(format!("person:{}", me.device.id))
    .bind(count as i64)
    .bind(size.0)
    .bind(size.1)
    .bind(if mode == Mode::System { "system" } else { "screens" })
    .bind(&frame)
    .execute(&app.pool)
    .await?;
    Ok(Json(ComposeView {
        id,
        doc,
        state: "drawing".into(),
        reason: String::new(),
        session: Some(session),
        directions: vec![],
        stage: Some("thinking".into()),
        flow: None,
    }))
}

async fn set(
    app: &App,
    id: &str,
    state: &str,
    reason: &str,
    dirs: &[Direction],
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE design_composes SET state = ?, reason = ?, directions = ? WHERE id = ?")
        .bind(state)
        .bind(reason)
        .bind(serde_json::to_string(dirs).unwrap_or_else(|_| "[]".into()))
        .bind(id)
        .execute(&app.pool)
        .await
        .map(drop)
}

fn person_took_over(e: EditError) -> String {
    match e {
        EditError::Paused => "a person took over this design".to_owned(),
        e => edit_err(e).message,
    }
}

#[utoipa::path(get, path = "/docs/{doc}/compose/{id}", operation_id = "designGetCompose", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("id" = String, Path, description = "The compose id")),
    responses((status = 200, description = "Where the drawing is. The first read that finds the AI session over \
        writes the frames (or fails with a reason in plain words: the AI account's quota, rate limit or sign-in, no \
        answer, a bad answer, or a person took over). A drawing still going after six minutes fails (`the AI stopped \
        answering`) and its session is stopped; 404 for no such compose", body = ComposeView)))]
pub(crate) async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path((doc, id)): Path<(String, String)>,
) -> ApiResult<ComposeView> {
    let none = || ApiError::not_found("no such drawing");
    let load = || async {
        sqlx::query("SELECT * FROM design_composes WHERE id = ? AND doc = ?")
            .bind(&id)
            .bind(&doc)
            .fetch_optional(&app.pool)
            .await
    };
    session::reap(&app).await?;
    let r = load().await?.ok_or_else(none)?;
    let mut v = row_view(&r)?;
    if v.state != "drawing" {
        return Ok(Json(v));
    }
    // a chain may have moved the run to a newer attempt (failover): that one is the answer
    let first = v.session.clone().unwrap_or_default();
    let sid = ainkrad_core_server::store::failover::newest(&app.pool, &first).await?;
    let s = agent_store::get(&app.pool, &sid).await?;
    if s.as_ref().is_some_and(|s| s.live()) {
        v.stage = Some(stage_of(&app, &sid).await?.to_owned());
        return Ok(Json(v));
    }
    // Over (or gone): exactly one reader finishes it.
    let won = sqlx::query(
        "UPDATE design_composes SET state = 'applying' WHERE id = ? AND state = 'drawing'",
    )
    .bind(&id)
    .execute(&app.pool)
    .await?
    .rows_affected();
    if won == 0 {
        return Ok(Json(row_view(&load().await?.ok_or_else(none)?)?));
    }
    let size = (r.try_get::<f64, _>("w")?, r.try_get::<f64, _>("h")?);
    let system = r.try_get::<String, _>("mode")? == "system";
    let count = r.try_get::<i64, _>("count")? as usize;
    // a single direction may be a flow; an edit is one screen
    let flow = count == 1 && r.try_get::<Option<String>, _>("frame")?.is_none();
    let outcome = match &s {
        None => Err("the AI session is gone".to_owned()),
        // a failed session's own reason (quota, sign-in...) beats "no answer" or "a bad answer"
        Some(s) => match session::answer_of(&app, &sid).await? {
            a if a.trim().is_empty() => Err("the AI gave no answer".to_owned()),
            a if system => compose_system::parse(&a).map(Parsed::System),
            a => answer::parse(&a, count, flow).map(Parsed::Screens),
        }
        .map_err(|why| failure_reason(s.outcome.as_ref(), s.gw_stop.as_deref()).unwrap_or(why)),
    };
    let origin = format!("session:{sid}");
    let finish = async {
        let dirs = match outcome? {
            Parsed::Screens(d) => d,
            Parsed::System(made) => {
                let lease = open_actor(&app, &reg, &me, &doc)
                    .await
                    .map_err(|e| e.message)?;
                write_tokens(&lease.actor, &origin, &made.ops)
                    .await
                    .map_err(person_took_over)?;
                return Ok(vec![Direction {
                    name: clip(&made.name, 40),
                    summary: clip(&made.summary, 120),
                    frame: None,
                    screens: None,
                }]);
            }
        };
        let lease = open_actor(&app, &reg, &me, &doc)
            .await
            .map_err(|e| e.message)?;
        let frames = draw(&lease.actor, &origin, &dirs, size)
            .await
            .map_err(person_took_over)?;
        Ok::<_, String>(
            dirs.iter()
                .zip(frames)
                .map(|(d, fs)| Direction {
                    name: clip(&d.name, 40),
                    summary: clip(&d.summary, 120),
                    frame: fs.first().cloned(),
                    screens: Some(fs),
                })
                .collect::<Vec<_>>(),
        )
    };
    match finish.await {
        Ok(dirs) => set(&app, &id, "done", "", &dirs).await?,
        Err(why) => set(&app, &id, "failed", &why, &[]).await?,
    }
    Ok(Json(row_view(&load().await?.ok_or_else(none)?)?))
}

#[cfg(test)]
#[path = "compose_tests.rs"]
mod tests;
