//! The Design composer (E11-4, D-29): "draw 3 directions". One call starts an AI session (a module
//! session like the Brain's distil, owned by no client) that answers with JSON: three directions, each
//! a name, a one-line summary, a background and a list of simple elements. The Core never trusts the
//! answer: it is parsed into a small fixed shape, every number is clamped and every colour checked,
//! and the result becomes three frames on the doc's first page through the same CRDT edit as
//! `designApply` (so the model's validators and the `paused` check still apply; origin `session:<id>`).
//!
//! The finish happens on read: the app polls `GET .../compose/{id}`, and the first poll that finds the
//! session over writes the frames (a compare-and-set on `state` makes that once). A Core restart in
//! between loses nothing: the row and the session are both stored.
//!
//! "Use this" is the app's: it deletes the other two frames with `designApply`. "Draw 3 more" and
//! "Refine" are new composes.

use std::collections::BTreeMap;
use std::sync::Arc;

use ainkrad_core_server::agents::{self, Refusal};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::agents::{self as agent_store, NewSession};
use ainkrad_core_server::store::alloc;
use ainkrad_core_server::store::chains::{self as ch, Request};
use axum::Json;
use axum::extract::{Extension, Path, State};
use design_model::ids;
use design_model::{Node, NodeType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use utoipa::ToSchema;

use crate::apply::{edit_err, mint, open_actor, resolve_temps};
use crate::docs::{In, doc_id_ok};
use crate::sync::{Actor, EditError, Registry};

/// The chain the session draws its account from, by agent name (like the Brain's `brain-distil`).
const AGENT: &str = "design-compose";
const FRAME_W: f64 = 360.0;
const FRAME_H: f64 = 630.0;
const GAP: f64 = 60.0;
const MAX_ELEMENTS: usize = 24;
const MAX_PROMPT: usize = 1000;

#[derive(Deserialize, ToSchema)]
pub struct NewCompose {
    /// What to draw, 1 to 1000 characters. To refine a direction, say so here with the changes.
    pub prompt: String,
    /// How many directions to draw: 1 or 3 (default 3).
    #[serde(default)]
    #[schema(required = false)]
    pub count: Option<u8>,
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct Direction {
    pub name: String,
    pub summary: String,
    /// The node id of the frame drawn for it (set once `state` is `done`).
    #[schema(required = false)]
    pub frame: Option<String>,
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
    /// The three directions, once `done`.
    pub directions: Vec<Direction>,
}

fn row_view(r: &sqlx::sqlite::SqliteRow) -> Result<ComposeView, sqlx::Error> {
    let dirs: String = r.try_get("directions")?;
    Ok(ComposeView {
        id: r.try_get("id")?,
        doc: r.try_get("doc")?,
        state: r.try_get("state")?,
        reason: r.try_get("reason")?,
        session: r.try_get("session")?,
        directions: serde_json::from_str(&dirs).unwrap_or_default(),
    })
}

// ---- the answer -------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct Answer {
    #[serde(default)]
    directions: Vec<Dir>,
}

#[derive(Deserialize, Default)]
struct Dir {
    #[serde(default)]
    name: String,
    #[serde(default)]
    summary: String,
    background: Option<String>,
    #[serde(default)]
    elements: Vec<El>,
}

#[derive(Deserialize, Default)]
struct El {
    #[serde(default)]
    kind: String,
    x: Option<f64>,
    y: Option<f64>,
    w: Option<f64>,
    h: Option<f64>,
    fill: Option<String>,
    radius: Option<f64>,
    text: Option<String>,
    size: Option<f64>,
    weight: Option<i64>,
    align: Option<String>,
}

pub(crate) fn prompt(user: &str, count: usize) -> String {
    let (draw, rule) = if count == 1 {
        ("ONE design direction", "exactly 1 direction")
    } else {
        (
            "THREE different design directions",
            "exactly 3 directions that look clearly different (type, colour, layout)",
        )
    };
    format!(
        "You are a UI designer. Draw {draw} for this request:\n\n\
         \"{user}\"\n\n\
         Each direction is one phone screen, {FRAME_W} wide and {FRAME_H} tall. Reply with ONLY one JSON \
         object, no prose and no code fence, in this shape:\n\
         {{\"directions\":[{{\"name\":\"Calm\",\"summary\":\"one short sentence\",\"background\":\"#F5F7FB\",\
         \"elements\":[{{\"kind\":\"text\",\"x\":24,\"y\":80,\"w\":300,\"text\":\"Hello\",\"size\":34,\
         \"weight\":700,\"align\":\"left\",\"fill\":\"#14213D\"}},{{\"kind\":\"rect\",\"x\":24,\"y\":540,\
         \"w\":312,\"h\":52,\"radius\":14,\"fill\":\"#2F7BEF\"}}]}}]}}\n\
         Rules: {rule}. `kind` is text, rect \
         or ellipse. Colours are #rrggbb. Positions are inside the screen. At most {MAX_ELEMENTS} elements \
         each. Put button labels as separate text elements above their rect. Use plain words a normal \
         person understands."
    )
}

/// The first `{` to the last `}` of the answer (a model may still wrap it in a sentence or a fence).
fn parse(answer: &str, count: usize) -> Result<Vec<Dir>, String> {
    let (a, b) = (answer.find('{'), answer.rfind('}'));
    let (a, b) = match (a, b) {
        (Some(a), Some(b)) if a < b => (a, b),
        _ => return Err("the AI did not answer with a design".into()),
    };
    let parsed: Answer = serde_json::from_str(&answer[a..=b])
        .map_err(|_| "the AI's answer was not in the expected shape".to_owned())?;
    if parsed.directions.len() != count {
        return Err(format!(
            "the AI drew {} directions, not {count}",
            parsed.directions.len()
        ));
    }
    Ok(parsed.directions)
}

fn clip(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(n)
        .collect()
}

fn hex(c: Option<&str>, default: &str) -> String {
    match c {
        Some(s)
            if s.strip_prefix('#').is_some_and(|h| {
                matches!(h.len(), 6 | 8) && h.bytes().all(|b| b.is_ascii_hexdigit())
            }) =>
        {
            s.to_owned()
        }
        _ => default.to_owned(),
    }
}

fn num(v: Option<f64>, lo: f64, hi: f64, default: f64) -> f64 {
    v.filter(|x| x.is_finite())
        .map_or(default, |x| x.clamp(lo, hi))
        .round()
}

fn solid(c: &str) -> Value {
    json!([{"type": "solid", "color": c}])
}

/// The ops of the three frames. `page` is the real id of the first page, or `None` to add one;
/// `last_order` the last frame's order under it; `x0` where the first new frame goes. Temp ids
/// (`$1`...) are resolved by the caller.
fn build_ops(
    dirs: &[Dir],
    page: Option<&str>,
    last_order: Option<&str>,
    x0: f64,
) -> (Vec<Value>, Vec<String>) {
    let mut ops = Vec::new();
    let mut frames = Vec::new();
    let mut n = 0u32;
    let mut temp = || {
        n += 1;
        format!("${n}")
    };
    let page_ref = match page {
        Some(p) => p.to_owned(),
        None => {
            let t = temp();
            ops.push(json!({"op": "add", "id": t, "type": "page", "parent": null, "order": "a", "name": "Page 1"}));
            t
        }
    };
    let mut order = last_order.map(str::to_owned);
    for (i, d) in dirs.iter().enumerate() {
        let id = temp();
        frames.push(id.clone());
        let o = ids::between(order.as_deref(), None).unwrap_or_else(|| "z".into());
        order = Some(o.clone());
        let name = match clip(&d.name, 40).trim() {
            "" => format!("Direction {}", ["A", "B", "C"][i % 3]),
            s => s.to_owned(),
        };
        ops.push(
            json!({"op": "add", "id": id, "type": "frame", "parent": page_ref, "order": o,
            "name": name, "props": {
                "x": x0 + i as f64 * (FRAME_W + GAP), "y": 0, "w": FRAME_W, "h": FRAME_H,
                "radius": 24, "clip": true,
                "fill": solid(&hex(d.background.as_deref(), "#F5F7FB"))}}),
        );
        let els: Vec<&El> = d.elements.iter().take(MAX_ELEMENTS).collect();
        let orders = ids::rebalance(els.len().max(1)).unwrap_or_default();
        for (e, o) in els.iter().zip(orders) {
            let (x, y) = (num(e.x, 0.0, FRAME_W, 0.0), num(e.y, 0.0, FRAME_H, 0.0));
            let kind = e.kind.as_str();
            let mut props = json!({"x": x, "y": y});
            let (ty, text, name) = match kind {
                "text" => {
                    let size = num(e.size, 8.0, 96.0, 16.0);
                    props["w"] = json!(num(e.w, 8.0, FRAME_W - x, 200.0).max(8.0));
                    props["h"] = json!((size * 1.3).ceil());
                    props["type"] = json!({"size": size, "weight": e.weight.unwrap_or(400).clamp(100, 900),
                        "align": match e.align.as_deref() { Some(a @ ("center" | "right")) => a, _ => "left" }});
                    props["fill"] = solid(&hex(e.fill.as_deref(), "#14213D"));
                    (
                        NodeType::Text,
                        Some(clip(e.text.as_deref().unwrap_or(""), 200)),
                        "Text",
                    )
                }
                "ellipse" | "rect" => {
                    props["w"] = json!(num(e.w, 1.0, FRAME_W, 80.0));
                    props["h"] = json!(num(e.h, 1.0, FRAME_H, 40.0));
                    props["fill"] = solid(&hex(e.fill.as_deref(), "#D6E6FF"));
                    if kind == "rect" {
                        props["radius"] = json!(num(e.radius, 0.0, 200.0, 0.0));
                    }
                    if kind == "rect" {
                        (NodeType::Rect, None, "Shape")
                    } else {
                        (NodeType::Ellipse, None, "Circle")
                    }
                }
                _ => continue,
            };
            let mut op = json!({"op": "add", "id": temp(), "type": ty, "parent": id, "order": o,
                "name": name, "props": props});
            if let Some(t) = text {
                op["text"] = json!(t);
            }
            ops.push(op);
        }
    }
    (ops, frames)
}

/// Draws the three directions on the doc's first page, to the right of what is there. The ids of the
/// three frames, in order.
async fn draw(actor: &Actor, origin: &str, dirs: &[Dir]) -> Result<Vec<String>, EditError> {
    let (frames, _) = actor
        .edit(origin, |live| {
            let doc = live.read();
            let page = doc
                .nodes
                .iter()
                .filter(|(_, n)| n.ty == NodeType::Page)
                .min_by(|a, b| a.1.order.cmp(&b.1.order).then(a.0.cmp(b.0)))
                .map(|(id, _)| id.clone());
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
            let (ops, temps) = build_ops(dirs, page.as_deref(), last, x0);
            let (ops, ids) = resolve_temps(ops, &|id| doc.nodes.contains_key(id), &mut mint)
                .map_err(EditError::Refused)?;
            let ops: Vec<design_doc::Op> = serde_json::from_value(Value::Array(ops))
                .map_err(|e| EditError::Refused(clip(&e.to_string(), 200)))?;
            live.apply_ops(&ops).map_err(crate::apply::doc_err)?;
            Ok(temps
                .iter()
                .filter_map(|t| ids.get(t).cloned())
                .collect::<Vec<_>>())
        })
        .await?;
    Ok(frames)
}

// ---- the session -----------------------------------------------------------------------------

fn session_policy() -> Value {
    json!({"mode": "ask", "min_isolation": "process"})
}

/// The first online runner that offers agent sessions in a sandbox meeting the policy.
fn pick_runner(app: &App) -> Option<String> {
    let policy = session_policy();
    let mut all: Vec<_> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| {
            r.online
                && r.drivers
                    .iter()
                    .any(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER)
                && agents::tier_refusal(r, &policy).is_none()
        })
        .map(|(id, _)| id)
        .collect();
    all.sort();
    all.into_iter().next()
}

async fn launch(app: &App, by: &str, prompt: &str) -> Result<String, ApiError> {
    let user = ch::user_of(&app.pool, by).await?;
    let entries = {
        let mut conn = app.pool.acquire().await?;
        match ch::resolve_for(&mut conn, user, None, Some(AGENT)).await? {
            Some(id) => ch::load(&mut conn, id).await?,
            None => vec![],
        }
    };
    if entries.is_empty() {
        return Err(ApiError::conflict(
            "connect an AI account first: no account can draw yet",
        ));
    }
    let Some(runner) = pick_runner(app) else {
        return Err(ApiError::conflict("no runner is online to run the AI"));
    };
    let policy = session_policy();
    let new = NewSession {
        runner: &runner,
        harness: "",
        model: None,
        prompt: Some(prompt),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: by,
    };
    let req = Request {
        user_id: user,
        chain: None,
        agent: Some(AGENT),
    };
    let s = ch::create_session(&app.pool, &new, None, None, req, BY, &app.clock.now())
        .await
        .map_err(ApiError::from)?;
    agents::authorize_module_session(app, &s.id);
    if let Err(r) = agents::start(app, &s).await {
        alloc::end_unstarted_why(&app.pool, &s.id, &app.clock.now(), "it could not start").await?;
        return Err(ApiError::conflict(match r {
            Refusal::Runner(e) => e.message,
            Refusal::Secrets(e) => e.to_string(),
            Refusal::Db(e) => e.to_string(),
        }));
    }
    Ok(s.id.clone())
}

/// What the model said: every `assistant_text` block of the session, joined.
async fn answer_of(app: &App, session: &str) -> Result<String, sqlx::Error> {
    let (mut after, mut out) = (0i64, Vec::<String>::new());
    loop {
        let page = agent_store::transcript(&app.pool, session, after, 500).await?;
        let Some(end) = page.last() else { break };
        after = i64::try_from(end.seq).unwrap_or(i64::MAX);
        out.extend(
            page.iter()
                .filter(|e| e.body["type"] == "assistant_text")
                .filter_map(|e| e.body["text"].as_str().map(str::to_owned)),
        );
    }
    Ok(out.join("\n"))
}

// ---- routes ----------------------------------------------------------------------------------

#[utoipa::path(post, path = "/docs/{doc}/compose", operation_id = "designCompose", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = NewCompose,
    responses((status = 200, description = "An AI session is drawing three directions (`drawing`); read it \
        with `designGetCompose` until `done` (the three frames are then on the canvas) or `failed`. 409 when \
        the design is archived or a person took over, when no AI account is set up, or no runner is online; \
        400 for an empty or over-long prompt; 404 for no such design. Only `design` docs", body = ComposeView)))]
pub(crate) async fn start(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
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
    let row: Option<(String, String, i64)> =
        sqlx::query_as("SELECT kind, state, ai_paused FROM design_docs WHERE id = ?")
            .bind(&doc)
            .fetch_optional(&app.pool)
            .await?;
    match row {
        Some((k, _, _)) if k == "mockup" => return Err(none()),
        None => return Err(none()),
        Some((_, s, _)) if s != "active" => {
            return Err(ApiError::conflict("the design is archived"));
        }
        Some((_, _, 1)) => {
            return Err(ApiError::conflict(
                "a person took over this design; resume it before the AI draws",
            ));
        }
        Some(_) => {}
    }
    let count = match req.count {
        None | Some(3) => 3,
        Some(1) => 1,
        Some(_) => return Err(ApiError::bad_request("count is 1 or 3")),
    };
    let session = launch(&app, &me.device.id, &prompt(want, count)).await?;
    let id = format!("dc_{}", &mint()[2..]);
    sqlx::query(
        "INSERT INTO design_composes (id, doc, session, prompt, state, created_by, count) \
         VALUES (?, ?, ?, ?, 'drawing', ?, ?)",
    )
    .bind(&id)
    .bind(&doc)
    .bind(&session)
    .bind(want)
    .bind(format!("person:{}", me.device.id))
    .bind(count as i64)
    .execute(&app.pool)
    .await?;
    Ok(Json(ComposeView {
        id,
        doc,
        state: "drawing".into(),
        reason: String::new(),
        session: Some(session),
        directions: vec![],
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

#[utoipa::path(get, path = "/docs/{doc}/compose/{id}", operation_id = "designGetCompose", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("id" = String, Path, description = "The compose id")),
    responses((status = 200, description = "Where the drawing is. The first read that finds the AI session over \
        writes the three frames (or fails with a reason: no answer, a bad answer, or a person took over); \
        404 for no such compose", body = ComposeView)))]
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
    let r = load().await?.ok_or_else(none)?;
    let v = row_view(&r)?;
    if v.state != "drawing" {
        return Ok(Json(v));
    }
    let session = v.session.clone().unwrap_or_default();
    let s = agent_store::get(&app.pool, &session).await?;
    if s.as_ref().is_some_and(|s| s.live()) {
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
    let outcome = match s {
        None => Err("the AI session is gone".to_owned()),
        Some(_) => match answer_of(&app, &session).await? {
            a if a.trim().is_empty() => Err("the AI gave no answer".to_owned()),
            a => parse(&a, r.try_get::<i64, _>("count")? as usize),
        },
    };
    let finish = async {
        let dirs = outcome?;
        let lease = open_actor(&app, &reg, &me, &doc)
            .await
            .map_err(|e| e.message)?;
        let frames = draw(&lease.actor, &format!("session:{session}"), &dirs)
            .await
            .map_err(|e| match e {
                EditError::Paused => "a person took over this design".to_owned(),
                e => edit_err(e).message,
            })?;
        Ok::<_, String>(
            dirs.iter()
                .enumerate()
                .map(|(i, d)| Direction {
                    name: clip(&d.name, 40),
                    summary: clip(&d.summary, 120),
                    frame: frames.get(i).cloned(),
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
mod tests {
    use super::*;

    fn answer(n: usize) -> String {
        let d = r##"{"name":"Calm","summary":"Soft","background":"#F5F7FB","elements":[
            {"kind":"text","x":24,"y":80,"w":300,"text":"Hi","size":34,"weight":700,"fill":"#14213D"},
            {"kind":"rect","x":24,"y":540,"w":312,"h":52,"radius":14,"fill":"#2F7BEF"},
            {"kind":"star"}]}"##;
        format!(
            "Here you go:\n{{\"directions\":[{}]}}",
            vec![d; n].join(",")
        )
    }

    #[test]
    fn needs_exactly_the_asked_directions() {
        assert_eq!(parse(&answer(3), 3).unwrap().len(), 3);
        assert!(parse(&answer(2), 3).is_err());
        assert!(parse("no json", 3).is_err());
        assert_eq!(parse(&answer(1), 1).unwrap().len(), 1);
        assert!(parse(&answer(3), 1).is_err());
        assert!(prompt("x", 1).contains("exactly 1 direction"));
        assert!(prompt("x", 3).contains("exactly 3 directions"));
    }

    #[test]
    fn ops_are_valid_for_the_model() {
        let dirs = parse(&answer(3), 3).unwrap();
        let (ops, frames) = build_ops(&dirs, None, None, 0.0);
        assert_eq!(frames.len(), 3);
        // page + 3 frames + 3 x 2 known elements (the unknown kind is dropped)
        assert_eq!(ops.len(), 1 + 3 + 6);
        let (ops, ids) = resolve_temps(ops, &|_| false, &mut mint).unwrap();
        assert_eq!(ids.len(), 10);
        let parsed: Vec<design_doc::Op> = serde_json::from_value(Value::Array(ops)).unwrap();
        assert_eq!(parsed.len(), 10);
    }

    #[test]
    fn hostile_numbers_and_colours_are_clamped() {
        let d = Dir {
            background: Some("red; drop".into()),
            elements: vec![El {
                kind: "rect".into(),
                x: Some(1e12),
                w: Some(f64::NAN),
                fill: Some("javascript:".into()),
                ..El::default()
            }],
            ..Dir::default()
        };
        let (ops, _) = build_ops(&[d], Some("n_aaaaaaaaaaaa"), Some("a"), 400.0);
        assert_eq!(ops[0]["props"]["fill"][0]["color"], "#F5F7FB");
        assert_eq!(ops[0]["props"]["x"], 400.0);
        assert_eq!(ops[1]["props"]["x"], FRAME_W);
        assert_eq!(ops[1]["props"]["w"], 80.0);
        assert_eq!(ops[1]["props"]["fill"][0]["color"], "#D6E6FF");
    }
}
