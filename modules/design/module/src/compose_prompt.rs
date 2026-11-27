//! What the composer tells the AI (audit 2026-11-26, "AI quality"): the request, the platform's conventions, the
//! linked design system's tokens and the brand kit, a compact look at up to two screens already in the doc (so new
//! ones match), and for an edit the frame itself in the answer's own shape (so the AI changes it, not redraws it from
//! scratch). Everything read from the doc is clipped and capped: a doc is as untrusted as the answer.

use design_model::{Doc, Node, NodeType, Token, TokenKind};
use serde_json::{Map, Value, json};

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, Caller};

use crate::apply::{edit_err, open_actor};
use crate::compose_answer::{Dim, ICONS, MAX_SCREENS, clip, max_elements};
use crate::compose_system::Brand;
use crate::sync::Registry;

/// Tokens named in the prompt, at most.
const MAX_TOKENS: usize = 60;
/// Elements of an edited frame sent back, at most (deeper or later ones are left out).
const MAX_EDIT_ELEMENTS: usize = 120;
const MAX_DEPTH: usize = 4;

/// What the prompt is built from besides the request.
#[derive(Default)]
pub(crate) struct Context {
    /// `name value` lines of the linked design system's day tokens.
    pub tokens: Vec<String>,
    /// The brand kit: its name and colours.
    pub brand: Option<String>,
    /// Compact summaries of up to two screens already on the canvas.
    pub frames: Vec<Value>,
    /// The frame an edit changes, in the answer's shape.
    pub edit: Option<Value>,
}

fn n(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|x| x.is_finite())
}

fn round(x: f64) -> Value {
    json!(x.round())
}

/// A token's day value in a few characters.
fn token_line(name: &str, t: &Token) -> Option<String> {
    let d = &t.day;
    let v = match t.kind {
        TokenKind::Color => d.as_str()?.to_owned(),
        TokenKind::Space | TokenKind::Radius | TokenKind::Size => format!("{}", n(Some(d))?),
        TokenKind::Type => format!(
            "size {} weight {} line {}",
            n(d.get("size")).unwrap_or(16.0),
            d.get("weight").and_then(Value::as_i64).unwrap_or(400),
            n(d.get("line")).map_or("auto".into(), |l| l.to_string())
        ),
        TokenKind::Shadow => {
            let s = d.get(0)?;
            format!(
                "x {} y {} blur {} {}",
                n(s.get("x")).unwrap_or(0.0),
                n(s.get("y")).unwrap_or(0.0),
                n(s.get("blur")).unwrap_or(0.0),
                s.get("color").and_then(Value::as_str).unwrap_or("")
            )
        }
        TokenKind::Material => return None,
    };
    Some(format!("{} {}", clip(name, 40), clip(&v, 60)))
}

/// The day tokens of a design system, colours first.
pub(crate) fn tokens_of(doc: &Doc) -> Vec<String> {
    let mut all: Vec<(&String, &Token)> = doc.tokens.iter().collect();
    all.sort_by_key(|(name, t)| (t.kind != TokenKind::Color, (*name).clone()));
    all.into_iter()
        .filter_map(|(name, t)| token_line(name, t))
        .take(MAX_TOKENS)
        .collect()
}

fn kids<'a>(doc: &'a Doc, id: &str) -> Vec<(&'a String, &'a Node)> {
    let mut k: Vec<_> = doc
        .nodes
        .iter()
        .filter(|(_, n)| n.parent.as_deref() == Some(id))
        .collect();
    k.sort_by(|a, b| a.1.order.cmp(&b.1.order).then(a.0.cmp(b.0)));
    k
}

/// The doc's first page.
pub(crate) fn first_page(doc: &Doc) -> Option<String> {
    doc.nodes
        .iter()
        .filter(|(_, n)| n.ty == NodeType::Page)
        .min_by(|a, b| a.1.order.cmp(&b.1.order).then(a.0.cmp(b.0)))
        .map(|(id, _)| id.clone())
}

/// The top-level frames of the first page, in order.
pub(crate) fn top_frames(doc: &Doc) -> Vec<String> {
    let Some(page) = first_page(doc) else {
        return vec![];
    };
    kids(doc, &page)
        .into_iter()
        .filter(|(_, n)| n.ty == NodeType::Frame)
        .map(|(id, _)| id.clone())
        .collect()
}

/// A fill list as the answer writes it: `#rrggbb` or `{from, to, angle}`.
fn paint_of(v: Option<&Value>) -> Option<Value> {
    let f = v?.as_array()?.first()?;
    match f.get("type")?.as_str()? {
        "solid" => Some(json!(f.get("color")?.as_str()?)),
        "linear" => {
            let s = f.get("stops")?.as_array()?;
            Some(
                json!({"from": s.first()?.get("color")?, "to": s.last()?.get("color")?,
                "angle": n(f.get("angle")).unwrap_or(90.0)}),
            )
        }
        _ => None,
    }
}

/// A short look at a screen: its size, background, main texts and colours.
pub(crate) fn summary(doc: &Doc, id: &str) -> Option<Value> {
    let f = doc.nodes.get(id)?;
    let (mut texts, mut colours, mut stack, mut seen) =
        (vec![], Vec::<String>::new(), vec![id.to_owned()], 0);
    while let Some(at) = stack.pop() {
        seen += 1;
        if seen > 400 {
            break;
        }
        for (kid, k) in kids(doc, &at) {
            if let Some(Value::String(c)) = paint_of(k.props.get("fill"))
                && colours.len() < 8
                && !colours.contains(&c)
            {
                colours.push(c);
            }
            if k.ty == NodeType::Text && texts.len() < 8 {
                texts.push(json!({"text": clip(k.text.as_deref().unwrap_or(""), 60),
                    "size": k.props.get("type").and_then(|t| n(t.get("size")))}));
            }
            stack.push(kid.clone());
        }
    }
    Some(
        json!({"name": clip(&f.name, 40), "w": n(f.props.get("w")), "h": n(f.props.get("h")),
        "background": paint_of(f.props.get("fill")), "texts": texts, "colours": colours}),
    )
}

fn element(doc: &Doc, id: &str, node: &Node, depth: usize, left: &mut usize) -> Option<Value> {
    if *left == 0 {
        return None;
    }
    let p = &node.props;
    let mut e = Map::new();
    for k in ["x", "y", "w", "h"] {
        if let Some(v) = n(p.get(k)) {
            e.insert(k.into(), round(v));
        }
    }
    let kind = match node.ty {
        NodeType::Text => {
            let t = p.get("type");
            e.insert(
                "text".into(),
                json!(clip(node.text.as_deref().unwrap_or(""), 400)),
            );
            for k in ["size", "weight", "line", "align"] {
                if let Some(v) = t.and_then(|t| t.get(k)).filter(|v| !v.is_object()) {
                    e.insert(k.into(), v.clone());
                }
            }
            "text"
        }
        NodeType::Rect => "rect",
        NodeType::Ellipse => "ellipse",
        NodeType::Vector => {
            let icon = node
                .name
                .strip_prefix("Icon ")
                .filter(|i| ICONS.iter().any(|(n, _)| n == i))?;
            e.insert("icon".into(), json!(icon));
            e.insert("size".into(), round(n(p.get("w")).unwrap_or(24.0)));
            if let Some(c) = p.get("stroke").and_then(|s| s.get("color")) {
                e.insert("fill".into(), c.clone());
            }
            "icon"
        }
        NodeType::Image => "image",
        NodeType::Frame | NodeType::Component | NodeType::Instance
            if node.name.starts_with("Image") =>
        {
            if let Some(l) = node.name.strip_prefix("Image: ") {
                e.insert("label".into(), json!(clip(l, 40)));
            }
            "image"
        }
        NodeType::Frame | NodeType::Component | NodeType::Instance => {
            e.insert("name".into(), json!(clip(&node.name, 40)));
            if let Some(l) = p.get("layout") {
                e.insert("layout".into(), l.clone());
            }
            "group"
        }
        NodeType::Page => return None,
    };
    *left -= 1;
    e.insert("kind".into(), json!(kind));
    if kind != "icon"
        && let Some(f) = paint_of(p.get("fill"))
    {
        e.insert("fill".into(), f);
    }
    if let Some(r) = n(p.get("radius")) {
        e.insert("radius".into(), round(r));
    }
    if kind != "icon"
        && let Some(s) = p.get("stroke")
    {
        e.insert(
            "stroke".into(),
            json!({"color": s.get("color"), "width": s.get("width")}),
        );
    }
    if let Some(s) = p.get("shadow").and_then(|s| s.get(0)) {
        e.insert("shadow".into(), s.clone());
    }
    if let Some(o) = n(p.get("opacity")) {
        e.insert("opacity".into(), json!(o));
    }
    if kind == "group" && depth < MAX_DEPTH {
        let children: Vec<Value> = kids(doc, id)
            .into_iter()
            .filter_map(|(kid, k)| element(doc, kid, k, depth + 1, left))
            .collect();
        e.insert("children".into(), json!(children));
    }
    Some(Value::Object(e))
}

/// A frame in the answer's shape (`name`, `background`, `elements`), for an edit; `None` when `id` is no frame.
pub(crate) fn frame_json(doc: &Doc, id: &str) -> Option<Value> {
    let f = doc.nodes.get(id).filter(|n| n.ty == NodeType::Frame)?;
    let mut left = MAX_EDIT_ELEMENTS;
    let elements: Vec<Value> = kids(doc, id)
        .into_iter()
        .filter_map(|(kid, k)| element(doc, kid, k, 1, &mut left))
        .collect();
    Some(
        json!({"name": clip(&f.name, 40), "background": paint_of(f.props.get("fill")), "elements": elements}),
    )
}

/// The frame's own size, when it has one in range.
pub(crate) fn frame_size(doc: &Doc, id: &str) -> Option<Dim> {
    let p = &doc.nodes.get(id)?.props;
    let ok = |v: f64| (200.0..=4000.0).contains(&v);
    match (n(p.get("w")), n(p.get("h"))) {
        (Some(w), Some(h)) if ok(w) && ok(h) => Some((w, h)),
        _ => None,
    }
}

fn platform(kind: &str, w: f64) -> String {
    match kind {
        "phone" => "Phone rules: keep the top 44 points free for the status bar; side margins 16 to 20; every tap \
            target at least 44 tall; the primary button within thumb reach near the bottom, or a bottom tab bar (4 \
            or 5 icons with labels) for an app's main screen; one clear title; stack content in one column."
            .to_owned(),
        "tablet" => "Tablet rules: margins 24 to 32; a sidebar or a two-column layout where it helps; tap targets \
            at least 44 tall; a top bar with the title and actions."
            .to_owned(),
        _ => format!(
            "Desktop / web rules: a header bar along the top with the logo or name, navigation links and one main \
             action; content centred in a column at most 1200 wide (so side margins of {} on this width) on a 12-column \
             grid with 24 gaps; a hero (big headline, one sentence, a button) then sections (features as 3 or 4 cards \
             in a row, a list or a table); a footer with small links at the bottom. Tap targets at least 32 tall.",
            ((w - 1200.0) / 2.0).max(32.0).round()
        ),
    }
}

/// The whole ask. `count` directions (1 or 3), at `(w, h)`; with `ctx.edit` one redrawn frame; a single-direction
/// ask that is not an edit may answer a flow of up to six screens.
pub(crate) fn prompt(user: &str, count: usize, (w, h): Dim, ctx: &Context) -> String {
    let kind = if w < 600.0 {
        "phone"
    } else if w < 1100.0 {
        "tablet"
    } else {
        "desktop"
    };
    let m = if kind == "phone" {
        20.0
    } else {
        (w * 0.05).round().max(24.0)
    };
    let cap = max_elements(w);
    let (draw, rule) = if ctx.edit.is_some() {
        (
            "ONE changed version of an existing screen",
            "exactly 1 direction",
        )
    } else if count == 1 {
        ("ONE design direction", "exactly 1 direction")
    } else {
        (
            "THREE different design directions",
            "exactly 3 directions that look clearly different (type, colour, layout)",
        )
    };
    let mut s = format!(
        "You are a senior product designer. Draw {draw} for this request:\n\n\"{user}\"\n\n\
         Each direction is one {kind} screen, {w} wide and {h} tall (points, origin top left). Lay it out for that size: \
         use the full width.\n{}\n",
        platform(kind, w)
    );
    if !ctx.tokens.is_empty() {
        s += &format!(
            "\nThe design uses this design system. Use ONLY its colours, type sizes, spacing and radii (write the values, \
             e.g. its color.primary hex):\n{}\n",
            ctx.tokens.join("\n")
        );
    }
    if let Some(b) = &ctx.brand {
        s += &format!(
            "\nThe brand kit: {b}. Use the brand's colours for the main actions and accents.\n"
        );
    }
    if !ctx.frames.is_empty() && ctx.edit.is_none() {
        s += &format!(
            "\nScreens already in this design (match their style, colours and type so the new screens belong with \
             them):\n{}\n",
            Value::Array(ctx.frames.clone())
        );
    }
    if let Some(e) = &ctx.edit {
        s += &format!(
            "\nThis is the screen to change, in the answer's own shape:\n{e}\nReturn the WHOLE screen redrawn with the \
             change made. Keep every element, text, colour and position the change does not touch exactly as it is.\n"
        );
    }
    let icons: Vec<&str> = ICONS.iter().map(|(n, _)| *n).collect();
    s += &format!(
        "\nReply with ONLY one JSON object, no prose and no code fence, in this shape:\n\
         {{\"directions\":[{{\"name\":\"Calm\",\"summary\":\"one short sentence\",\"background\":\"#F5F7FB\",\"elements\":[\
         {{\"kind\":\"text\",\"x\":{m},\"y\":64,\"w\":{tw},\"text\":\"Good morning, Sara\",\"size\":28,\"weight\":700,\"line\":34,\"fill\":\"#14213D\"}},\
         {{\"kind\":\"group\",\"name\":\"Card\",\"x\":{m},\"y\":120,\"w\":{tw},\"fill\":\"#FFFFFF\",\"radius\":12,\
         \"shadow\":{{\"x\":0,\"y\":4,\"blur\":16,\"color\":\"#1018281A\"}},\"layout\":{{\"dir\":\"column\",\"gap\":8,\"pad\":16}},\"children\":[\
         {{\"kind\":\"image\",\"label\":\"Harbour at sunset\",\"h\":140,\"radius\":8}},\
         {{\"kind\":\"text\",\"text\":\"Weekend in Lisbon\",\"size\":18,\"weight\":600}},\
         {{\"kind\":\"group\",\"layout\":{{\"dir\":\"row\",\"gap\":6,\"align\":\"center\"}},\"children\":[\
         {{\"kind\":\"icon\",\"icon\":\"star\",\"size\":16,\"fill\":\"#F79009\"}},{{\"kind\":\"text\",\"text\":\"4.8 · 120 reviews\",\"size\":14,\"fill\":\"#475467\"}}]}}]}},\
         {{\"kind\":\"rect\",\"x\":{m},\"y\":{by},\"w\":{tw},\"h\":52,\"radius\":12,\"fill\":{{\"from\":\"#2F7BEF\",\"to\":\"#5B9BFF\",\"angle\":90}},\"next\":true}},\
         {{\"kind\":\"text\",\"x\":{m},\"y\":{ty},\"w\":{tw},\"text\":\"Book this trip\",\"size\":17,\"weight\":600,\"align\":\"center\",\"fill\":\"#FFFFFF\"}}]}}]}}\n\
         Rules: {rule}. `kind` is text, rect, ellipse, image, icon or group. A group holds `children`; with a `layout` \
         ({{dir: row|column, gap, pad, align: start|center|end|stretch, justify: start|center|end|between}}) its children \
         flow and their x/y are ignored, which is best for lists, cards, nav bars and button rows; without one its children \
         sit at x/y inside it. `image` is a picture placeholder (give a `label` saying what it shows). `icon` is one of: \
         {icons}. Any element may have `fill` (#rrggbb, or {{from, to, angle}} for a gradient), `stroke` {{color, width}}, \
         `shadow` {{x, y, blur, color}}, `opacity` (0 to 1), `radius`. Text has `size`, `weight` (100 to 900), `line` \
         (line height), `align`, and a `w`: it wraps inside that width (the Core measures its height), so leave room \
         under long text. Colours are #rrggbb (or #rrggbbaa). Positions are inside the screen. At most {cap} elements a \
         screen. Put button labels as text above their rect. Use real, specific content a real product would show \
         (names, prices, dates, messages), never lorem ipsum or \"Title\". Write every visible text in the same language \
         as the request. Use plain words a normal person understands.",
        tw = (w - 2.0 * m).round(),
        by = (h - 96.0).round(),
        ty = (h - 96.0 + 15.0).round(),
        icons = icons.join(", "),
    );
    if count == 1 && ctx.edit.is_none() {
        s += &format!(
            "\nIf the request clearly asks for several screens (a flow such as sign-up, onboarding, checkout, or \"3 \
             screens\"), give the one direction `screens`: a list of up to {MAX_SCREENS} screens in order, each \
             {{\"name\",\"background\",\"elements\"}}, instead of `elements`; mark the element that goes to the next \
             screen with \"next\": true. Otherwise draw one screen."
        );
    }
    s
}

// ---- reading the doc for the prompt ------------------------------------------------------------

pub(crate) fn brand_line(b: &Brand) -> Option<String> {
    if b.colors.is_empty() && b.name.is_none() {
        return None;
    }
    let name = clip(b.name.as_deref().unwrap_or(""), 60).replace('\n', " ");
    Some(format!(
        "{}colours {}",
        if name.trim().is_empty() {
            String::new()
        } else {
            format!("\"{}\", ", name.trim())
        },
        if b.colors.is_empty() {
            "none given".to_owned()
        } else {
            b.colors.join(", ")
        }
    ))
}

/// What the prompt knows besides the request: the doc's screens (and, for an edit, the frame and its size) and the
/// linked system's tokens. An edit of a frame the doc lacks is refused.
pub(crate) async fn context(
    app: &App,
    reg: &Arc<Registry>,
    me: &Caller,
    doc: &str,
    system: Option<&str>,
    edit: Option<&str>,
) -> Result<(Context, Option<Dim>), ApiError> {
    let mut ctx = Context::default();
    let lease = open_actor(app, reg, me, doc).await?;
    let (d, _) = lease.actor.view().await.map_err(edit_err)?;
    drop(lease);
    let mut size = None;
    if let Some(f) = edit {
        ctx.edit = Some(
            frame_json(&d, f)
                .ok_or_else(|| ApiError::bad_request("the design has no such frame"))?,
        );
        size = frame_size(&d, f);
    }
    let tops: Vec<String> = top_frames(&d)
        .into_iter()
        .filter(|t| Some(t.as_str()) != edit)
        .collect();
    ctx.frames = tops
        .iter()
        .rev()
        .take(2)
        .rev()
        .filter_map(|t| summary(&d, t))
        .collect();
    // a system that cannot be read (archived, gone) only leaves its tokens out
    if let Some(s) = system
        && let Ok(lease) = open_actor(app, reg, me, s).await
        && let Ok((sd, _)) = lease.actor.view().await
    {
        ctx.tokens = tokens_of(&sd);
    }
    Ok((ctx, size))
}

#[cfg(test)]
#[path = "compose_prompt_tests.rs"]
mod tests;
