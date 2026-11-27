//! The ops a parsed compose answer becomes (`compose_answer`): frames in a row, elements clamped into them, groups
//! with auto layout, texts measured by their wrapped lines (what sits under a text that grew is pushed down), and
//! the prototype links of a flow.

use design_model::{NodeType, ids};
use serde_json::{Map, Value, json};

use crate::compose_answer::{
    Dim, Dir, GAP, clip, decorate, f, hex, icon_path, max_elements, num, paint, solid, text_height,
    text_of,
};

const MAX_DEPTH: usize = 4;

/// What the ops of a compose are: the ops (temp ids `$1`...), the frame temps of each direction in screen order, and
/// the prototype links to add once the temps are real ids (from, to).
pub(crate) struct Built {
    pub ops: Vec<Value>,
    pub frames: Vec<Vec<String>>,
    pub links: Vec<(String, String)>,
}

struct B {
    ops: Vec<Value>,
    n: u32,
    /// elements this screen may still add
    left: usize,
    /// the element of this screen marked `next`
    next: Option<String>,
}

impl B {
    fn temp(&mut self) -> String {
        self.n += 1;
        format!("${}", self.n)
    }
}

/// One element built: its op index, where it sits and the height it was given vs the height it really has.
struct Placed {
    op: usize,
    x: f64,
    y: f64,
    w: f64,
    asked_h: f64,
    h: f64,
}

/// The layout of a group, read from `{dir, gap, pad, align, justify}`; `None` when it has none.
fn layout_of(v: Option<&Value>) -> Option<(Value, bool, [f64; 4], f64)> {
    let l = v?.as_object()?;
    let col = matches!(
        l.get("dir").and_then(Value::as_str),
        Some("column" | "vertical" | "col")
    );
    let gap = num(l.get("gap").and_then(Value::as_f64), 0.0, 200.0, 8.0);
    let pad = match l.get("pad") {
        Some(Value::Array(a)) if a.len() == 4 => {
            let p = |i: usize| num(a[i].as_f64(), 0.0, 200.0, 0.0);
            [p(0), p(1), p(2), p(3)]
        }
        Some(p) => [num(p.as_f64(), 0.0, 200.0, 0.0); 4],
        None => [0.0; 4],
    };
    let en = |k: &str, ok: &[&'static str]| {
        l.get(k)
            .and_then(Value::as_str)
            .and_then(|s| ok.iter().find(|o| **o == s).copied())
    };
    let mut out = json!({"dir": if col { "column" } else { "row" }, "gap": gap, "pad": pad});
    if let Some(a) = en("align", &["start", "center", "end", "stretch"]) {
        out["align"] = json!(a);
    }
    if let Some(j) = en("justify", &["start", "center", "end", "between"]) {
        out["justify"] = json!(j);
    }
    Some((out, col, pad, gap))
}

/// Adds the elements under `parent`, an area `aw` x `ah`. `flow`: `None` places them at their x/y (and pushes down
/// whatever sits under a text that wrapped taller than it was given), `Some(column)` lets the parent's layout place
/// them. The (w, h) each one takes, in order.
fn elements(
    b: &mut B,
    parent: &str,
    els: &[Value],
    (aw, ah): Dim,
    flow: Option<bool>,
    depth: usize,
) -> Vec<Placed> {
    let mut placed = vec![];
    let keep: Vec<&Value> = els.iter().filter(|e| e.is_object()).take(b.left).collect();
    let orders = ids::rebalance(keep.len().max(1)).unwrap_or_default();
    for (e, o) in keep.into_iter().zip(orders) {
        if b.left == 0 {
            break;
        }
        if let Some(p) = element(b, parent, e, &o, (aw, ah), flow, depth) {
            placed.push(p);
        }
    }
    if flow.is_none() {
        reflow(b, &mut placed);
    }
    placed
}

/// A text that wrapped taller than the AI gave it pushes down what sits below it and overlaps it across.
fn reflow(b: &mut B, placed: &mut [Placed]) {
    let mut by_y: Vec<usize> = (0..placed.len()).collect();
    by_y.sort_by(|&i, &j| placed[i].y.total_cmp(&placed[j].y));
    for (k, &i) in by_y.iter().enumerate() {
        let grow = placed[i].h - placed[i].asked_h;
        if grow < 1.0 {
            continue;
        }
        let (x, w, bottom) = (placed[i].x, placed[i].w, placed[i].y + placed[i].asked_h);
        for &j in &by_y[k + 1..] {
            let p = &mut placed[j];
            if p.y >= bottom - 0.5 && p.x < x + w && x < p.x + p.w {
                p.y += grow;
                b.ops[p.op]["props"]["y"] = json!(p.y);
            }
        }
    }
}

fn element(
    b: &mut B,
    parent: &str,
    e: &Value,
    order: &str,
    (aw, ah): Dim,
    flow: Option<bool>,
    depth: usize,
) -> Option<Placed> {
    let kind = e.get("kind").and_then(Value::as_str).unwrap_or("");
    let free = flow.is_none();
    let x = if free {
        num(f(e, "x"), 0.0, aw, 0.0)
    } else {
        0.0
    };
    let y = if free {
        num(f(e, "y"), 0.0, ah, 0.0)
    } else {
        0.0
    };
    // what is left of the area to the right of x: the default width
    let room = (aw - x).max(8.0);
    let mut props = Map::new();
    if free {
        props.insert("x".into(), json!(x));
        props.insert("y".into(), json!(y));
    }
    let named = text_of(e, "name", 40);
    let id = b.temp();
    let (ty, name, text, w, asked_h, h) = match kind {
        "text" => {
            let size = num(f(e, "size"), 8.0, 96.0, 16.0);
            let weight = e
                .get("weight")
                .and_then(Value::as_i64)
                .unwrap_or(400)
                .clamp(100, 900);
            let line = f(e, "line").map(|l| num(Some(l), size, size * 3.0, size));
            let body = clip(e.get("text").and_then(Value::as_str).unwrap_or(""), 400);
            let w = match f(e, "w") {
                Some(w) => num(Some(w), 8.0, room, room),
                // in a row the text takes what it needs, up to the room
                None if flow == Some(false) => (body.chars().count() as f64 * size * 0.6)
                    .ceil()
                    .clamp(8.0, room),
                None => room,
            };
            let lh = line.unwrap_or((size * 1.3).ceil());
            let h = text_height(&body, w, size, weight, lh);
            let mut ty = json!({"size": size, "weight": weight,
                "align": e.get("align").and_then(Value::as_str).filter(|a| matches!(*a, "center" | "right")).unwrap_or("left")});
            if let Some(l) = line {
                ty["line"] = json!(l);
            }
            props.insert("type".into(), ty);
            props.insert(
                "fill".into(),
                solid(&hex(e.get("fill")).unwrap_or_else(|| "#14213D".into())),
            );
            let asked = f(e, "h").map_or(lh, |v| v.max(lh));
            (NodeType::Text, "Text".to_owned(), Some(body), w, asked, h)
        }
        "rect" | "ellipse" => {
            let w = num(f(e, "w"), 1.0, aw, 80.0);
            let h = num(f(e, "h"), 1.0, ah.max(1.0), 40.0);
            props.insert(
                "fill".into(),
                paint(e.get("fill")).unwrap_or_else(|| solid("#D6E6FF")),
            );
            if kind == "rect" {
                props.insert("radius".into(), json!(num(f(e, "radius"), 0.0, 200.0, 0.0)));
                (NodeType::Rect, "Shape".to_owned(), None, w, h, h)
            } else {
                (NodeType::Ellipse, "Circle".to_owned(), None, w, h, h)
            }
        }
        "icon" => {
            let icon = e
                .get("icon")
                .or(e.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let size = num(f(e, "size").or(f(e, "w")), 12.0, 64.0, 24.0);
            let path = icon_path(icon, size)?;
            let color = hex(e.get("fill").or(e.get("color"))).unwrap_or_else(|| "#14213D".into());
            props.insert("path".into(), json!(path));
            props.insert("fill".into(), json!([]));
            props.insert(
                "stroke".into(),
                json!({"color": color, "width": (size / 12.0).clamp(1.0, 4.0)}),
            );
            props.insert("w".into(), json!(size));
            props.insert("h".into(), json!(size));
            (
                NodeType::Vector,
                format!("Icon {icon}"),
                None,
                size,
                size,
                size,
            )
        }
        "image" | "group" | "frame" | "card" | "row" | "stack" => {
            let image = kind == "image";
            let w = num(f(e, "w"), 8.0, aw, room);
            let lay = if image {
                None
            } else {
                layout_of(e.get("layout"))
            };
            let given_h = f(e, "h").map(|h| num(Some(h), 8.0, ah.max(8.0), 100.0));
            props.insert(
                "fill".into(),
                paint(e.get("fill")).unwrap_or_else(|| {
                    if image {
                        json!([{"type": "linear", "angle": 135, "stops": [{"at": 0, "color": "#E4EAF2"}, {"at": 1, "color": "#C9D3E0"}]}])
                    } else {
                        json!([])
                    }
                }),
            );
            if let Some(r) = f(e, "radius") {
                props.insert("radius".into(), json!(num(Some(r), 0.0, 200.0, 0.0)));
            }
            if image {
                props.insert("clip".into(), json!(true));
            }
            let mut name = if image {
                match text_of(e, "label", 40).trim() {
                    "" => "Image".to_owned(),
                    l => format!("Image: {l}"),
                }
            } else {
                "Group".to_owned()
            };
            if !named.trim().is_empty() && !image {
                name = named.trim().to_owned();
            }
            b.left -= 1;
            let at = b.ops.len();
            b.ops.push(json!({"op": "add", "id": id, "type": NodeType::Frame, "parent": parent, "order": order, "name": name}));
            let inner_h = given_h.unwrap_or(ah);
            let h = if image {
                let h = given_h.unwrap_or((w * 0.6).round().min(ah.max(8.0)));
                if b.left > 0 {
                    // a picture mark in the middle, so it reads as an image
                    let s = (w.min(h) / 3.0).clamp(16.0, 48.0).round();
                    let icon = json!({"kind": "icon", "icon": "image", "size": s, "fill": "#64748B",
                        "x": ((w - s) / 2.0).round(), "y": ((h - s) / 2.0).round()});
                    elements(b, &id, &[icon], (w, h), None, depth + 1);
                }
                h
            } else if depth >= MAX_DEPTH {
                given_h.unwrap_or(40.0)
            } else {
                let kids: Vec<Value> = e
                    .get("children")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                match &lay {
                    Some((l, col, pad, gap)) => {
                        props.insert("layout".into(), l.clone());
                        let inner = (
                            (w - pad[1] - pad[3]).max(8.0),
                            (inner_h - pad[0] - pad[2]).max(8.0),
                        );
                        let got = elements(b, &id, &kids, inner, Some(*col), depth + 1);
                        let n = got.len().saturating_sub(1) as f64;
                        let hug = if *col {
                            got.iter().map(|p| p.h).sum::<f64>() + gap * n
                        } else {
                            got.iter().map(|p| p.h).fold(0.0, f64::max)
                        } + pad[0]
                            + pad[2];
                        given_h.unwrap_or(hug.ceil())
                    }
                    None => {
                        let got = elements(b, &id, &kids, (w, inner_h), None, depth + 1);
                        let bottom = got.iter().map(|p| p.y + p.h).fold(0.0, f64::max);
                        given_h.unwrap_or(bottom.ceil().max(8.0))
                    }
                }
            };
            props.insert("w".into(), json!(w));
            props.insert("h".into(), json!(h));
            decorate(e, &mut props);
            if e.get("next").and_then(Value::as_bool) == Some(true) && b.next.is_none() {
                b.next = Some(id.clone());
            }
            b.ops[at]["props"] = Value::Object(props);
            return Some(Placed {
                op: at,
                x,
                y,
                w,
                asked_h: given_h.unwrap_or(h),
                h,
            });
        }
        _ => return None,
    };
    if ty != NodeType::Vector {
        props.insert("w".into(), json!(w));
        props.insert("h".into(), json!(h));
    }
    decorate(e, &mut props);
    if e.get("next").and_then(Value::as_bool) == Some(true) && b.next.is_none() {
        b.next = Some(id.clone());
    }
    let name = if named.trim().is_empty() {
        name
    } else {
        named.trim().to_owned()
    };
    let mut op = json!({"op": "add", "id": id, "type": ty, "parent": parent, "order": order, "name": name, "props": props});
    if let Some(t) = text {
        op["text"] = json!(t);
    }
    b.left -= 1;
    b.ops.push(op);
    Some(Placed {
        op: b.ops.len() - 1,
        x,
        y,
        w,
        asked_h,
        h,
    })
}

/// The ops of the directions' frames, every screen in a row. `page` is the real id of the first page, or `None` to
/// add one; `last_order` the last frame's order under it; `x0` where the first new frame goes. A direction with more
/// than one screen is a flow: each screen links to the next (from its `next` element, else from the frame).
pub(crate) fn build_ops(
    dirs: &[Dir],
    page: Option<&str>,
    last_order: Option<&str>,
    x0: f64,
    (fw, fh): Dim,
) -> Built {
    let mut b = B {
        ops: vec![],
        n: 0,
        left: 0,
        next: None,
    };
    let page_ref = match page {
        Some(p) => p.to_owned(),
        None => {
            let t = b.temp();
            b.ops.push(json!({"op": "add", "id": t, "type": "page", "parent": null, "order": "a", "name": "Page 1"}));
            t
        }
    };
    let (mut frames, mut links) = (vec![], vec![]);
    let mut order = last_order.map(str::to_owned);
    let mut x = x0;
    for d in dirs {
        let mut mine = vec![];
        let mut sources = vec![];
        for s in &d.screens {
            let id = b.temp();
            let o = ids::between(order.as_deref(), None).unwrap_or_else(|| "z".into());
            order = Some(o.clone());
            let fill = paint(s.background.as_ref()).unwrap_or_else(|| solid("#F5F7FB"));
            // a real screen: square corners (devices are drawn by Present), content clipped to it
            b.ops.push(json!({"op": "add", "id": id, "type": "frame", "parent": page_ref, "order": o,
                "name": clip(&s.name, 40), "props": {"x": x, "y": 0, "w": fw, "h": fh, "radius": 0, "clip": true, "fill": fill}}));
            x += fw + GAP;
            b.left = max_elements(fw);
            b.next = None;
            elements(&mut b, &id, &s.elements, (fw, fh), None, 1);
            sources.push(b.next.take().unwrap_or_else(|| id.clone()));
            mine.push(id);
        }
        for i in 1..mine.len() {
            links.push((sources[i - 1].clone(), mine[i].clone()));
        }
        frames.push(mine);
    }
    Built {
        ops: b.ops,
        frames,
        links,
    }
}
