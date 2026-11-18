//! The CSS of one resolved node (V6-03). Each function mirrors a rule of the renderer (`render/src/layout.rs`,
//! `look.rs`, `draw.rs`) so that a screen exported here and drawn there agree; where CSS cannot say it the same way,
//! the function says so. Every value that reaches a declaration is rebuilt from a number, a validated colour or a
//! validated hash, never copied from the document as text.

use serde_json::{Map, Value};

use super::text::text;
use super::vector::{vector_box, vector_parts};
use crate::ids::is_sha256;
use crate::resolve::{ResolvedNode, Theme};
use crate::schema::NodeType;

/// `(selector, property, value)`.
pub(super) type Decl = (String, String, String);

/// How the parent places this node (the renderer's `Flow`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Flow {
    Root,
    Free,
    Row,
    Column,
}

pub(super) type Bounds<'a> = Option<&'a dyn Fn(&str) -> Option<(f32, f32)>>;

pub(super) struct Cx<'a> {
    pub theme: Theme,
    pub fallback: Option<&'a str>,
    /// Right and bottom of a path's tight bounds: the size a hugging vector has.
    pub bounds: Bounds<'a>,
}

/// A CSS number: finite, at most four decimals, no trailing zeros.
pub(super) fn num(v: f64) -> String {
    if !v.is_finite() {
        return "0".into();
    }
    let s = format!("{v:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-0" {
        "0".into()
    } else {
        s.to_owned()
    }
}

pub(super) fn px(v: f64) -> String {
    format!("{}px", num(v))
}

pub(super) fn fv(m: &Map<String, Value>, k: &str) -> Option<f64> {
    m.get(k)?.as_f64()
}

/// `#rrggbb` or `#rrggbbaa` (CSS reads both the way the schema does), lowercased.
pub(super) fn color(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    let h = s.strip_prefix('#')?;
    (matches!(h.len(), 6 | 8) && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| s.to_ascii_lowercase())
}

pub(super) struct Out {
    pub sel: String,
    pub v: Vec<Decl>,
}

impl Out {
    pub fn put(&mut self, k: &str, val: impl Into<String>) {
        self.v.push((self.sel.clone(), k.into(), val.into()));
    }
    pub fn at(&mut self, sel: &str, k: &str, val: impl Into<String>) {
        self.v.push((sel.into(), k.into(), val.into()));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Fixed,
    Hug,
    Fill,
}

pub(super) fn mode(p: &Map<String, Value>, axis: &str, has: bool) -> Mode {
    match p
        .get("sizing")
        .and_then(|s| s.get(axis))
        .and_then(Value::as_str)
    {
        Some("fill") => Mode::Fill,
        Some("hug") => Mode::Hug,
        Some("fixed") if has => Mode::Fixed,
        Some(_) => Mode::Hug,
        None if has => Mode::Fixed,
        None => Mode::Hug,
    }
}

fn sizing(o: &mut Out, n: &ResolvedNode, flow: Flow, cx: &Cx) {
    let p = &n.props;
    let vec = (n.ty == NodeType::Vector).then(|| vector_box(n, cx));
    for (is_w, key, prop) in [(true, "w", "width"), (false, "h", "height")] {
        let val = fv(p, key);
        let m = mode(p, key, val.is_some());
        match (m, val) {
            (Mode::Fixed, Some(v)) => o.put(prop, px(v)),
            (Mode::Fill, _) => match flow {
                Flow::Free => o.put(prop, "100%"),
                Flow::Row | Flow::Column => {
                    if (flow == Flow::Row) == is_w {
                        o.put("flex", "1 1 0px");
                    } else {
                        o.put("align-self", "stretch");
                    }
                }
                Flow::Root => {}
            },
            _ => {
                if let Some(b) = vec {
                    // an `<svg>` with no size is 300 x 150, not 0 x 0
                    let side = if is_w { b.0 } else { b.1 };
                    o.put(prop, px(side.unwrap_or(0.0)));
                }
            }
        }
    }
}

fn layout(o: &mut Out, l: &Map<String, Value>) {
    o.put("display", "flex");
    let col = l.get("dir").and_then(Value::as_str) == Some("column");
    o.put("flex-direction", if col { "column" } else { "row" });
    o.put("gap", px(fv(l, "gap").unwrap_or(0.0)));
    if let Some(a) = l
        .get("pad")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 4)
    {
        let v = |i: usize| px(a[i].as_f64().unwrap_or(0.0));
        o.put("padding", format!("{} {} {} {}", v(0), v(1), v(2), v(3)));
    }
    o.put(
        "align-items",
        match l.get("align").and_then(Value::as_str) {
            Some("center") => "center",
            Some("end") => "flex-end",
            Some("stretch") => "stretch",
            _ => "flex-start",
        },
    );
    o.put(
        "justify-content",
        match l.get("justify").and_then(Value::as_str) {
            Some("center") => "center",
            Some("end") => "flex-end",
            Some("between") => "space-between",
            _ => "flex-start",
        },
    );
    if l.get("wrap").and_then(Value::as_bool) == Some(true) {
        o.put("flex-wrap", "wrap");
    }
}

fn radius(o: &mut Out, n: &ResolvedNode) {
    if n.ty == NodeType::Ellipse {
        o.put("border-radius", "50%");
        return;
    }
    let r: [f64; 4] = match n.props.get("radius") {
        Some(Value::Array(a)) if a.len() == 4 => {
            std::array::from_fn(|i| a[i].as_f64().unwrap_or(0.0))
        }
        Some(x) => [x.as_f64().unwrap_or(0.0); 4],
        None => [0.0; 4],
    };
    if r.iter().any(|v| *v > 0.0) {
        o.put(
            "border-radius",
            format!("{} {} {} {}", px(r[0]), px(r[1]), px(r[2]), px(r[3])),
        );
    }
}

/// The renderer draws shadows in order, later ones on top; CSS lists the top one first.
fn shadows(p: &Map<String, Value>) -> Vec<String> {
    let mut v: Vec<String> = p
        .get("shadow")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| {
            let m = s.as_object()?;
            Some(format!(
                "{} {} {} {} {}",
                px(fv(m, "x").unwrap_or(0.0)),
                px(fv(m, "y").unwrap_or(0.0)),
                px(fv(m, "blur").unwrap_or(0.0)),
                px(fv(m, "spread").unwrap_or(0.0)),
                color(m.get("color")?)?
            ))
        })
        .collect();
    v.reverse();
    v
}

struct Layer {
    image: String,
    size: &'static str,
    repeat: &'static str,
    pos: &'static str,
}

fn image_layer(asset: &str, fit: &str) -> Option<Layer> {
    is_sha256(asset).then(|| Layer {
        image: format!("url(\"assets/{asset}\")"),
        size: match fit {
            "fit" => "contain",
            "tile" => "auto",
            _ => "cover",
        },
        repeat: if fit == "tile" { "repeat" } else { "no-repeat" },
        pos: if fit == "tile" { "0 0" } else { "center" },
    })
}

pub(super) fn stops(f: &Value) -> Vec<(f64, String)> {
    f.get("stops")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s.get("at")?.as_f64()?, color(s.get("color")?)?)))
        .collect()
}

/// Fills in draw order, then an image node's picture on top.
fn layers(n: &ResolvedNode) -> Vec<Layer> {
    let mut out = vec![];
    let flat = |c: String| Layer {
        image: format!("linear-gradient({c},{c})"),
        size: "auto",
        repeat: "no-repeat",
        pos: "0 0",
    };
    for f in n
        .props
        .get("fill")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match f.get("type").and_then(Value::as_str) {
            Some("solid") => out.extend(f.get("color").and_then(color).map(flat)),
            Some("linear") => {
                let s = stops(f);
                if s.len() >= 2 {
                    let angle = f.get("angle").and_then(Value::as_f64).unwrap_or(180.0);
                    let list: Vec<String> = s
                        .iter()
                        .map(|(a, c)| format!("{c} {}%", num(a * 100.0)))
                        .collect();
                    out.push(Layer {
                        image: format!("linear-gradient({}deg,{})", num(angle), list.join(",")),
                        size: "auto",
                        repeat: "no-repeat",
                        pos: "0 0",
                    });
                }
            }
            Some("image") => {
                let asset = f.get("asset").and_then(Value::as_str).unwrap_or("");
                let mode = f.get("mode").and_then(Value::as_str).unwrap_or("fill");
                out.extend(image_layer(asset, mode));
            }
            _ => {}
        }
    }
    if n.ty == NodeType::Image
        && let Some(a) = n.props.get("asset").and_then(Value::as_str)
    {
        let fit = n.props.get("fit").and_then(Value::as_str).unwrap_or("fill");
        out.extend(image_layer(a, fit));
    }
    out
}

fn paint_layers(o: &mut Out, sel: &str, n: &ResolvedNode) {
    let l = layers(n);
    if l.is_empty() {
        return;
    }
    // CSS paints the first background on top
    let join = |f: &dyn Fn(&Layer) -> &str| l.iter().rev().map(f).collect::<Vec<_>>().join(",");
    o.at(sel, "background-image", join(&|x| x.image.as_str()));
    o.at(sel, "background-size", join(&|x| x.size));
    o.at(sel, "background-repeat", join(&|x| x.repeat));
    o.at(sel, "background-position", join(&|x| x.pos));
}

/// The stroke is drawn inside the box (`draw.rs`): an inset spread.
fn stroke(n: &ResolvedNode) -> Option<String> {
    let s = n.props.get("stroke")?.as_object()?;
    let w = fv(s, "width").unwrap_or(1.0);
    (w > 0.0).then_some(())?;
    Some(format!("inset 0 0 0 {} {}", px(w), color(s.get("color")?)?))
}

/// `(tint, rim)` of a material, as `draw.rs::material` picks them.
fn material_look(kind: &str, day: bool) -> Option<(Option<&'static str>, Option<&'static str>)> {
    Some(match (kind, day) {
        ("glass", true) => (Some("#ffffff4c"), Some("#ffffff6e")),
        ("glass", false) => (Some("#ffffff1a"), Some("#ffffff32")),
        ("well", true) => (Some("#0000000e"), None),
        ("well", false) => (Some("#00000046"), None),
        ("clear", true) => (None, Some("#ffffff50")),
        ("clear", false) => (None, Some("#ffffff24")),
        _ => return None,
    })
}

/// All declarations of one node. `i` is its class number; `flow` how its parent places it.
pub(super) fn node_decls(n: &ResolvedNode, i: usize, flow: Flow, cx: &Cx) -> Vec<Decl> {
    let sel = format!(".n{i}");
    let mut o = Out {
        sel: sel.clone(),
        v: vec![],
    };
    let p = &n.props;
    match flow {
        Flow::Root => {
            o.put("position", "absolute");
            o.put("left", "0");
            o.put("top", "0");
        }
        Flow::Free => {
            o.put("position", "absolute");
            o.put("left", px(fv(p, "x").unwrap_or(0.0)));
            o.put("top", px(fv(p, "y").unwrap_or(0.0)));
        }
        Flow::Row | Flow::Column => {}
    }
    sizing(&mut o, n, flow, cx);
    if (n.ty.is_container() || n.ty == NodeType::Instance)
        && let Some(l) = p.get("layout").and_then(Value::as_object)
    {
        layout(&mut o, l);
    }
    // a hidden node still takes its room (the renderer lays it out and skips drawing it)
    if p.get("visible").and_then(Value::as_bool) == Some(false) {
        o.put("visibility", "hidden");
    }
    if let Some(a) = fv(p, "opacity")
        .map(|a| a.clamp(0.0, 1.0))
        .filter(|a| *a < 1.0)
    {
        o.put("opacity", num(a));
    }
    if let Some(b) = p
        .get("blend")
        .and_then(Value::as_str)
        .filter(|b| matches!(*b, "multiply" | "screen" | "overlay" | "darken" | "lighten"))
    {
        o.put("mix-blend-mode", b);
    }
    if p.get("clip").and_then(Value::as_bool) == Some(true) && !n.children.is_empty() {
        o.put("overflow", "hidden");
    }
    let mut outer = shadows(p);
    match n.ty {
        NodeType::Text => text(&mut o, n, cx),
        NodeType::Vector => {
            o.put("overflow", "visible");
            o.put("display", "block");
            let (_, parts) = vector_parts(n, i, cx);
            o.v.extend(parts);
        }
        _ => {
            radius(&mut o, n);
            let kind = p.get("material").and_then(Value::as_str);
            let day = cx.theme == Theme::Day;
            let mat = kind.and_then(|k| material_look(k, day));
            let ring = stroke(n);
            if let Some((tint, rim)) = mat {
                // material under fills under stroke: two layers behind the children
                o.put("isolation", "isolate");
                for (pseudo, z) in [("::before", "-2"), ("::after", "-1")] {
                    let s = format!("{sel}{pseudo}");
                    for (k, v) in [
                        ("content", "\"\""),
                        ("position", "absolute"),
                        ("inset", "0"),
                        ("border-radius", "inherit"),
                        ("pointer-events", "none"),
                        ("z-index", z),
                    ] {
                        o.at(&s, k, v);
                    }
                }
                let before = format!("{sel}::before");
                if let Some(t) = tint {
                    o.at(&before, "background-color", t);
                }
                if kind == Some("glass") {
                    o.at(&before, "backdrop-filter", "blur(16px)");
                }
                if let Some(r) = rim {
                    o.at(&before, "box-shadow", format!("inset 0 0 0 1px {r}"));
                }
                let after = format!("{sel}::after");
                paint_layers(&mut o, &after, n);
                if let Some(r) = ring {
                    o.at(&after, "box-shadow", r);
                }
            } else {
                paint_layers(&mut o, &sel, n);
                if let Some(r) = ring {
                    outer.insert(0, r);
                }
            }
        }
    }
    if !outer.is_empty() {
        o.put("box-shadow", outer.join(","));
    }
    o.v
}
