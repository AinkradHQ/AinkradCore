//! Validators: the trust boundary. Everything arriving from a client, an AI op or a stored document passes through
//! here before the resolver or the renderer sees it. Unknown props, unknown keys inside a prop, out-of-range
//! numbers, malformed colours/ids/hashes/paths are refused; nothing here panics on any input.

use serde_json::{Map, Value};

use crate::ids::{is_node_id, is_sha256, is_token_name, parse_component_ref};
use crate::limits::*;
use crate::schema::{NodeType, TokenKind};
use crate::svgpath;

type R = Result<(), String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub msg: String,
}

/// A token reference found while validating, with the kinds the position accepts (checked by lint / resolver).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenUse {
    pub name: String,
    pub kinds: &'static [TokenKind],
}

/// Validation context: whether `{"token": ...}` refs are allowed, and the refs seen.
#[derive(Debug, Default)]
pub struct Cx {
    pub allow_tokens: bool,
    pub uses: Vec<TokenUse>,
}

impl Cx {
    pub fn raw() -> Cx {
        Cx {
            allow_tokens: true,
            uses: vec![],
        }
    }
    pub fn resolved() -> Cx {
        Cx::default()
    }
    fn use_ref(&mut self, name: &str, kinds: &'static [TokenKind]) -> R {
        if !self.allow_tokens {
            return Err("a token reference is not allowed here".into());
        }
        if kinds.is_empty() {
            return Err("no token can be used here".into());
        }
        if !is_token_name(name) {
            return Err(format!("bad token name {:?}", clip(name)));
        }
        self.uses.push(TokenUse {
            name: name.to_string(),
            kinds,
        });
        Ok(())
    }
}

/// Untrusted text in a message or a path: at most 40 characters.
pub(crate) fn clip(s: &str) -> String {
    clip_n(s, 40)
}

pub(crate) fn clip_n(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `{"token": "<name>"}` and nothing else.
pub fn token_ref(v: &Value) -> Option<&str> {
    let m = v.as_object()?;
    if m.len() == 1 {
        m.get("token")?.as_str()
    } else {
        None
    }
}

use TokenKind as K;
const COLOR: &[K] = &[K::Color];
const LEN: &[K] = &[K::Space, K::Size];
const RADIUS: &[K] = &[K::Radius];
const SIZE: &[K] = &[K::Size];

fn num(v: &Value, cx: &mut Cx, kinds: &'static [K], min: f64, max: f64) -> R {
    if let Some(n) = token_ref(v) {
        return cx.use_ref(n, kinds);
    }
    match v.as_f64() {
        Some(f) if f.is_finite() && (min..=max).contains(&f) => Ok(()),
        _ => Err(format!("expected a number in {min}..={max}")),
    }
}

fn en(v: &Value, allowed: &[&str]) -> R {
    match v.as_str() {
        Some(s) if allowed.contains(&s) => Ok(()),
        _ => Err(format!("expected one of {allowed:?}")),
    }
}

fn boolean(v: &Value) -> R {
    if v.is_boolean() {
        Ok(())
    } else {
        Err("expected true or false".into())
    }
}

fn obj<'a>(v: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let m = v.as_object().ok_or("expected an object")?;
    match m.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("unknown key {:?}", clip(k))),
        None => Ok(m),
    }
}

fn arr(v: &Value, min: usize, max: usize) -> Result<&Vec<Value>, String> {
    match v.as_array() {
        Some(a) if (min..=max).contains(&a.len()) => Ok(a),
        _ => Err(format!("expected a list of {min}..={max} items")),
    }
}

fn is_hex_color(s: &str) -> bool {
    s.strip_prefix('#')
        .is_some_and(|h| matches!(h.len(), 6 | 8) && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn color(v: &Value, cx: &mut Cx) -> R {
    if let Some(n) = token_ref(v) {
        return cx.use_ref(n, COLOR);
    }
    match v.as_str() {
        Some(s) if is_hex_color(s) => Ok(()),
        _ => Err("expected a colour like #rrggbb or #rrggbbaa".into()),
    }
}

fn at<T>(key: &str, r: Result<T, String>) -> Result<T, String> {
    r.map_err(|e| format!("{key}: {e}"))
}

fn fill_item(v: &Value, cx: &mut Cx) -> R {
    let ty = v
        .get("type")
        .and_then(Value::as_str)
        .ok_or("missing fill type")?;
    match ty {
        "solid" => {
            let m = obj(v, &["type", "color"])?;
            at("color", color(m.get("color").ok_or("missing color")?, cx))
        }
        "linear" => {
            let m = obj(v, &["type", "angle", "stops"])?;
            if let Some(a) = m.get("angle") {
                at("angle", num(a, cx, &[], -360.0, 360.0))?;
            }
            for s in at("stops", arr(m.get("stops").ok_or("missing stops")?, 2, 16))? {
                let sm = obj(s, &["at", "color"])?;
                at(
                    "at",
                    num(sm.get("at").ok_or("missing at")?, cx, &[], 0.0, 1.0),
                )?;
                at("color", color(sm.get("color").ok_or("missing color")?, cx))?;
            }
            Ok(())
        }
        "image" => {
            let m = obj(v, &["type", "asset", "mode"])?;
            asset_ref(m.get("asset").ok_or("missing asset")?)?;
            m.get("mode")
                .map_or(Ok(()), |x| en(x, &["fill", "fit", "tile"]))
        }
        _ => Err("fill type must be solid, linear or image".into()),
    }
}

pub fn asset_ref(v: &Value) -> R {
    match v.as_str() {
        Some(s) if is_sha256(s) => Ok(()),
        _ => Err("expected a sha256 asset hash (64 lowercase hex)".into()),
    }
}

fn font_ref(v: &Value) -> R {
    if v.as_str() == Some("system") {
        return Ok(());
    }
    let m = obj(v, &["asset", "family", "weight"])?;
    asset_ref(
        m.get("asset")
            .ok_or("font needs an asset hash, or \"system\"")?,
    )?;
    if let Some(f) = m.get("family")
        && !f.as_str().is_some_and(|s| {
            (1..=MAX_NAME_CHARS).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'_' | b'-'))
        })
    {
        return Err("family: expected 1..=100 characters from A-Z a-z 0-9 space _ -".into());
    }
    m.get("weight")
        .map_or(Ok(()), |w| at("weight", int_range(w, 1, 1000)))
}

fn int_range(v: &Value, min: i64, max: i64) -> R {
    match v.as_i64() {
        Some(i) if (min..=max).contains(&i) => Ok(()),
        _ => Err(format!("expected an integer in {min}..={max}")),
    }
}

fn type_value(v: &Value, cx: &mut Cx) -> R {
    if let Some(n) = token_ref(v) {
        return cx.use_ref(n, &[K::Type]);
    }
    let m = obj(
        v,
        &[
            "font",
            "size",
            "weight",
            "line",
            "tracking",
            "transform",
            "align",
        ],
    )?;
    for (k, x) in m {
        at(
            k,
            match k.as_str() {
                "font" => font_ref(x),
                "size" => num(x, cx, SIZE, 1.0, 1000.0),
                "weight" => int_range(x, 1, 1000),
                "line" => num(x, cx, SIZE, 0.0, 1000.0),
                "tracking" => num(x, cx, &[], -1.0, 1.0),
                "transform" => en(x, &["none", "uppercase", "lowercase", "capitalize"]),
                _ => en(x, &["left", "center", "right", "justify"]),
            },
        )?;
    }
    Ok(())
}

fn shadow_value(v: &Value, cx: &mut Cx) -> R {
    if let Some(n) = token_ref(v) {
        return cx.use_ref(n, &[K::Shadow]);
    }
    for s in arr(v, 0, 8)? {
        let m = obj(s, &["x", "y", "blur", "spread", "color", "inset"])?;
        for (k, x) in m {
            at(
                k,
                match k.as_str() {
                    "x" | "y" | "spread" => num(x, cx, SIZE, -MAX_COORD, MAX_COORD),
                    "blur" => num(x, cx, SIZE, 0.0, MAX_COORD),
                    "inset" => boolean(x),
                    _ => color(x, cx),
                },
            )?;
        }
        at(
            "color",
            m.get("color")
                .map(|_| ())
                .ok_or_else(|| "missing".to_string()),
        )?;
    }
    Ok(())
}

fn material_value(v: &Value, cx: &mut Cx) -> R {
    if let Some(n) = token_ref(v) {
        return cx.use_ref(n, &[K::Material]);
    }
    en(v, &["glass", "well", "clear"])
}

/// Which node types a prop key applies to. `None` = not a prop of this schema.
pub fn applies(key: &str, ty: NodeType) -> Option<bool> {
    use NodeType as T;
    Some(match key {
        "fill" => true,
        "x" | "y" | "w" | "h" | "sizing" | "opacity" | "blend" | "visible" | "link" | "role"
        | "stroke" | "shadow" | "rotation" | "locked" | "blur" | "backdrop_blur" => ty != T::Page,
        "layout" | "clip" => matches!(ty, T::Frame | T::Component | T::Instance),
        "radius" => matches!(
            ty,
            T::Frame | T::Rect | T::Image | T::Component | T::Instance
        ),
        "material" => matches!(ty, T::Frame | T::Rect | T::Component | T::Instance),
        "type" => ty == T::Text,
        "path" => ty == T::Vector,
        "asset" | "fit" => ty == T::Image,
        "component" | "overrides" => ty == T::Instance,
        _ => return None,
    })
}

/// The value shape of one prop key, independent of the node type. Unknown key = error.
pub fn prop_value(key: &str, v: &Value, cx: &mut Cx) -> R {
    let r = match key {
        "x" | "y" => num(v, cx, LEN, -MAX_COORD, MAX_COORD),
        "w" | "h" => num(v, cx, LEN, 0.0, MAX_COORD),
        "sizing" => obj(v, &["w", "h"]).and_then(|m| {
            m.values()
                .try_for_each(|x| en(x, &["fixed", "hug", "fill"]))
        }),
        "layout" => layout(v, cx),
        "clip" | "visible" => boolean(v),
        "fill" => arr(v, 0, 16).and_then(|a| a.iter().try_for_each(|f| fill_item(f, cx))),
        "stroke" => match v.as_array() {
            Some(_) => arr(v, 0, 8).and_then(|a| a.iter().try_for_each(|x| stroke_item(x, cx))),
            None => stroke_item(v, cx),
        },
        "rotation" => num(v, cx, &[], -360.0, 360.0),
        "locked" => boolean(v),
        "blur" | "backdrop_blur" => num(v, cx, &[], 0.0, 1000.0),
        "radius" => match v.as_array() {
            Some(a) if a.len() == 4 => a
                .iter()
                .try_for_each(|x| num(x, cx, RADIUS, 0.0, MAX_COORD)),
            Some(_) => Err("expected 4 radii".into()),
            None => num(v, cx, RADIUS, 0.0, MAX_COORD),
        },
        "shadow" => shadow_value(v, cx),
        "material" => material_value(v, cx),
        "opacity" => num(v, cx, &[], 0.0, 1.0),
        "blend" => en(
            v,
            &[
                "normal", "multiply", "screen", "overlay", "darken", "lighten",
            ],
        ),
        "type" => type_value(v, cx),
        "link" => obj(v, &["to", "transition"]).and_then(|m| {
            match m.get("to").and_then(Value::as_str) {
                Some(s) if is_node_id(s) => {}
                _ => return Err("to: expected a node id".into()),
            }
            m.get("transition")
                .map_or(Ok(()), |t| en(t, &["none", "fade"]))
        }),
        "role" => en(
            v,
            &[
                "pane", "dialog", "popover", "menu", "card", "row", "control", "label",
            ],
        ),
        "path" => match v.as_str() {
            Some(s) => svgpath::validate(s)
                .map(|_| ())
                .map_err(|e| format!("byte {}: {}", e.at, e.msg)),
            None => Err("expected path data".into()),
        },
        "asset" => asset_ref(v),
        "fit" => en(v, &["fill", "fit", "crop", "tile"]),
        "component" => match v.as_str() {
            Some(s) if parse_component_ref(s).is_some() => Ok(()),
            _ => Err("expected \"<doc>/<node>\"".into()),
        },
        "overrides" => overrides(v, cx),
        _ => Err("unknown prop".into()),
    };
    at(key, r)
}

/// One stroke: `{color, width?, role?, align?, dash?}`. `stroke` is one of these or a list of up to 8 (drawn in order).
fn stroke_item(v: &Value, cx: &mut Cx) -> R {
    for (k, x) in obj(v, &["color", "width", "role", "align", "dash"])? {
        at(
            k,
            match k.as_str() {
                "color" => color(x, cx),
                "width" => num(x, cx, SIZE, 0.0, 1000.0),
                "align" => en(x, &["inside", "center", "outside"]),
                "dash" => arr(x, 0, 16)
                    .and_then(|a| a.iter().try_for_each(|d| num(d, cx, &[], 0.0, 1000.0))),
                _ => en(x, &["error", "focus", "drop", "checkbox", "chart", "other"]),
            },
        )?;
    }
    Ok(())
}

fn layout(v: &Value, cx: &mut Cx) -> R {
    let m = obj(v, &["dir", "gap", "pad", "align", "justify", "wrap"])?;
    for (k, x) in m {
        at(
            k,
            match k.as_str() {
                "dir" => en(x, &["row", "column"]),
                "gap" => num(x, cx, LEN, 0.0, MAX_COORD),
                "pad" => arr(x, 4, 4)
                    .and_then(|a| a.iter().try_for_each(|p| num(p, cx, LEN, 0.0, MAX_COORD))),
                "align" => en(x, &["start", "center", "end", "stretch"]),
                "justify" => en(x, &["start", "center", "end", "between"]),
                _ => boolean(x),
            },
        )?;
    }
    Ok(())
}

/// `"."` (the instance root) or `/`-joined node ids of the component's subtree, at most 16 deep.
pub fn is_override_path(s: &str) -> bool {
    s == "."
        || ((1..=MAX_INSTANCE_DEPTH).contains(&(s.split('/').count()))
            && s.split('/').all(is_node_id))
}

/// Override props: any known prop (applicability is checked against the target at resolve time), `null` removes the
/// component's value, `text` replaces a text node's content. Never `component`/`overrides` (no re-pointing).
pub fn override_props(v: &Value, cx: &mut Cx) -> R {
    let m = v.as_object().ok_or("expected an object")?;
    for (k, x) in m {
        if x.is_null() {
            applies(k, NodeType::Frame).ok_or_else(|| format!("{}: unknown prop", clip(k)))?;
            continue;
        }
        match k.as_str() {
            "text" => text(x).map_err(|e| format!("text: {e}"))?,
            "component" | "overrides" => return Err(format!("{k}: cannot be overridden")),
            _ => prop_value(k, x, cx)?,
        }
    }
    Ok(())
}

fn overrides(v: &Value, cx: &mut Cx) -> R {
    let m = v.as_object().ok_or("expected an object")?;
    if m.len() > MAX_OVERRIDES {
        return Err(format!("more than {MAX_OVERRIDES} overrides"));
    }
    for (p, props) in m {
        if !is_override_path(p) {
            return Err(format!("bad override path {:?}", clip(p)));
        }
        at(&clip(p), override_props(props, cx))?;
    }
    Ok(())
}

fn text(v: &Value) -> R {
    match v.as_str() {
        Some(s) => text_str(s),
        None => Err("expected a string".into()),
    }
}

/// One prop of a node of type `ty`: known key, applies to the type, value in schema.
pub fn prop(ty: NodeType, key: &str, v: &Value, cx: &mut Cx) -> R {
    match applies(key, ty) {
        None => Err(format!("{}: unknown prop", clip(key))),
        Some(false) => Err(format!("{key}: not a prop of a {ty:?} node")),
        Some(true) => prop_value(key, v, cx),
    }
}

pub fn props(ty: NodeType, m: &Map<String, Value>, cx: &mut Cx) -> Vec<Violation> {
    let mut out = vec![];
    for (k, v) in m {
        if out.len() >= MAX_REPORTED {
            break;
        }
        if let Err(msg) = prop(ty, k, v, cx) {
            out.push(Violation {
                path: format!("props.{}", clip(k)),
                msg,
            });
        }
    }
    out
}

mod document;
mod strings;
pub use document::{doc, node, token};
pub use strings::{is_format_char, name_str, text_str};
