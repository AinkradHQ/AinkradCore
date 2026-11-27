//! The composer's answer (E11-4, audit 2026-11-26): the shape the AI answers in and the ops it becomes. The Core
//! never trusts it: it is read leniently (a wrong type is a default, an unknown kind is dropped), every number is
//! clamped, every colour checked, every icon comes from a fixed set, and the result passes the doc model's own
//! validators when it is applied.
//!
//! An element is `text`, `rect`, `ellipse`, `image` (a placeholder: there is no image source to draw from), `icon`
//! (one of [`ICONS`], drawn as a stroked vector) or `group` (a frame holding `children`, with an optional auto
//! `layout`). Any element may carry `fill` (`#rrggbb` or `{from, to, angle}`), `stroke` `{color, width}`, `shadow`
//! `{x, y, blur, color}`, `opacity` and `next: true` (a tap on it goes to the next screen of a flow).

use serde_json::{Map, Value, json};

/// The screen size in points, (width, height).
pub(crate) type Dim = (f64, f64);
pub(crate) const GAP: f64 = 60.0;
/// The most screens one direction of a flow may have.
pub(crate) const MAX_SCREENS: usize = 6;

/// Elements one screen may hold, by its width: phone, tablet, desktop.
pub(crate) fn max_elements(w: f64) -> usize {
    if w < 600.0 {
        24
    } else if w < 1100.0 {
        40
    } else {
        60
    }
}

/// One screen of a direction.
pub(crate) struct Screen {
    pub name: String,
    pub background: Option<Value>,
    pub elements: Vec<Value>,
}

/// One direction: one screen, or the screens of a flow in order.
pub(crate) struct Dir {
    pub name: String,
    pub summary: String,
    pub screens: Vec<Screen>,
}

pub(crate) fn clip(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(n)
        .collect()
}

pub(crate) fn text_of(v: &Value, k: &str, n: usize) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .map(|s| clip(s, n))
        .unwrap_or_default()
}

fn screen_of(v: &Value, name: &str) -> Screen {
    Screen {
        name: match text_of(v, "name", 40).trim() {
            "" => name.to_owned(),
            s => s.to_owned(),
        },
        background: v.get("background").cloned(),
        elements: v
            .get("elements")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    }
}

/// The first `{` to the last `}` of the answer (a model may still wrap it in a sentence or a fence). Keeps the first
/// `count` directions and accepts fewer (at least one). With `flow`, a direction's `screens` (up to
/// [`MAX_SCREENS`]) are all kept; otherwise only its first screen.
pub(crate) fn parse(answer: &str, count: usize, flow: bool) -> Result<Vec<Dir>, String> {
    let (a, b) = (answer.find('{'), answer.rfind('}'));
    let (a, b) = match (a, b) {
        (Some(a), Some(b)) if a < b => (a, b),
        _ => return Err("the AI did not answer with a design".into()),
    };
    let v: Value = serde_json::from_str(&answer[a..=b])
        .map_err(|_| "the AI's answer was not in the expected shape".to_owned())?;
    // a model answering one bare direction (no `directions` list) is read as that one
    let list = match v.get("directions").and_then(Value::as_array) {
        Some(l) => l.clone(),
        None if v.get("elements").is_some() || v.get("screens").is_some() => vec![v],
        None => vec![],
    };
    let dirs: Vec<Dir> = list
        .iter()
        .filter(|d| d.is_object())
        .take(count)
        .enumerate()
        .map(|(i, d)| {
            let name = match text_of(d, "name", 40).trim() {
                "" => format!("Direction {}", ["A", "B", "C"][i % 3]),
                s => s.to_owned(),
            };
            let listed: Vec<&Value> = d
                .get("screens")
                .and_then(Value::as_array)
                .map(|s| s.iter().filter(|x| x.is_object()).collect())
                .unwrap_or_default();
            let screens = if listed.is_empty() || (!flow && d.get("elements").is_some()) {
                vec![screen_of(d, &name)]
            } else {
                let keep = if flow { MAX_SCREENS } else { 1 };
                listed
                    .iter()
                    .take(keep)
                    .map(|s| {
                        let mut sc = screen_of(s, &name);
                        if sc.background.is_none() {
                            sc.background = d.get("background").cloned();
                        }
                        sc
                    })
                    .collect()
            };
            Dir {
                summary: text_of(d, "summary", 120),
                name,
                screens,
            }
        })
        .collect();
    if dirs.is_empty() {
        return Err("the AI drew no design".into());
    }
    Ok(dirs)
}

// ---- values ----------------------------------------------------------------------------------

pub(crate) fn hex(c: Option<&Value>) -> Option<String> {
    let s = c?.as_str()?;
    s.strip_prefix('#')
        .is_some_and(|h| matches!(h.len(), 6 | 8) && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| s.to_owned())
}

pub(crate) fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64).filter(|x| x.is_finite())
}

pub(crate) fn num(v: Option<f64>, lo: f64, hi: f64, default: f64) -> f64 {
    v.map_or(default, |x| x.clamp(lo, hi.max(lo))).round()
}

/// `#rrggbb`, or `{from, to, angle}` (a two-stop linear gradient); `None` for anything else.
pub(crate) fn paint(v: Option<&Value>) -> Option<Value> {
    let v = v?;
    if let Some(c) = hex(Some(v)) {
        return Some(json!([{"type": "solid", "color": c}]));
    }
    let (from, to) = (hex(v.get("from"))?, hex(v.get("to"))?);
    let angle = num(f(v, "angle"), -360.0, 360.0, 90.0);
    Some(json!([{"type": "linear", "angle": angle,
        "stops": [{"at": 0, "color": from}, {"at": 1, "color": to}]}]))
}

pub(crate) fn solid(c: &str) -> Value {
    json!([{"type": "solid", "color": c}])
}

/// The props every element kind may carry: stroke, shadow, opacity.
pub(crate) fn decorate(e: &Value, props: &mut Map<String, Value>) {
    if let Some(s) = e.get("stroke")
        && let Some(c) = hex(s.get("color"))
    {
        props.insert(
            "stroke".into(),
            json!({"color": c, "width": num(f(s, "width"), 0.0, 20.0, 1.0).max(1.0)}),
        );
    }
    if let Some(s) = e.get("shadow").filter(|s| s.is_object()) {
        props.insert(
            "shadow".into(),
            json!([{"x": num(f(s, "x"), -100.0, 100.0, 0.0), "y": num(f(s, "y"), -100.0, 100.0, 4.0),
                "blur": num(f(s, "blur"), 0.0, 200.0, 12.0), "spread": 0,
                "color": hex(s.get("color")).unwrap_or_else(|| "#0000001F".into())}]),
        );
    }
    if let Some(o) = f(e, "opacity").filter(|o| *o < 1.0) {
        props.insert(
            "opacity".into(),
            json!((o.max(0.05) * 100.0).round() / 100.0),
        );
    }
}

/// How tall a text is once it wraps at `w`: a greedy word wrap at an estimated characters-per-line (an average glyph
/// is about half the size wide, a bold one a little more), times the line height.
pub(crate) fn text_height(text: &str, w: f64, size: f64, weight: i64, line: f64) -> f64 {
    let em = if weight >= 600 { 0.6 } else { 0.55 };
    let per = ((w / (size * em)).floor() as usize).max(1);
    let mut lines = 0usize;
    for para in text.split('\n') {
        let mut at = 0usize;
        lines += 1;
        for word in para.split_whitespace() {
            let n = word.chars().count();
            let need = if at == 0 { n } else { at + 1 + n };
            if need <= per {
                at = need;
            } else if n <= per {
                lines += 1;
                at = n;
            } else {
                // a word longer than the line breaks across lines
                if at > 0 {
                    lines += 1;
                }
                lines += (n - 1) / per;
                at = n % per;
            }
        }
    }
    (lines.max(1) as f64 * line).ceil()
}

// ---- icons -----------------------------------------------------------------------------------

/// A basic icon set, drawn on a 24-point grid with absolute M/L/C/Z commands only (so scaling is multiplying numbers).
pub(crate) const ICONS: &[(&str, &str)] = &[
    ("home", "M3 11 L12 3 L21 11 M5 10 L5 21 L19 21 L19 10"),
    (
        "search",
        "M10.5 4 C14.09 4 17 6.91 17 10.5 C17 14.09 14.09 17 10.5 17 C6.91 17 4 14.09 4 10.5 C4 6.91 6.91 4 10.5 4 Z M15.5 15.5 L20 20",
    ),
    (
        "user",
        "M12 4 C14.21 4 16 5.79 16 8 C16 10.21 14.21 12 12 12 C9.79 12 8 10.21 8 8 C8 5.79 9.79 4 12 4 Z M4 21 C4 16.58 7.58 14 12 14 C16.42 14 20 16.58 20 21",
    ),
    (
        "settings",
        "M4 6 L20 6 M4 12 L20 12 M4 18 L20 18 M9 4 L9 8 M15 10 L15 14 M7 16 L7 20",
    ),
    ("menu", "M4 6 L20 6 M4 12 L20 12 M4 18 L20 18"),
    ("close", "M6 6 L18 18 M18 6 L6 18"),
    ("plus", "M12 5 L12 19 M5 12 L19 12"),
    ("check", "M5 12 L10 17 L19 7"),
    ("chevron-right", "M9 5 L16 12 L9 19"),
    ("chevron-left", "M15 5 L8 12 L15 19"),
    ("chevron-down", "M5 9 L12 16 L19 9"),
    ("arrow-right", "M4 12 L20 12 M14 6 L20 12 L14 18"),
    (
        "bell",
        "M6 17 L6 11 C6 7.69 8.69 5 12 5 C15.31 5 18 7.69 18 11 L18 17 L20 19 L4 19 Z M10 21.5 L14 21.5",
    ),
    (
        "heart",
        "M12 20 C12 20 3 14.5 3 8.5 C3 5.5 5.5 3.5 8 3.5 C9.8 3.5 11.2 4.5 12 6 C12.8 4.5 14.2 3.5 16 3.5 C18.5 3.5 21 5.5 21 8.5 C21 14.5 12 20 12 20 Z",
    ),
    (
        "star",
        "M12 3 L14.6 9 L21 9.3 L16 13.4 L17.7 20 L12 16.3 L6.3 20 L8 13.4 L3 9.3 L9.4 9 Z",
    ),
    ("mail", "M3 6 L21 6 L21 18 L3 18 Z M3 6 L12 13 L21 6"),
    (
        "calendar",
        "M4 6 L20 6 L20 20 L4 20 Z M4 10 L20 10 M8 3 L8 7 M16 3 L16 7",
    ),
    (
        "bag",
        "M5 8 L19 8 L18 21 L6 21 Z M9 8 C9 5 10 3 12 3 C14 3 15 5 15 8",
    ),
    (
        "image",
        "M4 5 L20 5 L20 19 L4 19 Z M4 16 L9 11 L13 15 L16 12 L20 16",
    ),
    (
        "lock",
        "M6 11 L18 11 L18 21 L6 21 Z M8 11 L8 7 C8 4.79 9.79 3 12 3 C14.21 3 16 4.79 16 7 L16 11",
    ),
    ("chat", "M4 5 L20 5 L20 16 L9 16 L5 20 L5 16 L4 16 Z"),
    ("play", "M8 5 L19 12 L8 19 Z"),
    (
        "trash",
        "M4 7 L20 7 M9 7 L9 4 L15 4 L15 7 M6 7 L7 20 L17 20 L18 7",
    ),
];

/// The icon's path scaled from 24 points to `size`.
pub(crate) fn icon_path(name: &str, size: f64) -> Option<String> {
    let (_, d) = ICONS.iter().find(|(n, _)| *n == name)?;
    let k = size / 24.0;
    Some(
        d.split(' ')
            .map(|t| match t.parse::<f64>() {
                Ok(n) => format!("{}", (n * k * 100.0).round() / 100.0),
                Err(_) => t.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(test)]
#[path = "compose_answer_tests.rs"]
mod tests;
