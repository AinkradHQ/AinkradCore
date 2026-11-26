//! The drawing look of one node: the resolved props (already schema-valid, tokens substituted) as typed values.
//! Nothing here can fail: an absent or unusable prop falls back to the default.

use design_model::{NodeType, ResolvedNode};
use serde_json::{Map, Value};
use skia_safe::{BlendMode, Color, Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Material {
    None,
    Glass,
    Well,
    Clear,
}

/// Image placement. `fill` and `crop` cover the box (aspect kept, centred, clipped), `fit` contains it, `tile` repeats
/// the image at its natural size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    Cover,
    Contain,
    Tile,
}

#[derive(Debug, Clone)]
pub enum Fill {
    Solid(Color),
    /// CSS convention: 0 deg points up, 90 deg points right. Stops are `(at, colour)`.
    Linear(f32, Vec<(f32, Color)>),
    Image(String, Fit),
}

#[derive(Debug, Clone, Copy)]
pub struct Shadow {
    pub x: f32,
    pub y: f32,
    pub blur: f32,
    pub spread: f32,
    pub color: Color,
    /// an inner shadow, drawn inside the shape over its fills
    pub inset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Inside,
    Center,
    Outside,
}

#[derive(Debug, Clone)]
pub struct Stroke {
    pub color: Color,
    pub width: f32,
    pub align: Align,
    /// on / off lengths (an odd list repeats, as in SVG); empty = solid
    pub dash: Vec<f32>,
}

#[derive(Debug, Clone)]
pub struct Look {
    pub visible: bool,
    pub opacity: f32,
    pub blend: BlendMode,
    pub clip: bool,
    /// top-left, top-right, bottom-right, bottom-left
    pub radius: [f32; 4],
    pub fills: Vec<Fill>,
    /// in draw order; inside the box unless aligned otherwise (a vector's path is always stroked on its centre)
    pub strokes: Vec<Stroke>,
    pub shadows: Vec<Shadow>,
    /// degrees clockwise about the centre of the node's box
    pub rotation: f32,
    /// layer blur and background blur, Skia sigma x 2 (a CSS-like radius)
    pub blur: f32,
    pub backdrop_blur: f32,
    pub material: Material,
    pub path: Option<Path>,
    pub image: Option<(String, Fit)>,
}

pub fn num(m: &Map<String, Value>, k: &str) -> Option<f32> {
    m.get(k)?.as_f64().map(|f| f as f32)
}

pub fn hex(s: &str) -> Option<Color> {
    let h = s.strip_prefix('#')?;
    let v = u32::from_str_radix(h, 16).ok()?;
    match h.len() {
        6 => Some(Color::new(0xFF00_0000 | v)),
        8 => Some(Color::from_argb(
            (v & 255) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
        )),
        _ => None,
    }
}

fn color(v: &Value) -> Option<Color> {
    hex(v.as_str()?)
}

fn fit(s: Option<&Value>) -> Fit {
    match s.and_then(Value::as_str) {
        Some("fit") => Fit::Contain,
        Some("tile") => Fit::Tile,
        _ => Fit::Cover,
    }
}

fn fills(v: Option<&Value>) -> Vec<Fill> {
    let mut out = vec![];
    for f in v.and_then(Value::as_array).into_iter().flatten() {
        match f.get("type").and_then(Value::as_str) {
            Some("solid") => out.extend(f.get("color").and_then(color).map(Fill::Solid)),
            Some("linear") => {
                let stops: Vec<(f32, Color)> = f
                    .get("stops")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|s| {
                        Some((
                            s.get("at")?.as_f64()? as f32,
                            s.get("color").and_then(color)?,
                        ))
                    })
                    .collect();
                let angle = f.get("angle").and_then(Value::as_f64).unwrap_or(180.0) as f32;
                if stops.len() >= 2 {
                    out.push(Fill::Linear(angle, stops));
                }
            }
            Some("image") => {
                if let Some(a) = f.get("asset").and_then(Value::as_str) {
                    out.push(Fill::Image(a.to_string(), fit(f.get("mode"))));
                }
            }
            _ => {}
        }
    }
    out
}

fn radius(v: Option<&Value>) -> [f32; 4] {
    match v {
        Some(Value::Array(a)) if a.len() == 4 => {
            let g = |i: usize| a[i].as_f64().unwrap_or(0.0) as f32;
            [g(0), g(1), g(2), g(3)]
        }
        Some(x) => [x.as_f64().unwrap_or(0.0) as f32; 4],
        None => [0.0; 4],
    }
}

fn shadows(v: Option<&Value>) -> Vec<Shadow> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| {
            let m = s.as_object()?;
            Some(Shadow {
                x: num(m, "x").unwrap_or(0.0),
                y: num(m, "y").unwrap_or(0.0),
                blur: num(m, "blur").unwrap_or(0.0),
                spread: num(m, "spread").unwrap_or(0.0),
                color: m.get("color").and_then(color)?,
                inset: m.get("inset").and_then(Value::as_bool) == Some(true),
            })
        })
        .collect()
}

impl Look {
    pub fn of(n: &ResolvedNode) -> Look {
        let p = &n.props;
        let blend = match p.get("blend").and_then(Value::as_str) {
            Some("multiply") => BlendMode::Multiply,
            Some("screen") => BlendMode::Screen,
            Some("overlay") => BlendMode::Overlay,
            Some("darken") => BlendMode::Darken,
            Some("lighten") => BlendMode::Lighten,
            _ => BlendMode::SrcOver,
        };
        let one = |s: &Map<String, Value>| {
            let width = num(s, "width").unwrap_or(1.0);
            let dash: Vec<f32> = s
                .get("dash")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|d| d.as_f64().map(|d| d as f32))
                .collect();
            (width > 0.0).then_some(Stroke {
                color: s.get("color").and_then(color)?,
                width,
                align: match s.get("align").and_then(Value::as_str) {
                    Some("center") => Align::Center,
                    Some("outside") => Align::Outside,
                    _ => Align::Inside,
                },
                // an all-zero pattern draws nothing in Skia: solid instead
                dash: if dash.iter().any(|d| *d > 0.0) {
                    dash
                } else {
                    vec![]
                },
            })
        };
        let strokes = match p.get("stroke") {
            Some(Value::Array(a)) => a.iter().filter_map(|s| one(s.as_object()?)).collect(),
            Some(Value::Object(s)) => one(s).into_iter().collect(),
            _ => vec![],
        };
        let image = (n.ty == NodeType::Image)
            .then(|| {
                let a = p.get("asset")?.as_str()?;
                Some((a.to_string(), fit(p.get("fit"))))
            })
            .flatten();
        Look {
            visible: p.get("visible").and_then(Value::as_bool).unwrap_or(true),
            opacity: num(p, "opacity").unwrap_or(1.0).clamp(0.0, 1.0),
            blend,
            clip: p.get("clip").and_then(Value::as_bool).unwrap_or(false),
            radius: radius(p.get("radius")),
            fills: fills(p.get("fill")),
            strokes,
            shadows: shadows(p.get("shadow")),
            rotation: num(p, "rotation").unwrap_or(0.0),
            blur: num(p, "blur").unwrap_or(0.0).max(0.0),
            backdrop_blur: num(p, "backdrop_blur").unwrap_or(0.0).max(0.0),
            material: match p.get("material").and_then(Value::as_str) {
                Some("glass") => Material::Glass,
                Some("well") => Material::Well,
                Some("clear") => Material::Clear,
                _ => Material::None,
            },
            path: p
                .get("path")
                .and_then(Value::as_str)
                .and_then(Path::from_svg),
            image,
        }
    }
}
