//! A vector node's SVG (V6-03): its `<path>`s, gradients and their paint.

use serde_json::Value;

use super::style::{Cx, Decl, Mode, color, fv, mode, num, px, stops};
use crate::resolve::ResolvedNode;
use crate::svgpath;

pub(super) fn path_of(n: &ResolvedNode) -> Option<&str> {
    n.props
        .get("path")
        .and_then(Value::as_str)
        .filter(|d| svgpath::validate(d).is_ok())
}

/// A vector's size as the renderer lays it out: its own `w`/`h` when fixed, else its path's bounds.
pub(super) fn vector_box(n: &ResolvedNode, cx: &Cx) -> (Option<f64>, Option<f64>) {
    let b = path_of(n)
        .and_then(|d| cx.bounds.and_then(|f| f(d)))
        .map(|(w, h)| (f64::from(w), f64::from(h)));
    let side = |key: &str, hug: Option<f64>| {
        let v = fv(&n.props, key);
        match mode(&n.props, key, v.is_some()) {
            Mode::Fixed => v,
            Mode::Hug => hug,
            Mode::Fill => None,
        }
    };
    (side("w", b.map(|b| b.0)), side("h", b.map(|b| b.1)))
}

/// A vector's `<path>` elements (markup) and their paint (declarations). Linear gradients need the box the
/// renderer shades over; a vector whose size is not known here (hugging, no bounds callback) paints the first stop.
pub(super) fn vector_parts(n: &ResolvedNode, i: usize, cx: &Cx) -> (String, Vec<Decl>) {
    let (mut html, mut css) = (String::new(), vec![]);
    let Some(d) = path_of(n) else {
        return (html, css);
    };
    let d = super::esc(d);
    let (bw, bh) = vector_box(n, cx);
    let mut defs = String::new();
    let mut paths = String::new();
    for (k, f) in n
        .props
        .get("fill")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let sel = format!(".n{i}p{k}");
        match f.get("type").and_then(Value::as_str) {
            Some("solid") => {
                if let Some(c) = f.get("color").and_then(color) {
                    css.push((sel.clone(), "fill".into(), c));
                    paths += &format!("<path class=\"n{i}p{k}\" d=\"{d}\"/>");
                }
            }
            Some("linear") => {
                let s = stops(f);
                if s.len() < 2 {
                    continue;
                }
                match (bw, bh) {
                    (Some(w), Some(h)) => {
                        let a = f.get("angle").and_then(Value::as_f64).unwrap_or(180.0);
                        let (sx, sy) = (a.to_radians().sin(), -a.to_radians().cos());
                        let len = (w * sx).abs() + (h * sy).abs();
                        let (cx0, cy0) = (w / 2.0, h / 2.0);
                        defs += &format!(
                            "<linearGradient id=\"g{i}_{k}\" gradientUnits=\"userSpaceOnUse\" x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\">",
                            num(cx0 - sx * len / 2.0),
                            num(cy0 - sy * len / 2.0),
                            num(cx0 + sx * len / 2.0),
                            num(cy0 + sy * len / 2.0)
                        );
                        for (j, (at, c)) in s.iter().enumerate() {
                            defs +=
                                &format!("<stop offset=\"{}\" class=\"n{i}s{k}_{j}\"/>", num(*at));
                            css.push((format!(".n{i}s{k}_{j}"), "stop-color".into(), c.clone()));
                        }
                        defs += "</linearGradient>";
                        css.push((sel.clone(), "fill".into(), format!("url(#g{i}_{k})")));
                    }
                    // ponytail: no size known, so no gradient line; the first stop. The helper always supplies bounds.
                    _ => css.push((sel.clone(), "fill".into(), s[0].1.clone())),
                }
                paths += &format!("<path class=\"n{i}p{k}\" d=\"{d}\"/>");
            }
            _ => {}
        }
    }
    if let Some(s) = n.props.get("stroke").and_then(Value::as_object) {
        let w = fv(s, "width").unwrap_or(1.0);
        if let (true, Some(c)) = (w > 0.0, s.get("color").and_then(color)) {
            let sel = format!(".n{i}k");
            css.push((sel.clone(), "fill".into(), "none".into()));
            css.push((sel.clone(), "stroke".into(), c));
            css.push((sel, "stroke-width".into(), px(w)));
            paths += &format!("<path class=\"n{i}k\" d=\"{d}\"/>");
        }
    }
    if !defs.is_empty() {
        html += &format!("<defs>{defs}</defs>");
    }
    html += &paths;
    (html, css)
}
