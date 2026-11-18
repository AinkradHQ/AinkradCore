//! A text node's CSS (V6-03): the type props as font, size, weight, tracking, line height and alignment.

use serde_json::Value;

use super::style::{Cx, Out, color, fv, num, px, stops};
use crate::ids::is_sha256;
use crate::resolve::{ResolvedNode, Theme};

fn text_color(n: &ResolvedNode, theme: Theme) -> String {
    let default = if theme == Theme::Day {
        "#000000"
    } else {
        "#ffffff"
    };
    let first = n
        .props
        .get("fill")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    first
        .and_then(|f| match f.get("type").and_then(Value::as_str) {
            Some("solid") => f.get("color").and_then(color),
            Some("linear") => stops(f).first().map(|s| s.1.clone()),
            _ => None,
        })
        .unwrap_or_else(|| default.to_owned())
}

pub(super) fn families(font: Option<&Value>, fallback: Option<&str>) -> String {
    let mut out = vec![];
    if let Some(a) = font
        .and_then(|f| f.get("asset"))
        .and_then(Value::as_str)
        .filter(|a| is_sha256(a))
    {
        out.push(format!("\"asset-{a}\""));
    }
    if fallback.is_some_and(is_sha256) {
        out.push("\"design-system-fallback\"".to_owned());
    } else {
        out.extend(
            [
                "\"SF Pro\"",
                "-apple-system",
                "\"Helvetica Neue\"",
                "Arial",
                "\"DejaVu Sans\"",
                "sans-serif",
            ]
            .map(String::from),
        );
    }
    out.join(",")
}

/// The text the renderer shapes: `transform` applied here, in Rust, so both draw the same characters.
pub(super) fn shown_text(n: &ResolvedNode) -> String {
    let raw = n.text.as_deref().unwrap_or("");
    let t = n
        .props
        .get("type")
        .and_then(|t| t.get("transform"))
        .and_then(Value::as_str);
    match t {
        Some("uppercase") => raw.to_uppercase(),
        Some("lowercase") => raw.to_lowercase(),
        Some("capitalize") => raw
            .split(' ')
            .map(|w| {
                let mut c = w.chars();
                c.next()
                    .map(|f| f.to_uppercase().chain(c).collect::<String>())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => raw.to_owned(),
    }
}

pub(super) fn text(o: &mut Out, n: &ResolvedNode, cx: &Cx) {
    let ty = n.props.get("type").and_then(Value::as_object);
    let g = |k: &str| ty.and_then(|m| fv(m, k));
    let size = g("size").unwrap_or(14.0).max(1.0);
    o.put(
        "font-family",
        families(ty.and_then(|m| m.get("font")), cx.fallback),
    );
    o.put("font-size", px(size));
    o.put("font-weight", num(g("weight").unwrap_or(400.0).trunc()));
    o.put("color", text_color(n, cx.theme));
    if let Some(t) = g("tracking") {
        o.put("letter-spacing", px(t * size));
    }
    if let Some(l) = g("line").filter(|l| *l > 0.0) {
        o.put("line-height", px(l));
    }
    o.put(
        "text-align",
        match ty.and_then(|m| m.get("align")).and_then(Value::as_str) {
            Some("center") => "center",
            Some("right") => "right",
            Some("justify") => "justify",
            _ => "left",
        },
    );
    // newlines break lines, runs of spaces stay, as in the renderer's paragraph
    o.put("white-space", "pre-wrap");
}
