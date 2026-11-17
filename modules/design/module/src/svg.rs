//! SVG sanitiser (T8, Sec): an uploaded SVG is untrusted markup that apps and Chromium will render.
//! It is rewritten through an allow-list into a static subset, or refused. Only what the lists below
//! name survives: no script, no event handler, no `foreignObject`, no animation, no external
//! reference (an `href` may only point at `#id`, or an embedded raster `data:` image), no `@import`/
//! external `url(...)` in CSS, no comment, DOCTYPE, processing instruction or foreign namespace.
//! The output is re-serialised from parsed events, so nothing the parser did not understand is copied.
//! The parser (`quick-xml`) resolves no custom entity, so an entity bomb cannot expand; an unknown
//! entity refuses the file.

use quick_xml::Reader;
use quick_xml::escape::{escape, unescape};
use quick_xml::events::{BytesStart, Event};

const SVG_NS: &str = "http://www.w3.org/2000/svg";
const XLINK_NS: &str = "http://www.w3.org/1999/xlink";
const MAX_DEPTH: usize = 64;
const MAX_ELEMENTS: usize = 50_000;
const MAX_USES: usize = 256;

const ELEMENTS: &[&str] = &[
    "svg",
    "g",
    "defs",
    "symbol",
    "use",
    "path",
    "rect",
    "circle",
    "ellipse",
    "line",
    "polyline",
    "polygon",
    "text",
    "tspan",
    "textPath",
    "title",
    "desc",
    "linearGradient",
    "radialGradient",
    "stop",
    "pattern",
    "clipPath",
    "mask",
    "marker",
    "image",
    "style",
    "filter",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feFuncR",
    "feFuncG",
    "feFuncB",
    "feFuncA",
    "feComposite",
    "feFlood",
    "feGaussianBlur",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "feDropShadow",
    "feTurbulence",
];

const ATTRS: &[&str] = &[
    "id",
    "class",
    "style",
    "width",
    "height",
    "x",
    "y",
    "x1",
    "x2",
    "y1",
    "y2",
    "cx",
    "cy",
    "r",
    "rx",
    "ry",
    "fx",
    "fy",
    "d",
    "points",
    "transform",
    "viewBox",
    "preserveAspectRatio",
    "version",
    "fill",
    "fill-opacity",
    "fill-rule",
    "stroke",
    "stroke-width",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-miterlimit",
    "stroke-dasharray",
    "stroke-dashoffset",
    "stroke-opacity",
    "opacity",
    "color",
    "display",
    "visibility",
    "overflow",
    "clip-path",
    "clip-rule",
    "mask",
    "filter",
    "marker-start",
    "marker-mid",
    "marker-end",
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "font-variant",
    "letter-spacing",
    "word-spacing",
    "text-anchor",
    "text-decoration",
    "dominant-baseline",
    "alignment-baseline",
    "baseline-shift",
    "writing-mode",
    "direction",
    "textLength",
    "lengthAdjust",
    "dx",
    "dy",
    "rotate",
    "startOffset",
    "gradientUnits",
    "gradientTransform",
    "spreadMethod",
    "offset",
    "stop-color",
    "stop-opacity",
    "patternUnits",
    "patternContentUnits",
    "patternTransform",
    "clipPathUnits",
    "maskUnits",
    "maskContentUnits",
    "markerUnits",
    "markerWidth",
    "markerHeight",
    "refX",
    "refY",
    "orient",
    "filterUnits",
    "primitiveUnits",
    "in",
    "in2",
    "result",
    "stdDeviation",
    "mode",
    "values",
    "type",
    "operator",
    "k1",
    "k2",
    "k3",
    "k4",
    "flood-color",
    "flood-opacity",
    "radius",
    "baseFrequency",
    "numOctaves",
    "seed",
    "stitchTiles",
    "tableValues",
    "slope",
    "intercept",
    "amplitude",
    "exponent",
    "lighting-color",
    "mix-blend-mode",
    "isolation",
    "vector-effect",
    "shape-rendering",
    "image-rendering",
    "text-rendering",
    "color-interpolation",
    "color-interpolation-filters",
    "paint-order",
    "role",
    "aria-label",
    "aria-hidden",
];

/// Elements whose `href` may point at `#id`.
const REF_ELEMENTS: &[&str] = &[
    "use",
    "linearGradient",
    "radialGradient",
    "pattern",
    "textPath",
];

/// Functions a value may call; `url(` is separate (a local `#id` only). Anything else (`image-set(`,
/// `src(`, `var(`, `calc(` ...) can fetch or compute, so the value is dropped.
const FUNCTIONS: &[&str] = &[
    "rgb",
    "rgba",
    "hsl",
    "hsla",
    "translate",
    "rotate",
    "scale",
    "matrix",
    "skewx",
    "skewy",
];

/// A value that cannot carry script or reach outside the file: no backslash (CSS escapes can spell
/// `url(`), no quote, no function but the allow-list, and every `url(` a local `#id`.
fn value_ok(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    if [
        "javascript:",
        "vbscript:",
        "data:",
        "expression(",
        "<",
        "\\",
        "\"",
        "'",
    ]
    .iter()
    .any(|bad| l.contains(bad))
    {
        return false;
    }
    l.match_indices('(').all(|(i, _)| {
        let name = l[..i]
            .trim_end()
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .next()
            .unwrap_or("");
        if name == "url" {
            l[i + 1..].trim_start().starts_with('#')
        } else {
            FUNCTIONS.contains(&name)
        }
    })
}

/// CSS the file may keep: the value rules, no at-rule (`@import`), no script hook.
fn css_ok(css: &str) -> bool {
    value_ok(css)
        && !css.contains('@')
        && !css.to_ascii_lowercase().contains("behavior")
        && !css.to_ascii_lowercase().contains("binding")
}

/// An embedded raster image: `data:image/{png,jpeg,gif,webp};base64,<base64>`.
fn data_image_ok(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("data:image/") else {
        return false;
    };
    let Some((mime, b64)) = rest.split_once(";base64,") else {
        return false;
    };
    ["png", "jpeg", "gif", "webp"].contains(&mime)
        && b64.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'\n' | b'\r' | b' ')
        })
}

/// Each `<use>` can instantiate a subtree, so their number is capped (a cheap expansion bomb guard).
fn is_use(tag: &str) -> bool {
    tag.strip_prefix("<use")
        .is_some_and(|r| r.starts_with([' ', '/', '>']))
}

fn refuse<T>() -> Result<T, ()> {
    Err(())
}

/// One kept start tag, or `None` when the element is not allowed (its subtree goes with it).
fn open_tag(e: &BytesStart<'_>, self_closing: bool, root: bool) -> Result<Option<String>, ()> {
    let name = e.name().as_ref().to_owned();
    // No prefix at all: `svg:rect`, `inkscape:*`, `sodipodi:*` are dropped.
    if !ELEMENTS.contains(&name.as_str()) || (root && name != "svg") {
        return if root { refuse() } else { Ok(None) };
    }
    let mut out = format!("<{name}");
    for a in e.attributes() {
        let a = a.map_err(|_| ())?;
        let key = a.key.as_ref();
        let value = unescape(&a.value).map_err(|_| ())?;
        let keep = match key {
            "xmlns" => value == SVG_NS,
            "xmlns:xlink" => value == XLINK_NS,
            "xml:space" => matches!(&*value, "default" | "preserve"),
            "href" | "xlink:href" => {
                (REF_ELEMENTS.contains(&name.as_str())
                    && value.starts_with('#')
                    && !value.contains([' ', '(', ')']))
                    || (name == "image" && data_image_ok(&value))
            }
            "style" => css_ok(&value),
            k => ATTRS.contains(&k) && value_ok(&value),
        };
        if keep {
            out.push_str(&format!(" {key}=\"{}\"", escape(&*value)));
        }
    }
    out.push_str(if self_closing { "/>" } else { ">" });
    Ok(Some(out))
}

/// The sanitised SVG, or `Err(())` when the file is not an SVG, is not well-formed, or is too deep or
/// large to trust. `input` must be UTF-8.
pub(crate) fn sanitise(input: &[u8]) -> Result<Vec<u8>, ()> {
    let text = std::str::from_utf8(input).map_err(|_| ())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rd = Reader::from_str(text);
    let mut out = String::with_capacity(text.len());
    let (mut depth, mut skip, mut elements, mut roots, mut uses) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    // Where a kept `<style>` began in `out`, so a hostile one can be cut back out.
    let mut style_at: Vec<usize> = Vec::new();
    loop {
        match rd.read_event().map_err(|_| ())? {
            Event::Start(e) => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return refuse();
                }
                if skip > 0 {
                    skip += 1;
                    continue;
                }
                elements += 1;
                let root = depth == 1;
                if root {
                    roots += 1;
                }
                if elements > MAX_ELEMENTS || roots > 1 {
                    return refuse();
                }
                match open_tag(&e, false, root)? {
                    Some(tag) => {
                        uses += is_use(&tag) as usize;
                        if uses > MAX_USES {
                            return refuse();
                        }
                        if tag.starts_with("<style") {
                            style_at.push(out.len());
                        } else {
                            style_at.push(usize::MAX);
                        }
                        out.push_str(&tag);
                    }
                    None => skip = 1,
                }
            }
            Event::Empty(e) => {
                if skip > 0 {
                    continue;
                }
                elements += 1;
                let root = depth == 0;
                if root {
                    roots += 1;
                }
                if elements > MAX_ELEMENTS || roots > 1 || depth + 1 > MAX_DEPTH {
                    return refuse();
                }
                if let Some(tag) = open_tag(&e, true, root)? {
                    uses += is_use(&tag) as usize;
                    if uses > MAX_USES {
                        return refuse();
                    }
                    out.push_str(&tag);
                }
            }
            Event::End(e) => {
                depth = depth.checked_sub(1).ok_or(())?;
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                let name = e.name().as_ref().to_owned();
                let at = style_at.pop().ok_or(())?;
                if at != usize::MAX {
                    // `<style>` .. now: keep it only when its CSS is clean.
                    let css_start = out[at..].find('>').ok_or(())? + at + 1;
                    let css = unescape(&out[css_start..]).map_err(|_| ())?.into_owned();
                    if !css_ok(&css) {
                        out.truncate(at);
                        continue;
                    }
                }
                out.push_str(&format!("</{name}>"));
            }
            Event::Text(t) if skip == 0 && depth > 0 => {
                out.push_str(&escape(&*t.into_inner()));
            }
            Event::CData(t) if skip == 0 && depth > 0 => {
                out.push_str(&escape(&*t.into_inner()));
            }
            Event::GeneralRef(r) if skip == 0 && depth > 0 => {
                let c = match r.resolve_char_ref().map_err(|_| ())? {
                    Some(c) => c,
                    None => match &*r.into_inner() {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return refuse(),
                    },
                };
                out.push_str(&escape(&*c.to_string()));
            }
            Event::Eof => break,
            // Comments, the XML declaration, processing instructions and the DOCTYPE are dropped; text
            // outside the root (whitespace) too.
            _ => {}
        }
    }
    if depth != 0 || roots != 1 {
        return refuse();
    }
    Ok(out.into_bytes())
}
