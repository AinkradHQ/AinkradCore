//! HTML/CSS export of one screen (V6-03, plan T9, risk R5). Pure Rust, no I/O, no Skia: the same resolved tree the
//! renderer draws becomes a page whose CSS flexbox does what taffy does and whose paint does what Skia does.
//!
//! The package is `index.html` + `style.css` (+ `fonts/<sha256>` and `assets/<sha256>`, the library files the
//! caller already holds). It is inert by construction: no `<script>`, no event attribute, no `<a>`, `<form>`,
//! `<iframe>` or `<object>`; every URL is a fixed `fonts/<hash>` or `assets/<hash>` path built from a validated
//! hash; a CSP meta forbids script and network anyway; every name and text is escaped, and every value that reaches
//! CSS is rebuilt from a number, a validated colour or a validated hash.
//!
//! Themes: the package carries both. The page opens in `data-theme` day or night; a value that differs between the
//! two (a token) is a custom property `--vN` defined under `:root,[data-theme="day"]` and `[data-theme="night"]`,
//! so switching the attribute re-themes the page. Values equal in both themes stay plain.
//!
//! Known gaps against the renderer (the fidelity check measures them, it does not hide them):
//! - a CSS `box-shadow` is not drawn under its own box, Skia's shadow is: a shadow behind a translucent fill differs;
//! - Blink and Skia rasterise glyph edges differently (text is matched by metrics, not by pixel);
//! - gradients interpolate in premultiplied space in CSS, not in Skia (visible only with translucent stops).

mod style;
mod text;
mod vector;

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::Value;

use crate::ids::is_sha256;
use crate::resolve::{Resolved, ResolvedNode, Theme};
use crate::schema::NodeType;
use style::{Cx, Decl, Flow, color, node_decls};

/// What to export and how.
pub struct ExportOpts<'a> {
    pub page: usize,
    /// A resolved id of a top-level node of the page; `None`: the first.
    pub screen: Option<&'a str>,
    /// The theme the page opens in.
    pub theme: Theme,
    /// Sha256 of the library font `system` text falls back to (plan Q2); `None`: platform fonts.
    pub fallback_font: Option<&'a str>,
    /// Right and bottom of a path's tight bounds, which a hugging vector is as big as. The model has no path
    /// geometry; a host with Skia answers. `None`: hugging vectors are 0 x 0.
    pub path_bounds: Option<&'a dyn Fn(&str) -> Option<(f32, f32)>>,
}

impl ExportOpts<'_> {
    pub fn new(theme: Theme) -> Self {
        ExportOpts {
            page: 0,
            screen: None,
            theme,
            fallback_font: None,
            path_bounds: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    pub html: String,
    pub css: String,
    /// Library font hashes the package names (`fonts/<hash>`), the fallback included.
    pub fonts: Vec<String>,
    /// Library image hashes the package names (`assets/<hash>`).
    pub images: Vec<String>,
    /// The resolved id of the screen exported.
    pub screen: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportError {
    NoPage,
    NoScreen,
}

/// Text or an attribute value, safe between tags and inside a double-quoted attribute.
pub(crate) fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const CSP: &str = "script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; \
                   connect-src 'none'; frame-src 'none'";

const BASE: &str = "html,body{margin:0;padding:0;overflow:hidden}\
body{text-rendering:geometricPrecision;font-kerning:normal}\
.n{position:relative;flex:none;margin:0}\n";

struct Walk<'a> {
    day: Cx<'a>,
    night: Cx<'a>,
    html: String,
    d: Vec<Decl>,
    n: Vec<Decl>,
    next: usize,
}

fn child_flow(n: &ResolvedNode) -> Flow {
    let layout = (n.ty.is_container() || n.ty == NodeType::Instance)
        .then(|| n.props.get("layout").and_then(Value::as_object))
        .flatten();
    match layout {
        Some(l) if l.get("dir").and_then(Value::as_str) == Some("column") => Flow::Column,
        Some(_) => Flow::Row,
        None => Flow::Free,
    }
}

impl Walk<'_> {
    fn node(&mut self, d: &ResolvedNode, n: Option<&ResolvedNode>, flow: Flow) {
        let i = self.next;
        self.next += 1;
        self.d.extend(node_decls(d, i, flow, &self.day));
        if let Some(n) = n {
            self.n.extend(node_decls(n, i, flow, &self.night));
        }
        let ty = match d.ty {
            NodeType::Page => "page",
            NodeType::Frame => "frame",
            NodeType::Text => "text",
            NodeType::Rect => "rect",
            NodeType::Ellipse => "ellipse",
            NodeType::Image => "image",
            NodeType::Vector => "vector",
            NodeType::Component => "component",
            NodeType::Instance => "instance",
        };
        let tag = if d.ty == NodeType::Vector {
            "svg"
        } else {
            "div"
        };
        let mut attrs = format!(
            "class=\"n n{i}\" data-id=\"{}\" data-type=\"{ty}\"",
            esc(&d.id)
        );
        if !d.name.is_empty() {
            attrs += &format!(" data-name=\"{}\"", esc(&d.name));
        }
        if let Some(c) = &d.component {
            attrs += &format!(" data-component=\"{}\"", esc(c));
        }
        let p = &d.props;
        if let Some(r) = p.get("role").and_then(Value::as_str) {
            attrs += &format!(" data-role=\"{}\"", esc(r));
        }
        if let Some(l) = p.get("link").and_then(Value::as_object) {
            if let Some(t) = l.get("to").and_then(Value::as_str) {
                attrs += &format!(" data-link=\"{}\"", esc(t));
            }
            if let Some(t) = l.get("transition").and_then(Value::as_str) {
                attrs += &format!(" data-transition=\"{}\"", esc(t));
            }
        }
        if let Some(r) = p
            .get("stroke")
            .and_then(|s| s.get("role"))
            .and_then(Value::as_str)
        {
            attrs += &format!(" data-stroke-role=\"{}\"", esc(r));
        }
        self.html += &format!("<{tag} {attrs}>");
        match d.ty {
            NodeType::Text => self.html += &esc(&text::shown_text(d)),
            NodeType::Vector => self.html += &vector::vector_parts(d, i, &self.day).0,
            _ => {}
        }
        let flow = child_flow(d);
        for (k, c) in d.children.iter().enumerate() {
            self.node(c, n.and_then(|n| n.children.get(k)), flow);
        }
        self.html += &format!("</{tag}>");
    }
}

/// Day and night declarations as one stylesheet: equal values stay, differing ones become variables.
fn sheet(day: Vec<Decl>, night: Vec<Decl>) -> String {
    let mut by_night: HashMap<(&str, &str), &str> = HashMap::new();
    for (s, k, v) in &night {
        by_night.insert((s.as_str(), k.as_str()), v.as_str());
    }
    let mut groups: Vec<(String, Vec<String>)> = vec![];
    let mut at: HashMap<String, usize> = HashMap::new();
    let (mut vd, mut vn) = (vec![], vec![]);
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut var = 0usize;
    let mut push = |sel: &str, line: String| {
        let g = *at.entry(sel.to_owned()).or_insert_with(|| {
            groups.push((sel.to_owned(), vec![]));
            groups.len() - 1
        });
        groups[g].1.push(line);
    };
    for (s, k, v) in &day {
        seen.insert((s.as_str(), k.as_str()));
        match by_night.get(&(s.as_str(), k.as_str())) {
            Some(nv) if **nv == *v.as_str() => push(s, format!("{k}:{v}")),
            other => {
                let name = format!("--v{var}");
                var += 1;
                vd.push(format!("{name}:{v}"));
                if let Some(nv) = other {
                    vn.push(format!("{name}:{nv}"));
                }
                push(s, format!("{k}:var({name})"));
            }
        }
    }
    for (s, k, v) in &night {
        if seen.insert((s.as_str(), k.as_str())) {
            let name = format!("--v{var}");
            var += 1;
            vn.push(format!("{name}:{v}"));
            push(s, format!("{k}:var({name})"));
        }
    }
    let mut css = String::new();
    for (sel, lines) in &groups {
        css += &format!("{sel}{{{}}}\n", lines.join(";"));
    }
    css += &format!(":root,[data-theme=\"day\"]{{{}}}\n", vd.join(";"));
    css += &format!("[data-theme=\"night\"]{{{}}}\n", vn.join(";"));
    css
}

fn collect(n: &ResolvedNode, fonts: &mut BTreeSet<String>, images: &mut BTreeSet<String>) {
    let mut keep = |set: &mut BTreeSet<String>, v: Option<&Value>| {
        if let Some(a) = v.and_then(Value::as_str).filter(|a| is_sha256(a)) {
            set.insert(a.to_owned());
        }
    };
    keep(
        fonts,
        n.props
            .get("type")
            .and_then(|t| t.get("font"))
            .and_then(|f| f.get("asset")),
    );
    for f in n
        .props
        .get("fill")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if f.get("type").and_then(Value::as_str) == Some("image") {
            keep(images, f.get("asset"));
        }
    }
    if n.ty == NodeType::Image {
        keep(images, n.props.get("asset"));
    }
    for c in &n.children {
        collect(c, fonts, images);
    }
}

/// The page's own background (`scene.rs::page_background`): its first solid fill, else a fixed day or night colour.
fn page_background(page: &ResolvedNode, theme: Theme) -> String {
    let default = if theme == Theme::Day {
        "#e9ecf2"
    } else {
        "#16171b"
    };
    page.props
        .get("fill")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .filter(|f| f.get("type").and_then(Value::as_str) == Some("solid"))
        .and_then(|f| f.get("color").and_then(color))
        .unwrap_or_else(|| default.to_owned())
}

/// `day` and `night` are the same document resolved for each theme.
pub fn export(day: &Resolved, night: &Resolved, o: &ExportOpts) -> Result<Exported, ExportError> {
    let page = day.pages.get(o.page).ok_or(ExportError::NoPage)?;
    let night_page = night.pages.get(o.page);
    let at = match o.screen {
        Some(id) => page.children.iter().position(|c| c.id == id),
        None => (!page.children.is_empty()).then_some(0),
    }
    .ok_or(ExportError::NoScreen)?;
    let screen = &page.children[at];
    let cx = |theme| Cx {
        theme,
        fallback: o.fallback_font.filter(|f| is_sha256(f)),
        bounds: o.path_bounds,
    };
    let mut w = Walk {
        day: cx(Theme::Day),
        night: cx(Theme::Night),
        html: String::new(),
        d: vec![],
        n: vec![],
        next: 0,
    };
    w.node(
        screen,
        night_page.and_then(|p| p.children.get(at)),
        Flow::Root,
    );
    w.d.push((
        "body".into(),
        "background-color".into(),
        page_background(page, Theme::Day),
    ));
    w.n.push((
        "body".into(),
        "background-color".into(),
        night_page.map_or_else(
            || page_background(page, Theme::Night),
            |p| page_background(p, Theme::Night),
        ),
    ));
    let (mut fonts, mut images) = (BTreeSet::new(), BTreeSet::new());
    collect(screen, &mut fonts, &mut images);
    if let Some(n) = night_page.and_then(|p| p.children.get(at)) {
        collect(n, &mut fonts, &mut images);
    }
    let mut css = String::from(BASE);
    for f in &fonts {
        css += &format!(
            "@font-face{{font-family:\"asset-{f}\";src:url(\"fonts/{f}\");font-weight:1 1000}}\n"
        );
    }
    let fallback = o.fallback_font.filter(|f| is_sha256(f));
    if let Some(f) = fallback {
        css += &format!(
            "@font-face{{font-family:\"design-system-fallback\";src:url(\"fonts/{f}\");font-weight:1 1000}}\n"
        );
        fonts.insert(f.to_owned());
    }
    css += &sheet(w.d, w.n);
    let theme = if o.theme == Theme::Day {
        "day"
    } else {
        "night"
    };
    let html = format!(
        "<!doctype html><html lang=\"en\" data-theme=\"{theme}\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\"><title>{}</title>\
<link rel=\"stylesheet\" href=\"style.css\"></head><body>{}</body></html>\n",
        esc(&screen.name),
        w.html
    );
    Ok(Exported {
        html,
        css,
        fonts: fonts.into_iter().collect(),
        images: images.into_iter().collect(),
        screen: screen.id.clone(),
    })
}
