//! Layout: one top-level node of a page (an "artboard") -> a flat arena of positioned nodes, by taffy (T2).
//!
//! Semantics (the plan's auto-layout; decisions the plan did not spell out are marked):
//! - A frame / component / instance **with `layout`** is a flex container: `dir`, `gap`, `pad` (top, right, bottom,
//!   left; CSS order), `align` (cross axis, default start), `justify` (main axis), `wrap`. Its children flow; their
//!   `x`/`y` are ignored.
//! - A frame **without `layout`** places its children absolutely at their `x`/`y` (the only "absolute" the schema can
//!   express). Such a frame that is `hug` is 0x0 (content is still drawn, it just does not size the frame).
//! - `sizing.w|h`: `fixed` (uses `w`/`h`), `hug` (content), `fill` (grow along the parent's main axis, stretch across
//!   it, 100% of an absolute parent, hug at the top level). Absent sizing = `fixed` when `w`/`h` is set, else `hug`.
//! - Text measures through Skia paragraph; a text with a definite width wraps inside it.
//! - Positions are fractional (taffy rounding is off) so zoomed output stays exact.

use design_model::{NodeType, ResolvedNode, Theme};
use serde_json::Value;
use skia_safe::textlayout::{Paragraph, ParagraphBuilder, ParagraphStyle, TextAlign, TextStyle};
use skia_safe::{Color, FontStyle, Point, Rect};
use taffy::prelude::{
    AlignItems, AvailableSpace, FlexDirection, JustifyContent, NodeId, Position, Style, TaffyTree,
    auto, length, percent,
};

use crate::fonts::Fonts;
use crate::look::{Fill, Look, Shadow, num};

pub struct LNode {
    pub id: String,
    pub ty: NodeType,
    /// Absolute, in the artboard's own space (its root is at 0,0).
    pub rect: Rect,
    pub look: Look,
    pub kids: Vec<u32>,
    pub para: Option<Paragraph>,
}

pub struct Laid {
    pub nodes: Vec<LNode>,
    /// Everything drawn, shadows included, in artboard space.
    pub bounds: Rect,
    /// Glass-material nodes: each costs a live backdrop blur at `Lod::Full`.
    pub glass: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Flow {
    Row,
    Column,
    Free,
    Root,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Fixed,
    Hug,
    Fill,
}

struct B<'a> {
    t: TaffyTree<usize>,
    nodes: Vec<LNode>,
    tids: Vec<NodeId>,
    parent: Vec<usize>,
    paras: Vec<Paragraph>,
    fx: &'a Fonts,
    theme: Theme,
}

fn mode(n: &ResolvedNode, axis: &str, has: bool) -> Mode {
    match n
        .props
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

pub fn text_color(look: &Look, theme: Theme) -> Color {
    match look.fills.first() {
        Some(Fill::Solid(c)) => *c,
        Some(Fill::Linear(_, s)) => s[0].1,
        _ if theme == Theme::Day => Color::BLACK,
        _ => Color::WHITE,
    }
}

fn paragraph(n: &ResolvedNode, look: &Look, fx: &Fonts, theme: Theme) -> Paragraph {
    let ty = n.props.get("type").and_then(Value::as_object);
    let g = |k: &str| ty.and_then(|m| num(m, k));
    let size = g("size").unwrap_or(14.0).max(1.0);
    let weight = g("weight").unwrap_or(400.0) as i32;
    let font = ty.and_then(|m| m.get("font"));
    let fams = fx.families(font);
    let mut ts = TextStyle::new();
    ts.set_font_families(&fams);
    ts.set_font_size(size);
    ts.set_font_style(FontStyle::new(
        skia_safe::font_style::Weight::from(weight),
        skia_safe::font_style::Width::NORMAL,
        skia_safe::font_style::Slant::Upright,
    ));
    ts.set_color(text_color(look, theme));
    if let Some(t) = g("tracking") {
        ts.set_letter_spacing(t * size);
    }
    if let Some(l) = g("line").filter(|l| *l > 0.0) {
        ts.set_height(l / size);
        ts.set_height_override(true);
    }
    let mut ps = ParagraphStyle::new();
    ps.set_text_style(&ts);
    ps.set_text_align(
        match ty.and_then(|m| m.get("align")).and_then(Value::as_str) {
            Some("center") => TextAlign::Center,
            Some("right") => TextAlign::Right,
            Some("justify") => TextAlign::Justify,
            _ => TextAlign::Left,
        },
    );
    let raw = n.text.as_deref().unwrap_or("");
    let s = match ty.and_then(|m| m.get("transform")).and_then(Value::as_str) {
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
        _ => raw.to_string(),
    };
    let mut b = ParagraphBuilder::new(&ps, &fx.fc);
    b.add_text(&s);
    let mut p = b.build();
    p.layout(1.0e6);
    p
}

fn bleed(s: &[Shadow]) -> f32 {
    s.iter()
        .map(|s| s.blur * 1.5 + s.spread.max(0.0) + s.x.abs().max(s.y.abs()))
        .fold(0.0, f32::max)
}

impl<'a> B<'a> {
    fn add(&mut self, n: &ResolvedNode, flow: Flow, parent: usize) -> usize {
        let look = Look::of(n);
        let p = &n.props;
        let (w, h) = (num(p, "w"), num(p, "h"));
        let (mw, mh) = (mode(n, "w", w.is_some()), mode(n, "h", h.is_some()));
        let mut st = Style {
            flex_shrink: 0.0,
            ..Default::default()
        };
        // size per axis
        let axis = |m: Mode, v: Option<f32>, is_w: bool, st: &mut Style| {
            let dim = match (m, v) {
                (Mode::Fixed, Some(v)) => length(v),
                (Mode::Fill, _) => match flow {
                    Flow::Free => percent(1.0),
                    Flow::Row | Flow::Column => {
                        let main = (flow == Flow::Row) == is_w;
                        if main {
                            st.flex_grow = 1.0;
                            st.flex_basis = length(0.0);
                            st.flex_shrink = 1.0;
                        } else {
                            st.align_self = Some(AlignItems::STRETCH);
                        }
                        auto()
                    }
                    Flow::Root => auto(),
                },
                _ => auto(),
            };
            if is_w {
                st.size.width = dim;
            } else {
                st.size.height = dim;
            }
        };
        axis(mw, w, true, &mut st);
        axis(mh, h, false, &mut st);
        if flow == Flow::Free {
            st.position = Position::Absolute;
            st.inset = taffy::Rect {
                left: length(num(p, "x").unwrap_or(0.0)),
                top: length(num(p, "y").unwrap_or(0.0)),
                right: auto(),
                bottom: auto(),
            };
        }
        let mut child_flow = Flow::Free;
        if (n.ty.is_container() || n.ty == NodeType::Instance)
            && let Some(l) = p.get("layout").and_then(Value::as_object)
        {
            {
                let col = l.get("dir").and_then(Value::as_str) == Some("column");
                st.flex_direction = if col {
                    FlexDirection::Column
                } else {
                    FlexDirection::Row
                };
                child_flow = if col { Flow::Column } else { Flow::Row };
                let gap = num(l, "gap").unwrap_or(0.0);
                st.gap = taffy::Size {
                    width: length(gap),
                    height: length(gap),
                };
                if let Some(a) = l
                    .get("pad")
                    .and_then(Value::as_array)
                    .filter(|a| a.len() == 4)
                {
                    let v = |i: usize| a[i].as_f64().unwrap_or(0.0) as f32;
                    st.padding = taffy::Rect {
                        top: length(v(0)),
                        right: length(v(1)),
                        bottom: length(v(2)),
                        left: length(v(3)),
                    };
                }
                st.align_items = match l.get("align").and_then(Value::as_str) {
                    Some("center") => AlignItems::CENTER,
                    Some("end") => AlignItems::FLEX_END,
                    Some("stretch") => AlignItems::STRETCH,
                    _ => AlignItems::FLEX_START,
                };
                st.justify_content = match l.get("justify").and_then(Value::as_str) {
                    Some("center") => JustifyContent::CENTER,
                    Some("end") => JustifyContent::FLEX_END,
                    Some("between") => JustifyContent::SPACE_BETWEEN,
                    _ => JustifyContent::FLEX_START,
                };
                if l.get("wrap").and_then(Value::as_bool) == Some(true) {
                    st.flex_wrap = taffy::FlexWrap::Wrap;
                }
            }
        }
        let idx = self.nodes.len();
        let tid = if n.ty == NodeType::Text {
            let pa = paragraph(n, &look, self.fx, self.theme);
            self.paras.push(pa);
            self.t
                .new_leaf_with_context(st, self.paras.len() - 1)
                .unwrap_or_else(|_| unreachable_node())
        } else {
            if n.ty == NodeType::Vector
                && let Some(b) = look.path.as_ref().map(|p| p.compute_tight_bounds())
            {
                if mw == Mode::Hug {
                    st.size.width = length(b.right.max(0.0));
                }
                if mh == Mode::Hug {
                    st.size.height = length(b.bottom.max(0.0));
                }
            }
            self.t.new_leaf(st).unwrap_or_else(|_| unreachable_node())
        };
        self.nodes.push(LNode {
            id: n.id.clone(),
            ty: n.ty,
            rect: Rect::default(),
            look,
            kids: vec![],
            para: None,
        });
        self.tids.push(tid);
        self.parent.push(parent);
        if !n.children.is_empty() {
            let mut kid_t = vec![];
            for c in &n.children {
                let k = self.add(c, child_flow, idx);
                self.nodes[idx].kids.push(k as u32);
                kid_t.push(self.tids[k]);
            }
            let _ = self.t.set_children(tid, &kid_t);
        }
        idx
    }
}

fn unreachable_node() -> NodeId {
    // taffy only errors on a stale id; a fresh tree never produces one
    NodeId::new(0)
}

pub fn build(root: &ResolvedNode, fx: &Fonts, theme: Theme) -> Laid {
    let mut b = B {
        t: TaffyTree::new(),
        nodes: vec![],
        tids: vec![],
        parent: vec![],
        paras: vec![],
        fx,
        theme,
    };
    b.t.disable_rounding();
    b.add(root, Flow::Root, usize::MAX);
    let tid0 = b.tids[0];
    let paras = &mut b.paras;
    let _ = b.t.compute_layout_with_measure(
        tid0,
        taffy::Size {
            width: AvailableSpace::MaxContent,
            height: AvailableSpace::MaxContent,
        },
        |inputs, _id, ctx, style| {
            taffy::compute_leaf_layout(
                inputs,
                style,
                |_, _| 0.0,
                |known, avail| match ctx {
                    Some(i) => {
                        let p = &mut paras[*i];
                        let intr = p.max_intrinsic_width().ceil();
                        let w = known.width.unwrap_or(match avail.width {
                            AvailableSpace::Definite(a) => a.min(intr),
                            AvailableSpace::MinContent => p.min_intrinsic_width().ceil(),
                            AvailableSpace::MaxContent => intr,
                        });
                        p.layout(w);
                        taffy::Size {
                            width: w,
                            height: known.height.unwrap_or(p.height()),
                        }
                    }
                    None => taffy::Size::ZERO,
                },
            )
        },
    );
    // absolute rects: parents come before children in the arena
    let mut origin: Vec<Point> = vec![Point::new(0.0, 0.0); b.nodes.len()];
    let mut text_i = 0usize;
    let mut para_of: Vec<Option<usize>> = vec![None; b.nodes.len()];
    for (i, n) in b.nodes.iter().enumerate() {
        if n.ty == NodeType::Text {
            para_of[i] = Some(text_i);
            text_i += 1;
        }
    }
    let mut paras: Vec<Option<Paragraph>> = b.paras.drain(..).map(Some).collect();
    let mut bounds = Rect::default();
    for i in 0..b.nodes.len() {
        let l = b.t.layout(b.tids[i]).copied().unwrap_or_default();
        let base = if b.parent[i] == usize::MAX {
            Point::new(0.0, 0.0)
        } else {
            origin[b.parent[i]]
        };
        let o = Point::new(base.x + l.location.x, base.y + l.location.y);
        origin[i] = o;
        let n = &mut b.nodes[i];
        n.rect = Rect::from_xywh(o.x, o.y, l.size.width, l.size.height);
        if let Some(pi) = para_of[i] {
            let mut p = paras[pi].take();
            if let Some(p) = p.as_mut() {
                p.layout(l.size.width.max(1.0));
            }
            n.para = p;
        }
        let e = bleed(&n.look.shadows);
        let mut r = n.rect;
        r.outset((e, e));
        bounds = if i == 0 {
            r
        } else {
            Rect::new(
                bounds.left.min(r.left),
                bounds.top.min(r.top),
                bounds.right.max(r.right),
                bounds.bottom.max(r.bottom),
            )
        };
    }
    let glass = b
        .nodes
        .iter()
        .filter(|n| n.look.material == crate::look::Material::Glass)
        .count();
    Laid {
        nodes: b.nodes,
        bounds,
        glass,
    }
}
