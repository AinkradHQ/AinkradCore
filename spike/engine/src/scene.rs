//! Generated scene: 50 app screens, 5 000 nodes (40 text runs + 4 glass panels per screen),
//! laid out by taffy (text measured through Skia paragraph), drawn from one cached SkPicture per screen.
use skia_safe::textlayout::{
    FontCollection, Paragraph, ParagraphBuilder, ParagraphStyle, TextStyle, TypefaceFontProvider,
};
use skia_safe::{
    BlurStyle, Canvas, Color, Data, FontMgr, Paint, PaintStyle, Picture, PictureRecorder, Point, RRect, Rect as SkRect, TileMode,
    canvas::SaveLayerRec, gradient_shader, image_filters,
};
use std::time::Instant;
use taffy::prelude::*;

pub const COLS: usize = 10;
pub const ROWS: usize = 5;
pub const SCREEN_W: f32 = 390.0;
pub const SCREEN_H: f32 = 1040.0;
pub const GAP: f32 = 80.0;
pub const WORLD_W: f32 = COLS as f32 * SCREEN_W + (COLS as f32 - 1.0) * GAP;
pub const WORLD_H: f32 = ROWS as f32 * SCREEN_H + (ROWS as f32 - 1.0) * GAP;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Frame,
    Card,
    Image,
    Glass,
    Text,
    Icon,
}

pub struct Node {
    pub kind: Kind,
    pub rect: SkRect, // screen-local
    pub radius: f32,
    pub color: u32,
    pub group: i32, // nodes of one card move together when dragged; -1 = none
    pub para: Option<Paragraph>,
}

pub struct Screen {
    pub origin: Point,
    pub nodes: Vec<Node>,
    pub pic: Option<Picture>,
    pub pic_lod: Option<Picture>,
    pub pic_bars: Option<Picture>, // no blur, text drawn as bars (zoomed far out)
    pub pic_nb: Option<Picture>, // text kept, glass flat (no live backdrop blur)
    pub rerecords: u32,
}

pub struct Scene {
    pub screens: Vec<Screen>,
    pub open_ms: f64,
    pub layout_ms: f64,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 32) as u32
    }
    fn pick(&mut self, n: usize) -> usize {
        self.next() as usize % n
    }
}

const WORDS: &[&str] = &[
    "Wallet", "Orders", "Profile", "Settings", "Checkout", "Delivery", "Invoice", "Payment", "Account", "Activity",
    "Messages", "Calendar", "Garden", "Studio", "Journal", "Travel", "Coffee", "Market", "Design", "Review",
    "Summary", "Balance", "Security", "Support", "Offers", "Rewards", "Library", "Nearby", "History", "Team",
];

fn color_of(rng: &mut Rng, base: u32) -> u32 {
    let j = |c: u32, r: &mut Rng| ((c as i32 + (r.next() % 40) as i32 - 20).clamp(0, 255)) as u32;
    0xFF000000 | (j((base >> 16) & 255, rng) << 16) | (j((base >> 8) & 255, rng) << 8) | j(base & 255, rng)
}

pub fn font_collection(font_path: &str) -> FontCollection {
    let data = std::fs::read(font_path).unwrap_or_else(|e| panic!("font {font_path}: {e}"));
    let tf = FontMgr::new().new_from_data(Data::new_copy(&data), None).expect("typeface");
    let mut prov = TypefaceFontProvider::new();
    prov.register_typeface(tf, "SpikeSans");
    let mut fc = FontCollection::new();
    fc.set_asset_font_manager(Some(prov.into()));
    fc
}

fn para(fc: &FontCollection, text: &str, size: f32, color: u32) -> Paragraph {
    let mut ts = TextStyle::new();
    ts.set_font_families(&["SpikeSans"]);
    ts.set_font_size(size);
    ts.set_color(Color::new(color));
    let mut ps = ParagraphStyle::new();
    ps.set_text_style(&ts);
    ps.set_max_lines(1);
    let mut b = ParagraphBuilder::new(&ps, fc);
    b.add_text(text);
    let mut p = b.build();
    p.layout(1.0e6);
    p
}

enum Ctx {
    Text(usize), // index into the screen's paragraph list
}

fn style_fixed(w: f32, h: f32) -> Style {
    Style { size: Size { width: length(w), height: length(h) }, flex_shrink: 0.0, ..Default::default() }
}

/// One screen: returns flat nodes with absolute (screen-local) rects.
fn build_screen(fc: &FontCollection, rng: &mut Rng, hue: u32) -> (Vec<Node>, f64) {
    let mut t: TaffyTree<Ctx> = TaffyTree::new();
    let mut paras: Vec<Paragraph> = vec![];
    // (taffy node, kind, radius, color, group)
    let mut meta: Vec<(NodeId, Kind, f32, u32, i32)> = vec![];
    let ink = 0xFF1B1F2A;
    let mut text = |t: &mut TaffyTree<Ctx>, paras: &mut Vec<Paragraph>, meta: &mut Vec<_>, rng: &mut Rng, size: f32, grp: i32, col: u32, abs: bool| {
        let w = WORDS[rng.pick(WORDS.len())];
        let w2 = WORDS[rng.pick(WORDS.len())];
        paras.push(para(fc, &format!("{w} {w2}"), size, col));
        let mut s = Style::default();
        if abs {
            s.flex_shrink = 0.0;
        }
        let n = t.new_leaf_with_context(s, Ctx::Text(paras.len() - 1)).unwrap();
        meta.push((n, Kind::Text, 0.0, col, grp));
        n
    };
    let mut leaf = |t: &mut TaffyTree<Ctx>, meta: &mut Vec<_>, w: f32, h: f32, k: Kind, r: f32, c: u32, g: i32| {
        let n = t.new_leaf(style_fixed(w, h)).unwrap();
        meta.push((n, k, r, c, g));
        n
    };

    // header row: title + subtitle column + 2 icons
    let title = text(&mut t, &mut paras, &mut meta, rng, 22.0, -1, ink, false);
    let sub = text(&mut t, &mut paras, &mut meta, rng, 13.0, -1, 0xFF5A6275, false);
    let i1 = leaf(&mut t, &mut meta, 28.0, 28.0, Kind::Icon, 8.0, color_of(rng, hue), -1);
    let i2 = leaf(&mut t, &mut meta, 28.0, 28.0, Kind::Icon, 8.0, color_of(rng, hue), -1);
    let col = t.new_with_children(Style { flex_direction: FlexDirection::Column, flex_grow: 1.0, ..Default::default() }, &[title, sub]).unwrap();
    let header = t.new_with_children(Style { flex_direction: FlexDirection::Row, align_items: AlignItems::CENTER, gap: Size { width: length(8.0), height: zero() }, ..Default::default() }, &[col, i1, i2]).unwrap();
    meta.push((header, Kind::Frame, 0.0, 0, -2)); // layout-only, skipped at flatten

    let mut kids = vec![header];
    // hero image + glass overlay with label (absolute, bottom of hero)
    let hero = leaf(&mut t, &mut meta, 358.0, 160.0, Kind::Image, 14.0, color_of(rng, hue), -1);
    kids.push(hero);
    // strips: 13 + 14 thumbnails
    for row_i in 0..2 {
        let mut th = vec![];
        for _ in 0..(13 + row_i) {
            th.push(leaf(&mut t, &mut meta, 24.0, 36.0, Kind::Image, 5.0, color_of(rng, hue), -1));
        }
        let row = t.new_with_children(Style { flex_direction: FlexDirection::Row, gap: Size { width: length(4.0), height: zero() }, ..Default::default() }, &th).unwrap();
        meta.push((row, Kind::Frame, 0.0, 0, -2));
        kids.push(row);
    }
    // 10 cards: container(row) + avatar + 3 texts
    for g in 0..10 {
        let av = leaf(&mut t, &mut meta, 32.0, 32.0, Kind::Image, 8.0, color_of(rng, hue), g);
        let a = text(&mut t, &mut paras, &mut meta, rng, 15.0, g, ink, false);
        let b = text(&mut t, &mut paras, &mut meta, rng, 12.0, g, 0xFF6B7385, false);
        let c = text(&mut t, &mut paras, &mut meta, rng, 12.0, g, 0xFF2F6FED, false);
        let mid = t.new_with_children(Style { flex_direction: FlexDirection::Column, flex_grow: 1.0, ..Default::default() }, &[a, b]).unwrap();
        meta.push((mid, Kind::Frame, 0.0, 0, -2));
        let card = t.new_with_children(
            Style { flex_direction: FlexDirection::Row, align_items: AlignItems::CENTER, padding: Rect { left: length(8.0), right: length(8.0), top: length(6.0), bottom: length(6.0) }, gap: Size { width: length(10.0), height: zero() }, ..Default::default() },
            &[av, mid, c],
        ).unwrap();
        meta.push((card, Kind::Card, 12.0, 0xFFF2F4F9, g));
        kids.push(card);
    }
    // glass chip in the middle of the cards (absolute), fab, hero glass, tab bar (+5 icons +5 labels)
    let abs = |l: f32, tp: f32, w: f32, h: f32| Style { position: Position::Absolute, inset: Rect { left: length(l), top: length(tp), right: auto(), bottom: auto() }, size: Size { width: length(w), height: length(h) }, ..Default::default() };
    let chip = t.new_leaf(abs(150.0, 420.0, 190.0, 40.0)).unwrap();
    meta.push((chip, Kind::Glass, 20.0, 0, -1));
    let chip_t = text(&mut t, &mut paras, &mut meta, rng, 13.0, -1, 0xFFFFFFFF, true);
    let chip_wrap = t.new_with_children(Style { position: Position::Absolute, inset: Rect { left: length(170.0), top: length(430.0), right: auto(), bottom: auto() }, ..Default::default() }, &[chip_t]).unwrap();
    meta.push((chip_wrap, Kind::Frame, 0.0, 0, -2));
    let fab = t.new_leaf(abs(310.0, 880.0, 56.0, 56.0)).unwrap();
    meta.push((fab, Kind::Glass, 18.0, 0, -1));
    let fab_t = text(&mut t, &mut paras, &mut meta, rng, 13.0, -1, 0xFFFFFFFF, true);
    let fab_w = t.new_with_children(Style { position: Position::Absolute, inset: Rect { left: length(322.0), top: length(900.0), right: auto(), bottom: auto() }, ..Default::default() }, &[fab_t]).unwrap();
    meta.push((fab_w, Kind::Frame, 0.0, 0, -2));
    let hg = t.new_leaf(abs(24.0, 130.0, 342.0, 46.0)).unwrap();
    meta.push((hg, Kind::Glass, 14.0, 0, -1));
    let hg_t = text(&mut t, &mut paras, &mut meta, rng, 15.0, -1, 0xFFFFFFFF, true);
    let hg_w = t.new_with_children(Style { position: Position::Absolute, inset: Rect { left: length(40.0), top: length(142.0), right: auto(), bottom: auto() }, ..Default::default() }, &[hg_t]).unwrap();
    meta.push((hg_w, Kind::Frame, 0.0, 0, -2));
    let tab = t.new_leaf(abs(16.0, 956.0, 358.0, 68.0)).unwrap();
    meta.push((tab, Kind::Glass, 22.0, 0, -1));
    let mut tabkids = vec![];
    for _ in 0..5 {
        let ic = leaf(&mut t, &mut meta, 22.0, 22.0, Kind::Icon, 7.0, 0xFFFFFFFF, -1);
        let lb = text(&mut t, &mut paras, &mut meta, rng, 10.0, -1, 0xFFFFFFFF, false);
        let c = t.new_with_children(Style { flex_direction: FlexDirection::Column, align_items: AlignItems::CENTER, ..Default::default() }, &[ic, lb]).unwrap();
        meta.push((c, Kind::Frame, 0.0, 0, -2));
        tabkids.push(c);
    }
    let tab_row = t.new_with_children(Style { position: Position::Absolute, inset: Rect { left: length(28.0), top: length(966.0), right: auto(), bottom: auto() }, size: Size { width: length(334.0), height: length(48.0) }, flex_direction: FlexDirection::Row, justify_content: JustifyContent::SPACE_BETWEEN, ..Default::default() }, &tabkids).unwrap();
    meta.push((tab_row, Kind::Frame, 0.0, 0, -2));
    kids.extend([chip, chip_wrap, fab, fab_w, hg, hg_w, tab, tab_row]);

    let root = t.new_with_children(
        Style { flex_direction: FlexDirection::Column, size: Size { width: length(SCREEN_W), height: length(SCREEN_H) }, padding: Rect { left: length(16.0), right: length(16.0), top: length(24.0), bottom: length(16.0) }, gap: Size { width: zero(), height: length(8.0) }, ..Default::default() },
        &kids,
    ).unwrap();

    let t0 = Instant::now();
    t.compute_layout_with_measure(root, Size::MAX_CONTENT, |inputs, _id, ctx, style| {
        taffy::compute_leaf_layout(inputs, style, |_, _| 0.0, |known, _avail| match ctx {
            Some(Ctx::Text(i)) => {
                let p = &paras[*i];
                Size { width: known.width.unwrap_or(p.max_intrinsic_width().ceil()), height: known.height.unwrap_or(p.height().ceil()) }
            }
            None => Size::ZERO,
        })
    })
    .unwrap();
    let layout_ms = t0.elapsed().as_secs_f64() * 1e3;

    // flatten: absolute rects (walk parents)
    let mut nodes = vec![Node { kind: Kind::Frame, rect: SkRect::from_wh(SCREEN_W, SCREEN_H), radius: 0.0, color: 0xFFFFFFFF, group: -1, para: None }];
    fn walk(t: &TaffyTree<Ctx>, n: NodeId, ox: f32, oy: f32, out: &mut Vec<(NodeId, SkRect)>) {
        let l = t.layout(n).unwrap();
        let (x, y) = (ox + l.location.x, oy + l.location.y);
        out.push((n, SkRect::from_xywh(x, y, l.size.width, l.size.height)));
        for c in t.children(n).unwrap() {
            walk(t, c, x, y, out);
        }
    }
    let mut abs_rects = vec![];
    walk(&t, root, 0.0, 0.0, &mut abs_rects);
    let mut paras: Vec<Option<Paragraph>> = paras.into_iter().map(Some).collect();
    for (id, r) in abs_rects {
        if let Some((_, kind, radius, color, group)) = meta.iter().find(|m| m.0 == id) {
            if *group == -2 {
                continue;
            }
            let p = if *kind == Kind::Text {
                if let Some(Ctx::Text(i)) = t.get_node_context(id) { paras[*i].take() } else { None }
            } else {
                None
            };
            nodes.push(Node { kind: *kind, rect: r, radius: *radius, color: *color, group: *group, para: p });
        }
    }
    (nodes, layout_ms)
}

pub fn build(font_path: &str) -> Scene {
    let t0 = Instant::now();
    let fc = font_collection(font_path);
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let hues = [0x3B82F6u32, 0xEC4899, 0x10B981, 0xF59E0B, 0x8B5CF6];
    let mut screens = vec![];
    let mut layout_ms = 0.0;
    for i in 0..COLS * ROWS {
        let (nodes, l) = build_screen(&fc, &mut rng, hues[i % hues.len()]);
        layout_ms += l;
        let (c, r) = (i % COLS, i / COLS);
        screens.push(Screen { origin: Point::new(c as f32 * (SCREEN_W + GAP), r as f32 * (SCREEN_H + GAP)), nodes, pic: None, pic_lod: None, pic_nb: None, pic_bars: None, rerecords: 0 });
    }
    let mut s = Scene { screens, open_ms: 0.0, layout_ms };
    for i in 0..s.screens.len() {
        s.record(i);
    }
    s.open_ms = t0.elapsed().as_secs_f64() * 1e3;
    s
}

fn rr(r: SkRect, rad: f32) -> RRect {
    RRect::new_rect_xy(r, rad, rad)
}

/// mode 0 = full, 1 = no backdrop blur, 2 = LOD (no text, no blur), 3 = text as bars (no blur)
fn draw_nodes(c: &Canvas, nodes: &[Node], mode: u8) {
    let (lod, noblur) = (mode == 2, mode >= 1);
    for n in nodes {
        let mut p = Paint::default();
        p.set_anti_alias(true);
        match n.kind {
            Kind::Frame => {
                p.set_color(Color::new(n.color));
                c.draw_rect(n.rect, &p);
            }
            Kind::Card | Kind::Icon => {
                p.set_color(Color::new(if n.kind == Kind::Icon && n.color == 0xFFFFFFFF { 0x66FFFFFF } else { n.color }));
                c.draw_rrect(rr(n.rect, n.radius), &p);
            }
            Kind::Image => {
                let r = n.rect;
                let c2 = Color::new(n.color).with_a(255);
                let c1 = Color::new(0xFFFFFFFF ^ (n.color & 0x00FFFFFF)).with_a(255);
                let sh = gradient(&[c1, c2], (Point::new(r.left, r.top), Point::new(r.right, r.bottom)));
                p.set_shader(sh);
                c.draw_rrect(rr(r, n.radius), &p);
            }
            Kind::Glass => {
                let shape = rr(n.rect, n.radius);
                c.save();
                c.clip_rrect(shape, None, true);
                if !noblur {
                    let blur = image_filters::blur((18.0, 18.0), TileMode::Clamp, None, None);
                    if let Some(blur) = blur {
                        c.save_layer(&SaveLayerRec::default().bounds(&n.rect).backdrop(&blur));
                        c.restore();
                    }
                }
                p.set_color(Color::from_argb(70, 20, 30, 60));
                c.draw_rrect(shape, &p);
                c.restore();
                let mut rim = Paint::default();
                rim.set_anti_alias(true);
                rim.set_style(PaintStyle::Stroke);
                rim.set_stroke_width(1.0);
                rim.set_color(Color::from_argb(90, 255, 255, 255));
                c.draw_rrect(shape, &rim);
            }
            Kind::Text => {
                if mode == 3 {
                    let mut col = Color::new(n.color);
                    col = col.with_a(140);
                    p.set_color(col);
                    let r = SkRect::from_xywh(n.rect.left, n.rect.top + n.rect.height() * 0.3, n.rect.width(), n.rect.height() * 0.4);
                    c.draw_rrect(rr(r, r.height() / 2.0), &p);
                } else if !lod {
                    if let Some(para) = &n.para {
                        para.paint(c, Point::new(n.rect.left, n.rect.top));
                    }
                }
            }
        }
    }
    let _ = BlurStyle::Normal;
}

fn gradient(colors: &[Color], pts: (Point, Point)) -> Option<skia_safe::Shader> {
    #[allow(deprecated)]
    let r = gradient_shader::linear(pts, colors, None, TileMode::Clamp, None, None);
    r
}

impl Scene {
    pub fn record(&mut self, i: usize) {
        let s = &mut self.screens[i];
        let b = SkRect::from_wh(SCREEN_W, SCREEN_H);
        for mode in 0u8..4 {
            let mut rec = PictureRecorder::new();
            let c = rec.begin_recording(b, true);
            c.clip_rect(b, None, false);
            draw_nodes(c, &s.nodes, mode);
            let pic = rec.finish_recording_as_picture(None);
            match mode { 0 => s.pic = pic, 1 => s.pic_nb = pic, 2 => s.pic_lod = pic, _ => s.pic_bars = pic }
        }
        s.rerecords += 1;
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut n = (0, 0, 0);
        for s in &self.screens {
            n.0 += s.nodes.len();
            n.1 += s.nodes.iter().filter(|x| x.kind == Kind::Text).count();
            n.2 += s.nodes.iter().filter(|x| x.kind == Kind::Glass).count();
        }
        n
    }
}
