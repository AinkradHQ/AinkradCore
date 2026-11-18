//! The renderer: a page's top-level nodes as cached artboards, a camera, level of detail, hit testing, and dirty-region
//! bookkeeping. Single-threaded: it owns Skia objects, so the host keeps it on its render thread.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use design_model::{NodeType, Resolved, ResolvedNode, Theme};
use skia_safe::{Canvas, Color, Paint, Picture, Point, Rect};

use crate::assets::Assets;
use crate::camera::Camera;
use crate::draw::{DrawCx, LODS, Lod, record};
use crate::fonts::Fonts;
use crate::layout::{Laid, build};
use crate::look::{Fill, num};
use crate::overlay::{self, Overlay};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Config {
    /// on-screen artboard width (pt) under which glass drops its live blur
    pub blur_below: f32,
    /// ... under which text is drawn as bars
    pub bars_below: f32,
    /// ... under which text is not drawn
    pub boxes_below: f32,
    /// only artboards at least this wide (world pt) are level-of-detail candidates (a 40 pt icon keeps its text)
    pub lod_min_world_w: f32,
    /// soft cap on recorded pictures; pictures of off-screen artboards are dropped first
    pub picture_cap: usize,
    /// live backdrop blurs per frame: the artboards with the most area in view keep theirs (the first always does),
    /// the rest draw flat glass. Each blur breaks the GPU pass (the T5 fallback, applied per frame).
    pub max_live_blurs: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            blur_below: 250.0,
            bars_below: 150.0,
            boxes_below: 60.0,
            lod_min_world_w: 200.0,
            picture_cap: 256 * 1024 * 1024,
            max_live_blurs: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Dirty {
    Clean,
    /// world rectangle that changed
    Rect(Rect),
    All,
}

impl Dirty {
    fn add(self, r: Rect) -> Dirty {
        match self {
            Dirty::Clean => Dirty::Rect(r),
            Dirty::Rect(a) => Dirty::Rect(Rect::new(
                a.left.min(r.left),
                a.top.min(r.top),
                a.right.max(r.right),
                a.bottom.max(r.bottom),
            )),
            Dirty::All => Dirty::All,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub layouts: u64,
    pub pictures_recorded: u64,
}

pub(crate) struct Board {
    pub(crate) id: String,
    hash: u64,
    fonts_epoch: u64,
    pub(crate) origin: Point,
    pub(crate) laid: Laid,
    pub(crate) index: HashMap<String, u32>,
    pics: [Option<Picture>; LODS],
    last_used: u64,
}

impl Board {
    fn world_bounds(&self) -> Rect {
        self.laid.bounds.with_offset(self.origin)
    }
}

pub struct Renderer {
    pub fonts: Fonts,
    pub assets: Assets,
    pub cfg: Config,
    pub camera: Camera,
    pub stats: Stats,
    theme: Theme,
    pub(crate) boards: Vec<Board>,
    background: Color,
    dirty: Dirty,
    frame: u64,
    assets_epoch: u64,
    shadows: crate::draw::ShadowCache,
    order: Vec<String>,
    /// asset hashes the last frames wanted and did not have (deduplicated)
    pub missing: Vec<String>,
    overlay: Overlay,
}

fn hash_of(n: &ResolvedNode) -> u64 {
    let mut h = DefaultHasher::new();
    serde_json::to_vec(n).unwrap_or_default().hash(&mut h);
    h.finish()
}

fn page_background(page: &ResolvedNode, theme: Theme) -> Color {
    match crate::look::Look::of(page).fills.first() {
        Some(Fill::Solid(c)) => *c,
        _ if theme == Theme::Day => Color::new(0xFFE9_ECF2),
        _ => Color::new(0xFF16_171B),
    }
}

impl Renderer {
    pub fn new(fonts: Fonts, assets: Assets) -> Renderer {
        let assets_epoch = assets.epoch;
        Renderer {
            fonts,
            assets,
            cfg: Config::default(),
            camera: Camera::default(),
            stats: Stats::default(),
            theme: Theme::Day,
            boards: vec![],
            background: Color::WHITE,
            dirty: Dirty::All,
            frame: 0,
            assets_epoch,
            shadows: Default::default(),
            order: vec![],
            missing: vec![],
            overlay: Overlay::default(),
        }
    }

    fn build_board(&mut self, n: &ResolvedNode) -> Board {
        self.stats.layouts += 1;
        let laid = build(n, &self.fonts, self.theme);
        self.missing_fonts(n);
        let index = laid
            .nodes
            .iter()
            .enumerate()
            .map(|(i, x)| (x.id.clone(), i as u32))
            .collect();
        Board {
            id: n.id.clone(),
            hash: hash_of(n),
            fonts_epoch: self.fonts.epoch,
            origin: Point::new(
                num(&n.props, "x").unwrap_or(0.0),
                num(&n.props, "y").unwrap_or(0.0),
            ),
            laid,
            index,
            pics: Default::default(),
            last_used: 0,
        }
    }

    /// Library fonts the board names and the host has not supplied: they join `missing` (the host fetches them by
    /// hash like images and hands them over with `add_font`; the text draws with the fallback until then).
    fn missing_fonts(&mut self, n: &ResolvedNode) {
        let mut stack = vec![n];
        while let Some(n) = stack.pop() {
            if let Some(a) = n
                .props
                .get("type")
                .and_then(|t| t.get("font"))
                .and_then(|f| f.get("asset"))
                .and_then(serde_json::Value::as_str)
                && !self.fonts.has_asset(a)
                && !self.missing.iter().any(|m| m == a)
            {
                self.missing.push(a.to_string());
            }
            stack.extend(n.children.iter());
        }
    }

    /// Show page `page` of `r`. Only top-level nodes whose resolved content changed are laid out again; everything
    /// else keeps its layout and its recorded pictures. Returns what to redraw.
    pub fn load(&mut self, r: &Resolved, page: usize) -> Dirty {
        let Some(pg) = r.pages.get(page) else {
            self.boards.clear();
            self.dirty = Dirty::All;
            return self.dirty;
        };
        let all = r.theme != self.theme;
        self.theme = r.theme;
        self.background = page_background(pg, r.theme);
        let roots: Vec<&ResolvedNode> = pg.children.iter().collect();
        let epoch = self.fonts.epoch;
        self.load_roots(&roots, all, |b, c| {
            b.hash == hash_of(c) && b.fonts_epoch == epoch
        })
    }

    /// A gesture preview (V2-03): the page's top-level nodes in order, of which only `changed` are laid out again;
    /// every other board is kept as is, without hashing its content (a drag frame stays within budget).
    pub fn load_patch(&mut self, roots: &[&ResolvedNode], changed: &HashSet<String>) -> Dirty {
        let epoch = self.fonts.epoch;
        self.load_roots(roots, false, |b, c| {
            !changed.contains(&c.id) && b.fonts_epoch == epoch
        })
    }

    fn load_roots(
        &mut self,
        roots: &[&ResolvedNode],
        all: bool,
        keep: impl Fn(&Board, &ResolvedNode) -> bool,
    ) -> Dirty {
        let mut old: HashMap<String, Board> = std::mem::take(&mut self.boards)
            .into_iter()
            .map(|b| (b.id.clone(), b))
            .collect();
        let before: Vec<String> = roots.iter().map(|c| c.id.clone()).collect();
        let mut d = if all { Dirty::All } else { Dirty::Clean };
        let mut boards = Vec::with_capacity(before.len());
        for c in roots {
            let ob = old.remove(&c.id);
            let prev = ob.as_ref().map(Board::world_bounds);
            match ob.filter(|b| !all && keep(b, c)) {
                Some(b) => boards.push(b),
                None => {
                    let b = self.build_board(c);
                    d = d.add(b.world_bounds());
                    if let Some(p) = prev {
                        d = d.add(p);
                    }
                    boards.push(b);
                }
            }
        }
        // boards that did not come back (deleted, or replaced above and still in `old`)
        for (_, b) in old {
            d = d.add(b.world_bounds());
        }
        if before != self.order {
            d = Dirty::All;
        }
        self.order = before;
        self.boards = boards;
        self.mark(d);
        d
    }

    fn mark(&mut self, d: Dirty) {
        self.dirty = match (self.dirty, d) {
            (Dirty::All, _) | (_, Dirty::All) => Dirty::All,
            (a, Dirty::Rect(r)) => a.add(r),
            (a, Dirty::Clean) => a,
        };
    }

    pub fn dirty(&self) -> Dirty {
        self.dirty
    }

    /// Anything to draw? A still canvas with no pending change draws zero frames.
    pub fn needs_frame(&mut self) -> bool {
        self.sync_epochs();
        self.dirty != Dirty::Clean
    }

    /// The host changed fonts or assets: fonts re-lay-out (on the next `load`), assets re-record.
    fn sync_epochs(&mut self) {
        if self.assets.epoch != self.assets_epoch {
            self.assets_epoch = self.assets.epoch;
            for b in &mut self.boards {
                b.pics = Default::default();
            }
            self.dirty = Dirty::All;
        }
    }

    /// Selection, hover, marquee and guides (V2-03). A change redraws the frame; the same overlay does not.
    pub fn set_overlay(&mut self, o: Overlay) {
        if o != self.overlay {
            self.overlay = o;
            self.dirty = Dirty::All;
        }
    }

    pub fn overlay(&self) -> &Overlay {
        &self.overlay
    }

    pub fn set_camera(&mut self, c: Camera) {
        if c != self.camera {
            self.camera = c;
            self.dirty = Dirty::All;
        }
    }

    pub fn world_bounds(&self) -> Option<Rect> {
        self.boards.iter().map(Board::world_bounds).reduce(|a, b| {
            Rect::new(
                a.left.min(b.left),
                a.top.min(b.top),
                a.right.max(b.right),
                a.bottom.max(b.bottom),
            )
        })
    }

    pub fn invalidate_all(&mut self) {
        self.dirty = Dirty::All;
    }

    pub fn node_count(&self) -> usize {
        self.boards.iter().map(|b| b.laid.nodes.len()).sum()
    }

    /// Each artboard's world origin and layout, in page order (runner `design.measure` and `design.review`).
    pub fn boards(&self) -> impl Iterator<Item = (Point, &Laid)> {
        self.boards.iter().map(|b| (b.origin, &b.laid))
    }

    /// Absolute world rectangle of a node (resolved id).
    pub fn node_rect(&self, id: &str) -> Option<Rect> {
        self.boards.iter().find_map(|b| {
            let i = *b.index.get(id)?;
            Some(b.laid.nodes[i as usize].rect.with_offset(b.origin))
        })
    }

    /// The level of detail an artboard is drawn at under the current camera (live-blur budget included).
    pub fn lod_of(&self, id: &str) -> Option<Lod> {
        let i = self.boards.iter().position(|b| b.id == id)?;
        if self.demoted(self.camera.visible()).contains(&i) {
            return Some(Lod::NoBlur);
        }
        Some(self.lod_for(&self.boards[i]))
    }

    fn lod_for(&self, b: &Board) -> Lod {
        let root = &b.laid.nodes[0];
        let w = root.rect.width();
        let frameish = matches!(
            root.ty,
            NodeType::Frame | NodeType::Component | NodeType::Instance
        );
        if !frameish || w < self.cfg.lod_min_world_w {
            return Lod::Full;
        }
        let on = w * self.camera.zoom;
        if on < self.cfg.boxes_below {
            Lod::Boxes
        } else if on < self.cfg.bars_below {
            Lod::Bars
        } else if on < self.cfg.blur_below {
            Lod::NoBlur
        } else {
            Lod::Full
        }
    }

    /// Draw the current view. With `partial` and a pending `Dirty::Rect`, only that region is cleared and redrawn
    /// (the host must keep the previous frame's pixels for the rest). Clears the dirty state.
    pub fn draw(&mut self, canvas: &Canvas, partial: bool) {
        self.sync_epochs();
        self.frame += 1;
        let cam = self.camera;
        canvas.save();
        canvas.scale((cam.scale, cam.scale));
        let mut vis = cam.visible();
        // an overlay sits over everything: a partial redraw would draw its strokes twice over kept pixels
        let partial = partial && self.overlay.is_empty();
        if let (true, Dirty::Rect(r)) = (partial, self.dirty) {
            let (x0, y0) = cam.to_screen(r.left, r.top);
            let (x1, y1) = cam.to_screen(r.right, r.bottom);
            let clip = Rect::new(x0.floor(), y0.floor(), x1.ceil(), y1.ceil());
            canvas.clip_rect(clip, None, false);
            vis = Rect::new(r.left, r.top, r.right, r.bottom);
        }
        canvas.clear(self.background);
        canvas.translate(cam.pan);
        canvas.scale((cam.zoom, cam.zoom));
        let demoted = self.demoted(vis);
        for bi in 0..self.boards.len() {
            let wb = self.boards[bi].world_bounds();
            if !Rect::intersects(&wb, vis) {
                continue;
            }
            let lod = if demoted.contains(&bi) {
                Lod::NoBlur
            } else {
                self.lod_for(&self.boards[bi])
            };
            self.boards[bi].last_used = self.frame;
            if self.boards[bi].pics[lod as usize].is_none() {
                let mut miss = vec![];
                let pic = {
                    let mut cx = DrawCx {
                        assets: &mut self.assets,
                        theme: self.theme,
                        missing: &mut miss,
                        shadows: &mut self.shadows,
                    };
                    record(&self.boards[bi].laid, lod, &mut cx)
                };
                self.stats.pictures_recorded += 1;
                for m in miss {
                    if !self.missing.contains(&m) {
                        self.missing.push(m);
                    }
                }
                self.boards[bi].pics[lod as usize] = pic;
            }
            if let Some(p) = &self.boards[bi].pics[lod as usize] {
                canvas.save();
                canvas.translate(self.boards[bi].origin);
                canvas.draw_picture(p, None, None::<&Paint>);
                canvas.restore();
            }
        }
        canvas.restore();
        if !self.overlay.is_empty() {
            canvas.save();
            canvas.scale((cam.scale, cam.scale));
            overlay::draw(canvas, &cam, &self.overlay);
            canvas.restore();
        }
        self.dirty = Dirty::Clean;
        self.trim();
    }

    /// Artboards in view that want live blur but are over the per-frame budget.
    fn demoted(&self, vis: Rect) -> Vec<usize> {
        let mut want: Vec<(usize, f32)> = vec![];
        for (i, b) in self.boards.iter().enumerate() {
            let w = b.world_bounds();
            if b.laid.glass > 0 && Rect::intersects(&w, vis) && self.lod_for(b) == Lod::Full {
                let (dx, dy) = (
                    w.right.min(vis.right) - w.left.max(vis.left),
                    w.bottom.min(vis.bottom) - w.top.max(vis.top),
                );
                want.push((i, dx * dy));
            }
        }
        want.sort_by(|a, b| b.1.total_cmp(&a.1));
        let (mut used, mut out) = (0, vec![]);
        for (i, _) in want {
            let g = self.boards[i].laid.glass;
            if used == 0 || used + g <= self.cfg.max_live_blurs {
                used += g;
            } else {
                out.push(i);
            }
        }
        out
    }

    /// Bytes held by recorded pictures.
    pub fn picture_bytes(&self) -> usize {
        self.boards
            .iter()
            .flat_map(|b| b.pics.iter().flatten())
            .map(Picture::approximate_bytes_used)
            .sum()
    }

    /// Drop pictures of artboards not drawn lately until under the cap (oldest first).
    pub fn trim(&mut self) {
        let mut total = self.picture_bytes();
        if total <= self.cfg.picture_cap {
            return;
        }
        let mut idx: Vec<usize> = (0..self.boards.len()).collect();
        idx.sort_by_key(|i| self.boards[*i].last_used);
        for i in idx {
            if total <= self.cfg.picture_cap || self.boards[i].last_used == self.frame {
                break;
            }
            let freed: usize = self.boards[i]
                .pics
                .iter()
                .flatten()
                .map(Picture::approximate_bytes_used)
                .sum();
            self.boards[i].pics = Default::default();
            total -= freed;
        }
    }
}
