//! The canvas overlay (V2-03): hover and selection outlines, the selection bounds with its resize handles, the
//! marquee and snap guides. World coordinates in, drawn in screen points on top of the artboards in the same frame,
//! so a drag and its outline never drift apart. Handles are small rounded rects (no circles).

use skia_safe::{Canvas, Color, Font, FontMgr, FontStyle, Paint, PaintStyle, RRect, Rect};

use crate::camera::Camera;

const ACCENT: Color = Color::new(0xFF0A_84FF);
const GUIDE: Color = Color::new(0xFFFF_375F);
/// Handle size in points.
pub const HANDLE: f32 = 7.0;

/// Marker colours for other people and AI sessions (a peer keeps one by its slot).
const PEER_COLORS: [u32; 6] = [
    0xFF8B_5CF6,
    0xFF14_B8A6,
    0xFFF9_7316,
    0xFFEC_4899,
    0xFF84_CC16,
    0xFF06_B6D4,
];

/// Another device's or AI session's cursor and selection (V2-06). World coordinates.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PeerMark {
    pub label: String,
    /// An AI session: its chip carries a small square mark.
    pub ai: bool,
    /// Index into the marker colours (taken modulo their count).
    pub slot: usize,
    pub cursor: Option<(f32, f32)>,
    pub selected: Vec<Rect>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overlay {
    /// Other peers, drawn under the local selection.
    pub peers: Vec<PeerMark>,
    pub hover: Option<Rect>,
    pub selected: Vec<Rect>,
    /// Bounds of the selection; drawn with its eight resize handles.
    pub bounds: Option<Rect>,
    pub marquee: Option<Rect>,
    /// Guide segments `[x1, y1, x2, y2]`.
    pub guides: Vec<[f32; 4]>,
    /// Text editing (V2-04), world rects: the caret (zero width), the selected text, the IME's marked text.
    pub caret: Option<Rect>,
    pub text_selection: Vec<Rect>,
    pub marked: Vec<Rect>,
}

impl Overlay {
    pub fn is_empty(&self) -> bool {
        *self == Overlay::default()
    }
}

/// The eight handle centres of `r` (screen or world): nw, n, ne, e, se, s, sw, w.
pub fn handles(r: Rect) -> [(f32, f32); 8] {
    let (cx, cy) = (r.center_x(), r.center_y());
    [
        (r.left, r.top),
        (cx, r.top),
        (r.right, r.top),
        (r.right, cy),
        (r.right, r.bottom),
        (cx, r.bottom),
        (r.left, r.bottom),
        (r.left, cy),
    ]
}

fn screen(cam: &Camera, r: Rect) -> Rect {
    let (l, t) = cam.to_screen(r.left, r.top);
    let (rr, b) = cam.to_screen(r.right, r.bottom);
    Rect::new(l, t, rr, b)
}

/// Draw in screen points (the canvas is already scaled to the backing scale).
pub fn draw(canvas: &Canvas, cam: &Camera, o: &Overlay) {
    for p in &o.peers {
        draw_peer(canvas, cam, p);
    }
    let mut line = Paint::default();
    line.set_anti_alias(true);
    line.set_style(PaintStyle::Stroke);
    line.set_stroke_width(1.0);
    line.set_color(ACCENT);
    if let Some(h) = o.hover {
        canvas.draw_rect(screen(cam, h), &line);
    }
    for r in &o.selected {
        canvas.draw_rect(screen(cam, *r), &line);
    }
    if let Some(m) = o.marquee {
        let r = screen(cam, m);
        let mut fill = Paint::default();
        fill.set_color(ACCENT.with_a(0x1A));
        canvas.draw_rect(r, &fill);
        canvas.draw_rect(r, &line);
    }
    if let Some(b) = o.bounds {
        let r = screen(cam, b);
        canvas.draw_rect(r, &line);
        let mut fill = Paint::default();
        fill.set_anti_alias(true);
        fill.set_color(Color::WHITE);
        for (x, y) in handles(r) {
            let h = RRect::new_rect_xy(
                Rect::from_xywh(x - HANDLE / 2.0, y - HANDLE / 2.0, HANDLE, HANDLE),
                1.5,
                1.5,
            );
            canvas.draw_rrect(h, &fill);
            canvas.draw_rrect(h, &line);
        }
    }
    let mut fill = Paint::default();
    fill.set_anti_alias(true);
    fill.set_color(ACCENT.with_a(0x48));
    for r in &o.text_selection {
        canvas.draw_rect(screen(cam, *r), &fill);
    }
    fill.set_color(ACCENT);
    for r in &o.marked {
        let r = screen(cam, *r);
        canvas.draw_rect(Rect::new(r.left, r.bottom - 1.0, r.right, r.bottom), &fill);
    }
    if let Some(c) = o.caret {
        let r = screen(cam, c);
        canvas.draw_rect(
            Rect::new(r.left - 0.75, r.top, r.left + 0.75, r.bottom),
            &fill,
        );
    }
    line.set_color(GUIDE);
    for g in &o.guides {
        let (x1, y1) = cam.to_screen(g[0], g[1]);
        let (x2, y2) = cam.to_screen(g[2], g[3]);
        canvas.draw_line((x1, y1), (x2, y2), &line);
    }
}

/// Outlines drawn per peer; the full selection stays in the peer list.
pub const MAX_PEER_OUTLINES: usize = 32;

thread_local! {
    /// The chip font, built once per thread (the default typeface lookup is not free).
    static CHIP_FONT: Option<Font> = FontMgr::new()
        .legacy_make_typeface(None, FontStyle::default())
        .map(|t| Font::from_typeface(t, 11.0));
}

/// Screen rects of a peer's selection that touch `clip` (all when unknown), at most [`MAX_PEER_OUTLINES`].
fn visible_outlines(sel: &[Rect], cam: &Camera, clip: Option<Rect>) -> Vec<Rect> {
    sel.iter()
        .map(|r| screen(cam, *r))
        .filter(|r| clip.is_none_or(|c| c.intersects(r)))
        .take(MAX_PEER_OUTLINES)
        .collect()
}

/// Rounded-rect markers only: an outline per selected node, a small rounded square at the cursor and a rounded chip
/// with the label beside it.
fn draw_peer(canvas: &Canvas, cam: &Camera, p: &PeerMark) {
    let c = Color::new(PEER_COLORS[p.slot % PEER_COLORS.len()]);
    let mut line = Paint::default();
    line.set_anti_alias(true);
    line.set_style(PaintStyle::Stroke);
    line.set_stroke_width(1.5);
    line.set_color(c);
    for r in visible_outlines(&p.selected, cam, canvas.local_clip_bounds()) {
        canvas.draw_rrect(RRect::new_rect_xy(r, 2.0, 2.0), &line);
    }
    let Some((wx, wy)) = p.cursor else { return };
    let (x, y) = cam.to_screen(wx, wy);
    let mut fill = Paint::default();
    fill.set_anti_alias(true);
    fill.set_color(c);
    canvas.draw_rrect(
        RRect::new_rect_xy(Rect::from_xywh(x - 3.0, y - 3.0, 7.0, 7.0), 2.0, 2.0),
        &fill,
    );
    let font = CHIP_FONT.with(|f| f.clone());
    let (w, h, pad) = match &font {
        Some(f) => (f.measure_str(&p.label, None).0, 16.0, 6.0),
        None => (0.0, 16.0, 6.0),
    };
    let mark = if p.ai { 10.0 } else { 0.0 };
    let chip = Rect::from_xywh(x + 8.0, y + 8.0, w + 2.0 * pad + mark, h);
    canvas.draw_rrect(RRect::new_rect_xy(chip, 4.0, 4.0), &fill);
    let mut ink = Paint::default();
    ink.set_anti_alias(true);
    ink.set_color(Color::WHITE);
    if p.ai {
        canvas.draw_rrect(
            RRect::new_rect_xy(
                Rect::from_xywh(chip.left + pad, chip.top + 5.0, 6.0, 6.0),
                1.5,
                1.5,
            ),
            &ink,
        );
    }
    if let Some(f) = &font {
        canvas.draw_str(&p.label, (chip.left + pad + mark, chip.top + 11.5), f, &ink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_outlines_skip_off_screen_and_cap() {
        let cam = Camera::default();
        let clip = Some(Rect::from_xywh(0.0, 0.0, 100.0, 100.0));
        let on = Rect::from_xywh(10.0, 10.0, 5.0, 5.0);
        let off = Rect::from_xywh(5000.0, 5000.0, 5.0, 5.0);
        assert_eq!(visible_outlines(&[off, on, off], &cam, clip).len(), 1);
        let many = vec![on; MAX_PEER_OUTLINES + 20];
        assert_eq!(visible_outlines(&many, &cam, clip).len(), MAX_PEER_OUTLINES);
        assert_eq!(
            visible_outlines(&[off], &cam, None).len(),
            1,
            "no clip, no culling"
        );
    }
}
