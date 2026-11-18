//! The canvas overlay (V2-03): hover and selection outlines, the selection bounds with its resize handles, the
//! marquee and snap guides. World coordinates in, drawn in screen points on top of the artboards in the same frame,
//! so a drag and its outline never drift apart. Handles are small rounded rects (no circles).

use skia_safe::{Canvas, Color, Paint, PaintStyle, RRect, Rect};

use crate::camera::Camera;

const ACCENT: Color = Color::new(0xFF0A_84FF);
const GUIDE: Color = Color::new(0xFFFF_375F);
/// Handle size in points.
pub const HANDLE: f32 = 7.0;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overlay {
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
