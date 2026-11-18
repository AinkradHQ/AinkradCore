//! Text-editing geometry (V2-04): caret, selection and hit positions on a laid-out Skia paragraph. Offsets are
//! UTF-16 code units (Skia paragraph's public offsets, and `NSTextInputClient`'s); the caller passes grapheme
//! boundaries only (it owns the string). Rects are in world coordinates.

use skia_safe::textlayout::{Paragraph, RectHeightStyle, RectWidthStyle, TextDirection};
use skia_safe::{Point, Rect};

use crate::scene::Renderer;

pub struct TextGeo<'a> {
    para: &'a Paragraph,
    /// world top-left of the text box
    at: Point,
}

impl Renderer {
    /// The laid-out paragraph of text node `id` (a resolved id), if it is on the current page.
    pub fn text_geo(&self, id: &str) -> Option<TextGeo<'_>> {
        self.boards.iter().find_map(|b| {
            let n = &b.laid.nodes[*b.index.get(id)? as usize];
            Some(TextGeo {
                para: n.para.as_ref()?,
                at: Point::new(b.origin.x + n.rect.left, b.origin.y + n.rect.top),
            })
        })
    }
}

impl TextGeo<'_> {
    fn world(&self, r: Rect) -> Rect {
        r.with_offset(self.at)
    }

    fn boxes(&self, a: usize, b: usize) -> Vec<(Rect, TextDirection)> {
        self.para
            .get_rects_for_range(a..b, RectHeightStyle::Max, RectWidthStyle::Tight)
            .into_iter()
            .map(|t| (self.world(t.rect), t.direct))
            .collect()
    }

    /// Selection (or marked-text) highlight rects for `a..b`, one per line run.
    pub fn ranges(&self, a: usize, b: usize) -> Vec<Rect> {
        if a >= b {
            return vec![];
        }
        self.boxes(a, b).into_iter().map(|(r, _)| r).collect()
    }

    /// The caret at `off` as a zero-width world rect (top to bottom of its line). `prev` / `next` = the grapheme
    /// boundaries before and after it (equal to `off` at the ends); `after_newline` = the text before it ends a line.
    pub fn caret(&self, prev: usize, off: usize, next: usize, after_newline: bool) -> Rect {
        let edge = |r: Rect, x: f32| Rect::new(x, r.top, x, r.bottom);
        // the character after the caret places it on its own line; at the end, the one before it does
        // ponytail: an empty line in the middle (a newline after a newline) relies on Skia boxing the newline
        if next > off
            && let Some((r, d)) = self.boxes(off, next).first().copied()
        {
            return edge(
                r,
                if d == TextDirection::RTL {
                    r.right
                } else {
                    r.left
                },
            );
        }
        if prev < off
            && !after_newline
            && let Some((r, d)) = self.boxes(prev, off).last().copied()
        {
            return edge(
                r,
                if d == TextDirection::RTL {
                    r.left
                } else {
                    r.right
                },
            );
        }
        // an empty text, or the empty line after a final newline: that line's start
        let lines = self.para.get_line_metrics();
        match lines.last() {
            Some(l) => {
                let top = (l.baseline - l.ascent) as f32;
                let x = l.left as f32;
                self.world(Rect::new(x, top, x, top + l.height as f32))
            }
            None => self.world(Rect::new(0.0, 0.0, 0.0, self.para.height())),
        }
    }

    /// The UTF-16 offset nearest world point (x, y) (the caller snaps it to a grapheme boundary).
    pub fn index_at(&self, x: f32, y: f32) -> usize {
        let p = self
            .para
            .get_glyph_position_at_coordinate((x - self.at.x, y - self.at.y));
        p.position.max(0) as usize
    }

    /// The first line's part of `a..b` (the caret for an empty range): where the IME puts its candidate window.
    pub fn first_rect(&self, prev: usize, a: usize, b: usize, after_newline: bool) -> Rect {
        let bx = self.ranges(a, b);
        match bx.first() {
            Some(f) => bx
                .iter()
                .filter(|r| (r.top - f.top).abs() < 0.5)
                .fold(*f, |u, r| {
                    Rect::new(u.left.min(r.left), u.top, u.right.max(r.right), u.bottom)
                }),
            None => self.caret(prev, a, a, after_newline),
        }
    }
}
