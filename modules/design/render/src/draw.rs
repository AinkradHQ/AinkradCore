//! Draw: one laid-out artboard -> an `SkPicture` for a level of detail. Pictures hold glyph runs, not pixels, so text
//! stays sharp at any zoom the picture is replayed at (and on Metal, distance-field text, see `metal`).

use std::collections::HashMap;

use design_model::{NodeType, Theme};
use skia_safe::{
    AlphaType, BlendMode, BlurStyle, Canvas, Color, Color4f, ColorType, FilterMode, IRect, Image,
    ImageInfo, MaskFilter, MipmapMode, Paint, PaintStyle, Path, PathEffect, PathFillType, Picture,
    PictureRecorder, Point, RRect, Rect, SamplingOptions, TileMode,
    canvas::SaveLayerRec,
    gradient::{self, Colors, Gradient, Interpolation},
    image_filters,
};

use crate::assets::Assets;
use crate::layout::{LNode, Laid, text_color};
use crate::look::{Align, Fill, Fit, Look, Material};

/// What a picture contains. Chosen per artboard from its on-screen width (spike adjustments 1 and 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lod {
    /// everything, live backdrop blur included
    Full = 0,
    /// glass is a flat tint: no live blur (screens drawn under 250 pt)
    NoBlur = 1,
    /// text as bars (under 150 pt)
    Bars = 2,
    /// no text at all (under 60 pt)
    Boxes = 3,
}

pub const LODS: usize = 4;

pub struct DrawCx<'a> {
    pub assets: &'a mut Assets,
    pub theme: Theme,
    /// asset hashes that were wanted and not available
    pub missing: &'a mut Vec<String>,
    pub shadows: &'a mut ShadowCache,
}

/// Blurred rounded-rect masks by (sigma, radius), shared by every shadow with that look (any colour, any size).
pub type ShadowCache = HashMap<(u32, u32), Option<Image>>;

/// Resolution of a cached shadow mask relative to points.
const SHADOW_RES: f32 = 2.0;

fn shadow_mask(cache: &mut ShadowCache, sigma: f32, r: f32) -> Option<(Image, i32, i32)> {
    let pad = (3.0 * sigma * SHADOW_RES).ceil() as i32;
    let rp = (r * SHADOW_RES).ceil() as i32;
    let img = cache
        .entry((sigma.to_bits(), r.to_bits()))
        .or_insert_with(|| {
            let core = 2 * rp + 4;
            let side = core + 2 * pad;
            let mut s = skia_safe::surfaces::raster(
                &ImageInfo::new((side, side), ColorType::N32, AlphaType::Premul, None),
                None,
                None,
            )?;
            let mut p = paint(Color::BLACK);
            p.set_mask_filter(MaskFilter::blur(
                BlurStyle::Normal,
                sigma * SHADOW_RES,
                true,
            ));
            let rect = Rect::from_xywh(pad as f32, pad as f32, core as f32, core as f32);
            s.canvas()
                .draw_rrect(RRect::new_rect_xy(rect, rp as f32, rp as f32), &p);
            Some(s.image_snapshot())
        })
        .clone()?;
    Some((img, pad, rp))
}

/// One shadow. A rounded rect big enough for a nine-patch draws from the cached mask (a handful of quads, no
/// per-frame blur: 500 live blurs cost 4x a whole screen of content on Metal); anything else blurs live.
fn draw_shadow(c: &Canvas, n: &LNode, s: &crate::look::Shadow, cx: &mut DrawCx) {
    let sh = {
        let mut sh = shape(n, s.spread);
        sh.offset((s.x, s.y));
        sh
    };
    let rect = *sh.rect();
    let sigma = s.blur / 2.0;
    let r = n.look.radius.iter().cloned().fold(0.0f32, f32::max) + s.spread.max(0.0);
    let fits = s.blur > 0.0
        && n.ty != NodeType::Ellipse
        && rect.width() >= 2.0 * r + 2.0
        && rect.height() >= 2.0 * r + 2.0;
    if fits && let Some((img, pad, rp)) = shadow_mask(cx.shadows, sigma, r) {
        let core = 2 * rp + 4;
        let center = IRect::new(pad + rp, pad + rp, pad + core - rp, pad + core - rp);
        let mut dst = rect;
        let o = pad as f32 / SHADOW_RES;
        dst.outset((o, o));
        let mut p = Paint::default();
        p.set_color_filter(skia_safe::color_filters::blend(s.color, BlendMode::SrcIn));
        c.draw_image_nine(img, center, dst, FilterMode::Linear, Some(&p));
        return;
    }
    let mut p = paint(s.color);
    if s.blur > 0.0 {
        p.set_mask_filter(MaskFilter::blur(BlurStyle::Normal, sigma, true));
    }
    c.draw_rrect(sh, &p);
}

fn shape(n: &LNode, grow: f32) -> RRect {
    let mut r = n.rect;
    r.outset((grow, grow));
    if n.ty == NodeType::Ellipse {
        return RRect::new_oval(r);
    }
    let q = n.look.radius.map(|v| (v + grow).max(0.0));
    RRect::new_rect_radii(
        r,
        &[
            Point::new(q[0], q[0]),
            Point::new(q[1], q[1]),
            Point::new(q[2], q[2]),
            Point::new(q[3], q[3]),
        ],
    )
}

fn paint(c: Color) -> Paint {
    let mut p = Paint::default();
    p.set_anti_alias(true);
    p.set_color(c);
    p
}

fn linear(angle: f32, stops: &[(f32, Color)], r: Rect) -> Option<skia_safe::Shader> {
    let a = angle.to_radians();
    let d = Point::new(a.sin(), -a.cos());
    let len = (r.width() * d.x).abs() + (r.height() * d.y).abs();
    let c = Point::new(r.center_x(), r.center_y());
    let (p0, p1) = (
        Point::new(c.x - d.x * len / 2.0, c.y - d.y * len / 2.0),
        Point::new(c.x + d.x * len / 2.0, c.y + d.y * len / 2.0),
    );
    linear_gradient((p0, p1), stops)
}

/// A clamped linear gradient shader between two points.
pub fn linear_gradient(pts: (Point, Point), stops: &[(f32, Color)]) -> Option<skia_safe::Shader> {
    let colors: Vec<Color4f> = stops.iter().map(|s| Color4f::from(s.1)).collect();
    let pos: Vec<f32> = stops.iter().map(|s| s.0).collect();
    let g = Gradient::new(
        Colors::new(&colors, Some(&pos), TileMode::Clamp, None),
        Interpolation::default(),
    );
    gradient::shaders::linear_gradient(pts, &g, None)
}

fn sampling() -> SamplingOptions {
    SamplingOptions::new(FilterMode::Linear, MipmapMode::Linear)
}

/// One shaded rounded-rect draw per image (no clip, so a screen of thumbnails batches): the image is a shader placed by
/// `fit`; outside the image (contain) the shader is transparent.
fn draw_image(c: &Canvas, img: &Image, fit: Fit, rr: &RRect) {
    let dst = *rr.rect();
    let (iw, ih) = (img.width() as f32, img.height() as f32);
    let (k, mode) = match fit {
        Fit::Cover => ((dst.width() / iw).max(dst.height() / ih), TileMode::Decal),
        Fit::Contain => ((dst.width() / iw).min(dst.height() / ih), TileMode::Decal),
        Fit::Tile => (1.0, TileMode::Repeat),
    };
    let (tx, ty) = match fit {
        Fit::Tile => (dst.left, dst.top),
        _ => (
            dst.left + (dst.width() - iw * k) / 2.0,
            dst.top + (dst.height() - ih * k) / 2.0,
        ),
    };
    let mut m = skia_safe::Matrix::translate((tx, ty));
    m.pre_scale((k, k), None);
    let mut p = Paint::default();
    p.set_anti_alias(true);
    p.set_shader(img.to_shader((mode, mode), sampling(), Some(&m)));
    c.draw_rrect(rr, &p);
}

fn vector_path(n: &LNode) -> Option<Path> {
    n.look
        .path
        .as_ref()
        .map(|p| p.with_offset((n.rect.left, n.rect.top)))
}

fn draw_fill(c: &Canvas, n: &LNode, f: &Fill, rr: &RRect, cx: &mut DrawCx) {
    let mut p = Paint::default();
    p.set_anti_alias(true);
    match f {
        Fill::Solid(col) => {
            p.set_color(*col);
        }
        Fill::Linear(a, s) => {
            p.set_shader(linear(*a, s, n.rect));
        }
        Fill::Image(a, fit) => {
            match cx.assets.image(a) {
                Some(img) => draw_image(c, &img, *fit, rr),
                None => cx.missing.push(a.clone()),
            }
            return;
        }
    }
    if n.ty == NodeType::Vector {
        if let Some(path) = vector_path(n) {
            c.draw_path(&path, &p);
        }
    } else if n.ty == NodeType::Ellipse {
        c.draw_oval(n.rect, &p);
    } else {
        c.draw_rrect(rr, &p);
    }
}

fn material(c: &Canvas, n: &LNode, rr: &RRect, lod: Lod, theme: Theme) {
    let day = theme == Theme::Day;
    let (tint, rim) = match n.look.material {
        Material::Glass => {
            let a = if lod == Lod::Full { 1.0 } else { 1.6 };
            let t = if day { 76.0 } else { 26.0 } * a;
            (
                Some(Color::from_argb(t as u8, 255, 255, 255)),
                Some(Color::from_argb(if day { 110 } else { 50 }, 255, 255, 255)),
            )
        }
        Material::Well => (
            Some(Color::from_argb(if day { 14 } else { 70 }, 0, 0, 0)),
            None,
        ),
        Material::Clear => (
            None,
            Some(Color::from_argb(if day { 80 } else { 36 }, 255, 255, 255)),
        ),
        Material::None => return,
    };
    if n.look.material == Material::Glass && lod == Lod::Full {
        c.save();
        c.clip_rrect(rr, None, true);
        if let Some(b) = image_filters::blur((16.0, 16.0), TileMode::Clamp, None, None) {
            c.save_layer(&SaveLayerRec::default().bounds(rr.rect()).backdrop(&b));
            c.restore();
        }
        c.restore();
    }
    if let Some(t) = tint {
        c.draw_rrect(rr, &paint(t));
    }
    if let Some(r) = rim {
        let mut p = paint(r);
        p.set_style(PaintStyle::Stroke);
        p.set_stroke_width(1.0);
        c.draw_rrect(shape(n, -0.5), &p);
    }
}

fn draw_node(c: &Canvas, nodes: &[LNode], i: usize, lod: Lod, cx: &mut DrawCx) {
    let n = &nodes[i];
    let lk: &Look = &n.look;
    if !lk.visible {
        return;
    }
    let rotated = lk.rotation != 0.0;
    if rotated {
        c.save();
        c.rotate(
            lk.rotation,
            Some(Point::new(n.rect.center_x(), n.rect.center_y())),
        );
    }
    // layer blur below Lod::NoBlur is dropped like the live glass blur (small on screen, costly)
    let blur = (lk.blur > 0.0 && lod <= Lod::NoBlur)
        .then(|| image_filters::blur((lk.blur / 2.0, lk.blur / 2.0), TileMode::Decal, None, None))
        .flatten();
    let layer = lk.opacity < 1.0 || lk.blend != BlendMode::SrcOver || blur.is_some();
    if layer {
        let mut p = Paint::default();
        p.set_alpha_f(lk.opacity);
        p.set_blend_mode(lk.blend);
        if let Some(f) = blur {
            p.set_image_filter(f);
        }
        let mut b = n.rect;
        b.outset((200.0 + lk.blur * 1.5, 200.0 + lk.blur * 1.5));
        c.save_layer(&SaveLayerRec::default().bounds(&b).paint(&p));
    }
    let rr = shape(n, 0.0);
    if lod <= Lod::NoBlur {
        for s in lk.shadows.iter().filter(|s| !s.inset) {
            draw_shadow(c, n, s, cx);
        }
    }
    if lk.backdrop_blur > 0.0 && lod == Lod::Full {
        backdrop(c, &rr, lk.backdrop_blur / 2.0);
    }
    match n.ty {
        NodeType::Text => {
            if let Some(para) = &n.para {
                match lod {
                    Lod::Full | Lod::NoBlur => para.paint(c, Point::new(n.rect.left, n.rect.top)),
                    Lod::Bars => {
                        let h = n.rect.height();
                        let w = para.longest_line().min(n.rect.width()).max(1.0);
                        let r = Rect::from_xywh(n.rect.left, n.rect.top + h * 0.3, w, h * 0.4);
                        let col = text_color(lk, cx.theme).with_a(140);
                        c.draw_rrect(RRect::new_rect_xy(r, 1.0, 1.0), &paint(col));
                    }
                    Lod::Boxes => {}
                }
            }
        }
        _ => {
            material(c, n, &rr, lod, cx.theme);
            for f in &lk.fills {
                draw_fill(c, n, f, &rr, cx);
            }
            if let Some((a, fit)) = &lk.image {
                match cx.assets.image(a) {
                    Some(img) => draw_image(c, &img, *fit, &rr),
                    None => {
                        cx.missing.push(a.clone());
                        c.draw_rrect(rr, &paint(Color::from_argb(60, 128, 128, 128)));
                    }
                }
            }
            for sh in lk.shadows.iter().filter(|s| s.inset) {
                if lod <= Lod::NoBlur {
                    inner_shadow(c, n, sh, &rr);
                }
            }
            for st in &lk.strokes {
                draw_stroke(c, n, st);
            }
        }
    }
    let clip = lk.clip && !n.kids.is_empty();
    if clip {
        c.save();
        c.clip_rrect(rr, None, true);
    }
    for k in &n.kids {
        draw_node(c, nodes, *k as usize, lod, cx);
    }
    if clip {
        c.restore();
    }
    if layer {
        c.restore();
    }
    if rotated {
        c.restore();
    }
}

/// The node's outline as a path: its rounded rect / oval grown by `grow`, or a vector's own path.
fn outline(n: &LNode, grow: f32) -> Option<Path> {
    if n.ty == NodeType::Vector {
        return vector_path(n);
    }
    Some(Path::rrect(shape(n, grow), None))
}

/// One stroke. Inside / centre / outside move the outline by half the width; a vector's path is stroked on its
/// centre (an open path has no inside).
fn draw_stroke(c: &Canvas, n: &LNode, st: &crate::look::Stroke) {
    let w = st.width;
    let grow = match st.align {
        Align::Inside => -w / 2.0,
        Align::Center => 0.0,
        Align::Outside => w / 2.0,
    };
    let mut p = paint(st.color);
    p.set_style(PaintStyle::Stroke);
    p.set_stroke_width(w);
    if !st.dash.is_empty() {
        let mut d = st.dash.clone();
        if d.len() % 2 == 1 {
            d.extend_from_within(..);
        }
        p.set_path_effect(PathEffect::dash(&d, 0.0));
    }
    if n.ty == NodeType::Vector {
        if let Some(path) = vector_path(n) {
            c.draw_path(&path, &p);
        }
    } else if st.dash.is_empty() {
        c.draw_rrect(shape(n, grow), &p);
    } else if let Some(path) = outline(n, grow) {
        c.draw_path(&path, &p);
    }
}

/// An inner shadow: everything outside the (offset, spread-shrunk) shape, blurred, clipped to the shape.
fn inner_shadow(c: &Canvas, n: &LNode, s: &crate::look::Shadow, rr: &RRect) {
    let Some(mut hole) = outline(n, -s.spread) else {
        return;
    };
    hole = hole.with_offset((s.x, s.y));
    hole.set_fill_type(PathFillType::InverseWinding);
    c.save();
    match outline(n, 0.0) {
        Some(clip) if n.ty == NodeType::Vector => c.clip_path(&clip, None, true),
        _ => c.clip_rrect(rr, None, true),
    };
    let mut p = paint(s.color);
    if s.blur > 0.0 {
        p.set_mask_filter(MaskFilter::blur(BlurStyle::Normal, s.blur / 2.0, true));
    }
    c.draw_path(&hole, &p);
    c.restore();
}

/// Background blur: what is drawn under the shape, blurred, inside the shape.
fn backdrop(c: &Canvas, rr: &RRect, sigma: f32) {
    c.save();
    c.clip_rrect(rr, None, true);
    if let Some(b) = image_filters::blur((sigma, sigma), TileMode::Clamp, None, None) {
        c.save_layer(&SaveLayerRec::default().bounds(rr.rect()).backdrop(&b));
        c.restore();
    }
    c.restore();
}

pub fn record(laid: &Laid, lod: Lod, cx: &mut DrawCx) -> Option<Picture> {
    let mut rec = PictureRecorder::new();
    let c = rec.begin_recording(laid.bounds, true);
    draw_node(c, &laid.nodes, 0, lod, cx);
    rec.finish_recording_as_picture(None)
}
