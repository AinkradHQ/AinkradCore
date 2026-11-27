//! CPU raster backend: runners (`design.render`), golden images, and the Mac-vs-Linux comparison.

use skia_safe::{AlphaType, Color, ColorType, Data, EncodedImageFormat, Image, ImageInfo, Rect, Surface, surfaces};

use crate::camera::Camera;
use crate::overlay::Overlay;
use crate::scene::Renderer;

/// Draw the current view into a fresh `w` x `h` point surface at the camera's scale.
pub fn render(r: &mut Renderer) -> Option<Surface> {
    let c = r.camera;
    let mut s = surfaces::raster_n32_premul((
        (c.view.0 * c.scale).round() as i32,
        (c.view.1 * c.scale).round() as i32,
    ))?;
    r.draw(s.canvas(), false);
    Some(s)
}

pub fn png(s: &mut Surface) -> Vec<u8> {
    s.image_snapshot()
        .encode(None, EncodedImageFormat::PNG, 100)
        .map(|d| d.as_bytes().to_vec())
        .unwrap_or_default()
}

/// Render and encode in one call: what a runner op returns.
pub fn render_png(r: &mut Renderer) -> Vec<u8> {
    render(r).map(|mut s| png(&mut s)).unwrap_or_default()
}

/// The world `rect` at `scale` (device pixels per point) as PNG bytes, on a transparent background and without the
/// overlay. The renderer's camera, background and overlay are put back afterwards.
pub fn export_png(r: &mut Renderer, rect: Rect, scale: f32) -> Option<Vec<u8>> {
    let (w, h) = (
        (rect.width() * scale).round() as i32,
        (rect.height() * scale).round() as i32,
    );
    let mut s = surfaces::raster_n32_premul((w.max(1), h.max(1)))?;
    let (cam, bg, overlay) = (r.camera, r.background, r.overlay().clone());
    r.set_overlay(Overlay::default());
    r.background = Color::TRANSPARENT;
    r.set_camera(Camera {
        zoom: scale,
        pan: (-rect.left * scale, -rect.top * scale),
        view: (w as f32, h as f32),
        scale: 1.0,
    });
    r.draw(s.canvas(), false);
    r.background = bg;
    r.set_overlay(overlay);
    r.set_camera(cam);
    Some(png(&mut s))
}

/// Size and one pixel (`[r, g, b, a]`, premultiplied RGBA) of PNG bytes: tests check what an export drew.
#[doc(hidden)]
pub fn png_pixel(bytes: &[u8], x: i32, y: i32) -> Option<((i32, i32), [u8; 4])> {
    let img = Image::from_encoded(Data::new_copy(bytes))?;
    let mut px = [0u8; 4];
    let info = ImageInfo::new((1, 1), ColorType::RGBA8888, AlphaType::Premul, None);
    img.read_pixels(
        &info,
        &mut px,
        4,
        (x, y),
        skia_safe::image::CachingHint::Allow,
    )
    .then_some(((img.width(), img.height()), px))
}
