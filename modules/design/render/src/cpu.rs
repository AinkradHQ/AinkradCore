//! CPU raster backend: runners (`design.render`), golden images, and the Mac-vs-Linux comparison.

use skia_safe::{EncodedImageFormat, Surface, surfaces};

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
