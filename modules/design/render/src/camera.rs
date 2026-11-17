//! The viewport: zoom + pan in points, the view size and the backing scale. Screen = (world * zoom) + pan.

use skia_safe::Rect;

pub const MIN_ZOOM: f32 = 0.05;
pub const MAX_ZOOM: f32 = 8.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Camera {
    pub zoom: f32,
    /// screen position (points) of the world origin
    pub pan: (f32, f32),
    /// view size in points
    pub view: (f32, f32),
    /// device pixels per point
    pub scale: f32,
}

impl Default for Camera {
    fn default() -> Self {
        Camera {
            zoom: 1.0,
            pan: (0.0, 0.0),
            view: (1280.0, 800.0),
            scale: 1.0,
        }
    }
}

impl Camera {
    pub fn to_world(&self, x: f32, y: f32) -> (f32, f32) {
        ((x - self.pan.0) / self.zoom, (y - self.pan.1) / self.zoom)
    }

    pub fn to_screen(&self, x: f32, y: f32) -> (f32, f32) {
        (x * self.zoom + self.pan.0, y * self.zoom + self.pan.1)
    }

    /// The visible world rectangle.
    pub fn visible(&self) -> Rect {
        Rect::from_xywh(
            -self.pan.0 / self.zoom,
            -self.pan.1 / self.zoom,
            self.view.0 / self.zoom,
            self.view.1 / self.zoom,
        )
    }

    /// Zoom by `factor` keeping the world point under screen `(cx, cy)` fixed.
    pub fn zoom_at(&mut self, factor: f32, cx: f32, cy: f32) {
        let z = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let f = z / self.zoom;
        self.pan = (cx - (cx - self.pan.0) * f, cy - (cy - self.pan.1) * f);
        self.zoom = z;
    }

    /// Frame `r` (world) in the view with `margin` (fraction of the view, e.g. 0.05).
    pub fn fit(&mut self, r: Rect, margin: f32) {
        if r.width() <= 0.0 || r.height() <= 0.0 {
            return;
        }
        let k = 1.0 - 2.0 * margin;
        let z = ((self.view.0 * k) / r.width())
            .min((self.view.1 * k) / r.height())
            .clamp(MIN_ZOOM, MAX_ZOOM);
        self.zoom = z;
        self.pan = (
            (self.view.0 - r.width() * z) / 2.0 - r.left * z,
            (self.view.1 - r.height() * z) / 2.0 - r.top * z,
        );
    }
}
