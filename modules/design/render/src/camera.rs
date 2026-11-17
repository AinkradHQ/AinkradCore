//! The viewport: zoom + pan in points, the view size and the backing scale. Screen = (world * zoom) + pan.
//!
//! Bounds (V2-03): the pan is free while the view centre stays over the page's content; past that it is rubber-banded
//! (the overshoot is resisted, like an NSScrollView edge) and settles back when the gesture ends.

use skia_safe::Rect;

pub const MIN_ZOOM: f32 = 0.05;
pub const MAX_ZOOM: f32 = 8.0;
/// AppKit's rubber-band stiffness.
const RUBBER: f32 = 0.55;

/// Resisted overshoot: `over` points past an edge show as at most `dim` (the view size on that axis).
pub fn rubber(over: f32, dim: f32) -> f32 {
    let d = dim.max(1.0);
    (1.0 - 1.0 / (over.abs() * RUBBER / d + 1.0)) * d * over.signum()
}

/// The inverse of `rubber`: the raw overshoot that shows as `shown`.
pub fn unrubber(shown: f32, dim: f32) -> f32 {
    let d = dim.max(1.0);
    let f = (shown.abs() / d).min(0.999);
    d / RUBBER * (1.0 / (1.0 - f) - 1.0) * shown.signum()
}

/// `v` inside `[lo, hi]` unchanged, outside rubber-banded.
pub fn band(v: f32, (lo, hi): (f32, f32), dim: f32) -> f32 {
    if v < lo {
        lo + rubber(v - lo, dim)
    } else if v > hi {
        hi + rubber(v - hi, dim)
    } else {
        v
    }
}

pub fn unband(v: f32, (lo, hi): (f32, f32), dim: f32) -> f32 {
    if v < lo {
        lo + unrubber(v - lo, dim)
    } else if v > hi {
        hi + unrubber(v - hi, dim)
    } else {
        v
    }
}

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

    /// The pan range per axis that keeps the view centre over `content` (world): `[(lo x, hi x), (lo y, hi y)]`.
    pub fn pan_range(&self, content: Rect) -> [(f32, f32); 2] {
        let (w, h, z) = (self.view.0 / 2.0, self.view.1 / 2.0, self.zoom);
        [
            (w - content.right * z, w - content.left * z),
            (h - content.bottom * z, h - content.top * z),
        ]
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

/// Camera moves on the renderer (benches and the host's scripted paths).
impl crate::scene::Renderer {
    pub fn pan_by(&mut self, dx: f32, dy: f32) {
        let c = Camera {
            pan: (self.camera.pan.0 + dx, self.camera.pan.1 + dy),
            ..self.camera
        };
        self.set_camera(c);
    }

    pub fn zoom_at(&mut self, factor: f32, x: f32, y: f32) {
        let mut c = self.camera;
        c.zoom_at(factor, x, y);
        self.set_camera(c);
    }

    pub fn set_view(&mut self, w: f32, h: f32, scale: f32) {
        let c = Camera {
            view: (w, h),
            scale,
            ..self.camera
        };
        self.set_camera(c);
    }

    pub fn fit_all(&mut self) {
        if let Some(r) = self.world_bounds() {
            let mut c = self.camera;
            c.fit(r, 0.05);
            self.set_camera(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-3
    }

    #[test]
    fn world_and_screen_round_trip_and_zoom_keeps_the_anchor() {
        let mut c = Camera {
            zoom: 2.0,
            pan: (30.0, -12.0),
            ..Camera::default()
        };
        let (wx, wy) = c.to_world(400.0, 300.0);
        let (sx, sy) = c.to_screen(wx, wy);
        assert!(close(sx, 400.0) && close(sy, 300.0));
        c.zoom_at(1.5, 400.0, 300.0);
        assert!(close(c.zoom, 3.0));
        let (sx, sy) = c.to_screen(wx, wy);
        assert!(
            close(sx, 400.0) && close(sy, 300.0),
            "the point under the cursor stays"
        );
        c.zoom_at(1000.0, 0.0, 0.0);
        assert_eq!(c.zoom, MAX_ZOOM);
        c.zoom_at(1e-6, 0.0, 0.0);
        assert_eq!(c.zoom, MIN_ZOOM);
    }

    #[test]
    fn fit_centres_the_rect_with_its_margin() {
        let mut c = Camera {
            view: (1000.0, 500.0),
            ..Camera::default()
        };
        c.fit(Rect::from_xywh(100.0, 100.0, 400.0, 100.0), 0.05);
        assert!(close(c.zoom, 2.25), "{}", c.zoom);
        let (l, t) = c.to_screen(100.0, 100.0);
        let (r, b) = c.to_screen(500.0, 200.0);
        assert!(close(l, 1000.0 - r) && close(t, 500.0 - b), "centred");
        let before = c;
        c.fit(Rect::from_xywh(0.0, 0.0, 0.0, 10.0), 0.05);
        assert_eq!(c, before, "an empty rect changes nothing");
    }

    #[test]
    fn rubber_band_resists_and_inverts() {
        assert_eq!(rubber(0.0, 800.0), 0.0);
        let a = rubber(100.0, 800.0);
        assert!(a > 0.0 && a < 100.0, "resisted");
        assert!(rubber(1e9, 800.0) < 800.0, "never past the view size");
        assert!(close(rubber(-100.0, 800.0), -a), "symmetric");
        for v in [-500.0, -3.0, 0.5, 40.0, 700.0] {
            assert!(close(unrubber(rubber(v, 800.0), 800.0), v), "{v}");
        }
        let r = (-200.0, 100.0);
        assert_eq!(band(50.0, r, 800.0), 50.0, "inside: free");
        assert!(band(300.0, r, 800.0) < 300.0 && band(300.0, r, 800.0) > 100.0);
        assert!(band(-400.0, r, 800.0) > -400.0);
        for v in [-900.0, -200.0, 0.0, 100.0, 250.0] {
            assert!(close(unband(band(v, r, 800.0), r, 800.0), v), "{v}");
        }
    }

    #[test]
    fn pan_range_keeps_the_view_centre_over_the_content() {
        let c = Camera {
            zoom: 0.5,
            view: (800.0, 600.0),
            ..Camera::default()
        };
        let content = Rect::from_xywh(0.0, 0.0, 2000.0, 1000.0);
        let [x, y] = c.pan_range(content);
        for (px, py) in [(x.0, y.0), (x.1, y.1)] {
            let (wx, wy) = Camera { pan: (px, py), ..c }.to_world(400.0, 300.0);
            assert!(close(wx, 2000.0) || close(wx, 0.0), "{wx}");
            assert!(close(wy, 1000.0) || close(wy, 0.0), "{wy}");
        }
        assert!(x.0 < x.1 && y.0 < y.1);
    }
}
