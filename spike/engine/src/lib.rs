//! V0-01 spike engine: scene + camera + hit/drag + Metal and CPU backends, behind a C ABI.
pub mod scene;

use scene::*;
use scene::Kind;
use skia_safe::{
    AlphaType, Color, ColorType, EncodedImageFormat, ImageInfo, Paint, Rect, Surface, surfaces,
};
use std::ffi::{CStr, c_char, c_void};
use std::time::Instant;

pub const MIN_ZOOM: f32 = 0.05;
pub const MAX_ZOOM: f32 = 8.0;

struct Drag {
    screen: usize,
    group: i32,
    last: (f32, f32), // world
}

pub struct Engine {
    pub scene: Scene,
    pub zoom: f32,
    pub pan: (f32, f32), // points
    pub view: (f32, f32), // points
    pub scale: f32,
    pub lod: bool,
    pub bars_max_w: f32, // below this on-screen screen width text is drawn as bars
    pub blur_min_w: f32, // on-screen screen width (pt) below which live blur is dropped
    drag: Option<Drag>,
    #[cfg(feature = "metal")]
    ctx: Option<skia_safe::gpu::DirectContext>,
    pub last_rerecord_ms: f64,
}

impl Engine {
    pub fn new(font: &str) -> Engine {
        Engine {
            scene: scene::build(font),
            zoom: 1.0,
            pan: (0.0, 0.0),
            view: (1280.0, 800.0),
            scale: 2.0,
            lod: true,
            bars_max_w: 150.0,
            blur_min_w: 250.0,
            drag: None,
            #[cfg(feature = "metal")]
            ctx: None,
            last_rerecord_ms: 0.0,
        }
    }

    pub fn fit_zoom(&self) -> f32 {
        (self.view.0 / WORLD_W).min(self.view.1 / WORLD_H) * 0.95
    }

    pub fn set_camera(&mut self, zoom: f32, pan: (f32, f32)) {
        self.zoom = zoom.clamp(MIN_ZOOM, MAX_ZOOM);
        self.pan = pan;
    }

    /// Zoom by `factor` keeping the world point under `(cx, cy)` (points) fixed.
    pub fn zoom_at(&mut self, factor: f32, cx: f32, cy: f32) {
        let z = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let f = z / self.zoom;
        self.pan = (cx - (cx - self.pan.0) * f, cy - (cy - self.pan.1) * f);
        self.zoom = z;
    }

    pub fn to_world(&self, x: f32, y: f32) -> (f32, f32) {
        ((x - self.pan.0) / self.zoom, (y - self.pan.1) / self.zoom)
    }

    /// Topmost card or glass node under the point; starts a drag of its group.
    pub fn drag_begin(&mut self, x: f32, y: f32) -> bool {
        let (wx, wy) = self.to_world(x, y);
        for (si, s) in self.scene.screens.iter().enumerate() {
            let (lx, ly) = (wx - s.origin.x, wy - s.origin.y);
            if lx < 0.0 || ly < 0.0 || lx > SCREEN_W || ly > SCREEN_H {
                continue;
            }
            for n in s.nodes.iter().rev() {
                if n.group >= 0 && (n.rect.left <= lx && lx < n.rect.right && n.rect.top <= ly && ly < n.rect.bottom) {
                    self.drag = Some(Drag { screen: si, group: n.group, last: (wx, wy) });
                    return true;
                }
            }
        }
        false
    }

    pub fn drag_move(&mut self, x: f32, y: f32) {
        let (wx, wy) = self.to_world(x, y);
        let Some(d) = &mut self.drag else { return };
        let (dx, dy) = (wx - d.last.0, wy - d.last.1);
        d.last = (wx, wy);
        let (si, g) = (d.screen, d.group);
        for n in &mut self.scene.screens[si].nodes {
            if n.group == g {
                n.rect.offset((dx, dy));
            }
        }
        let t = Instant::now();
        self.scene.record(si);
        self.last_rerecord_ms = t.elapsed().as_secs_f64() * 1e3;
    }

    pub fn drag_end(&mut self) {
        self.drag = None;
    }

    pub fn draw(&self, c: &skia_safe::Canvas) {
        c.clear(Color::new(0xFFE9ECF2));
        c.save();
        c.scale((self.scale, self.scale));
        c.translate(self.pan);
        c.scale((self.zoom, self.zoom));
        let vis = Rect::from_xywh(-self.pan.0 / self.zoom, -self.pan.1 / self.zoom, self.view.0 / self.zoom, self.view.1 / self.zoom);
        let on_screen_w = SCREEN_W * self.zoom;
        for s in &self.scene.screens {
            let r = Rect::from_xywh(s.origin.x, s.origin.y, SCREEN_W, SCREEN_H);
            if !Rect::intersects(&r, vis) {
                continue;
            }
            // level of detail: far screens drop text + live blur (T5 fallback), below 60 pt wide
            let pic = if self.lod && on_screen_w < 60.0 {
                &s.pic_lod
            } else if on_screen_w < self.bars_max_w {
                &s.pic_bars
            } else if on_screen_w < self.blur_min_w {
                &s.pic_nb
            } else {
                &s.pic
            };
            if let Some(p) = pic {
                c.save();
                c.translate(s.origin);
                c.draw_picture(p, None, None::<&Paint>);
                c.restore();
            }
        }
        c.restore();
    }

    pub fn render_cpu(&self, w: i32, h: i32) -> Surface {
        let mut s = surfaces::raster_n32_premul((w, h)).expect("raster surface");
        self.draw(s.canvas());
        s
    }
}

pub fn save_png(surface: &mut Surface, path: &str) {
    let img = surface.image_snapshot();
    let data = img.encode(None, EncodedImageFormat::PNG, 100).expect("png");
    std::fs::write(path, data.as_bytes()).expect("write png");
}

// ---------------- C ABI ----------------
macro_rules! eng {
    ($p:expr) => {
        unsafe { &mut *$p }
    };
}

/// # Safety: `font` must be a NUL-terminated path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_new(font: *const c_char) -> *mut Engine {
    let f = unsafe { CStr::from_ptr(font) }.to_string_lossy().into_owned();
    Box::into_raw(Box::new(Engine::new(&f)))
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_free(e: *mut Engine) {
    if !e.is_null() {
        drop(unsafe { Box::from_raw(e) });
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_open_ms(e: *mut Engine) -> f64 {
    eng!(e).scene.open_ms
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_layout_ms(e: *mut Engine) -> f64 {
    eng!(e).scene.layout_ms
}
/// out = [nodes, text runs, glass panels]
#[unsafe(no_mangle)]
pub extern "C" fn ds_counts(e: *mut Engine, out: *mut u32) {
    let (a, b, c) = eng!(e).scene.counts();
    unsafe {
        *out = a as u32;
        *out.add(1) = b as u32;
        *out.add(2) = c as u32;
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_set_view(e: *mut Engine, w: f32, h: f32, scale: f32) {
    let e = eng!(e);
    e.view = (w, h);
    e.scale = scale;
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_fit_zoom(e: *mut Engine) -> f32 {
    eng!(e).fit_zoom()
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_set_camera(e: *mut Engine, zoom: f32, px: f32, py: f32) {
    eng!(e).set_camera(zoom, (px, py));
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_get_camera(e: *mut Engine, out: *mut f32) {
    let e = eng!(e);
    unsafe {
        *out = e.zoom;
        *out.add(1) = e.pan.0;
        *out.add(2) = e.pan.1;
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_pan(e: *mut Engine, dx: f32, dy: f32) {
    let e = eng!(e);
    e.pan = (e.pan.0 + dx, e.pan.1 + dy);
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_zoom_at(e: *mut Engine, factor: f32, cx: f32, cy: f32) {
    eng!(e).zoom_at(factor, cx, cy);
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_set_lod(e: *mut Engine, on: i32) {
    eng!(e).lod = on != 0;
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_set_blur_min_w(e: *mut Engine, w: f32) {
    eng!(e).blur_min_w = w;
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_set_bars_max_w(e: *mut Engine, w: f32) {
    eng!(e).bars_max_w = w;
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_drag_begin(e: *mut Engine, x: f32, y: f32) -> i32 {
    eng!(e).drag_begin(x, y) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_drag_move(e: *mut Engine, x: f32, y: f32) {
    eng!(e).drag_move(x, y);
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_drag_end(e: *mut Engine) {
    eng!(e).drag_end();
}
#[unsafe(no_mangle)]
pub extern "C" fn ds_last_rerecord_ms(e: *mut Engine) -> f64 {
    eng!(e).last_rerecord_ms
}

/// CPU raster of the current camera to a PNG file (used on the Mac too, for the CPU-vs-Metal diff).
/// # Safety: `path` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_render_cpu_png(e: *mut Engine, w: i32, h: i32, path: *const c_char) -> f64 {
    let p = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    let t = Instant::now();
    let mut s = eng!(e).render_cpu(w, h);
    let ms = t.elapsed().as_secs_f64() * 1e3;
    save_png(&mut s, &p);
    ms
}

/// Draw into a Metal texture (the CAMetalLayer drawable's), flush + submit on the shared queue.
/// Swift presents with its own command buffer on the same queue afterwards (queue order = after Skia's work).
/// Returns CPU encode+submit milliseconds, or -1 on failure. `png` (nullable) snapshots the frame.
/// # Safety: all pointers are live Metal objects (id<MTLDevice>, id<MTLCommandQueue>, id<MTLTexture>).
#[cfg(feature = "metal")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_render_metal(
    e: *mut Engine,
    device: *mut c_void,
    queue: *mut c_void,
    texture: *mut c_void,
    w: i32,
    h: i32,
    png: *const c_char,
) -> f64 {
    use skia_safe::gpu::{self, SurfaceOrigin, backend_render_targets, direct_contexts, mtl};
    let e = eng!(e);
    let t = Instant::now();
    if e.ctx.is_none() {
        let bc = unsafe { mtl::BackendContext::new(device as mtl::Handle, queue as mtl::Handle) };
        let mut opts = skia_safe::gpu::ContextOptions::new();
        if std::env::var("DS_NOSDF").is_err() {
            // distance-field text: glyph masks independent of scale, so zooming does not re-raster glyphs
            opts.min_distance_field_font_size = 4.0;
            opts.glyphs_as_paths_font_size = 324.0;
        }
        e.ctx = direct_contexts::make_metal(&bc, &opts);
    }
    let Some(mut ctx) = e.ctx.take() else { return -1.0 };
    let ti = unsafe { mtl::TextureInfo::new(texture as mtl::Handle) };
    let brt = backend_render_targets::make_mtl((w, h), &ti);
    let props = std::env::var("DS_NOSDF").is_err().then(|| skia_safe::SurfaceProps::new(skia_safe::SurfacePropsFlags::USE_DEVICE_INDEPENDENT_FONTS, skia_safe::PixelGeometry::Unknown));
    let Some(mut surface) =
        gpu::surfaces::wrap_backend_render_target(&mut ctx, &brt, SurfaceOrigin::TopLeft, ColorType::BGRA8888, None, props.as_ref())
    else {
        e.ctx = Some(ctx);
        return -1.0;
    };
    e.draw(surface.canvas());
    let ok = ctx.flush_and_submit().is_ok();
    let ms = t.elapsed().as_secs_f64() * 1e3;
    if !png.is_null() {
        let path = unsafe { CStr::from_ptr(png) }.to_string_lossy().into_owned();
        let info = ImageInfo::new((w, h), ColorType::BGRA8888, AlphaType::Premul, None);
        let mut px = vec![0u8; (w * h * 4) as usize];
        if surface.read_pixels(&info, &mut px, (w * 4) as usize, (0, 0)) {
            let img = skia_safe::images::raster_from_data(&info, skia_safe::Data::new_copy(&px), (w * 4) as usize).unwrap();
            let d = img.encode(None, EncodedImageFormat::PNG, 100).unwrap();
            std::fs::write(path, d.as_bytes()).unwrap();
        }
    }
    drop(surface);
    e.ctx = Some(ctx);
    if ok { ms } else { -1.0 }
}

/// World-space center of card group `g` on screen 0 (the host aims its scripted drag at it). out = [x, y].
#[unsafe(no_mangle)]
pub extern "C" fn ds_card_center(e: *mut Engine, g: i32, out: *mut f32) {
    let e = eng!(e);
    let s = &e.scene.screens[0];
    let n = s.nodes.iter().find(|n| n.group == g && n.kind == Kind::Card).expect("card");
    unsafe {
        *out = s.origin.x + n.rect.center_x();
        *out.add(1) = s.origin.y + n.rect.center_y();
    }
}
