//! Metal backend (feature `metal`, macOS): the same `Renderer::draw`, on a Ganesh Metal context.
//!
//! The only `unsafe` in this crate: building Skia's Metal context from raw `MTLDevice` / `MTLCommandQueue` handles,
//! and wrapping a host-owned `MTLTexture`. Everything else is safe Rust. The FFI crate (V2-02) calls `from_raw` and
//! `draw_texture` with the `CAMetalLayer` drawable's objects.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::time::Instant;

use skia_safe::gpu::{
    self, Budgeted, ContextOptions, DirectContext, SurfaceOrigin, backend_render_targets,
    direct_contexts, mtl,
};
use skia_safe::{
    AlphaType, ColorType, ImageInfo, PixelGeometry, Surface, SurfaceProps, SurfacePropsFlags,
};

use crate::scene::Renderer;

/// Distance-field text (spike adjustment 3): glyph masks independent of scale, so a continuous zoom never re-rasters
/// glyphs.
pub fn context_options() -> ContextOptions {
    let mut o = ContextOptions::new();
    o.min_distance_field_font_size = 4.0;
    o.glyphs_as_paths_font_size = 324.0;
    o
}

pub fn surface_props() -> SurfaceProps {
    SurfaceProps::new(
        SurfacePropsFlags::USE_DEVICE_INDEPENDENT_FONTS,
        PixelGeometry::Unknown,
    )
}

/// Milliseconds: CPU time to record and submit, and total until the GPU finished.
#[derive(Debug, Clone, Copy)]
pub struct FrameTimes {
    pub cpu_ms: f64,
    pub total_ms: f64,
}

pub struct Metal {
    ctx: DirectContext,
    target: Option<((i32, i32), Surface)>,
    // keep the objects the context was built from alive when we created them ourselves
    _owned: Option<(metal::Device, metal::CommandQueue)>,
}

impl Metal {
    /// The system's default GPU, with its own command queue (benches, tools, tests).
    pub fn system_default() -> Option<Metal> {
        use metal::foreign_types::ForeignType;
        let dev = metal::Device::system_default()?;
        let q = dev.new_command_queue();
        let mut m = unsafe { Metal::from_raw(dev.as_ptr().cast(), q.as_ptr().cast()) }?;
        m._owned = Some((dev, q));
        Some(m)
    }

    /// # Safety
    /// `device` and `queue` are live `id<MTLDevice>` / `id<MTLCommandQueue>` that outlive the returned value.
    pub unsafe fn from_raw(device: *mut c_void, queue: *mut c_void) -> Option<Metal> {
        let bc = unsafe { mtl::BackendContext::new(device as mtl::Handle, queue as mtl::Handle) };
        let ctx = direct_contexts::make_metal(&bc, &context_options())?;
        Some(Metal {
            ctx,
            target: None,
            _owned: None,
        })
    }

    /// Draw into a host-owned texture (the drawable's), flush and submit on the shared queue.
    ///
    /// # Safety
    /// `texture` is a live `id<MTLTexture>` of `w` x `h` BGRA8 pixels, usable as a render target.
    pub unsafe fn draw_texture(
        &mut self,
        r: &mut Renderer,
        texture: *mut c_void,
        w: i32,
        h: i32,
        partial: bool,
    ) -> Option<FrameTimes> {
        let t = Instant::now();
        let ti = unsafe { mtl::TextureInfo::new(texture as mtl::Handle) };
        let brt = backend_render_targets::make_mtl((w, h), &ti);
        let props = surface_props();
        let mut s = gpu::surfaces::wrap_backend_render_target(
            &mut self.ctx,
            &brt,
            SurfaceOrigin::TopLeft,
            ColorType::BGRA8888,
            None,
            Some(&props),
        )?;
        r.draw(s.canvas(), partial);
        let ok = self.ctx.flush_and_submit().is_ok();
        let ms = t.elapsed().as_secs_f64() * 1e3;
        ok.then_some(FrameTimes {
            cpu_ms: ms,
            total_ms: ms,
        })
    }

    /// Draw the renderer's view into an offscreen target of the camera's pixel size and wait for the GPU.
    pub fn render_offscreen(&mut self, r: &mut Renderer) -> Option<FrameTimes> {
        let c = r.camera;
        let dim = (
            (c.view.0 * c.scale).round() as i32,
            (c.view.1 * c.scale).round() as i32,
        );
        if self.target.as_ref().map(|t| t.0) != Some(dim) {
            let info = ImageInfo::new(dim, ColorType::BGRA8888, AlphaType::Premul, None);
            let props = surface_props();
            let s = gpu::surfaces::render_target(
                &mut self.ctx,
                Budgeted::No,
                &info,
                None,
                SurfaceOrigin::TopLeft,
                Some(&props),
                false,
                false,
            )?;
            self.target = Some((dim, s));
        }
        let s = &mut self.target.as_mut()?.1;
        let t = Instant::now();
        r.draw(s.canvas(), false);
        let ok = self.ctx.flush_and_submit().is_ok();
        let cpu = t.elapsed().as_secs_f64() * 1e3;
        let synced = self.ctx.submit(gpu::SyncCpu::Yes);
        let total = t.elapsed().as_secs_f64() * 1e3;
        (ok && synced).then_some(FrameTimes {
            cpu_ms: cpu,
            total_ms: total,
        })
    }

    /// PNG of the last offscreen frame (read back from the GPU).
    pub fn png(&mut self) -> Vec<u8> {
        let Some((_, s)) = self.target.as_mut() else {
            return vec![];
        };
        let (w, h) = (s.width(), s.height());
        let info = ImageInfo::new((w, h), ColorType::RGBA8888, AlphaType::Premul, None);
        let mut px = vec![0u8; (w * h * 4) as usize];
        if !s.read_pixels(&info, &mut px, (w * 4) as usize, (0, 0)) {
            return vec![];
        }
        skia_safe::images::raster_from_data(&info, skia_safe::Data::new_copy(&px), (w * 4) as usize)
            .and_then(|i| i.encode(None, skia_safe::EncodedImageFormat::PNG, 100))
            .map(|d| d.as_bytes().to_vec())
            .unwrap_or_default()
    }
}
