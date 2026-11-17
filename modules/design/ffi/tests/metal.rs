//! V2-02: the App's path, a real Metal device, queue and render-target texture through the C ABI (`--features metal`).
#![cfg(all(feature = "metal", target_os = "macos"))]
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use metal::foreign_types::ForeignType;

#[test]
fn attach_draw_detach() {
    let Some(dev) = metal::Device::system_default() else {
        eprintln!("no Metal device; skipped");
        return;
    };
    let q = dev.new_command_queue();
    let td = metal::TextureDescriptor::new();
    td.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
    td.set_width(320);
    td.set_height(200);
    td.set_usage(metal::MTLTextureUsage::RenderTarget | metal::MTLTextureUsage::ShaderRead);
    let tex = dev.new_texture(&td);
    let ops = br##"[{"op":"add","id":"n_aaaaaaaaaaaa","type":"page","parent":null,"order":"a"},
      {"op":"add","id":"n_bbbbbbbbbbbb","type":"frame","parent":"n_aaaaaaaaaaaa","order":"a",
       "props":{"w":100,"h":100,"fill":[{"type":"solid","color":"#ff0000"}]}}]"##;
    let mut h = 0u64;
    unsafe {
        assert_eq!(de_engine_new(b"dd_metal".as_ptr(), 8, &mut h), DE_OK);
        assert_eq!(
            de_draw_metal(h, tex.as_ptr().cast(), 320, 200),
            DE_ERR_NO_SURFACE
        );
        assert_eq!(
            de_attach_metal(h, dev.as_ptr().cast(), q.as_ptr().cast()),
            DE_OK
        );
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
        assert_eq!(de_resize(h, 160.0, 100.0, 2.0), DE_OK);
        assert_eq!(de_needs_frame(h), 1);
        assert_eq!(de_draw_metal(h, tex.as_ptr().cast(), 320, 200), DE_OK);
        assert_eq!(de_detach(h), DE_OK);
        assert_eq!(
            de_draw_metal(h, tex.as_ptr().cast(), 320, 200),
            DE_ERR_NO_SURFACE
        );
    }
    assert_eq!(de_engine_free(h), DE_OK);
}
