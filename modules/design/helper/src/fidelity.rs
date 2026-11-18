//! `design.fidelity`: how far apart two PNGs of one screen are (V6-03, plan T15). The engine's frame
//! against Chromium's shot of the export; both are decoded here, inside the sandbox, never in the Core.
//!
//! The measure is the one the render goldens use (`render/tests/common`): the share of pixels whose worst RGB
//! channel differs by more than `TOLERANCE` (a glyph edge or a half-pixel gradient step is below it; a moved box or a
//! wrong colour is far above). The plan's gate is 1 %. Advisory: it flags, it never blocks.

use ainkrad_proto::v2::{
    DESIGN_MAX_PIXELS, DESIGN_MAX_PNG, DESIGN_MAX_SIDE, DesignFidelity, DesignFidelityScore,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use skia_safe::{AlphaType, ColorType, Data, Image, ImageInfo, image::CachingHint};

/// Worst-channel difference, of 255, above which a pixel counts as changed.
pub const TOLERANCE: i32 = 48;

fn decode(b64: &str) -> Result<(Vec<u8>, u32, u32), String> {
    let bytes = STANDARD
        .decode(b64)
        .ok()
        .filter(|b| b.len() <= DESIGN_MAX_PNG)
        .ok_or("the image is not base64, or is too large")?;
    // the header is read and sized before any pixel is decoded
    let img = Image::from_encoded(Data::new_copy(&bytes)).ok_or("the image is not a PNG")?;
    let (w, h) = (img.width(), img.height());
    if !(1..=DESIGN_MAX_SIDE as i32).contains(&w)
        || !(1..=DESIGN_MAX_SIDE as i32).contains(&h)
        || (w as u64) * (h as u64) > DESIGN_MAX_PIXELS
    {
        return Err("the image is too large".into());
    }
    let info = ImageInfo::new((w, h), ColorType::RGBA8888, AlphaType::Premul, None);
    let mut px = vec![0u8; (w as usize) * (h as usize) * 4];
    if !img.read_pixels(
        &info,
        &mut px,
        (w as usize) * 4,
        (0, 0),
        CachingHint::Disallow,
    ) {
        return Err("the image cannot be decoded".into());
    }
    Ok((px, w as u32, h as u32))
}

pub fn fidelity(f: &DesignFidelity) -> Result<DesignFidelityScore, String> {
    let (a, (aw, ah)) = decode(&f.a).map(|(p, w, h)| (p, (w, h)))?;
    let (b, (bw, bh)) = decode(&f.b).map(|(p, w, h)| (p, (w, h)))?;
    let total = u64::from(aw) * u64::from(ah);
    // other sizes are not comparable: the whole screen counts as changed
    if (aw, ah) != (bw, bh) {
        return Ok(DesignFidelityScore {
            percent: 100.0,
            changed: total,
            total,
            width: aw,
            height: ah,
        });
    }
    let changed = a
        .chunks_exact(4)
        .zip(b.chunks_exact(4))
        .filter(|(p, q)| (0..3).any(|c| (i32::from(p[c]) - i32::from(q[c])).abs() > TOLERANCE))
        .count() as u64;
    Ok(DesignFidelityScore {
        percent: changed as f64 * 100.0 / total as f64,
        changed,
        total,
        width: aw,
        height: ah,
    })
}
