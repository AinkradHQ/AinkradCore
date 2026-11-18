//! Images: the host supplies encoded bytes by asset hash; each is decoded once and kept in a byte-capped LRU. A decode
//! that fails is remembered as a miss, so a hostile file costs one attempt, not one per frame. The cap is soft: a
//! recorded picture keeps its own reference to an image until the picture is dropped (`Renderer::trim`).

use std::collections::HashMap;

use skia_safe::{AlphaType, ColorType, Data, Image, ImageInfo, surfaces};

/// Longest side kept after decoding; bigger images are scaled down once (a 12 MP photo on a phone screen is waste).
pub const MAX_SIDE: i32 = 4096;
pub const DEFAULT_CAP: usize = 128 * 1024 * 1024;
/// Pixels an image may claim in its header. `Image::from_encoded` only reads the header; the decode happens in Skia
/// (C++, outside any Rust allocation cap) when the image is drawn, at full size: a 60000 x 60000 PNG is ~14 GB.
/// Anything bigger is refused before it is drawn (64 MP x 4 bytes = 256 MB transient).
pub const MAX_PIXELS: i64 = 64 * 1024 * 1024;

struct Slot {
    img: Option<Image>,
    bytes: usize,
    tick: u64,
}

pub struct Assets {
    encoded: HashMap<String, Data>,
    decoded: HashMap<String, Slot>,
    cap: usize,
    used: usize,
    tick: u64,
    /// bumped when an asset arrives; pictures that drew a placeholder are recorded again
    pub(crate) epoch: u64,
}

impl Default for Assets {
    fn default() -> Self {
        Self::new(DEFAULT_CAP)
    }
}

fn decode(d: &Data) -> Option<(Image, usize)> {
    let img = Image::from_encoded(d.clone())?;
    let (w, h) = (img.width(), img.height());
    if w <= 0 || h <= 0 || i64::from(w) * i64::from(h) > MAX_PIXELS {
        return None;
    }
    let k = (MAX_SIDE as f32 / w.max(h) as f32).min(1.0);
    let (tw, th) = (
        ((w as f32 * k) as i32).max(1),
        ((h as f32 * k) as i32).max(1),
    );
    let mut s = surfaces::raster(
        &ImageInfo::new((tw, th), ColorType::N32, AlphaType::Premul, None),
        None,
        None,
    )?;
    s.canvas().draw_image_rect(
        &img,
        None,
        skia_safe::Rect::from_wh(tw as f32, th as f32),
        &skia_safe::Paint::default(),
    );
    let out = s.image_snapshot();
    Some((out, (tw * th * 4) as usize))
}

impl Assets {
    pub fn new(cap: usize) -> Assets {
        Assets {
            encoded: HashMap::new(),
            decoded: HashMap::new(),
            cap,
            used: 0,
            tick: 0,
            epoch: 0,
        }
    }

    pub fn add(&mut self, hash: &str, bytes: &[u8]) {
        self.encoded.insert(hash.to_string(), Data::new_copy(bytes));
        if let Some(s) = self.decoded.remove(hash) {
            self.used -= s.bytes;
        }
        self.epoch += 1;
    }

    pub fn has(&self, hash: &str) -> bool {
        self.encoded.contains_key(hash)
    }

    /// Bytes of decoded pixels currently held.
    pub fn used(&self) -> usize {
        self.used
    }

    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
        self.evict(0);
    }

    fn evict(&mut self, incoming: usize) {
        while self.used + incoming > self.cap {
            let Some(k) = self
                .decoded
                .iter()
                .filter(|(_, s)| s.img.is_some())
                .min_by_key(|(_, s)| s.tick)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(s) = self.decoded.remove(&k) {
                self.used -= s.bytes;
            }
        }
    }

    /// The decoded image, or `None` when the asset is missing or undecodable.
    pub fn image(&mut self, hash: &str) -> Option<Image> {
        self.tick += 1;
        if let Some(s) = self.decoded.get_mut(hash) {
            s.tick = self.tick;
            return s.img.clone();
        }
        let data = self.encoded.get(hash)?;
        let got = decode(data);
        let bytes = got.as_ref().map_or(0, |g| g.1);
        self.evict(bytes);
        let img = got.map(|g| g.0);
        self.used += bytes;
        self.decoded.insert(
            hash.to_string(),
            Slot {
                img: img.clone(),
                bytes,
                tick: self.tick,
            },
        );
        img
    }
}
