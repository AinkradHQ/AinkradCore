//! Read-outs for the style guide and exports: this document's own tokens, and a node as a PNG.

use design_model::Theme;
use design_render::Rect;
use serde_json::json;

use crate::ffi::*;
use crate::host::Host;

/// Longest side and most pixels an export may have.
const MAX_SIDE_PX: f32 = 16_384.0;
const MAX_PIXELS: f32 = 64.0e6;

impl Host {
    /// `[{name, kind, day, night}]`: the tokens this document itself holds (a system doc), in name order.
    pub fn doc_tokens_json(&mut self) -> Vec<u8> {
        let all: Vec<_> = self
            .model()
            .tokens
            .iter()
            .map(|(n, t)| json!({"name": n, "kind": t.kind, "day": t.day, "night": t.night}))
            .collect();
        serde_json::to_vec(&all).unwrap_or_else(|_| b"[]".to_vec())
    }

    /// Node `id` as PNG bytes: Skia on the CPU at `scale` (1..=4), in the day or night theme, transparent behind it.
    /// Whatever else overlaps the node's rectangle is drawn too (export a top-level frame).
    pub fn export_png(&mut self, id: &str, scale: f32, night: bool) -> Result<Vec<u8>, i32> {
        if !(1.0..=4.0).contains(&scale) {
            return Err(DE_ERR_ARG);
        }
        self.refresh();
        if !self.model().nodes.contains_key(id) {
            return Err(DE_ERR_INVALID);
        }
        let was_night = self.theme == Theme::Night;
        if was_night != night {
            self.set_theme(night);
            self.refresh();
        }
        let png = match self.rect(id) {
            Some(r)
                if r.width() * scale <= MAX_SIDE_PX
                    && r.height() * scale <= MAX_SIDE_PX
                    && r.width() * r.height() * scale * scale <= MAX_PIXELS =>
            {
                let r = Rect::new(r.left, r.top, r.right, r.bottom);
                design_render::cpu::export_png(self.renderer(), r, scale).ok_or(DE_ERR_INVALID)
            }
            Some(_) => Err(DE_ERR_TOO_LARGE),
            None => Err(DE_ERR_INVALID),
        };
        if was_night != night {
            self.set_theme(was_night);
        }
        self.refresh();
        png
    }
}
