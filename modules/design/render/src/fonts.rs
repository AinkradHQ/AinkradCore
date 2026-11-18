//! Fonts (T9): a design names fonts by library asset hash or `system`. The host hands the renderer the font files;
//! every renderer loading the same files lays text out the same way. `system` resolves to the registered fallback
//! face when there is one (goldens, Linux runners), else to the platform's own fonts.

use std::collections::HashMap;

use serde_json::Value;
use skia_safe::textlayout::{
    FontCollection, ParagraphBuilder, ParagraphStyle, TextStyle, TypefaceFontProvider,
};
use skia_safe::{Data, FontMgr};

const FALLBACK: &str = "design-system-fallback";

pub struct Fonts {
    pub(crate) fc: FontCollection,
    prov: TypefaceFontProvider,
    /// asset hash -> registered family name
    by_asset: HashMap<String, String>,
    has_fallback: bool,
    /// bumped on every change; artboards laid out under an older epoch are laid out again
    pub(crate) epoch: u64,
}

impl Default for Fonts {
    fn default() -> Self {
        Self::new()
    }
}

impl Fonts {
    pub fn new() -> Fonts {
        let mut f = Fonts {
            fc: FontCollection::new(),
            prov: TypefaceFontProvider::new(),
            by_asset: HashMap::new(),
            has_fallback: false,
            epoch: 0,
        };
        f.fc.set_default_font_manager(FontMgr::default(), None);
        // V2-04 font fallback: a character the named faces lack (CJK, emoji, Arabic...) is drawn from a platform face
        // that has it instead of as a missing glyph (CoreText on the Mac, fontconfig on Linux runners)
        f.fc.enable_font_fallback();
        f.fc.set_asset_font_manager(Some(f.prov.clone().into()));
        f
    }

    fn register(&mut self, bytes: &[u8], family: &str) -> bool {
        let tf = FontMgr::new().new_from_data(Data::new_copy(bytes), None);
        let Some(tf) = tf else { return false };
        self.prov.register_typeface(tf, family);
        self.fc
            .set_asset_font_manager(Some(self.prov.clone().into()));
        self.epoch += 1;
        true
    }

    /// Register a font file under its library hash. Returns false when the bytes are not a usable font.
    pub fn add_font(&mut self, asset: &str, bytes: &[u8]) -> bool {
        let family = format!("asset-{asset}");
        let ok = self.register(bytes, &family);
        if ok {
            self.by_asset.insert(asset.to_string(), family);
        }
        ok
    }

    /// The face `system` (and any missing asset font) resolves to.
    pub fn set_fallback(&mut self, bytes: &[u8]) -> bool {
        let ok = self.register(bytes, FALLBACK);
        self.has_fallback |= ok;
        ok
    }

    /// Family names to try, in order, for a `type.font` value.
    pub(crate) fn families(&self, font: Option<&Value>) -> Vec<String> {
        let mut out = vec![];
        if let Some(a) = font
            .and_then(|f| f.get("asset"))
            .and_then(Value::as_str)
            .and_then(|a| self.by_asset.get(a))
        {
            out.push(a.clone());
        }
        if self.has_fallback {
            out.push(FALLBACK.to_string());
        } else {
            out.extend(
                [
                    "SF Pro",
                    ".AppleSystemUIFont",
                    "Helvetica Neue",
                    "Arial",
                    "DejaVu Sans",
                    "sans-serif",
                ]
                .map(String::from),
            );
        }
        out
    }

    /// Characters of `text` that no face draws, fallback included (`system` text at 14 pt): 0 when font fallback
    /// covers it. Tests, and the "metrics differ" check on runners.
    pub fn unresolved(&self, text: &str) -> usize {
        let mut ts = TextStyle::new();
        ts.set_font_families(&self.families(None));
        ts.set_font_size(14.0);
        let mut ps = ParagraphStyle::new();
        ps.set_text_style(&ts);
        let mut b = ParagraphBuilder::new(&ps, &self.fc);
        b.add_text(text);
        let mut p = b.build();
        p.layout(1.0e6);
        p.unresolved_glyphs().unwrap_or(0)
    }

    /// Does the design's font resolve to a file the host supplied? (`system` always does.)
    pub fn has_asset(&self, asset: &str) -> bool {
        self.by_asset.contains_key(asset)
    }
}
