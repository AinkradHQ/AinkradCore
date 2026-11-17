//! The document ops on the render crate's CPU backend, and the font check.

use ainkrad_proto::v2::{
    DESIGN_MAX_PIXELS, DESIGN_MAX_PNG, DESIGN_MAX_SIDE, DesignBox, DesignBoxes, DesignCheck,
    DesignChecked, DesignDoc, DesignFinding, DesignFindings, DesignImage, DesignRender,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use design_model::{Doc, Resolved, ResolvedNode, Theme, limits, resolve};
use design_render::{Assets, Camera, Config, Fonts, Renderer, cpu};
use skia_safe::textlayout::{
    FontCollection, ParagraphBuilder, ParagraphStyle, TextStyle, TypefaceFontProvider,
};
use skia_safe::{Data, FontMgr, Rect};

/// An image whose header claims more than this is never decoded (a decompression bomb).
const IMAGE_MAX_SIDE: i32 = 16_384;
const IMAGE_MAX_PIXELS: i64 = 64 << 20;
const MAX_FINDINGS: usize = 500;

fn b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

/// Whether `b` is an image whose header the renderer may decode: a format Skia knows and a size
/// under the caps. Reads only the header (`from_encoded` is lazy).
pub fn image_ok(b: &[u8]) -> bool {
    skia_safe::Image::from_encoded(Data::new_copy(b)).is_some_and(|i| {
        let (w, h) = (i.width(), i.height());
        (1..=IMAGE_MAX_SIDE).contains(&w)
            && (1..=IMAGE_MAX_SIDE).contains(&h)
            && i64::from(w) * i64::from(h) <= IMAGE_MAX_PIXELS
    })
}

fn theme(t: &str) -> Result<Theme, String> {
    match t {
        "day" => Ok(Theme::Day),
        "night" => Ok(Theme::Night),
        _ => Err("the theme is day or night".into()),
    }
}

/// The document resolved and laid out, with the job's fonts and the images that pass `image_ok`.
fn load(d: &DesignDoc) -> Result<(Renderer, Resolved), String> {
    let doc: Doc =
        serde_json::from_value(d.doc.clone()).map_err(|_| "the design is not a valid document")?;
    let system: Option<Doc> = match &d.system {
        Some(s) => Some(
            serde_json::from_value(s.clone()).map_err(|_| "the system is not a valid document")?,
        ),
        None => None,
    };
    let sys = d.system_id.as_deref().zip(system.as_ref());
    let resolved = resolve(&d.doc_id, &doc, sys, theme(&d.theme)?)
        .map_err(|e| format!("the design does not resolve: {e:?}"))?;
    let mut fonts = Fonts::new();
    for f in &d.fonts {
        let Some(bytes) = b64(&f.data) else { continue };
        if d.fallback_font.as_deref() == Some(f.sha256.as_str()) {
            fonts.set_fallback(&bytes);
        }
        fonts.add_font(&f.sha256, &bytes);
    }
    let mut assets = Assets::default();
    for i in &d.images {
        match b64(&i.data) {
            Some(bytes) if image_ok(&bytes) => assets.add(&i.sha256, &bytes),
            _ => {}
        }
    }
    let mut r = Renderer::new(fonts, assets);
    // A shot is for fidelity: no level of detail, every material drawn in full.
    r.cfg = Config {
        blur_below: 0.0,
        bars_below: 0.0,
        boxes_below: 0.0,
        ..Config::default()
    };
    r.load(&resolved, d.page as usize);
    Ok((r, resolved))
}

/// Text whose font is not a library file the job supplied: laid out with a fallback (plan Q2).
fn metrics_differ(n: &ResolvedNode, fonts: &Fonts) -> bool {
    let asset = n
        .props
        .get("type")
        .and_then(|t| t.get("font"))
        .and_then(|f| f.get("asset"))
        .and_then(|a| a.as_str());
    (n.text.is_some() && !asset.is_some_and(|a| fonts.has_asset(a)))
        || n.children.iter().any(|c| metrics_differ(c, fonts))
}

pub fn render(job: &DesignRender) -> Result<DesignImage, String> {
    let (mut r, resolved) = load(&job.doc)?;
    let rect = match &job.node {
        Some(id) => r.node_rect(id).ok_or("no such node on that page")?,
        None => r.world_bounds().ok_or("the page is empty")?,
    };
    let s = job.scale;
    if !(0.25..=4.0).contains(&s) {
        return Err("the scale is 0.25 to 4".into());
    }
    let (w, h) = (
        (rect.width() * s).ceil() as u64,
        (rect.height() * s).ceil() as u64,
    );
    let side = u64::from(DESIGN_MAX_SIDE);
    if w == 0 || h == 0 || w > side || h > side || w * h > DESIGN_MAX_PIXELS {
        return Err("the image would be too large; use a smaller scale".into());
    }
    r.set_camera(Camera {
        zoom: 1.0,
        pan: (-rect.left, -rect.top),
        view: (rect.width(), rect.height()),
        scale: s,
    });
    let png = cpu::render_png(&mut r);
    if png.is_empty() || png.len() > DESIGN_MAX_PNG {
        return Err("the image could not be made within the size limit".into());
    }
    let differ = resolved
        .pages
        .get(job.doc.page as usize)
        .is_some_and(|p| metrics_differ(p, &r.fonts));
    Ok(DesignImage {
        png: STANDARD.encode(&png),
        width: w as u32,
        height: h as u32,
        metrics_differ: differ,
    })
}

pub fn measure(d: &DesignDoc) -> Result<DesignBoxes, String> {
    let (r, _) = load(d)?;
    let mut nodes = Vec::new();
    for (o, laid) in r.boards() {
        for n in &laid.nodes {
            if nodes.len() >= limits::MAX_RESOLVED_NODES {
                break;
            }
            let b = n.rect.with_offset(o);
            nodes.push(DesignBox {
                id: n.id.clone(),
                x: b.left,
                y: b.top,
                w: b.width(),
                h: b.height(),
            });
        }
    }
    Ok(DesignBoxes { nodes })
}

/// `inner` lies inside `outer`, give or take half a point.
fn inside(inner: Rect, outer: Rect) -> bool {
    inner.left >= outer.left - 0.5
        && inner.top >= outer.top - 0.5
        && inner.right <= outer.right + 0.5
        && inner.bottom <= outer.bottom + 0.5
}

/// Geometry findings: a child outside its parent's box, text that does not fit its box.
pub fn review(d: &DesignDoc) -> Result<DesignFindings, String> {
    let (r, _) = load(d)?;
    let mut findings = Vec::new();
    let mut add = |rule: &str, node: &str, msg: String| {
        if findings.len() < MAX_FINDINGS {
            findings.push(DesignFinding {
                rule: rule.into(),
                node: node.into(),
                msg,
            });
        }
    };
    for (_, laid) in r.boards() {
        for n in &laid.nodes {
            for &k in &n.kids {
                let Some(c) = laid.nodes.get(k as usize) else {
                    continue;
                };
                if !inside(c.rect, n.rect) {
                    add(
                        "geometry.outside",
                        &c.id,
                        format!("the node extends outside its parent {}", n.id),
                    );
                }
            }
            if let Some(p) = &n.para
                && (p.height() > n.rect.height() + 0.5 || p.longest_line() > n.rect.width() + 0.5)
            {
                add(
                    "geometry.text_overflow",
                    &n.id,
                    "the text does not fit its box".into(),
                );
            }
        }
    }
    Ok(DesignFindings { findings })
}

fn refused(why: &str) -> DesignChecked {
    DesignChecked {
        ok: false,
        reason: Some(why.into()),
    }
}

pub fn check(c: &DesignCheck) -> DesignChecked {
    let Some(bytes) = b64(&c.data) else {
        return refused("the file is not base64");
    };
    let r = match c.kind.as_str() {
        "font" => check_font(&bytes),
        "icon_composer" => crate::icon::check(&bytes),
        _ => Err("the kind is font or icon_composer"),
    };
    match r {
        Ok(()) => DesignChecked {
            ok: true,
            reason: None,
        },
        Err(why) => refused(why),
    }
}

/// A font is usable when Skia reads it, it has glyphs and a family, and text lays out with it.
pub fn check_font(bytes: &[u8]) -> Result<(), &'static str> {
    let tf = FontMgr::new()
        .new_from_data(Data::new_copy(bytes), None)
        .ok_or("the file is not a font this renderer can read")?;
    if tf.count_glyphs() == 0 {
        return Err("the font has no glyphs");
    }
    if tf.family_name().trim().is_empty() {
        return Err("the font has no family name");
    }
    let mut prov = TypefaceFontProvider::new();
    prov.register_typeface(tf, "check");
    let mut fc = FontCollection::new();
    fc.set_asset_font_manager(Some(prov.into()));
    let mut ts = TextStyle::new();
    ts.set_font_families(&["check"]);
    ts.set_font_size(16.0);
    let mut ps = ParagraphStyle::new();
    ps.set_text_style(&ts);
    let mut b = ParagraphBuilder::new(&ps, fc);
    b.add_text("Hamburgefonstiv 0123456789 ÀÉÎõü fi ffl — “quotes”");
    let mut p = b.build();
    p.layout(400.0);
    if !(p.height() > 0.0 && p.longest_line() > 0.0) {
        return Err("text does not lay out with the font");
    }
    Ok(())
}
