//! `design.export`: one screen as an inert HTML/CSS package (V6-03). The model crate writes the page; this
//! side adds what only the renderer knows: a vector's path bounds, the screen's laid-out size (the viewport a shot
//! of it needs) and whether any text falls back to a font other than the one it names.

use ainkrad_proto::v2::{DesignExport, DesignExported};
use design_model::{ExportError, ExportOpts, Theme};
use skia_safe::Path;

use crate::ops::{load, metrics_differ, resolved, theme};

pub fn export(job: &DesignExport) -> Result<DesignExported, String> {
    let d = &job.doc;
    let open = theme(&d.theme)?;
    let (day, night) = (resolved(d, Theme::Day)?, resolved(d, Theme::Night)?);
    // ponytail: the path is parsed once per hugging vector; a document has few.
    let bounds = |p: &str| -> Option<(f32, f32)> {
        Path::from_svg(p).map(|p| {
            let b = p.compute_tight_bounds();
            (b.right.max(0.0), b.bottom.max(0.0))
        })
    };
    let mut o = ExportOpts::new(open);
    o.page = d.page as usize;
    o.screen = job.screen.as_deref();
    o.fallback_font = d.fallback_font.as_deref();
    o.path_bounds = Some(&bounds);
    let out = design_model::export(&day, &night, &o).map_err(|e| match e {
        ExportError::NoPage => "the design has no such page".to_owned(),
        ExportError::NoScreen => "the page has no such screen".to_owned(),
    })?;
    let (r, shown) = load(d)?;
    let rect = r
        .node_rect(&out.screen)
        .ok_or("no such screen on that page")?;
    let differ = shown
        .pages
        .get(d.page as usize)
        .and_then(|p| p.children.iter().find(|c| c.id == out.screen))
        .is_some_and(|s| metrics_differ(s, &r.fonts));
    Ok(DesignExported {
        screen: out.screen,
        html: out.html,
        css: out.css,
        fonts: out.fonts,
        images: out.images,
        width: rect.width().ceil() as u32,
        height: rect.height().ceil() as u32,
        metrics_differ: differ,
    })
}
