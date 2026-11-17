//! The engine host, safe Rust: everything a C call does after `ffi.rs` has validated and copied its arguments.
//! Every method returns a `DE_*` code on refusal; nothing here trusts a value it did not check.

use design_doc::{Error, Live, parse_ops};
use design_model::ids::{is_doc_id, is_sha256};
use std::collections::HashSet;

use design_model::tree::forest;
use design_model::{Doc, Forest, Resolved, Theme, resolve};
use design_render::{Assets, Camera, Fonts, Renderer};
use serde_json::{Value, json};

use crate::ffi::*;

/// View size in points, backing scale, coordinates and pan: anything outside is refused as a bad argument.
pub(crate) const MAX_VIEW: f32 = 16_384.0;
pub(crate) const MAX_SCALE: f32 = 8.0;
pub(crate) const MAX_COORD: f32 = 1.0e7;
pub(crate) const MAX_FONT_BYTES: usize = 25 << 20;
pub(crate) const MAX_ASSET_BYTES: usize = 25 << 20;
/// Raw asset and font bytes the host keeps in total (decoded images have their own cap in `Assets`).
pub(crate) const MAX_HELD_BYTES: usize = 512 << 20;
pub(crate) const MAX_FONTS: usize = 256;
/// Ancestor walks stop here (the model caps depth at 64; the effective tree has no cycles).
pub(crate) const MAX_DEPTH_WALK: usize = 256;

pub fn code(e: Error) -> i32 {
    match e {
        Error::TooLarge => DE_ERR_TOO_LARGE,
        Error::Malformed(_) | Error::Refused(_) => DE_ERR_INVALID,
    }
}

pub(crate) fn finite(v: &[f32], lim: f32) -> Result<(), i32> {
    if v.iter().all(|x| x.is_finite() && x.abs() <= lim) {
        Ok(())
    } else {
        Err(DE_ERR_ARG)
    }
}

pub struct Host {
    doc_id: String,
    pub(crate) live: Live,
    system: Live,
    /// The document as last read out of `live` (None = changed since), and its tree.
    pub(crate) model: Option<Doc>,
    pub(crate) tree: Option<Forest>,
    /// The resolved document the renderer last loaded (gesture previews patch its boards).
    pub(crate) resolved: Option<Resolved>,
    pub(crate) camera: Camera,
    theme: Theme,
    pub(crate) page: usize,
    pub(crate) selection: Vec<String>,
    pub(crate) renderer: Option<Renderer>,
    loaded: bool,
    pub(crate) gesture: Option<crate::interact::Gesture>,
    pub(crate) hover: Option<String>,
    /// Rubber-band settle target (pan).
    pub(crate) settle: Option<(f32, f32)>,
    /// Boards the current preview changed (to put back).
    pub(crate) previewed: HashSet<String>,
    pub(crate) rng: u64,
    held: usize,
    fonts: usize,
    #[cfg(all(feature = "metal", target_os = "macos"))]
    pub(crate) metal: Option<design_render::metal::Metal>,
}

impl Host {
    pub fn new(doc_id: &str) -> Result<Host, i32> {
        if !is_doc_id(doc_id) {
            return Err(DE_ERR_INVALID);
        }
        Ok(Host {
            doc_id: doc_id.to_string(),
            live: Live::new(),
            system: Live::new(),
            model: None,
            tree: None,
            resolved: None,
            camera: Camera::default(),
            theme: Theme::Day,
            page: 0,
            selection: vec![],
            renderer: None,
            loaded: false,
            gesture: None,
            hover: None,
            settle: None,
            previewed: HashSet::new(),
            rng: crate::edits::seed(),
            held: 0,
            fonts: 0,
            #[cfg(all(feature = "metal", target_os = "macos"))]
            metal: None,
        })
    }

    pub(crate) fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub(crate) fn changed(&mut self) {
        self.model = None;
        self.tree = None;
        self.loaded = false;
    }

    fn model(&mut self) -> &Doc {
        if self.model.is_none() {
            let d = self.live.read();
            self.selection.retain(|id| d.nodes.contains_key(id));
            if self
                .hover
                .as_ref()
                .is_some_and(|h| !d.nodes.contains_key(h))
            {
                self.hover = None;
            }
            self.tree = Some(forest(&d));
            self.model = Some(d);
        }
        self.model.get_or_insert_with(Doc::default)
    }

    // ---- sync -------------------------------------------------------------------------------------------------

    pub fn sync_apply(&mut self, target: u32, bytes: &[u8]) -> Result<(), i32> {
        match target {
            DE_DOC => self.live.apply_remote(bytes),
            DE_SYSTEM => self.system.apply_remote(bytes),
            _ => return Err(DE_ERR_ARG),
        }
        .map_err(code)?;
        self.changed();
        Ok(())
    }

    pub fn state_vector(&self) -> Vec<u8> {
        self.live.state_vector()
    }

    pub fn diff(&self, sv: &[u8]) -> Result<Vec<u8>, i32> {
        self.live.diff(sv).map_err(code)
    }

    pub fn outbox(&self, take: bool) -> Vec<u8> {
        self.live.outbox(take)
    }

    // ---- edits ------------------------------------------------------------------------------------------------

    pub fn edit(&mut self, json: &[u8]) -> Result<(), i32> {
        let ops = parse_ops(json).map_err(code)?;
        self.live.apply_ops(&ops).map_err(code)?;
        self.changed();
        Ok(())
    }

    /// `true` when something was undone / redone.
    pub fn undo(&mut self, redo: bool) -> bool {
        self.cancel();
        let did = if redo {
            self.live.redo()
        } else {
            self.live.undo()
        };
        if did {
            self.changed();
        }
        did
    }

    fn delete_selection(&mut self) -> Result<(), i32> {
        self.refresh();
        // a node under another selected node goes with it; deleting it again would refuse the batch
        let ops: Vec<Value> = self
            .top_selected()
            .iter()
            .map(|id| json!({"op": "delete", "id": id}))
            .collect();
        if ops.is_empty() {
            return Ok(());
        }
        self.edit(Value::Array(ops).to_string().as_bytes())?;
        self.selection.clear();
        Ok(())
    }

    // ---- presence ---------------------------------------------------------------------------------------------

    pub fn presence_set(&mut self, json: &str) -> Result<(), i32> {
        self.live.presence().set_local(json).map_err(code)
    }

    pub fn presence_encode(&mut self) -> Vec<u8> {
        self.live.presence().encode_local()
    }

    pub fn presence_apply(&mut self, bytes: &[u8]) -> Result<(), i32> {
        self.live.presence().apply(bytes).map_err(code)
    }

    pub fn presence_peers(&mut self) -> Vec<u8> {
        self.live.presence().peers().to_string().into_bytes()
    }

    // ---- view + input -----------------------------------------------------------------------------------------

    pub fn resize(&mut self, w: f32, h: f32, scale: f32) -> Result<(), i32> {
        if !(w > 0.0
            && w <= MAX_VIEW
            && h > 0.0
            && h <= MAX_VIEW
            && scale > 0.0
            && scale <= MAX_SCALE)
        {
            return Err(DE_ERR_ARG);
        }
        self.camera.view = (w, h);
        self.camera.scale = scale;
        Ok(())
    }

    pub fn set_theme(&mut self, night: bool) {
        self.theme = if night { Theme::Night } else { Theme::Day };
        self.loaded = false;
    }

    pub fn set_page(&mut self, page: u32) {
        self.page = page as usize;
        self.loaded = false;
    }

    /// Frame the selection (everything when nothing is selected).
    pub fn fit_selection(&mut self) {
        self.refresh();
        let ids = self.top_selected();
        match crate::interact::union(ids.iter().filter_map(|id| self.rect(id))) {
            Some(r) => {
                self.settle = None;
                self.camera.fit(r, 0.1);
            }
            None => self.fit(),
        }
    }

    pub fn fit(&mut self) {
        self.settle = None;
        self.refresh();
        if let Some(r) = self.renderer.as_mut() {
            r.set_camera(self.camera);
            r.fit_all();
            self.camera = r.camera;
        }
    }

    pub fn magnify(&mut self, factor: f32, x: f32, y: f32) -> Result<(), i32> {
        finite(&[x, y], MAX_COORD)?;
        if !(factor.is_finite() && factor > 0.0 && factor <= 100.0) {
            return Err(DE_ERR_ARG);
        }
        self.settle = None;
        let before = self.camera;
        self.camera.zoom_at(factor, x, y);
        if finite(&[self.camera.pan.0, self.camera.pan.1], MAX_COORD).is_err() {
            self.camera = before;
            return Err(DE_ERR_ARG);
        }
        Ok(())
    }

    pub fn key(&mut self, key: u32, mods: u32) -> Result<(), i32> {
        let step = if mods & DE_MOD_SHIFT != 0 { 10.0 } else { 1.0 };
        // a press that has not moved yet is not a gesture to protect; a drag is (keys wait for its end)
        if matches!(self.gesture, Some(crate::interact::Gesture::Press { .. })) {
            self.gesture = None;
        }
        if key != DE_KEY_ESCAPE && self.gesture.is_some() {
            return Ok(());
        }
        match key {
            DE_KEY_DELETE => self.delete_selection(),
            DE_KEY_ESCAPE => {
                if !self.cancel() {
                    self.selection.clear();
                }
                Ok(())
            }
            DE_KEY_DUPLICATE => self.duplicate(),
            DE_KEY_LEFT => self.nudge(-step, 0.0),
            DE_KEY_RIGHT => self.nudge(step, 0.0),
            DE_KEY_UP => self.nudge(0.0, -step),
            DE_KEY_DOWN => self.nudge(0.0, step),
            _ => Ok(()),
        }
    }

    // ---- queries ----------------------------------------------------------------------------------------------

    pub fn selection_json(&mut self) -> Vec<u8> {
        self.model();
        json!(self.selection).to_string().into_bytes()
    }

    /// One node for the inspector, or `null`.
    pub fn node_json(&mut self, id: &str) -> Vec<u8> {
        let v = match self.model().nodes.get(id) {
            Some(n) => {
                json!({"id": id, "type": n.ty, "parent": n.parent, "order": n.order, "name": n.name,
                              "props": n.props, "text": n.text})
            }
            None => Value::Null,
        };
        v.to_string().into_bytes()
    }

    fn hit(&mut self, x: f32, y: f32) -> Option<(String, Value)> {
        self.refresh();
        let r = self.renderer.as_mut()?;
        r.set_camera(self.camera);
        let h = r.hit(x, y)?;
        Some((
            h.id.clone(),
            json!({"id": h.id, "artboard": h.artboard, "path": h.path}),
        ))
    }

    pub fn hit_json(&mut self, x: f32, y: f32) -> Result<Vec<u8>, i32> {
        finite(&[x, y], MAX_COORD)?;
        Ok(self
            .hit(x, y)
            .map_or(Value::Null, |h| h.1)
            .to_string()
            .into_bytes())
    }

    // ---- fonts + assets ---------------------------------------------------------------------------------------

    fn hold(&mut self, n: usize) -> Result<(), i32> {
        if self.held + n > MAX_HELD_BYTES {
            return Err(DE_ERR_TOO_LARGE);
        }
        self.held += n;
        Ok(())
    }

    /// `asset` = the font's library hash; an empty `asset` sets the fallback (what `system` draws with).
    pub fn font_add(&mut self, asset: &str, bytes: &[u8]) -> Result<(), i32> {
        if bytes.len() > MAX_FONT_BYTES || self.fonts >= MAX_FONTS {
            return Err(DE_ERR_TOO_LARGE);
        }
        if !asset.is_empty() && !is_sha256(asset) {
            return Err(DE_ERR_ARG);
        }
        self.hold(bytes.len())?;
        self.fonts += 1;
        let f = &mut self.renderer().fonts;
        let ok = if asset.is_empty() {
            f.set_fallback(bytes)
        } else {
            f.add_font(asset, bytes)
        };
        self.loaded = false;
        if ok { Ok(()) } else { Err(DE_ERR_INVALID) }
    }

    pub fn asset_add(&mut self, hash: &str, bytes: &[u8]) -> Result<(), i32> {
        if bytes.len() > MAX_ASSET_BYTES {
            return Err(DE_ERR_TOO_LARGE);
        }
        if !is_sha256(hash) {
            return Err(DE_ERR_ARG);
        }
        self.hold(bytes.len())?;
        self.renderer().assets.add(hash, bytes);
        Ok(())
    }

    /// Asset hashes the last frames wanted and did not have: the host fetches them from the Core.
    pub fn missing_json(&mut self) -> Vec<u8> {
        let m = self
            .renderer
            .as_ref()
            .map(|r| r.missing.clone())
            .unwrap_or_default();
        json!(m).to_string().into_bytes()
    }

    // ---- frames -----------------------------------------------------------------------------------------------

    pub(crate) fn renderer(&mut self) -> &mut Renderer {
        self.renderer
            .get_or_insert_with(|| Renderer::new(Fonts::new(), Assets::default()))
    }

    /// Bring the renderer up to date with the document, theme, page and camera.
    pub(crate) fn refresh(&mut self) {
        if !self.loaded {
            let doc = self.model().clone();
            let sys_doc = self.system.read();
            let sys = doc.meta.system.clone();
            let (doc_id, theme, page) = (self.doc_id.clone(), self.theme, self.page);
            let resolved =
                resolve(&doc_id, &doc, sys.as_deref().map(|s| (s, &sys_doc)), theme).ok();
            let r = self.renderer();
            match &resolved {
                Some(res) => {
                    r.load(res, page);
                }
                None => r.invalidate_all(),
            }
            self.resolved = resolved;
            self.loaded = true;
            // the renderer holds the document as it is now; a gesture in progress is shown over it again
            self.previewed.clear();
            self.sync_preview();
        }
        let cam = self.camera;
        self.renderer().set_camera(cam);
        let o = self.overlay();
        self.renderer().set_overlay(o);
    }

    /// Up-to-date renderer and the attached Metal context, or `None` when nothing is attached.
    #[cfg(all(feature = "metal", target_os = "macos"))]
    pub(crate) fn with_metal<T>(
        &mut self,
        f: impl FnOnce(&mut design_render::metal::Metal, &mut Renderer) -> T,
    ) -> Option<T> {
        self.metal.as_ref()?;
        self.refresh();
        Some(f(self.metal.as_mut()?, self.renderer.as_mut()?))
    }

    pub fn needs_frame(&mut self) -> bool {
        self.refresh();
        self.renderer().needs_frame()
    }

    pub(crate) fn import(&mut self, doc: &Doc, system: &Doc) {
        self.live.import(doc);
        self.system.import(system);
        self.changed();
    }

    /// One full frame at the view size (benches): Metal offscreen or CPU raster, in µs.
    pub(crate) fn bench_frame(&mut self, metal: bool) -> Option<i32> {
        self.refresh();
        let t = std::time::Instant::now();
        #[cfg(all(feature = "metal", target_os = "macos"))]
        if metal {
            let m = match self.metal.as_mut() {
                Some(m) => m,
                None => self
                    .metal
                    .insert(design_render::metal::Metal::system_default()?),
            };
            m.render_offscreen(self.renderer.as_mut()?)?;
            return Some(t.elapsed().as_micros() as i32);
        }
        if metal {
            return None;
        }
        design_render::cpu::render(self.renderer())?;
        Some(t.elapsed().as_micros() as i32)
    }

    /// Draw one CPU frame at most 256 x 256 px (tests and the fuzz target exercise the draw path with it).
    pub fn draw_cpu(&mut self, w: i32, h: i32) -> bool {
        self.refresh();
        let r = self.renderer();
        let cam = r.camera;
        let mut small = cam;
        small.view = (w.clamp(1, 256) as f32, h.clamp(1, 256) as f32);
        small.scale = 1.0;
        r.set_camera(small);
        let ok = design_render::cpu::render(r).is_some();
        r.set_camera(cam);
        ok
    }
}
