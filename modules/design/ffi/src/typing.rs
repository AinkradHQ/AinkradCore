//! Text editing on the canvas (V2-04), host side: an editing session (`text::Session`) on one text node, driven by
//! the App's `NSTextInputClient` (insert, marked text, commands) and the pointer, drawn as a caret / selection /
//! marked-text overlay from the node's laid-out Skia paragraph.
//!
//! Every write is one `splice` op through the document's validators (`design-doc`), as one batch; a run of typing
//! (or of deleting) joins one undo step. The text stays a plain string: no formatting ever goes into the yrs text.
//! The marked text is previewed on the node's board only (the gesture-preview path) and never reaches the CRDT
//! until it is committed. Offsets from the App are range-checked in `range_arg` and snapped in `text`.

use std::collections::HashMap;

use design_doc::Op;
use design_model::NodeType;
use design_render::Rect;
use serde_json::{Value, json};

use crate::ffi::*;
use crate::host::{Host, MAX_COORD, finite};
use crate::text::{self, Edit, Session, len16};

/// A UTF-16 range from the ABI: `DE_TEXT_NO_RANGE`, or a start and length in `0..=DE_MAX_TEXT_OFFSET`.
pub(crate) fn range_arg(start: i64, len: i64) -> Result<Option<(usize, usize)>, i32> {
    if start == DE_TEXT_NO_RANGE {
        return Ok(None);
    }
    let ok = |v: i64| (0..=DE_MAX_TEXT_OFFSET).contains(&v);
    if !ok(start) || !ok(len) {
        return Err(DE_ERR_ARG);
    }
    Ok(Some((start as usize, (start + len) as usize)))
}

impl Host {
    /// Leave editing when the edited node is gone or is no longer text; otherwise keep the caret on its characters
    /// (called whenever the document is read again: remote updates, undo, redo).
    pub(crate) fn rebase_text(&mut self) {
        let Some(s) = &self.text else { return };
        let now = self
            .model
            .as_ref()
            .and_then(|m| m.nodes.get(&s.id))
            .filter(|n| n.ty == NodeType::Text)
            .map(|n| n.text.clone().unwrap_or_default());
        match (now, self.text.as_mut()) {
            (Some(t), Some(s)) => s.rebase(&t),
            _ => self.text = None,
        }
    }

    /// Start editing the text node under view point (x, y), the caret at that point. `DE_ERR_INVALID`: no text there.
    pub fn text_begin(&mut self, x: f32, y: f32) -> Result<(), i32> {
        finite(&[x, y], MAX_COORD)?;
        self.text_end()?;
        self.cancel();
        self.refresh();
        let id = self.hit_doc(x, y).ok_or(DE_ERR_INVALID)?;
        let base = match self.model.as_ref().and_then(|m| m.nodes.get(&id)) {
            Some(n) if n.ty == NodeType::Text => n.text.clone().unwrap_or_default(),
            _ => return Err(DE_ERR_INVALID),
        };
        let (wx, wy) = self.camera.to_world(x, y);
        let at = self
            .renderer
            .as_ref()
            .and_then(|r| r.text_geo(&id))
            .map_or(len16(&base), |g| g.index_at(wx, wy));
        self.selection = vec![id.clone()];
        self.hover = None;
        self.text = Some(Session::new(id, base, at));
        self.refresh();
        Ok(())
    }

    /// Stop editing; marked text is committed first. Not editing: nothing happens.
    pub fn text_end(&mut self) -> Result<(), i32> {
        self.refresh();
        if self.text.is_none() {
            return Ok(());
        }
        let r = self.text_apply(Session::unmark);
        let ended = self.text.take();
        self.sync_preview();
        self.refresh();
        // a text node the text tool made and nobody typed into goes again
        let fresh = self.tools.fresh_text.take();
        let empty = |h: &Host, id: &str| {
            h.model
                .as_ref()
                .and_then(|m| m.nodes.get(id))
                .is_some_and(|n| {
                    n.ty == NodeType::Text && n.text.as_deref().unwrap_or_default().is_empty()
                })
        };
        if let (Some(f), Some(s)) = (fresh, ended)
            && f == s.id
            && empty(self, &f)
        {
            self.commit(&[Op::Delete { id: f }], &HashMap::new())?;
            self.refresh();
        }
        r
    }

    /// Run `f` on the session and write the splice it returns, if any (one batch).
    fn text_apply(&mut self, f: impl FnOnce(&mut Session) -> Option<Edit>) -> Result<(), i32> {
        // brings the session up to date with the document first (a remote update may have changed the text)
        self.refresh();
        let s = self.text.as_mut().ok_or(DE_ERR_INVALID)?;
        let last = s.last;
        let r = match f(s) {
            None => Ok(()),
            Some(e) => {
                let op = Op::Splice {
                    id: s.id.clone(),
                    at: e.at as u32,
                    del: e.del as u32,
                    text: e.text.clone(),
                };
                let r = self.commit_as(&[op], &HashMap::new(), Some(last == Some(e.kind)));
                if r.is_ok()
                    && let Some(s) = self.text.as_mut()
                {
                    s.applied(&e);
                }
                r
            }
        };
        self.sync_preview();
        self.refresh();
        r
    }

    /// `insertText(_:replacementRange:)`.
    pub fn text_insert(&mut self, t: &str, rep: Option<(usize, usize)>) -> Result<(), i32> {
        self.text_apply(|s| s.insert(t, rep))
    }

    /// `setMarkedText(_:selectedRange:replacementRange:)`; `sel` is inside `t`.
    pub fn text_set_marked(
        &mut self,
        t: &str,
        sel: (usize, usize),
        rep: Option<(usize, usize)>,
    ) -> Result<(), i32> {
        self.text_apply(|s| s.set_marked(t, sel, rep))
    }

    pub fn text_unmark(&mut self) -> Result<(), i32> {
        self.text_apply(Session::unmark)
    }

    /// The caret at composed offset `off`, world (valid after `refresh`).
    fn caret_at(&self, off: usize) -> Option<Rect> {
        let s = self.text.as_ref()?;
        let t = s.composed();
        let g = self.renderer.as_ref()?.text_geo(&s.id)?;
        let off = off.min(len16(&t));
        let after_nl = off > 0 && t.encode_utf16().nth(off - 1) == Some(u16::from(b'\n'));
        Some(g.caret(text::prev(&t, off), off, text::next(&t, off), after_nl))
    }

    /// The composed offset nearest world point (x, y).
    fn text_index(&self, wx: f32, wy: f32) -> usize {
        let Some(s) = &self.text else { return 0 };
        let t = s.composed();
        self.renderer
            .as_ref()
            .and_then(|r| r.text_geo(&s.id))
            .map_or(len16(&t), |g| text::snap(&t, g.index_at(wx, wy)))
    }

    /// `doCommand(by:)`: a `DE_TEXT_*` with `DE_MOD_*` bits. Marked text is committed first.
    pub fn text_command(&mut self, cmd: u32, mods: u32) -> Result<(), i32> {
        if !(DE_TEXT_LEFT..=DE_TEXT_NEWLINE).contains(&cmd) {
            return Err(DE_ERR_ARG);
        }
        self.text_apply(Session::unmark)?;
        let (shift, word, line) = (
            mods & DE_MOD_SHIFT != 0,
            mods & DE_MOD_OPTION != 0,
            mods & DE_MOD_COMMAND != 0,
        );
        let s = self.text.as_ref().ok_or(DE_ERR_INVALID)?;
        let (focus, len) = (s.focus, len16(&s.base));
        // geometry for the line and vertical moves
        let caret = self.caret_at(focus);
        let node = self.rect(&s.id);
        let goal = s.goal_x;
        let to_line_edge = |h: &Self, right: bool| {
            caret.map(|c| {
                h.text_index(
                    if right {
                        c.left + 1.0e6
                    } else {
                        c.left - 1.0e6
                    },
                    c.center_y(),
                )
            })
        };
        let vertical = |h: &Self, down: bool| {
            let (c, n) = (caret?, node?);
            let x = goal.unwrap_or(c.left);
            let y = if down { c.bottom + 1.0 } else { c.top - 1.0 };
            let to = if y < n.top {
                0
            } else if y > n.bottom {
                len
            } else {
                h.text_index(x, y)
            };
            Some((to, x))
        };
        let horizontal = matches!(cmd, DE_TEXT_LEFT | DE_TEXT_RIGHT);
        let vert = matches!(cmd, DE_TEXT_UP | DE_TEXT_DOWN);
        let edge = (horizontal && line)
            .then(|| to_line_edge(self, cmd == DE_TEXT_RIGHT))
            .flatten();
        let v = (vert && !line)
            .then(|| vertical(self, cmd == DE_TEXT_DOWN))
            .flatten();
        self.text_apply(|s| match cmd {
            DE_TEXT_LEFT | DE_TEXT_RIGHT if line => {
                s.move_to(
                    edge.unwrap_or(if cmd == DE_TEXT_RIGHT { len } else { 0 }),
                    shift,
                );
                None
            }
            DE_TEXT_LEFT | DE_TEXT_RIGHT => {
                s.step(cmd == DE_TEXT_RIGHT, word, shift);
                None
            }
            DE_TEXT_UP | DE_TEXT_DOWN => {
                let down = cmd == DE_TEXT_DOWN;
                let (to, x) = match (line, v) {
                    (false, Some(v)) => (v.0, Some(v.1)),
                    _ => (if down { len } else { 0 }, None),
                };
                s.move_to(to, shift);
                s.goal_x = x;
                None
            }
            DE_TEXT_DELETE_BACK => s.delete(false, word),
            DE_TEXT_DELETE_FORWARD => s.delete(true, word),
            DE_TEXT_SELECT_ALL => {
                s.select_all();
                None
            }
            _ => s.insert("\n", None),
        })
    }

    /// The pointer while editing: inside the text it places the caret (shift extends) and a drag selects; a press
    /// outside ends editing and is then handled as usual (`None`).
    pub(crate) fn text_pointer(
        &mut self,
        phase: u32,
        x: f32,
        y: f32,
        mods: u32,
    ) -> Option<Result<(), i32>> {
        let s = self.text.as_ref()?;
        let (wx, wy) = self.camera.to_world(x, y);
        match phase {
            DE_POINTER_DOWN => {
                let inside = self.rect(&s.id).is_some_and(|r| {
                    wx >= r.left && wx <= r.right && wy >= r.top && wy <= r.bottom
                });
                if !inside {
                    return self.text_end().err().map(Err);
                }
                if let Err(e) = self.text_apply(Session::unmark) {
                    return Some(Err(e));
                }
                let at = self.text_index(wx, wy);
                let s = self.text.as_mut()?;
                s.move_to(at, mods & DE_MOD_SHIFT != 0);
                s.selecting = true;
                Some(Ok(()))
            }
            DE_POINTER_MOVE if s.selecting => {
                let at = self.text_index(wx, wy);
                self.text.as_mut()?.move_to(at, true);
                Some(Ok(()))
            }
            DE_POINTER_UP if s.selecting => {
                self.text.as_mut()?.selecting = false;
                Some(Ok(()))
            }
            _ => None,
        }
    }

    /// Caret, selection and marked text for the overlay; the edited node keeps its outline, without handles.
    pub(crate) fn text_overlay(&self, o: &mut design_render::Overlay) {
        let Some(s) = &self.text else { return };
        o.bounds = None;
        o.hover = None;
        let Some(g) = self.renderer.as_ref().and_then(|r| r.text_geo(&s.id)) else {
            return;
        };
        let (a, b) = s.sel();
        if a == b {
            o.caret = self.caret_at(a);
        } else {
            o.text_selection = g.ranges(a, b);
        }
        if let Some((ma, mb)) = s.marked_range() {
            o.marked = g.ranges(ma, mb);
        }
    }

    /// The marked text as a preview op (drawn on its board, never written).
    pub(crate) fn marked_preview(&self) -> Option<Op> {
        let s = self.text.as_ref().filter(|s| s.marked.is_some())?;
        Some(Op::Text {
            id: s.id.clone(),
            text: s.composed(),
        })
    }

    // ---- queries ----------------------------------------------------------------------------------------------

    /// `{id, text, selection: [start, len], marked: [start, len] | null}` in the composed text, or `null`.
    pub fn text_state_json(&mut self) -> Vec<u8> {
        self.refresh();
        let v = match &self.text {
            None => Value::Null,
            Some(s) => {
                let (a, b) = s.sel();
                json!({"id": s.id, "text": s.composed(), "selection": [a, b - a],
                       "marked": s.marked_range().map(|(a, b)| [a, b - a])})
            }
        };
        v.to_string().into_bytes()
    }

    /// `firstRect(forCharacterRange:actualRange:)`: `{rect: [x, y, w, h] in view points, range: [start, len]}`.
    pub fn text_first_rect_json(&mut self, start: i64, len: i64) -> Result<Vec<u8>, i32> {
        let (a, b) = range_arg(start, len)?.ok_or(DE_ERR_ARG)?;
        self.refresh();
        let s = self.text.as_ref().ok_or(DE_ERR_INVALID)?;
        let t = s.composed();
        let a = text::snap(&t, a);
        let b = text::snap(&t, b).max(a);
        let g = self
            .renderer
            .as_ref()
            .and_then(|r| r.text_geo(&s.id))
            .ok_or(DE_ERR_INVALID)?;
        let after_nl = a > 0 && t.encode_utf16().nth(a - 1) == Some(u16::from(b'\n'));
        let r = g.first_rect(text::prev(&t, a), a, b, after_nl);
        let (l, top) = self.camera.to_screen(r.left, r.top);
        let (rr, bot) = self.camera.to_screen(r.right, r.bottom);
        Ok(
            json!({"rect": [l, top, rr - l, bot - top], "range": [a, b - a]})
                .to_string()
                .into_bytes(),
        )
    }

    /// `characterIndex(for:)`: the composed offset nearest view point (x, y).
    pub fn text_index_at(&mut self, x: f32, y: f32) -> Result<i32, i32> {
        finite(&[x, y], MAX_COORD)?;
        self.refresh();
        if self.text.is_none() {
            return Err(DE_ERR_INVALID);
        }
        let (wx, wy) = self.camera.to_world(x, y);
        Ok(self.text_index(wx, wy) as i32)
    }
}
