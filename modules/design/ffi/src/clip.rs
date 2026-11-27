//! Structure edits the App drives from menus and shortcuts: copy / paste (⌘C ⌘V, across documents through
//! NSPasteboard), group / ungroup, components (create from the selection, insert an instance, detach one). Each is
//! one `commit` batch, one undo step, validated by the document crate like any other edit.
//!
//! Clipboard JSON (`de_copy` out, `de_paste` in), ids left out so a paste always makes fresh ones:
//! `{"format": "ainkrad-design/1", "doc": "dd_...", "nodes": [{"type", "name", "props", "text"?, "at": [x, y],
//! "children": [...]}]}`; `at` (roots only) is the root's world top-left when it was copied.

use std::collections::HashMap;

use design_doc::Op;
use design_model::ids::{between, is_node_id, parse_component_ref};
use design_model::tree::forest;
use design_model::{Doc, NodeType};
use serde_json::{Map, Value, json};

use crate::codes::*;
use crate::host::{Host, MAX_COORD, finite};
use crate::interact::union;
use crate::snap::round2;

pub const CLIP_FORMAT: &str = "ainkrad-design/1";
/// Nesting a clipboard node may have (the model's own depth cap).
const MAX_CLIP_DEPTH: usize = design_model::limits::MAX_DEPTH;

fn set(id: &str, key: &str, value: Value) -> Op {
    Op::Set {
        id: id.into(),
        key: key.into(),
        value,
    }
}

/// `{type, name, props, text?, children}` of `id`'s subtree in `d` (children in order), depth-capped.
fn subtree(d: &Doc, kids: &dyn Fn(&str) -> Vec<String>, id: &str, depth: usize) -> Value {
    let Some(n) = d.nodes.get(id) else {
        return Value::Null;
    };
    let children: Vec<Value> = if depth < MAX_CLIP_DEPTH {
        kids(id)
            .iter()
            .map(|k| subtree(d, kids, k, depth + 1))
            .collect()
    } else {
        vec![]
    };
    let mut v = json!({"type": n.ty, "name": n.name, "props": n.props, "children": children});
    if let Some(t) = &n.text {
        v["text"] = json!(t);
    }
    v
}

impl Host {
    fn last_order(&self, parent: &str) -> Option<String> {
        let last = self.kids(parent).last().and_then(|k| self.order_of(k));
        between(last.as_deref(), None)
    }

    /// The order right after sibling `id` (before the one after it).
    fn order_after(&self, id: &str) -> Option<String> {
        let p = self.parent_of(id)?;
        let kids = self.kids(&p);
        let next = kids
            .iter()
            .position(|k| k == id)
            .and_then(|i| kids.get(i + 1))
            .and_then(|k| self.order_of(k));
        between(self.order_of(id).as_deref(), next.as_deref())
    }

    /// Write a structure batch and select `sel`. A full re-read afterwards: these batches add instances and whole
    /// subtrees, which the gesture-preview patch is not meant to follow.
    fn write_and_select(&mut self, ops: &[Op], sel: Vec<String>) -> Result<(), i32> {
        if ops.is_empty() {
            return Err(DE_ERR_INVALID);
        }
        let r = self.commit(ops, &HashMap::new());
        self.changed();
        r?;
        self.selection = sel;
        self.refresh();
        Ok(())
    }

    fn container(&self, id: &str) -> bool {
        self.model
            .as_ref()
            .and_then(|m| m.nodes.get(id))
            .is_some_and(|n| n.ty.is_container())
    }

    // ---- clipboard ----------------------------------------------------------------------------------------------

    /// The clipboard JSON of `ids` (empty: the selection); nodes inside another copied node go with it. Pages and
    /// unknown ids are `DE_ERR_INVALID`; more than `DE_MAX_CLIP_BYTES` is `DE_ERR_TOO_LARGE`.
    pub fn copy_json(&mut self, ids_json: &[u8]) -> Result<Vec<u8>, i32> {
        self.refresh();
        let ids: Vec<String> = if ids_json.is_empty() {
            self.selection.clone()
        } else {
            serde_json::from_slice(ids_json).map_err(|_| DE_ERR_INVALID)?
        };
        if ids.len() > DE_MAX_SELECT_IDS {
            return Err(DE_ERR_TOO_LARGE);
        }
        let m = self.model.clone().unwrap_or_default();
        if ids
            .iter()
            .any(|i| m.nodes.get(i).is_none_or(|n| n.ty == NodeType::Page))
        {
            return Err(DE_ERR_INVALID);
        }
        let saved = std::mem::replace(&mut self.selection, ids);
        let tops = self.top_selected();
        self.selection = saved;
        let kids = |id: &str| self.kids(id);
        let nodes: Vec<Value> = tops
            .iter()
            .map(|id| {
                let mut v = subtree(&m, &kids, id, 0);
                if let Some(r) = self.rect(id) {
                    v["at"] = json!([r.left, r.top]);
                }
                v
            })
            .collect();
        let out = json!({"format": CLIP_FORMAT, "doc": self.doc_id, "nodes": nodes}).to_string();
        if out.len() > DE_MAX_CLIP_BYTES {
            return Err(DE_ERR_TOO_LARGE);
        }
        Ok(out.into_bytes())
    }

    /// Paste clipboard JSON into `parent` (empty: the page) with new ids, as one undo step, and select the pasted
    /// roots. They keep their world position, or with `at` (view point) the pasted bounds' top-left goes there.
    /// In an auto-layout parent they are appended to the flow.
    pub fn paste(&mut self, json: &[u8], parent: &str, at: Option<(f32, f32)>) -> Result<(), i32> {
        if let Some(p) = at {
            finite(&[p.0, p.1], MAX_COORD)?;
        }
        let clip: Value = serde_json::from_slice(json).map_err(|_| DE_ERR_INVALID)?;
        if clip.get("format").and_then(Value::as_str) != Some(CLIP_FORMAT) {
            return Err(DE_ERR_INVALID);
        }
        let roots = clip
            .get("nodes")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
            .ok_or(DE_ERR_INVALID)?;
        self.text_end()?;
        self.cancel();
        self.refresh();
        let parent = if parent.is_empty() {
            self.page_id().ok_or(DE_ERR_INVALID)?
        } else {
            parent.to_string()
        };
        if !self.container(&parent) {
            return Err(DE_ERR_INVALID);
        }
        let xy = |v: &Value| -> (f32, f32) {
            let a = v.get("at");
            let g = |i: usize| {
                a.and_then(|a| a.get(i))
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0) as f32
            };
            (g(0), g(1))
        };
        let min = roots
            .iter()
            .map(xy)
            .reduce(|a, b| (a.0.min(b.0), a.1.min(b.1)))
            .unwrap_or_default();
        let shift = match at {
            Some(p) => {
                let w = self.camera.to_world(p.0, p.1);
                (w.0 - min.0, w.1 - min.1)
            }
            None => (0.0, 0.0),
        };
        let (o, flow) = (self.origin(&parent), self.is_flow(&parent));
        let mut lo = self.kids(&parent).last().and_then(|k| self.order_of(k));
        let (mut ops, mut sel) = (vec![], vec![]);
        for r in roots {
            let ord = between(lo.as_deref(), None).ok_or(DE_ERR_INVALID)?;
            lo = Some(ord.clone());
            let root = ops.len();
            let id = self.paste_node(r, &parent, ord, 0, &mut ops)?;
            if let Some(Op::Add { props, .. }) = ops.get_mut(root) {
                if flow {
                    props.remove("x");
                    props.remove("y");
                } else {
                    let (x, y) = xy(r);
                    props.insert("x".into(), json!(round2(x + shift.0 - o.0)));
                    props.insert("y".into(), json!(round2(y + shift.1 - o.1)));
                }
            }
            sel.push(id);
        }
        if ops.len() > design_doc::MAX_GESTURE_OPS {
            return Err(DE_ERR_TOO_LARGE);
        }
        self.write_and_select(&ops, sel)
    }

    /// `add` ops for one clipboard node and its children (parents first); its new id.
    fn paste_node(
        &mut self,
        v: &Value,
        parent: &str,
        order: String,
        depth: usize,
        ops: &mut Vec<Op>,
    ) -> Result<String, i32> {
        if depth > MAX_CLIP_DEPTH || ops.len() > design_doc::MAX_GESTURE_OPS {
            return Err(DE_ERR_TOO_LARGE);
        }
        let ty: NodeType = serde_json::from_value(v.get("type").cloned().unwrap_or_default())
            .map_err(|_| DE_ERR_INVALID)?;
        let id = self.new_id();
        ops.push(Op::Add {
            id: id.clone(),
            ty,
            parent: Some(parent.to_string()),
            order,
            name: v
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            props: v
                .get("props")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            text: v.get("text").and_then(Value::as_str).map(str::to_string),
        });
        let mut lo: Option<String> = None;
        for c in v
            .get("children")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let ord = between(lo.as_deref(), None).ok_or(DE_ERR_INVALID)?;
            lo = Some(ord.clone());
            self.paste_node(c, &id, ord, depth + 1, ops)?;
        }
        Ok(id)
    }

    // ---- group / ungroup ----------------------------------------------------------------------------------------

    /// Wrap the selected siblings in a new frame (or component) sized to their boxes, where the topmost of them
    /// was; they keep their place on the canvas. Siblings of different parents are `DE_ERR_INVALID`.
    pub fn group(&mut self, ty: NodeType) -> Result<(), i32> {
        self.text_end()?;
        self.cancel();
        self.refresh();
        let mut ids = self.top_selected();
        let par = match ids.first().and_then(|i| self.parent_of(i)) {
            Some(p) if ids.iter().all(|i| self.parent_of(i).as_deref() == Some(&p)) => p,
            _ => return Err(DE_ERR_INVALID),
        };
        ids.sort_by_key(|i| self.kids(&par).iter().position(|k| k == i));
        let rects: Vec<_> = ids
            .iter()
            .map(|i| self.rect(i))
            .collect::<Option<_>>()
            .ok_or(DE_ERR_INVALID)?;
        let b = union(rects.iter().copied()).ok_or(DE_ERR_INVALID)?;
        let last = ids.last().ok_or(DE_ERR_INVALID)?;
        let order = self.order_after(last).ok_or(DE_ERR_INVALID)?;
        let g = self.new_id();
        let mut props = Map::new();
        props.insert("w".into(), json!(round2(b.width())));
        props.insert("h".into(), json!(round2(b.height())));
        if !self.is_flow(&par) {
            let o = self.origin(&par);
            props.insert("x".into(), json!(round2(b.left - o.0)));
            props.insert("y".into(), json!(round2(b.top - o.1)));
        }
        let name = if ty == NodeType::Component {
            "Component"
        } else {
            "Group"
        };
        let mut ops = vec![Op::Add {
            id: g.clone(),
            ty,
            parent: Some(par),
            order,
            name: name.into(),
            props,
            text: None,
        }];
        let mut lo: Option<String> = None;
        for (id, r) in ids.iter().zip(&rects) {
            let ord = between(lo.as_deref(), None).ok_or(DE_ERR_INVALID)?;
            lo = Some(ord.clone());
            ops.push(Op::Move {
                id: id.clone(),
                parent: Some(g.clone()),
                order: ord,
            });
            ops.push(set(id, "x", json!(round2(r.left - b.left))));
            ops.push(set(id, "y", json!(round2(r.top - b.top))));
        }
        self.write_and_select(&ops, vec![g])
    }

    /// Put the children of each selected frame where the frame was (same place on the canvas) and remove the
    /// frame. No selected frame is `DE_ERR_INVALID`.
    pub fn ungroup(&mut self) -> Result<(), i32> {
        self.text_end()?;
        self.cancel();
        self.refresh();
        let frames: Vec<String> = self
            .top_selected()
            .into_iter()
            .filter(|i| {
                self.model
                    .as_ref()
                    .and_then(|m| m.nodes.get(i))
                    .is_some_and(|n| n.ty == NodeType::Frame)
                    && self.parent_of(i).is_some()
            })
            .collect();
        if frames.is_empty() {
            return Err(DE_ERR_INVALID);
        }
        let (mut ops, mut sel) = (vec![], vec![]);
        for f in frames {
            let par = self.parent_of(&f).ok_or(DE_ERR_INVALID)?;
            let (o, flow) = (self.origin(&par), self.is_flow(&par));
            let mut lo = self.order_of(&f);
            // the slot between the frame and its next sibling, shared out in order
            let hi = {
                let kids = self.kids(&par);
                kids.iter()
                    .position(|k| *k == f)
                    .and_then(|i| kids.get(i + 1))
                    .and_then(|k| self.order_of(k))
            };
            for k in self.kids(&f) {
                let ord = between(lo.as_deref(), hi.as_deref()).ok_or(DE_ERR_INVALID)?;
                lo = Some(ord.clone());
                ops.push(Op::Move {
                    id: k.clone(),
                    parent: Some(par.clone()),
                    order: ord,
                });
                if !flow && let Some(r) = self.rect(&k) {
                    ops.push(set(&k, "x", json!(round2(r.left - o.0))));
                    ops.push(set(&k, "y", json!(round2(r.top - o.1))));
                }
                sel.push(k);
            }
            ops.push(Op::Delete { id: f });
        }
        self.write_and_select(&ops, sel)
    }

    // ---- components ---------------------------------------------------------------------------------------------

    /// Make a component of the selection: one frame becomes a component in place (same props, children and
    /// place; the node gets a new id), anything else is wrapped in a new component as `group` wraps it.
    pub fn component_create(&mut self) -> Result<(), i32> {
        self.text_end()?;
        self.cancel();
        self.refresh();
        let tops = self.top_selected();
        let one = match &tops[..] {
            [f] => self
                .model
                .as_ref()
                .and_then(|m| m.nodes.get(f))
                .filter(|n| n.ty == NodeType::Frame)
                .cloned(),
            _ => None,
        };
        let (Some(n), [f]) = (one, &tops[..]) else {
            return self.group(NodeType::Component);
        };
        let par = self.parent_of(f).ok_or(DE_ERR_INVALID)?;
        let c = self.new_id();
        let mut ops = vec![Op::Add {
            id: c.clone(),
            ty: NodeType::Component,
            parent: Some(par),
            order: self.order_after(f).ok_or(DE_ERR_INVALID)?,
            name: n.name.clone(),
            props: n.props.clone(),
            text: None,
        }];
        for k in self.kids(f) {
            let order = self.order_of(&k).ok_or(DE_ERR_INVALID)?;
            ops.push(Op::Move {
                id: k,
                parent: Some(c.clone()),
                order,
            });
        }
        ops.push(Op::Delete { id: f.clone() });
        self.write_and_select(&ops, vec![c])
    }

    /// The component a ref names (`<doc>/<node>`, or a bare node id in this document), in this document or its
    /// design system: its document and node id.
    fn component_doc(&mut self, r: &str) -> Option<(Doc, String, String)> {
        let full = if is_node_id(r) {
            format!("{}/{r}", self.doc_id)
        } else {
            r.to_string()
        };
        let (d, n) = parse_component_ref(&full)?;
        let doc = if d == self.doc_id {
            self.model.clone()?
        } else if self.model.as_ref()?.meta.system.as_deref() == Some(d) {
            self.system.read()
        } else {
            return None;
        };
        (doc.nodes.get(n)?.ty == NodeType::Component).then(|| (doc, n.to_string(), full.clone()))
    }

    /// Insert an instance of component `r` with its top-left at view point (x, y), into the frame there (else the
    /// page), and select it. An unknown component is `DE_ERR_INVALID`.
    pub fn instance_insert(&mut self, r: &str, x: f32, y: f32) -> Result<(), i32> {
        finite(&[x, y], MAX_COORD)?;
        self.text_end()?;
        self.cancel();
        self.refresh();
        let (_, _, full) = self.component_doc(r).ok_or(DE_ERR_INVALID)?;
        let page = self.page_id().ok_or(DE_ERR_INVALID)?;
        let p = self.camera.to_world(x, y);
        let par = self.drop_target(p, &[], &page);
        let mut props = Map::new();
        props.insert("component".into(), json!(full));
        if !self.is_flow(&par) {
            let o = self.origin(&par);
            props.insert("x".into(), json!(round2(p.0 - o.0)));
            props.insert("y".into(), json!(round2(p.1 - o.1)));
        }
        let id = self.new_id();
        let op = Op::Add {
            id: id.clone(),
            ty: NodeType::Instance,
            parent: Some(par.clone()),
            order: self.last_order(&par).ok_or(DE_ERR_INVALID)?,
            name: String::new(),
            props,
            text: None,
        };
        self.write_and_select(&[op], vec![id])
    }

    /// Detach each selected instance: a plain frame in its place holding copies of its component's nodes with the
    /// instance's overrides written in. Nested instances stay instances (their deeper overrides move onto them).
    /// No selected instance whose component is found is `DE_ERR_INVALID`.
    pub fn instance_detach(&mut self) -> Result<(), i32> {
        self.text_end()?;
        self.cancel();
        self.refresh();
        let (mut ops, mut sel) = (vec![], vec![]);
        for i in self.top_selected() {
            let Some(n) = self
                .model
                .as_ref()
                .and_then(|m| m.nodes.get(&i))
                .filter(|n| n.ty == NodeType::Instance)
                .cloned()
            else {
                continue;
            };
            let Some((doc, cid, _)) = n
                .props
                .get("component")
                .and_then(Value::as_str)
                .and_then(|r| self.component_doc(r))
            else {
                continue;
            };
            let (Some(par), Some(order)) = (self.parent_of(&i), self.order_after(&i)) else {
                continue;
            };
            let ov = n
                .props
                .get("overrides")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            // the root: the component's look under the instance's own props, then the `.` override
            let mut props = doc.nodes[&cid].props.clone();
            props.remove("x");
            props.remove("y");
            for (k, v) in &n.props {
                if k != "component" && k != "overrides" {
                    props.insert(k.clone(), v.clone());
                }
            }
            apply_override(&mut props, &mut None, ov.get("."));
            let f = self.new_id();
            ops.push(Op::Add {
                id: f.clone(),
                ty: NodeType::Frame,
                parent: Some(par),
                order,
                name: n.name.clone(),
                props,
                text: None,
            });
            let fo = forest(&doc);
            let kids = |id: &str| fo.children.get(id).cloned().unwrap_or_default();
            for k in kids(&cid) {
                self.detach_copy(&doc, &kids, &k, k.clone(), &f, &ov, 0, &mut ops);
            }
            ops.push(Op::Delete { id: i });
            sel.push(f);
        }
        self.write_and_select(&ops, sel)
    }

    /// Copy component node `src` (override path `path`) under `parent` with its overrides applied.
    #[allow(clippy::too_many_arguments)]
    fn detach_copy(
        &mut self,
        doc: &Doc,
        kids: &dyn Fn(&str) -> Vec<String>,
        src: &str,
        path: String,
        parent: &str,
        ov: &Map<String, Value>,
        depth: usize,
        ops: &mut Vec<Op>,
    ) {
        let Some(n) = doc.nodes.get(src).filter(|_| depth < MAX_CLIP_DEPTH) else {
            return;
        };
        let (mut props, mut text) = (n.props.clone(), n.text.clone());
        apply_override(&mut props, &mut text, ov.get(&path));
        if n.ty == NodeType::Instance {
            // overrides that reach inside this nested instance become its own (the detached one's win)
            let mut inner = props
                .get("overrides")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let pre = format!("{path}/");
            for (k, v) in ov {
                if let Some(rest) = k.strip_prefix(&pre) {
                    inner.insert(rest.to_string(), v.clone());
                }
            }
            if !inner.is_empty() {
                props.insert("overrides".into(), Value::Object(inner));
            }
        }
        let id = self.new_id();
        ops.push(Op::Add {
            id: id.clone(),
            ty: n.ty,
            parent: Some(parent.to_string()),
            order: n.order.clone(),
            name: n.name.clone(),
            props,
            text,
        });
        for k in kids(src) {
            let p = format!("{path}/{k}");
            self.detach_copy(doc, kids, &k, p, &id, ov, depth + 1, ops);
        }
    }
}

/// One override layer: `null` removes the prop, `text` replaces a text's content, anything else is set.
fn apply_override(
    props: &mut Map<String, Value>,
    text: &mut Option<String>,
    layer: Option<&Value>,
) {
    for (k, v) in layer.and_then(Value::as_object).into_iter().flatten() {
        match (k.as_str(), v) {
            (_, Value::Null) => {
                props.remove(k);
            }
            ("text", Value::String(s)) => {
                if text.is_some() {
                    *text = Some(s.clone());
                }
            }
            ("text", _) => {}
            _ => {
                props.insert(k.clone(), v.clone());
            }
        }
    }
}
