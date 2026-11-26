//! C ABI for the structure edits in `clip.rs` (clipboard, group, components). Same rules as `ffi.rs`: every pointer
//! and length is checked by its helpers there, every call runs under `with` (handle lookup, lock, panic catch).
#![allow(unsafe_code)]

use design_model::NodeType;

use crate::ffi::{
    DE_MAX_CLIP_BYTES, DE_MAX_ID_BYTES, DE_MAX_JSON_BYTES, bytes, ok, put, text, with,
};

/// The clipboard JSON of the nodes in `ids_json` (a JSON array of ids; `len == 0`: the selection), subtrees
/// included, for `NSPasteboard`: `{"format": "ainkrad-design/1", "doc", "nodes": [{type, name, props, text?, at: [x, y],
/// children}]}`. Ids are left out (a paste makes new ones). A page or an unknown id is `DE_ERR_INVALID`; more than
/// `DE_MAX_CLIP_BYTES` is `DE_ERR_TOO_LARGE`.
///
/// # Safety
/// `ids_json..+len` readable; see `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_copy(
    h: u64,
    ids_json: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let ids = unsafe { bytes(ids_json, len, DE_MAX_JSON_BYTES) }?;
        let data = e.copy_json(ids)?;
        unsafe { put(&data, out, cap, out_len) }
    })
}

/// Paste clipboard JSON from `de_copy` (this or another design) into node `parent` (`parent_len == 0`: the current
/// page) with new ids: one undo step, the pasted roots selected. They keep their position, or with `at` non-zero
/// the pasted bounds' top-left goes to view point (x, y). In an auto-layout parent they join the flow at its end.
/// Bad JSON, a parent that cannot hold children or a node the validators refuse is `DE_ERR_INVALID` (nothing
/// written). ⌘D and ⌥-drag stay `DE_KEY_DUPLICATE` and `de_pointer`.
///
/// # Safety
/// `json..+len` and `parent..+parent_len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_paste(
    h: u64,
    json: *const u8,
    len: usize,
    parent: *const u8,
    parent_len: usize,
    x: f32,
    y: f32,
    at: u32,
) -> i32 {
    with(h, |e| {
        let j = unsafe { bytes(json, len, DE_MAX_CLIP_BYTES) }?;
        let p = unsafe { text(parent, parent_len, DE_MAX_ID_BYTES) }?;
        ok(e.paste(j, p, (at != 0).then_some((x, y))))
    })
}

/// Group the selected siblings: a new frame `Group` sized to their boxes, where the topmost was, holding them in
/// place; the group is selected. One undo step. Nothing selected or different parents: `DE_ERR_INVALID`.
#[unsafe(no_mangle)]
pub extern "C" fn de_group(h: u64) -> i32 {
    with(h, |e| ok(e.group(NodeType::Frame)))
}

/// Ungroup: the children of each selected frame go where the frame was (same place on the canvas), the frame is
/// removed and the children are selected. One undo step. No frame selected: `DE_ERR_INVALID`.
#[unsafe(no_mangle)]
pub extern "C" fn de_ungroup(h: u64) -> i32 {
    with(h, |e| ok(e.ungroup()))
}

/// Create a component from the selection: one selected frame becomes a component in place (new id, same props
/// and children), anything else is wrapped in a new component like `de_group`. One undo step; it is selected.
#[unsafe(no_mangle)]
pub extern "C" fn de_component_create(h: u64) -> i32 {
    with(h, |e| ok(e.component_create()))
}

/// Insert an instance of `component` (`"<doc>/<node>"`, or a bare node id of this design) with its top-left at
/// view point (x, y), inside the frame there (else the page), and select it. One undo step. A component not in
/// this design or its design system is `DE_ERR_INVALID`.
///
/// # Safety
/// `component..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_instance_insert(
    h: u64,
    component: *const u8,
    len: usize,
    x: f32,
    y: f32,
) -> i32 {
    with(h, |e| {
        let r = unsafe { text(component, len, 2 * DE_MAX_ID_BYTES) }?;
        ok(e.instance_insert(r, x, y))
    })
}

/// Detach each selected instance: a frame in its place with copies of the component's nodes, overrides written
/// in (nested instances stay instances). One undo step; the frames are selected. No detachable instance selected:
/// `DE_ERR_INVALID`.
#[unsafe(no_mangle)]
pub extern "C" fn de_instance_detach(h: u64) -> i32 {
    with(h, |e| ok(e.instance_detach()))
}
