//! The C ABI of the Design engine (V2-02, T4). Header: `include/DesignEngine.h` (cbindgen, `make engine-header`).
//!
//! # Security model
//!
//! Callers: the Mac app only (Swift, same process). The engine trusts the App's *memory*, not its *values*: what
//! arrives through these functions is document data that may come from other devices and AI sessions.
//!
//! - **Handles, not pointers.** An engine is a `u64` handle into a registry; ids are never reused, so a stale,
//!   freed or forged handle is `DE_ERR_HANDLE`, never a use-after-free. Each engine sits behind its own mutex, so
//!   calls from the main thread (input) and the render thread (frames) are serialised, never racing.
//! - **Every pointer and length is checked** before use: NULL with a non-zero length, lengths above the per-call
//!   cap (`MAX_*`), pointer + length overflow and misaligned out-pointers are `DE_ERR_ARG` / `DE_ERR_TOO_LARGE`;
//!   text must be UTF-8; floats must be finite and in range. Input slices are dropped before any output is written.
//!   What cannot be checked is the App's promise that `ptr..ptr+len` is readable (writable for outputs) for the call.
//! - **No Rust allocation crosses the boundary.** Outputs go into caller buffers: `*out_len` always gets the size
//!   needed; if it exceeds `cap` the call returns `DE_ERR_SMALL_BUFFER`, writes nothing and consumes nothing.
//! - **Panics never cross.** Every function runs inside `catch_unwind`; a panic returns `DE_ERR_PANIC`, and the
//!   engine whose lock it held is poisoned: every later call on it returns `DE_ERR_POISONED` until it is freed.
//!   (The crate must build with `panic = "unwind"`, the default; `tests/abi.rs` proves the catch.) A stack overflow
//!   or out-of-memory is an abort, not a panic: sizes are capped for that reason, `design-doc` depth-caps nested
//!   values in remote bytes, and any single Rust allocation over 256 MiB is refused (`Capped`), so a hostile length
//!   fails a decode, not the process. Skia decodes images in C++, outside that cap: `design-render` refuses images
//!   claiming more than 64 MP before they are drawn.
//! - **Metal objects** (`de_attach_metal`, `de_draw_metal`) are the one thing taken on trust: they must be live
//!   `id<MTLDevice>` / `id<MTLCommandQueue>` / `id<MTLTexture>`; the texture's size and format are read from it and
//!   checked, never taken from the caller. Skia's GPU context is used under
//!   the engine's mutex only; free an engine on the thread that drew with it, after `de_detach`.
//! - The engine has no network, file or process access; fonts and images arrive as bytes and are decoded by Skia.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::host::Host;

pub use crate::codes::*;

/// The largest single Rust allocation. yrs reserves wire-sized collections (`try_reserve(len)` with `len` read from
/// the bytes) before reading their contents; on macOS such a reservation succeeds lazily and the process is killed
/// once it is touched. Refusing it here turns a hostile length into a decode error instead.
const MAX_ALLOC: usize = 256 << 20;

struct Capped;

// SAFETY: forwards to the system allocator, only refusing (null) oversized requests, which `GlobalAlloc` allows.
unsafe impl std::alloc::GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        if l.size() > MAX_ALLOC {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(l) }
        }
    }
    unsafe fn alloc_zeroed(&self, l: std::alloc::Layout) -> *mut u8 {
        if l.size() > MAX_ALLOC {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc_zeroed(l) }
        }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        if n > MAX_ALLOC {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(p, l, n) }
        }
    }
}

#[global_allocator]
static ALLOC: Capped = Capped;

struct Slot(Mutex<Host>);
// SAFETY: a `Host` holds Skia objects that are not `Send`. They are only touched under the slot's mutex, so one
// thread at a time uses them; Skia's ref-counted objects tolerate moving between threads under that discipline,
// and its GPU context requires exactly that (single-threaded use, external synchronisation).
unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

static HOSTS: Mutex<BTreeMap<u64, Arc<Slot>>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, BTreeMap<u64, Arc<Slot>>> {
    HOSTS.lock().unwrap_or_else(|e| e.into_inner())
}

type R = Result<i32, i32>;

pub(crate) fn guard(f: impl FnOnce() -> R) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v) | Err(v)) => v,
        Err(_) => DE_ERR_PANIC,
    }
}

pub(crate) fn with(h: u64, f: impl FnOnce(&mut Host) -> R) -> i32 {
    guard(|| {
        let slot = registry().get(&h).cloned().ok_or(DE_ERR_HANDLE)?;
        let mut host = slot.0.lock().map_err(|_| DE_ERR_POISONED)?;
        f(&mut host)
    })
}

fn ok(r: Result<(), i32>) -> R {
    r.map(|()| DE_OK)
}

/// # Safety
/// `p..p+n` is readable for the call when `n > 0`.
pub(crate) unsafe fn bytes<'a>(p: *const u8, n: usize, max: usize) -> Result<&'a [u8], i32> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(DE_ERR_ARG);
    }
    if n > max {
        return Err(DE_ERR_TOO_LARGE);
    }
    if (p as usize).checked_add(n).is_none() || n > isize::MAX as usize {
        return Err(DE_ERR_ARG);
    }
    // SAFETY: non-null, length capped and not wrapping; readability is the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(p, n) })
}

/// # Safety
/// As `bytes`.
pub(crate) unsafe fn text<'a>(p: *const u8, n: usize, max: usize) -> Result<&'a str, i32> {
    std::str::from_utf8(unsafe { bytes(p, n, max) }?).map_err(|_| DE_ERR_ARG)
}

/// Copy `data` out. `*out_len` = bytes needed, always; nothing written when it does not fit.
///
/// # Safety
/// `out_len` is writable; `out..out+cap` is writable when `cap > 0`.
pub(crate) unsafe fn put(data: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> R {
    if out_len.is_null() || !out_len.is_aligned() {
        return Err(DE_ERR_ARG);
    }
    // SAFETY: non-null and aligned; writability is the caller's contract.
    unsafe { out_len.write(data.len()) };
    if data.len() > cap {
        return Err(DE_ERR_SMALL_BUFFER);
    }
    if data.is_empty() {
        return Ok(DE_OK);
    }
    if out.is_null() || (out as usize).checked_add(cap).is_none() {
        return Err(DE_ERR_ARG);
    }
    // SAFETY: `data` is engine-owned (never the caller's memory), fits in `cap`, `out` is non-null.
    unsafe { std::ptr::copy(data.as_ptr(), out, data.len()) };
    Ok(DE_OK)
}

// ---- lifecycle ----------------------------------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn de_abi_version() -> u32 {
    DE_ABI_VERSION
}

/// New engine for design `doc_id` (`dd_...`). Writes the handle (never 0) to `*out_handle`.
///
/// # Safety
/// `doc_id..+len` readable; `out_handle` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_engine_new(doc_id: *const u8, len: usize, out_handle: *mut u64) -> i32 {
    guard(|| {
        if out_handle.is_null() || !out_handle.is_aligned() {
            return Err(DE_ERR_ARG);
        }
        let h = engine_new(unsafe { text(doc_id, len, DE_MAX_ID_BYTES) }?)?;
        // SAFETY: checked non-null and aligned above.
        unsafe { out_handle.write(h) };
        Ok(DE_OK)
    })
}

pub(crate) fn engine_new(doc_id: &str) -> Result<u64, i32> {
    let host = Host::new(doc_id)?;
    let mut reg = registry();
    if reg.len() >= DE_MAX_ENGINES {
        return Err(DE_ERR_TOO_LARGE);
    }
    let h = NEXT.fetch_add(1, Ordering::Relaxed);
    reg.insert(h, Arc::new(Slot(Mutex::new(host))));
    Ok(h)
}

/// Free an engine (also a poisoned one). The handle is dead afterwards; a second free is `DE_ERR_HANDLE`.
#[unsafe(no_mangle)]
pub extern "C" fn de_engine_free(h: u64) -> i32 {
    guard(|| {
        let slot = registry().remove(&h).ok_or(DE_ERR_HANDLE)?;
        drop(slot);
        Ok(DE_OK)
    })
}

// ---- sync ---------------------------------------------------------------------------------------------------------

/// Apply a yrs v1 update from the Core relay to the design (`DE_DOC`) or its read-only design system (`DE_SYSTEM`).
///
/// # Safety
/// `bytes..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_sync_apply(h: u64, target: u32, bytes_: *const u8, len: usize) -> i32 {
    with(h, |e| {
        let b = unsafe { bytes(bytes_, len, DE_MAX_SYNC_BYTES) }?;
        ok(e.sync_apply(target, b))
    })
}

/// This replica's state vector (yrs v1).
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_sync_state_vector(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe { put(&e.state_vector(), out, cap, out_len) })
}

/// The update a peer at state vector `sv` needs (`sv_len == 0`: the full state).
///
/// # Safety
/// `sv..+sv_len` readable; see `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_sync_diff(
    h: u64,
    sv: *const u8,
    sv_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let d = e.diff(unsafe { bytes(sv, sv_len, DE_MAX_SYNC_BYTES) }?)?;
        unsafe { put(&d, out, cap, out_len) }
    })
}

/// Local edits not yet sent, merged into one update of at most `DE_MAX_SYNC_BYTES`; more pending than that come in
/// later calls, so call until `*out_len == 0` (nothing to send). Drained only when they fit.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_sync_outbox(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let r = unsafe { put(&e.outbox(false), out, cap, out_len) }?;
        e.outbox(true);
        Ok(r)
    })
}

// ---- presence -----------------------------------------------------------------------------------------------------

/// Set this device's presence: a JSON object (cursor, selection, label), at most 4 KiB.
///
/// # Safety
/// `json..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_set(h: u64, json: *const u8, len: usize) -> i32 {
    with(h, |e| {
        ok(e.presence_set(unsafe { text(json, len, DE_MAX_JSON_BYTES) }?))
    })
}

/// This device's awareness update, to send (`*out_len == 0` before `de_presence_set`).
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_encode(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe {
        put(&e.presence_encode(), out, cap, out_len)
    })
}

/// # Safety
/// `bytes..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_apply(h: u64, bytes_: *const u8, len: usize) -> i32 {
    with(h, |e| {
        ok(e.presence_apply(unsafe { bytes(bytes_, len, DE_MAX_JSON_BYTES) }?))
    })
}

/// Other peers' presence as JSON `{"<client>": {...}}`.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_peers(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe {
        put(&e.presence_peers(), out, cap, out_len)
    })
}

// ---- other peers (V2-06) ------------------------------------------------------------------------------------------

/// One presence message relayed by the Core's socket, with a `label` the App added: `{"peer","conn","label"?,
/// "cursor"?,"selection"?,"view"?}` or `{"conn","gone":true}`, at most 4 KiB. A message out of bounds is
/// `DE_ERR_INVALID` and changes nothing. A peer silent for 30 s disappears; a peer that sends a `view` moves a
/// camera that follows it.
///
/// # Safety
/// `json..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_remote(h: u64, json: *const u8, len: usize) -> i32 {
    with(h, |e| {
        ok(e.presence_remote(unsafe { text(json, len, crate::presence::MAX_MESSAGE) }?))
    })
}

/// This device's presence to send to the Core's socket as a text frame: `{"cursor","selection","view"}` (world
/// coordinates). `*out_len == 0`: nothing changed since the last call that took it. Taken only when it fits.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_local(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let r = unsafe { put(&e.presence_local(false), out, cap, out_len) }?;
        e.presence_local(true);
        Ok(r)
    })
}

/// The peers on the canvas: `[{"peer","label","kind":"person"|"ai","following"}]`, oldest first.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_presence_list(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe { put(&e.presence_list(), out, cap, out_len) })
}

/// Follow a peer (its `peer` id from `de_presence_list`): the camera shows what it sees until the viewer pans,
/// zooms, fits or presses on the canvas, or the peer goes. An empty id stops following; an unknown peer is
/// `DE_ERR_ARG`.
///
/// # Safety
/// `peer..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_follow(h: u64, peer: *const u8, len: usize) -> i32 {
    with(h, |e| ok(e.follow(unsafe { text(peer, len, DE_MAX_ID_BYTES) }?)))
}

// ---- edits --------------------------------------------------------------------------------------------------------

/// A JSON array of edit ops (`add`, `set`, `name`, `text`, `move`, `delete`); all or nothing, one undo step.
///
/// # Safety
/// `json..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_edit(h: u64, json: *const u8, len: usize) -> i32 {
    with(h, |e| {
        ok(e.edit(unsafe { bytes(json, len, DE_MAX_JSON_BYTES) }?))
    })
}

/// 1 when something was undone, 0 when there was nothing to undo.
#[unsafe(no_mangle)]
pub extern "C" fn de_undo(h: u64) -> i32 {
    with(h, |e| Ok(e.undo(false) as i32))
}

#[unsafe(no_mangle)]
pub extern "C" fn de_redo(h: u64) -> i32 {
    with(h, |e| Ok(e.undo(true) as i32))
}

// ---- view + input -------------------------------------------------------------------------------------------------

/// View size in points and the backing scale.
#[unsafe(no_mangle)]
pub extern "C" fn de_resize(h: u64, w: f32, height: f32, scale: f32) -> i32 {
    with(h, |e| ok(e.resize(w, height, scale)))
}

#[unsafe(no_mangle)]
pub extern "C" fn de_set_theme(h: u64, night: u32) -> i32 {
    with(h, |e| {
        e.set_theme(night != 0);
        Ok(DE_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn de_set_page(h: u64, page: u32) -> i32 {
    with(h, |e| {
        e.set_page(page);
        Ok(DE_OK)
    })
}

/// Frame every artboard of the page in the view.
#[unsafe(no_mangle)]
pub extern "C" fn de_fit(h: u64) -> i32 {
    with(h, |e| {
        e.fit();
        Ok(DE_OK)
    })
}

/// Frame the selection (everything when nothing is selected).
#[unsafe(no_mangle)]
pub extern "C" fn de_fit_selection(h: u64) -> i32 {
    with(h, |e| {
        e.fit_selection();
        Ok(DE_OK)
    })
}

/// Pointer at view point (x, y): `DE_POINTER_*` phase, `DE_MOD_*` bits. Down selects (shift toggles); a drag moves
/// the selection (option: a copy of it; ⌘: no snapping), resizes it from a handle, or draws a marquee; up writes the
/// move or resize as one undo step. A move without a press is a hover.
#[unsafe(no_mangle)]
pub extern "C" fn de_pointer(h: u64, phase: u32, x: f32, y: f32, mods: u32) -> i32 {
    with(h, |e| ok(e.pointer(phase, x, y, mods)))
}

/// The cursor for view point (x, y): a `DE_CURSOR_*` value (>= 0), or an error code.
#[unsafe(no_mangle)]
pub extern "C" fn de_cursor(h: u64, x: f32, y: f32) -> i32 {
    with(h, |e| e.cursor(x, y))
}

/// Pan by a scroll delta in points (the host's momentum included). Past the content bounds the pan is
/// rubber-banded; call `de_gesture_end` when the scroll or pinch ends.
#[unsafe(no_mangle)]
pub extern "C" fn de_scroll(h: u64, dx: f32, dy: f32) -> i32 {
    with(h, |e| ok(e.scroll(dx, dy)))
}

/// A scroll or pinch ended: settle back inside the content bounds, animated through `de_tick`, or at once when
/// `reduce_motion` is non-zero.
#[unsafe(no_mangle)]
pub extern "C" fn de_gesture_end(h: u64, reduce_motion: u32) -> i32 {
    with(h, |e| {
        e.gesture_end(reduce_motion != 0);
        Ok(DE_OK)
    })
}

/// Advance animations (the rubber-band settle) by `dt` seconds (0..=1), once per display frame. 1 while
/// something is still moving, 0 when at rest.
#[unsafe(no_mangle)]
pub extern "C" fn de_tick(h: u64, dt: f32) -> i32 {
    with(h, |e| e.tick(dt).map(i32::from))
}

/// Zoom by `factor` (> 0) about view point (x, y).
#[unsafe(no_mangle)]
pub extern "C" fn de_magnify(h: u64, factor: f32, x: f32, y: f32) -> i32 {
    with(h, |e| ok(e.magnify(factor, x, y)))
}

/// `DE_KEY_*` with `DE_MOD_*` bits; unknown keys are ignored.
#[unsafe(no_mangle)]
pub extern "C" fn de_key(h: u64, key: u32, mods: u32) -> i32 {
    with(h, |e| ok(e.key(key, mods)))
}

// ---- queries ------------------------------------------------------------------------------------------------------

/// Selected node ids, a JSON array.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_selection(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe {
        put(&e.selection_json(), out, cap, out_len)
    })
}

/// The node tree for the layers panel, a JSON array `[{id, type, parent, order, name, hidden}]` in id order (the App
/// sorts siblings by `order`). `parent` is the effective parent (`null` for pages and detached roots); `hidden` is
/// `props.visible == false`. Output grows with the document, so size the buffer from `*out_len` on `DE_ERR_SMALL_BUFFER`.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_tree(h: u64, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    with(h, |e| unsafe { put(&e.tree_json(), out, cap, out_len) })
}

/// The linked design system's tokens, a JSON array `[{name, kind}]` in name order (`[]` until the system has synced).
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_tokens(h: u64, out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    with(h, |e| unsafe { put(&e.tokens_json(), out, cap, out_len) })
}

/// Select nodes by id: `ids_json` is a JSON array of strings (at most `DE_MAX_SELECT_IDS`, each at most
/// `DE_MAX_ID_BYTES`), replacing the selection; `[]` clears it. Ends text editing and cancels a gesture first. An id
/// that is not in the document refuses the whole call (`DE_ERR_INVALID`, selection unchanged).
///
/// # Safety
/// `ids_json..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_select(h: u64, ids_json: *const u8, len: usize) -> i32 {
    with(h, |e| {
        let b = unsafe { bytes(ids_json, len, DE_MAX_JSON_BYTES) }?;
        ok(e.select(b))
    })
}

/// One node for the inspector (`{id, type, parent, order, name, props, text}`), or `null`.
///
/// # Safety
/// `id..+id_len` readable; see `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_node(
    h: u64,
    id: *const u8,
    id_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let id = unsafe { text(id, id_len, DE_MAX_ID_BYTES) }?.to_string();
        unsafe { put(&e.node_json(&id), out, cap, out_len) }
    })
}

/// The deepest visible node at view point (x, y): `{id, artboard, path}` or `null`.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_hit(
    h: u64,
    x: f32,
    y: f32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let j = e.hit_json(x, y)?;
        unsafe { put(&j, out, cap, out_len) }
    })
}

/// Asset hashes the renderer wanted and did not have (JSON array): fetch them, then `de_asset_add`.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_missing_assets(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe { put(&e.missing_json(), out, cap, out_len) })
}

// ---- text editing (V2-04) ---------------------------------------------------------------------------------------
//
// What the App's `NSTextInputClient` bridge calls. Offsets and lengths are UTF-16 code units of the composed text
// (the node's text with the IME's marked text in place), as `NSRange` counts them; a range argument is a start and
// a length, each in `0..=DE_MAX_TEXT_OFFSET`, or start `DE_TEXT_NO_RANGE` (Swift's `NSNotFound`). Offsets past the
// text are clamped and offsets inside a character or emoji sequence snap to its edge. Calls other than
// `de_text_begin` / `de_text_end` return `DE_ERR_INVALID` when no text is being edited.

/// Start editing the text node under view point (x, y) with the caret there (a double-click on text). Marked text
/// of an earlier session is committed first. `DE_ERR_INVALID` when there is no text node at the point.
#[unsafe(no_mangle)]
pub extern "C" fn de_text_begin(h: u64, x: f32, y: f32) -> i32 {
    with(h, |e| ok(e.text_begin(x, y)))
}

/// Stop editing (commits marked text). Not editing: `DE_OK`.
#[unsafe(no_mangle)]
pub extern "C" fn de_text_end(h: u64) -> i32 {
    with(h, |e| ok(e.text_end()))
}

/// `insertText(_:replacementRange:)`: UTF-8 `text` replaces the marked text, else the replacement range, else the
/// selection. One batch; a run of typing is one undo step.
///
/// # Safety
/// `text..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_text_insert(
    h: u64,
    text_: *const u8,
    len: usize,
    rep_start: i64,
    rep_len: i64,
) -> i32 {
    with(h, |e| {
        let t = unsafe { text(text_, len, DE_MAX_TEXT_BYTES) }?;
        let rep = crate::typing::range_arg(rep_start, rep_len)?;
        ok(e.text_insert(t, rep))
    })
}

/// `setMarkedText(_:selectedRange:replacementRange:)`: the IME's composition, drawn in place and never written to
/// the document until it is committed (`de_text_insert`, `de_text_unmark`). `sel` is inside `text`; an empty `text`
/// ends the composition.
///
/// # Safety
/// `text..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_text_set_marked(
    h: u64,
    text_: *const u8,
    len: usize,
    sel_start: i64,
    sel_len: i64,
    rep_start: i64,
    rep_len: i64,
) -> i32 {
    with(h, |e| {
        let t = unsafe { text(text_, len, DE_MAX_TEXT_BYTES) }?;
        let end = t.encode_utf16().count();
        let sel = crate::typing::range_arg(sel_start, sel_len)?.unwrap_or((end, end));
        let rep = crate::typing::range_arg(rep_start, rep_len)?;
        ok(e.text_set_marked(t, sel, rep))
    })
}

/// `unmarkText()`: the marked text goes in as it is.
#[unsafe(no_mangle)]
pub extern "C" fn de_text_unmark(h: u64) -> i32 {
    with(h, |e| ok(e.text_unmark()))
}

/// `doCommand(by:)`: a `DE_TEXT_*` command with `DE_MOD_*` bits.
#[unsafe(no_mangle)]
pub extern "C" fn de_text_command(h: u64, cmd: u32, mods: u32) -> i32 {
    with(h, |e| ok(e.text_command(cmd, mods)))
}

/// The editing state as JSON: `{id, text, selection: [start, len], marked: [start, len] | null}`, or `null` when
/// not editing (`selectedRange()`, `markedRange()`, `hasMarkedText()`, `attributedSubstring(forProposedRange:)`).
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_text_state(
    h: u64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| unsafe {
        put(&e.text_state_json(), out, cap, out_len)
    })
}

/// `firstRect(forCharacterRange:actualRange:)`: `{rect: [x, y, w, h], range: [start, len]}`, the rect in view
/// points (the App converts it to screen coordinates), the range as it was snapped.
///
/// # Safety
/// See `put`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_text_first_rect(
    h: u64,
    start: i64,
    len: i64,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    with(h, |e| {
        let j = e.text_first_rect_json(start, len)?;
        unsafe { put(&j, out, cap, out_len) }
    })
}

/// `characterIndex(for:)`: the offset nearest view point (x, y) (>= 0), or an error code.
#[unsafe(no_mangle)]
pub extern "C" fn de_text_index_at(h: u64, x: f32, y: f32) -> i32 {
    with(h, |e| e.text_index_at(x, y))
}

// ---- fonts + assets -----------------------------------------------------------------------------------------------

/// A library font by its sha256 (`asset_len == 0`: the fallback `system` draws with).
///
/// # Safety
/// `asset..+asset_len` and `data..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_font_add(
    h: u64,
    asset: *const u8,
    asset_len: usize,
    data: *const u8,
    len: usize,
) -> i32 {
    with(h, |e| {
        let a = unsafe { text(asset, asset_len, DE_MAX_ID_BYTES) }?;
        let d = unsafe { bytes(data, len, DE_MAX_BLOB_BYTES) }?;
        ok(e.font_add(a, d))
    })
}

/// An image asset by its sha256.
///
/// # Safety
/// `hash..+hash_len` and `data..+len` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_asset_add(
    h: u64,
    hash: *const u8,
    hash_len: usize,
    data: *const u8,
    len: usize,
) -> i32 {
    with(h, |e| {
        let k = unsafe { text(hash, hash_len, DE_MAX_ID_BYTES) }?;
        let d = unsafe { bytes(data, len, DE_MAX_BLOB_BYTES) }?;
        ok(e.asset_add(k, d))
    })
}

// ---- surface ------------------------------------------------------------------------------------------------------

/// Attach Skia to the App's Metal device and queue (`DE_ERR_GPU` in a build without Metal).
///
/// # Safety
/// `device` / `queue` are live `id<MTLDevice>` / `id<MTLCommandQueue>` that outlive the attachment.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_attach_metal(
    h: u64,
    device: *mut std::ffi::c_void,
    queue: *mut std::ffi::c_void,
) -> i32 {
    with(h, |e| {
        if device.is_null() || queue.is_null() {
            return Err(DE_ERR_ARG);
        }
        #[cfg(all(feature = "metal", target_os = "macos"))]
        {
            // SAFETY: the caller's contract above.
            let m = unsafe { design_render::metal::Metal::from_raw(device, queue) }
                .ok_or(DE_ERR_GPU)?;
            e.metal = Some(m);
            Ok(DE_OK)
        }
        #[cfg(not(all(feature = "metal", target_os = "macos")))]
        {
            let _ = e;
            Err(DE_ERR_GPU)
        }
    })
}

/// Drop the GPU context (the document, camera and caches stay).
#[unsafe(no_mangle)]
pub extern "C" fn de_detach(h: u64) -> i32 {
    with(h, |e| {
        #[cfg(all(feature = "metal", target_os = "macos"))]
        {
            e.metal = None;
        }
        let _ = e;
        Ok(DE_OK)
    })
}

/// 1 when something changed since the last frame, 0 when the canvas is still (draw nothing).
#[unsafe(no_mangle)]
pub extern "C" fn de_needs_frame(h: u64) -> i32 {
    with(h, |e| Ok(e.needs_frame() as i32))
}

/// Draw a frame into the drawable's texture and submit it. Size and pixel format are read from the texture itself
/// (they can change under a live resize); anything but a BGRA8 render target in range is `DE_ERR_ARG`.
///
/// # Safety
/// `texture` is a live `id<MTLTexture>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn de_draw_metal(h: u64, texture: *mut std::ffi::c_void) -> i32 {
    with(h, |e| {
        if texture.is_null() {
            return Err(DE_ERR_ARG);
        }
        #[cfg(all(feature = "metal", target_os = "macos"))]
        {
            use metal::foreign_types::ForeignTypeRef;
            // SAFETY: the caller's contract above; borrowed for this call only, never retained or released.
            let t = unsafe { metal::TextureRef::from_ptr(texture.cast()) };
            let lim = (crate::host::MAX_VIEW * crate::host::MAX_SCALE) as u64;
            let (w, height) = (t.width(), t.height());
            if !(1..=lim).contains(&w)
                || !(1..=lim).contains(&height)
                || t.pixel_format() != metal::MTLPixelFormat::BGRA8Unorm
                || !t.usage().contains(metal::MTLTextureUsage::RenderTarget)
            {
                return Err(DE_ERR_ARG);
            }
            let drawn = e
                .with_metal(|m, r| {
                    // SAFETY: a live BGRA8 render target of exactly `w` x `height`, checked above.
                    unsafe { m.draw_texture(r, texture, w as i32, height as i32, false) }.is_some()
                })
                .ok_or(DE_ERR_NO_SURFACE)?;
            if drawn { Ok(DE_OK) } else { Err(DE_ERR_GPU) }
        }
        #[cfg(not(all(feature = "metal", target_os = "macos")))]
        {
            let _ = e;
            Err(DE_ERR_NO_SURFACE)
        }
    })
}
