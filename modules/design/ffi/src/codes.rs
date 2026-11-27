//! Return codes, flags and limits of the C ABI (exported to the header by cbindgen).

pub const DE_ABI_VERSION: u32 = 1;

pub const DE_OK: i32 = 0;
pub const DE_ERR_HANDLE: i32 = -1;
pub const DE_ERR_ARG: i32 = -2;
pub const DE_ERR_TOO_LARGE: i32 = -3;
/// Refused by a validator, or bytes that do not decode.
pub const DE_ERR_INVALID: i32 = -4;
pub const DE_ERR_SMALL_BUFFER: i32 = -5;
pub const DE_ERR_NO_SURFACE: i32 = -6;
pub const DE_ERR_PANIC: i32 = -7;
/// A panic happened inside this engine earlier; free it and make a new one.
pub const DE_ERR_POISONED: i32 = -8;
pub const DE_ERR_GPU: i32 = -9;
/// A remote update failed inside yrs and the document was reset: send the state vector again and apply the full diff
/// from the Core. Unsent local edits are kept and still go out; the undo history is cleared.
pub const DE_ERR_RESET: i32 = -10;
/// Three resets within a minute: remote updates are no longer applied. Local edits still work and still go out; free
/// the engine and open the design again.
pub const DE_ERR_HALTED: i32 = -11;
/// No thread could be started for a remote update; nothing changed. Retry later.
pub const DE_ERR_BUSY: i32 = -12;

/// `de_sync_apply` targets.
pub const DE_DOC: u32 = 0;
pub const DE_SYSTEM: u32 = 1;

pub const DE_POINTER_DOWN: u32 = 0;
pub const DE_POINTER_MOVE: u32 = 1;
pub const DE_POINTER_UP: u32 = 2;

pub const DE_MOD_SHIFT: u32 = 1;
pub const DE_MOD_CONTROL: u32 = 2;
pub const DE_MOD_OPTION: u32 = 4;
pub const DE_MOD_COMMAND: u32 = 8;

pub const DE_KEY_DELETE: u32 = 1;
/// Cancels a gesture in progress; otherwise clears the selection.
pub const DE_KEY_ESCAPE: u32 = 2;
/// ⌘D in the App.
pub const DE_KEY_DUPLICATE: u32 = 3;
/// Arrow keys nudge the selection 1 pt (10 with `DE_MOD_SHIFT`), or reorder it in an auto-layout frame.
pub const DE_KEY_LEFT: u32 = 4;
pub const DE_KEY_RIGHT: u32 = 5;
pub const DE_KEY_UP: u32 = 6;
pub const DE_KEY_DOWN: u32 = 7;
/// Return / Enter: ends a pen path in progress.
pub const DE_KEY_ENTER: u32 = 8;

/// `de_cursor` results.
pub const DE_CURSOR_DEFAULT: i32 = 0;
pub const DE_CURSOR_RESIZE_NS: i32 = 1;
pub const DE_CURSOR_RESIZE_EW: i32 = 2;
pub const DE_CURSOR_RESIZE_NWSE: i32 = 3;
pub const DE_CURSOR_RESIZE_NESW: i32 = 4;
/// Draw tools (frame, rectangle, ellipse, line, pen).
pub const DE_CURSOR_CROSSHAIR: i32 = 5;
/// Hand tool: open hand, and closed while dragging.
pub const DE_CURSOR_GRAB: i32 = 6;
pub const DE_CURSOR_GRABBING: i32 = 7;
/// Text tool: I-beam.
pub const DE_CURSOR_TEXT: i32 = 8;
/// Just outside a corner of the selection bounds: a drag there rotates the selection (⇧ snaps to 15°).
pub const DE_CURSOR_ROTATE: i32 = 9;

/// `de_set_tool` tools. Drawing tools return to `DE_TOOL_SELECT` after one node (the pen after one path).
pub const DE_TOOL_SELECT: u32 = 0;
pub const DE_TOOL_HAND: u32 = 1;
pub const DE_TOOL_FRAME: u32 = 2;
pub const DE_TOOL_RECT: u32 = 3;
pub const DE_TOOL_ELLIPSE: u32 = 4;
pub const DE_TOOL_LINE: u32 = 5;
pub const DE_TOOL_TEXT: u32 = 6;
pub const DE_TOOL_PEN: u32 = 7;

/// `de_text_command` (V2-04): what `NSTextInputClient.doCommand(by:)` maps to. `DE_MOD_SHIFT` extends the selection;
/// `DE_MOD_OPTION` moves or deletes by word; `DE_MOD_COMMAND` turns ←/→ into line start/end and ↑/↓ into text
/// start/end.
pub const DE_TEXT_LEFT: u32 = 1;
pub const DE_TEXT_RIGHT: u32 = 2;
pub const DE_TEXT_UP: u32 = 3;
pub const DE_TEXT_DOWN: u32 = 4;
pub const DE_TEXT_DELETE_BACK: u32 = 5;
pub const DE_TEXT_DELETE_FORWARD: u32 = 6;
pub const DE_TEXT_SELECT_ALL: u32 = 7;
pub const DE_TEXT_NEWLINE: u32 = 8;
/// "No range" for `de_text_insert` / `de_text_set_marked` (`NSNotFound` in Swift maps to this).
pub const DE_TEXT_NO_RANGE: i64 = -1;
/// UTF-16 offsets and lengths the text calls take (a text holds at most 100 000 characters).
pub const DE_MAX_TEXT_OFFSET: i64 = 1 << 20;
/// UTF-8 bytes one `de_text_insert` / `de_text_set_marked` takes (a paste of a whole text fits).
pub const DE_MAX_TEXT_BYTES: usize = 1 << 20;

/// Engines alive at once.
pub const DE_MAX_ENGINES: usize = 64;
/// Sync bytes in (a full document state fits).
pub const DE_MAX_SYNC_BYTES: usize = 33 << 20;
pub const DE_MAX_JSON_BYTES: usize = 1 << 20;
pub const DE_MAX_ID_BYTES: usize = 128;
/// Ids one `de_select` takes.
pub const DE_MAX_SELECT_IDS: usize = 4096;
pub const DE_MAX_BLOB_BYTES: usize = 25 << 20;
/// Clipboard JSON `de_copy` writes and `de_paste` takes.
pub const DE_MAX_CLIP_BYTES: usize = 8 << 20;

// Literals for the header; kept equal to the document crate's caps.
const _: () = assert!(DE_MAX_SYNC_BYTES == design_doc::MAX_UPDATE_BYTES);
const _: () = assert!(DE_MAX_JSON_BYTES == design_doc::MAX_OPS_BYTES);
