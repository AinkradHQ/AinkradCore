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
pub const DE_KEY_ESCAPE: u32 = 2;

/// Engines alive at once.
pub const DE_MAX_ENGINES: usize = 64;
/// Sync bytes in (a full document state fits).
pub const DE_MAX_SYNC_BYTES: usize = 33 << 20;
pub const DE_MAX_JSON_BYTES: usize = 1 << 20;
pub const DE_MAX_ID_BYTES: usize = 128;
pub const DE_MAX_BLOB_BYTES: usize = 25 << 20;

// Literals for the header; kept equal to the document crate's caps.
const _: () = assert!(DE_MAX_SYNC_BYTES == design_doc::MAX_UPDATE_BYTES);
const _: () = assert!(DE_MAX_JSON_BYTES == design_doc::MAX_OPS_BYTES);
