//! The Design engine host (V2-02): a live document (`design-doc`), the renderer (`design-render`), a camera, a
//! selection and input handling (V2-03: gestures in `interact`, their ops in `edits`, previews in `preview`), behind a small handle-based C ABI (`ffi`, header `include/DesignEngine.h`).
//! Security model: see the top of `ffi.rs`.

mod codes;
mod edits;
pub mod ffi;
pub mod host;
mod interact;
mod pen;
mod presence;
mod preview;
mod query;
mod snap;
pub mod testing;
mod text;
mod tools;
mod typing;

pub use host::Host;
