//! The Design engine host (V2-02): a live document (`design-doc`), the renderer (`design-render`), a camera, a
//! selection and input handling, behind a small handle-based C ABI (`ffi`, header `include/DesignEngine.h`).
//! Security model: see the top of `ffi.rs`.

mod codes;
pub mod ffi;
pub mod host;
pub mod testing;

pub use host::Host;
