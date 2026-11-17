//! The Design renderer (V2-01, T2): resolved model -> taffy layout -> Skia draw.
//!
//! ```text
//! design_model::resolve -> Renderer::load (layout per top-level node, cached) -> Renderer::draw(canvas)
//!                                                      CPU raster (`cpu`) | Metal (`metal`, feature)
//! ```
//! The same draw code runs on both backends. Host contract: build a [`Renderer`] on the render thread (Skia objects are
//! not `Send`), hand it fonts and assets by hash, call `load` after every model change and `draw` only when
//! `needs_frame` says so.

pub mod assets;
pub mod camera;
pub mod cpu;
pub mod draw;
pub mod fonts;
pub mod hit;
pub mod layout;
pub mod look;
#[cfg(all(feature = "metal", target_os = "macos"))]
pub mod metal;
pub mod overlay;
pub mod scene;
pub mod synth;

pub use assets::Assets;
pub use camera::Camera;
pub use draw::Lod;
pub use fonts::Fonts;
pub use hit::Hit;
pub use overlay::Overlay;
pub use scene::{Config, Dirty, Renderer};
pub use skia_safe::Rect;
