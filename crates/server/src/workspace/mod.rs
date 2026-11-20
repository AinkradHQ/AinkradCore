//! The canonical workspace on the Core host (E15-2): its layout (`paths`), the Core's path-safe
//! file access (`fs`), what a sync includes (`rules`), manifests (`manifest`), the delta
//! protocol's Core end (`sync`), the live view of overflow sessions (`watch`), and adoption of
//! live remote sessions (`adopt`), and session documents (`docs`).

pub mod adopt;
pub mod docs;
pub mod fs;
pub mod manifest;
pub mod paths;
pub mod rules;
pub mod sync;
pub mod watch;

#[cfg(test)]
mod props;
