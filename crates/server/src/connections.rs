//! Connections to outside services (C1; design `2026-11-06-core-connections-design`): the kind
//! adapter framework. A kind (`github`, `jira`) is one [`adapter::KindAdapter`]: a descriptor
//! (data) and a credential test. The rows, sealing, grants, bindings and health live in
//! `store::connections`. GitHub ships (C2), Jira is C3's; no HTTP route (C5).

pub mod adapter;
pub mod github;
pub mod material;

#[cfg(test)]
pub(crate) mod fake;
