//! Connections to outside services (C1; design `2026-11-06-core-connections-design`): the kind
//! adapter framework. A kind (`github`, `jira`) is one [`adapter::KindAdapter`]: a descriptor
//! (data) and a credential test. The rows, sealing, grants, bindings and health live in
//! `store::connections`. GitHub (C2), Jira (C3), Linear (C8) and Slack (C9) ship.

pub mod adapter;
pub mod apps;
pub mod broker;
pub mod flows;
pub mod github;
pub mod jira;
pub mod linear;
pub mod material;
pub mod pace;
pub mod slack;

#[cfg(test)]
pub(crate) mod fake;
