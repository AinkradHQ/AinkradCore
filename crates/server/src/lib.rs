// `cli` (the `serve` entry, moved here from `main.rs` so a composed binary can reuse it) names this
// crate by its package name.
extern crate self as ainkrad_core_server;

pub mod agents;
pub mod api;
pub mod auth;
pub mod cli;
pub mod gateway;
pub mod hub;
pub mod jobs;
pub mod live;
pub mod module;
pub mod ops;
pub mod push;
pub mod scheduler;
pub mod store;
