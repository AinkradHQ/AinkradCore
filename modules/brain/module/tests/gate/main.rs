//! The Brain through the Core's real gate: signed requests into `api::router`, so scope, step-up,
//! the migration guard and the registries are the Core's own code. Every item here is synthetic.

mod ai;
mod ai_semantic;
mod ai_write;
mod backfill;
mod claim;
mod collectors;
mod common;
mod distil;
mod index;
mod intake;
mod keys;
mod review;
mod rooms;
mod runner_history;
mod semantic;
mod sync;
