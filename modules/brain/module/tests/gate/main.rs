//! The Brain through the Core's real gate: signed requests into `api::router`, so scope, step-up,
//! the migration guard and the registries are the Core's own code. Every item here is synthetic.

mod ai;
mod ai_semantic;
mod ai_write;
mod auto_distil;
mod changes;
mod checkpoint;
mod backfill;
mod claim;
mod collectors;
mod common;
mod decide;
mod distil;
mod index;
mod intake;
mod keys;
mod lore;
mod merge;
mod overview;
mod project_rooms;
mod query;
mod retention;
mod review;
mod schema_v2;
mod rooms;
mod runner_history;
mod semantic;
mod sorting;
mod supersede;
mod sync;
mod tidy;
