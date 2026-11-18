//! The Brain through the Core's real gate: signed requests into `api::router`, so scope, step-up,
//! the migration guard and the registries are the Core's own code. Every item here is synthetic.

mod ai;
mod ai_semantic;
mod ai_write;
mod auto_distil;
mod checkpoint;
mod backfill;
mod changes;
mod claim;
mod collectors;
mod context;
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
mod redistil;
mod retention;
mod review;
mod rooms;
mod runner_history;
mod schema_v2;
mod semantic;
mod sorting;
mod supersede;
mod sync;
mod tidy;
