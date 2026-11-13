//! The Brain's data and its pure rules: the item format (E1-1), the signals of an item (E2-1), the
//! grouping of items into proposed rooms (E2-2) and the refusal rules (E1-4). It depends on no Core
//! crate and does no I/O, so every rule here is a plain function with a plain test.

pub mod group;
pub mod item;
pub mod rules;
pub mod semantic;
pub mod signals;
