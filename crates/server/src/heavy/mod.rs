//! Heavy jobs (E15-3, spec §5): the Core decides whether a build or test command runs here or on
//! other hardware. `rules` and `history` are tiers 1 and 2, `decide` ties the tiers together and
//! asks the Decisions service for tier 3.

pub mod decide;
pub mod history;
pub mod rules;
