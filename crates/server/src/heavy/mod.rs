//! Heavy jobs (E15-3, spec §5): the Core decides whether a build or test command runs here or on
//! other hardware. `rules` and `history` are tiers 1 and 2, `decide` ties the tiers together and
//! asks the Decisions service for tier 3.

pub mod decide;
pub mod history;
pub mod rules;

/// The canonical workspace the jobs' folders live in.
// ponytail: the default root; E15-2 puts the configured `workspace_root` on `App`, and this reads it.
pub fn workspace() -> crate::workspace::paths::Workspace {
    crate::workspace::paths::Workspace::new(crate::workspace::paths::DEFAULT_ROOT)
}
