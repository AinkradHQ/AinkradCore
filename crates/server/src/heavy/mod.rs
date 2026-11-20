//! Heavy jobs (E15-3, spec §5): the Core decides whether a build or test command runs here or on
//! other hardware. `rules` and `history` are tiers 1 and 2, `decide` ties the tiers together and
//! asks the Decisions service for tier 3.

pub mod decide;
pub mod history;
pub mod rules;

pub mod run;

static WS_ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Takes the Core's `workspace_root` (config or `AINKRAD_WORKSPACE_ROOT`); `serve` calls it once.
pub fn set_workspace_root(root: std::path::PathBuf) {
    let _ = WS_ROOT.set(root);
}

/// The canonical workspace the jobs' folders live in.
pub fn workspace() -> crate::workspace::paths::Workspace {
    use crate::workspace::paths::{DEFAULT_ROOT, Workspace};
    match WS_ROOT.get() {
        Some(r) => Workspace::new(r.clone()),
        None => Workspace::new(
            std::env::var("AINKRAD_WORKSPACE_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.into()),
        ),
    }
}

/// Environment names a job may carry from a shim or a client (the shim sends the same list).
pub const ENV_ALLOW: [&str; 11] = [
    "CI",
    "TERM",
    "NO_COLOR",
    "FORCE_COLOR",
    "CARGO_TERM_COLOR",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "RUSTFLAGS",
    "NODE_ENV",
    "GOFLAGS",
    "CGO_ENABLED",
];
