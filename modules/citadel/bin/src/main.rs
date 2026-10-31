//! The Core with Citadel carried (E2-13): `ainkrad-core-citadel serve <db> --enable-module citadel`.
//!
//! The dependency direction forbids any Core crate from depending on `modules/`, so the Core's
//! own binary cannot name Citadel. This crate may depend on both: it hands `cli::run` the module,
//! and `serve` mounts it only on the explicit `--enable-module citadel` (a plain `serve` of this
//! binary mounts nothing, exactly as the plain Core). `serve` runs the module's migrations, event
//! kinds and audit actions before it mounts, registers its scheduler jobs and its settings.
//! Built by `make build-citadel`; not part of `make build`.

use std::sync::Arc;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    ainkrad_core_server::cli::run(vec![Arc::new(citadel_module::Citadel::default())]).await
}
