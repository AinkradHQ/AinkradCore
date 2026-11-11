//! The Core with the Brain carried: `ainkrad-core-brain serve <db> --enable-module brain`. Like
//! `ainkrad-core-citadel`: no Core crate may depend on `modules/`, so this crate hands `cli::run`
//! the module. Built by `make build-brain`.

use std::sync::Arc;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    ainkrad_core_server::cli::run(vec![Arc::new(brain_module::Brain::default())]).await
}
