//! The released Core: `ainkrad-core-brain serve ...` mounts the Brain by default (no flag needed, so the
//! unit and existing installs are unchanged). The release ships this binary under the name
//! `ainkrad-core-server`. No Core crate may depend on `modules/`, so this crate hands `cli::run` the
//! module. Built by `make build-brain`.

use std::sync::Arc;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    ainkrad_core_server::cli::run_with_defaults(
        vec![Arc::new(brain_module::Brain::default())],
        &["brain"],
    )
    .await
}
