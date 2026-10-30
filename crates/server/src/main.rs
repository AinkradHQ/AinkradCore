//! The plain Core: no module is carried, so `--enable-module` has nothing to mount. A binary that
//! carries modules (`modules/citadel/bin`) calls the same `cli::run` with them.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    ainkrad_core_server::cli::run(Vec::new()).await
}
