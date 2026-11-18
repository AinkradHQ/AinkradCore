//! Prints the Core's contract with the Design routes merged in (`make contract` writes it to
//! `modules/design/api/openapi.core.json`).

use std::sync::Arc;

use ainkrad_core_server::module::Module;

fn main() {
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(design_module::Design::default())];
    print!("{}", ainkrad_core_server::api::v1::spec::json_for(&modules));
}
