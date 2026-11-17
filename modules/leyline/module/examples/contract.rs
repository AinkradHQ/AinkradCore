//! Prints the Core's contract with the Leyline routes merged in (`make contract` writes it to
//! `modules/leyline/api/openapi.core.json`).

use std::sync::Arc;

use ainkrad_core_server::module::Module;

fn main() {
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(leyline_module::Leyline)];
    print!("{}", ainkrad_core_server::api::v1::spec::json_for(&modules));
}
