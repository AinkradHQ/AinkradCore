//! Prints the Core's contract with the Lore routes merged in (`make contract` writes it to
//! `modules/lore/api/openapi.core.json`).

use std::sync::Arc;

use ainkrad_core_server::module::Module;

fn main() {
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(lore_module::Lore::default())];
    print!("{}", ainkrad_core_server::api::v1::spec::json_for(&modules));
}
