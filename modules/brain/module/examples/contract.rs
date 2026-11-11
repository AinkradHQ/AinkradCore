//! Prints the Core's contract with the Brain's routes merged in (`make contract` writes it to
//! `modules/brain/api/openapi.core.json`).

use std::sync::Arc;

use ainkrad_core_server::module::Module;

fn main() {
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(brain_module::Brain::default())];
    print!("{}", ainkrad_core_server::api::v1::spec::json_for(&modules));
}
