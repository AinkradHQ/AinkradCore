//! One-off import of approved HTML mockups into a Core's database (V4-02), run on the Core host:
//! `import_mockups <core.db> <name> <dir> [skip-prefix ...]`. Same checks as an upload; a symlink,
//! a bad path or a limit refuses the whole folder and stores nothing.

use std::path::Path;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("usage: import_mockups <core.db> <name> <dir> [skip-prefix ...]");
        std::process::exit(2);
    }
    let pool = ainkrad_core_server::store::connect(Path::new(&a[1]))
        .await
        .expect("open the database");
    match design_module::import_dir(&pool, Path::new(&a[3]), &a[2], &a[4..]).await {
        Ok((id, n)) => println!("{id}\t{n} files\t{}", a[2]),
        Err(e) => {
            eprintln!("refused: {e}");
            std::process::exit(1);
        }
    }
}
