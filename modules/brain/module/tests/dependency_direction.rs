//! BM-04 §5.2: `brain-model` is pure data and logic, so it names no Core crate, no database and no
//! async runtime; the module may use the Core, never the other way round; the bin is the only crate
//! that mounts the module.

fn deps(manifest: &str) -> String {
    let text = std::fs::read_to_string(format!(
        "{}/../{manifest}/Cargo.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    text.split("[dependencies]")
        .nth(1)
        .unwrap_or("")
        .split("\n[")
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn model_depends_on_no_core_crate_database_or_runtime() {
    let d = deps("model");
    for banned in ["ainkrad", "sqlx", "tokio", "axum", "brain-module", "utoipa"] {
        assert!(
            !d.contains(banned),
            "brain-model must not depend on {banned}"
        );
    }
}

#[test]
fn module_does_not_depend_on_the_bin() {
    assert!(!deps("module").contains("ainkrad-core-brain"));
}

#[test]
fn only_the_bin_depends_on_the_module() {
    assert!(!deps("model").contains("brain-module"));
    assert!(deps("bin").contains("brain-module"));
}
