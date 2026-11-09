//! The dependency direction (E1-02.6): modules build on the platform, never the other way. No
//! package of the Core workspace may have a path dependency into `modules/`.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[test]
fn no_workspace_crate_depends_on_a_module() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("cargo runs");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).expect("cargo metadata is JSON");
    let modules = Path::new(meta["workspace_root"].as_str().unwrap()).join("modules");
    let packages = meta["packages"].as_array().unwrap();
    assert!(packages.len() > 1, "the workspace's packages are listed");
    let wrong: Vec<String> = packages
        .iter()
        .flat_map(|p| {
            let name = p["name"].as_str().unwrap_or_default().to_owned();
            p["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|d| d["path"].as_str())
                .filter(|path| Path::new(path).starts_with(&modules))
                .map(move |path| format!("{name} -> {path}"))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "Core crates must not depend on modules/: {wrong:?}"
    );
}
