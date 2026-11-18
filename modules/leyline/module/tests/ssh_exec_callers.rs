//! Y4-02 review, MEDIUM: the Hub's ungated ssh.exec dispatch takes no proof, so only Leyline's `exec.rs`
//! (which holds the gate's `Authorized`) may call it. Fails when any other source file does.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if name != "target" && name != ".git" && name != "node_modules" {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn only_the_gated_runner_calls_the_ungated_dispatch() {
    // No `(`: an alias or a value use is a caller too. Comment lines (`//`) do not count. The name
    // is built from two pieces so this file never holds it whole.
    let needle = format!("dispatch_ssh_{}", "exec");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    for d in ["crates", "modules"] {
        rust_files(&root.join(d), &mut files);
    }
    assert!(files.len() > 50, "the walk found the source tree");
    let mut callers: Vec<String> = files
        .iter()
        .filter(|f| {
            std::fs::read_to_string(f).is_ok_and(|s| {
                s.lines()
                    .any(|l| !l.trim_start().starts_with("//") && l.contains(&needle))
            })
        })
        .map(|f| {
            f.canonicalize()
                .unwrap()
                .strip_prefix(root.canonicalize().unwrap())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    callers.sort();
    assert_eq!(
        callers,
        [
            "crates/server/src/hub/mod.rs",
            "modules/leyline/module/src/exec.rs"
        ],
        "a new caller of the ungated ssh.exec dispatch"
    );
}
