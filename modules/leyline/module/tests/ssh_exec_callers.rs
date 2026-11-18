//! Y4-02 review, MEDIUM: the Hub's ungated ssh.exec dispatch takes no proof, so only Leyline's `exec.rs`
//! (which holds the gate's `Authorized`) may call it. Y7-01 review: the same for the SFTP read dispatch.
//! Fails when any other source file does.

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

/// Every source file under `crates` and `modules` that mentions `needle` (no `(`: an alias or a
/// value use is a caller too).
fn callers(needle: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = Vec::new();
    for d in ["crates", "modules"] {
        rust_files(&root.join(d), &mut files);
    }
    assert!(files.len() > 50, "the walk found the source tree");
    let mut found: Vec<String> = files
        .iter()
        .filter(|f| std::fs::read_to_string(f).is_ok_and(|s| s.contains(needle)))
        .map(|f| {
            f.canonicalize()
                .unwrap()
                .strip_prefix(root.canonicalize().unwrap())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    found
}

const ALLOWED: [&str; 2] = [
    "crates/server/src/hub/mod.rs",
    "modules/leyline/module/src/exec.rs",
];

// The needles are split so this file does not match itself.
#[test]
fn only_the_gated_runner_calls_dispatch_ssh_exec() {
    assert_eq!(
        callers(&format!("dispatch_ssh_{}", "exec")),
        ALLOWED,
        "a new caller of the ungated ssh.exec dispatch"
    );
}

#[test]
fn only_the_gated_runner_calls_dispatch_ssh_sftp_read() {
    assert_eq!(
        callers(&format!("dispatch_ssh_sftp_{}", "read")),
        ALLOWED,
        "a new caller of the ungated sftp read dispatch"
    );
}
