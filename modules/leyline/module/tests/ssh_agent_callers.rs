//! The agent ops leave the Core only through the hub's one `SshAgentLine` (no public constructor;
//! `Hub::take_ssh_agent_line` hands it out once). Structurally: a second take gets nothing. As a
//! text check too: no file of the whole workspace but `direct.rs` takes it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ainkrad_core_server::hub::{Hub, HubConfig};

/// Every `.rs` file under `dir`, skipping build output and nested checkouts (worktrees).
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            let name = p.file_name().unwrap_or_default();
            if name == "target"
                || name == ".git"
                || name == "node_modules"
                || p.join(".git").exists()
            {
                continue;
            }
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn only_direct_rs_in_the_workspace_takes_the_agent_line() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let root = root.canonicalize().unwrap();
    assert!(root.join("Cargo.toml").exists(), "not the workspace root");
    let mut files = Vec::new();
    sources(&root, &mut files);
    // Split so the old name in this file does not match itself.
    let needle = concat!(".take_ssh_agent", "_line(");
    let old = concat!("dispatch_ssh", "_agent(");
    let mut callers: Vec<_> = files
        .iter()
        .filter(|f| {
            let text = std::fs::read_to_string(f).unwrap_or_default();
            text.contains(needle) || text.contains(old)
        })
        .map(|f| {
            f.strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    callers.sort();
    // This file takes the line of a hub of its own (below), never an App's.
    assert_eq!(
        callers,
        [
            "modules/leyline/module/src/direct.rs",
            "modules/leyline/module/tests/ssh_agent_callers.rs"
        ]
    );
}

#[test]
fn the_hub_hands_out_its_agent_line_once() {
    let hub = Arc::new(Hub::new(HubConfig::default()));
    let line = hub.take_ssh_agent_line().expect("the first take");
    assert!(line.serves(&hub));
    assert!(hub.take_ssh_agent_line().is_none(), "a second line");
    let other = Arc::new(Hub::new(HubConfig::default()));
    assert!(!line.serves(&other));
}

/// The gate decides, before any lease: both routes authorize `Action::Direct` first.
#[test]
fn both_routes_pass_the_gate_before_anything_else() {
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/direct.rs"))
        .unwrap();
    assert_eq!(
        src.matches("gate::authorize(&app, &Principal::of(&me), &id, &Action::Direct)")
            .count(),
        2
    );
}
