//! `Hub::dispatch_ssh_agent` takes no proof (the hub cannot see a module's gate), so only the file
//! whose entry points take the gate's `Authorized` may call it. This fails if another one does.

use std::path::Path;

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn only_direct_rs_dispatches_the_agent_ops() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let callers: Vec<_> = files
        .iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .unwrap()
                .contains("dispatch_ssh_agent(")
        })
        .map(|f| f.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(callers, ["direct.rs"]);
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
