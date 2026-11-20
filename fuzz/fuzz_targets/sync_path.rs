//! E15-2 (spec 4.3, 11): the workspace path checks and the Core's path-safe file access, against
//! anything a runner or client can name. A path is refused or it stays inside the root: after
//! every input, nothing exists outside the root, whatever links the tree holds.
#![no_main]
use std::path::PathBuf;
use std::sync::OnceLock;

use ainkrad_core_server::workspace::fs::{Tree, check_path};
use ainkrad_core_server::workspace::manifest::link_ok;
use ainkrad_proto::v2::wire_path_problem;
use libfuzzer_sys::fuzz_target;

struct Fixture {
    tree: Tree,
    outside: PathBuf,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let base = std::env::temp_dir().join(format!("ainkrad-sync-path-fuzz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (root, outside) = (base.join("root"), base.join("outside"));
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("out")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("d/out")).unwrap();
        std::os::unix::fs::symlink("../outside/f", root.join("leaf")).unwrap();
        Fixture { tree: Tree::open(&root).unwrap(), outside }
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    // The Core's check is never looser than the wire check the runner shares.
    if check_path(path).is_ok() {
        assert!(wire_path_problem(path).is_none());
        assert!(!path.split('/').any(|p| p == ".." || p == "." || p.is_empty()));
    }
    let f = fixture();
    let _ = f.tree.write(path, b"x", None);
    let _ = f.tree.read(path, 16);
    let _ = f.tree.remove(path);
    let _ = f.tree.symlink(path, "d/x");
    // A link target the manifest accepts never climbs out of the root.
    if link_ok("a", path) {
        assert!(!path.starts_with('/'));
    }
    assert_eq!(
        std::fs::read_dir(&f.outside).unwrap().count(),
        0,
        "something was written through a link"
    );
});
