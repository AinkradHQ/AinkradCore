//! Files and directories the runner makes inside a harness's home, which the agent can also
//! write to (KAN-435 G6). The runner is outside the sandbox, so anything the agent plants there is
//! read by a process with more reach than the agent: a link at a name the runner writes must never
//! be followed, and a link where a directory belongs must never be walked into.

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

/// Makes sure `root/rel` is a chain of real directories (no link, no file in the way), creating
/// them. A link or file found where a directory belongs is removed (the link, never what it points
/// to) and replaced. `root` itself is the runner's and is not checked; `rel` is relative and plain.
pub(crate) fn real_dir(root: &Path, rel: &Path) -> io::Result<()> {
    let mut at = root.to_path_buf();
    for part in rel.components() {
        let Component::Normal(name) = part else {
            return Err(io::Error::other("a runner directory path is not plain"));
        };
        at.push(name);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => continue,
            Ok(_) => std::fs::remove_file(&at)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        std::fs::create_dir(&at)?;
    }
    Ok(())
}

/// Writes `dir/name`, replacing what is there. A link at the name or at the temp name is removed
/// (not followed), the temp file is made with `create_new`, and a rename puts it in place.
pub(crate) fn write_replacing(dir: &Path, name: &str, text: &str) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.runner-tmp"));
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("safe-fs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_link_where_a_directory_belongs_is_replaced_and_never_walked() {
        let root = scratch("dirs");
        let outside = scratch("outside");
        std::fs::write(outside.join("keep"), "keep").unwrap();
        // A link at the first part, a file at the second, a link to a file at the last.
        std::os::unix::fs::symlink(&outside, root.join("a")).unwrap();
        real_dir(&root, Path::new("a/b/c")).unwrap();
        assert!(root.join("a/b/c").is_dir());
        assert!(
            !std::fs::symlink_metadata(root.join("a"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            1,
            "wrote outside"
        );
        std::fs::remove_dir_all(root.join("a/b/c")).unwrap();
        std::fs::write(root.join("a/b/c"), "x").unwrap();
        std::os::unix::fs::symlink(outside.join("keep"), root.join("a/b/d")).unwrap();
        real_dir(&root, Path::new("a/b/c")).unwrap();
        real_dir(&root, Path::new("a/b/d")).unwrap();
        assert!(root.join("a/b/c").is_dir() && root.join("a/b/d").is_dir());
        assert_eq!(
            std::fs::read_to_string(outside.join("keep")).unwrap(),
            "keep"
        );
        // Dots and absolute parts are refused.
        assert!(real_dir(&root, Path::new("../x")).is_err());
        assert!(real_dir(&root, Path::new("/x")).is_err());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_file_is_written_by_rename_and_never_through_a_planted_link() {
        let dir = scratch("file");
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        for name in ["f", "f.runner-tmp"] {
            std::os::unix::fs::symlink(&victim, dir.join(name)).unwrap();
        }
        write_replacing(&dir, "f", "new").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert!(
            std::fs::symlink_metadata(dir.join("f"))
                .unwrap()
                .file_type()
                .is_file()
        );
        assert_eq!(std::fs::read_to_string(dir.join("f")).unwrap(), "new");
        write_replacing(&dir, "f", "again").unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("f")).unwrap(), "again");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
