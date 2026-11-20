//! Session documents on the Core (Lore E10-2 moved off the runner, E15-2 spec 4.7): the `.md`
//! files an AI session made or changed in its own folder, read straight from the workspace
//! through [`Tree`] (so a link in the folder never leads out of it).
//!
//! "Made or changed" is measured against a baseline of the folder's documents, `(size, mtime)` by
//! path, taken when the Core first hears the session's folder (a moment after its harness
//! started) and kept outside the folder, at `<ws>/.ainkrad-docs/<session>.json`, where the
//! session's own sandbox cannot reach it. ponytail: files the agent wrote in the seconds before
//! the baseline are taken as already there; the runner's own baseline was taken just before the start.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use ainkrad_proto::v2::{
    DOC_MAX_BYTES, DOC_MAX_DEPTH, DOC_MAX_FILES, DOC_MAX_VISITED, DocFile, valid_doc_path,
};
use sha2::{Digest, Sha256};

use super::fs::Tree;
use ainkrad_sys::Kind;

type Base = BTreeMap<String, (u64, i64)>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The lowercase hex sha-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Every document of the folder as `(path, size, mtime ns)`, within the walk limits.
fn walk(tree: &Tree) -> Base {
    let mut out = Base::new();
    let mut visited = 0usize;
    let mut stack = vec![(String::new(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(names) = tree.read_dir(&dir) else {
            continue;
        };
        for (name, st) in names {
            visited += 1;
            if visited > DOC_MAX_VISITED {
                return out;
            }
            let rel = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            match st.kind {
                Kind::Dir if depth + 1 < DOC_MAX_DEPTH => {
                    let skip = name.starts_with('.') || name == "node_modules" || name == "target";
                    if !skip {
                        stack.push((rel, depth + 1));
                    }
                }
                Kind::File if valid_doc_path(&rel) => {
                    out.insert(rel, (st.size, st.mtime_ns));
                }
                _ => {}
            }
        }
    }
    out
}

fn base_path(ws_root: &Path, session: &str) -> io::Result<std::path::PathBuf> {
    // The session id becomes a file name: one plain component only.
    let ok = ainkrad_proto::v2::wire_path_problem(session).is_none() && !session.contains('/');
    match ok {
        true => Ok(ws_root
            .join(".ainkrad-docs")
            .join(format!("{session}.json"))),
        false => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

/// Records the folder's documents as the baseline of `session`, unless one is kept already.
pub fn take_baseline(ws_root: &Path, session: &str, tree: &Tree) -> io::Result<()> {
    let path = base_path(ws_root, session)?;
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path.parent().expect("a file path"))?;
    let json = serde_json::to_vec(&walk(tree)).map_err(io::Error::other)?;
    std::fs::write(path, json)
}

/// The documents made or changed since the baseline, newest limits applied (at most
/// [`DOC_MAX_FILES`], over [`DOC_MAX_BYTES`] left out), with their hashes. A session with no
/// baseline gets one now and lists nothing.
pub fn list(ws_root: &Path, session: &str, tree: &Tree) -> io::Result<Vec<DocFile>> {
    let path = base_path(ws_root, session)?;
    let Ok(bytes) = std::fs::read(&path) else {
        take_baseline(ws_root, session, tree)?;
        return Ok(Vec::new());
    };
    let base: Base = serde_json::from_slice(&bytes).unwrap_or_default();
    let mut files = Vec::new();
    for (rel, (size, ns)) in walk(tree) {
        if base.get(&rel) == Some(&(size, ns)) || size > DOC_MAX_BYTES as u64 {
            continue;
        }
        // Read through the tree again: the hash is of what is there now.
        let Ok(data) = tree.read(&rel, DOC_MAX_BYTES as u64) else {
            continue;
        };
        files.push(DocFile {
            path: rel,
            size: data.len() as u64,
            sha256: sha256(&data),
        });
        if files.len() >= DOC_MAX_FILES {
            break;
        }
    }
    Ok(files)
}

/// A document's text and its sha-256. The path must be a document path.
pub fn read(tree: &Tree, rel: &str) -> io::Result<(String, String)> {
    if !valid_doc_path(rel) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a document path",
        ));
    }
    let data = tree.read(rel, DOC_MAX_BYTES as u64)?;
    let sha = sha256(&data);
    let text = String::from_utf8(data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the file is not UTF-8 text"))?;
    Ok((text, sha))
}

/// What a document write needs checked and done.
pub enum Write {
    /// The bytes to put at the path (the file is as `base` says, or new when `base` is none).
    Put(Vec<u8>),
    /// The file is not as `base` says (or exists when none was named): nothing is written.
    Conflict,
}

/// Checks a Lore write: `text` goes over `rel` only when the file's current sha-256 is `base`
/// (a new file takes none). The caller then writes the bytes (directly, or pushed to a runner for
/// an overflow session).
pub fn plan_write(tree: &Tree, rel: &str, text: &str, base: Option<&str>) -> io::Result<Write> {
    if !valid_doc_path(rel) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a document path",
        ));
    }
    if text.len() > DOC_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the document is too large",
        ));
    }
    let now = match tree.read(rel, DOC_MAX_BYTES as u64) {
        Ok(d) => Some(sha256(&d)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    Ok(match (now.as_deref(), base) {
        (None, None) => Write::Put(text.as_bytes().to_vec()),
        (Some(n), Some(b)) if n == b => Write::Put(text.as_bytes().to_vec()),
        _ => Write::Conflict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-docs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn only_documents_made_or_changed_after_the_baseline_are_listed() {
        let ws = temp("ws");
        let d = temp("folder");
        fs::write(d.join("old.md"), "old").unwrap();
        fs::create_dir_all(d.join("docs")).unwrap();
        let tree = Tree::open(&d).unwrap();
        assert!(
            list(&ws, "as_1", &tree).unwrap().is_empty(),
            "the first call takes the baseline"
        );
        fs::write(d.join("docs/plan.md"), "plan").unwrap();
        fs::write(d.join("CLAUDE.md"), "steer").unwrap();
        fs::create_dir_all(d.join(".claude")).unwrap();
        fs::write(d.join(".claude/n.md"), "hidden").unwrap();
        fs::write(d.join("old.md"), "changed text").unwrap();
        let mut got: Vec<_> = list(&ws, "as_1", &tree)
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .collect();
        got.sort();
        assert_eq!(got, ["docs/plan.md", "old.md"]);
        assert!(
            !d.join(".ainkrad-docs").exists(),
            "the baseline is not in the session folder"
        );
        assert!(list(&ws, "../x", &tree).is_err());
        let _ = fs::remove_dir_all(&ws);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_write_needs_the_hash_the_file_has_and_a_link_is_never_followed() {
        let d = temp("write");
        let outside = temp("write-out");
        fs::write(d.join("a.md"), "one").unwrap();
        fs::write(outside.join("s.md"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.join("s.md"), d.join("l.md")).unwrap();
        let tree = Tree::open(&d).unwrap();
        let (text, sha) = read(&tree, "a.md").unwrap();
        assert_eq!(text, "one");
        assert!(matches!(
            plan_write(&tree, "a.md", "two", Some(&sha)).unwrap(),
            Write::Put(_)
        ));
        assert!(matches!(
            plan_write(&tree, "a.md", "two", Some("0".repeat(64).as_str())).unwrap(),
            Write::Conflict
        ));
        assert!(matches!(
            plan_write(&tree, "a.md", "two", None).unwrap(),
            Write::Conflict
        ));
        assert!(matches!(
            plan_write(&tree, "new.md", "x", None).unwrap(),
            Write::Put(_)
        ));
        assert!(matches!(
            plan_write(&tree, "new.md", "x", Some(&sha)).unwrap(),
            Write::Conflict
        ));
        assert!(read(&tree, "l.md").is_err(), "a link is refused");
        assert!(read(&tree, "../x.md").is_err() && read(&tree, "CLAUDE.md").is_err());
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&outside);
    }
}
