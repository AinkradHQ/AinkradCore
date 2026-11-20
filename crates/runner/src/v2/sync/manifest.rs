//! Manifests of a cache folder (E15-4, the runner end of spec §4.5): entries by wire path, the tree
//! hash both ends compare, and the scan that builds them under the Core's rules.
//!
//! **The tree hash fold is E15-2's** (`server/src/workspace/manifest.rs`); this is a copy, and
//! `tests::the_fold_is_the_documented_one` rebuilds it from the spec's words to catch drift. blake3
//! over `ainkrad-tree-v1\n`, then each entry in ascending path-byte order: `u32 LE path length,
//! path, kind byte (0 file, 1 symlink), exec byte, u64 LE size, 32-byte file hash, u32 LE link
//! length, link`. A file's hash is blake3 of its content; a symlink's is blake3 of its target text.

use std::collections::BTreeMap;
use std::io::{self, Read as _};

use ainkrad_proto::v2::{CHUNK_BYTES, Entry, EntryKind, Hash, MAX_FILE_BYTES, TreeHash};
use ainkrad_sys::Kind;
use serde::{Deserialize, Serialize};

use super::rules::{BUILD_DIRS, Rules, has_git};
use super::tree::{MAX_DEPTH, Tree, check_path};

pub type Entries = BTreeMap<String, Entry>;

/// blake3 of a reader's content, its size, and each [`CHUNK_BYTES`] chunk's hash.
pub fn hash_reader(mut r: impl io::Read) -> io::Result<(Hash, u64, Vec<Hash>)> {
    let mut whole = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; CHUNK_BYTES as usize];
    loop {
        let mut n = 0;
        while n < buf.len() {
            let got = r.read(&mut buf[n..])?;
            if got == 0 {
                break;
            }
            n += got;
        }
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        chunks.push(Hash(*blake3::hash(&buf[..n]).as_bytes()));
        size += n as u64;
        if n < buf.len() {
            break;
        }
    }
    Ok((Hash(*whole.finalize().as_bytes()), size, chunks))
}

pub fn tree_hash(entries: &Entries) -> TreeHash {
    let mut h = blake3::Hasher::new();
    h.update(b"ainkrad-tree-v1\n");
    for (path, e) in entries {
        h.update(&(path.len() as u32).to_le_bytes());
        h.update(path.as_bytes());
        h.update(&[u8::from(e.kind == EntryKind::Symlink), u8::from(e.exec)]);
        h.update(&e.size.to_le_bytes());
        h.update(&e.hash.0);
        let link = e.link.as_deref().unwrap_or("");
        h.update(&(link.len() as u32).to_le_bytes());
        h.update(link.as_bytes());
    }
    TreeHash(*h.finalize().as_bytes())
}

/// Whether the relative symlink `target` of the link at `path` stays inside the project: not
/// absolute, never above the root at any step, and not through `.git`.
pub fn link_ok(path: &str, target: &str) -> bool {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains('\0')
        || target.contains('\\')
    {
        return false;
    }
    let mut depth = path.split('/').count() as i64 - 1;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            p if p.eq_ignore_ascii_case(".git") => return false,
            _ => depth += 1,
        }
    }
    true
}

/// What the runner remembers about a file it hashed: `(mtime ns, size, inode)` and its entry, so an
/// unchanged file is not read again (spec §4.5: index path to mtime, size, ino, hash).
#[derive(Default, Serialize, Deserialize)]
pub struct Memo(pub BTreeMap<String, ((i64, u64, u64), Entry)>);

/// A file modified within this many nanoseconds of the scan is hashed again next time.
const RACY_NS: i64 = 2_000_000_000;

#[derive(Debug, Default)]
pub struct Scan {
    pub entries: Entries,
    /// Paths left out that a person would want to hear of (too big, a link that leaves the project).
    pub skipped: Vec<String>,
}

/// Scans `tree` under `rules`: sync IN (`out` false: what the Core pushes and the tree hash covers)
/// or sync OUT (`out` true: also named build output). Hash work is skipped for a file `memo` knows.
pub fn scan(
    tree: &Tree,
    rules: &Rules,
    out: bool,
    memo: &mut Memo,
    now_ns: i64,
) -> io::Result<Scan> {
    let mut res = Scan::default();
    let mut seen = std::collections::BTreeSet::new();
    walk(tree, rules, out, memo, now_ns, "", 0, &mut res, &mut seen)?;
    memo.0.retain(|p, _| seen.contains(p));
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn walk(
    tree: &Tree,
    rules: &Rules,
    out: bool,
    memo: &mut Memo,
    now_ns: i64,
    dir: &str,
    depth: usize,
    res: &mut Scan,
    seen: &mut std::collections::BTreeSet<String>,
) -> io::Result<()> {
    if depth >= MAX_DEPTH {
        return Ok(());
    }
    let mut names = tree.read_dir(dir)?;
    names.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, st) in names {
        let rel = if dir.is_empty() {
            name.clone()
        } else {
            format!("{dir}/{name}")
        };
        if has_git(&name) {
            continue;
        }
        if check_path(&rel).is_err() {
            res.skipped.push(rel);
            continue;
        }
        match st.kind {
            Kind::Dir => {
                if BUILD_DIRS.contains(&name.as_str()) && !rules.enters_build_dirs(out) {
                    continue;
                }
                walk(tree, rules, out, memo, now_ns, &rel, depth + 1, res, seen)?;
            }
            Kind::File | Kind::Symlink => {
                if !(if out {
                    rules.sync_out(&rel)
                } else {
                    rules.sync_in(&rel)
                }) {
                    continue;
                }
                if st.kind == Kind::Symlink {
                    let target = tree.read_link(&rel).unwrap_or_default();
                    if !link_ok(&rel, &target) {
                        res.skipped.push(rel);
                        continue;
                    }
                    seen.insert(rel.clone());
                    res.entries.insert(
                        rel.clone(),
                        Entry {
                            path: rel,
                            kind: EntryKind::Symlink,
                            exec: false,
                            size: target.len() as u64,
                            hash: Hash(*blake3::hash(target.as_bytes()).as_bytes()),
                            chunks: Vec::new(),
                            link: Some(target),
                        },
                    );
                    continue;
                }
                if st.size > MAX_FILE_BYTES {
                    res.skipped.push(rel);
                    continue;
                }
                let key = (st.mtime_ns, st.size, st.ino);
                let exec = st.mode & 0o100 != 0;
                seen.insert(rel.clone());
                if let Some((k, e)) = memo.0.get(&rel)
                    && *k == key
                    && e.exec == exec
                {
                    res.entries.insert(rel, e.clone());
                    continue;
                }
                let file = match tree.open_file(&rel) {
                    Ok(f) => f,
                    // Gone, or swapped for a link, since the listing: leave it out this time.
                    Err(_) => {
                        seen.remove(&rel);
                        continue;
                    }
                };
                let (hash, size, chunks) = hash_reader(file.take(MAX_FILE_BYTES + 1))?;
                if size > MAX_FILE_BYTES {
                    seen.remove(&rel);
                    res.skipped.push(rel);
                    continue;
                }
                let entry = Entry {
                    path: rel.clone(),
                    kind: EntryKind::File,
                    exec,
                    size,
                    hash,
                    chunks,
                    link: None,
                };
                if now_ns - st.mtime_ns > RACY_NS {
                    memo.0.insert(rel.clone(), (key, entry.clone()));
                }
                res.entries.insert(rel, entry);
            }
            Kind::Other => res.skipped.push(rel),
        }
    }
    Ok(())
}

/// The paths that collide on a case-insensitive disk (macOS): a tree with any is refused for a Mac.
/// ponytail: lowercase folding only, no Unicode normalisation (NFD) as APFS does.
pub fn case_collisions<'a>(paths: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut out = std::collections::BTreeSet::new();
    for p in paths {
        let mut acc = String::new();
        for part in p.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            let folded = acc.to_lowercase();
            match seen.get(&folded) {
                Some(real) if *real != acc => {
                    out.insert((real.clone(), acc.clone()));
                }
                Some(_) => {}
                None => {
                    seen.insert(folded, acc.clone());
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Entries of `to` that `from` lacks or holds differently, and paths of `from` that `to` lacks.
pub fn diff(from: &Entries, to: &Entries) -> (Vec<Entry>, Vec<String>) {
    let put = to
        .values()
        .filter(|e| {
            from.get(&e.path)
                .is_none_or(|f| f.hash != e.hash || f.exec != e.exec || f.kind != e.kind)
        })
        .cloned()
        .collect();
    let delete = from
        .keys()
        .filter(|p| !to.contains_key(*p))
        .cloned()
        .collect();
    (put, delete)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, body: &[u8], exec: bool) -> Entry {
        Entry {
            path: path.to_owned(),
            kind: EntryKind::File,
            exec,
            size: body.len() as u64,
            hash: Hash(*blake3::hash(body).as_bytes()),
            ..Entry::default()
        }
    }

    #[test]
    fn the_fold_is_the_documented_one() {
        let mut m = Entries::new();
        for e in [file("b.txt", b"two", false), file("a/x.sh", b"one", true)] {
            m.insert(e.path.clone(), e);
        }
        // Written out from the spec's words, in ascending path-byte order: `a/x.sh` then `b.txt`.
        let mut h = blake3::Hasher::new();
        h.update(b"ainkrad-tree-v1\n");
        for (p, body, exec) in [("a/x.sh", &b"one"[..], 1u8), ("b.txt", &b"two"[..], 0u8)] {
            h.update(&(p.len() as u32).to_le_bytes());
            h.update(p.as_bytes());
            h.update(&[0u8, exec]);
            h.update(&(body.len() as u64).to_le_bytes());
            h.update(blake3::hash(body).as_bytes());
            h.update(&0u32.to_le_bytes());
        }
        assert_eq!(tree_hash(&m).0, *h.finalize().as_bytes());
        let empty = blake3::hash(b"ainkrad-tree-v1\n");
        assert_eq!(tree_hash(&Entries::new()).0, *empty.as_bytes());
    }

    #[test]
    fn chunks_are_one_mebibyte_and_the_last_may_be_short() {
        let data = vec![7u8; CHUNK_BYTES as usize + 5];
        let (whole, size, chunks) = hash_reader(&data[..]).unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(chunks.len(), 2);
        assert_eq!(whole.0, *blake3::hash(&data).as_bytes());
        assert_eq!(
            chunks[1].0,
            *blake3::hash(&data[CHUNK_BYTES as usize..]).as_bytes()
        );
        assert!(hash_reader(&b""[..]).unwrap().2.is_empty());
    }

    #[test]
    fn links_stay_inside_the_project() {
        assert!(link_ok("a/b", "c"));
        assert!(link_ok("a/b", "../c"));
        assert!(!link_ok("a/b", "../../c"));
        assert!(!link_ok("a", "/etc/passwd"));
        assert!(!link_ok("a", "x/.git/hooks"));
        assert!(!link_ok("a", ""));
    }

    #[test]
    fn a_mac_refuses_names_that_differ_only_in_case() {
        let c = case_collisions(["A/x", "a/y", "b"].into_iter());
        assert_eq!(c, vec![("A".to_owned(), "a".to_owned())]);
        assert!(case_collisions(["a/x", "a/y"].into_iter()).is_empty());
    }

    #[test]
    fn diff_lists_changed_new_and_gone() {
        let mut from = Entries::new();
        let mut to = Entries::new();
        for e in [
            file("keep", b"k", false),
            file("edit", b"1", false),
            file("gone", b"g", false),
        ] {
            from.insert(e.path.clone(), e);
        }
        for e in [
            file("keep", b"k", false),
            file("edit", b"2", false),
            file("new", b"n", false),
        ] {
            to.insert(e.path.clone(), e);
        }
        let (put, del) = diff(&from, &to);
        let mut put: Vec<_> = put.into_iter().map(|e| e.path).collect();
        put.sort();
        assert_eq!(put, ["edit", "new"]);
        assert_eq!(del, ["gone"]);
    }
}
