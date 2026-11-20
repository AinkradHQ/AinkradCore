//! Manifests of a workspace tree (E15-2, spec 4.5): what a folder holds as `Entry`s, the tree
//! hash both ends compare, and the delta between two manifests.
//!
//! **The tree hash fold** (the runner's `sync` driver computes the same one, so it is fixed here):
//! blake3 over the domain `ainkrad-tree-v1\n`, then for every entry in ascending order of its path
//! BYTES: `u32 LE path length, path, kind byte (0 file, 1 symlink), exec byte (0 or 1), u64 LE
//! size, the 32-byte whole-file hash, u32 LE link length, link (empty for a file)`. Chunk hashes
//! are not part of it (they derive from the content). An empty tree hashes the domain alone.
//!
//! The file hash is blake3 of the content; a symlink's is blake3 of its target text.

use std::collections::BTreeMap;
use std::io::{self, Read as _};

use ainkrad_proto::v2::{CHUNK_BYTES, Entry, EntryKind, Hash, MAX_FILE_BYTES, TreeHash};
use ainkrad_sys::Kind;

use super::fs::{MAX_DEPTH, TMP_PREFIX, Tree, check_path};
use super::rules::{Rules, Skip, has_git};

/// A manifest: entries by wire path.
pub type Entries = BTreeMap<String, Entry>;

/// Why a path is in the skipped list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    Rule(Skip),
    /// Over [`MAX_FILE_BYTES`].
    TooBig,
    /// A symlink that is absolute, leaves the project, or names `.git`.
    Link,
    /// A FIFO, socket or device.
    Special,
    /// A name that is not a wire path (not UTF-8, a control character, too long ...).
    Name,
}

#[derive(Debug, Default)]
pub struct Scan {
    pub entries: Entries,
    /// Paths left out, with why: the job result and the UI list them.
    pub skipped: Vec<(String, Why)>,
}

/// blake3 of a reader's content, its size, and each [`CHUNK_BYTES`] chunk's hash.
pub fn hash_reader(mut r: impl io::Read) -> io::Result<(Hash, u64, Vec<Hash>)> {
    let mut whole = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; CHUNK_BYTES as usize];
    loop {
        let mut n = 0;
        // A chunk is exactly CHUNK_BYTES unless it is the last.
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

/// The hash of content already in memory, as [`hash_reader`] gives it.
pub fn hash_bytes(data: &[u8]) -> (Hash, Vec<Hash>) {
    let chunks = data
        .chunks(CHUNK_BYTES as usize)
        .map(|c| Hash(*blake3::hash(c).as_bytes()))
        .collect();
    (Hash(*blake3::hash(data).as_bytes()), chunks)
}

/// The tree hash of `entries` (see the module docs for the fold).
pub fn tree_hash(entries: &Entries) -> TreeHash {
    let mut h = blake3::Hasher::new();
    h.update(b"ainkrad-tree-v1\n");
    // BTreeMap<String, _> iterates in byte order of the key.
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
    let mut depth = path.split('/').count() as i64 - 1; // folders above the link
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

/// What the Core remembers about a file it hashed: its `(mtime ns, size, inode)` and entry, so
/// an unchanged file is not read again.
#[derive(Default)]
pub struct Memo(BTreeMap<String, ((i64, u64, u64), Entry)>);

impl Memo {
    pub fn forget(&mut self, path: &str) {
        self.0.remove(path);
    }
}

/// A file modified within this many nanoseconds of the scan is hashed again next time: its
/// timestamp cannot yet tell a later write from this one.
const RACY_NS: i64 = 2_000_000_000;

/// Scans `tree` as the Core's side of a sync IN (the runner gets what this lists): rules applied,
/// `.git` never entered, build directories entered only when the project's rules name something
/// inside them. Hash work is skipped for a file `memo` knows.
pub fn scan(tree: &Tree, rules: &Rules, memo: &mut Memo, now_ns: i64) -> io::Result<Scan> {
    let mut out = Scan::default();
    let mut seen = std::collections::BTreeSet::new();
    walk(tree, rules, memo, now_ns, "", 0, &mut out, &mut seen)?;
    memo.0.retain(|p, _| seen.contains(p));
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn walk(
    tree: &Tree,
    rules: &Rules,
    memo: &mut Memo,
    now_ns: i64,
    dir: &str,
    depth: usize,
    out: &mut Scan,
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
            out.skipped.push((rel, Why::Name));
            continue;
        }
        match st.kind {
            Kind::Dir => {
                // Build output stays on the runner, unless a project rule reaches into it.
                if super::rules::BUILD_DIRS.contains(&name.as_str()) && !rules.has_include() {
                    out.skipped.push((rel, Why::Rule(Skip::BuildOutput)));
                    continue;
                }
                walk(tree, rules, memo, now_ns, &rel, depth + 1, out, seen)?;
            }
            Kind::File | Kind::Symlink => {
                if let Some(skip) = rules.sync_in(&rel) {
                    out.skipped.push((rel, Why::Rule(skip)));
                    continue;
                }
                if st.kind == Kind::Symlink {
                    let target = tree.read_link(&rel).unwrap_or_default();
                    if !link_ok(&rel, &target) {
                        out.skipped.push((rel, Why::Link));
                        continue;
                    }
                    let entry = Entry {
                        path: rel.clone(),
                        kind: EntryKind::Symlink,
                        exec: false,
                        size: target.len() as u64,
                        hash: Hash(*blake3::hash(target.as_bytes()).as_bytes()),
                        chunks: Vec::new(),
                        link: Some(target),
                    };
                    seen.insert(rel.clone());
                    out.entries.insert(rel, entry);
                    continue;
                }
                if st.size > MAX_FILE_BYTES {
                    out.skipped.push((rel, Why::TooBig));
                    continue;
                }
                let key = (st.mtime_ns, st.size, st.ino);
                seen.insert(rel.clone());
                if let Some((k, e)) = memo.0.get(&rel)
                    && *k == key
                    && e.exec == (st.mode & 0o100 != 0)
                {
                    out.entries.insert(rel, e.clone());
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
                    out.skipped.push((rel, Why::TooBig));
                    continue;
                }
                let entry = Entry {
                    path: rel.clone(),
                    kind: EntryKind::File,
                    exec: st.mode & 0o100 != 0,
                    size,
                    hash,
                    chunks,
                    link: None,
                };
                if now_ns - st.mtime_ns > RACY_NS {
                    memo.0.insert(rel.clone(), (key, entry.clone()));
                }
                out.entries.insert(rel, entry);
            }
            Kind::Other => out.skipped.push((rel, Why::Special)),
        }
    }
    Ok(())
}

/// The paths that collide on a case-insensitive disk (macOS): pairs of a folder or file name that
/// differ only in case (`A/x` and `a/y` collide on the folder). A tree with any is refused for a
/// Mac. ponytail: lowercase folding only, no Unicode normalisation (NFD) as APFS does.
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

/// What it takes to turn manifest `from` into `to`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Delta {
    /// Entries of `to` that `from` lacks or holds differently.
    pub put: Vec<Entry>,
    pub delete: Vec<String>,
}

pub fn diff(from: &Entries, to: &Entries) -> Delta {
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
    Delta { put, delete }
}

/// Applies `delta` to a copy of `entries`: what the tree is once the runner applied it.
pub fn apply(entries: &Entries, delta: &Delta) -> Entries {
    let mut out = entries.clone();
    for p in &delta.delete {
        out.remove(p);
    }
    for e in &delta.put {
        out.insert(e.path.clone(), e.clone());
    }
    out
}

/// Whether `name` is a temp file of a write in progress (never part of a manifest).
pub fn is_temp(name: &str) -> bool {
    name.starts_with(TMP_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-manifest-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    fn scan_of(d: &std::path::Path) -> Scan {
        let tree = Tree::open(d).unwrap();
        scan(&tree, &Rules::default(), &mut Memo::default(), i64::MAX / 2).unwrap()
    }

    #[test]
    fn a_scan_lists_files_links_and_what_it_left_out() {
        let d = temp("scan");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::create_dir_all(d.join(".git")).unwrap();
        fs::create_dir_all(d.join("target/debug")).unwrap();
        fs::write(d.join("src/a.rs"), "fn main() {}").unwrap();
        fs::write(d.join(".git/config"), "x").unwrap();
        fs::write(d.join("target/debug/x"), "x").unwrap();
        fs::write(d.join(".env"), "SECRET=1").unwrap();
        symlink("src/a.rs", d.join("ok")).unwrap();
        symlink("../outside", d.join("up")).unwrap();
        symlink("/etc/passwd", d.join("abs")).unwrap();
        let s = scan_of(&d);
        let paths: Vec<_> = s.entries.keys().map(String::as_str).collect();
        assert_eq!(paths, ["ok", "src/a.rs"]);
        assert_eq!(s.entries["ok"].kind, EntryKind::Symlink);
        assert_eq!(s.entries["src/a.rs"].size, 12);
        let skipped: BTreeMap<_, _> = s.skipped.iter().cloned().collect();
        assert_eq!(skipped["up"], Why::Link);
        assert_eq!(skipped["abs"], Why::Link);
        assert_eq!(skipped[".env"], Why::Rule(Skip::Secret));
        assert_eq!(skipped["target"], Why::Rule(Skip::BuildOutput));
        assert!(!skipped.contains_key(".git"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_tree_hash_follows_content_and_not_order_and_a_delta_round_trips() {
        let d = temp("tree");
        fs::write(d.join("a"), "1").unwrap();
        fs::write(d.join("b"), "2").unwrap();
        let before = scan_of(&d).entries;
        let h0 = tree_hash(&before);
        assert_eq!(h0, tree_hash(&scan_of(&d).entries));
        fs::write(d.join("a"), "changed").unwrap();
        fs::remove_file(d.join("b")).unwrap();
        fs::write(d.join("c"), "3").unwrap();
        let after = scan_of(&d).entries;
        assert_ne!(h0, tree_hash(&after));
        let delta = diff(&before, &after);
        assert_eq!(delta.delete, ["b"]);
        assert_eq!(
            delta
                .put
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
        assert_eq!(tree_hash(&apply(&before, &delta)), tree_hash(&after));
        assert_eq!(diff(&after, &after), Delta::default());
        let empty = tree_hash(&Entries::new());
        assert_ne!(empty, h0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn chunks_are_one_mebibyte_and_the_whole_hash_matches_the_bytes() {
        let data = vec![7u8; CHUNK_BYTES as usize + 5];
        let (whole, size, chunks) = hash_reader(&data[..]).unwrap();
        assert_eq!((size, chunks.len()), (data.len() as u64, 2));
        assert_eq!((whole, chunks.clone()), hash_bytes(&data));
        assert_eq!(
            chunks[1],
            Hash(*blake3::hash(&data[CHUNK_BYTES as usize..]).as_bytes())
        );
        assert_eq!(hash_reader(&[][..]).unwrap().2.len(), 0);
    }

    #[test]
    fn links_must_stay_inside_and_case_collisions_are_found() {
        assert!(link_ok("a/b", "c") && link_ok("a/b", "../x") && link_ok("a", "b/../c"));
        assert!(!link_ok("a", "../x") && !link_ok("a/b", "../../x") && !link_ok("a", "/x"));
        assert!(!link_ok("a", ".git/config") && !link_ok("a", "x/.GIT") && !link_ok("a", ""));
        assert!(case_collisions(["a/x", "b/y"].into_iter()).is_empty());
        let c = case_collisions(["README", "readme", "Dir/f", "dir/g"].into_iter());
        assert_eq!(c.len(), 2, "{c:?}");
    }
}
