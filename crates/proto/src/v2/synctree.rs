//! The pure half of workspace sync both ends share (E15-2 and E15-4, spec 4.3 to 4.5): the
//! include/exclude rules, the wire-path and link checks, the file hash and the tree hash fold. The
//! Core and the runner must agree on every byte of these, so there is one copy, here.
//!
//! **The tree hash fold:** blake3 over the domain `ainkrad-tree-v1\n`, then for every entry in
//! ascending order of its path BYTES: `u32 LE path length, path, kind byte (0 file, 1 symlink),
//! exec byte (0 or 1), u64 LE size, the 32-byte whole-file hash, u32 LE link length, link (empty
//! for a file)`. Chunk hashes are not part of it (they derive from the content). An empty tree
//! hashes the domain alone. A file's hash is blake3 of its content; a symlink's is blake3 of its
//! target text.
//!
//! **The rules:** `.git` is never synced, in either direction. Build output (`target/`,
//! `node_modules/` ...) is not synced in, and comes out only when a project `outputs` glob names
//! it. Secret-shaped files (`.env*`, keys, `.npmrc` ...) are never synced unless the project lists
//! them in `include`. On the wire `exclude` is the built-ins merged with the project's own; the
//! built-ins give way to a project `include`, a project exclude never does.

use std::collections::BTreeMap;
use std::io;

use super::{CHUNK_BYTES, Entry, EntryKind, Hash, SyncRules, TreeHash, wire_path_problem};

/// Directories that are build output, by name (any depth).
pub const BUILD_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".build",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
    ".gradle",
    "DerivedData",
    ".next",
    ".turbo",
];

/// Files that look like secrets: by file name (`*` matches any run), or by path for the ones
/// with a `/`. Lower case: [`is_secret`] matches them case-insensitively (E15 security review M3).
pub const SECRET_NAMES: &[&str] = &[
    ".env",
    ".env.*",
    ".envrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.ppk",
    "*.kdbx",
    "id_*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".htpasswd",
    "credentials.json",
    "service-account*.json",
    "secrets.yml",
    "secrets.yaml",
    "*.tfstate",
    "*.tfstate.*",
    "**/.aws/credentials",
    "**/.docker/config.json",
    "**/.kube/config",
];

/// A manifest: entries by wire path.
pub type Entries = BTreeMap<String, Entry>;

/// Why a path is not synced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    Git,
    BuildOutput,
    Secret,
    Excluded,
}

/// A project's own sync lists (the built-ins are applied by name, not listed here).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub outputs: Vec<String>,
}

fn builtin(g: &str) -> bool {
    SECRET_NAMES.contains(&g) || g.strip_suffix('/').is_some_and(|d| BUILD_DIRS.contains(&d))
}

impl Rules {
    /// The rules as they came on the wire: the built-in excludes told apart by name.
    pub fn from_wire(w: &SyncRules) -> Self {
        Self {
            include: w.include.clone(),
            exclude: w.exclude.iter().filter(|g| !builtin(g)).cloned().collect(),
            outputs: w.outputs.clone(),
        }
    }

    /// The effective rules as they go on the wire: the built-in excludes (build directories as
    /// `name/`, the secret-shaped names) merged with the project's own. `.git/` is not listed:
    /// both ends exclude it whatever the rules say.
    pub fn to_wire(&self) -> SyncRules {
        let built = BUILD_DIRS
            .iter()
            .map(|d| format!("{d}/"))
            .chain(SECRET_NAMES.iter().map(|s| (*s).to_owned()));
        SyncRules {
            include: self.include.clone(),
            exclude: built.chain(self.exclude.iter().cloned()).collect(),
            outputs: self.outputs.clone(),
        }
    }

    /// The hash of the wire rules (`SyncManifest::rules_hash`), the same for the same rules in any order.
    pub fn hash(&self) -> [u8; 32] {
        let mut w = self.to_wire();
        for list in [&mut w.include, &mut w.exclude, &mut w.outputs] {
            list.sort();
        }
        let json = serde_json::to_vec(&w).expect("rules serialize");
        *blake3::hash(&json).as_bytes()
    }

    fn listed(&self, rel: &str) -> bool {
        self.include.iter().any(|g| glob(g, rel))
    }

    fn in_output(&self, rel: &str) -> bool {
        self.outputs.iter().any(|g| glob(g, rel))
    }

    /// A build directory is walked only when a rule can reach into it (`out`: a sync-out scan).
    pub fn enters_build_dirs(&self, out: bool) -> bool {
        !self.include.is_empty() || (out && !self.outputs.is_empty())
    }

    /// Sync IN (Core to runner): `None` to include `rel` (a file or link path), else why not.
    pub fn sync_in(&self, rel: &str) -> Option<Skip> {
        self.skip(rel, false)
    }

    /// Sync OUT (runner to Core): the same, except build output comes back when `outputs` names it.
    pub fn sync_out(&self, rel: &str) -> Option<Skip> {
        self.skip(rel, true)
    }

    fn skip(&self, rel: &str, out: bool) -> Option<Skip> {
        if has_git(rel) {
            return Some(Skip::Git);
        }
        if self.exclude.iter().any(|g| glob(g, rel)) {
            return Some(Skip::Excluded);
        }
        if in_build_dir(rel) && !(out && self.in_output(rel)) && !self.listed(rel) {
            return Some(Skip::BuildOutput);
        }
        if is_secret(rel) && !self.listed(rel) {
            return Some(Skip::Secret);
        }
        None
    }
}

/// Any component of `rel` is `.git`, whatever its case (a case-folding disk would alias it).
pub fn has_git(rel: &str) -> bool {
    rel.split('/').any(|p| p.eq_ignore_ascii_case(".git"))
}

/// Any DIRECTORY component of `rel` (the last is the file) is a build directory.
pub fn in_build_dir(rel: &str) -> bool {
    let mut it = rel.split('/').peekable();
    while let Some(p) = it.next() {
        if it.peek().is_some() && BUILD_DIRS.contains(&p) {
            return true;
        }
    }
    false
}

/// `rel` looks like a secret (`.env`, `*.pem`, `.aws/credentials` ...), whatever its case.
pub fn is_secret(rel: &str) -> bool {
    let low = rel.to_lowercase();
    SECRET_NAMES.iter().any(|g| glob(g, &low))
}

/// A small glob: `*` any run without `/`, `**` any run (also across `/`), `?` one character
/// that is not `/`. A pattern with no `/` also matches the last component anywhere
/// (`*.pem` matches `a/b/c.pem`). Case-sensitive.
pub fn glob(pat: &str, path: &str) -> bool {
    if !pat.contains('/') {
        let name = path.rsplit('/').next().unwrap_or(path);
        return glob_at(pat.as_bytes(), name.as_bytes());
    }
    glob_at(pat.trim_start_matches("./").as_bytes(), path.as_bytes())
}

fn glob_at(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') if p.get(1) == Some(&b'*') => {
            let rest = &p[2..];
            // `**/` also matches zero folders.
            let rest = rest.strip_prefix(b"/").unwrap_or(rest);
            (0..=s.len()).any(|i| glob_at(rest, &s[i..]))
        }
        Some(b'*') => {
            let rest = &p[1..];
            let run = s.iter().position(|&c| c == b'/').unwrap_or(s.len());
            (0..=run).any(|i| glob_at(rest, &s[i..]))
        }
        Some(b'?') => s.first().is_some_and(|&c| c != b'/') && glob_at(&p[1..], &s[1..]),
        Some(&c) => s.first() == Some(&c) && glob_at(&p[1..], &s[1..]),
    }
}

/// A wire path (spec 4.3, [`wire_path_problem`]) plus no control character. `Err` is the reason,
/// for a `bad_path` / `path_refused` answer.
pub fn check_path(rel: &str) -> Result<(), &'static str> {
    if let Some(why) = wire_path_problem(rel) {
        return Err(why);
    }
    match rel.chars().any(char::is_control) {
        true => Err("the path holds a control character"),
        false => Ok(()),
    }
}

/// Whether the relative symlink `target` of the link at `path` stays inside the project: not
/// absolute, never above the root at any step, and not through `.git`. `..` is allowed only as a
/// leading run (E15 security review M2): `d/l/../..` would climb from wherever the link `d/l`
/// points, not from `d`, so a chain of links could leave the root while each target passes on
/// paper. With leading `..` only, a target climbs from the link's own folder (a real folder: no
/// entry is written through a link) and then only descends, so every chain stays beneath the root.
pub fn link_ok(path: &str, target: &str) -> bool {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains('\0')
        || target.contains('\\')
    {
        return false;
    }
    let mut depth = path.split('/').count() as i64 - 1; // folders above the link
    let mut descended = false;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." if descended => return false,
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            p if p.eq_ignore_ascii_case(".git") => return false,
            _ => {
                descended = true;
                depth += 1;
            }
        }
    }
    true
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

#[cfg(test)]
#[path = "synctree_tests.rs"]
mod tests;
