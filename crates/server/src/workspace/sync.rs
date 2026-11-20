//! The Core's end of the delta protocol (E15-2, spec 4.5, 4.6 and 7): `sync.manifest`,
//! `sync.push`, `sync.pull`, and the two flows built on them, [`sync_in`] (before a job) and
//! [`sync_back`] (after it, Core wins).
//!
//! The runner is untrusted for what it SENDS: every path it names passes `check_path` and the
//! sync-out rules again here, every chunk is hashed before it is written, every file is hashed
//! whole before its rename, and nothing is ever written outside the root fd of the tree it is
//! routed to. A secret never travels (rules) and a lease is required for every call.

use std::collections::HashMap;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, CHUNK_BYTES, Command, Entry, EntryKind, ErrorCode, Hash,
    MAX_SYNC_OUT_BYTES, Output, Reply, file_entry_sound,
    SYNC_FRAME_BYTES, SYNC_STREAM_WINDOW, StreamError, SyncManifest, SyncPull, SyncPush, TreeHash,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub use super::flow::{Back, SyncedIn, sync_back, sync_in};
use super::fs::{Tree, check_path};
pub use super::leases::{Leases, Registry};
use super::manifest::{Delta, Entries, apply, hash_bytes, tree_hash};
use super::rules::Rules;
use crate::hub::{Dispatched, Hub};

/// A runner silent this long on a sync stream fails it.
const STEP: Duration = Duration::from_secs(60);
/// The most entries one manifest may hold.
const MAX_ENTRIES: usize = 1_000_000;

/// Why a sync step failed; `code` is the answer's `code` (a job's `error`, a route's 409).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncError {
    pub code: &'static str,
    pub why: String,
}

impl SyncError {
    pub fn new(code: &'static str, why: impl Into<String>) -> Self {
        Self {
            code,
            why: why.into(),
        }
    }
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.why)
    }
}

impl From<StreamError> for SyncError {
    fn from(e: StreamError) -> Self {
        let code = match e.code {
            ErrorCode::HashMismatch => "hash_mismatch",
            ErrorCode::BaseMismatch => "base_mismatch",
            ErrorCode::PathRefused => "path_refused",
            ErrorCode::Offline | ErrorCode::Lost => "runner_offline",
            ErrorCode::UnsupportedCommand => "unsupported_command",
            ErrorCode::Busy => "runner_busy",
            _ => "runner_failed",
        };
        Self::new(code, e.message)
    }
}

impl From<io::Error> for SyncError {
    fn from(e: io::Error) -> Self {
        Self::new("workspace_io", e.to_string())
    }
}

// ---------------------------------------------------------------------------------------------
// The three ops.

/// Where a push reads the bytes of the files it puts.
pub enum Source<'a> {
    /// The files of this tree.
    Tree(&'a Tree),
    /// Contents held in memory, by path (a person's write on an overflow session).
    Mem(&'a HashMap<String, Vec<u8>>),
}

/// Reads one chunk of the file `e`, and fails if it is not the chunk the entry lists (the file
/// changed since the scan: the caller scans again).
struct ChunkReader<'a> {
    src: &'a Source<'a>,
    open: Option<(String, std::fs::File)>,
}

impl ChunkReader<'_> {
    fn chunk(&mut self, e: &Entry, i: usize) -> Result<Vec<u8>, SyncError> {
        let changed = || {
            SyncError::new(
                "source_changed",
                format!("{} changed while syncing", e.path),
            )
        };
        let want = e.chunks.get(i).ok_or_else(changed)?;
        let start = i as u64 * CHUNK_BYTES;
        let len = e.size.saturating_sub(start).min(CHUNK_BYTES) as usize;
        let bytes = match self.src {
            Source::Mem(m) => {
                let all = m.get(&e.path).ok_or_else(changed)?;
                all.get(start as usize..start as usize + len)
                    .ok_or_else(changed)?
                    .to_vec()
            }
            Source::Tree(tree) => {
                if self.open.as_ref().is_none_or(|(p, _)| *p != e.path) {
                    self.open = Some((e.path.clone(), tree.open_file(&e.path)?));
                }
                let f = &mut self.open.as_mut().expect("just set").1;
                f.seek(SeekFrom::Start(start))?;
                let mut buf = vec![0u8; len];
                f.read_exact(&mut buf).map_err(|_| changed())?;
                buf
            }
        };
        match Hash(*blake3::hash(&bytes).as_bytes()) == *want {
            true => Ok(bytes),
            false => Err(changed()),
        }
    }
}

/// Waits for the next frame of a stream, `STEP` at most.
async fn next(d: &mut Dispatched) -> Result<Body, SyncError> {
    match tokio::time::timeout(STEP, d.next_ungranted()).await {
        Ok(Some(b)) => Ok(b),
        Ok(None) => Err(SyncError::new("runner_offline", "the stream ended")),
        Err(_) => Err(SyncError::new(
            "runner_timeout",
            "the runner did not answer in time",
        )),
    }
}

/// The stream's closing frame, skipping credit and output.
async fn last(mut d: Dispatched) -> Result<Reply, SyncError> {
    loop {
        match next(&mut d).await? {
            Body::Result(r) => return Ok(r),
            Body::Error(e) => return Err(e.into()),
            _ => {}
        }
    }
}

fn wrong() -> SyncError {
    SyncError::new("runner_failed", "an answer of another op")
}

/// A runner's manifest: its entries and tree hash, checked (paths, count, and that the tree hash
/// is the fold of the entries).
pub async fn manifest(
    hub: &Arc<Hub>,
    device: &str,
    project: i64,
    lease: &str,
    rules: &Rules,
) -> Result<(Entries, TreeHash), SyncError> {
    let cmd = Command::SyncManifest(SyncManifest {
        project,
        lease: lease.to_owned(),
        rules_hash: Hash(rules.hash()),
        rules: rules.to_wire(),
        // ponytail: no `git clone` seed; a first sync sends every file. Seed from the Core's copy
        // when big first syncs matter.
        seed: None,
    });
    let Reply::SyncManifest(r) = last(hub.dispatch_sync(device, cmd)?).await? else {
        return Err(wrong());
    };
    if r.entries.len() > MAX_ENTRIES {
        return Err(SyncError::new("runner_failed", "a manifest that large"));
    }
    let mut entries = Entries::new();
    for e in r.entries {
        check_path(&e.path)
            .map_err(|w| SyncError::new("path_refused", format!("{}: {w}", e.path)))?;
        if e.kind == EntryKind::File && !file_entry_sound(&e) {
            return Err(SyncError::new(
                "runner_failed",
                format!("{}: the chunk list does not cover the file", e.path),
            ));
        }
        if entries.insert(e.path.clone(), e).is_some() {
            return Err(SyncError::new("runner_failed", "a path listed twice"));
        }
    }
    match tree_hash(&entries) == r.tree {
        true => Ok((entries, r.tree)),
        false => Err(SyncError::new(
            "sync_integrity",
            "the manifest does not hash to its tree",
        )),
    }
}

/// Pushes `delta` to the runner's cache (at `base`), reading file bytes from `src`; the cache must
/// be `want` afterwards. Chunk frames follow the command in the listed order, each only once the
/// runner's credit covers it.
#[allow(clippy::too_many_arguments)]
pub async fn push(
    hub: &Arc<Hub>,
    device: &str,
    project: i64,
    lease: &str,
    base: TreeHash,
    delta: &Delta,
    want: TreeHash,
    rules: &Rules,
    base_files: Vec<(String, Hash)>,
    session: Option<&str>,
    src: &Source<'_>,
) -> Result<TreeHash, SyncError> {
    for e in &delta.put {
        check_path(&e.path).map_err(|w| SyncError::new("path_refused", w))?;
    }
    let cmd = Command::SyncPush(SyncPush {
        project,
        lease: lease.to_owned(),
        base,
        put: delta.put.clone(),
        delete: delta.delete.clone(),
        want_tree: want,
        rules: rules.to_wire(),
        base_files,
        session: session.map(str::to_owned),
    });
    let mut d = hub.dispatch_sync(device, cmd)?;
    let mut window = SYNC_STREAM_WINDOW;
    let mut reader = ChunkReader { src, open: None };
    for e in delta.put.iter().filter(|e| e.kind == EntryKind::File) {
        for i in 0..e.chunks.len() {
            let bytes = reader.chunk(e, i)?;
            // A chunk goes as frames of at most SYNC_FRAME_BYTES, never spanning two chunks.
            for part in bytes.chunks(SYNC_FRAME_BYTES) {
                let n = part.len() as u64;
                while window < n {
                    match next(&mut d).await? {
                        Body::Credit(c) => window = window.saturating_add(c.bytes),
                        Body::Error(e) => return Err(e.into()),
                        Body::Result(_) => {
                            return Err(SyncError::new(
                                "runner_failed",
                                "answered before the chunks",
                            ));
                        }
                        _ => {}
                    }
                }
                window -= n;
                let frame = Body::Output(Output {
                    data: STANDARD.encode(part),
                });
                d.send(frame)?;
            }
        }
    }
    match last(d).await? {
        Reply::SyncPush(p) => Ok(p.tree),
        _ => Err(wrong()),
    }
}

/// Where a pulled file goes, or `None` to receive and check it but keep nothing.
pub type Route<'a> = dyn Fn(&Entry) -> Option<(&'a Tree, String)> + Sync + 'a;

/// Pulls the files `wanted` (kind `File`) from the runner's cache of `project`, or from the
/// overflow session `session` when it is `Some`. Each chunk is hashed against the entry before it
/// is staged, the whole file before it is renamed into place. Returns the files kept.
#[allow(clippy::too_many_arguments)]
pub async fn pull(
    hub: &Arc<Hub>,
    device: &str,
    project: i64,
    lease: &str,
    session: Option<&str>,
    wanted: &[Entry],
    route: &Route<'_>,
) -> Result<u64, SyncError> {
    let mut total = 0u64;
    for e in wanted {
        check_path(&e.path).map_err(|w| SyncError::new("path_refused", w))?;
        if e.kind != EntryKind::File || !file_entry_sound(e) {
            return Err(SyncError::new(
                "path_refused",
                format!("{} is not a pullable file", e.path),
            ));
        }
        // M1: one pull never brings more than the sync-out cap, counted without overflow.
        total = total
            .checked_add(e.size)
            .filter(|t| *t <= MAX_SYNC_OUT_BYTES)
            .ok_or_else(|| SyncError::new("outputs_too_large", "a pull over the size limit"))?;
    }
    let cmd = Command::SyncPull(SyncPull {
        project,
        lease: lease.to_owned(),
        cache_or_session: session.unwrap_or_default().to_owned(),
        paths: wanted.iter().map(|e| (e.path.clone(), e.hash)).collect(),
    });
    let mut d = hub.dispatch_sync(device, cmd)?;
    let mut kept = 0u64;
    for e in wanted {
        let mut staged = match route(e) {
            Some((tree, rel)) => Some(tree.stage(&rel)?),
            None => None,
        };
        let mut whole = blake3::Hasher::new();
        let mut got = 0u64;
        for i in 0..e.chunks.len() {
            // One hashing chunk arrives as frames that never span two chunks.
            let want = e
                .size
                .saturating_sub(i as u64 * CHUNK_BYTES)
                .min(CHUNK_BYTES) as usize;
            let mut bytes = Vec::with_capacity(want);
            while bytes.len() < want {
                let data = match next(&mut d).await? {
                    Body::Output(o) => o.data,
                    Body::Error(e) => return Err(e.into()),
                    _ => {
                        return Err(SyncError::new(
                            "runner_failed",
                            "a pull ended before its chunks",
                        ));
                    }
                };
                let part = STANDARD
                    .decode(&data)
                    .map_err(|_| SyncError::new("hash_mismatch", "a chunk that is not base64"))?;
                if part.len() > SYNC_FRAME_BYTES || bytes.len() + part.len() > want {
                    return Err(SyncError::new("hash_mismatch", "a frame over its chunk"));
                }
                d.grant_read(part.len() as u64);
                bytes.extend_from_slice(&part);
            }
            let ok = Hash(*blake3::hash(&bytes).as_bytes()) == e.chunks[i];
            if !ok {
                return Err(SyncError::new(
                    "hash_mismatch",
                    format!("a chunk of {}", e.path),
                ));
            }
            whole.update(&bytes);
            got += bytes.len() as u64;
            if let Some(s) = staged.as_mut() {
                s.file.write_all(&bytes)?;
            }
        }
        if got != e.size || Hash(*whole.finalize().as_bytes()) != e.hash {
            return Err(SyncError::new(
                "hash_mismatch",
                format!("the file {}", e.path),
            ));
        }
        if let Some(s) = staged {
            s.commit(Some(e.exec))?;
            kept += 1;
        }
    }
    match last(d).await? {
        Reply::SyncPull(p) if p.count == wanted.len() as u64 => Ok(kept),
        _ => Err(SyncError::new(
            "runner_failed",
            "a pull that did not count its files",
        )),
    }
}

/// The entries of `have` with `delta` applied: what a cache holds after a push.
pub fn after(have: &Entries, delta: &Delta) -> Entries {
    apply(have, delta)
}

/// The folder `dir` (made when it is not there) as a [`Tree`]: where a job's conflicts go.
pub fn tree_at(dir: &std::path::Path) -> io::Result<Tree> {
    std::fs::create_dir_all(dir)?;
    Tree::open(dir)
}

/// One file's entry from bytes in memory (a person's write).
pub fn entry_of(path: &str, data: &[u8], exec: bool) -> Entry {
    let (hash, chunks) = hash_bytes(data);
    Entry {
        path: path.to_owned(),
        kind: EntryKind::File,
        exec,
        size: data.len() as u64,
        hash,
        chunks,
        link: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cores_copy_wins_unless_it_is_unchanged_or_already_equal() {
        use super::super::flow::same;
        let e = |h: u8| Entry {
            path: "a".into(),
            hash: Hash([h; 32]),
            ..Default::default()
        };
        assert!(same(None, None) && same(Some(&e(1)), Some(&e(1))));
        assert!(!same(None, Some(&e(1))) && !same(Some(&e(1)), Some(&e(2))));
    }

    #[test]
    fn an_entry_from_memory_chunks_like_a_file() {
        let data = vec![1u8; CHUNK_BYTES as usize * 2 + 1];
        let e = entry_of("x", &data, true);
        assert_eq!(
            (e.size, e.chunks.len(), e.exec),
            (data.len() as u64, 3, true)
        );
    }
}
