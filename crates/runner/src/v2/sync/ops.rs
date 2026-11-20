//! `sync.push`, `sync.pull` and `sync.watch` (E15-4): the ops that move file bytes.
//!
//! Chunk frames follow spec §4.5 and `ainkrad_proto::v2::sync`: a file's chunks go in the order the
//! entries list them, each chunk cut into `output` frames of at most `SYNC_FRAME_BYTES` that never
//! span two chunks, and the receiver hashes each whole chunk (`hash_mismatch` on a difference) and
//! the whole file before it renames it into place.

use std::io::{Read, Write};
use std::sync::Arc;

use ainkrad_proto::v2::{
    Body, CHUNK_BYTES, Control, Entry, EntryKind, ErrorCode, Hash, InlineFile, MAX_FILE_BYTES,
    MAX_INLINE_BYTES, SYNC_FRAME_BYTES, StreamError, SyncEvent, SyncPull, SyncPulled, SyncPush,
    SyncPushed, SyncWatch, SyncWatched, WATCH_INTERVAL_MS,
};
use base64::Engine as _;

use super::manifest::{self, Entries, tree_hash};
use super::tree::{Tree, check_path};
use super::{Key, SyncDriver, invalid};
use crate::v2::flow::{Flow, Stop};

fn err(code: ErrorCode, why: impl Into<String>) -> StreamError {
    StreamError::new(code, why)
}

fn refused(why: &str) -> StreamError {
    err(ErrorCode::PathRefused, why)
}

fn stopped(s: Stop) -> StreamError {
    match s {
        Stop::Cancelled => err(ErrorCode::Cancelled, "the Core cancelled the transfer"),
        Stop::Dropped => err(ErrorCode::Lost, "the stream was lost"),
    }
}

fn io(e: std::io::Error) -> StreamError {
    err(ErrorCode::Internal, e.to_string())
}

/// The length of chunk `i` of a file of `size` bytes.
fn chunk_len(size: u64, i: usize) -> usize {
    let start = i as u64 * CHUNK_BYTES;
    size.saturating_sub(start).min(CHUNK_BYTES) as usize
}

/// Reads `want` bytes from the Core's frames (a frame never spans two chunks, so the sum is exact).
async fn read_chunk(flow: &mut Flow, want: usize) -> Result<Vec<u8>, StreamError> {
    let mut chunk = Vec::with_capacity(want);
    while chunk.len() < want {
        let frame = flow.read().await.map_err(stopped)?;
        if frame.len() > SYNC_FRAME_BYTES || chunk.len() + frame.len() > want {
            return Err(err(ErrorCode::HashMismatch, "a frame crosses a chunk"));
        }
        chunk.extend_from_slice(&frame);
    }
    Ok(chunk)
}

/// Whether a symlink `entry` of a push is acceptable: relative, inside the project, not through
/// `.git` (the Core checked too; the runner never trusts it).
fn link_target(e: &Entry) -> Result<&str, StreamError> {
    match e.link.as_deref() {
        Some(t) if manifest::link_ok(&e.path, t) => Ok(t),
        _ => Err(refused("a symlink that leaves the project")),
    }
}

pub(super) async fn push(
    d: &Arc<SyncDriver>,
    req: SyncPush,
    flow: &mut Flow,
) -> Result<SyncPushed, StreamError> {
    SyncDriver::check(req.project, &req.lease)?;
    // Everything is checked before anything is touched.
    for p in req
        .put
        .iter()
        .map(|e| &e.path)
        .chain(&req.delete)
        .chain(req.base_files.iter().map(|b| &b.0))
    {
        check_path(p).map_err(refused)?;
    }
    for e in &req.put {
        match e.kind {
            EntryKind::File if e.size > MAX_FILE_BYTES => {
                return Err(err(ErrorCode::TooLarge, "a file over the size limit"));
            }
            EntryKind::File if e.chunks.len() != e.size.div_ceil(CHUNK_BYTES) as usize => {
                return Err(invalid("the chunk list does not cover the file"));
            }
            EntryKind::File => {}
            EntryKind::Symlink => {
                link_target(e)?;
            }
            EntryKind::Unknown => return Err(invalid("an entry kind this runner does not know")),
        }
    }
    let key = d.target(req.project, &req.lease);
    let root = d.root_of(&key)?;
    if !root.is_dir() {
        return Err(invalid("no such cache"));
    }
    let mut st = d.lock(&key).await;
    st.saved.rules = req.rules.clone();
    let current = d.scan(&mut st, &root, false).await?.entries;
    if cfg!(target_os = "macos") {
        let all = current
            .keys()
            .chain(req.put.iter().map(|e| &e.path))
            .map(String::as_str);
        if let Some((a, b)) = manifest::case_collisions(all).first() {
            return Err(refused(&format!(
                "{a} and {b} differ only in case, which this Mac cannot hold"
            )));
        }
    }
    let per_file = !req.base_files.is_empty();
    if per_file {
        // Overflow writes (§4.6): conflict only where a listed file changed; the whole-tree base and
        // `want_tree` are the zero hash and unchecked.
        for (path, base) in &req.base_files {
            let now = current.get(path).map_or(Hash::default(), |e| e.hash);
            if now != *base {
                return Err(err(
                    ErrorCode::BaseMismatch,
                    format!("{path} changed here since the Core saw it"),
                ));
            }
        }
    } else if tree_hash(&current) != req.base {
        return Err(err(
            ErrorCode::BaseMismatch,
            "the cache is not at the base the push names",
        ));
    }
    let tree = Tree::open(&root).map_err(io)?;
    for p in &req.delete {
        tree.remove(p).map_err(io)?;
        st.saved.memo.0.remove(p);
    }
    for e in &req.put {
        if e.kind == EntryKind::Symlink {
            tree.symlink(&e.path, link_target(e)?).map_err(io)?;
            continue;
        }
        let mut staged = tree.stage(&e.path).map_err(io)?;
        let mut whole = blake3::Hasher::new();
        for (i, want) in e.chunks.iter().enumerate() {
            let chunk = read_chunk(flow, chunk_len(e.size, i)).await?;
            if blake3::hash(&chunk).as_bytes() != &want.0 {
                return Err(err(
                    ErrorCode::HashMismatch,
                    format!("a chunk of {} did not hash as listed", e.path),
                ));
            }
            whole.update(&chunk);
            staged.file.write_all(&chunk).map_err(io)?;
        }
        if whole.finalize().as_bytes() != &e.hash.0 {
            return Err(err(
                ErrorCode::HashMismatch,
                format!("{} did not hash as listed", e.path),
            ));
        }
        staged.commit(e.exec).map_err(io)?;
    }
    let after = d.scan(&mut st, &root, false).await?.entries;
    let got = tree_hash(&after);
    if !per_file && got != req.want_tree {
        return Err(err(
            ErrorCode::HashMismatch,
            "the tree after the push is not the one the Core wants",
        ));
    }
    st.saved.tree = Some(got);
    d.save(&key, &mut st);
    Ok(SyncPushed { tree: got })
}

pub(super) async fn pull(
    d: &Arc<SyncDriver>,
    req: SyncPull,
    flow: &mut Flow,
) -> Result<SyncPulled, StreamError> {
    SyncDriver::check(req.project, &req.lease)?;
    let key = match req.cache_or_session.as_str() {
        "" => Key::Project(req.project),
        s => Key::Session(s.to_owned()),
    };
    for (p, _) in &req.paths {
        check_path(p).map_err(refused)?;
    }
    let root = d.root_of(&key)?;
    let tree = Tree::open(&root).map_err(|_| invalid("no such cache"))?;
    let mut count = 0;
    for (path, want) in &req.paths {
        // First read: does it still hash as the Core expects? Second: send it.
        let (hash, size, chunks) =
            manifest::hash_reader(tree.open_file(path).map_err(io)?).map_err(io)?;
        if hash != *want {
            return Err(err(
                ErrorCode::HashMismatch,
                format!("{path} changed since the Core listed it"),
            ));
        }
        let mut file = tree.open_file(path).map_err(io)?;
        for i in 0..chunks.len() {
            let mut chunk = vec![0u8; chunk_len(size, i)];
            file.read_exact(&mut chunk).map_err(io)?;
            flow.write(&chunk, SYNC_FRAME_BYTES)
                .await
                .map_err(stopped)?;
        }
        count += 1;
    }
    Ok(SyncPulled { count })
}

/// The inline bytes of a changed file when it is small enough to ride in its event.
fn inline(tree: &Tree, e: &Entry) -> Option<InlineFile> {
    if e.kind != EntryKind::File || e.size as usize > MAX_INLINE_BYTES {
        return None;
    }
    let mut data = Vec::new();
    tree.open_file(&e.path)
        .ok()?
        .take(MAX_INLINE_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .ok()?;
    (data.len() <= MAX_INLINE_BYTES && blake3::hash(&data).as_bytes() == &e.hash.0).then(|| {
        InlineFile {
            path: e.path.clone(),
            data: base64::engine::general_purpose::STANDARD.encode(&data),
        }
    })
}

/// Streams every change in an overflow session's folder until the Core closes the stream: the first
/// event (`seq` 1) is a full snapshot, later ones deltas, at most every `WATCH_INTERVAL_MS`.
/// ponytail: a 1 s-class scan (the memo makes it stat-only); `notify` if latency matters.
pub(super) async fn watch(
    d: &Arc<SyncDriver>,
    req: SyncWatch,
    flow: &mut Flow,
) -> Result<SyncWatched, StreamError> {
    SyncDriver::check(1, &req.lease)?;
    let key = Key::Session(req.session.clone());
    let root = d.root_of(&key)?;
    let _registered = d.watch_lease(&req.lease, &req.session);
    let mut last = Entries::new();
    let mut seq = 0u64;
    loop {
        let mut st = d.lock(&key).await;
        st.saved.rules = req.rules.clone();
        let now = d.scan(&mut st, &root, false).await?.entries;
        drop(st);
        let (put, delete) = manifest::diff(&last, &now);
        if seq == 0 || !put.is_empty() || !delete.is_empty() {
            seq += 1;
            let tree = Tree::open(&root).map_err(io)?;
            let inline = put.iter().filter_map(|e| inline(&tree, e)).collect();
            flow.send(Body::Control(Control::SyncEvent(SyncEvent {
                seq,
                put,
                delete,
                inline,
            })));
            last = now;
        }
        let tick = tokio::time::sleep(std::time::Duration::from_millis(WATCH_INTERVAL_MS));
        tokio::select! {
            _ = tick => {}
            ev = flow.event() => {
                if let crate::v2::flow::Event::Stop(_) = ev {
                    return Ok(SyncWatched { last_seq: seq });
                }
            }
        }
    }
}
