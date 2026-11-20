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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, CHUNK_BYTES, Command, Entry, EntryKind, ErrorCode, Hash, MAX_FILE_BYTES,
    MAX_SYNC_IN_BYTES, MAX_SYNC_OUT_BYTES, Output, Reply, STREAM_WINDOW, StreamError, SyncManifest,
    SyncPull, SyncPush, TreeHash,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::fs::{Tree, check_path};
use super::manifest::{
    Delta, Entries, Memo, Scan, apply, case_collisions, diff, hash_bytes, link_ok, scan, tree_hash,
};
use super::rules::Rules;
use crate::hub::{Dispatched, Hub};

/// A runner silent this long on a sync stream fails it.
const STEP: Duration = Duration::from_secs(60);
/// What the Core grants a pull up front: a chunk frame (1 MiB, 1.4 MiB as base64 text) is larger
/// than the 64 KiB `STREAM_WINDOW` a stream starts with.
const PULL_WINDOW: u64 = 4 * CHUNK_BYTES;
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
// Leases: per (device, project, job or session), in memory, never written to disk (spec 7).

struct Lease {
    device: String,
    project: i64,
    scope: String,
    expires: i64,
}

/// The sync leases a Core process has handed out.
#[derive(Default)]
pub struct Leases(Mutex<HashMap<String, Lease>>);

impl Leases {
    /// A new lease `l_…` for `device` to work on `project` for `scope` (a job or session id),
    /// valid `ttl` seconds from `now`.
    pub fn issue(&self, device: &str, project: i64, scope: &str, ttl: i64, now: i64) -> String {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).expect("the system random source");
        let id = format!(
            "l_{}",
            raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let mut all = self.0.lock().unwrap();
        all.retain(|_, l| l.expires > now);
        all.insert(
            id.clone(),
            Lease {
                device: device.to_owned(),
                project,
                scope: scope.to_owned(),
                expires: now + ttl,
            },
        );
        id
    }

    /// The scope of `lease` when it is live and belongs to exactly this device and project; any
    /// other case is `None`, and the caller answers the same 404 whatever the reason.
    pub fn check(&self, lease: &str, device: &str, project: i64, now: i64) -> Option<String> {
        let all = self.0.lock().unwrap();
        let l = all.get(lease)?;
        (l.device == device && l.project == project && l.expires > now).then(|| l.scope.clone())
    }

    /// Ends every lease of `scope` (a job or session ended).
    pub fn revoke_scope(&self, scope: &str) {
        self.0.lock().unwrap().retain(|_, l| l.scope != scope);
    }
}

/// What the hub keeps for workspace sync: the leases and the live session watches.
#[derive(Default)]
pub struct Registry {
    pub leases: Leases,
    pub watches: super::watch::Watches,
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
        let len = (e.size - start).min(CHUNK_BYTES) as usize;
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
    });
    let mut d = hub.dispatch_sync(device, cmd)?;
    let mut window = STREAM_WINDOW;
    let mut reader = ChunkReader { src, open: None };
    for e in delta.put.iter().filter(|e| e.kind == EntryKind::File) {
        for i in 0..e.chunks.len() {
            let bytes = reader.chunk(e, i)?;
            let n = bytes.len() as u64;
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
                data: STANDARD.encode(&bytes),
            });
            d.send(frame)?;
        }
    }
    match last(d).await? {
        Reply::SyncPush(p) => Ok(p.tree),
        _ => Err(wrong()),
    }
}

/// Where a pulled file goes, or `None` to receive and check it but keep nothing.
pub type Route<'a> = dyn Fn(&Entry) -> Option<(&'a Tree, String)> + 'a;

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
    for e in wanted {
        check_path(&e.path).map_err(|w| SyncError::new("path_refused", w))?;
        if e.kind != EntryKind::File || e.size > MAX_FILE_BYTES {
            return Err(SyncError::new(
                "path_refused",
                format!("{} is not a pullable file", e.path),
            ));
        }
    }
    let cmd = Command::SyncPull(SyncPull {
        project,
        lease: lease.to_owned(),
        cache_or_session: session.unwrap_or_default().to_owned(),
        paths: wanted.iter().map(|e| (e.path.clone(), e.hash)).collect(),
    });
    let mut d = hub.dispatch_sync(device, cmd)?;
    d.grant_read(PULL_WINDOW);
    let mut kept = 0u64;
    for e in wanted {
        let mut staged = match route(e) {
            Some((tree, rel)) => Some(tree.stage(&rel)?),
            None => None,
        };
        let mut whole = blake3::Hasher::new();
        let mut got = 0u64;
        for i in 0..e.chunks.len() {
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
            let bytes = STANDARD
                .decode(&data)
                .map_err(|_| SyncError::new("hash_mismatch", "a chunk that is not base64"))?;
            d.grant_read(bytes.len() as u64);
            let ok = bytes.len() as u64 <= CHUNK_BYTES
                && Hash(*blake3::hash(&bytes).as_bytes()) == e.chunks[i];
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

// ---------------------------------------------------------------------------------------------
// Before a job.

/// What [`sync_in`] left: the manifest M0 the Core pushed (the base of the conflict check), the
/// bytes sent, and what the rules left out.
#[derive(Debug)]
pub struct SyncedIn {
    pub m0: Entries,
    pub bytes: u64,
    pub skipped: Scan,
}

/// Brings the runner's cache of `project` to the Core's tree: scan, manifest, diff, push; the
/// runner must end at the tree the Core scanned, else one retry from a fresh manifest, then
/// `sync_integrity`. `case_insensitive` is true for a Mac: a tree that collides is refused
/// (`case_collision`). A tree over 4096 MB is `too_large` (the job runs on the Core instead).
#[allow(clippy::too_many_arguments)]
pub async fn sync_in(
    hub: &Arc<Hub>,
    device: &str,
    project: i64,
    lease: &str,
    tree: &Tree,
    rules: &Rules,
    memo: &mut Memo,
    case_insensitive: bool,
    now_ns: i64,
) -> Result<SyncedIn, SyncError> {
    let mut mine = scan(tree, rules, memo, now_ns)?;
    let m0 = std::mem::take(&mut mine.entries);
    if m0.values().map(|e| e.size).sum::<u64>() > MAX_SYNC_IN_BYTES {
        return Err(SyncError::new(
            "too_large",
            "the project is over the sync limit",
        ));
    }
    if case_insensitive {
        let clash = case_collisions(m0.keys().map(String::as_str));
        if let Some((a, b)) = clash.first() {
            return Err(SyncError::new(
                "case_collision",
                format!("{a} and {b} differ only in case"),
            ));
        }
    }
    let want = tree_hash(&m0);
    let mut bytes = 0;
    let mut tries = 0;
    loop {
        let (have, base) = manifest(hub, device, project, lease, rules).await?;
        let delta = diff(&have, &m0);
        bytes = delta.put.iter().map(|e| e.size).sum::<u64>().max(bytes);
        let sent = push(
            hub,
            device,
            project,
            lease,
            base,
            &delta,
            want,
            &Source::Tree(tree),
        )
        .await;
        match sent {
            Ok(got) if got == want => {
                return Ok(SyncedIn {
                    m0,
                    bytes,
                    skipped: mine,
                });
            }
            Ok(_)
            | Err(SyncError {
                code: "hash_mismatch" | "base_mismatch" | "source_changed",
                ..
            }) if tries == 0 => {
                tries += 1;
                // A file changed under the scan: scan again so the retry pushes what is there now.
                let again = scan(tree, rules, memo, now_ns)?;
                if again.entries != m0 {
                    return Err(SyncError::new(
                        "sync_integrity",
                        "the workspace changed while syncing",
                    ));
                }
            }
            Ok(_) => {
                return Err(SyncError::new(
                    "sync_integrity",
                    "the runner's tree is not the pushed one",
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// After a job: Core wins.

/// What [`sync_back`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Back {
    /// Files written to the Core's tree (new, changed or removed).
    pub applied: Vec<String>,
    /// Paths the Core's copy won: the runner's version is in `conflicts/<job>/` (or, for a delete
    /// the Core's copy outlived, nothing).
    pub conflicts: Vec<String>,
    pub bytes: u64,
}

fn same(a: Option<&Entry>, b: Option<&Entry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.kind == b.kind && a.hash == b.hash && a.exec == b.exec,
        _ => false,
    }
}

/// Takes a finished job's changes from the runner. `m0` is what was pushed before the job. For
/// each path the runner changed: if the Core's copy still equals M0 the runner's version is
/// applied; if the Core's copy is already the runner's, nothing; otherwise the Core wins and the
/// runner's version is kept in `conflicts` (a tree at `conflicts/<job>/`). A delete applies only
/// when the Core's copy is unchanged since M0. Output over 2048 MB is `outputs_too_large` and
/// nothing is applied.
#[allow(clippy::too_many_arguments)]
pub async fn sync_back(
    hub: &Arc<Hub>,
    device: &str,
    project: i64,
    lease: &str,
    tree: &Tree,
    conflicts: &Tree,
    rules: &Rules,
    m0: &Entries,
    memo: &mut Memo,
    now_ns: i64,
) -> Result<Back, SyncError> {
    let (m1, _) = manifest(hub, device, project, lease, rules).await?;
    let core = scan(tree, rules, memo, now_ns)?.entries;
    // What the runner changed, as far as the rules let anything come back (the runner is not
    // trusted to have applied them).
    let mut changed: Vec<&Entry> = Vec::new();
    let mut deleted: Vec<&String> = Vec::new();
    for (p, e) in &m1 {
        if rules.sync_out(p).is_some() || same(m0.get(p), Some(e)) {
            continue;
        }
        if e.kind == EntryKind::Symlink && !e.link.as_deref().is_some_and(|l| link_ok(p, l)) {
            continue;
        }
        if e.kind == EntryKind::Unknown || e.size > MAX_FILE_BYTES {
            continue;
        }
        changed.push(e);
    }
    for p in m0.keys() {
        if !m1.contains_key(p) && rules.sync_out(p).is_none() {
            deleted.push(p);
        }
    }
    if changed.iter().map(|e| e.size).sum::<u64>() > MAX_SYNC_OUT_BYTES {
        return Err(SyncError::new(
            "outputs_too_large",
            "the job's output is over the limit",
        ));
    }
    let mut out = Back::default();
    let mut apply_files: Vec<Entry> = Vec::new();
    let mut keep_files: Vec<Entry> = Vec::new();
    // Deletes first: a folder that becomes a file (or the reverse) needs the old one gone.
    for p in deleted {
        match (core.get(p), m0.get(p)) {
            (mine, was) if same(mine, was) => {
                tree.remove(p)?;
                memo.forget(p);
                out.applied.push(p.clone());
            }
            (None, _) => {}
            // The Core changed it since: the Core wins, nothing is removed.
            (Some(_), _) => out.conflicts.push(p.clone()),
        }
    }
    for e in changed {
        let mine = core.get(&e.path);
        if same(mine, Some(e)) {
            continue;
        }
        let core_untouched = same(mine, m0.get(&e.path));
        match (core_untouched, e.kind) {
            (true, EntryKind::Symlink) => {
                let target = e.link.as_deref().unwrap_or_default();
                tree.symlink(&e.path, target)?;
                out.applied.push(e.path.clone());
            }
            (true, _) => apply_files.push(e.clone()),
            (false, EntryKind::Symlink) => {
                out.conflicts.push(e.path.clone());
                conflicts.symlink(&e.path, e.link.as_deref().unwrap_or_default())?;
            }
            (false, _) => {
                out.conflicts.push(e.path.clone());
                keep_files.push(e.clone());
            }
        }
    }
    out.bytes = apply_files.iter().chain(&keep_files).map(|e| e.size).sum();
    let all: Vec<Entry> = apply_files.iter().chain(&keep_files).cloned().collect();
    if !all.is_empty() {
        let keep: std::collections::HashSet<&str> =
            keep_files.iter().map(|e| e.path.as_str()).collect();
        let route = |e: &Entry| -> Option<(&Tree, String)> {
            match keep.contains(e.path.as_str()) {
                true => Some((conflicts, e.path.clone())),
                false => Some((tree, e.path.clone())),
            }
        };
        pull(hub, device, project, lease, None, &all, &route).await?;
    }
    out.applied
        .extend(apply_files.iter().map(|e| e.path.clone()));
    for e in &apply_files {
        memo.forget(&e.path);
    }
    Ok(out)
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
    fn a_lease_serves_only_its_device_project_and_time() {
        let l = Leases::default();
        let id = l.issue("d1", 7, "j_1", 60, 100);
        assert!(id.starts_with("l_") && id.len() == 34);
        assert_eq!(l.check(&id, "d1", 7, 150).as_deref(), Some("j_1"));
        assert_eq!(l.check(&id, "d2", 7, 150), None, "another device");
        assert_eq!(l.check(&id, "d1", 8, 150), None, "another project");
        assert_eq!(l.check(&id, "d1", 7, 161), None, "expired");
        assert_eq!(l.check("l_nope", "d1", 7, 150), None);
        l.revoke_scope("j_1");
        assert_eq!(l.check(&id, "d1", 7, 150), None, "revoked");
    }

    #[test]
    fn the_cores_copy_wins_unless_it_is_unchanged_or_already_equal() {
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
