//! Continuous sync for a session that overflowed to a runner (E15-2, spec 4.6): the runner's
//! folder is the writer, `sync.watch` streams its changes, and the Core applies them to the
//! session's folder in the workspace (`session_dir`), so Lore and Files read it from the Core
//! with about 1 s of lag.
//!
//! **Stream contract** (E15-4 writes the runner end): the first event of a watch (`seq` 1) lists
//! every file of the folder as `put`; later events are deltas; `seq` rises by one. A gap ends the
//! stream and the Core opens a new one (whose first event is a snapshot again).
//!
//! A person's write on the Core goes the other way ([`write_through`]): a `sync.push` whose base
//! is the tree the Core last saw, so an agent edit the Core has not received yet makes it a 409
//! `conflict` instead of a lost update.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, Command, Control, Entry, EntryKind, Hash, MAX_FILE_BYTES, MAX_INLINE_BYTES, SyncDrop,
    SyncEvent, SyncWatch, TreeHash,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::Notify;

use super::fs::{Tree, check_path};
use super::manifest::{Delta, Entries, hash_bytes, link_ok, tree_hash};
use super::rules::Rules;
use super::sync::{Source, SyncError, entry_of, manifest, pull, push};
use crate::hub::Hub;

const RETRIES: u32 = 5;

/// The live watches, by session id.
#[derive(Default)]
pub struct Watches(Mutex<HashMap<String, Arc<WatchState>>>);

impl Watches {
    pub fn get(&self, session: &str) -> Option<Arc<WatchState>> {
        self.0.lock().unwrap().get(session).cloned()
    }
}

/// What the Core has seen of one overflow session's folder.
pub struct WatchState {
    args: WatchArgs,
    inner: Mutex<Inner>,
    /// One writer at a time on the folder: an event being applied or a person's write.
    io: tokio::sync::Mutex<()>,
    stop: Notify,
}

#[derive(Default)]
struct Inner {
    entries: Entries,
    seq: u64,
    /// The stream is open (false between a loss and its reopening, and after the end).
    live: bool,
    /// Events or paths refused so far (a runner sending what the rules forbid).
    refused: u64,
    error: Option<String>,
}

/// What a watch needs.
#[derive(Clone)]
pub struct WatchArgs {
    pub device: String,
    pub session: String,
    /// `0` for a session with no project.
    pub project: i64,
    pub lease: String,
    /// The session's folder in the workspace.
    pub root: PathBuf,
    pub rules: Rules,
}

impl WatchState {
    /// The tree hash of what the Core has seen: the `base` of a write.
    pub fn base(&self) -> ainkrad_proto::v2::TreeHash {
        tree_hash(&self.inner.lock().unwrap().entries)
    }

    pub fn entries(&self) -> Entries {
        self.inner.lock().unwrap().entries.clone()
    }

    pub fn is_live(&self) -> bool {
        self.inner.lock().unwrap().live
    }

    pub fn refused(&self) -> u64 {
        self.inner.lock().unwrap().refused
    }

    pub fn last_error(&self) -> Option<String> {
        self.inner.lock().unwrap().error.clone()
    }

    pub fn args(&self) -> &WatchArgs {
        &self.args
    }
}

/// Applies one event to the folder `tree` and the state. A path or entry the rules or the path
/// check refuse is skipped and counted; a hash that does not match fails the whole event
/// (`hash_mismatch`): a runner that sends wrong bytes is not trusted for the rest of the stream.
pub async fn apply_event(
    hub: &Arc<Hub>,
    st: &WatchState,
    tree: &Tree,
    ev: SyncEvent,
) -> Result<(), SyncError> {
    let _io = st.io.lock().await;
    let args = &st.args;
    {
        let seq = st.inner.lock().unwrap().seq;
        if ev.seq != seq + 1 {
            return Err(SyncError::new(
                "watch_gap",
                format!("event {} after {seq}", ev.seq),
            ));
        }
    }
    let mut inline: HashMap<&str, Vec<u8>> = HashMap::new();
    for f in &ev.inline {
        let bytes = STANDARD
            .decode(&f.data)
            .map_err(|_| SyncError::new("hash_mismatch", "an inline file that is not base64"))?;
        if bytes.len() > MAX_INLINE_BYTES {
            return Err(SyncError::new(
                "hash_mismatch",
                "an inline file over the limit",
            ));
        }
        inline.insert(f.path.as_str(), bytes);
    }
    // Within one event the deletes apply before the puts (a folder that becomes a file).
    let mut refused = 0u64;
    let mut removed = Vec::new();
    for p in &ev.delete {
        if check_path(p).is_err() || args.rules.sync_out(p).is_some() {
            refused += 1;
            continue;
        }
        tree.remove(p)?;
        removed.push(p.clone());
    }
    let mut done: Vec<Entry> = Vec::new();
    let mut to_pull: Vec<Entry> = Vec::new();
    let known = st.entries();
    for e in ev.put {
        let ok = check_path(&e.path).is_ok()
            && args.rules.sync_out(&e.path).is_none()
            && e.size <= MAX_FILE_BYTES;
        if !ok {
            refused += 1;
            continue;
        }
        match e.kind {
            EntryKind::File => {
                if let Some(bytes) = inline.get(e.path.as_str()) {
                    if bytes.len() as u64 != e.size || hash_bytes(bytes).0 != e.hash {
                        return Err(SyncError::new(
                            "hash_mismatch",
                            format!("inline {}", e.path),
                        ));
                    }
                    tree.write(&e.path, bytes, Some(e.exec))?;
                    done.push(e);
                } else if known
                    .get(&e.path)
                    .is_some_and(|k| k.hash == e.hash && k.exec == e.exec)
                {
                    done.push(e);
                } else {
                    to_pull.push(e);
                }
            }
            EntryKind::Symlink => {
                let target = e.link.clone().unwrap_or_default();
                if !link_ok(&e.path, &target)
                    || Hash(*blake3::hash(target.as_bytes()).as_bytes()) != e.hash
                {
                    refused += 1;
                    continue;
                }
                tree.symlink(&e.path, &target)?;
                done.push(e);
            }
            EntryKind::Unknown => refused += 1,
        }
    }
    if !to_pull.is_empty() {
        let route = |e: &Entry| Some((tree, e.path.clone()));
        let sess = Some(args.session.as_str());
        pull(
            hub,
            &args.device,
            args.project,
            &args.lease,
            sess,
            &to_pull,
            &route,
        )
        .await?;
        done.extend(to_pull);
    }
    let mut g = st.inner.lock().unwrap();
    for e in done {
        g.entries.insert(e.path.clone(), e);
    }
    for p in removed {
        g.entries.remove(&p);
    }
    g.seq = ev.seq;
    g.refused += refused;
    Ok(())
}

/// One open stream until it ends. `Ok` when the runner closed it cleanly or `stop` was asked.
async fn run_once(hub: &Arc<Hub>, st: &Arc<WatchState>, tree: &Tree) -> Result<(), SyncError> {
    let a = &st.args;
    let cmd = Command::SyncWatch(SyncWatch {
        session: a.session.clone(),
        lease: a.lease.clone(),
        rules: a.rules.to_wire(),
    });
    let mut d = hub.dispatch_sync(&a.device, cmd)?;
    {
        let mut g = st.inner.lock().unwrap();
        g.seq = 0;
        g.live = true;
        g.error = None;
    }
    loop {
        let frame = tokio::select! {
            f = d.next() => f,
            () = st.stop.notified() => {
                let _ = d.send(Body::Close(Default::default()));
                // The runner answers the close with its last frame; a quiet one is not waited for.
                let _ = tokio::time::timeout(Duration::from_secs(5), d.next()).await;
                return Ok(());
            }
        };
        match frame {
            Some(Body::Control(Control::SyncEvent(ev))) => apply_event(hub, st, tree, ev).await?,
            Some(Body::Result(_)) => return Ok(()),
            Some(Body::Error(e)) => return Err(e.into()),
            Some(_) => {}
            None => return Err(SyncError::new("runner_offline", "the stream ended")),
        }
    }
}

/// Starts watching an overflow session and registers it. The folder is made if it is not there.
pub fn start(hub: &Arc<Hub>, args: WatchArgs) -> Result<Arc<WatchState>, SyncError> {
    std::fs::create_dir_all(&args.root)?;
    let tree = Tree::open(&args.root)?;
    let st = Arc::new(WatchState {
        args,
        inner: Mutex::default(),
        io: tokio::sync::Mutex::new(()),
        stop: Notify::new(),
    });
    hub.sync
        .watches
        .0
        .lock()
        .unwrap()
        .insert(st.args.session.clone(), Arc::clone(&st));
    let (hub, task) = (Arc::clone(hub), Arc::clone(&st));
    tokio::spawn(async move {
        let mut tries = 0;
        loop {
            let ended = run_once(&hub, &task, &tree).await;
            task.inner.lock().unwrap().live = false;
            match ended {
                Ok(()) => break,
                Err(e) => {
                    tracing::warn!(session = %task.args.session, error = %e, "a session watch ended");
                    task.inner.lock().unwrap().error = Some(e.to_string());
                    // A runner that sent wrong bytes, or is gone for good, is not retried.
                    let fatal = matches!(
                        e.code,
                        "hash_mismatch" | "path_refused" | "unsupported_command"
                    );
                    tries += 1;
                    if fatal || tries > RETRIES {
                        break;
                    }
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(2)) => {}
                        () = task.stop.notified() => break,
                    }
                }
            }
        }
    });
    Ok(st)
}

/// Ends a session's watch: stops the stream, takes a final diff of the runner's folder, tells the
/// runner to drop its copy, and forgets the watch and its lease.
pub async fn finish(hub: &Arc<Hub>, session: &str) -> Result<(), SyncError> {
    let Some(st) = hub.sync.watches.get(session) else {
        return Ok(());
    };
    st.stop.notify_one();
    // The task ends on its own once told; the final diff does not need it.
    let a = &st.args;
    let tree = Tree::open(&a.root)?;
    let diffed = async {
        let (have, _) = manifest(hub, &a.device, a.project, &a.lease, &a.rules).await?;
        let delta = super::manifest::diff(&st.entries(), &have);
        let seq = st.inner.lock().unwrap().seq + 1;
        let ev = SyncEvent {
            seq,
            put: delta.put,
            delete: delta.delete,
            inline: Vec::new(),
        };
        apply_event(hub, &st, &tree, ev).await
    }
    .await;
    let drop_cmd = Command::SyncDrop(SyncDrop { project: a.project });
    if let Ok(d) = hub.dispatch_sync(&a.device, drop_cmd) {
        let _ = tokio::time::timeout(Duration::from_secs(30), d.outcome()).await;
    }
    hub.sync.leases.revoke_scope(&a.session);
    hub.sync.watches.0.lock().unwrap().remove(session);
    diffed
}

/// A person's write of `data` to `rel` of an overflow session: pushed to the runner (the writer)
/// with the Core's last-seen tree as base, then applied to the Core's view. A runner whose folder
/// changed since (`base_mismatch`) answers `conflict`: nothing was written.
pub async fn write_through(
    hub: &Arc<Hub>,
    st: &WatchState,
    rel: &str,
    data: &[u8],
    exec: Option<bool>,
) -> Result<(), SyncError> {
    check_path(rel).map_err(|w| SyncError::new("path_refused", w))?;
    let a = &st.args;
    if a.rules.sync_in(rel).is_some() {
        return Err(SyncError::new(
            "path_refused",
            "that path is not synced to a runner",
        ));
    }
    let _io = st.io.lock().await;
    let mut entries = st.entries();
    let exec = exec.unwrap_or_else(|| entries.get(rel).is_some_and(|e| e.exec));
    let entry = entry_of(rel, data, exec);
    // Per-file base (spec 4.6): the push conflicts only if THIS file changed on the runner since
    // the Core last saw it (the zero hash: the Core saw none). The whole-tree base and
    // `want_tree` are then unchecked (the zero tree), since other files move under a live session.
    let base_files = vec![(
        rel.to_owned(),
        entries.get(rel).map(|e| e.hash).unwrap_or_default(),
    )];
    entries.insert(rel.to_owned(), entry.clone());
    let mem = HashMap::from([(rel.to_owned(), data.to_vec())]);
    let delta = Delta {
        put: vec![entry.clone()],
        delete: Vec::new(),
    };
    let pushed = push(
        hub,
        &a.device,
        a.project,
        &a.lease,
        TreeHash::default(),
        &delta,
        TreeHash::default(),
        &a.rules,
        base_files,
        Some(&a.session),
        &Source::Mem(&mem),
    )
    .await;
    match pushed {
        Ok(_) => {}
        Err(e) if e.code == "base_mismatch" => {
            return Err(SyncError::new(
                "conflict",
                "the session changed since the Core last saw it",
            ));
        }
        Err(e) => return Err(e),
    }
    Tree::open(&a.root)?.write(rel, data, Some(exec))?;
    st.inner
        .lock()
        .unwrap()
        .entries
        .insert(rel.to_owned(), entry);
    Ok(())
}

/// A person's removal of `rel` from an overflow session, by the same rules as [`write_through`].
pub async fn delete_through(hub: &Arc<Hub>, st: &WatchState, rel: &str) -> Result<(), SyncError> {
    check_path(rel).map_err(|w| SyncError::new("path_refused", w))?;
    let a = &st.args;
    let _io = st.io.lock().await;
    let mut entries = st.entries();
    let Some(seen) = entries.remove(rel) else {
        return Ok(());
    };
    let base_files = vec![(rel.to_owned(), seen.hash)];
    let delta = Delta {
        put: Vec::new(),
        delete: vec![rel.to_owned()],
    };
    let none = HashMap::new();
    match push(
        hub,
        &a.device,
        a.project,
        &a.lease,
        TreeHash::default(),
        &delta,
        TreeHash::default(),
        &a.rules,
        base_files,
        Some(&a.session),
        &Source::Mem(&none),
    )
    .await
    {
        Ok(_) => {}
        Err(e) if e.code == "base_mismatch" => {
            return Err(SyncError::new(
                "conflict",
                "the session changed since the Core last saw it",
            ));
        }
        Err(e) => return Err(e),
    }
    Tree::open(&a.root)?.remove(rel)?;
    st.inner.lock().unwrap().entries.remove(rel);
    Ok(())
}
