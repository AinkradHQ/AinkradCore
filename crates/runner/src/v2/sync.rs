//! The `sync` driver (E15-4, the runner end of spec §4.5): a warm per-project cache the Core keeps
//! in step with its canonical workspace by deltas, and the live folder of an overflow AI session.
//!
//! - **Cache:** `<work_root>/cache/<core_id>/<project>/`, private to the runner user, with an index
//!   (path to mtime, size, inode and hash) so an unchanged file is never read again. LRU eviction
//!   (`cache`). The first manifest may seed it with `git clone` from the Core's copy (`seed`); `.git`
//!   itself is never synced.
//! - **Ops:** `sync.manifest` and `sync.drop` here; `sync.push`, `sync.pull` and `sync.watch` in
//!   `ops`. Bytes travel as credited `output` frames (`flow`), every chunk hashed on arrival.
//! - **Path safety:** every wire path is checked (`wire_path_problem` plus control characters), and
//!   every open, write and removal happens beneath the cache's root descriptor
//!   (`ainkrad_sys::tree`, the same `Tree` as the Core's workspace), never by path.
//! - **Leases:** an op without a lease is refused as if the cache did not exist. A watch registers its
//!   lease; a push under that lease writes to the watched session's folder (spec §4.6).
//! - Jobs use [`SyncDriver::snapshot`] before and after they run (`job`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::{
    CAP_SYNC, CacheInfo, Command, DriverInfo, ErrorCode, OP_SYNC_DROP, OP_SYNC_MANIFEST,
    OP_SYNC_PULL, OP_SYNC_PUSH, OP_SYNC_WATCH, Reply, StreamError, SyncDropped, SyncManifest,
    SyncManifestReply, SyncRules, TreeHash,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedMutexGuard, Semaphore};

use super::flow::Flow;

mod cache;
mod manifest;
mod ops;
mod seed;

use ainkrad_proto::v2::synctree::Rules;
use ainkrad_sys::tree::Tree;
pub(super) use cache::fresh_for_origin;
pub(super) use cache::safe_core_id as safe_name;
use cache::{Held, Layout};
use manifest::{Entries, Memo, Scan, scan, tree_hash};

/// What the runner keeps of a project's cache between ops and restarts.
#[derive(Default, Serialize, Deserialize)]
struct Saved {
    rules: SyncRules,
    memo: Memo,
    tree: Option<TreeHash>,
    bytes: u64,
    last_used: u64,
    /// The commit the cache was seeded at.
    head: Option<String>,
}

#[derive(Default)]
pub(super) struct State {
    saved: Saved,
    loaded: bool,
}

/// What an op works on: a project's cache, or an overflow session's own folder.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) enum Key {
    Project(i64),
    Session(String),
}

pub struct SyncConfig {
    pub work_root: PathBuf,
    /// The Core's fingerprint: the cache path's Core part.
    pub core_id: String,
    /// `<state>/agents`: where a session's `meta.json` names its folder (for `sync.watch`).
    pub agents: PathBuf,
    /// Ops at once; one more is `busy`.
    pub capacity: u32,
}

pub struct SyncDriver {
    layout: Layout,
    agents: PathBuf,
    capacity: u32,
    slots: Semaphore,
    states: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<State>>>>,
    /// Lease to the session folder of an active `sync.watch`.
    watches: Mutex<HashMap<String, String>>,
    clones: Option<Arc<super::agent::AgentDriver>>,
    /// What `caches` reports, kept in step by every save (a heartbeat must not read the indexes).
    infos: Mutex<HashMap<i64, CacheInfo>>,
}

pub(super) fn invalid(why: impl Into<String>) -> StreamError {
    StreamError::new(ErrorCode::InvalidArgs, why)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl SyncDriver {
    /// `None` when the Core id is not path-safe.
    pub fn new(cfg: SyncConfig) -> Option<Self> {
        let core = cache::safe_core_id(&cfg.core_id)?;
        Some(Self {
            layout: Layout::new(&cfg.work_root, &core),
            agents: cfg.agents,
            capacity: cfg.capacity.max(1),
            slots: Semaphore::new(cfg.capacity.max(1) as usize),
            states: Mutex::default(),
            watches: Mutex::default(),
            clones: None,
            infos: Mutex::default(),
        })
        .inspect(|d| d.load_infos())
    }

    /// The warm caches an earlier run left, read once at start.
    fn load_infos(&self) {
        let mut infos = self.infos.lock().unwrap();
        for p in self.layout.projects() {
            let saved = std::fs::read(self.layout.index(p))
                .ok()
                .and_then(|b| serde_json::from_slice::<Saved>(&b).ok());
            if let Some(info) = saved.and_then(|s| Self::info_of(p, &s)) {
                infos.insert(p, info);
            }
        }
    }

    fn info_of(project: i64, saved: &Saved) -> Option<CacheInfo> {
        Some(CacheInfo {
            project,
            tree_hash: ainkrad_proto::v2::Hash(saved.tree?.0),
            bytes: saved.bytes,
        })
    }

    /// Seeds from the Core's repo copies through the agent driver's mirror path.
    pub fn with_clones(mut self, agents: Arc<super::agent::AgentDriver>) -> Self {
        self.clones = Some(agents);
        self
    }

    pub fn info(&self) -> DriverInfo {
        DriverInfo {
            name: CAP_SYNC.to_owned(),
            commands: [
                OP_SYNC_MANIFEST,
                OP_SYNC_PUSH,
                OP_SYNC_PULL,
                OP_SYNC_WATCH,
                OP_SYNC_DROP,
            ]
            .map(str::to_owned)
            .to_vec(),
            capacity: self.capacity,
            ..DriverInfo::default()
        }
    }

    pub(super) fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The warm caches held, for `Capacity::caches`.
    pub fn caches(&self) -> Vec<CacheInfo> {
        let mut all: Vec<CacheInfo> = self.infos.lock().unwrap().values().cloned().collect();
        all.sort_by_key(|c| c.project);
        all
    }

    fn check(project: i64, lease: &str) -> Result<(), StreamError> {
        // The same answer for no lease and no cache (spec §7).
        if lease.is_empty() || project <= 0 {
            return Err(invalid("no such cache"));
        }
        Ok(())
    }

    /// The cache or session folder an op works on.
    pub(super) fn root_of(&self, key: &Key) -> Result<PathBuf, StreamError> {
        match key {
            Key::Project(p) => Ok(self.layout.root(*p)),
            Key::Session(s) => {
                if !ainkrad_proto::v2::valid_session_id(s) {
                    return Err(invalid("no such session on this runner"));
                }
                let meta = std::fs::read(self.agents.join(s).join("meta.json"))
                    .map_err(|_| invalid("no such session on this runner"))?;
                serde_json::from_slice::<serde_json::Value>(&meta)
                    .ok()
                    .and_then(|m| m["folder"].as_str().map(PathBuf::from))
                    .filter(|f| f.is_absolute() && f.is_dir())
                    .ok_or_else(|| invalid("this runner has recorded no folder for the session"))
            }
        }
    }

    /// The key a push under `lease` works on: the watched session's folder, else the project's cache.
    pub(super) fn target(&self, project: i64, lease: &str) -> Key {
        match self.watches.lock().unwrap().get(lease) {
            Some(s) => Key::Session(s.clone()),
            None => Key::Project(project),
        }
    }

    pub(super) fn watch_lease(&self, lease: &str, session: &str) -> WatchGuard<'_> {
        self.watches
            .lock()
            .unwrap()
            .insert(lease.to_owned(), session.to_owned());
        WatchGuard(self, lease.to_owned())
    }

    pub(super) async fn lock(&self, key: &Key) -> OwnedMutexGuard<State> {
        let cell = Arc::clone(self.states.lock().unwrap().entry(key.clone()).or_default());
        let mut st = cell.lock_owned().await;
        if !st.loaded {
            if let Key::Project(p) = key
                && let Ok(bytes) = std::fs::read(self.layout.index(*p))
            {
                st.saved = serde_json::from_slice(&bytes).unwrap_or_default();
            }
            st.loaded = true;
        }
        st
    }

    /// Saves the index of a project's cache (a session's is kept in memory only).
    pub(super) fn save(&self, key: &Key, st: &mut State) {
        st.saved.last_used = now_secs();
        let Key::Project(p) = key else { return };
        match Self::info_of(*p, &st.saved) {
            Some(info) => self.infos.lock().unwrap().insert(*p, info),
            None => self.infos.lock().unwrap().remove(p),
        };
        let Ok(text) = serde_json::to_vec(&st.saved) else {
            return;
        };
        let (file, tmp) = (
            self.layout.index(*p),
            self.layout.base().join(format!("{p}.index.tmp")),
        );
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &file);
        }
    }

    /// Scans `root` under the rules the Core last sent: IN (what the Core pushes and the tree hash
    /// covers) or OUT (also named build output). The memo makes an unchanged file a stat.
    pub(super) async fn scan(
        &self,
        st: &mut State,
        root: &Path,
        out: bool,
    ) -> Result<Scan, StreamError> {
        let rules = Rules::from_wire(&st.saved.rules);
        let mut memo = std::mem::take(&mut st.saved.memo);
        let root = root.to_owned();
        let done = tokio::task::spawn_blocking(move || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as i64);
            let r = Tree::open(&root).and_then(|t| scan(&t, &rules, out, &mut memo, now));
            (r, memo)
        })
        .await
        .map_err(|e| StreamError::new(ErrorCode::Internal, e.to_string()))?;
        st.saved.memo = done.1;
        done.0
            .map_err(|e| StreamError::new(ErrorCode::Internal, format!("scanning the cache: {e}")))
    }

    /// Makes the cache folder (private to this user) and drops caches that are over the limits.
    async fn prepare(&self, project: i64) -> Result<PathBuf, StreamError> {
        let internal = |e: std::io::Error| StreamError::new(ErrorCode::Internal, e.to_string());
        super::agent::secrets::private_dir(self.layout.base()).map_err(internal)?;
        let root = self.layout.root(project);
        super::agent::secrets::private_dir(&root).map_err(internal)?;
        let held: Vec<Held> = self
            .layout
            .projects()
            .into_iter()
            .filter_map(|p| {
                let saved: Saved =
                    serde_json::from_slice(&std::fs::read(self.layout.index(p)).ok()?).ok()?;
                Some(Held {
                    project: p,
                    last_used: saved.last_used,
                    bytes: saved.bytes,
                })
            })
            .collect();
        for p in cache::to_evict(&held, cache::free_pct(self.layout.base()), project) {
            tracing::info!(project = p, "evicting a warm cache (disk or size limit)");
            self.forget(p).await;
        }
        Ok(root)
    }

    /// Removes a project's cache, index and job home; the bytes freed.
    async fn forget(&self, project: i64) -> u64 {
        let key = Key::Project(project);
        let _st = self.lock(&key).await;
        let (root, home) = (self.layout.root(project), self.layout.home(project));
        let freed = cache::dir_size(&root) + cache::dir_size(&home);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_file(self.layout.index(project));
        self.states.lock().unwrap().remove(&key);
        self.infos.lock().unwrap().remove(&project);
        freed
    }

    async fn manifest(&self, req: SyncManifest) -> Result<SyncManifestReply, StreamError> {
        Self::check(req.project, &req.lease)?;
        let key = Key::Project(req.project);
        let mut st = self.lock(&key).await;
        let root = self.prepare(req.project).await?;
        if let Some(clone) = &req.seed {
            self.seed(&root, clone, req.project, &mut st).await?;
        }
        st.saved.rules = req.rules.clone();
        let scanned = self.scan(&mut st, &root, false).await?;
        let tree = tree_hash(&scanned.entries);
        st.saved.tree = Some(tree);
        st.saved.bytes = cache::dir_size(&root);
        self.save(&key, &mut st);
        Ok(SyncManifestReply {
            entries: scanned.entries.into_values().collect(),
            tree,
        })
    }

    /// The commit the cache was seeded at (`AINKRAD_GIT_HEAD`), if it was.
    pub async fn head(&self, project: i64) -> Option<String> {
        self.lock(&Key::Project(project)).await.saved.head.clone()
    }

    /// The OUT entries of project's cache and its IN tree hash now: a job takes one before it runs
    /// and one after, and what differs is what it changed (`job`).
    pub async fn snapshot(&self, project: i64) -> Result<Snapshot, StreamError> {
        let key = Key::Project(project);
        let mut st = self.lock(&key).await;
        let root = self.layout.root(project);
        if !root.is_dir() {
            return Err(invalid("no such cache"));
        }
        let out = self.scan(&mut st, &root, true).await?.entries;
        let rules = Rules::from_wire(&st.saved.rules);
        let inn: Entries = out
            .iter()
            .filter(|(p, _)| rules.sync_in(p).is_none())
            .map(|(p, e)| (p.clone(), e.clone()))
            .collect();
        let tree = tree_hash(&inn);
        st.saved.tree = Some(tree);
        st.saved.bytes = cache::dir_size(&root);
        self.save(&key, &mut st);
        Ok(Snapshot { out, tree })
    }

    /// A job's writable home (package caches), made on demand.
    pub fn job_home(&self, project: i64) -> std::io::Result<PathBuf> {
        let home = self.layout.home(project);
        super::agent::secrets::private_dir(&home)?;
        Ok(home)
    }

    pub async fn handle(
        self: &Arc<Self>,
        command: Command,
        mut flow: Flow,
    ) -> Result<Reply, StreamError> {
        let _slot = self.slots.try_acquire().map_err(|_| {
            StreamError::new(
                ErrorCode::Busy,
                format!("sync is at capacity ({})", self.capacity),
            )
        })?;
        match command {
            Command::SyncManifest(r) => self.manifest(r).await.map(Reply::SyncManifest),
            Command::SyncPush(r) => ops::push(self, r, &mut flow).await.map(Reply::SyncPush),
            Command::SyncPull(r) => ops::pull(self, r, &mut flow).await.map(Reply::SyncPull),
            Command::SyncWatch(r) => ops::watch(self, r, &mut flow).await.map(Reply::SyncWatch),
            Command::SyncDrop(r) => {
                if r.project <= 0 {
                    return Err(invalid("no such cache"));
                }
                Ok(Reply::SyncDrop(SyncDropped {
                    bytes_freed: self.forget(r.project).await,
                }))
            }
            other => Err(StreamError::new(
                ErrorCode::UnsupportedCommand,
                format!("{} is not a sync op", other.op()),
            )),
        }
    }
}

/// What a job's cache holds now.
pub struct Snapshot {
    pub out: Entries,
    pub tree: TreeHash,
}

pub(super) struct WatchGuard<'a>(&'a SyncDriver, String);

impl Drop for WatchGuard<'_> {
    fn drop(&mut self) {
        self.0.watches.lock().unwrap().remove(&self.1);
    }
}

/// Paths that are in `now` and not as in `before` (new or changed), and paths gone: what a job did.
pub fn job_delta(before: &Entries, now: &Entries) -> (Vec<ainkrad_proto::v2::Entry>, Vec<String>) {
    manifest::diff(before, now)
}

#[cfg(test)]
mod tests;
