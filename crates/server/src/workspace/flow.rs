//! The two flows built on the sync ops (E15-2, spec 4.6): [`sync_in`] before a job and
//! [`sync_back`] after it.

use std::sync::Arc;

use ainkrad_proto::v2::{Entry, EntryKind, MAX_FILE_BYTES, MAX_SYNC_IN_BYTES, MAX_SYNC_OUT_BYTES};

use super::fs::Tree;
use super::manifest::{Entries, Memo, Scan, case_collisions, diff, link_ok, scan, tree_hash};
use super::rules::Rules;
use super::sync::{Source, SyncError, manifest, pull, push};
use crate::hub::Hub;

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
            rules,
            Vec::new(),
            None,
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

pub(super) fn same(a: Option<&Entry>, b: Option<&Entry>) -> bool {
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
        // A name new to the Core that a case- or normalisation-insensitive disk (APFS) resolves
        // to an existing file (`SRC/main.rs` onto `src/main.rs`, `.ENV` onto `.env`): never a
        // silent overwrite, it goes to the conflicts folder (E15 security review L1).
        let aliased = mine.is_none() && tree.aliased(&e.path)?;
        let core_untouched = !aliased && same(mine, m0.get(&e.path));
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
