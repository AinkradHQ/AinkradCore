//! What the Core knows of a runner's warm cache of a project (`core_hw_cache`): the tree it is at
//! and whether `prepare` (a lockfile install such as `npm ci`) ran for the lockfiles it holds now.

use ainkrad_proto::v2::TreeHash;

use crate::api::App;
use crate::workspace::manifest::Entries;

/// Lockfile names, by file name, whose content decides whether `prepare` runs again.
const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "uv.lock",
    "poetry.lock",
];

fn is_lockfile(name: &str) -> bool {
    LOCKFILES.contains(&name) || (name.starts_with("requirements") && name.ends_with(".txt"))
}

/// blake3 over the path and content hash of every lockfile in the synced tree (any depth, in path
/// order), so an edit, an addition or a removal of one changes it.
pub fn lock_hash(m0: &Entries) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for (path, e) in m0 {
        if is_lockfile(path.rsplit('/').next().unwrap_or(path)) {
            h.update(&(path.len() as u32).to_le_bytes());
            h.update(path.as_bytes());
            h.update(&e.hash.0);
        }
    }
    *h.finalize().as_bytes()
}

/// Whether the device's cache of the project already ran `prepare` for the lockfiles `lock`.
pub async fn prepared(app: &App, device: &str, project: i64, lock: &[u8; 32]) -> bool {
    sqlx::query_scalar::<_, Option<Vec<u8>>>(
        "SELECT prepared FROM core_hw_cache WHERE device_id = ? AND project_id = ?",
    )
    .bind(device)
    .bind(project)
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten()
    .flatten()
    .is_some_and(|p| p == lock)
}

/// Records the tree the device's cache is at after a job and, when `prepared` is given (a prepare
/// ran and the job succeeded), the lockfiles it was prepared for. `None` keeps the last marker.
pub async fn remember(
    app: &App,
    device: &str,
    project: i64,
    tree: &TreeHash,
    prepared: Option<[u8; 32]>,
) {
    let _ = sqlx::query(
        "INSERT INTO core_hw_cache (device_id, project_id, tree_hash, synced_at, prepared) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (device_id, project_id) DO UPDATE SET \
         tree_hash = excluded.tree_hash, synced_at = excluded.synced_at, \
         prepared = COALESCE(excluded.prepared, core_hw_cache.prepared)",
    )
    .bind(device)
    .bind(project)
    .bind(tree.0.to_vec())
    .bind(app.clock.now())
    .bind(prepared.map(|p| p.to_vec()))
    .execute(&app.pool)
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainkrad_proto::v2::{Entry, Hash};

    fn with(files: &[(&str, u8)]) -> Entries {
        files
            .iter()
            .map(|(p, b)| {
                let e = Entry {
                    path: (*p).to_owned(),
                    hash: Hash([*b; 32]),
                    ..Entry::default()
                };
                ((*p).to_owned(), e)
            })
            .collect()
    }

    #[test]
    fn the_lock_hash_follows_lockfiles_only() {
        let base = lock_hash(&with(&[("Cargo.lock", 1), ("src/a.rs", 2)]));
        assert_eq!(
            base,
            lock_hash(&with(&[("Cargo.lock", 1), ("src/a.rs", 9)]))
        );
        assert_ne!(
            base,
            lock_hash(&with(&[("Cargo.lock", 3), ("src/a.rs", 2)]))
        );
        assert_ne!(
            base,
            lock_hash(&with(&[("Cargo.lock", 1), ("web/pnpm-lock.yaml", 4)]))
        );
        assert_ne!(base, lock_hash(&with(&[("src/a.rs", 2)])));
        let py = lock_hash(&with(&[("requirements-dev.txt", 5)]));
        assert_ne!(py, lock_hash(&with(&[("requirements-dev.txt", 6)])));
        assert_eq!(
            lock_hash(&with(&[("notes.txt", 1)])),
            lock_hash(&Entries::new())
        );
    }
}
