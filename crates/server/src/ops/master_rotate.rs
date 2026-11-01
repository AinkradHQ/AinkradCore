//! Master-key rotation (E2-07.1, threat model T-SEC-1): `secrets rotate-master <db>` and
//! `secrets purge-retired-keys <db>`. Offline only: the CLI holds `<db>.lock` and refuses beside
//! a server, so the procedure is stop, rotate, start (no lease or redemption runs during it).
//!
//! Files in `keys/`: `master.key` is always the current key. A rotation
//! 1. checks that every key a secret names is held (current, retired or pending);
//! 2. keeps the current key as `master.<id>.key.retired`, and writes the new one as the pending
//!    `master.<newid>.key` (0600, synced) before the database is touched;
//! 3. re-seals every secret under the new key in one database transaction (`reseal_all`:
//!    fresh nonces, same associated data, verified with the new key alone before commit, audit
//!    row in the same transaction);
//!    Then the sealed key files (the Core identity, its pending next key, the ACME account:
//!    `ops::sealed`) are re-sealed under the new key, each by an atomic rename, idempotent;
//! 4. renames the pending file over `master.key` (atomic).
//!
//! A crash leaves one of these states, all consistent: before the commit (rows under the old
//! key; a stray pending key), after the commit and before the rename (rows under the pending
//! key, the key files under either key; `master.key` still the old one), or done. `serve` loads retired and pending keys as
//! spares, so it opens every row in each state; a re-run takes the pending key as its target
//! and completes the move, a no-op for rows already there. A run on a finished rotation starts
//! a new one. Backups carry the retired and pending keys (inside the age-encrypted archive).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::SqlitePool;
use zeroize::Zeroizing;

use super::sealed;
use super::secretbox::{SecretBox, key_files};
use crate::store::{self, secrets};

/// Crash injection for tests; the CLI always passes `Never`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stop {
    Never,
    /// After re-sealing and verifying, before the transaction commits.
    BeforeCommit,
    /// After the commit, before the key files are re-sealed.
    BeforeFiles,
    /// After the commit and the key files, before the new key becomes `master.key`.
    BeforeSwitch,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub from: String,
    pub to: String,
    pub secrets: usize,
    pub moved: usize,
    pub resumed: bool,
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// A new 0600 key file holding `key`, synced; never over an existing file.
fn write_key(path: &Path, key: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(key)?;
    f.sync_all()
}

fn load(path: &Path) -> Result<SecretBox, Box<dyn std::error::Error>> {
    let (id, _) = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(super::secretbox::key_file_kind)
        .ok_or("not a key file name")?;
    let b = SecretBox::from_private_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if b.key_id() != id {
        return Err(format!("{} holds a key that is not {id}", path.display()).into());
    }
    Ok(b)
}

async fn row_key_ids(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT DISTINCT key_id FROM core_secrets")
        .fetch_all(pool)
        .await
}

/// Rotates the master key of the home whose database is `db`; `keys` is its `keys/` directory.
/// The caller holds the database lock (no server is running).
pub async fn rotate(
    db: &Path,
    keys: &Path,
    stop: Stop,
) -> Result<Report, Box<dyn std::error::Error>> {
    let current_path = keys.join("master.key");
    if !current_path.exists() {
        return Err(format!(
            "no master key at {}: nothing to rotate",
            current_path.display()
        )
        .into());
    }
    let current = SecretBox::from_private_file(&current_path)
        .map_err(|e| format!("{}: {e}", current_path.display()))?;
    let files = key_files(keys)?;
    let pending: Vec<&PathBuf> = files.iter().filter(|f| !f.2).map(|f| &f.1).collect();
    if pending.len() > 1 {
        return Err(format!(
            "{} pending master keys in {}: an earlier rotation left more than one; remove the \
             ones no secret names (their ids: see the audit rows) and re-run",
            pending.len(),
            keys.display()
        )
        .into());
    }
    let mut spares = Vec::new();
    for (_, path, retired) in &files {
        match load(path) {
            Ok(b) => spares.push(b),
            // A retired key that does not load only matters if a secret names it (checked below).
            Err(e) if *retired => eprintln!("warning: spare key skipped: {e}"),
            Err(e) => return Err(e),
        }
    }

    let pool = store::connect(db).await?;
    let done = async {
        // Refuse before writing anything when a secret's key is not here.
        let from = current.key_id().to_owned();
        let keyring = current.with_extra(spares);
        let state = keys.parent().unwrap_or(Path::new("."));
        let mut named = row_key_ids(&pool).await?;
        named.extend(sealed::file_key_ids(state)?);
        for id in named {
            if !keyring.holds(&id) {
                return Err(format!(
                    "a secret is sealed under master key {id}, which is not in {} (neither the \
                     current key nor a spare): restore master.{id}.key.retired from a backup. \
                     Nothing was changed.",
                    keys.display()
                )
                .into());
            }
        }
        // The current key is kept before anything else changes.
        let retired = keys.join(format!("master.{from}.key.retired"));
        if retired.exists() {
            // Never trust a file that is already there: it must be this very key, or the run
            // stops before anything else is written (and before the switch could replace the
            // only good copy).
            load(&retired).map_err(|e| format!("the retired copy of the current key: {e}"))?;
        } else {
            write_key(&retired, &*raw(&current_path)?)?;
        }
        let (target_path, resumed) = match pending.first() {
            Some(p) => ((*p).clone(), true),
            None => {
                let mut key = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut *key).map_err(|e| io::Error::other(e.to_string()))?;
                let id = SecretBox::new(&key).key_id().to_owned();
                let p = keys.join(format!("master.{id}.key"));
                write_key(&p, &*key)?;
                (p, false)
            }
        };
        sync_dir(keys)?;
        let target = load(&target_path)?;
        let r = secrets::reseal_all(&pool, &keyring, &target, stop == Stop::BeforeCommit)
            .await
            .map_err(|e| e.to_string())?;
        if stop == Stop::BeforeFiles {
            return Err("stopped after the commit, before the key files (test)".into());
        }
        // The identity key (and its pending next key) and the ACME account, under the new key:
        // a failure here leaves the rest openable (spares), and a re-run finishes.
        for (file, label) in [
            (
                state.join(crate::auth::identity::FILE),
                sealed::IDENTITY_LABEL,
            ),
            (
                state.join(crate::auth::identity::NEXT),
                sealed::IDENTITY_NEXT_LABEL,
            ),
            (state.join("tls").join("account.json"), sealed::ACME_LABEL),
        ] {
            let kf = sealed::KeyFile {
                path: &file,
                home: state,
                label,
            };
            sealed::reseal(kf, &keyring, &target)?;
        }
        if stop == Stop::BeforeSwitch {
            return Err("stopped after the commit, before the switch (test)".into());
        }
        fs::rename(&target_path, &current_path)?;
        sync_dir(keys)?;
        Ok::<_, Box<dyn std::error::Error>>(Report {
            from,
            to: target.key_id().to_owned(),
            secrets: r.secrets,
            moved: r.moved,
            resumed,
        })
    }
    .await;
    pool.close().await;
    done
}

fn raw(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(fs::read(path)?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::other(format!("{} is not a 32-byte key", path.display())))?;
    Ok(Zeroizing::new(key))
}

/// Deletes the retired keys older than `older_than_days` that no secret names; returns their
/// ids. A retired key a secret still names is kept. The bytes are overwritten before the file
/// is removed, but that is best effort only: a copy-on-write or flash filesystem (APFS, SSD
/// wear levelling) may keep the old blocks, so purging is not secure erasure.
pub async fn purge_retired(
    db: &Path,
    keys: &Path,
    older_than_days: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let pool = store::connect(db).await?;
    let named = row_key_ids(&pool).await;
    pool.close().await;
    let mut named = named?;
    // A key a sealed key file still names is in use too.
    named.extend(sealed::file_key_ids(
        keys.parent().unwrap_or(Path::new(".")),
    )?);
    let limit = Duration::from_secs(older_than_days.saturating_mul(86_400));
    let mut gone = Vec::new();
    for (id, path, retired) in key_files(keys)? {
        let age = fs::metadata(&path)?
            .modified()?
            .elapsed()
            .unwrap_or(Duration::ZERO);
        if !retired || named.contains(&id) || age < limit {
            continue;
        }
        let mut f = fs::OpenOptions::new().write(true).open(&path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&[0u8; 32])?;
        f.sync_all()?;
        fs::remove_file(&path)?;
        gone.push(id);
    }
    sync_dir(keys)?;
    Ok(gone)
}

/// The text the CLI prints after `rotate`.
pub fn describe(r: &Report) -> String {
    format!(
        "master key {} -> {}: {} of {} secrets re-sealed{}. The old key is kept as \
         master.{}.key.retired; remove it with `secrets purge-retired-keys` after the retention \
         window. Start the server again.",
        r.from,
        r.to,
        r.moved,
        r.secrets,
        if r.resumed {
            " (resumed an earlier run)"
        } else {
            ""
        },
        r.from
    )
}
