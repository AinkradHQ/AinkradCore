//! `init <home>` (E1-13.1): a new, working home. Never over an existing one.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::config::{Home, template};
use super::{Result_, archive, private_dir, private_file};
use crate::store;

/// `home` as an absolute path, if nothing is there or only an empty directory; an error naming
/// it otherwise. `init`, `restore` and `import` only ever write into a fresh home.
pub fn fresh(home: &Path) -> io::Result<PathBuf> {
    let home = std::path::absolute(home)?;
    match fs::read_dir(&home).map(|mut e| e.next().is_none()) {
        Ok(true) => Ok(home),
        Ok(false) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} is not empty; refusing to write a home over it",
                home.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(home),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "{}: {e} (a home must be a new or empty directory)",
                home.display()
            ),
        )),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = private_file(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Lays out a home in `home` (fresh, absolute): 0700 dirs, the config, a new signing key, and
/// the master key (`master`, or 32 new random bytes). Not the database. Returns the home and
/// the signing key's fingerprint.
pub fn lay_out(home: &Path, master: Option<&[u8]>) -> io::Result<(Home, String)> {
    let h = Home(home.to_path_buf());
    private_dir(&h.0)?;
    private_dir(&h.keys())?;
    private_dir(&h.backups())?;
    let mut key = [0u8; 32];
    match master {
        Some(m) if m.len() == 32 => key.copy_from_slice(m),
        Some(_) => return Err(io::Error::other("the master key is not 32 bytes")),
        None => getrandom::fill(&mut key).map_err(|e| io::Error::other(e.to_string()))?,
    }
    write_new(&h.master_key(), &key)?;
    let pkcs8 = archive::new_signing_key()?;
    write_new(&h.signing_key(), &pkcs8)?;
    let fp = archive::signer_fingerprint(&archive::load_signer(&pkcs8)?);
    let mut config = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(h.config())?;
    config.write_all(template(&h.0).as_bytes())?;
    config.sync_all()?;
    Ok((h, fp))
}

/// Opens (so migrates) the home's database and closes it, leaving one file.
pub(crate) async fn migrate(h: &Home) -> Result<(), sqlx::Error> {
    let pool = store::connect(&h.db()).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;
    Ok(())
}

pub async fn init(home: &Path) -> Result_ {
    let path = fresh(home)?;
    let existed = path.exists();
    let made = async {
        let (h, fp) = lay_out(&path, None)?;
        migrate(&h).await?;
        Ok::<_, Box<dyn std::error::Error>>((h, fp))
    }
    .await;
    let (h, fp) = match made {
        Ok(done) => done,
        Err(e) => {
            undo(&path, existed);
            return Err(e);
        }
    };
    eprintln!(
        "home {} created: config.toml, core.db, keys/master.key and keys/backup-signing.p8 \
         (0600), backups/.\nSet backup_recipient in the config (`backup-keygen` on another \
         machine). The backup signing key's fingerprint, printed once below: record it offline \
         with the age identity; restore and import need it as --signer.",
        h.0.display()
    );
    println!("{fp}");
    Ok(())
}

/// Removes what a failed `init`/`restore` wrote: the whole home if it did not exist, else its
/// contents (it was empty).
pub(crate) fn undo(home: &Path, existed: bool) {
    if !existed {
        let _ = fs::remove_dir_all(home);
    } else if let Ok(entries) = fs::read_dir(home) {
        for e in entries.flatten() {
            let _ = fs::remove_dir_all(e.path()).or_else(|_| fs::remove_file(e.path()));
        }
    }
}
