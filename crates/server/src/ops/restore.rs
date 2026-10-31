//! `restore` and `import` (E1-13.3): a backup or an export becomes a NEW home, in a fresh
//! directory only. Order: the target is checked fresh; the archive is unpacked into a staging
//! directory beside it, which checks the signature against the pinned `--signer` before writing
//! a byte and every file's hash after; only then is the home laid out (with the archive's master
//! key and Core identity key, a new signing key and a default config), the database swapped in through
//! `store::restore` (`integrity_check`, schema not newer than this binary) and migrated.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use super::config::Home;
use super::init::{fresh, lay_out, migrate, undo};
use super::s3::Bucket;
use super::{Result_, archive, private_dir, random_hex};
use crate::auth::Identity;
use crate::store;

/// `restore <file|s3:<key>> --identity <file> --signer <fp> <home>`.
pub async fn restore(src: &str, identity: &Path, signer: &str, home: &Path) -> Result_ {
    let home = fresh(home)?;
    let identities = age::IdentityFile::from_file(identity.display().to_string())
        .map_err(|e| format!("reading the identity {}: {e}", identity.display()))?
        .into_identities()
        .map_err(|e| format!("the identity {}: {e}", identity.display()))?;
    build(&home, signer, async |staging: &Path| {
        let file = match src.strip_prefix("s3:") {
            Some(key) => {
                let bucket = Bucket::from_env()
                    .map_err(|e| e.to_string())?
                    .ok_or("s3:<key> needs the bucket: set AINKRAD_BACKUP_*")?;
                let to = staging.join("download.age");
                let n = bucket.get(key, &to).await.map_err(|e| e.to_string())?;
                eprintln!("downloaded {key} ({n} bytes)");
                to
            }
            None => PathBuf::from(src),
        };
        let decryptor = age::Decryptor::new(BufReader::new(File::open(&file)?))
            .map_err(|e| format!("{}: not an age file ({e})", file.display()))?;
        let reader = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
            .map_err(|e| format!("decrypting {}: {e}", file.display()))?;
        unpack(BufReader::new(reader), signer, staging)
    })
    .await
}

/// `import <file> --signer <fp> <home>`: an export (an unencrypted archive).
pub async fn import(src: &Path, signer: &str, home: &Path) -> Result_ {
    let home = fresh(home)?;
    build(&home, signer, async |staging: &Path| {
        unpack(BufReader::new(File::open(src)?), signer, staging)
    })
    .await
}

fn unpack(
    mut input: impl BufRead,
    signer: &str,
    staging: &Path,
) -> Result<archive::Manifest, Box<dyn std::error::Error>> {
    let out = staging.join("archive");
    private_dir(&out)?;
    Ok(archive::read(&mut input, signer, &out)?)
}

async fn build(
    home: &Path,
    signer: &str,
    fill: impl AsyncFnOnce(&Path) -> Result<archive::Manifest, Box<dyn std::error::Error>>,
) -> Result_ {
    let parent = home.parent().unwrap_or(Path::new("/"));
    let staging = parent.join(format!(".ainkrad-restore-{}", random_hex()?));
    private_dir(&staging)?;
    let existed = home.exists();
    let mut created = false;
    let done = async {
        let manifest = fill(&staging).await?;
        let files = staging.join("archive");
        let master = match std::fs::read(files.join("keys/master.key")) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        // The Core identity, checked before the home is touched: a key that does not load would
        // only fail later, at serve.
        let identity = files.join(archive::IDENTITY);
        let core_fp = match std::fs::read(&identity) {
            Ok(der) => Some(Identity::from_pkcs8(&der)?.fp),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        created = true;
        let (h, fp) = lay_out(home, master.as_deref())?;
        if core_fp.is_some() {
            // Staged 0600 beside the home (same filesystem), so a rename keeps it private.
            std::fs::rename(&identity, h.identity())?;
        }
        store::restore(&files.join("core.db"), &h.db(), false).await?;
        migrate(&h).await?;
        Ok::<_, Box<dyn std::error::Error>>((manifest, h, fp, master.is_some(), core_fp))
    }
    .await;
    archive::discard(&staging);
    let (manifest, h, fp, kept_master, core_fp) = match done {
        Ok(d) => d,
        Err(e) => {
            if created {
                undo(home, existed);
            }
            return Err(e);
        }
    };
    report(&manifest, &h, &fp, signer, kept_master);
    match core_fp {
        Some(core_fp) => eprintln!(
            "The Core identity was restored ({core_fp}): paired devices and runners accept it."
        ),
        None => eprintln!(
            "WARNING: the {} has no Core identity key ({}): it was made before backups carried \
             it, or it is an export, or the Core never served. The restored Core makes a NEW \
             identity on first serve, and every paired device and runner refuses it \
             (core_identity_mismatch) until it is paired again.",
            manifest.kind,
            archive::IDENTITY
        ),
    }
    Ok(())
}

fn report(m: &archive::Manifest, h: &Home, fp: &str, signer: &str, kept_master: bool) {
    eprintln!(
        "{} of {} verified (signed by {signer}) and restored into {}: the database (checked and \
         migrated){}. The new home has its own backup signing key; record its fingerprint, \
         printed below, and set backup_recipient in {}.",
        m.kind,
        m.created_at,
        h.0.display(),
        if kept_master {
            " and the master key"
        } else {
            "; a new master key (the archive had none)"
        },
        h.config().display()
    );
    println!("{fp}");
}
