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
use super::sealed;
use super::secretbox::{SecretBox, key_files};
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
        // The spare master keys (a rotation's retired and pending ones), checked like the
        // master key before the home is touched: each must be 32 bytes and named by its id.
        let mut spares = Vec::new();
        let mut spare_keys = Vec::new();
        for (id, path, _) in super::secretbox::key_files(&files.join("keys"))? {
            let key = super::secretbox::SecretBox::from_file(&path)?;
            if key.key_id() != id {
                return Err(format!("{} is not the key it is named for", path.display()).into());
            }
            spares.push(path);
            spare_keys.push(key);
        }
        // The Core identity, checked before the home is touched: a key that does not load would
        // only fail later, at serve. It is sealed under the archive's master key (or a spare):
        // an archive without that key cannot restore it, and does not pretend to.
        let identity = files.join(archive::IDENTITY);
        let core_fp = match std::fs::read(&identity) {
            Ok(bytes) if sealed::is_sealed(&bytes) => {
                let key: [u8; 32] = master
                    .as_deref()
                    .ok_or(
                        "the archive's Core identity is sealed but it carries no master key; \
                         nothing was written",
                    )?
                    .try_into()
                    .map_err(|_| "the archive's master key is not 32 bytes")?;
                let keyring = SecretBox::new(&key).with_extra(spare_keys);
                let der =
                    sealed::open_bytes(&keyring, sealed::IDENTITY_LABEL, &bytes).map_err(|e| {
                        format!("the archive's Core identity: {e}; nothing was written")
                    })?;
                Some(Identity::from_pkcs8(&der)?.fp)
            }
            // A backup made before the identity was sealed: sealed below, in the new home.
            Ok(der) => Some(Identity::from_pkcs8(&der)?.fp),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        created = true;
        let (h, fp) = lay_out(home, master.as_deref())?;
        for path in spares {
            // Staged 0600 beside the home (same filesystem), so a rename keeps it private.
            std::fs::rename(
                &path,
                h.keys().join(path.file_name().ok_or("a key file name")?),
            )?;
        }
        if core_fp.is_some() {
            // Staged 0600 beside the home (same filesystem), so a rename keeps it private.
            std::fs::rename(&identity, h.identity())?;
            // A legacy plaintext identity is sealed under the restored master key now.
            let seal = SecretBox::for_home(&h.0)?;
            let kf = sealed::KeyFile {
                path: &h.identity(),
                home: &h.0,
                label: sealed::IDENTITY_LABEL,
            };
            sealed::read(kf, &seal, true, |b| Identity::from_pkcs8(b).is_ok())?;
        }
        store::restore(&files.join("core.db"), &h.db(), false).await?;
        migrate(&h).await?;
        unheld_keys(&h).await?;
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

/// Fails when a secret in the restored database is sealed under a master key the restored home
/// does not hold (the current key and the spares from the archive): such a secret could never
/// be opened, so a restore that looks fine would hide a lost key (for example one purged before
/// the backup). The caller removes the half-built home.
async fn unheld_keys(h: &Home) -> Result_ {
    let pool = store::connect(&h.db()).await?;
    let named: Result<Vec<String>, _> =
        sqlx::query_scalar("SELECT DISTINCT key_id FROM core_secrets")
            .fetch_all(&pool)
            .await;
    pool.close().await;
    let mut held = vec![SecretBox::from_file(&h.master_key())?.key_id().to_owned()];
    held.extend(key_files(&h.keys())?.into_iter().map(|f| f.0));
    let mut named = named?;
    named.extend(sealed::file_key_ids(&h.0)?);
    let missing: Vec<String> = named.into_iter().filter(|id| !held.contains(id)).collect();
    match missing.is_empty() {
        true => Ok(()),
        false => Err(format!(
            "restore refused: the database holds secrets sealed under master key(s) {} that the \
             archive does not carry (a retired key purged before the backup?). Restore an \
             archive that has them (keys/master.<id>.key.retired); nothing was written.",
            missing.join(", ")
        )
        .into()),
    }
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
