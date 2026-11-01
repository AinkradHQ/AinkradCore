//! Key files sealed at rest (E1-13.1 closing the gap): the Core identity key and the ACME
//! account key are stored as `SecretBox` envelopes, under the home's master key, not as plain
//! 0600 files.
//!
//! File format: `"ACSF" ‖ 0x01 ‖ key id (16 ASCII hex) ‖ SecretBox envelope` (the envelope
//! carries its own version byte, a random nonce, AES-256-GCM and the label as associated data).
//! The key id names the master key it was sealed under, so a file sealed under a key this home
//! does not hold is named as such instead of failing as tampered, and a rotation can find what
//! it still has to move. The file name stays the same as before (`core-identity.p8`,
//! `tls/account.json`): a file that does not start with the magic is a legacy plaintext one.
//!
//! The outer header (magic, version, key id) is bound into the associated data together with the
//! label, so neither can be edited without failing the open; each file kind has its own label.
//!
//! Migration of a legacy file ([`read`] with `migrate`): the plaintext must first validate (a
//! corrupt file is refused and left alone), is sealed to a private temp file in the same
//! directory (0600, synced), the TEMP FILE is read back from disk and decrypted, then it is
//! renamed over the original (atomic) and the directory synced. A crash before the rename leaves
//! the plaintext file (loadable, migrated on the next start, a stray temp file is cleaned up); after
//! it, the sealed one. The key is never only in memory. Afterwards a durable marker
//! (`keys/.sealed.<label>`) records that the file kind is sealed: a plaintext file that shows up
//! later is refused unless `AINKRAD_ALLOW_PLAINTEXT_KEYFILES=1` is set (a restored legacy backup).
//! Symlinks are refused.
//!
//! Honest scope: the master key is a file on the same host, so this protects copies of the data
//! directory (a disk snapshot, a stray backup of `core.db`'s directory), not an attacker who can
//! read the home as its owner or root.

use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::secretbox::SecretBox;

const MAGIC: &[u8; 5] = b"ACSF\x01";
const ID_LEN: usize = 16;
const HEADER: usize = MAGIC.len() + ID_LEN;
/// Set to `1` to accept (and seal) a plaintext key file although its kind was sealed before.
pub const ALLOW_PLAIN_ENV: &str = "AINKRAD_ALLOW_PLAINTEXT_KEYFILES";

pub const IDENTITY_LABEL: &str = "core.identity";
pub const IDENTITY_NEXT_LABEL: &str = "core.identity.next";
pub const ACME_LABEL: &str = "acme.account";

/// A key file: where it is, the home it belongs to (the marker lives in `<home>/keys`) and its
/// label.
#[derive(Clone, Copy)]
pub struct KeyFile<'a> {
    pub path: &'a Path,
    pub home: &'a Path,
    pub label: &'a str,
}

impl KeyFile<'_> {
    fn marker(&self) -> PathBuf {
        self.home
            .join("keys")
            .join(format!(".sealed.{}", self.label))
    }

    /// Whether this kind of file was sealed before (the marker exists).
    pub fn was_sealed(&self) -> bool {
        self.marker().exists()
    }

    /// Records, durably, that this kind of file is sealed.
    fn mark(&self) -> io::Result<()> {
        let m = self.marker();
        if m.exists() {
            return Ok(());
        }
        let keys = self.home.join("keys");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&keys)?;
        write_atomic(&m, b"sealed\n", true, Stop::Never, |_| true)?;
        Ok(())
    }
}

/// Crash injection for tests; real callers use `Never`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stop {
    Never,
    /// After the sealed temp file is synced and verified, before the rename (temp file left).
    AfterTempSync,
    /// After the rename, before the directory is synced.
    AfterRename,
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// The master key id a sealed file names, if `bytes` is one.
pub fn key_id_of(bytes: &[u8]) -> Option<String> {
    let id = bytes
        .get(MAGIC.len()..HEADER)
        .filter(|_| is_sealed(bytes))?;
    let id = std::str::from_utf8(id).ok()?;
    id.bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        .then(|| id.to_owned())
}

/// The label as the AEAD sees it: the caller's label and the whole outer header.
fn bound(label: &str, header: &[u8]) -> Vec<u8> {
    [label.as_bytes(), b"\0", header].concat()
}

fn bound_str(label: &str, header: &[u8]) -> String {
    // Header bytes are ASCII (magic, 0x01, hex), so this is lossless.
    String::from_utf8_lossy(&bound(label, header)).into_owned()
}

pub fn seal_bytes(seal: &SecretBox, label: &str, plain: &[u8]) -> io::Result<Vec<u8>> {
    let header = [MAGIC.as_slice(), seal.key_id().as_bytes()].concat();
    let env = seal.seal(&bound_str(label, &header), plain)?;
    Ok([header, env].concat())
}

/// Opens a sealed file's bytes under the key they name (current or spare). Every failure says
/// which file-level problem it is, never anything about key bytes.
pub fn open_bytes(seal: &SecretBox, label: &str, bytes: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let id = key_id_of(bytes).ok_or_else(|| err("not a sealed key file (damaged header)"))?;
    if !seal.holds(&id) {
        return Err(err(format!(
            "sealed under master key {id}, which this home does not hold (keys/master.key or \
             keys/master.{id}.key.retired): restore it from a backup; nothing was changed"
        )));
    }
    seal.open_as(&id, &bound_str(label, &bytes[..HEADER]), &bytes[HEADER..])
        .map_err(|e| err(format!("cannot be opened ({e})")))
}

/// Writes `bytes` to `path`: private temp file in the same directory (0600, synced), re-read from
/// disk and checked with `verify`, then `rename` over `path` (`replace`) or a hard link that never
/// replaces (`!replace`: an existing file is kept, `AlreadyExists`), then the directory synced.
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    replace: bool,
    stop: Stop,
    verify: impl Fn(&[u8]) -> bool,
) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or(Path::new("."));
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| err(e.to_string()))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    let tmp = dir.join(format!(
        ".{name}.{}.tmp",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let done = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // What is on disk, not what is in memory.
        if !verify(&std::fs::read(&tmp)?) {
            return Err(err(
                "the written key file did not verify; nothing was changed",
            ));
        }
        if stop == Stop::AfterTempSync {
            return Err(err("stopped after the temp file (test)"));
        }
        if replace {
            std::fs::rename(&tmp, path)
        } else {
            std::fs::hard_link(&tmp, path)
        }
    })();
    // An injected stop leaves the temp file behind, as a crash would.
    if stop != Stop::AfterTempSync || done.is_ok() {
        let _ = std::fs::remove_file(&tmp);
    }
    done?;
    if stop == Stop::AfterRename {
        return Err(err("stopped after the rename (test)"));
    }
    std::fs::File::open(dir)?.sync_all()
}

/// Seals `plain` under `seal` into `kf.path` (`replace`, else only as a new file), verified from
/// disk before it is put in place, and records that the kind is sealed.
pub fn write_sealed(
    kf: KeyFile,
    seal: &SecretBox,
    plain: &[u8],
    replace: bool,
    stop: Stop,
) -> io::Result<()> {
    let sealed = seal_bytes(seal, kf.label, plain)?;
    write_atomic(kf.path, &sealed, replace, stop, |disk| {
        open_bytes(seal, kf.label, disk).is_ok_and(|p| p.as_slice() == plain)
    })?;
    kf.mark()
}

/// Seals `plain` as a new file at `kf.path` (never over an existing one).
pub fn create(kf: KeyFile, seal: &SecretBox, plain: &[u8]) -> io::Result<()> {
    write_sealed(kf, seal, plain, false, Stop::Never)
}

/// Seals `plain` over `kf.path`.
pub fn replace(kf: KeyFile, seal: &SecretBox, plain: &[u8]) -> io::Result<()> {
    write_sealed(kf, seal, plain, true, Stop::Never)
}

/// Mode check without following a symlink: a key file must be a regular file, 0600 or tighter.
fn checked_meta(path: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(path)?;
    if !md.file_type().is_file() {
        return Err(err(format!(
            "{} is not a regular file (a symlink?); refusing it",
            path.display()
        )));
    }
    let mode = md.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(err(format!(
            "{} is readable by others (mode {:o}); chmod 600 it",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

/// Removes temp files a crashed write left beside `path` (older than a minute, so a writer in
/// another process is never raced).
fn clean_stale(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let prefix = format!(".{name}.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let n = e.file_name();
        let n = n.to_string_lossy();
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().is_ok_and(|a| a.as_secs() > 60));
        if n.starts_with(&prefix) && n.ends_with(".tmp") && old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The plaintext of the key file `kf` (mode 0600 or tighter, a regular file). A sealed file is
/// opened. A file without the magic is a legacy plaintext one: refused when this kind was sealed
/// before (unless [`ALLOW_PLAIN_ENV`] is `1`), else it must satisfy `valid` (else refused,
/// untouched) and, with `migrate`, is sealed in place first (see the module docs); without it (a
/// read-only caller) it is returned as it is and left alone.
pub fn read(
    kf: KeyFile,
    seal: &SecretBox,
    migrate: bool,
    valid: impl Fn(&[u8]) -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let allow = std::env::var(ALLOW_PLAIN_ENV).is_ok_and(|v| v == "1");
    read_with(kf, seal, migrate, allow, valid)
}

/// [`read`] with the override given instead of read from the environment.
pub fn read_with(
    kf: KeyFile,
    seal: &SecretBox,
    migrate: bool,
    allow_plain: bool,
    valid: impl Fn(&[u8]) -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let path = kf.path;
    checked_meta(path)?;
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let named = |e: io::Error| err(format!("{}: {e}", path.display()));
    if is_sealed(&bytes) {
        let plain = open_bytes(seal, kf.label, &bytes).map_err(named)?;
        if migrate {
            kf.mark()?;
            clean_stale(path);
        }
        return Ok(plain);
    }
    if kf.marker().exists() && !allow_plain {
        return Err(err(format!(
            "{} is plaintext but this kind of file was sealed before: a planted or restored old \
             file? Refusing it (set {ALLOW_PLAIN_ENV}=1 to accept and seal it)",
            path.display()
        )));
    }
    if !valid(&bytes) {
        return Err(err(format!(
            "{} is neither a sealed key file nor a valid legacy one; refusing to use it",
            path.display()
        )));
    }
    if migrate {
        clean_stale(path);
        write_sealed(kf, seal, &bytes, true, Stop::Never)?;
        tracing::info!(file = %path.display(), key_id = seal.key_id(), "key file sealed under the master key");
    }
    Ok(bytes)
}

/// Re-seals the sealed file at `kf.path` under `target`, opening it with `keyring` (which holds
/// the key it names). `Ok(false)`: absent, legacy plaintext (the next load migrates it) or
/// already under `target`. Idempotent, so an interrupted rotation just runs it again.
pub fn reseal(kf: KeyFile, keyring: &SecretBox, target: &SecretBox) -> io::Result<bool> {
    match std::fs::symlink_metadata(kf.path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
        Ok(_) => checked_meta(kf.path)?,
    }
    let bytes = Zeroizing::new(std::fs::read(kf.path)?);
    if !is_sealed(&bytes) || key_id_of(&bytes).as_deref() == Some(target.key_id()) {
        return Ok(false);
    }
    let plain = open_bytes(keyring, kf.label, &bytes)
        .map_err(|e| err(format!("{}: {e}", kf.path.display())))?;
    write_sealed(kf, target, &plain, true, Stop::Never)?;
    Ok(true)
}

/// The master key ids named by the sealed key files in `state` (the home): identity, the next
/// identity of a rotation, the ACME account. Purge and rotate treat them like a secret's row.
/// Anything but a missing file that cannot be read, or a sealed file whose key id cannot be
/// parsed, is an error: a purge must never go ahead on a guess.
pub fn file_key_ids(state: &Path) -> io::Result<Vec<String>> {
    let mut ids = Vec::new();
    for p in [
        state.join(crate::auth::identity::FILE),
        state.join(crate::auth::identity::NEXT),
        state.join("tls").join("account.json"),
    ] {
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(err(format!("{}: {e}", p.display()))),
        };
        // Anything that claims to be one of ours but has no readable v1 header is an error:
        // it cannot be classified, so a purge must not go ahead.
        if bytes.starts_with(b"ACSF") {
            ids.push(key_id_of(&bytes).ok_or_else(|| {
                err(format!(
                    "{}: a sealed key file with an unreadable key id",
                    p.display()
                ))
            })?);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests;
