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
//! Migration of a legacy file ([`read`] with `migrate`): the plaintext must first validate (a
//! corrupt file is refused and left alone), is sealed to a private temp file in the same
//! directory (0600, synced), read back and compared, renamed over the original (atomic) and the
//! directory synced. A crash before the rename leaves the plaintext file, loadable and migrated
//! on the next start; after it, the sealed one. The key is never only in memory. Afterwards the
//! file starts with the magic and is only ever opened with the master key.
//!
//! Honest scope: the master key is a file on the same host, so this protects copies of the data
//! directory (a disk snapshot, a stray backup of `core.db`'s directory), not an attacker who can
//! read the home as its owner or root.

use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use zeroize::Zeroizing;

use super::secretbox::SecretBox;

const MAGIC: &[u8; 5] = b"ACSF\x01";
const ID_LEN: usize = 16;
const HEADER: usize = MAGIC.len() + ID_LEN;

pub const IDENTITY_LABEL: &str = "core.identity";
pub const ACME_LABEL: &str = "acme.account";

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

pub fn seal_bytes(seal: &SecretBox, label: &str, plain: &[u8]) -> io::Result<Vec<u8>> {
    let env = seal.seal(label, plain)?;
    let mut out = Vec::with_capacity(HEADER + env.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(seal.key_id().as_bytes());
    out.extend_from_slice(&env);
    Ok(out)
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
    seal.open_as(&id, label, &bytes[HEADER..])
        .map_err(|e| err(format!("cannot be opened ({e})")))
}

/// Writes `bytes` to `path`: private temp file in the same directory (0600, synced), then
/// `rename` over `path` (`replace`) or a hard link that never replaces (`!replace`, an existing
/// file is kept: `AlreadyExists`), then the directory synced.
pub fn write_atomic(path: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
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
        if replace {
            std::fs::rename(&tmp, path)
        } else {
            std::fs::hard_link(&tmp, path)
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    done?;
    std::fs::File::open(dir)?.sync_all()
}

/// Seals `plain` as a new file at `path` (never over an existing one).
pub fn create(path: &Path, seal: &SecretBox, label: &str, plain: &[u8]) -> io::Result<()> {
    write_atomic(path, &seal_bytes(seal, label, plain)?, false)
}

/// Seals `plain` over `path`.
pub fn replace(path: &Path, seal: &SecretBox, label: &str, plain: &[u8]) -> io::Result<()> {
    write_atomic(path, &seal_bytes(seal, label, plain)?, true)
}

/// The plaintext of the key file at `path` (mode 0600 or tighter). A sealed file is opened. A
/// file without the magic is a legacy plaintext one: it must satisfy `valid` (else refused,
/// untouched) and, with `migrate`, is sealed in place first (see the module docs); without it
/// (a read-only caller) it is returned as it is and left alone.
pub fn read(
    path: &Path,
    seal: &SecretBox,
    label: &str,
    migrate: bool,
    valid: impl Fn(&[u8]) -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(err(format!(
            "{} is readable by others (mode {:o}); chmod 600 it",
            path.display(),
            mode & 0o777
        )));
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let named = |e: io::Error| err(format!("{}: {e}", path.display()));
    if is_sealed(&bytes) {
        return open_bytes(seal, label, &bytes).map_err(named);
    }
    if !valid(&bytes) {
        return Err(err(format!(
            "{} is neither a sealed key file nor a valid legacy one; refusing to use it",
            path.display()
        )));
    }
    if migrate {
        let sealed = seal_bytes(seal, label, &bytes)?;
        if open_bytes(seal, label, &sealed)?.as_slice() != bytes.as_slice() {
            return Err(err(
                "sealing did not round-trip; the plaintext file is kept",
            ));
        }
        write_atomic(path, &sealed, true)?;
        tracing::info!(file = %path.display(), key_id = seal.key_id(), "key file sealed under the master key");
    }
    Ok(bytes)
}

/// Re-seals the sealed file at `path` under `target`, opening it with `keyring` (which holds
/// the key it names). `Ok(false)`: absent, legacy plaintext (the next load migrates it) or
/// already under `target`. Idempotent, so an interrupted rotation just runs it again.
pub fn reseal(
    path: &Path,
    label: &str,
    keyring: &SecretBox,
    target: &SecretBox,
) -> io::Result<bool> {
    let bytes = match std::fs::read(path) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !is_sealed(&bytes) || key_id_of(&bytes).as_deref() == Some(target.key_id()) {
        return Ok(false);
    }
    let plain =
        open_bytes(keyring, label, &bytes).map_err(|e| err(format!("{}: {e}", path.display())))?;
    let sealed = seal_bytes(target, label, &plain)?;
    if open_bytes(target, label, &sealed)?.as_slice() != plain.as_slice() {
        return Err(err("re-sealing did not round-trip; nothing was changed"));
    }
    write_atomic(path, &sealed, true)?;
    Ok(true)
}

/// The master key ids named by the sealed key files in `state` (the home): identity, the next
/// identity of a rotation, the ACME account. Purge and rotate treat them like a secret's row.
pub fn file_key_ids(state: &Path) -> Vec<String> {
    [
        state.join(crate::auth::identity::FILE),
        state.join(crate::auth::identity::NEXT),
        state.join("tls").join("account.json"),
    ]
    .iter()
    .filter_map(|p| key_id_of(&std::fs::read(p).ok()?))
    .collect()
}

#[cfg(test)]
mod tests;
