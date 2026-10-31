//! The signed state archive (E1-13.6, threat model T-BAK-2): what `backup` encrypts and what
//! `export` writes. `age` gives confidentiality, not provenance (anyone with the public recipient
//! can encrypt a valid-looking file), so every archive is signed, and `restore`/`import` check
//! the signature against a fingerprint the operator pins (`--signer`) before writing anything.
//!
//! Layout:
//!
//! ```text
//! AINKRAD-ARCHIVE-1\n
//! <manifest JSON, one line>\n
//! <signature: base64url, no padding>\n
//! <each file's bytes, in manifest order>
//! ```
//!
//! The signature is ECDSA P-256 / SHA-256, raw `r‖s` (handshake spec §3), over the magic line
//! followed by the manifest's exact bytes, never a re-serialisation. The manifest names the
//! signer's SPKI and fingerprint (`base64url(SHA-256(SPKI))`, spec §3) and each file's size and
//! SHA-256, so the files are covered too. Names come from `FILES` only: a name is never a path.
//!
//! The signing key: the Core identity key (E1-07) is not on `development` yet, so `init` makes a
//! dedicated backup-signing key (`keys/backup-signing.p8`, 0600) beside the master key.
//! ponytail: one key per role until the identity lane lands; then sign with the identity key
//! (same curve, same fingerprint rule) and drop this file.

use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::digest::{Context, SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8] = b"AINKRAD-ARCHIVE-1\n";
/// The only names an archive may hold.
/// `core-identity.p8` (the Core identity key, beside the database) goes only into a backup, which
/// is encrypted; an archive without it (an export, or one written before it was carried) is
/// still read.
pub const FILES: [&str; 3] = ["core.db", "keys/master.key", IDENTITY];
/// A spare master key member (`keys/master.<id>.key[.retired]`): a retired key, or a rotation's
/// pending one. Only a backup carries them (it is encrypted).
pub fn is_spare_key(name: &str) -> bool {
    name.strip_prefix("keys/")
        .is_some_and(|f| super::secretbox::key_file_kind(f).is_some())
}
/// The Core identity key's member name, the same as its file name in a home.
pub const IDENTITY: &str = crate::auth::identity::FILE;
/// DER prefix of a P-256 `SubjectPublicKeyInfo` with an uncompressed point (spec §3).
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const LINE_MAX: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// `backup` or `export`.
    pub kind: String,
    pub created_at: String,
    /// The signer's SPKI, base64url.
    pub signer: String,
    pub signer_fp: String,
    pub files: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
}

fn invalid(why: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The 91-byte SPKI of an uncompressed P-256 point.
pub fn spki(public: &[u8]) -> Vec<u8> {
    [&SPKI_PREFIX[..], public].concat()
}

/// `base64url_nopad(SHA-256(SPKI))`, 43 characters.
pub fn fingerprint(spki: &[u8]) -> String {
    B64.encode(digest(&SHA256, spki))
}

/// A new PKCS#8 P-256 signing key.
pub fn new_signing_key() -> io::Result<Vec<u8>> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .map(|d| d.as_ref().to_vec())
        .map_err(|_| io::Error::other("generating the signing key failed"))
}

pub fn load_signer(pkcs8: &[u8]) -> io::Result<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8,
        &SystemRandom::new(),
    )
    .map_err(|_| invalid("not a PKCS#8 P-256 signing key"))
}

pub fn signer_fingerprint(key: &EcdsaKeyPair) -> String {
    fingerprint(&spki(key.public_key().as_ref()))
}

fn sha256_file(path: &Path) -> io::Result<(u64, String)> {
    let mut ctx = Context::new(&SHA256);
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok((size, hex(ctx.finish().as_ref())));
        }
        size += n as u64;
        ctx.update(&buf[..n]);
    }
}

/// A file's SHA-256, lowercase hex.
pub fn sha256_hex(path: &Path) -> io::Result<String> {
    sha256_file(path).map(|(_, h)| h)
}

/// Writes a signed archive of `files` (`(name, path)`, each name from `FILES`) to `out`.
pub fn write(
    out: &mut impl Write,
    signer: &EcdsaKeyPair,
    kind: &str,
    created_at: &str,
    files: &[(&str, &Path)],
) -> io::Result<Manifest> {
    let spki = spki(signer.public_key().as_ref());
    let mut entries = Vec::new();
    for (name, path) in files {
        let (size, sha256) = sha256_file(path)?;
        entries.push(Entry {
            name: (*name).to_owned(),
            size,
            sha256,
        });
    }
    let manifest = Manifest {
        version: 1,
        kind: kind.to_owned(),
        created_at: created_at.to_owned(),
        signer: B64.encode(&spki),
        signer_fp: fingerprint(&spki),
        files: entries,
    };
    let json = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
    let signature = signer
        .sign(&SystemRandom::new(), &[MAGIC, &json].concat())
        .map_err(|_| io::Error::other("signing failed"))?;
    out.write_all(MAGIC)?;
    out.write_all(&json)?;
    out.write_all(b"\n")?;
    out.write_all(B64.encode(signature.as_ref()).as_bytes())?;
    out.write_all(b"\n")?;
    for (entry, (_, path)) in manifest.files.iter().zip(files) {
        // The file must not change between hashing and copying (it is a private snapshot).
        let copied = io::copy(&mut File::open(path)?.take(entry.size), out)?;
        if copied != entry.size {
            return Err(io::Error::other(format!(
                "{} shrank while archiving",
                entry.name
            )));
        }
    }
    out.flush()?;
    Ok(manifest)
}

/// One `\n`-terminated line of at most `LINE_MAX` bytes, without the `\n`.
fn line(input: &mut impl BufRead, what: &str) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    input.take(LINE_MAX).read_until(b'\n', &mut buf)?;
    if buf.pop() != Some(b'\n') {
        return Err(invalid(format!("not an Ainkrad archive: no {what} line")));
    }
    Ok(buf)
}

/// Checks the header (magic, manifest, signature by the key whose fingerprint is `pinned`)
/// and only then writes each file into `dir` (0600), checking its size and SHA-256 and that
/// nothing follows the last one. `dir` must exist; on an error it may hold part of the files,
/// so the caller throws it away.
pub fn read(input: &mut impl BufRead, pinned: &str, dir: &Path) -> io::Result<Manifest> {
    let mut magic = vec![0u8; MAGIC.len()];
    input
        .read_exact(&mut magic)
        .map_err(|_| invalid("not an Ainkrad archive"))?;
    if magic != MAGIC {
        return Err(invalid("not an Ainkrad archive (or a newer format)"));
    }
    let json = line(input, "manifest")?;
    let signature = line(input, "signature")?;
    let manifest: Manifest =
        serde_json::from_slice(&json).map_err(|e| invalid(format!("manifest: {e}")))?;
    let spki = B64
        .decode(&manifest.signer)
        .map_err(|_| invalid("manifest: signer is not base64url"))?;
    if spki.len() != 91 || spki[..26] != SPKI_PREFIX {
        return Err(invalid("manifest: signer is not a P-256 key"));
    }
    let fp = fingerprint(&spki);
    if fp != pinned || manifest.signer_fp != fp {
        return Err(invalid(format!(
            "signed by {fp}, not the pinned signer {pinned}: refusing it"
        )));
    }
    if signature.is_empty() {
        return Err(invalid("unsigned archive: refusing it"));
    }
    let signature = B64
        .decode(&signature)
        .map_err(|_| invalid("signature is not base64url"))?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &spki[26..])
        .verify(&[MAGIC, &json].concat(), &signature)
        .map_err(|_| invalid("bad signature: the archive was changed or forged; refusing it"))?;
    if manifest.version != 1 {
        return Err(invalid(format!("archive version {}", manifest.version)));
    }
    let names: Vec<&str> = manifest.files.iter().map(|e| e.name.as_str()).collect();
    if names.first() != Some(&"core.db")
        || names.iter().any(|n| !FILES.contains(n) && !is_spare_key(n))
        || (1..names.len()).any(|i| names[..i].contains(&names[i]))
    {
        return Err(invalid(format!("archive holds {names:?}")));
    }

    for entry in &manifest.files {
        let path = dir.join(&entry.name);
        if let Some(parent) = path.parent() {
            super::private_dir(parent)?;
        }
        let mut out = super::private_file(&path)?;
        let mut ctx = Context::new(&SHA256);
        let mut left = entry.size;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let n = input.read(&mut buf[..want])?;
            if n == 0 {
                return Err(invalid(format!("{} is truncated", entry.name)));
            }
            ctx.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        if hex(ctx.finish().as_ref()) != entry.sha256 {
            return Err(invalid(format!(
                "{} does not match its signed hash",
                entry.name
            )));
        }
        out.sync_all()?;
    }
    if input.read(&mut [0u8; 1])? != 0 {
        return Err(invalid("bytes after the last file"));
    }
    Ok(manifest)
}

/// Removes a staging directory, ignoring one that is already gone.
pub fn discard(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

#[cfg(test)]
mod tests;
