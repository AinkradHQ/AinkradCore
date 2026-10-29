use std::io::Cursor;
use std::path::PathBuf;

use super::*;

/// A temp dir, removed on drop.
struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn dir(name: &str) -> Dir {
    let d = std::env::temp_dir().join(format!("core-archive-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    Dir(d)
}

/// An archive of two small files, and the signer's fingerprint.
fn archive(d: &Dir, key: &EcdsaKeyPair) -> Vec<u8> {
    fs::write(d.0.join("db"), b"SQLite format 3\0 and some pages").unwrap();
    fs::write(d.0.join("mk"), [9u8; 32]).unwrap();
    let mut out = Vec::new();
    write(
        &mut out,
        key,
        "backup",
        "2026-10-29T10:00:00.000Z",
        &[
            ("core.db", &d.0.join("db")),
            ("keys/master.key", &d.0.join("mk")),
        ],
    )
    .unwrap();
    out
}

fn key() -> EcdsaKeyPair {
    load_signer(&new_signing_key().unwrap()).unwrap()
}

fn unpack(bytes: &[u8], pinned: &str, d: &Dir) -> io::Result<Manifest> {
    let out = d.0.join("out");
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).unwrap();
    read(&mut Cursor::new(bytes), pinned, &out)
}

#[test]
fn round_trips_and_pins_the_signer() {
    let d = dir("round");
    let key = key();
    let fp = signer_fingerprint(&key);
    assert_eq!(fp.len(), 43);
    let bytes = archive(&d, &key);
    let m = unpack(&bytes, &fp, &d).unwrap();
    assert_eq!(m.kind, "backup");
    assert_eq!(m.files[1].size, 32);
    assert_eq!(
        fs::read(d.0.join("out/core.db")).unwrap(),
        b"SQLite format 3\0 and some pages"
    );
    assert_eq!(
        fs::read(d.0.join("out/keys/master.key")).unwrap(),
        [9u8; 32]
    );

    let other = signer_fingerprint(&super::load_signer(&new_signing_key().unwrap()).unwrap());
    let e = unpack(&bytes, &other, &d).unwrap_err();
    assert!(e.to_string().contains("not the pinned signer"), "{e}");
    assert!(
        !d.0.join("out/core.db").exists(),
        "nothing written before the check"
    );
}

#[test]
fn refuses_a_forged_a_tampered_and_an_unsigned_archive() {
    let d = dir("tamper");
    let key = key();
    let fp = signer_fingerprint(&key);
    let bytes = archive(&d, &key);
    let header = MAGIC.len()
        + bytes[MAGIC.len()..]
            .iter()
            .position(|b| *b == b'\n')
            .unwrap()
        + 1;
    let sig_end = header + bytes[header..].iter().position(|b| *b == b'\n').unwrap() + 1;

    // A byte of the database.
    let mut body = bytes.clone();
    body[sig_end + 3] ^= 1;
    let e = unpack(&body, &fp, &d).unwrap_err();
    assert!(
        e.to_string().contains("does not match its signed hash"),
        "{e}"
    );

    // The manifest (a size), signature left as it was.
    let text = String::from_utf8_lossy(&bytes[..header]).replace("\"size\":32", "\"size\":31");
    let mut manifest = text.into_bytes();
    manifest.extend_from_slice(&bytes[header..]);
    let e = unpack(&manifest, &fp, &d).unwrap_err();
    assert!(e.to_string().contains("bad signature"), "{e}");

    // No signature.
    let mut unsigned = bytes[..header].to_vec();
    unsigned.push(b'\n');
    unsigned.extend_from_slice(&bytes[sig_end..]);
    let e = unpack(&unsigned, &fp, &d).unwrap_err();
    assert!(e.to_string().contains("unsigned"), "{e}");

    // Signed by another key that names itself: the pin catches it.
    let forger = super::load_signer(&new_signing_key().unwrap()).unwrap();
    let forged = archive(&d, &forger);
    let e = unpack(&forged, &fp, &d).unwrap_err();
    assert!(e.to_string().contains("not the pinned signer"), "{e}");

    // Truncated, and with bytes appended.
    let e = unpack(&bytes[..bytes.len() - 1], &fp, &d).unwrap_err();
    assert!(e.to_string().contains("truncated"), "{e}");
    let mut longer = bytes.clone();
    longer.push(0);
    let e = unpack(&longer, &fp, &d).unwrap_err();
    assert!(e.to_string().contains("after the last file"), "{e}");
    assert!(unpack(b"PK\x03\x04", &fp, &d).is_err());
}
