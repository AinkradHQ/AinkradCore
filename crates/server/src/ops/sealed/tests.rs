use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::*;
use crate::auth::Identity;

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn dir(name: &str) -> Dir {
    let d = std::env::temp_dir().join(format!("core-sealed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Dir(d)
}
fn key(n: u8) -> SecretBox {
    SecretBox::new(&[n; 32])
}
fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn any(_: &[u8]) -> bool {
    true
}
fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_sealed_file_names_its_key_and_opens_only_with_it_under_its_label() {
    let b = key(1);
    let s = seal_bytes(&b, "l", b"secret-material").unwrap();
    assert_eq!(&s[..5], MAGIC);
    assert_eq!(key_id_of(&s).as_deref(), Some(b.key_id()));
    assert!(
        !s.windows(15).any(|w| w == b"secret-material"),
        "no plaintext in the file"
    );
    assert_eq!(
        open_bytes(&b, "l", &s).unwrap().as_slice(),
        b"secret-material"
    );
    // wrong label, wrong key (named as not held), flipped bytes anywhere, truncation
    assert!(open_bytes(&b, "other", &s).is_err());
    let e = open_bytes(&key(2), "l", &s).unwrap_err().to_string();
    assert!(e.contains("does not hold") && e.contains(b.key_id()), "{e}");
    for i in [0, 6, HEADER, s.len() - 1] {
        let mut t = s.clone();
        t[i] ^= 1;
        assert!(open_bytes(&b, "l", &t).is_err(), "byte {i}");
    }
    assert!(open_bytes(&b, "l", &s[..HEADER + 4]).is_err());
}

#[test]
fn a_legacy_plaintext_file_is_sealed_once_in_place_and_never_read_as_plaintext_again() {
    let d = dir("migrate");
    let p = d.0.join("k");
    private(&p, b"legacy-key-bytes");
    let b = key(1);
    let got = read(&p, &b, "l", true, any).unwrap();
    assert_eq!(got.as_slice(), b"legacy-key-bytes");
    let after = std::fs::read(&p).unwrap();
    assert!(is_sealed(&after) && !after.windows(16).any(|w| w == b"legacy-key-bytes"));
    assert_eq!(mode(&p), 0o600);
    assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 1, "no temp left");
    // The second read opens the sealed file, byte for byte untouched, and needs the key: a
    // box that lacks it is refused, not given the plaintext.
    assert_eq!(
        read(&p, &b, "l", true, any).unwrap().as_slice(),
        b"legacy-key-bytes"
    );
    assert_eq!(std::fs::read(&p).unwrap(), after);
    assert!(read(&p, &key(2), "l", true, any).is_err());
    // A sealed file is never "valid legacy": plaintext validation is not consulted.
    assert!(read(&p, &b, "l", true, |_| false).is_ok());
}

#[test]
fn read_only_callers_do_not_migrate_and_an_invalid_legacy_file_is_refused_untouched() {
    let d = dir("refuse");
    let p = d.0.join("k");
    private(&p, b"legacy");
    read(&p, &key(1), "l", false, any).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"legacy", "read-only leaves it");
    let e = read(&p, &key(1), "l", true, |_| false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("neither a sealed key file"), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), b"legacy", "untouched");
    // A damaged magic is not mistaken for a plaintext key either.
    let mut s = seal_bytes(&key(1), "l", b"x").unwrap();
    s[0] ^= 1;
    private(&p, &s);
    assert!(read(&p, &key(1), "l", true, |_| false).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), s);
    // Group/other-readable is refused, as before.
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read(&p, &key(1), "l", true, any).is_err());
}

/// A crash between writing the sealed temp file and the rename leaves the plaintext file
/// loadable (and a stray 0600 temp), and the next start finishes the job.
#[test]
fn a_crash_before_the_rename_leaves_a_loadable_file() {
    let d = dir("crash");
    let p = d.0.join("k");
    private(&p, b"legacy-key-bytes");
    let b = key(1);
    let tmp = d.0.join(".k.deadbeef.tmp");
    private(&tmp, &seal_bytes(&b, "l", b"legacy-key-bytes").unwrap());
    assert_eq!(
        read(&p, &b, "l", true, any).unwrap().as_slice(),
        b"legacy-key-bytes"
    );
    assert!(is_sealed(&std::fs::read(&p).unwrap()));
    // After the rename the file is whole: sealed, openable.
    assert_eq!(
        read(&p, &b, "l", true, any).unwrap().as_slice(),
        b"legacy-key-bytes"
    );
}

#[test]
fn reseal_moves_a_file_to_the_new_key_and_is_idempotent() {
    let d = dir("reseal");
    let p = d.0.join("k");
    let (old, new) = (key(1), key(2));
    create(&p, &old, "l", b"v").unwrap();
    assert!(
        create(&p, &old, "l", b"other").is_err(),
        "never over an existing file"
    );
    let ring = key(1).with_extra(vec![key(2)]);
    assert!(reseal(&p, "l", &ring, &new).unwrap());
    assert_eq!(
        key_id_of(&std::fs::read(&p).unwrap()).as_deref(),
        Some(new.key_id())
    );
    assert!(!reseal(&p, "l", &ring, &new).unwrap(), "already there");
    assert_eq!(
        open_bytes(&new, "l", &std::fs::read(&p).unwrap())
            .unwrap()
            .as_slice(),
        b"v"
    );
    assert_eq!(mode(&p), 0o600);
    // A keyring without the file's key changes nothing.
    create(&d.0.join("j"), &old, "l", b"w").unwrap();
    let before = std::fs::read(d.0.join("j")).unwrap();
    assert!(reseal(&d.0.join("j"), "l", &key(3), &new).is_err());
    assert_eq!(std::fs::read(d.0.join("j")).unwrap(), before);
    assert!(!reseal(&d.0.join("none"), "l", &ring, &new).unwrap());
}

// The Core identity.

#[test]
fn the_identity_is_created_sealed_and_a_wrong_or_missing_master_never_makes_a_new_one() {
    let d = dir("identity");
    let a = Identity::load_or_create(&d.0, &key(1)).unwrap();
    let file = d.0.join(crate::auth::identity::FILE);
    let on_disk = std::fs::read(&file).unwrap();
    assert!(is_sealed(&on_disk), "sealed from the first byte");
    assert_eq!(mode(&file), 0o600);
    assert_eq!(Identity::load_or_create(&d.0, &key(1)).unwrap().fp, a.fp);
    // Another master key: refused with a message naming the missing key, file untouched, no
    // second identity file anywhere.
    let e = Identity::load_or_create(&d.0, &key(2))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("does not hold") && e.contains(key(1).key_id()),
        "{e}"
    );
    assert!(Identity::load_readonly(&d.0, &key(2)).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), on_disk);
    assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 1);
    // A corrupted sealed file is refused too, not regenerated.
    let mut bad = on_disk.clone();
    *bad.last_mut().unwrap() ^= 1;
    std::fs::write(&file, &bad).unwrap();
    assert!(Identity::load_or_create(&d.0, &key(1)).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), bad);
    // No master key file at all: the home loader says so (the Core does not start).
    let e = SecretBox::for_home(&d.0).unwrap_err().to_string();
    assert!(e.contains("will not start without it"), "{e}");
}

#[test]
fn a_legacy_plaintext_identity_keeps_its_fingerprint_and_is_sealed_by_the_first_load() {
    let d = dir("identity-legacy");
    let der = Identity::generate_pkcs8().unwrap();
    let fp = Identity::from_pkcs8(&der).unwrap().fp;
    let file = d.0.join(crate::auth::identity::FILE);
    private(&file, &der);
    // The read-only path (CLI) reads it and leaves it alone.
    assert_eq!(Identity::load_readonly(&d.0, &key(1)).unwrap().fp, fp);
    assert_eq!(std::fs::read(&file).unwrap(), der);
    assert_eq!(Identity::load_or_create(&d.0, &key(1)).unwrap().fp, fp);
    let sealed_now = std::fs::read(&file).unwrap();
    assert!(is_sealed(&sealed_now) && !sealed_now.windows(der.len()).any(|w| w == der.as_slice()));
    assert_eq!(Identity::load_readonly(&d.0, &key(1)).unwrap().fp, fp);
    assert_eq!(Identity::load_or_create(&d.0, &key(1)).unwrap().fp, fp);
    // The plaintext is not accepted as a stand-in for a lost key.
    assert!(Identity::load_or_create(&d.0, &key(2)).is_err());
}
