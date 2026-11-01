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
/// A key file `name` in the home `d`.
fn kf<'a>(d: &'a Path, p: &'a Path, label: &'a str) -> KeyFile<'a> {
    KeyFile {
        path: p,
        home: d,
        label,
    }
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

/// The outer header is authenticated: a key id edited to name ANOTHER held key (so the lookup
/// succeeds) still fails the open, and the version byte cannot be changed either.
#[test]
fn the_outer_header_is_bound_into_the_authenticated_data() {
    let ring = key(1).with_extra(vec![key(2)]);
    let s = seal_bytes(&key(1), "l", b"v").unwrap();
    let mut t = s.clone();
    t[MAGIC.len()..HEADER].copy_from_slice(key(2).key_id().as_bytes());
    assert!(ring.holds(key(2).key_id()));
    let e = open_bytes(&ring, "l", &t).unwrap_err().to_string();
    assert!(e.contains("cannot be opened"), "{e}");
    assert_eq!(open_bytes(&ring, "l", &s).unwrap().as_slice(), b"v");
    // The current and the next identity files do not open as each other.
    let n = seal_bytes(&key(1), IDENTITY_NEXT_LABEL, b"v").unwrap();
    assert!(open_bytes(&key(1), IDENTITY_LABEL, &n).is_err());
}

#[test]
fn a_legacy_plaintext_file_is_sealed_once_in_place_and_never_read_as_plaintext_again() {
    let d = dir("migrate");
    let p = d.0.join("k");
    private(&p, b"legacy-key-bytes");
    let b = key(1);
    let f = kf(&d.0, &p, "l");
    let got = read(f, &b, true, any).unwrap();
    assert_eq!(got.as_slice(), b"legacy-key-bytes");
    let after = std::fs::read(&p).unwrap();
    assert!(is_sealed(&after) && !after.windows(16).any(|w| w == b"legacy-key-bytes"));
    assert_eq!(mode(&p), 0o600);
    assert!(d.0.join("keys/.sealed.l").exists(), "the durable marker");
    assert_eq!(
        std::fs::read_dir(&d.0).unwrap().count(),
        2,
        "the file and keys/, no temp left"
    );
    // The second read opens the sealed file, byte for byte untouched, and needs the key: a
    // box that lacks it is refused, not given the plaintext.
    assert_eq!(
        read(f, &b, true, any).unwrap().as_slice(),
        b"legacy-key-bytes"
    );
    assert_eq!(std::fs::read(&p).unwrap(), after);
    assert!(read(f, &key(2), true, any).is_err());
    // A sealed file is never "valid legacy": plaintext validation is not consulted.
    assert!(read(f, &b, true, |_| false).is_ok());
}

/// After a migration a plaintext file at the same place is refused, whether it is planted
/// or swapped in; read-only callers are refused too; an explicit override accepts and seals it.
#[test]
fn a_plaintext_file_appearing_after_the_migration_is_refused_unless_overridden() {
    let d = dir("planted");
    let p = d.0.join("k");
    let f = kf(&d.0, &p, "l");
    private(&p, b"first");
    read(f, &key(1), true, any).unwrap();
    private(&p, b"planted-plaintext");
    for migrate in [true, false] {
        let e = read_with(f, &key(1), migrate, false, any)
            .unwrap_err()
            .to_string();
        assert!(e.contains("sealed before"), "{e}");
    }
    assert_eq!(
        std::fs::read(&p).unwrap(),
        b"planted-plaintext",
        "untouched"
    );
    let got = read_with(f, &key(1), true, true, any).unwrap();
    assert_eq!(got.as_slice(), b"planted-plaintext");
    assert!(
        is_sealed(&std::fs::read(&p).unwrap()),
        "sealed by the override"
    );
    // Another kind of file in the same home is not affected by this marker.
    let q = d.0.join("other");
    private(&q, b"legacy");
    assert!(read_with(kf(&d.0, &q, "m"), &key(1), true, false, any).is_ok());
}

#[test]
fn read_only_callers_do_not_migrate_and_an_invalid_legacy_file_is_refused_untouched() {
    let d = dir("refuse");
    let p = d.0.join("k");
    let f = kf(&d.0, &p, "l");
    private(&p, b"legacy");
    read(f, &key(1), false, any).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"legacy", "read-only leaves it");
    assert!(!d.0.join("keys").exists(), "and writes no marker");
    let e = read(f, &key(1), true, |_| false).unwrap_err().to_string();
    assert!(e.contains("neither a sealed key file"), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), b"legacy", "untouched");
    // A damaged magic is not mistaken for a plaintext key either.
    let mut s = seal_bytes(&key(1), "l", b"x").unwrap();
    s[0] ^= 1;
    private(&p, &s);
    assert!(read(f, &key(1), true, |_| false).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), s);
    // Group/other-readable is refused, as before.
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read(f, &key(1), true, any).is_err());
}

#[test]
fn a_symlink_is_refused_for_reading_and_resealing() {
    let d = dir("symlink");
    let real = d.0.join("real");
    private(&real, &seal_bytes(&key(1), "l", b"v").unwrap());
    let link = d.0.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let f = kf(&d.0, &link, "l");
    let e = read(f, &key(1), true, any).unwrap_err().to_string();
    assert!(e.contains("not a regular file"), "{e}");
    assert!(reseal(f, &key(1), &key(2)).is_err());
    assert_eq!(
        open_bytes(&key(1), "l", &std::fs::read(&real).unwrap())
            .unwrap()
            .as_slice(),
        b"v"
    );
}

/// Crash injection (`Stop`): after the temp file but before the rename (the plaintext is still
/// the file, a temp file is left, the next load migrates and cleans it up); after the rename but
/// before the directory sync (the sealed file is whole and loads).
#[test]
fn a_crash_at_either_seam_leaves_a_loadable_file() {
    let d = dir("crash");
    let p = d.0.join("k");
    let f = kf(&d.0, &p, "l");
    let b = key(1);
    private(&p, b"legacy-key-bytes");
    let e = write_sealed(f, &b, b"legacy-key-bytes", true, Stop::AfterTempSync).unwrap_err();
    assert!(e.to_string().contains("temp file"), "{e}");
    assert_eq!(
        std::fs::read(&p).unwrap(),
        b"legacy-key-bytes",
        "plaintext still there"
    );
    let stray: Vec<_> = std::fs::read_dir(&d.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "tmp"))
        .collect();
    assert_eq!(stray.len(), 1, "the crash left its temp file");
    assert_eq!(mode(&stray[0]), 0o600);
    // A fresh temp file is kept (a writer may be running); an old one is cleaned up on load.
    read(f, &b, true, any).unwrap();
    assert!(stray[0].exists(), "not older than a minute: kept");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(&stray[0])
        .unwrap()
        .set_modified(old)
        .unwrap();
    read(f, &b, true, any).unwrap();
    assert!(!stray[0].exists(), "stale temp file removed");
    assert!(is_sealed(&std::fs::read(&p).unwrap()));

    // After the rename, before the directory sync.
    let q = d.0.join("q");
    private(&q, b"second");
    let fq = kf(&d.0, &q, "m");
    write_sealed(fq, &b, b"second", true, Stop::AfterRename).unwrap_err();
    assert!(is_sealed(&std::fs::read(&q).unwrap()), "already in place");
    assert_eq!(read(fq, &b, true, any).unwrap().as_slice(), b"second");
    assert!(
        d.0.join("keys/.sealed.m").exists(),
        "the marker catches up on load"
    );
}

#[test]
fn the_written_file_is_verified_from_disk_before_it_replaces_anything() {
    let d = dir("verify");
    let p = d.0.join("k");
    private(&p, b"old");
    let e = write_atomic(&p, b"new", true, Stop::Never, |_| false).unwrap_err();
    assert!(e.to_string().contains("did not verify"), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), b"old");
    assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 1, "temp removed");
}

#[test]
fn reseal_moves_a_file_to_the_new_key_and_is_idempotent() {
    let d = dir("reseal");
    let p = d.0.join("k");
    let f = kf(&d.0, &p, "l");
    let (old, new) = (key(1), key(2));
    create(f, &old, b"v").unwrap();
    assert!(
        create(f, &old, b"other").is_err(),
        "never over an existing file"
    );
    let ring = key(1).with_extra(vec![key(2)]);
    assert!(reseal(f, &ring, &new).unwrap());
    assert_eq!(
        key_id_of(&std::fs::read(&p).unwrap()).as_deref(),
        Some(new.key_id())
    );
    assert!(!reseal(f, &ring, &new).unwrap(), "already there");
    assert_eq!(
        open_bytes(&new, "l", &std::fs::read(&p).unwrap())
            .unwrap()
            .as_slice(),
        b"v"
    );
    assert_eq!(mode(&p), 0o600);
    // A keyring without the file's key changes nothing.
    let j = d.0.join("j");
    create(kf(&d.0, &j, "l"), &old, b"w").unwrap();
    let before = std::fs::read(&j).unwrap();
    assert!(reseal(kf(&d.0, &j, "l"), &key(3), &new).is_err());
    assert_eq!(std::fs::read(&j).unwrap(), before);
    assert!(!reseal(kf(&d.0, &d.0.join("none"), "l"), &ring, &new).unwrap());
}

/// `file_key_ids` is what keeps `purge-retired-keys` from deleting the only key that opens the
/// identity: it never guesses.
#[test]
fn file_key_ids_names_keys_and_errors_instead_of_guessing() {
    let d = dir("ids");
    let id = d.0.join(crate::auth::identity::FILE);
    assert!(file_key_ids(&d.0).unwrap().is_empty(), "nothing there");
    private(&id, &seal_bytes(&key(1), IDENTITY_LABEL, b"v").unwrap());
    assert_eq!(
        file_key_ids(&d.0).unwrap(),
        vec![key(1).key_id().to_owned()]
    );
    // A legacy plaintext file names no key.
    private(&id, b"legacy");
    assert!(file_key_ids(&d.0).unwrap().is_empty());
    // Sealed, but the key id is damaged: an error, not "no key".
    let mut bad = seal_bytes(&key(1), IDENTITY_LABEL, b"v").unwrap();
    bad[MAGIC.len()] = b'Z';
    private(&id, &bad);
    let e = file_key_ids(&d.0).unwrap_err().to_string();
    assert!(e.contains("unreadable key id"), "{e}");
    // Unreadable: an error too.
    private(&id, &seal_bytes(&key(1), IDENTITY_LABEL, b"v").unwrap());
    std::fs::set_permissions(&id, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&id).is_err() {
        assert!(file_key_ids(&d.0).is_err());
    }
    std::fs::set_permissions(&id, std::fs::Permissions::from_mode(0o600)).unwrap();
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
    assert_eq!(
        std::fs::read_dir(&d.0).unwrap().count(),
        2,
        "the file and keys/"
    );
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
    assert_eq!(std::fs::read(&file).unwrap(), der.as_slice());
    assert_eq!(Identity::load_or_create(&d.0, &key(1)).unwrap().fp, fp);
    let sealed_now = std::fs::read(&file).unwrap();
    assert!(is_sealed(&sealed_now) && !sealed_now.windows(der.len()).any(|w| w == der.as_slice()));
    assert_eq!(Identity::load_readonly(&d.0, &key(1)).unwrap().fp, fp);
    assert_eq!(Identity::load_or_create(&d.0, &key(1)).unwrap().fp, fp);
    // The plaintext is not accepted as a stand-in for a lost key.
    assert!(Identity::load_or_create(&d.0, &key(2)).is_err());
}
