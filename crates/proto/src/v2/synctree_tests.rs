use super::*;

fn own(l: &[&str]) -> Vec<String> {
    l.iter().map(|s| (*s).to_owned()).collect()
}

fn rules(include: &[&str], exclude: &[&str], outputs: &[&str]) -> Rules {
    Rules {
        include: own(include),
        exclude: own(exclude),
        outputs: own(outputs),
    }
}

fn file(path: &str, body: &[u8], exec: bool) -> Entry {
    let (hash, chunks) = hash_bytes(body);
    Entry {
        path: path.to_owned(),
        kind: EntryKind::File,
        exec,
        size: body.len() as u64,
        hash,
        chunks,
        link: None,
    }
}

#[test]
fn git_is_never_synced_and_no_setting_lifts_it() {
    let r = rules(&[".git/**", "**"], &[], &["**"]);
    for p in [".git/config", "a/.git/hooks/x", ".GIT/x", "sub/.Git"] {
        assert_eq!(r.sync_in(p), Some(Skip::Git), "{p}");
        assert_eq!(r.sync_out(p), Some(Skip::Git), "{p}");
    }
    assert_eq!(Rules::default().sync_in(".gitignore"), None);
}

#[test]
fn build_output_and_secrets_stay_out_unless_the_project_says() {
    let r = Rules::default();
    assert_eq!(r.sync_in("target/debug/x"), Some(Skip::BuildOutput));
    assert_eq!(r.sync_in("a/node_modules/p/i.js"), Some(Skip::BuildOutput));
    assert_eq!(
        r.sync_in("src/build.rs"),
        None,
        "a file named build is not a dir"
    );
    assert_eq!(r.sync_in("app/.env"), Some(Skip::Secret));
    assert_eq!(r.sync_in(".env.local"), Some(Skip::Secret));
    for p in [
        "k.pem",
        "x/id_ed25519",
        ".npmrc",
        "a/.netrc",
        "v.kdbx",
        "t.key",
    ] {
        assert_eq!(r.sync_in(p), Some(Skip::Secret), "{p}");
        assert_eq!(r.sync_out(p), Some(Skip::Secret), "{p}");
    }
    let r = rules(
        &[".env.example", "certs/*.pem"],
        &[],
        &["target/release/app"],
    );
    assert_eq!(r.sync_in(".env.example"), None);
    assert_eq!(r.sync_in("certs/a.pem"), None);
    assert_eq!(r.sync_in("other/a.pem"), Some(Skip::Secret));
    assert_eq!(r.sync_in("target/release/app"), Some(Skip::BuildOutput));
    assert_eq!(r.sync_out("target/release/app"), None);
    assert_eq!(r.sync_out("target/release/other"), Some(Skip::BuildOutput));
    assert!(r.enters_build_dirs(true) && r.enters_build_dirs(false));
    assert!(rules(&[], &[], &["x"]).enters_build_dirs(true));
    assert!(!rules(&[], &[], &["x"]).enters_build_dirs(false));
}

#[test]
fn the_wire_round_trip_tells_built_ins_from_the_projects_own() {
    let r = rules(
        &[".env.test", "dist/keep.js"],
        &["dist/**"],
        &["target/release/app"],
    );
    let w = r.to_wire();
    assert!(w.exclude.contains(&"target/".to_owned()) && w.exclude.contains(&".env.*".to_owned()));
    assert!(w.exclude.contains(&"dist/**".to_owned()));
    assert_eq!(Rules::from_wire(&w), r);
    // A project include lets a secret-shaped file in, but never past a project exclude.
    assert_eq!(r.sync_in(".env.test"), None);
    assert_eq!(r.sync_in(".env.prod"), Some(Skip::Secret));
    assert_eq!(r.sync_in("dist/keep.js"), Some(Skip::Excluded));
}

#[test]
fn globs_match_as_documented() {
    assert!(glob("*.pem", "a/b/c.pem") && !glob("a/*.pem", "a/b/c.pem"));
    assert!(glob("a/**", "a/b/c") && glob("a/**/c", "a/c") && glob("a/**/c", "a/b/c"));
    assert!(glob("src/**/*.rs", "src/a/b.rs") && !glob("src/*.rs", "src/a/b.rs"));
    assert!(glob("a/?.x", "a/b.x") && !glob("a/?.x", "a//.x"));
    assert!(!glob(".env.*", ".env") && glob(".env", ".env"));
}

#[test]
fn the_rules_hash_changes_with_the_rules_and_not_with_their_order() {
    assert_eq!(
        rules(&["x", "y"], &[], &[]).hash(),
        rules(&["y", "x"], &[], &[]).hash()
    );
    assert_ne!(
        rules(&["x"], &[], &[]).hash(),
        rules(&["y"], &[], &[]).hash()
    );
    assert_ne!(Rules::default().hash(), rules(&[], &["x"], &[]).hash());
}

#[test]
fn the_fold_is_the_documented_one() {
    let mut m = Entries::new();
    for e in [file("b.txt", b"two", false), file("a/x.sh", b"one", true)] {
        m.insert(e.path.clone(), e);
    }
    // Written out from the docs' words, in ascending path-byte order: `a/x.sh` then `b.txt`.
    let mut h = blake3::Hasher::new();
    h.update(b"ainkrad-tree-v1\n");
    for (p, body, exec) in [("a/x.sh", &b"one"[..], 1u8), ("b.txt", &b"two"[..], 0u8)] {
        h.update(&(p.len() as u32).to_le_bytes());
        h.update(p.as_bytes());
        h.update(&[0u8, exec]);
        h.update(&(body.len() as u64).to_le_bytes());
        h.update(blake3::hash(body).as_bytes());
        h.update(&0u32.to_le_bytes());
    }
    assert_eq!(tree_hash(&m).0, *h.finalize().as_bytes());
    let empty = blake3::hash(b"ainkrad-tree-v1\n");
    assert_eq!(tree_hash(&Entries::new()).0, *empty.as_bytes());
}

#[test]
fn chunks_are_one_mebibyte_and_the_whole_hash_matches_the_bytes() {
    let data = vec![7u8; CHUNK_BYTES as usize + 5];
    let (whole, size, chunks) = hash_reader(&data[..]).unwrap();
    assert_eq!((size, chunks.len()), (data.len() as u64, 2));
    assert_eq!((whole, chunks.clone()), hash_bytes(&data));
    assert_eq!(
        chunks[1],
        Hash(*blake3::hash(&data[CHUNK_BYTES as usize..]).as_bytes())
    );
    assert!(hash_reader(&b""[..]).unwrap().2.is_empty());
}

#[test]
fn links_stay_inside_the_project_and_paths_are_checked() {
    assert!(link_ok("a/b", "c") && link_ok("a/b", "../x") && link_ok("a", "b/../c"));
    assert!(!link_ok("a", "../x") && !link_ok("a/b", "../../x") && !link_ok("a", "/x"));
    assert!(!link_ok("a", ".git/config") && !link_ok("a", "x/.GIT") && !link_ok("a", ""));
    assert_eq!(check_path("src/main.rs"), Ok(()));
    for bad in ["", "/abs", "a/../b", "a\nb", ".git/config"] {
        assert!(check_path(bad).is_err(), "{bad:?}");
    }
}
