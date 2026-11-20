use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command as Proc;

fn temp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ainkrad-wsfs-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

fn edit(old: &str, new: &str) -> RevertEdit {
    RevertEdit {
        old: old.to_owned(),
        new: new.to_owned(),
    }
}

#[test]
fn a_wire_path_is_checked_whole() {
    for ok in ["a", "a/b.rs", "dir/.gitignore", "ü/é"] {
        assert_eq!(check_path(ok), Ok(()), "{ok}");
    }
    let long = "x".repeat(MAX_COMPONENT + 1);
    let deep = vec!["d"; MAX_DEPTH + 1].join("/");
    let bad = [
        "",
        "/a",
        "../a",
        "a/..",
        "a/./b",
        "a//b",
        "a/",
        "a\\b",
        "a\0b",
        "a\nb",
        ".git",
        "x/.GIT/config",
        &long,
        &deep,
    ];
    for p in bad {
        assert!(check_path(p).is_err(), "{p:?}");
    }
}

/// No path built from the dangerous parts ever passes `check_path` and then escapes: every
/// accepted path, written under a root that has a link out, stays inside the root.
#[test]
fn random_paths_never_write_outside_the_root() {
    let d = temp("rand");
    let outside = temp("rand-out");
    symlink(&outside, d.join("out")).unwrap();
    let tree = Tree::open(&d).unwrap();
    let parts = [
        "a", "b", "..", ".", "out", ".git", "", "\\", "c.txt", "out/x",
    ];
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..3000 {
        let n = 1 + (seed % 4) as usize;
        let mut p = Vec::new();
        for _ in 0..n {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            p.push(parts[(seed >> 33) as usize % parts.len()]);
        }
        let _ = tree.write(&p.join("/"), b"x", None);
    }
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        0,
        "nothing leaked through the link"
    );
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn writes_are_atomic_and_never_follow_a_link() {
    let d = temp("write");
    let outside = temp("write-out");
    fs::write(outside.join("victim"), "keep").unwrap();
    symlink(outside.join("victim"), d.join("f")).unwrap();
    symlink(&outside, d.join("dir")).unwrap();
    let tree = Tree::open(&d).unwrap();
    // The link `f` is replaced, its target is untouched.
    tree.write("f", b"new", None).unwrap();
    assert_eq!(fs::read(outside.join("victim")).unwrap(), b"keep");
    assert_eq!(fs::read(d.join("f")).unwrap(), b"new");
    assert!(tree.write("dir/x", b"no", None).is_err());
    assert!(tree.read("dir/victim", 10).is_err());
    assert!(!outside.join("x").exists());
    // A new file in new folders; no temp file is left; the exec bit is honoured.
    tree.write("p/q/r.sh", b"#!/bin/sh", Some(true)).unwrap();
    let names: Vec<_> = tree
        .read_dir("p/q")
        .unwrap()
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(names, ["r.sh"]);
    assert_eq!(tree.stat("p/q/r.sh").unwrap().mode & 0o100, 0o100);
    // A staged write dropped uncommitted leaves nothing behind.
    drop(tree.stage("p/q/z").unwrap());
    assert_eq!(fs::read_dir(d.join("p/q")).unwrap().count(), 1);
    tree.remove("p/q/r.sh").unwrap();
    tree.remove("p/q/r.sh").unwrap();
    assert!(tree.read(".git/config", 9).is_err());
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_fifo_is_refused_without_blocking_and_a_listing_never_follows_a_link() {
    let d = temp("list");
    let outside = temp("list-out");
    fs::create_dir_all(d.join("src")).unwrap();
    fs::write(d.join("b.txt"), "xyz").unwrap();
    fs::create_dir_all(d.join("node_modules")).unwrap();
    symlink(&outside, d.join("link")).unwrap();
    assert!(
        Proc::new("mkfifo")
            .arg(d.join("pipe"))
            .status()
            .unwrap()
            .success(),
        "mkfifo"
    );
    let tree = Tree::open(&d).unwrap();
    assert!(tree.read("pipe", 10).is_err());
    let (entries, truncated) = tree.list_folder("").unwrap();
    let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.dir)).collect();
    assert_eq!(
        names,
        [
            ("src", true),
            ("b.txt", false),
            ("link", false),
            ("pipe", false)
        ]
    );
    assert!(!truncated);
    assert!(tree.list_folder("link").is_err());
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn a_revert_goes_through_the_tree_and_changes_nothing_on_a_conflict() {
    let d = temp("revert");
    let tree = Tree::open(&d).unwrap();
    tree.write("x.rs", b"x a y", None).unwrap();
    let done = tree.revert(&d, "x.rs", &[edit("B", "a")], false).unwrap();
    assert_eq!(done, RevertResult::Reverted);
    assert_eq!(fs::read_to_string(d.join("x.rs")).unwrap(), "x B y");
    let moved = tree.revert(&d, "x.rs", &[edit("1", "zzz")], false).unwrap();
    assert_eq!(moved, RevertResult::Conflict);
    assert_eq!(fs::read_to_string(d.join("x.rs")).unwrap(), "x B y");
    tree.write("n.txt", b"hello", None).unwrap();
    let gone = tree
        .revert(&d, "n.txt", &[edit("", "hello")], false)
        .unwrap();
    assert_eq!(gone, RevertResult::Deleted);
    assert!(!d.join("n.txt").exists());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn edits_are_undone_newest_first_and_only_when_the_text_is_still_there() {
    let edits = [edit("B", "B2"), edit("a", "B")];
    let got = reverse(Some("x B2 y".into()), &edits, false, || None);
    assert_eq!(
        got,
        Ok(Reversal::Content("x a y".into(), RevertResult::Reverted))
    );
    let moved = reverse(Some("x other y".into()), &edits, false, || None);
    assert_eq!(moved.unwrap_err().0, RevertResult::Conflict);
    let w = [edit("", "hello")];
    assert_eq!(
        reverse(Some("hello".into()), &w, false, || None),
        Ok(Reversal::Delete)
    );
    let none = reverse(Some("a".into()), &[], false, || None);
    assert_eq!(none.unwrap_err().0, RevertResult::Impossible);
}
