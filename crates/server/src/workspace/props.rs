//! Property tests (spec 11): a sync round trip reproduces a tree exactly, and the refusal cases
//! (symlink escape, `..`, case collision, `.git`, secrets) never get through, over many random
//! trees from a fixed seed (no new dependency: a small xorshift).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::path::Path;

use ainkrad_proto::v2::EntryKind;

use super::fs::{Tree, check_path};
use super::manifest::{Entries, Memo, apply, case_collisions, diff, link_ok, scan, tree_hash};
use super::rules::{Rules, has_git, is_secret};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, of: &[&'a str]) -> &'a str {
        of[self.below(of.len())]
    }
}

fn temp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ainkrad-props-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

const NAMES: &[&str] = &[
    "a",
    "b",
    "src",
    "lib.rs",
    "x.txt",
    "Makefile",
    ".env",
    "k.pem",
    "target",
    ".git",
    ".GIT",
    "node_modules",
    "README",
    "readme",
    "deep",
];

/// A random tree under `root`: files, folders, links that stay inside and links that do not.
fn grow(root: &Path, rng: &mut Rng) {
    for _ in 0..40 {
        let depth = 1 + rng.below(3);
        let parts: Vec<&str> = (0..depth).map(|_| rng.pick(NAMES)).collect();
        let rel = parts.join("/");
        // Never through a link this tree already holds: a write or a folder made through one
        // would land outside `root` (or block on whatever it names).
        let through_link = (1..=parts.len()).any(|n| {
            fs::symlink_metadata(root.join(parts[..n].join("/")))
                .is_ok_and(|m| m.file_type().is_symlink())
        });
        if through_link {
            continue;
        }
        let p = root.join(&rel);
        if let Some(parent) = p.parent()
            && fs::create_dir_all(parent).is_err()
        {
            continue;
        }
        match rng.below(6) {
            0 => {
                let _ = symlink("../../outside", &p);
            }
            1 => {
                let _ = symlink("/etc/passwd", &p);
            }
            2 => {
                let _ = symlink(rng.pick(NAMES), &p);
            }
            _ => {
                let body = vec![rng.below(251) as u8; rng.below(3000)];
                let _ = fs::write(&p, body);
            }
        }
    }
}

fn scan_of(root: &Path, rules: &Rules) -> Entries {
    let tree = Tree::open(root).unwrap();
    scan(&tree, rules, &mut Memo::default(), i64::MAX / 2)
        .unwrap()
        .entries
}

/// What a runner does with a push: receive each put file, hash it, rename it in; delete the rest.
fn receive(src: &Tree, dst: &Tree, from: &Entries, to: &Entries) {
    let delta = diff(from, to);
    // Deletes first: a folder that becomes a file (or the reverse) needs the old one gone.
    for p in &delta.delete {
        dst.remove(p).unwrap();
    }
    for e in &delta.put {
        match e.kind {
            EntryKind::File => {
                let mut f = src.open_file(&e.path).unwrap();
                let mut s = dst.stage(&e.path).unwrap();
                std::io::copy(&mut f, &mut s.file).unwrap();
                s.file.flush().unwrap();
                s.commit(Some(e.exec)).unwrap();
            }
            EntryKind::Symlink => dst.symlink(&e.path, e.link.as_deref().unwrap()).unwrap(),
            EntryKind::Unknown => unreachable!(),
        }
    }
}

#[test]
fn a_round_trip_reproduces_any_tree_and_a_second_pass_changes_nothing() {
    let rules = Rules::default();
    for seed in 1..=25u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let (a, b) = (temp(&format!("a{seed}")), temp(&format!("b{seed}")));
        let mut have = Entries::new();
        for round in 0..3 {
            grow(&a, &mut rng);
            let want = scan_of(&a, &rules);
            let (src, dst) = (Tree::open(&a).unwrap(), Tree::open(&b).unwrap());
            receive(&src, &dst, &have, &want);
            have = apply(&have, &diff(&have, &want));
            let got = scan_of(&b, &rules);
            assert_eq!(
                tree_hash(&got),
                tree_hash(&want),
                "seed {seed} round {round}"
            );
            assert_eq!(got, want, "seed {seed} round {round}");
            assert!(diff(&got, &want).put.is_empty() && diff(&got, &want).delete.is_empty());
        }
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }
}

#[test]
fn no_scan_ever_lists_git_a_secret_an_escaping_link_or_a_bad_path() {
    let rules = Rules::default();
    for seed in 1..=40u64 {
        let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let d = temp(&format!("refuse{seed}"));
        grow(&d, &mut rng);
        let tree = Tree::open(&d).unwrap();
        let s = scan(&tree, &rules, &mut Memo::default(), i64::MAX / 2).unwrap();
        for (p, e) in &s.entries {
            assert!(check_path(p).is_ok(), "{p}");
            assert!(!has_git(p) && !is_secret(p), "{p}");
            assert!(rules.sync_in(p).is_none(), "{p}");
            if e.kind == EntryKind::Symlink {
                assert!(link_ok(p, e.link.as_deref().unwrap()), "{p}");
            }
            assert!(!p.split('/').any(|c| c == ".." || c == "." || c.is_empty()));
        }
        let _ = fs::remove_dir_all(&d);
    }
}

#[test]
fn a_case_collision_is_always_found_and_a_clean_tree_never_flagged() {
    let mut rng = Rng(77);
    for _ in 0..200 {
        let n = 2 + rng.below(6);
        let paths: Vec<String> = (0..n)
            .map(|_| {
                let a = rng.pick(&["a", "A", "b", "dir", "Dir"]);
                let b = rng.pick(&["x", "X", "y"]);
                format!("{a}/{b}")
            })
            .collect();
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut want = false;
        for p in &paths {
            // Two different spellings of one folder or file, folded.
            for (i, _) in p.match_indices('/').chain(std::iter::once((p.len(), "/"))) {
                let prefix = &p[..i];
                if let Some(first) = seen.insert(prefix.to_lowercase(), prefix.to_owned()) {
                    want |= first != prefix;
                    seen.insert(prefix.to_lowercase(), first);
                }
            }
        }
        let got = !case_collisions(paths.iter().map(String::as_str)).is_empty();
        assert_eq!(got, want, "{paths:?}");
    }
}

#[test]
fn dotdot_dot_git_and_absolute_paths_are_refused_wherever_they_sit_in_a_path() {
    let mut rng = Rng(5);
    let bad = ["..", ".", ".git", ".GiT", "", "a\0b", "a\\b"];
    for _ in 0..500 {
        let mut parts: Vec<String> = (0..1 + rng.below(4))
            .map(|_| rng.pick(NAMES).replace(".GIT", "x").replace(".git", "g"))
            .collect();
        let at = rng.below(parts.len() + 1);
        parts.insert(at, rng.pick(&bad).to_owned());
        let p = parts.join("/");
        assert!(check_path(&p).is_err(), "{p:?}");
        assert!(check_path(&format!("/{}", parts[0])).is_err());
    }
}
