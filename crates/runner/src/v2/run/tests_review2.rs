//! Round-2 security review fixes (PR #297): the egress marker the runner trusts, and what a run's
//! checkout must be before it is bundled.

use std::process::Command;
use std::time::{Duration, SystemTime};

use super::*;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("v2run-r2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A committed git repo at `dir`.
fn repo(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("README"), "x").unwrap();
    for args in [
        &["init", "-q"][..],
        &["add", "-A"],
        &["commit", "-q", "-m", "x"],
    ] {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }
}

#[test]
fn the_egress_block_counts_only_while_roots_marker_is_fresh() {
    assert_eq!(EGRESS_MARKER, "/run/ainkrad-run-egress.ok");
    let d = scratch("egress");
    let m = d.join("ok");
    let before = SystemTime::now();
    assert!(!egress_fresh(&m, before), "no marker, no egress block");
    std::fs::write(&m, "").unwrap();
    let now = SystemTime::now();
    assert!(egress_fresh(&m, now));
    assert!(egress_fresh(&m, now + Duration::from_secs(60)));
    assert!(
        !egress_fresh(&m, now + Duration::from_secs(600)),
        "a stale marker: nft has been failing"
    );
    assert!(
        !egress_fresh(&m, now - Duration::from_secs(600)),
        "a marker from the future"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_checkout_is_a_plain_repo_inside_its_own_projects_root() {
    let base = scratch("checkouts");
    let root = base.join("work");
    let mine = root.join("projects/7");
    let theirs = root.join("projects/8");
    repo(&mine.join("r1/web"));
    repo(&theirs.join("r2/web"));
    let ok = checkout_dir(&root, 7, mine.join("r1/web").to_str().unwrap()).unwrap();
    assert_eq!(ok, mine.canonicalize().unwrap().join("r1/web/.git"));

    // Outside the project's own root.
    std::os::unix::fs::symlink(theirs.join("r2/web"), mine.join("link")).unwrap();
    for bad in [
        theirs.join("r2/web"),
        mine.join("link"),
        mine.join("r1/web/../../../8/r2/web"),
        mine.clone(),
        root.clone(),
        PathBuf::from("/etc"),
        mine.join("missing"),
    ] {
        assert!(
            checkout_dir(&root, 7, bad.to_str().unwrap()).is_err(),
            "{}",
            bad.display()
        );
    }
    // A project with no checkout root here at all.
    assert!(checkout_dir(&root, 9, mine.join("r1/web").to_str().unwrap()).is_err());

    // Inside the root, but git would read another repo.
    let other_git = theirs.join("r2/web/.git");
    let sym = mine.join("sym");
    std::fs::create_dir_all(&sym).unwrap();
    std::os::unix::fs::symlink(&other_git, sym.join(".git")).unwrap();
    let file = mine.join("file");
    std::fs::create_dir_all(&file).unwrap();
    std::fs::write(
        file.join(".git"),
        format!("gitdir: {}\n", other_git.display()),
    )
    .unwrap();
    let objs = mine.join("objs");
    repo(&objs);
    std::fs::remove_dir_all(objs.join(".git/objects")).unwrap();
    std::os::unix::fs::symlink(other_git.join("objects"), objs.join(".git/objects")).unwrap();
    let alt = mine.join("alt");
    repo(&alt);
    std::fs::create_dir_all(alt.join(".git/objects/info")).unwrap();
    std::fs::write(
        alt.join(".git/objects/info/alternates"),
        format!("{}\n", other_git.join("objects").display()),
    )
    .unwrap();
    let common = mine.join("common");
    repo(&common);
    std::fs::write(
        common.join(".git/commondir"),
        format!("{}\n", other_git.display()),
    )
    .unwrap();
    for (d, why) in [
        (&sym, "plain directory"),
        (&file, "plain directory"),
        (&objs, "plain directory"),
        (&alt, "alternates"),
        (&common, "commondir"),
    ] {
        let e = checkout_dir(&root, 7, d.to_str().unwrap()).unwrap_err();
        assert!(e.contains(why), "{}: {e}", d.display());
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn a_checkout_is_bundled_from_its_named_git_dir() {
    let base = scratch("bundle");
    let root = base.join("work");
    let web = root.join("projects/7/r1/web");
    repo(&web);
    let git = checkout_dir(&root, 7, web.to_str().unwrap()).unwrap();
    let (path, len) = bundle(&git, &base.join("b")).await.unwrap();
    assert!(len > 0 && path.exists());
    let _ = std::fs::remove_dir_all(&base);
}
