//! The mirror's git side: fetching into a bare copy, the older head kept when the remote goes,
//! and a credential that never leaves the environment of the one git process.

use std::path::{Path, PathBuf};

use super::*;

const TOKEN: &str = "tok-probe-91c3d7e5a0b2";

pub(crate) fn tmp(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("mirrors-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A repo with one commit on `main`, as a remote; its path and head.
pub(crate) fn remote(dir: &Path) -> (PathBuf, String) {
    let path = dir.join("remote");
    std::fs::create_dir_all(&path).unwrap();
    git(&path, &["init", "-q"]);
    std::fs::write(path.join("a.txt"), "one").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-q", "-m", "one"]);
    let head = git(&path, &["rev-parse", "HEAD"]);
    (path, head)
}

fn target(url: &Path) -> Target {
    Target {
        id: 7,
        remote: url.to_str().unwrap().to_owned(),
        branch: "main".into(),
        owner: 1,
        active: true,
    }
}

#[tokio::test]
async fn a_fetch_makes_the_copy_and_a_later_one_updates_it() {
    let dir = tmp("fetch");
    let (remote, first) = remote(&dir);
    let m = Mirrors::new(dir.join("mirrors"));
    assert_eq!(m.sync(&target(&remote), None).await.unwrap(), first);
    assert!(m.dir(7).join("HEAD").exists() && !m.dir(7).with_extension("cloning").exists());
    // HEAD is the default branch, so a clone checks it out.
    assert_eq!(git(&m.dir(7), &["symbolic-ref", "HEAD"]), "refs/heads/main");
    // The copy holds no remote and no credential.
    assert!(
        !std::fs::read_to_string(m.dir(7).join("config"))
            .unwrap()
            .contains("remote")
    );
    std::fs::write(remote.join("b.txt"), "two").unwrap();
    git(&remote, &["add", "."]);
    git(&remote, &["commit", "-q", "-m", "two"]);
    let second = git(&remote, &["rev-parse", "HEAD"]);
    assert_eq!(m.sync(&target(&remote), None).await.unwrap(), second);
    // A clone from the copy, as a runner does.
    let clone = dir.join("clone");
    git(
        &dir,
        &[
            "clone",
            "-q",
            "--no-hardlinks",
            m.dir(7).to_str().unwrap(),
            clone.to_str().unwrap(),
        ],
    );
    assert!(clone.join("b.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_unreachable_remote_is_an_error_and_the_older_copy_stays() {
    let dir = tmp("gone");
    let (remote, head) = remote(&dir);
    let m = Mirrors::new(dir.join("mirrors"));
    assert_eq!(m.sync(&target(&remote), None).await.unwrap(), head);
    std::fs::rename(&remote, dir.join("moved")).unwrap();
    let err = m.sync(&target(&remote), None).await.unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(
        git(&m.dir(7), &["rev-parse", "refs/heads/main"]),
        head,
        "older head kept"
    );
    // A first fetch that fails leaves nothing behind.
    let m2 = Mirrors::new(dir.join("other"));
    assert!(m2.sync(&target(&remote), None).await.is_err());
    assert!(!m2.dir(7).exists() && !m2.dir(7).with_extension("cloning").exists());
    // A branch the remote lacks is named.
    let mut t = target(&dir.join("moved"));
    t.branch = "nope".into();
    assert!(
        m.sync(&t, None)
            .await
            .unwrap_err()
            .contains("no branch nope")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A git that records how it was called and then fails, printing the token the way a bad one might.
fn fake_git(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let (script, log) = (dir.join("fakegit"), dir.join("calls.log"));
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {log}\nprintf 'ENV token=%s askpass=%s\\n' \"$AINKRAD_GIT_TOKEN\" \"$GIT_ASKPASS\" >> {log}\n\
         echo \"fatal: authentication failed for $AINKRAD_GIT_TOKEN\" >&2\nexit 1\n",
        log = log.display()
    );
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script, log)
}

#[tokio::test]
async fn a_token_is_only_in_the_environment_never_argv_or_the_error() {
    let dir = tmp("token");
    let (script, log) = fake_git(&dir);
    let m = Mirrors::new(dir.join("mirrors")).with_git(script);
    let mut t = target(&dir.join("x"));
    t.remote = "https://github.com/acme/web.git".into();
    // `init` is the first call and fails; the fetch is reached by the second sync on a made dir.
    std::fs::create_dir_all(m.dir(7)).unwrap();
    std::fs::write(m.dir(7).join("HEAD"), "ref: refs/heads/main\n").unwrap();
    let err = m.sync(&t, Some(TOKEN)).await.unwrap_err();
    assert!(!err.contains(TOKEN) && err.contains("***"), "{err}");
    let calls = std::fs::read_to_string(&log).unwrap();
    for line in calls.lines().filter(|l| !l.starts_with("ENV ")) {
        assert!(!line.contains(TOKEN), "token in argv: {line}");
    }
    assert!(
        calls.contains(&format!(
            "ENV token={TOKEN} askpass={}",
            m.root.join("askpass").display()
        )),
        "{calls}"
    );
    assert!(calls.contains("https://github.com/acme/web.git"));
    // The askpass is the fixed script and holds no token.
    let askpass = std::fs::read_to_string(m.root.join("askpass")).unwrap();
    assert!(!askpass.contains(TOKEN) && askpass.contains("AINKRAD_GIT_TOKEN"));
    // Without a token, no askpass is offered at all.
    std::fs::remove_file(&log).unwrap();
    let _ = m.sync(&t, None).await;
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(calls.contains("ENV token= askpass=\n"), "{calls}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_a_plain_github_remote_gets_a_token_and_text_is_scrubbed() {
    assert_eq!(
        github_repo("https://github.com/acme/web.git").as_deref(),
        Some("acme/web")
    );
    assert_eq!(
        github_repo("HTTPS://GitHub.com/acme/web/").as_deref(),
        Some("acme/web")
    );
    for no in [
        "https://gitlab.com/acme/web.git",
        "ssh://git@github.com/acme/web.git",
        "git@github.com:acme/web.git",
        "https://github.com.evil.io/acme/web",
        "https://github.com/acme",
        "https://github.com/acme/web/extra",
    ] {
        assert_eq!(github_repo(no), None, "{no}");
    }
    assert_eq!(scrub("a\n  b  tok c", Some("tok")), "a b *** c");
    assert!(scrub(&"x".repeat(1000), None).len() <= 300);
}
