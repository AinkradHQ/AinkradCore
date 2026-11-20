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
        project: 1,
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
         case \"$*\" in *for-each-ref*) exit 0 ;; esac\n\
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
    std::fs::write(m.dir(7).join(MARKER), t.key()).unwrap();
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

#[tokio::test]
async fn a_commit_the_remote_dropped_is_not_kept_after_the_next_fetch() {
    let dir = tmp("gc");
    let (remote, old) = remote(&dir);
    let m = Mirrors::new(dir.join("mirrors"));
    assert_eq!(m.sync(&target(&remote), None).await.unwrap(), old);
    // A force push: the old commit is replaced by an amended one.
    git(&remote, &["commit", "-q", "--amend", "-m", "rewritten"]);
    let new = git(&remote, &["rev-parse", "HEAD"]);
    assert_ne!(old, new);
    assert_eq!(m.sync(&target(&remote), None).await.unwrap(), new);
    let dropped = std::process::Command::new("git")
        .args(["cat-file", "-e", &old])
        .current_dir(m.dir(7))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(
        !dropped.success(),
        "the dropped commit is still in the copy"
    );
    // A plain fast-forward keeps its history (and needs no collection).
    std::fs::write(remote.join("c.txt"), "c").unwrap();
    git(&remote, &["add", "."]);
    git(&remote, &["commit", "-q", "-m", "three"]);
    let third = git(&remote, &["rev-parse", "HEAD"]);
    assert_eq!(m.sync(&target(&remote), None).await.unwrap(), third);
    git(&m.dir(7), &["cat-file", "-e", &new]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_copy_made_from_another_remote_is_never_reused() {
    let dir = tmp("recycled");
    let (remote, old) = remote(&dir);
    let m = Mirrors::new(dir.join("mirrors"));
    m.sync(&target(&remote), None).await.unwrap();
    assert!(m.ready(7, &target(&remote).key()).is_ok());
    // The same remote under another project (a recycled id) is not this copy either.
    assert!(m.ready(7, &key(2, remote.to_str().unwrap())).is_err());
    // The same id, another remote that cannot be reached: nothing of the old repo is served.
    let other = dir.join("nowhere");
    assert!(m.sync(&target(&other), None).await.is_err());
    assert!(!m.dir(7).exists(), "the old copy was kept");
    assert_eq!(m.ready(7, &target(&other).key()), Err(ServeError::NotReady));
    // Another remote that works: its own objects only.
    let dir2 = tmp("recycled2");
    let (remote2, _) = self::remote(&dir2);
    git(
        &remote2,
        &[
            "commit",
            "-q",
            "--amend",
            "--allow-empty",
            "-m",
            "another root",
        ],
    );
    let new = git(&remote2, &["rev-parse", "HEAD"]);
    assert_eq!(m.sync(&target(&remote2), None).await.unwrap(), new);
    let missing = std::process::Command::new("git")
        .args(["cat-file", "-e", &old])
        .current_dir(m.dir(7))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(
        !missing.success(),
        "the old repo's commit is in the new copy"
    );
    assert_eq!(
        m.ready(7, &target(&remote).key()),
        Err(ServeError::NotReady)
    );
    // `forget` removes the copy.
    m.forget(7).await;
    assert!(!m.dir(7).exists());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[tokio::test]
async fn ssh_runs_only_when_the_mirrors_path_can_go_into_the_ssh_command() {
    let t = |dir: &Path| {
        let mut t = target(dir);
        t.remote = "ssh://git@127.0.0.1:9/x.git".into();
        t
    };
    // A path with a space cannot be given to `sh -c` whole: ssh is not allowed at all, so
    // nothing reads the Core user's own ssh config or keys.
    let bad = tmp("a b");
    let m = Mirrors::new(bad.join("mirrors"));
    let err = m.sync(&t(&bad), None).await.unwrap_err();
    assert!(err.contains("not allowed"), "{err}");
    // Control: a plain path does reach ssh (which cannot connect to that port).
    let good = tmp("plain");
    let m = Mirrors::new(good.join("mirrors"));
    let err = m.sync(&t(&good), None).await.unwrap_err();
    assert!(!err.contains("not allowed"), "{err}");
    let _ = std::fs::remove_dir_all(&bad);
    let _ = std::fs::remove_dir_all(&good);
}

#[tokio::test]
async fn a_gc_that_did_not_run_is_made_up_at_the_next_fetch() {
    let dir = tmp("gcflag");
    let (remote, old) = remote(&dir);
    let m = Mirrors::new(dir.join("mirrors"));
    m.sync(&target(&remote), None).await.unwrap();
    git(&remote, &["commit", "-q", "--amend", "-m", "rewritten"]);
    // As if the collection after this fetch had failed: the flag is left behind.
    let _ = std::fs::write(m.dir(7).join(GC_FLAG), "");
    let new = git(&remote, &["rev-parse", "HEAD"]);
    m.sync(&target(&remote), None).await.unwrap();
    let kept = std::process::Command::new("git")
        .args(["cat-file", "-e", &old])
        .current_dir(m.dir(7))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(!kept.success());
    assert!(!m.dir(7).join(GC_FLAG).exists(), "cleared once collected");
    // Nothing dropped and nothing owed: the flag does not stay.
    m.sync(&target(&remote), None).await.unwrap();
    assert!(!m.dir(7).join(GC_FLAG).exists());
    assert_eq!(git(&m.dir(7), &["rev-parse", "refs/heads/main"]), new);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_fetch_is_sorted_into_a_reason_a_person_can_act_on() {
    let gh = "https://github.com/acme/web.git";
    let prompt =
        "fatal: could not read Username for 'https://github.com': terminal prompts disabled";
    // Private on GitHub with no connection covering it: connect GitHub.
    assert_eq!(classify(prompt, gh, false), Reason::NeedsGithub);
    assert_eq!(
        classify("remote: Repository not found.", gh, false),
        Reason::NeedsGithub
    );
    // With a token the same words mean the token is wrong or cannot see it.
    assert_eq!(classify(prompt, gh, true), Reason::AuthFailed);
    assert_eq!(
        classify("remote: Repository not found.", gh, true),
        Reason::NotFoundOrPrivate
    );
    // Not GitHub: no connection could have helped.
    let other = "https://git.example.com/a/b.git";
    assert_eq!(classify(prompt, other, false), Reason::AuthFailed);
    assert_eq!(
        classify("fatal: repository 'x' not found", other, false),
        Reason::NotFoundOrPrivate
    );
    assert_eq!(classify("git timed out", gh, true), Reason::Timeout);
    assert_eq!(
        classify(
            "Permission denied (publickey).",
            "git@github.com:a/b.git",
            false
        ),
        Reason::SshNotSupported
    );
    assert_eq!(classify("disk full", gh, true), Reason::Other);
    // A local path is not ssh.
    assert_eq!(classify("fatal: boom", "/tmp/x", false), Reason::Other);
    assert!(ssh_problem("ssh://git@github.com/a/b.git").is_some());
    assert!(ssh_problem("git@github.com:a/b.git").is_some());
    assert!(ssh_problem(gh).is_none());
    // The sentence carries no git text, so no token or URL, except for `Other`.
    assert!(!Reason::NeedsGithub.sentence("secret").contains("secret"));
}
