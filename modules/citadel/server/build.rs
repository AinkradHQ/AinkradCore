use std::process::Command;

fn main() {
    // sqlx::migrate! embeds migrations/ at compile time; rebuild when only .sql files change.
    println!("cargo:rerun-if-changed=migrations");
    // The commit `GET /api/v1/me` reports: `CITADEL_GIT_SHA` when the build sets it (a
    // release from a tarball), else git's, else none.
    println!("cargo:rerun-if-env-changed=CITADEL_GIT_SHA");
    if std::env::var_os("CITADEL_GIT_SHA").is_some() {
        return;
    }
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).output().ok()?;
        let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
        (out.status.success() && !s.is_empty()).then_some(s)
    };
    let Some(sha) = git(&["rev-parse", "--short=12", "HEAD"]) else {
        return;
    };
    println!("cargo:rustc-env=CITADEL_GIT_SHA={sha}");
    // ponytail: HEAD and its branch ref only; a commit landing via packed-refs alone keeps
    // the old sha until the next rebuild of this crate.
    for path in ["HEAD".to_owned()]
        .into_iter()
        .chain(git(&["symbolic-ref", "-q", "HEAD"]))
    {
        if let Some(p) = git(&["rev-parse", "--git-path", &path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}
