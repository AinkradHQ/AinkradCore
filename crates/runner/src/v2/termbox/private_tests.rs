//! The private-root sandbox (E6-1): path escapes, symlinks, and on macOS a real Seatbelt run.

use super::*;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("apr-priv-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

#[test]
fn a_sandbox_user_cannot_be_a_path() {
    let base = tmp("user");
    for bad in [
        "",
        "..",
        "../x",
        "a/b",
        "A",
        "x y",
        ".hidden",
        &"a".repeat(33),
    ] {
        assert!(sandbox_home(&base.join("sb"), bad).is_err(), "{bad:?}");
    }
    let h = sandbox_home(&base.join("sb"), "u-1").unwrap();
    assert_eq!(h, base.join("sb/u-1"));
    // Persistent: the same home again, not a new one.
    std::fs::write(h.join("keep"), "x").unwrap();
    assert!(
        sandbox_home(&base.join("sb"), "u-1")
            .unwrap()
            .join("keep")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_symlinked_home_or_base_is_refused() {
    let base = tmp("link");
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(base.join("sb")).unwrap();
    std::os::unix::fs::symlink(&outside, base.join("sb/evil")).unwrap();
    assert!(
        sandbox_home(&base.join("sb"), "evil")
            .unwrap_err()
            .contains("symlink")
    );
    std::os::unix::fs::symlink(&outside, base.join("sb2")).unwrap();
    assert!(
        sandbox_home(&base.join("sb2"), "u")
            .unwrap_err()
            .contains("symlink")
    );
    assert!(
        std::fs::read_dir(&outside).unwrap().next().is_none(),
        "nothing created outside"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_folder_that_escapes_or_overlaps_is_refused() {
    let base = tmp("folder");
    let sb = base.join("state/sandbox");
    std::fs::create_dir_all(sb.join("other")).unwrap();
    let state = base.join("state");
    let ok = base.join("state/agents/s1");
    std::fs::create_dir_all(&ok).unwrap();
    let hidden = vec![state.clone()];
    let sbc = sb.canonicalize().unwrap();
    // A session folder inside the hidden state is fine: it holds no hidden path itself.
    assert_eq!(check_folder(&ok, &sbc, &hidden).unwrap(), ok);
    // `..` and a symlink out are resolved first, so they land on what they really are.
    let up = ok.join("../../sandbox/other");
    assert!(
        check_folder(&up, &sbc, &hidden)
            .unwrap_err()
            .contains("overlaps")
    );
    std::os::unix::fs::symlink(sb.join("other"), ok.join("jump")).unwrap();
    assert!(check_folder(&ok.join("jump"), &sbc, &hidden).is_err());
    // The state, a folder holding it, the sandbox dir, and the root.
    for bad in [
        &state,
        &base,
        &sb,
        &PathBuf::from("/"),
        &PathBuf::from("/usr/bin"),
    ] {
        assert!(check_folder(bad, &sbc, &hidden).is_err(), "{bad:?}");
    }
    assert!(check_folder(&base.join("missing"), &sbc, &hidden).is_err());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn only_the_home_and_the_named_folder_are_writable() {
    let base = tmp("argv");
    let home = sandbox_home(&base.join("sb"), "u").unwrap();
    let folder = base.join("proj");
    std::fs::create_dir_all(&folder).unwrap();
    let go = |f: Option<&Path>| wrap_private(&home, f, "/bin/sh", &["-i".to_owned()], &Net::Host);
    assert!(go(None).is_ok());
    let b = go(Some(&folder)).unwrap();
    assert_eq!(b.cwd, folder.to_string_lossy());
    assert_eq!(b.args[b.args.len() - 2..], ["/bin/sh", "-i"]);
    if cfg!(target_os = "linux") {
        let writable: Vec<&str> = b
            .args
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| w[2].as_str())
            .collect();
        assert_eq!(writable, [BOX_HOME, folder.to_str().unwrap()]);
        // The host root and the runner's state are never bound.
        assert!(!b.args.windows(3).any(|w| w[0] == "--bind" && w[1] == "/"));
        assert!(b.args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]));
        assert!(b.args.contains(&"--disable-userns".to_owned()));
    } else {
        let p = &b.args[1];
        assert!(p.starts_with("(version 1)\n(deny default)"), "{p}");
        assert!(!p.contains("(allow default)"));
        let h = home.to_str().unwrap();
        assert!(p.contains(&format!("(allow file-read* file-write* (subpath \"{h}\"))")));
        assert!(b.env.iter().any(|(k, v)| k == "TMPDIR" && v.starts_with(h)));
    }
    // A program outside the provided system directories, or an option, is refused.
    for bad in ["/tmp/evil", "/Users/x/sh", "-f", "sh", "/usr/../tmp/x"] {
        assert!(
            wrap_private(&home, None, bad, &[], &Net::Host).is_err(),
            "{bad}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// The real thing on macOS: a file outside the home, a symlink out of it, and the host's home
/// directory are unreadable; the home is writable; the named folder is reachable and its
/// neighbour is not. (`sandbox-exec` asks for nothing.)
#[cfg(target_os = "macos")]
#[test]
fn seatbelt_denies_everything_but_the_home_and_the_folder() {
    let base = tmp("sb-real");
    let home = sandbox_home(&base.join("sb"), "u").unwrap();
    let folder = base.join("proj");
    let neighbour = base.join("neighbour");
    for d in [&folder, &neighbour] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(base.join("outside.txt"), "secret").unwrap();
    std::fs::write(folder.join("in.txt"), "ok").unwrap();
    std::fs::write(neighbour.join("n.txt"), "no").unwrap();
    std::os::unix::fs::symlink(base.join("outside.txt"), home.join("link")).unwrap();
    let run = |script: String| {
        let b = wrap_private(
            &home,
            Some(&folder),
            "/bin/sh",
            &["-c".to_owned(), script],
            &Net::Host,
        )
        .unwrap();
        let o = Command::new(&b.launcher)
            .args(&b.args)
            .current_dir(&b.cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let (o, n, l) = (
        base.join("outside.txt"),
        neighbour.join("n.txt"),
        home.join("link"),
    );
    let out = run(format!(
        "cat {} || echo OUT-DENIED; cat {} || echo NEIGHBOUR-DENIED; cat {} || echo LINK-DENIED; \
         echo w > {}/w && echo HOME-WRITE; cat in.txt; ls /Users || echo USERS-DENIED",
        o.display(),
        n.display(),
        l.display(),
        home.display()
    ));
    for want in [
        "OUT-DENIED",
        "NEIGHBOUR-DENIED",
        "LINK-DENIED",
        "HOME-WRITE",
        "ok",
        "USERS-DENIED",
    ] {
        assert!(out.contains(want), "{want} missing in {out}");
    }
    assert!(!out.contains("secret") && !out.contains("no\n"));
    let _ = std::fs::remove_dir_all(&base);
}
