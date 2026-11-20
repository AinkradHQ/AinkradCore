//! The private-root sandbox (E6-1): path escapes, symlinks, the launcher's environment, the
//! Seatbelt profile, scratch directories, and on macOS a real Seatbelt run.

use super::*;
use std::collections::BTreeMap;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("apr-priv-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

/// A spec for `/bin/sh -i` with `env`, on the host network.
fn spec<'a>(
    base: &'a Path,
    home: &'a Path,
    folder: Option<&'a Path>,
    env: &'a BTreeMap<String, String>,
    args: &'a [String],
    net: &'a Net,
) -> PrivateSpec<'a> {
    PrivateSpec {
        base,
        user: "u",
        home,
        folder,
        program: "/bin/sh",
        args,
        net,
        terminal: "t_1",
        env,
        hide: &[],
    }
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
fn a_folder_that_escapes_or_overlaps_or_holds_a_launcher_is_refused() {
    let base = tmp("folder");
    let sb = base.join("state/sandbox");
    std::fs::create_dir_all(sb.join("other")).unwrap();
    let state = base.join("state");
    let ok = base.join("state/agents/s1");
    std::fs::create_dir_all(&ok).unwrap();
    let launchers = base.join("proj/.config/systemd/user");
    std::fs::create_dir_all(&launchers).unwrap();
    let hidden = vec![state.clone(), launchers.clone()];
    let sbc = sb.canonicalize().unwrap();
    assert_eq!(check_folder(&ok, &sbc, &hidden).unwrap(), ok);
    let up = ok.join("../../sandbox/other");
    assert!(
        check_folder(&up, &sbc, &hidden)
            .unwrap_err()
            .contains("overlaps")
    );
    std::os::unix::fs::symlink(sb.join("other"), ok.join("jump")).unwrap();
    assert!(check_folder(&ok.join("jump"), &sbc, &hidden).is_err());
    // L2: a project folder that carries a launcher directory is not mounted.
    assert!(
        check_folder(&base.join("proj"), &sbc, &hidden)
            .unwrap_err()
            .contains("hides")
    );
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

/// M2: a folder swapped for a link, or for another directory, between the check and the launch is
/// caught by the re-check.
#[test]
fn a_folder_swapped_after_the_check_is_caught() {
    let base = tmp("swap");
    let f = base.join("proj");
    std::fs::create_dir_all(&f).unwrap();
    let f = f.canonicalize().unwrap();
    let was = identity(&f).unwrap();
    assert!(recheck_folder(&f, was).is_ok());
    // Another directory at the same path.
    std::fs::remove_dir_all(&f).unwrap();
    std::fs::create_dir_all(&f).unwrap();
    // (An inode can be reused at once on some filesystems; a link is certain.)
    std::fs::remove_dir_all(&f).unwrap();
    std::fs::create_dir_all(base.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(base.join("elsewhere"), &f).unwrap();
    assert!(
        recheck_folder(&f, was)
            .unwrap_err()
            .contains("changed while")
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn only_the_home_and_the_named_folder_are_writable() {
    let base = tmp("argv");
    let sb = base.join("sb");
    let home = sandbox_home(&sb, "u").unwrap();
    let sbc = sb.canonicalize().unwrap();
    let folder = base.join("proj");
    std::fs::create_dir_all(&folder).unwrap();
    let (args, env) = (vec!["-i".to_owned()], BTreeMap::new());
    let go = |f: Option<&Path>| wrap_private(&spec(&sbc, &home, f, &env, &args, &Net::Host));
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
        assert!(!b.args.windows(3).any(|w| w[0] == "--bind" && w[1] == "/"));
        assert!(b.args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]));
        for f in ["--disable-userns", "--clearenv", "--unshare-pid"] {
            assert!(b.args.contains(&f.to_owned()), "{f}");
        }
        // The runner's installer configuration is hidden even though /etc is bound.
        if Path::new("/etc/ainkrad-runner").is_dir() {
            assert!(
                b.args
                    .windows(2)
                    .any(|w| w == ["--tmpfs", "/etc/ainkrad-runner"])
            );
        }
    } else {
        let p = &b.args[1];
        assert!(p.starts_with("(version 1)\n(deny default)"), "{p}");
        assert!(!p.contains("(allow default)"));
    }
    for bad in ["/tmp/evil", "/Users/x/sh", "-f", "sh", "/usr/../tmp/x"] {
        let mut s = spec(&sbc, &home, None, &env, &args, &Net::Host);
        s.program = bad;
        assert!(wrap_private(&s).is_err(), "{bad}");
    }
    let mut s = spec(&sbc, &home, None, &env, &args, &Net::Host);
    s.terminal = "../x";
    assert!(wrap_private(&s).is_err());
    let _ = std::fs::remove_dir_all(&base);
}

/// C2: what a client put in the shell's environment (`LD_PRELOAD` included, were it ever let
/// through) reaches the shell only as launcher options, and the launcher's own environment is the
/// fixed clean one.
#[test]
fn the_launcher_gets_a_clean_environment_and_the_shell_gets_the_clients() {
    let base = tmp("env");
    let sb = base.join("sb");
    let home = sandbox_home(&sb, "u").unwrap();
    let sbc = sb.canonicalize().unwrap();
    let env = BTreeMap::from([
        ("EDITOR".to_owned(), "vi".to_owned()),
        ("LD_PRELOAD".to_owned(), "/tmp/evil.so".to_owned()),
    ]);
    let b = wrap_private(&spec(&sbc, &home, None, &env, &[], &Net::Host)).unwrap();
    assert_eq!(b.env, [("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
    if cfg!(target_os = "linux") {
        let set = |k: &str, v: &str| {
            b.args
                .windows(3)
                .any(|w| w[0] == "--setenv" && w[1] == k && w[2] == v)
        };
        assert!(set("EDITOR", "vi") && set("HOME", BOX_HOME));
        let clear = b.args.iter().position(|a| a == "--clearenv").unwrap();
        let first = b.args.iter().position(|a| a == "--setenv").unwrap();
        assert!(clear < first);
    } else {
        assert!(b.args.contains(&"EDITOR=vi".to_owned()));
        let at = b.args.iter().position(|a| a == "/usr/bin/env").unwrap();
        assert_eq!(b.args[at - 1], "--");
    }
    // The host-view wrapper does the same.
    let mut args: Vec<String> = if cfg!(target_os = "macos") {
        ["-p", "(version 1)", "--", "/bin/sh"]
            .map(str::to_owned)
            .to_vec()
    } else {
        ["--bind", "/", "/", "--chdir", "/", "--", "/bin/sh"]
            .map(str::to_owned)
            .to_vec()
    };
    inject_env(&mut args, &env);
    assert!(args.iter().any(|a| a == "EDITOR=vi" || a == "EDITOR"));
    assert_eq!(args.last().unwrap(), "/bin/sh");
    assert_eq!(
        launcher_env(),
        BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())])
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// H1, H2, M5: the profile names devices one by one, allows IP only (no unix sockets but the
/// name service's), names the Mach services and sysctls, and shuts what a shell must not touch.
#[test]
fn the_seatbelt_profile_is_an_allowlist() {
    let home = PathBuf::from("/private/tmp/h");
    let scratch = PathBuf::from("/private/tmp/s/u/t");
    let hide = [PathBuf::from("/private/etc/ainkrad-runner")];
    let p = seatbelt_profile(&home, None, &scratch, &Net::Host, &hide);
    assert!(p.starts_with("(version 1)\n(deny default)\n"));
    // H1: no whole /dev, no terminal devices to write.
    assert!(!p.contains("(subpath \"/dev\")"), "{p}");
    assert!(!p.contains("file-write* (literal \"/dev/null\") (literal \"/dev/tty\") (regex"));
    for d in [
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        assert!(p.contains(&format!("(literal \"{d}\")")), "{d}");
    }
    assert!(
        !p.contains("file-write* (regex"),
        "no write to another ttys"
    );
    // H2: network is by IP, localhost denied, not `network*`.
    assert!(!p.contains("(allow network*)"));
    assert!(p.contains("(allow network-outbound (remote ip \"*:*\")"));
    assert!(p.contains("(deny network-outbound (remote ip \"localhost:*\"))"));
    // M5: explicit lists, none of the open forms, no pasteboard or launch services.
    assert!(!p.contains("(allow mach-lookup)\n") && !p.contains("(allow sysctl-read)\n"));
    assert!(p.contains("(allow mach-lookup (global-name"));
    assert!(p.contains("(allow sysctl-read (sysctl-name"));
    for no in [
        "pasteboard",
        "launchservicesd",
        "kern.procargs2",
        "kern.proc.",
    ] {
        assert!(!p.contains(no), "{no}");
    }
    // The scratch directory and the home are open; the runner's configuration is not.
    assert!(p.contains("(allow file-read* file-write* (subpath \"/private/tmp/s/u/t\"))"));
    // Seatbelt's last matching rule wins: the hidden path is denied BEFORE the allows, so the home,
    // the scratch and a session folder inside the hidden state are let back in.
    let deny = p
        .find("(deny file-read* file-write* (subpath \"/private/etc/ainkrad-runner\"))\n")
        .expect("the hidden path is denied");
    let allow = p
        .find("(allow file-read* file-write* (subpath \"/private/tmp/s/u/t\"))")
        .unwrap();
    assert!(deny < allow, "the denies come first");
    // A locked network has no network rules at all.
    let none = seatbelt_profile(&home, None, &scratch, &Net::None, &[]);
    assert!(!none.contains("network-outbound (remote"), "{none}");
}

/// C1: a terminal's scratch directory is made beside the user's home, never in it; a link in
/// the way is refused, removal never follows a link, and young or live directories stay.
#[test]
fn scratch_is_outside_the_home_and_reaping_follows_no_link() {
    let base = tmp("scratch");
    let sb = base.join("sb");
    let home = sandbox_home(&sb, "u").unwrap();
    let sbc = sb.canonicalize().unwrap();
    let d = scratch_dir(&sbc, "u", "t_1").unwrap();
    assert!(d.starts_with(sbc.join(".scratch/u")) && !d.starts_with(&home));
    // Nothing the shell writes decides where scratch lives: a link in the home changes nothing.
    std::os::unix::fs::symlink(&base, home.join(".tmp")).unwrap();
    assert!(
        scratch_dir(&sbc, "u", "t_2")
            .unwrap()
            .starts_with(sbc.join(".scratch"))
    );
    assert!(scratch_dir(&sbc, "u", "../x").is_err());

    let victim = base.join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("precious"), "x").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let age = |p: &Path| std::fs::File::open(p).unwrap().set_modified(old).unwrap();
    // A gone terminal's directory holding a link to a directory and one to a file.
    let gone = scratch_dir(&sbc, "u", "gone").unwrap();
    std::os::unix::fs::symlink(&victim, gone.join("dirlink")).unwrap();
    std::os::unix::fs::symlink(victim.join("precious"), gone.join("filelink")).unwrap();
    age(&gone);
    let live = scratch_dir(&sbc, "u", "live").unwrap();
    age(&live);
    let young = scratch_dir(&sbc, "u", "young").unwrap();
    let keep = std::collections::HashSet::from(["live".to_owned()]);
    reap_scratch(&sbc, &keep);
    assert!(!gone.exists(), "the gone one is removed");
    assert!(victim.join("precious").exists(), "no link was followed");
    assert!(live.exists() && young.exists());

    // A symlinked `.scratch` (or user directory) is not entered at all.
    let other = tmp("scratch2");
    let target = other.join("t");
    std::fs::create_dir_all(target.join("u/gone")).unwrap();
    age(&target.join("u/gone"));
    std::os::unix::fs::symlink(&target, other.join(".scratch")).unwrap();
    reap_scratch(&other, &std::collections::HashSet::new());
    assert!(target.join("u/gone").exists());
    assert!(scratch_dir(&other, "u", "t_1").is_err());
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&other);
}

/// The real thing on macOS: a file outside the home, a symlink out of it, the host's home
/// directory, `/dev`, the other terminals' ttys are unreadable or unwritable; the home, the scratch
/// directory and the named folder are usable; its neighbour is not.
#[cfg(target_os = "macos")]
#[test]
fn seatbelt_denies_everything_but_the_home_the_scratch_and_the_folder() {
    let base = tmp("sb-real");
    let sb = base.join("sb");
    let home = sandbox_home(&sb, "u").unwrap();
    let sbc = sb.canonicalize().unwrap();
    let folder = base.join("proj");
    let neighbour = base.join("neighbour");
    for d in [&folder, &neighbour] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(base.join("outside.txt"), "secret").unwrap();
    std::fs::write(folder.join("in.txt"), "ok").unwrap();
    std::fs::write(neighbour.join("n.txt"), "no").unwrap();
    std::os::unix::fs::symlink(base.join("outside.txt"), home.join("link")).unwrap();
    let env = BTreeMap::from([("GREETING".to_owned(), "hello".to_owned())]);
    let run = |script: String| {
        let args = ["-c".to_owned(), script];
        let b = wrap_private(&spec(&sbc, &home, Some(&folder), &env, &args, &Net::Host)).unwrap();
        let o = Command::new(&b.launcher)
            .args(&b.args)
            .env_clear()
            .envs(b.env.iter().cloned())
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
         echo w > {}/w && echo HOME-WRITE; cat in.txt; ls /Users || echo USERS-DENIED; \
         ls /dev || echo DEV-DENIED; echo x > /dev/ttys000 || echo TTY-DENIED; \
         echo x > $TMPDIR/s && echo SCRATCH-WRITE; echo $GREETING; pbpaste || echo PB-DENIED",
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
        "DEV-DENIED",
        "TTY-DENIED",
        "SCRATCH-WRITE",
        "hello",
        "PB-DENIED",
    ] {
        assert!(out.contains(want), "{want} missing in {out}");
    }
    assert!(!out.contains("secret") && !out.contains("no\n"));
    let _ = std::fs::remove_dir_all(&base);
}
