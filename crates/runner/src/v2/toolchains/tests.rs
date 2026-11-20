//! Toolchain tests: program mapping, tarball vetting, the Rust channel rule, version probes and the
//! job's mounts and environment.
use super::*;

#[test]
fn programs_map_to_the_toolchain_that_runs_them() {
    assert_eq!(tool_for("cargo"), Some("rust"));
    assert_eq!(tool_for("/usr/bin/npm"), Some("node"));
    assert_eq!(tool_for("pytest"), Some("python"));
    assert_eq!(tool_for("go"), Some("go"));
    assert_eq!(tool_for("make"), None);
}

#[test]
fn a_tarball_may_hold_inner_links_but_never_an_escape() {
    let names = "node-v22/\nnode-v22/bin/node\nnode-v22/bin/npm\n";
    let ok = "drwxr-xr-x 0/0 0 d node-v22/\n-rwxr-xr-x 0/0 9 d node-v22/bin/node\nlrwxr-xr-x 0/0 0 d node-v22/bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js\n";
    assert_eq!(unsafe_member(names, ok), None);
    let climbs = "drwxr-xr-x 0/0 0 d node-v22/\n-rwxr-xr-x 0/0 9 d node-v22/bin/node\nlrwxr-xr-x 0/0 0 d node-v22/bin/npm -> ../../../etc/passwd\n";
    assert!(unsafe_member(names, climbs).is_some());
    let absolute = "drwxr-xr-x 0/0 0 d node-v22/\n-rwxr-xr-x 0/0 9 d node-v22/bin/node\nlrwxr-xr-x 0/0 0 d node-v22/bin/npm -> /etc/passwd\n";
    assert!(unsafe_member(names, absolute).is_some());
    let hard = "drwxr-xr-x 0/0 0 d node-v22/\n-rwxr-xr-x 0/0 9 d node-v22/bin/node\nhrwxr-xr-x 0/0 0 d node-v22/bin/npm link to node-v22/bin/node\n";
    assert!(unsafe_member(names, hard).is_some());
    assert!(unsafe_member("../evil\n", "-rw-r--r-- 0/0 1 d ../evil\n").is_some());
    assert!(unsafe_member("/evil\n", "-rw-r--r-- 0/0 1 d /evil\n").is_some());
}

#[test]
fn the_projects_rust_channel_is_stable_the_pin_or_refused() {
    let dir = std::env::temp_dir().join(format!("tc-rust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    assert_eq!(check_rust_channel(&dir), Ok(()), "no file");
    let set = |text: &str| std::fs::write(dir.join("rust-toolchain.toml"), text).unwrap();
    set("[toolchain]\nchannel = \"stable\"\ncomponents = [\"clippy\"]\n");
    assert_eq!(rust_channel(&dir).as_deref(), Some("stable"));
    assert_eq!(check_rust_channel(&dir), Ok(()));
    set(&format!("[toolchain]\nchannel = '{RUST_TOOLCHAIN}'\n"));
    assert_eq!(check_rust_channel(&dir), Ok(()));
    set("[toolchain]\nchannel = \"nightly-2026-01-01\"\n");
    assert!(check_rust_channel(&dir).unwrap_err().contains("nightly"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_versions_are_read_from_their_version_lines() {
    assert_eq!(
        parse_version("Xcode 16.4\nBuild version 16F6\n", "Xcode ").as_deref(),
        Some("16.4")
    );
    assert_eq!(
        parse_version(
            "Swift version 6.1.2 (swift-6.1.2-RELEASE)\n",
            "Swift version "
        )
        .as_deref(),
        Some("6.1.2")
    );
    assert_eq!(
        parse_version("Docker version 27.0.1, build abc\n", "Docker version ").as_deref(),
        Some("27.0.1")
    );
    assert_eq!(parse_version("nothing\n", "Xcode "), None);
}

#[test]
fn a_job_sees_installs_read_only_and_its_caches_in_its_own_home() {
    let state = std::env::temp_dir().join(format!("tc-job-{}", std::process::id()));
    let tc = Toolchains::new(&state);
    let node = pin("node").unwrap();
    std::fs::create_dir_all(tc.dir(node)).unwrap();
    std::fs::write(tc.dir(node).join(".ok"), "x").unwrap();
    let got = tc.job_tools(&["node", "go"], Path::new("/h"));
    assert_eq!(got.ro, vec![tc.dir(node)], "go is not installed");
    assert_eq!(got.path, vec![tc.dir(node).join("bin")]);
    assert!(
        got.env
            .contains(&("npm_config_cache".to_owned(), "/h/npm".to_owned()))
    );
    assert_eq!(
        tc.installed().get("node").map(String::as_str),
        Some("22.22.1")
    );
    let _ = std::fs::remove_dir_all(&state);
}

/// A stand-in for rustup-init, which like the real one refuses to install unless its file is
/// named `rustup-init` (it is a multi-call binary): the name `.download` made every runner's Rust
/// install fail at once, and so every remote `cargo` job (e2e 2026-11-20).
#[tokio::test]
async fn the_rust_installer_runs_under_its_own_name_and_says_why_it_failed() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("tc-installer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let fake = "#!/bin/sh\n\
        case \"$(basename \"$0\")\" in rustup-init) ;; *) echo \"error: unknown proxy name: '$(basename \"$0\")'\" >&2; exit 1 ;; esac\n\
        mkdir -p \"$CARGO_HOME/bin\" && touch \"$CARGO_HOME/bin/cargo\"\n";
    let put = |name: &str| {
        let f = base.as_path().join(name);
        std::fs::write(&f, fake).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o700)).unwrap();
        f
    };
    let f = put(download_name(Kind::Installer));
    run_installer(&f, "1.100.0", "x86_64-unknown-linux-gnu", base.as_path())
        .await
        .unwrap();
    assert!(base.as_path().join("cargo/bin/cargo").is_file());
    // Under another name it fails, and the error carries the installer's own reason.
    let f = put(".download");
    let e = run_installer(&f, "1.100.0", "x86_64-unknown-linux-gnu", base.as_path())
        .await
        .unwrap_err();
    assert!(e.contains("unknown proxy name"), "{e}");
    let _ = std::fs::remove_dir_all(&base);
}
