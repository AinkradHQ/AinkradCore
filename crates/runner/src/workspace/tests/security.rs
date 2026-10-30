//! Security regression tests use real git and broker delivery; transport fixtures stay local.
use super::*;
use crate::v2::agent::secrets::{Leased, deliver};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::time::Duration;

fn request() -> SessionWorkspace {
    SessionWorkspace {
        repo: "https://fixture.invalid/origin.git".into(),
        reference: "main".into(),
        branch: "agent/topic".into(),
        name: String::new(),
    }
}

fn fixture(dir: &Path) -> Workspaces {
    origin(dir);
    let mut w = workspaces(dir);
    let shim = dir.join("fixture-git");
    script(
        &shim,
        &format!(
            "exec git -c 'url.file://{}/.insteadOf=https://fixture.invalid/' \"$@\"",
            dir.display()
        ),
    );
    w.git = shim;
    w
}

#[tokio::test]
async fn generations_isolate_objects_and_cleanup_preserves_wip_without_trusting_git() {
    let dir = scratch("secure-generation");
    let w = fixture(&dir);
    let first = w
        .prepare_session("as_a", 1, &[request()], None)
        .await
        .unwrap();
    let second = w
        .prepare_session("as_a", 2, &[request()], None)
        .await
        .unwrap();
    assert!(first.join(".git/objects").is_dir());
    assert!(second.join(".git/objects").is_dir());
    assert!(!first.join(".git/objects/info/alternates").exists());
    assert!(!dir.join("work/mirrors").exists());
    let marker = dir.join("executed");
    script(
        &first.join(".git/hooks/reference-transaction"),
        &format!("touch '{}'", marker.display()),
    );
    git(
        &first,
        &[
            "config",
            "core.fsmonitor",
            &format!("touch '{}'", marker.display()),
        ],
    );
    std::fs::write(first.join("draft.txt"), "unfinished").unwrap();
    // Cleanup must never follow an agent's forged gitdir.
    std::fs::remove_dir_all(first.join(".git")).unwrap();
    std::fs::write(
        first.join(".git"),
        format!("gitdir: {}\n", dir.join("evil/worktrees/x").display()),
    )
    .unwrap();
    w.cleanup_session("as_a", 1).await.unwrap();
    w.cleanup_session("as_a", 1).await.unwrap();
    assert!(
        second.join("README.md").exists(),
        "old cleanup removed the resumed run"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("work/session-wip/as_a/1/draft.txt")).unwrap(),
        "unfinished"
    );
    assert!(!marker.exists());
    w.cleanup_session("as_a", 2).await.unwrap();
}

#[tokio::test]
async fn runner_ignores_global_config_hooks_and_old_session_config() {
    let dir = scratch("secure-config");
    let w = fixture(&dir);
    let marker = dir.join("executed");
    std::fs::create_dir_all(&w.git_home).unwrap();
    std::fs::write(w.git_home.join("config"), format!("[core]\n sshCommand = touch {}\n[credential]\n helper = !touch {}\n[url \"ext::touch {}\"]\n insteadOf = https://fixture.invalid/\n", marker.display(), marker.display(), marker.display())).unwrap();
    let first = w
        .prepare_session("as_a", 1, &[request()], None)
        .await
        .unwrap();
    let hook = first.join(".git/hooks/reference-transaction");
    script(&hook, &format!("touch '{}'", marker.display()));
    git(
        &first,
        &[
            "config",
            "core.sshCommand",
            &format!("touch '{}'", marker.display()),
        ],
    );
    let next = w
        .prepare_session("as_b", 2, &[request()], None)
        .await
        .unwrap();
    assert!(next.join("README.md").exists());
    assert!(!marker.exists());
    let command = w.command(&dir, &["status"]);
    let env = command.as_std().get_envs().collect::<Vec<_>>();
    assert!(
        env.iter().any(
            |(k, v)| *k == "GIT_CONFIG_GLOBAL" && *v == Some(std::ffi::OsStr::new("/dev/null"))
        )
    );
    let args = command
        .as_std()
        .get_args()
        .map(|v| v.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    for required in [
        "http.followRedirects=false",
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "protocol.allow=never",
        "submodule.recurse=false",
        "init.templateDir=",
    ] {
        assert!(args.iter().any(|a| a == required), "{required}");
    }
    w.cleanup_session("as_a", 1).await.unwrap();
    w.cleanup_session("as_b", 2).await.unwrap();
    assert!(!marker.exists());
}

#[tokio::test]
async fn recovery_reaps_only_orphans_and_retains_their_wip() {
    let dir = scratch("secure-recovery");
    let w = fixture(&dir);
    let live = w
        .prepare_session("as_live", 1, &[request()], None)
        .await
        .unwrap();
    let orphan = w
        .prepare_session("as_orphan", 2, &[request()], None)
        .await
        .unwrap();
    std::fs::write(orphan.join("draft"), "keep").unwrap();
    let next = workspaces(&dir);
    assert!(
        live.exists() && orphan.exists(),
        "construction must not wipe sessions"
    );
    next.recover_sessions(&["as_live".into()]);
    assert!(live.exists());
    assert!(!orphan.exists());
    assert_eq!(
        std::fs::read_to_string(dir.join("work/session-wip/as_orphan/2/draft")).unwrap(),
        "keep"
    );
}

#[tokio::test]
async fn local_transports_are_rejected_before_spawning() {
    let dir = scratch("secure-url");
    let mut w = workspaces(&dir);
    w.git = dir.join("must-not-exist");
    for repo in [
        "/absolute/repo",
        "relative/repo",
        "file:///repo",
        "http://example.com/repo",
        "git://example.com/repo",
        "ext::evil",
        "https://example.com/repo?token=secret",
    ] {
        let r = SessionWorkspace {
            repo: repo.into(),
            ..request()
        };
        let why = w.prepare_session("as_a", 1, &[r], None).await.unwrap_err();
        assert!(!why.contains("spawn"), "{repo}: {why}");
    }
    assert_ne!(repo_name("https://h/o/r"), repo_name("https://h/o_r"));
    assert_ne!(repo_name("https://h/Foo"), repo_name("https://h/foo"));
}

#[tokio::test]
async fn git_timeout_output_and_disk_caps_terminate_processes_and_do_not_lock_repo() {
    let dir = scratch("secure-limits");
    let mut w = workspaces(&dir);
    let shim = dir.join("git");
    let pidfile = dir.join("pid");
    script(
        &shim,
        &format!("echo $$ > '{}'; exec sleep 60", pidfile.display()),
    );
    w.git = shim.clone();
    w.git_timeout = Duration::from_secs(2);
    assert!(
        w.git(&dir, &["fetch"])
            .await
            .unwrap_err()
            .contains("timeout")
    );
    let pid = std::fs::read_to_string(&pidfile).unwrap();
    assert!(
        !Std::new("/bin/kill")
            .args(["-0", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    script(&shim, "exec yes huge-output");
    assert!(
        w.git(&dir, &["fetch"])
            .await
            .unwrap_err()
            .contains("output limit")
    );
    script(
        &shim,
        &format!(
            "dd if=/dev/zero of='{}/bomb' bs=1024 count=8 2>/dev/null; exec sleep 60",
            w.root.display()
        ),
    );
    w.git_size_cap = 4096;
    assert!(
        w.git(&dir, &["clone"])
            .await
            .unwrap_err()
            .contains("size limit")
    );
    std::fs::remove_file(w.root.join("bomb")).unwrap();
    // Session transfers never acquire the shared mirror lock: hold it throughout a real clone.
    let w = fixture(&dir);
    let _lock = w.lock(&w.mirror(&request().repo)).await;
    let path = tokio::time::timeout(
        Duration::from_secs(5),
        w.prepare_session("as_a", 1, &[request()], None),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(path.join("README.md").exists());
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: requires AINKRAD_TEST_RAMDIR on a verified RAM disk"
)]
async fn broker_credentials_are_host_scoped_and_clone_uses_only_helper_path() {
    let dir = scratch("secure-broker");
    // Secret files are refused outside a verified RAM filesystem, so they live in one.
    let ram = if cfg!(target_os = "linux") {
        std::path::PathBuf::from("/dev/shm")
    } else {
        std::env::var_os("AINKRAD_TEST_RAMDIR").map_or_else(std::env::temp_dir, Into::into)
    };
    let secrets = TestDir(ram.join(format!("broker-secrets-{}", std::process::id())));
    let mut delivered = deliver(
        &secrets.0,
        "as_a",
        vec![(
            "TOKEN".into(),
            Leased {
                name: "git".into(),
                delivery: "askpass".into(),
                value: "broker-token".to_owned().into(),
            },
        )],
    )
    .unwrap();
    let helper = delivered
        .git_helper(&["forge.invalid".into()])
        .unwrap()
        .unwrap();
    let query = |host: &str| {
        // Reading the script through its interpreter avoids Linux ETXTBSY when an
        // unrelated concurrent fork briefly inherited its just-closed writer fd.
        let mut child = Std::new("/bin/sh")
            .arg(&helper)
            .process_group(0)
            .arg("get")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Kill the helper group even if writing the request or an assertion panics.
        let _group = super::super::command::Group(child.id());
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("protocol=https\nhost={host}\n\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    assert!(query("forge.invalid").contains("password=broker-token"));
    for host in [
        "attacker.invalid",
        "forge.invalid.attacker.invalid",
        "forge.invalid:443",
    ] {
        assert!(query(host).is_empty(), "credential leaked to {host}");
    }
    let mut w = fixture(&dir);
    let shim = dir.join("clone-with-credential");
    let log = dir.join("argv");
    script(
        &shim,
        &format!(
            "printf '%s\\n' \"$@\" >> '{}'\nexec '{}' \"$@\"",
            log.display(),
            w.git.display()
        ),
    );
    w.git = shim;
    w.prepare_session("as_a", 1, &[request()], Some(&helper))
        .await
        .unwrap();
    let args = std::fs::read_to_string(log).unwrap();
    assert!(args.contains(helper.to_str().unwrap()));
    assert!(!args.contains("broker-token"));
    let config =
        std::fs::read_to_string(w.session_path("as_a").unwrap().join("1/.git/config")).unwrap();
    assert!(!config.contains("broker-token") && !config.contains("git-credential"));
    drop(delivered);
    assert!(!helper.exists());
}
