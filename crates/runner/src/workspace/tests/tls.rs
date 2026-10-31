//! The git workspace against real HTTPS servers on loopback (KAN-271): redirects, credentials by
//! host, hostile repositories, a stalled server and an oversize pack. The servers and their
//! throwaway CA come from `ainkrad-gitfixture`; the runner's git trusts that CA only through a
//! shim assigned to `Workspaces::git` in these tests (see that crate's docs). Every test also has
//! a control that shows the trap is armed, so a pass cannot be a blind spot.

use std::process::Stdio;
use std::time::{Duration, Instant};

use ainkrad_gitfixture::{Ca, Config, Server, bare_repo, git as setup_git};

use super::*;
use crate::v2::agent::secrets::{Delivered, Leased, deliver};

const TOKEN: &str = "fixture-token";

struct Rig {
    dir: TestDir,
    ca: Ca,
    served: PathBuf,
    w: Workspaces,
}

fn rig(name: &str) -> Rig {
    let dir = scratch(name);
    let served = dir.join("served");
    std::fs::create_dir_all(&served).unwrap();
    let ca = Ca::new(&dir.join("ca"));
    let mut w = workspaces(&dir);
    w.git = ca.git_shim(&dir);
    Rig { dir, ca, served, w }
}

impl Rig {
    async fn server(&self, tune: impl FnOnce(&mut Config)) -> Server {
        let mut config = Config {
            root: self.served.clone(),
            ..Config::default()
        };
        tune(&mut config);
        Server::start(&self.ca, config).await
    }

    /// The broker's host-scoped credential helper for `hosts`, with the secrets in a RAM fs.
    fn helper(&self, hosts: &[String]) -> (TestDir, Delivered, PathBuf) {
        let ram = if cfg!(target_os = "linux") {
            PathBuf::from("/dev/shm")
        } else {
            std::env::var_os("AINKRAD_TEST_RAMDIR").map_or_else(std::env::temp_dir, Into::into)
        };
        let secrets = TestDir(ram.join(format!(
            "tls-secrets-{}-{}",
            std::process::id(),
            self.dir.file_name().unwrap().to_string_lossy()
        )));
        let mut delivered = deliver(
            &secrets.0,
            "as_a",
            vec![(
                "TOKEN".into(),
                Leased {
                    name: "git".into(),
                    delivery: "askpass".into(),
                    value: TOKEN.to_owned().into(),
                },
            )],
        )
        .unwrap();
        let helper = delivered.git_helper(hosts).unwrap().unwrap();
        (secrets, delivered, helper)
    }

    /// A plain git of the test's own (never the runner's), trusting the fixture CA, no config.
    async fn plain(&self, args: &[&str], global: &Path) -> std::process::Output {
        let out = tokio::process::Command::new(self.w.git.as_path())
            .args(args)
            .env("GIT_CONFIG_GLOBAL", global)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output();
        tokio::time::timeout(Duration::from_secs(30), out)
            .await
            .expect("plain git hung")
            .unwrap()
    }
}

fn request(repo: String) -> SessionWorkspace {
    SessionWorkspace {
        repo,
        reference: "main".into(),
        branch: "agent/topic".into(),
        name: String::new(),
    }
}

fn readme(dir: &Path) {
    std::fs::write(dir.join("README.md"), "hello\n").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    target_os = "macos",
    ignore = "Apple git uses the system keychain and ignores GIT_SSL_CAINFO; runs on Linux"
)]
async fn a_session_clones_over_https_and_certificate_checks_stay_on() {
    let rig = rig("tls-clone");
    bare_repo(&rig.served, "origin.git", readme);
    let server = rig.server(|_| {}).await;
    let url = server.url("127.0.0.1", "origin.git");
    let tree = rig
        .w
        .prepare_session("as_a", 1, &[request(url.clone())], None)
        .await
        .unwrap();
    assert!(tree.join("README.md").exists());
    // The same runner git without the shim does not know the CA: verification was not weakened.
    let mut strict = workspaces(&rig.dir);
    strict.git = PathBuf::from("git");
    let why = strict
        .prepare_session("as_b", 2, &[request(url)], None)
        .await
        .unwrap_err();
    assert!(why.contains("git clone failed"), "{why}");
    assert!(!strict.session_path("as_b").unwrap().join("2").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: requires AINKRAD_TEST_RAMDIR on a verified RAM disk"
)]
async fn a_redirect_to_another_host_is_not_followed_and_gets_no_credentials() {
    let rig = rig("tls-redirect");
    bare_repo(&rig.served, "origin.git", readme);
    let target = rig.server(|_| {}).await;
    let to = format!("https://localhost:{}", target.port);
    let hop = rig
        .server(|c| {
            c.token = Some(TOKEN.into());
            c.redirect = Some(to.clone());
        })
        .await;
    let (_secrets, _delivered, helper) = rig.helper(&[format!("127.0.0.1:{}", hop.port)]);
    let url = hop.url("127.0.0.1", "origin.git");
    rig.w
        .prepare_session("as_a", 1, &[request(url)], Some(&helper))
        .await
        .unwrap_err();
    // The configured host did get the credential and answered with the redirect ...
    let authed = hop
        .seen()
        .iter()
        .filter(|r| r.authorization.is_some())
        .count();
    assert!(
        authed >= 1,
        "the redirect was never reached: {:?}",
        hop.seen()
    );
    // ... and the other host was never contacted, so it saw nothing, least of all the secret.
    assert!(target.seen().is_empty(), "followed: {:?}", target.seen());

    // Control: git with its default `http.followRedirects=initial` does follow this redirect
    // to the other host, so the empty log above is the flag's doing.
    let open = rig.server(|c| c.redirect = Some(to.clone())).await;
    let ls = rig
        .plain(
            &["ls-remote", &open.url("127.0.0.1", "origin.git")],
            Path::new("/dev/null"),
        )
        .await;
    assert!(ls.status.success(), "{ls:?}");
    assert!(
        !target.seen().is_empty(),
        "the control never reached the other host"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    target_os = "macos",
    ignore = "OWNER: requires AINKRAD_TEST_RAMDIR on a verified RAM disk"
)]
async fn the_credential_helper_answers_only_the_configured_host() {
    let rig = rig("tls-hosts");
    bare_repo(&rig.served, "origin.git", readme);
    let configured = rig.server(|c| c.token = Some(TOKEN.into())).await;
    let other_port = rig.server(|c| c.token = Some(TOKEN.into())).await;
    let (_secrets, _delivered, helper) = rig.helper(&[format!("127.0.0.1:{}", configured.port)]);
    let try_clone = |n: i64, url: String| {
        let (w, helper) = (&rig.w, helper.clone());
        async move {
            w.prepare_session("as_a", n, &[request(url)], Some(&helper))
                .await
        }
    };
    // Another name for the same server, and another port on the same name: both demand a token,
    // both ask the helper, and neither gets it.
    try_clone(1, configured.url("localhost", "origin.git"))
        .await
        .unwrap_err();
    try_clone(2, other_port.url("127.0.0.1", "origin.git"))
        .await
        .unwrap_err();
    for server in [&configured, &other_port] {
        let seen = server.seen();
        assert!(!seen.is_empty(), "the attempt never reached the server");
        assert!(
            seen.iter().all(|r| r.authorization.is_none()),
            "a credential left for the wrong host: {seen:?}"
        );
    }
    // The configured host name and port does get it.
    let tree = try_clone(3, configured.url("127.0.0.1", "origin.git"))
        .await
        .unwrap();
    assert!(tree.join("README.md").exists());
    assert!(configured.seen().iter().any(|r| r.authorization.is_some()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    target_os = "macos",
    ignore = "Apple git uses the system keychain and ignores GIT_SSL_CAINFO; runs on Linux"
)]
async fn a_hostile_repo_runs_nothing_and_fetches_no_submodule() {
    let rig = rig("tls-hostile");
    let server = rig.server(|_| {}).await;
    let marker = rig.dir.join("executed");
    let trap = rig.dir.join("trap.sh");
    script(&trap, &format!("touch '{}'\ncat", marker.display()));
    let sub = bare_repo(&rig.served, "sub.git", |d| {
        std::fs::write(d.join("lib.txt"), "sub\n").unwrap()
    });
    assert_eq!(sub.len(), 40);
    let sub_url = server.url("127.0.0.1", "sub.git");
    let hostile = rig.served.join("hostile.git");
    bare_repo(&rig.served, "hostile.git", |d| {
        readme(d);
        std::fs::write(d.join(".gitattributes"), "* filter=evil\n").unwrap();
        std::fs::write(
            d.join(".gitmodules"),
            format!("[submodule \"sub\"]\n\tpath = sub\n\turl = {sub_url}\n"),
        )
        .unwrap();
        setup_git(
            d,
            &[
                "clone",
                "-q",
                rig.served.join("sub.git").to_str().unwrap(),
                "sub",
            ],
        );
    });
    // Server-side traps: git does not copy hooks or config on clone, and must not run them.
    script(
        &hostile.join("hooks/post-checkout"),
        &format!("touch '{}'", marker.display()),
    );
    setup_git(
        &hostile,
        &["config", "core.fsmonitor", &trap.display().to_string()],
    );
    // Runner-side traps: the config a harness's git reads. The runner's own git must ignore it.
    let global = rig.w.git_home.join("config");
    std::fs::create_dir_all(&rig.w.git_home).unwrap();
    let hooks = rig.dir.join("hooks");
    script(
        &hooks.join("post-checkout"),
        &format!("touch '{}'", marker.display()),
    );
    std::fs::write(
        &global,
        format!(
            "[filter \"evil\"]\n\tsmudge = {t}\n\tclean = cat\n[core]\n\tfsmonitor = {t}\n\thooksPath = {h}\n",
            t = trap.display(),
            h = hooks.display()
        ),
    )
    .unwrap();

    // Controls: a git that does read that config runs the trap on checkout, and a git that
    // recurses fetches the submodule from the server, so the checks below can fail.
    let ctrl = rig.dir.join("ctrl");
    let out = rig
        .plain(
            &[
                "clone",
                "-q",
                hostile.to_str().unwrap(),
                ctrl.to_str().unwrap(),
            ],
            &global,
        )
        .await;
    assert!(
        out.status.success() && marker.exists(),
        "the trap is not armed: {out:?}"
    );
    std::fs::remove_file(&marker).unwrap();
    let ctrl2 = rig.dir.join("ctrl2");
    let url = server.url("127.0.0.1", "hostile.git");
    let out = rig
        .plain(
            &[
                "clone",
                "-q",
                "--recurse-submodules",
                &url,
                ctrl2.to_str().unwrap(),
            ],
            Path::new("/dev/null"),
        )
        .await;
    assert!(out.status.success(), "{out:?}");
    assert!(
        server.seen().iter().any(|r| r.target.contains("sub.git")),
        "control saw no submodule fetch"
    );
    let before = server.seen().len();

    let tree = rig
        .w
        .prepare_session("as_a", 1, &[request(url)], None)
        .await
        .unwrap();
    assert!(tree.join("README.md").exists());
    assert!(
        tree.join(".gitmodules").exists(),
        "the checkout must be of the hostile commit"
    );
    assert!(
        !marker.exists(),
        "a hostile repo ran code in the runner's git"
    );
    assert!(
        !server.seen()[before..]
            .iter()
            .any(|r| r.target.contains("sub.git")),
        "the runner fetched a submodule"
    );
    assert!(std::fs::read_dir(tree.join("sub")).map_or(true, |mut d| d.next().is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    target_os = "macos",
    ignore = "Apple git uses the system keychain and ignores GIT_SSL_CAINFO; runs on Linux"
)]
async fn a_stalled_server_is_cut_off_at_the_timeout_and_git_is_killed() {
    let mut rig = rig("tls-stall");
    let server = rig.server(|c| c.stall = true).await;
    rig.w.git_timeout = Duration::from_secs(2);
    let dest = rig.w.root.join("stalled.git");
    let url = server.url("127.0.0.1", "origin.git");
    let started = Instant::now();
    let why = rig
        .w
        .git(
            &rig.w.root,
            &["clone", "--bare", "--", &url, dest.to_str().unwrap()],
        )
        .await
        .unwrap_err();
    assert!(why.contains("timeout"), "{why}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    // The client really went away (git and its transport were killed), not just abandoned.
    for _ in 0..50 {
        if server.hung_up() > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the stalled connection is still open: git survived the timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    target_os = "macos",
    ignore = "Apple git uses the system keychain and ignores GIT_SSL_CAINFO; runs on Linux"
)]
async fn an_oversize_pack_is_cut_off_by_the_size_cap_while_streaming() {
    let mut rig = rig("tls-oversize");
    const BLOB: usize = 24 * 1024 * 1024;
    bare_repo(&rig.served, "big.git", |d| {
        use std::io::Read;
        // Random bytes do not compress: the pack is about as large as the blob.
        let mut bytes = vec![0u8; BLOB];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        std::fs::write(d.join("blob.bin"), bytes).unwrap();
    });
    let server = rig
        .server(|c| c.throttle = Some((64 * 1024, Duration::from_millis(25))))
        .await;
    rig.w.git_size_cap = 2 * 1024 * 1024;
    let dest = rig.w.root.join("big.git");
    let url = server.url("127.0.0.1", "big.git");
    let why = rig
        .w
        .git(
            &rig.w.root,
            &["clone", "--bare", "--", &url, dest.to_str().unwrap()],
        )
        .await
        .unwrap_err();
    assert!(why.contains("size limit"), "{why}");
    // Stopped while the server was still sending: the cap acts during the transfer.
    assert!(
        server.sent() < (BLOB as u64) * 3 / 4,
        "the whole pack was transferred: {}",
        server.sent()
    );
}
