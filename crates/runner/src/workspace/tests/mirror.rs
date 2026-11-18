//! A project session's checkout is cloned from the Core's copy through the loopback relay
//! (P3-02): independent of the copy, no trace of the relay in it, and the relay answers nothing
//! but the granted repos' upload-pack.

use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::workspace::relay::{Call, Reply, Upstream};

/// A stand-in for the Core: `git upload-pack` over the bare repo `copy`, for repo id 7 only.
fn core(copy: PathBuf, seen: Arc<Mutex<Vec<String>>>) -> Upstream {
    Arc::new(move |call: Call| {
        let (copy, seen) = (copy.clone(), Arc::clone(&seen));
        Box::pin(async move {
            seen.lock()
                .unwrap()
                .push(format!("{} {}", call.method, call.path));
            let advertise = call.method == "GET";
            let mut cmd = tokio::process::Command::new("git");
            cmd.args(["upload-pack", "--stateless-rpc"])
                .args(advertise.then_some("--advertise-refs"))
                .arg(&copy)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            if let Some((_, v)) = call.headers.iter().find(|(n, _)| n == "git-protocol") {
                cmd.env("GIT_PROTOCOL", v);
            }
            let mut child = cmd.spawn().map_err(|e| e.to_string())?;
            let mut stdin = child.stdin.take().unwrap();
            stdin
                .write_all(&call.body)
                .await
                .map_err(|e| e.to_string())?;
            drop(stdin);
            let mut out = Vec::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut out)
                .await
                .map_err(|e| e.to_string())?;
            let mut body = Vec::new();
            // Version 2 has no service line (as the Core's own serve code).
            let v2 = call
                .headers
                .iter()
                .any(|(n, v)| n == "git-protocol" && v.contains("version=2"));
            if advertise && !v2 {
                body.extend_from_slice(b"001e# service=git-upload-pack\n0000");
            }
            body.extend(out);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(Ok(body)).await.unwrap();
            Ok(Reply {
                status: 200,
                // git treats any other type as a dumb server and fails with "is this a git repository?".
                content_type: if advertise {
                    "application/x-git-upload-pack-advertise"
                } else {
                    "application/x-git-upload-pack-result"
                }
                .into(),
                body: rx,
            })
        })
    })
}

fn request(remote: &str, mirror: Option<i64>) -> SessionWorkspace {
    SessionWorkspace {
        repo: remote.to_owned(),
        reference: "main".into(),
        branch: "ainkrad/s1".into(),
        name: String::new(),
        mirror,
    }
}

const REMOTE: &str = "https://github.com/acme/web.git";

#[tokio::test]
async fn a_project_checkout_is_cloned_from_the_core_copy_and_cannot_touch_it() {
    let dir = scratch("mirror-clone");
    let copy = PathBuf::from(origin(&dir));
    let w = Workspaces::new(dir.join("work"), dir.join("git-home"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    w.set_mirror_upstream(core(copy.clone(), Arc::clone(&seen)));
    let refs_before = git(&copy, &["for-each-ref"]);

    let path = w
        .prepare_session("as_p", 1, &[request(REMOTE, Some(7))], None)
        .await
        .unwrap();
    assert!(path.join("README.md").is_file());
    assert_eq!(
        git(&path, &["rev-parse", "--abbrev-ref", "HEAD"]).trim(),
        "ainkrad/s1"
    );
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter().all(|c| c.contains("/api/v1/mirrors/7/")),
        "{seen:?}"
    );
    assert!(seen.iter().any(|c| c.starts_with("POST ")), "{seen:?}");

    // The checkout's origin is the real remote: nothing of the relay, its port or its token.
    let config = std::fs::read_to_string(path.join(".git/config")).unwrap();
    assert!(
        config.contains(REMOTE) && !config.contains("127.0.0.1"),
        "{config}"
    );
    assert!(!path.join(".git/objects/info/alternates").exists());

    // What a session does in its checkout never reaches the copy.
    script_hook(&path.join(".git/hooks/post-commit"));
    git(&path, &["config", "alias.x", "!echo"]);
    std::fs::write(path.join("a.txt"), "x").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "agent work"]);
    git(&path, &["update-ref", "refs/heads/main", "HEAD"]);
    assert_eq!(git(&copy, &["for-each-ref"]), refs_before);
    assert!(!copy.join("hooks/post-commit").exists());
    assert!(
        !std::fs::read_to_string(copy.join("config"))
            .unwrap()
            .contains("alias")
    );
}

fn script_hook(path: &Path) {
    std::fs::write(path, "#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn a_mirror_with_no_way_to_reach_the_core_is_refused() {
    let dir = scratch("mirror-none");
    let w = Workspaces::new(dir.join("work"), dir.join("git-home"));
    let r = w
        .prepare_session("as_p", 1, &[request(REMOTE, Some(7))], None)
        .await;
    assert!(r.is_err_and(|e| e.contains("cannot clone from the Core")));
    assert!(!dir.join("work/worktrees/sessions/as_p").exists());
}

/// What the relay answers a raw request with (its status line).
async fn ask(port_url: &str, request: &str) -> String {
    let addr = port_url
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    out.lines().next().unwrap_or("").to_owned()
}

#[tokio::test]
async fn the_relay_answers_only_the_granted_repos_upload_pack_with_its_token() {
    let dir = scratch("mirror-relay");
    let copy = PathBuf::from(origin(&dir));
    let up = core(copy, Arc::default());
    let relay = crate::workspace::relay::Relay::start(up, vec![7])
        .await
        .unwrap();
    let url = relay.url(7);
    let (base, tail) = url.split_once("/mirrors/").unwrap();
    let token = base.rsplit('/').next().unwrap();
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n");
    let refs = "info/refs?service=git-upload-pack";
    let ok = ask(&url, &get(&format!("/{token}/mirrors/{tail}/{refs}"))).await;
    assert!(ok.contains("200"), "{ok}");
    for bad in [
        format!("/{token}/mirrors/8/{refs}"),
        format!("/wrong/mirrors/{tail}/{refs}"),
        format!("/{token}/mirrors/{tail}/info/refs?service=git-receive-pack"),
        format!("/{token}/mirrors/{tail}/git-receive-pack"),
        format!("/{token}/mirrors/{tail}/../8/{refs}"),
        format!("/mirrors/{tail}/{refs}"),
    ] {
        assert!(ask(&url, &get(&bad)).await.contains("404"), "{bad}");
    }
    let push = format!(
        "POST /{token}/mirrors/{tail}/git-upload-pack HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n"
    );
    assert!(ask(&url, &push).await.contains("411"));
    let big = format!(
        "POST /{token}/mirrors/{tail}/git-upload-pack HTTP/1.1\r\ncontent-length: 99999999\r\n\r\n"
    );
    assert!(ask(&url, &big).await.contains("413"));
    drop(relay);
    assert!(
        tokio::net::TcpStream::connect(
            url.strip_prefix("http://")
                .unwrap()
                .split('/')
                .next()
                .unwrap()
        )
        .await
        .is_err()
    );
}
