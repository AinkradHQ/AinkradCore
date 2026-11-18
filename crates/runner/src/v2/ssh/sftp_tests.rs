//! `ssh.sftp.*` against the in-process `russh` + in-memory SFTP fixture: the plain ops, paths as
//! data, streamed reads and writes under credit, the 2 GiB cap, and a cancel that leaves nothing.

use std::sync::atomic::Ordering::SeqCst;

use ainkrad_proto::v2::{
    Body, Command, Control, Credit, Output, Reply, SFTP_MAX_BYTES, STREAM_WINDOW, SftpDone,
    SftpEntries, SftpEntry, SftpKind, SftpList, SftpMkdir, SftpRead, SftpRemove, SftpRename,
    SftpStat, SftpTransferred, SftpWrite, SshRoute,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;

use super::fixture::*;
use super::*;

fn route(s: &Server) -> SshRoute {
    SshRoute {
        target: s.hop("me", "l_1"),
        hops: vec![],
    }
}

async fn unary(d: &SshDriver, c: Command) -> Result<Reply, StreamError> {
    d.sftp_unary(&c, never()).await
}

fn mkdir(s: &Server, path: &str) -> Command {
    Command::SshSftpMkdir(SftpMkdir {
        route: route(s),
        path: path.into(),
    })
}

fn stat(s: &Server, path: &str, follow: bool) -> Command {
    Command::SshSftpStat(SftpStat {
        route: route(s),
        path: path.into(),
        follow,
    })
}

fn ssh_with(leases: &Leases) -> Arc<SshDriver> {
    leases.key("l_1");
    Arc::new(ssh(leases))
}

/// A running read or write: what it sent, what the Core can send it, and its cancel.
struct Xfer {
    out: UnboundedReceiver<Body>,
    core: UnboundedSender<Body>,
    cancel: oneshot::Sender<()>,
    done: JoinHandle<Result<SftpTransferred, StreamError>>,
}

fn start_read(d: &Arc<SshDriver>, req: SftpRead) -> Xfer {
    let (out_tx, out) = unbounded_channel();
    let (core, inbox) = unbounded_channel();
    let (cancel, cancel_rx) = oneshot::channel();
    let d = Arc::clone(d);
    let done = tokio::spawn(async move {
        let send = move |b| drop(out_tx.send(b));
        d.sftp_read(&req, send, inbox, cancel_rx).await
    });
    Xfer {
        out,
        core,
        cancel,
        done,
    }
}

fn start_write(d: &Arc<SshDriver>, req: SftpWrite) -> Xfer {
    let (out_tx, out) = unbounded_channel();
    let (core, inbox) = unbounded_channel();
    let (cancel, cancel_rx) = oneshot::channel();
    let d = Arc::clone(d);
    let done = tokio::spawn(async move {
        let send = move |b| drop(out_tx.send(b));
        d.sftp_write(&req, send, inbox, cancel_rx).await
    });
    Xfer {
        out,
        core,
        cancel,
        done,
    }
}

fn write_req(s: &Server, path: &str, overwrite: bool, size: Option<u64>) -> SftpWrite {
    SftpWrite {
        route: route(s),
        path: path.into(),
        overwrite,
        size,
        mode: None,
    }
}

fn read_req(s: &Server, path: &str) -> SftpRead {
    SftpRead {
        route: route(s),
        path: path.into(),
        offset: 0,
    }
}

fn data(bytes: &[u8]) -> Body {
    Body::Output(Output {
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
    })
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 % 251) as u8).collect()
}

/// Sends `bytes` as the Core would: frames of `step`, never past the credit the runner granted.
async fn feed(x: &mut Xfer, bytes: &[u8], step: usize) {
    let mut allowed = STREAM_WINDOW;
    for chunk in bytes.chunks(step) {
        while allowed < chunk.len() as u64 {
            match x.out.recv().await {
                Some(Body::Credit(c)) => allowed += c.bytes,
                other => panic!("expected credit, got {other:?}"),
            }
        }
        allowed -= chunk.len() as u64;
        x.core.send(data(chunk)).unwrap();
    }
}

fn kept(s: &Server) -> Vec<String> {
    let mut v: Vec<_> = s.fs.lock().unwrap().files.keys().cloned().collect();
    v.sort();
    v
}

fn err_of<T: std::fmt::Debug>(r: Result<T, StreamError>) -> ErrorCode {
    r.unwrap_err().code
}

#[tokio::test]
async fn list_stat_mkdir_rename_remove_and_one_pooled_connection() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    {
        let mut fs = s.fs.lock().unwrap();
        fs.dirs.insert("/d".into());
        fs.files.insert("/d/b.txt".into(), b"hello".to_vec());
        fs.files.insert("/d/a".into(), vec![]);
        fs.links.insert("/d/l".into(), "/d/b.txt".into());
    }
    let list = Command::SshSftpList(SftpList {
        route: route(&s),
        path: "/d".into(),
    });
    let Reply::SshSftpList(SftpEntries { entries, truncated }) = unary(&d, list).await.unwrap()
    else {
        panic!("not a list")
    };
    let got: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(
        got,
        [
            ("a", SftpKind::File),
            ("b.txt", SftpKind::File),
            ("l", SftpKind::Symlink)
        ]
    );
    assert!(!truncated);
    assert_eq!(entries[1].size, Some(5));
    assert_eq!(entries[1].mode, Some(0o644));
    assert_eq!(entries[1].mtime, Some(1_700_000_000));

    // A symlink is a symlink unless asked to be followed.
    let Reply::SshSftpStat(SftpEntry { kind, .. }) =
        unary(&d, stat(&s, "/d/l", false)).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(kind, SftpKind::Symlink);
    let Reply::SshSftpStat(e) = unary(&d, stat(&s, "/d/l", true)).await.unwrap() else {
        panic!()
    };
    assert_eq!((e.kind, e.size), (SftpKind::File, Some(5)));
    assert_eq!(
        err_of(unary(&d, stat(&s, "/d/nope", false)).await),
        ErrorCode::SftpNotFound
    );

    assert_eq!(
        unary(&d, mkdir(&s, "/d/n")).await.unwrap(),
        Reply::SshSftpMkdir(SftpDone {})
    );
    assert_eq!(
        err_of(unary(&d, mkdir(&s, "/d/n")).await),
        ErrorCode::SftpExists
    );
    let rename = |from: &str, to: &str| {
        Command::SshSftpRename(SftpRename {
            route: route(&s),
            from: from.into(),
            to: to.into(),
        })
    };
    unary(&d, rename("/d/b.txt", "/d/c.txt")).await.unwrap();
    assert_eq!(
        err_of(unary(&d, rename("/d/a", "/d/c.txt")).await),
        ErrorCode::SftpExists
    );
    let remove = |path: &str, dir: bool| {
        Command::SshSftpRemove(SftpRemove {
            route: route(&s),
            path: path.into(),
            dir,
        })
    };
    // Removing the link leaves what it pointed at.
    unary(&d, remove("/d/l", false)).await.unwrap();
    unary(&d, remove("/d/n", true)).await.unwrap();
    assert_eq!(kept(&s), ["/d/a", "/d/c.txt"]);
    assert_eq!(
        err_of(unary(&d, remove("/d/zzz", false)).await),
        ErrorCode::SftpNotFound
    );
    assert_eq!(s.seen.conns.load(SeqCst), 1, "each op dialled again");
}

#[tokio::test]
async fn paths_are_data_never_a_shell_or_an_option() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    let names = [
        "../x",
        "a\nb",
        "-rf",
        "x; rm -rf /tmp",
        "$(id)",
        "a b",
        "--help",
        "/d/../../etc",
    ];
    for name in names {
        unary(&d, mkdir(&s, name)).await.unwrap();
        let Reply::SshSftpStat(e) = unary(&d, stat(&s, name, false)).await.unwrap() else {
            panic!()
        };
        assert_eq!((e.name.as_str(), e.kind), (name, SftpKind::Dir));
        // And as a file, through the part-file path.
        let file = format!("/d/{name}");
        let x = start_write(&d, write_req(&s, &file, false, Some(3)));
        x.core.send(data(b"abc")).unwrap();
        x.core.send(Body::Control(Control::Eof)).unwrap();
        assert_eq!(x.done.await.unwrap().unwrap().bytes, 3);
        assert_eq!(s.fs.lock().unwrap().files[&file], b"abc");
    }
    let fs = s.fs.lock().unwrap();
    for name in names {
        assert!(fs.dirs.contains(name), "{name:?} was changed on the way");
        assert!(fs.paths.iter().any(|p| p == name));
    }
    // Nothing but the named files: no temporary left behind.
    assert!(fs.files.keys().all(|k| !k.contains(".part-")));
}

#[tokio::test]
async fn an_empty_nul_or_huge_path_is_refused_before_any_dial() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    for bad in [String::new(), "a\0b".to_owned(), "x".repeat(4097)] {
        assert_eq!(
            err_of(unary(&d, mkdir(&s, &bad)).await),
            ErrorCode::InvalidArgs
        );
        let x = start_read(&d, read_req(&s, &bad));
        assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::InvalidArgs);
        let x = start_write(&d, write_req(&s, &bad, false, None));
        assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::InvalidArgs);
    }
    let x = start_write(&d, write_req(&s, "/dir/", false, None));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::InvalidArgs);
    assert_eq!(s.seen.conns.load(SeqCst), 0);
    assert_eq!(leases.redeemed.load(SeqCst), 0);
}

#[tokio::test]
async fn a_read_streams_within_the_credit_and_ends_with_the_count() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    let content = pattern(200_000);
    s.fs.lock()
        .unwrap()
        .files
        .insert("/big".into(), content.clone());
    let mut x = start_read(&d, read_req(&s, "/big"));
    let mut got = Vec::new();
    // Without credit the runner stops at one window.
    while let Ok(Some(Body::Output(o))) =
        tokio::time::timeout(Duration::from_millis(400), x.out.recv()).await
    {
        got.extend(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, o.data).unwrap(),
        );
    }
    assert_eq!(got.len() as u64, STREAM_WINDOW);
    assert!(!x.done.is_finished());
    // The Core reads and grants; the rest flows.
    x.core
        .send(Body::Credit(Credit { bytes: 1 << 20 }))
        .unwrap();
    while let Some(Body::Output(o)) = x.out.recv().await {
        got.extend(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, o.data).unwrap(),
        );
    }
    assert_eq!(x.done.await.unwrap().unwrap().bytes, 200_000);
    assert_eq!(got, content);
}

#[tokio::test]
async fn a_read_resumes_at_an_offset_and_refuses_a_directory() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    {
        let mut fs = s.fs.lock().unwrap();
        fs.files.insert("/f".into(), b"0123456789".to_vec());
        fs.dirs.insert("/d".into());
    }
    let mut req = read_req(&s, "/f");
    req.offset = 4;
    let mut x = start_read(&d, req);
    let Some(Body::Output(o)) = x.out.recv().await else {
        panic!("no data")
    };
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, o.data).unwrap();
    assert_eq!(bytes, b"456789");
    assert_eq!(x.done.await.unwrap().unwrap().bytes, 6);
    let x = start_read(&d, read_req(&s, "/d"));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::SftpFailed);
    let x = start_read(&d, read_req(&s, "/missing"));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::SftpNotFound);
}

#[tokio::test]
async fn a_write_lands_atomically_under_credit_and_replaces_only_when_asked() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    let content = pattern(300_000);
    let mut x = start_write(&d, write_req(&s, "/up.bin", false, Some(300_000)));
    feed(&mut x, &content, 20_000).await;
    x.core.send(Body::Control(Control::Eof)).unwrap();
    assert_eq!(x.done.await.unwrap().unwrap().bytes, 300_000);
    assert_eq!(s.fs.lock().unwrap().files["/up.bin"], content);
    assert_eq!(kept(&s), ["/up.bin"], "a part file was left");

    // Taken: refused before anything is written.
    let x = start_write(&d, write_req(&s, "/up.bin", false, None));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::SftpExists);
    assert_eq!(s.fs.lock().unwrap().files["/up.bin"], content);
    // Overwrite replaces it.
    let x = start_write(&d, write_req(&s, "/up.bin", true, None));
    x.core.send(data(b"new")).unwrap();
    x.core.send(Body::Control(Control::Eof)).unwrap();
    assert_eq!(x.done.await.unwrap().unwrap().bytes, 3);
    assert_eq!(s.fs.lock().unwrap().files["/up.bin"], b"new");
    assert_eq!(kept(&s), ["/up.bin"]);
}

#[tokio::test]
async fn a_cancel_mid_transfer_leaves_no_partial_file() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    // An existing file stays as it was.
    s.fs.lock()
        .unwrap()
        .files
        .insert("/keep".into(), b"old".to_vec());
    for (path, overwrite) in [("/new", false), ("/keep", true)] {
        let x = start_write(&d, write_req(&s, path, overwrite, None));
        x.core.send(data(&pattern(10_000))).unwrap();
        // Wait until the part file has its bytes, then cancel.
        for _ in 0..200 {
            let started =
                s.fs.lock()
                    .unwrap()
                    .files
                    .keys()
                    .any(|k| k.contains(".part-"));
            if started {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        x.cancel.send(()).unwrap();
        assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::Cancelled);
        assert_eq!(kept(&s), ["/keep"], "{path}: a file was left");
        assert_eq!(s.fs.lock().unwrap().files["/keep"], b"old");
    }
    // The Core's stream going away (its sender dropped) is the same.
    let x = start_write(&d, write_req(&s, "/gone", false, None));
    for _ in 0..200 {
        let started =
            s.fs.lock()
                .unwrap()
                .files
                .keys()
                .any(|k| k.contains(".part-"));
        if started {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(x.core);
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::Cancelled);
    assert_eq!(kept(&s), ["/keep"]);
}

#[tokio::test]
async fn a_write_of_the_wrong_size_or_past_the_credit_leaves_nothing() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    let d = ssh_with(&leases);
    let x = start_write(&d, write_req(&s, "/short", false, Some(10)));
    x.core.send(data(b"12345")).unwrap();
    x.core.send(Body::Control(Control::Eof)).unwrap();
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::SftpFailed);
    // More than the window in one go: the Core broke the credit rules.
    let x = start_write(&d, write_req(&s, "/greedy", false, None));
    x.core.send(data(&pattern(70_000))).unwrap();
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::InvalidArgs);
    assert!(kept(&s).is_empty(), "{:?}", kept(&s));
}

#[tokio::test]
async fn a_transfer_over_the_cap_is_refused() {
    // The real cap is 2 GiB.
    assert_eq!(SFTP_MAX_BYTES, 2 << 30);
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let d = Arc::new(ssh(&leases));
    {
        let mut fs = s.fs.lock().unwrap();
        fs.files.insert("/huge".into(), b"x".to_vec());
        fs.claimed.insert("/huge".into(), (2 << 30) + 1);
    }
    // A host that says the file is over 2 GiB: refused before one byte moves.
    let x = start_read(&d, read_req(&s, "/huge"));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::TooLarge);
    // A sender that declares more: refused before dialling.
    let conns = s.seen.conns.load(SeqCst);
    let x = start_write(&d, write_req(&s, "/w", false, Some((2 << 30) + 1)));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::TooLarge);
    assert_eq!(s.seen.conns.load(SeqCst), conns);

    // The streaming check, with a small cap: it stops mid-transfer and leaves nothing.
    let small = Arc::new(ssh(&leases).with_cap(100));
    s.fs.lock()
        .unwrap()
        .files
        .insert("/two".into(), vec![1; 200]);
    let x = start_read(&small, read_req(&s, "/two"));
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::TooLarge);
    let x = start_write(&small, write_req(&s, "/too-big", false, None));
    x.core.send(data(&[1; 60])).unwrap();
    x.core.send(data(&[1; 60])).unwrap();
    x.core.send(Body::Control(Control::Eof)).unwrap();
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::TooLarge);
    assert_eq!(kept(&s), ["/huge", "/two"]);
}

#[tokio::test]
async fn sftp_uses_the_same_host_key_checks_and_jump_chain_as_exec() {
    let (leases, j, t) = (
        Leases::default(),
        serve("J", true).await,
        serve("T", true).await,
    );
    for l in ["l_j", "l_t"] {
        leases.key(l);
    }
    let d = ssh(&leases);
    // An unpinned target: unknown, with the fingerprint, nothing authenticated.
    let mut hop = t.hop("me", "l_t");
    hop.pinned_keys.clear();
    let route_of = |target: SshHop, hops| SshRoute { target, hops };
    let list = |r: SshRoute| {
        Command::SshSftpList(SftpList {
            route: r,
            path: "/".into(),
        })
    };
    let e = d
        .sftp_unary(&list(route_of(hop, vec![])), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyUnknown);
    assert_eq!(e.host_key.unwrap().fingerprint, fp(&t.host_key));
    assert_eq!(t.seen.auth.load(SeqCst), 0);
    // Through a jump host.
    t.fs.lock()
        .unwrap()
        .files
        .insert("/hi".into(), b"x".to_vec());
    let r = route_of(t.hop("me", "l_t"), vec![j.hop("j", "l_j")]);
    let Reply::SshSftpList(l) = d.sftp_unary(&list(r), never()).await.unwrap() else {
        panic!()
    };
    assert_eq!(l.entries[0].name, "hi");
    assert_eq!(j.seen.forwards.load(SeqCst), 1);
    // Four hops: refused, as for exec.
    let jumps: Vec<_> = (0..4).map(|_| j.hop("j", "l_j")).collect();
    let e = d
        .sftp_unary(&list(route_of(t.hop("me", "l_t"), jumps)), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
}

#[tokio::test]
async fn a_cancel_before_the_session_opens_stops_the_op() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    *leases.delay.lock().unwrap() = Duration::from_secs(5);
    let d = ssh(&leases);
    let (tx, rx) = oneshot::channel();
    drop(tx);
    let e = d.sftp_unary(&mkdir(&s, "/x"), rx).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
    assert!(s.fs.lock().unwrap().paths.is_empty());
}

/// Y2-03 integration against a real OpenSSH server in Podman (`#[ignore]`: it needs one). The setup
/// exports `LEYLINE_IT_*` as for `real_openssh_exec_trust_jump_and_refused_algorithms`
/// (A = the server's port, A_FP its host key, KEY the private key file; user `it`; its home is
/// writable). Run: `cargo test -p ainkrad-runner --lib -- --ignored real_openssh_sftp`.
#[tokio::test]
#[ignore = "needs a throwaway OpenSSH container (LEYLINE_IT_*)"]
async fn real_openssh_sftp_roundtrip_hostile_names_cap_and_cancel() {
    let env = |k: &str| std::env::var(format!("LEYLINE_IT_{k}")).unwrap_or_else(|_| panic!("{k}"));
    let leases = Leases::default();
    leases.add("l_ed", &std::fs::read_to_string(env("KEY")).unwrap());
    let hop = SshHop {
        host: "127.0.0.1".to_owned(),
        port: env("A").parse().unwrap(),
        user: "it".to_owned(),
        pinned_keys: vec![env("A_FP")],
        lease: "l_ed".to_owned(),
    };
    let route = SshRoute {
        target: hop,
        hops: vec![],
    };
    let d = Arc::new(ssh(&leases));
    let u = |c: Command| {
        let d = Arc::clone(&d);
        async move { d.sftp_unary(&c, never()).await }
    };
    let base = format!("/tmp/leyline-sftp-{}", std::process::id());
    let mk = |p: &str| {
        Command::SshSftpMkdir(SftpMkdir {
            route: route.clone(),
            path: p.into(),
        })
    };
    u(mk(&base)).await.unwrap();
    assert_eq!(err_of(u(mk(&base)).await), ErrorCode::SftpExists);

    // Hostile names land as exactly those names, and the host's own `ls` agrees.
    let names = ["../esc", "a\nb", "-rf", "x; touch pwned", "$(id)", "a b"];
    for name in names {
        let path = format!("{base}/{name}");
        let parent = path.rsplit_once('/').unwrap().0.to_owned();
        // `../esc` resolves one level up: it must be a real directory to write into.
        u(mk(&parent)).await.ok();
        let body = pattern(150_000);
        let w = SftpWrite {
            route: route.clone(),
            path: path.clone(),
            overwrite: false,
            size: Some(body.len() as u64),
            mode: None,
        };
        let mut x = start_write(&d, w);
        feed(&mut x, &body, 16_384).await;
        x.core.send(Body::Control(Control::Eof)).unwrap();
        assert_eq!(x.done.await.unwrap().unwrap().bytes, 150_000, "{name:?}");
        let mut r = start_read(
            &d,
            SftpRead {
                route: route.clone(),
                path: path.clone(),
                offset: 0,
            },
        );
        let mut got = Vec::new();
        r.core
            .send(Body::Credit(Credit { bytes: 1 << 20 }))
            .unwrap();
        while let Some(Body::Output(o)) = r.out.recv().await {
            got.extend(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, o.data).unwrap(),
            );
        }
        assert_eq!(r.done.await.unwrap().unwrap().bytes, 150_000);
        assert_eq!(got, body, "{name:?}");
    }
    // Nothing was run by the host (no shell reads a path), and no part file is left.
    let ls = Command::SshSftpList(SftpList {
        route: route.clone(),
        path: base.clone(),
    });
    let Reply::SshSftpList(l) = u(ls).await.unwrap() else {
        panic!()
    };
    assert!(l.entries.iter().all(|e| e.name != "pwned"));
    // Cancel mid-write: no partial file.
    let w = SftpWrite {
        route: route.clone(),
        path: format!("{base}/cancelled"),
        overwrite: false,
        size: None,
        mode: None,
    };
    let x = start_write(&d, w);
    x.core.send(data(&pattern(40_000))).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    x.cancel.send(()).unwrap();
    assert_eq!(err_of(x.done.await.unwrap()), ErrorCode::Cancelled);
    let ls = Command::SshSftpList(SftpList {
        route: route.clone(),
        path: base.clone(),
    });
    let Reply::SshSftpList(l) = u(ls).await.unwrap() else {
        panic!()
    };
    let left: Vec<_> = l
        .entries
        .iter()
        .filter(|e| e.name.contains("cancel"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    // A symlink is not followed unasked (the setup plants `$HOME/link -> /etc/hostname`).
    let st = |follow| {
        Command::SshSftpStat(SftpStat {
            route: route.clone(),
            path: "link".into(),
            follow,
        })
    };
    if let Ok(Reply::SshSftpStat(e)) = u(st(false)).await {
        assert_eq!(e.kind, SftpKind::Symlink);
        let Reply::SshSftpStat(f) = u(st(true)).await.unwrap() else {
            panic!()
        };
        assert_eq!(f.kind, SftpKind::File);
    }
}
