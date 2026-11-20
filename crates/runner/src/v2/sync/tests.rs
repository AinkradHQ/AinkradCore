//! The sync driver against a real folder: push, manifest, pull, drop and every refusal (spec §11:
//! symlink escapes, `..`, `.git`, a stale base, a bad hash). Needs the `*at` wrappers E15-2 puts in
//! `ainkrad_sys`.

use ainkrad_proto::v2::{
    Body, Command, Entry, EntryKind, ErrorCode, Hash, Output, Reply, SYNC_FRAME_BYTES,
    SYNC_STREAM_WINDOW, SyncDrop, SyncManifest, SyncPull, SyncPush, SyncRules, TreeHash,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::{mpsc, oneshot};

use super::manifest::{Entries, tree_hash};
use super::*;

struct Rig {
    d: Arc<SyncDriver>,
    dir: PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rig(name: &str) -> Rig {
    let dir = std::env::temp_dir().join(format!("ainkrad-sync-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = SyncDriver::new(SyncConfig {
        work_root: dir.clone(),
        core_id: "core".to_owned(),
        agents: dir.join("agents"),
        capacity: 4,
    })
    .unwrap();
    Rig {
        d: Arc::new(d),
        dir,
    }
}

type Wire = (
    Flow,
    mpsc::UnboundedReceiver<(u64, Body)>,
    mpsc::UnboundedSender<Body>,
    oneshot::Sender<()>,
);

fn wire() -> Wire {
    let (out, out_rx) = mpsc::unbounded_channel();
    let (in_tx, inbox) = mpsc::unbounded_channel();
    let (cancel_tx, cancel) = oneshot::channel();
    (
        Flow::new(1, out, inbox, cancel, SYNC_STREAM_WINDOW),
        out_rx,
        in_tx,
        cancel_tx,
    )
}

fn file(path: &str, body: &[u8]) -> Entry {
    let (hash, size, chunks) = manifest::hash_reader(body).unwrap();
    Entry {
        path: path.to_owned(),
        kind: EntryKind::File,
        exec: false,
        size,
        hash,
        chunks,
        link: None,
    }
}

fn frames(inbox: &mpsc::UnboundedSender<Body>, body: &[u8]) {
    for c in body.chunks(SYNC_FRAME_BYTES) {
        inbox
            .send(Body::Output(Output {
                data: STANDARD.encode(c),
            }))
            .unwrap();
    }
}

async fn manifest(r: &Rig, project: i64) -> SyncManifestReply {
    let (flow, ..) = wire();
    let cmd = Command::SyncManifest(SyncManifest {
        project,
        lease: "l_x".into(),
        rules: SyncRules {
            exclude: vec!["target/".into()],
            ..Default::default()
        },
        ..Default::default()
    });
    match r.d.handle(cmd, flow).await.unwrap() {
        Reply::SyncManifest(m) => m,
        other => panic!("{other:?}"),
    }
}

async fn push(r: &Rig, req: SyncPush, bodies: &[&[u8]]) -> Result<TreeHash, StreamError> {
    let (flow, _out, inbox, _c) = wire();
    for b in bodies {
        frames(&inbox, b);
    }
    match r.d.handle(Command::SyncPush(req), flow).await? {
        Reply::SyncPush(p) => Ok(p.tree),
        other => panic!("{other:?}"),
    }
}

fn req(
    project: i64,
    base: TreeHash,
    put: Vec<Entry>,
    delete: Vec<String>,
    want: TreeHash,
) -> SyncPush {
    SyncPush {
        project,
        lease: "l_x".into(),
        base,
        put,
        delete,
        want_tree: want,
        ..Default::default()
    }
}

fn tree_of(entries: &[Entry]) -> TreeHash {
    let m: Entries = entries
        .iter()
        .map(|e| (e.path.clone(), e.clone()))
        .collect();
    tree_hash(&m)
}

#[tokio::test]
async fn a_push_lands_files_and_the_manifest_and_pull_agree() {
    let r = rig("roundtrip");
    let empty = manifest(&r, 3).await;
    assert!(empty.entries.is_empty());
    let (a, b) = (
        file("src/a.rs", b"fn a() {}"),
        file("big.bin", &vec![9u8; 1_500_000]),
    );
    let want = tree_of(&[a.clone(), b.clone()]);
    let got = push(
        &r,
        req(3, empty.tree, vec![a.clone(), b.clone()], vec![], want),
        &[b"fn a() {}", &vec![9u8; 1_500_000]],
    )
    .await;
    assert_eq!(got.unwrap(), want);
    assert_eq!(
        std::fs::read(r.d.layout().root(3).join("src/a.rs")).unwrap(),
        b"fn a() {}"
    );
    let m = manifest(&r, 3).await;
    assert_eq!(m.tree, want);
    assert_eq!(m.entries.len(), 2);
    // Pull streams the chunks back, credited, in order.
    let (mut flow, mut out, _inbox, _c) = wire();
    let pull = SyncPull {
        project: 3,
        lease: "l_x".into(),
        paths: vec![("src/a.rs".into(), a.hash)],
        ..Default::default()
    };
    let n = ops::pull(&r.d, pull, &mut flow).await.unwrap();
    assert_eq!(n.count, 1);
    let Some((_, Body::Output(o))) = out.recv().await else {
        panic!("no output")
    };
    assert_eq!(STANDARD.decode(o.data).unwrap(), b"fn a() {}");
}

#[tokio::test]
async fn a_stale_base_a_bad_chunk_and_a_wrong_want_are_refused() {
    let r = rig("refusals");
    let m = manifest(&r, 4).await;
    let a = file("a.txt", b"hello");
    let want = tree_of(std::slice::from_ref(&a));
    let stale = TreeHash([5; 32]);
    let e = push(
        &r,
        req(4, stale, vec![a.clone()], vec![], want),
        &[b"hello"],
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::BaseMismatch);
    let e = push(
        &r,
        req(4, m.tree, vec![a.clone()], vec![], want),
        &[b"HELLO"],
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::HashMismatch);
    assert!(manifest(&r, 4).await.entries.is_empty(), "nothing landed");
    // A tree that is not the one the Core wants is reported after the fact (the Core retries once
    // with a full diff); the file is in place by then.
    let e = push(
        &r,
        req(4, m.tree, vec![a.clone()], vec![], TreeHash([1; 32])),
        &[b"hello"],
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::HashMismatch);
}

#[tokio::test]
async fn escapes_dotdot_and_git_are_refused_before_anything_is_written() {
    let r = rig("paths");
    let m = manifest(&r, 5).await;
    for bad in [
        "../x",
        "a/../../x",
        ".git/hooks/pre-commit",
        "/etc/passwd",
        "a//b",
    ] {
        let e = file(bad, b"x");
        let err = push(
            &r,
            req(5, m.tree, vec![e], vec![], TreeHash::default()),
            &[b"x"],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathRefused, "{bad}");
    }
    let link = |target: &str| Entry {
        path: "l".into(),
        kind: EntryKind::Symlink,
        link: Some(target.into()),
        hash: Hash(*blake3::hash(target.as_bytes()).as_bytes()),
        size: target.len() as u64,
        ..Default::default()
    };
    for bad in ["/etc/passwd", "../outside", "a/.git/x"] {
        let err = push(
            &r,
            req(5, m.tree, vec![link(bad)], vec![], TreeHash::default()),
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathRefused, "{bad}");
    }
    assert!(manifest(&r, 5).await.entries.is_empty());
}

#[tokio::test]
async fn a_planted_symlink_cannot_send_a_write_outside_the_cache() {
    let r = rig("plant");
    let m = manifest(&r, 6).await;
    let outside = r.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    // A job (or anyone) plants `evil -> ../../outside` inside the cache; a push through it must fail.
    std::os::unix::fs::symlink(&outside, r.d.layout().root(6).join("evil")).unwrap();
    let e = file("evil/pwned.txt", b"x");
    let want = tree_of(std::slice::from_ref(&e));
    let cur = manifest(&r, 6).await;
    let res = push(&r, req(6, cur.tree, vec![e], vec![], want), &[b"x"]).await;
    assert!(res.is_err());
    assert!(!outside.join("pwned.txt").exists());
    let _ = m;
}

#[tokio::test]
async fn per_file_bases_conflict_only_where_that_file_changed() {
    let r = rig("basefiles");
    let m = manifest(&r, 7).await;
    let a = file("a.txt", b"one");
    push(
        &r,
        req(
            7,
            m.tree,
            vec![a.clone()],
            vec![],
            tree_of(std::slice::from_ref(&a)),
        ),
        &[b"one"],
    )
    .await
    .unwrap();
    // A new file: the Core's base is the zero hash; the whole-tree base and want are the zero tree.
    let b = file("b.txt", b"two");
    let mut p = req(
        7,
        TreeHash::default(),
        vec![b.clone()],
        vec![],
        TreeHash::default(),
    );
    p.base_files = vec![("b.txt".into(), Hash::default())];
    push(&r, p, &[b"two"]).await.unwrap();
    // An edit of `a.txt` with the base the Core saw works; a stale one conflicts.
    let a2 = file("a.txt", b"uno");
    let mut ok = req(
        7,
        TreeHash::default(),
        vec![a2.clone()],
        vec![],
        TreeHash::default(),
    );
    ok.base_files = vec![("a.txt".into(), a.hash)];
    push(&r, ok, &[b"uno"]).await.unwrap();
    let a3 = file("a.txt", b"eins");
    let mut stale = req(
        7,
        TreeHash::default(),
        vec![a3],
        vec![],
        TreeHash::default(),
    );
    stale.base_files = vec![("a.txt".into(), a.hash)];
    let e = push(&r, stale, &[b"eins"]).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BaseMismatch);
}

#[tokio::test]
async fn no_lease_is_the_same_answer_as_no_cache_and_drop_frees_the_cache() {
    let r = rig("lease");
    let (flow, ..) = wire();
    let e =
        r.d.handle(
            Command::SyncManifest(SyncManifest {
                project: 8,
                ..Default::default()
            }),
            flow,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    let m = manifest(&r, 8).await;
    let a = file("a.txt", b"data");
    push(
        &r,
        req(8, m.tree, vec![a.clone()], vec![], tree_of(&[a])),
        &[b"data"],
    )
    .await
    .unwrap();
    let (flow, ..) = wire();
    let Reply::SyncDrop(d) =
        r.d.handle(Command::SyncDrop(SyncDrop { project: 8 }), flow)
            .await
            .unwrap()
    else {
        panic!("not a drop");
    };
    assert!(d.bytes_freed >= 4);
    assert!(!r.d.layout().root(8).exists());
    assert!(r.d.caches().is_empty());
}

#[tokio::test]
async fn a_push_naming_a_session_needs_that_sessions_watch() {
    let r = rig("session");
    let empty = manifest(&r, 3).await;
    let a = file("a.txt", b"x");
    let want = tree_of(std::slice::from_ref(&a));
    let mut q = req(3, empty.tree, vec![a], vec![], want);
    q.session = Some("as_other".into());
    let err = push(&r, q.clone(), &[b"x"]).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
    // Holding the watch of a different session does not help either.
    let _w = r.d.watch_lease("l_x", "as_mine");
    assert!(push(&r, q, &[b"x"]).await.is_err());
}
