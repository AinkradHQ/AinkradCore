use super::*;
use ainkrad_proto::v2::InlineFile;

#[tokio::test]
async fn another_spelling_of_a_session_file_never_replaces_or_removes_it() {
    // L1: on APFS a runner's `SRC/main.rs` opens the session's `src/main.rs`.
    let dir = std::env::temp_dir().join(format!("ainkrad-watch-l1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/main.rs"), "core").unwrap();
    let folds = dir.join("SRC/MAIN.RS").exists();
    let tree = Tree::open(&dir).unwrap();
    let mut entries = Entries::new();
    entries.insert(
        "src/main.rs".into(),
        entry_of("src/main.rs", b"core", false),
    );
    let st = WatchState {
        args: WatchArgs {
            device: "d".into(),
            session: "as_x".into(),
            project: 1,
            lease: "l".into(),
            root: dir.clone(),
            rules: Rules::default(),
        },
        inner: Mutex::new(Inner {
            entries,
            ..Inner::default()
        }),
        io: tokio::sync::Mutex::new(()),
        stop: Notify::new(),
    };
    let inline = |p: &str, b: &[u8]| InlineFile {
        path: p.into(),
        data: STANDARD.encode(b),
    };
    let ev = SyncEvent {
        seq: 1,
        put: vec![
            entry_of("SRC/main.rs", b"evil", false),
            entry_of("src/new.rs", b"new", false),
        ],
        delete: vec!["SRC/MAIN.RS".into()],
        inline: vec![inline("SRC/main.rs", b"evil"), inline("src/new.rs", b"new")],
    };
    apply_event(
        &Arc::new(Hub::new(crate::hub::HubConfig::default())),
        &st,
        &tree,
        ev,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(dir.join("src/new.rs")).unwrap(), b"new");
    assert_eq!(std::fs::read(dir.join("src/main.rs")).unwrap(), b"core");
    if folds {
        assert_eq!(st.refused(), 2);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
