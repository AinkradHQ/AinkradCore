//! Reading a published file (E15.12): only inside the issue's worktree, symlinks resolved, the
//! size checked before reading.

use super::*;

#[tokio::test]
async fn reads_only_inside_the_worktree_and_within_the_size() {
    let dir = scratch("read");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    std::fs::create_dir_all(path.join("out")).unwrap();
    std::fs::write(path.join("out/report.md"), "# done").unwrap();
    assert_eq!(w.read_file(1, "out/report.md", 100).unwrap(), b"# done");

    let too_big = w.read_file(1, "out/report.md", 5).unwrap_err();
    assert!(too_big.contains("6 bytes; the most is 5"), "{too_big}");
    for bad in ["../x", "/etc/hosts", "out/../../x", "./out/report.md", ""] {
        let why = w.read_file(1, bad, 100).unwrap_err();
        assert!(why.contains("plain relative path"), "{bad}: {why}");
    }
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "key").unwrap();
    std::os::unix::fs::symlink(&secret, path.join("out/link")).unwrap();
    let why = w.read_file(1, "out/link", 100).unwrap_err();
    assert!(why.contains("leads outside the worktree"), "{why}");
    assert!(
        w.read_file(1, "out", 100)
            .unwrap_err()
            .contains("not a file")
    );
    assert!(
        w.read_file(1, "out/missing.md", 100)
            .unwrap_err()
            .contains("no file")
    );
    assert!(
        w.read_file(2, "x", 100)
            .unwrap_err()
            .contains("no worktree")
    );
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}
