//! The conformance corpus (E2-04.4): `tests/corpus/<name>.vt` is a raw output stream; the first
//! line of `<name>.golden` is the size (`rows cols`) and the rest is `Terminal::dump()` after
//! feeding the stream. Each case also checks the reattach promise: a terminal rebuilt from a
//! snapshot dumps identically, and so does one that was fed the stream in 1-byte chunks.
//!
//! `BLESS=1 cargo test -p ainkrad-term --test corpus` rewrites the goldens; review the diff by eye,
//! a golden is only as good as the screen it was checked against.

use std::fs;
use std::path::Path;

use ainkrad_term::{Limits, ScreenSink, Size, Terminal};

fn size_of(golden: &str) -> Size {
    let first = golden.lines().next().expect("golden has a size line");
    let mut it = first.split(' ').map(|n| n.parse::<u16>().expect("size"));
    Size {
        rows: it.next().expect("rows"),
        cols: it.next().expect("cols"),
    }
}

#[test]
fn corpus_matches_goldens_and_survives_reattach() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let bless = std::env::var_os("BLESS").is_some();
    let mut names: Vec<_> = fs::read_dir(&dir)
        .expect("corpus dir")
        .filter_map(|e| {
            let path = e.ok()?.path();
            let stem = path.file_stem()?.to_string_lossy().into_owned();
            (path.extension()? == "vt").then_some(stem)
        })
        .collect();
    names.sort();
    assert!(names.len() >= 10, "corpus too small: {names:?}");
    let mut failed = Vec::new();
    for name in &names {
        let input = fs::read(dir.join(format!("{name}.vt"))).expect("stream");
        let golden_path = dir.join(format!("{name}.golden"));
        let golden = fs::read_to_string(&golden_path).expect("golden");
        let size = size_of(&golden);

        let mut t = Terminal::new(size, Limits::default());
        t.feed(&input);
        let got = format!("{} {}\n{}", size.rows, size.cols, t.dump());
        if bless {
            fs::write(&golden_path, &got).expect("bless");
        } else if got != golden {
            failed.push(format!(
                "{name}: golden differs\n--- want\n{golden}--- got\n{got}"
            ));
        }

        let mut bytewise = Terminal::new(size, Limits::default());
        for b in &input {
            bytewise.feed(std::slice::from_ref(b));
        }
        if bytewise.dump() != t.dump() {
            failed.push(format!("{name}: 1-byte chunks differ\n{}", bytewise.dump()));
        }

        let snap = t.snapshot(usize::MAX);
        let mut rebuilt = Terminal::new(snap.size, Limits::default());
        rebuilt.feed(&snap.bytes);
        if rebuilt.dump() != t.dump() {
            failed.push(format!(
                "{name}: snapshot replay differs\n--- original\n{}--- rebuilt\n{}",
                t.dump(),
                rebuilt.dump()
            ));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}
