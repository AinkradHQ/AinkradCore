//! Reattach behaviour through the public API: split sequences, continuation after a snapshot
//! (incl. alt-screens), limits, stale and future `seq`, resize, diffs.

use ainkrad_term::*;

fn term(rows: u16, cols: u16) -> Terminal {
    Terminal::new(Size { rows, cols }, Limits::default())
}

fn rebuilt(t: &Terminal, lines: usize) -> Terminal {
    let snap = t.snapshot(lines);
    let mut r = Terminal::new(snap.size, Limits::default());
    r.feed(&snap.bytes);
    r
}

#[test]
fn a_split_sequence_waits_for_its_end() {
    let mut t = term(4, 20);
    t.feed(b"ab\x1b[3");
    assert_eq!(t.snapshot(0).seq, 2);
    t.feed(b"1mc");
    assert_eq!(t.snapshot(0).seq, 8);
    assert!(t.dump().contains("|ab\\e[31mc"), "{}", t.dump());
}

#[test]
fn continuation_after_a_snapshot_matches() {
    // emu(A ++ B) == emu(snapshot(A) ++ B), including a snapshot taken inside vim.
    let a: &[u8] = b"$ ls\r\nfile\r\n$ vim\x1b[?1049h\x1b[H\x1b[2Jhello\x1b[3;1Hx\x1b[1";
    let b: &[u8] = b"m!\x1b[?1049l\r\n$ ";
    let mut t = term(5, 20);
    t.feed(a);
    let snap = t.snapshot(100);
    let mut r = Terminal::new(snap.size, Limits::default());
    r.feed(&snap.bytes);
    let tail = t.attach(Some(snap.seq), 0).unwrap();
    t.feed(b);
    let Attach::Replay { bytes, .. } = tail else {
        panic!("expected replay")
    };
    r.feed(&bytes);
    r.feed(b);
    assert_eq!(r.dump(), t.dump());
}

#[test]
fn an_old_style_alt_screen_comes_back_too() {
    // `?47h`/`?47l` keep each screen's cursor and save nothing.
    let a: &[u8] = b"\x1b7$ top\r\n$ \x1b[33m\x1b[?47h\x1b[Hdashboard\x1b[m";
    let b: &[u8] = b"\x1b[?47lback\x1b8!";
    let mut t = term(4, 20);
    t.feed(a);
    let mut r = rebuilt(&t, 10);
    t.feed(b);
    r.feed(b);
    assert_eq!(r.dump(), t.dump());
}

#[test]
fn scrollback_is_bounded_by_lines_and_bytes() {
    let limits = Limits {
        scrollback_lines: 5,
        scrollback_bytes: 1 << 20,
        replay_bytes: 64,
    };
    let mut t = Terminal::new(Size { rows: 2, cols: 10 }, limits);
    for i in 0..20 {
        t.feed(format!("line{i}\r\n").as_bytes());
    }
    let l = t.scrollback(0..100);
    assert_eq!(l.held, 14..19);
    assert_eq!(l.first, 14);
    assert!(l.lines[0].starts_with("line14"), "{:?}", l.lines);
    assert!(t.replay_window().end - t.replay_window().start <= 64);

    let limits = Limits {
        scrollback_lines: 1000,
        scrollback_bytes: 40,
        replay_bytes: 64,
    };
    let mut t = Terminal::new(Size { rows: 2, cols: 10 }, limits);
    for i in 0..20 {
        t.feed(format!("line{i}\r\n").as_bytes());
    }
    let l = t.scrollback(0..100);
    assert!(l.lines.iter().map(String::len).sum::<usize>() <= 40);
    assert_eq!(l.held.end, 19);
}

#[test]
fn stale_seq_gets_a_snapshot_and_future_seq_an_error() {
    let limits = Limits {
        replay_bytes: 8,
        ..Limits::default()
    };
    let mut t = Terminal::new(Size { rows: 3, cols: 10 }, limits);
    t.feed(b"0123456789abcdef");
    assert!(matches!(t.attach(Some(2), 0), Ok(Attach::Snapshot(s)) if s.seq == 16));
    assert_eq!(
        t.attach(Some(10), 0),
        Ok(Attach::Replay {
            from: 10,
            bytes: b"abcdef".to_vec()
        })
    );
    assert_eq!(
        t.attach(Some(17), 0),
        Err(SeqAhead {
            requested: 17,
            head: 16
        })
    );
}

#[test]
fn resize_while_detached_and_clamping() {
    let mut t = term(5, 10);
    t.feed(b"hello\r\nworld");
    t.resize(Size { rows: 3, cols: 30 });
    assert_eq!(t.snapshot(0).size, Size { rows: 3, cols: 30 });
    assert_eq!(rebuilt(&t, 10).dump(), t.dump());
    t.resize(Size {
        rows: 0,
        cols: u16::MAX,
    });
    assert_eq!(
        t.size(),
        Size {
            rows: 1,
            cols: MAX_COLS
        }
    );
}

#[test]
fn diff_brings_a_client_up_to_date() {
    let mut t = term(4, 20);
    t.feed(b"one\r\ntwo");
    let snap = t.snapshot(0);
    let state = t.state();
    t.feed(b"\x1b[1;1H\x1b[32mONE\x1b[m\r\n\r\nthree");
    let mut client = Terminal::new(snap.size, Limits::default());
    client.feed(&snap.bytes);
    let (seq, diff) = t.diff(&state);
    assert_eq!(seq, t.head());
    client.feed(&diff);
    // The client's scrollback is its own business; compare the screens.
    let screen = |d: String| d.split("-- screen").nth(1).unwrap().to_owned();
    assert_eq!(screen(client.dump()), screen(t.dump()));
}

#[test]
fn literal_backslash_e_text_reattaches() {
    // Found by fuzzing: text that spells `\e[94m` is plain text, not an escape, in a snapshot too.
    let mut t = term(1, 2);
    t.feed(b"x\\e[94m4b5\r\nbrolled\\e[m");
    assert_eq!(rebuilt(&t, usize::MAX).dump(), t.dump());
}
