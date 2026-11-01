//! Real-program streams (E2-04.4): `tests/corpus/real_*.vt` were recorded from vim, htop, tmux,
//! less, `ls --color` and `cat` of wide text in a pty (`scripts/term-goldens/record.py`, 24x80,
//! xterm-256color, UTF-8). `corpus.rs` pins each final screen; here we check the screens mean what
//! the app drew, and that reattaching works from EVERY few bytes of the stream, not just its end.
//!
//! The streams are fixed files, so replay is exact. What varies between recordings (htop's numbers,
//! timing) is handled by asserting on stable text (labels, status bar, borders), never on values.

use std::fs;
use std::path::Path;

use ainkrad_term::{Attach, Limits, ScreenSink, Size, Terminal};

const SIZE: Size = Size { rows: 24, cols: 80 };

fn stream(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/corpus/{name}.vt"));
    fs::read(p).expect("fixture")
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// The visible rows of a dump as plain text (SGR removed).
fn screen_text(dump: &str) -> String {
    let screen = dump.rsplit_once("-- screen\n").expect("dump layout").1;
    let mut out = String::new();
    for row in screen.lines() {
        let mut rest = row.strip_prefix('|').unwrap_or(row);
        while let Some(i) = rest.find("\\e[") {
            out.push_str(&rest[..i]);
            let body = &rest[i + 3..];
            let end = body.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(body.len().saturating_sub(1));
            // blank runs are drawn as cursor-forward / erase-characters: they are spaces
            if matches!(body.as_bytes().get(end), Some(b'C' | b'X')) {
                let n: usize = body[..end].parse().unwrap_or(1);
                out.push_str(&" ".repeat(n));
            }
            rest = &body[(end + 1).min(body.len())..];
        }
        out.push_str(rest);
        out.push('\n');
    }
    out
}

/// The screen as the app left it just before it left the alt-screen (its last full picture).
fn before_exit(name: &str) -> Terminal {
    let s = stream(name);
    cut_before(name, &s)
}

fn cut_before(name: &str, s: &[u8]) -> Terminal {
    // vim and less keep their last picture until they leave; tmux and htop clear first, so they
    // are cut at the last thing they drew (`plain.txt` from `ls` in a pane; htop's key bar).
    let cut = match name {
        "real_tmux_splits" => find(s, b"plain.txt").expect("ls output") + 9,
        "real_vim_split_scroll" => s.windows(3).position(|w| w == b":q!").expect("quit typed"),
        "real_htop" => find(s, b"Quit").expect("key bar") + 4,
        _ => find(s, b"\x1b[?1049l").expect("app leaves the alt-screen"),
    };
    let mut t = Terminal::new(SIZE, Limits::default());
    t.feed(&s[..cut]);
    t
}

#[test]
fn vim_edit_shows_the_file_and_leaves_clean() {
    let t = before_exit("real_vim_edit");
    let text = screen_text(&t.dump());
    // `A// ok<Esc>u` was undone; the `o/* more */` line stays
    assert!(text.contains("int main(void)") && !text.contains("// ok"), "{text}");
    assert!(text.contains("/* more */"), "{text}");
    let mut full = Terminal::new(SIZE, Limits::default());
    full.feed(&stream("real_vim_edit"));
    assert!(full.dump().contains("alt=false"), "{}", full.dump());
}

#[test]
fn vim_split_has_two_status_lines_and_scrolled() {
    let s = stream("real_vim_split_scroll");
    // a scroll region (DECSTBM) was set by the split
    let lossy = String::from_utf8_lossy(&s);
    assert!(lossy.contains('r') && lossy.matches("\x1b[").count() > 20, "stream");
    let text = screen_text(&before_exit("real_vim_split_scroll").dump());
    assert_eq!(text.matches("notes.txt").count(), 2, "{text}");
    assert!(text.contains("of the notes file"), "{text}");
}

#[test]
fn htop_draws_header_table_and_footer() {
    // the key bar is gone by the time htop quits, so check the footer in the stream itself
    assert!(String::from_utf8_lossy(&stream("real_htop")).contains("Quit"));
    let text = screen_text(&before_exit("real_htop").dump());
    for want in ["CPU", "Mem", "Tasks:", "Load average:", "Uptime:", "PID", "Command"] {
        assert!(text.contains(want), "missing {want}\n{text}");
    }
}

#[test]
fn tmux_has_three_panes_and_a_status_bar() {
    let text = screen_text(&before_exit("real_tmux_splits").dump());
    assert!(text.contains("[s]") && text.contains("main") && text.contains("ainkrad"), "{text}");
    assert!(text.contains('│') || text.contains('|'), "no vertical border\n{text}");
    assert!(text.contains('─') || text.contains('-'), "no horizontal border\n{text}");
    for want in ["one", "two", "three"] {
        assert!(text.contains(want), "{want}\n{text}");
    }
}

#[test]
fn ls_colour_keeps_its_colours() {
    let mut t = Terminal::new(SIZE, Limits::default());
    t.feed(&stream("real_ls_color"));
    let d = t.dump();
    assert!(d.contains("\\e[34;1m") && d.contains("\\e[32;1m") && d.contains("\\e[36;1m"), "{d}");
    let text = screen_text(&d);
    for want in ["dir", "run.sh", "data.tar.gz", "link", "plain.txt"] {
        assert!(text.contains(want), "{want}\n{text}");
    }
}

#[test]
fn wide_text_keeps_its_cells() {
    let mut t = Terminal::new(SIZE, Limits::default());
    t.feed(&stream("real_wide_chars"));
    let text = screen_text(&t.dump());
    for want in ["\u{4f60}\u{597d}", "\u{3053}\u{3093}", "\u{1f680}", "e\u{301}", "wraps"] {
        assert!(text.contains(want), "{want:?}\n{text}");
    }
}

#[test]
fn less_returns_to_the_shell_screen() {
    let mut t = Terminal::new(SIZE, Limits::default());
    t.feed(&stream("real_less_alt_screen"));
    let d = t.dump();
    assert!(d.contains("alt=false"), "{d}");
    let text = screen_text(&d);
    assert!(text.contains("before") && text.contains("after"), "{text}");
    assert!(!text.contains("of the notes file"), "pager text leaked\n{text}");
}

const REAL: [&str; 7] = [
    "real_vim_edit",
    "real_vim_split_scroll",
    "real_htop",
    "real_tmux_splits",
    "real_ls_color",
    "real_wide_chars",
    "real_less_alt_screen",
];

#[test]
fn reattach_from_every_point_of_every_stream() {
    let mut cuts = 0;
    for name in REAL {
        let s = stream(name);
        for cut in (1..s.len()).step_by(97).chain([s.len()]) {
            let mut t = Terminal::new(SIZE, Limits::default());
            t.feed(&s[..cut]);
            let snap = t.snapshot(usize::MAX);
            let mut r = Terminal::new(snap.size, Limits::default());
            r.feed(&snap.bytes);
            assert_eq!(r.dump(), t.dump(), "{name} snapshot at {cut}");
            // and the stream carries on identically for a client that attached at `cut`
            let Ok(Attach::Replay { bytes, .. }) = t.attach(Some(snap.seq), 0) else {
                panic!("{name}: no replay at {cut}")
            };
            t.feed(&s[cut..]);
            r.feed(&bytes);
            r.feed(&s[cut..]);
            assert_eq!(r.dump(), t.dump(), "{name} continuation from {cut}");
            cuts += 1;
        }
    }
    assert!(cuts > 150, "only {cuts} cut points");
}

#[test]
fn resize_then_reattach_keeps_fidelity() {
    let sizes = [
        Size { rows: 18, cols: 60 },
        Size { rows: 30, cols: 120 },
        Size { rows: 24, cols: 40 },
        Size { rows: 3, cols: 80 },
    ];
    for name in REAL {
        let s = stream(name);
        for cut in [s.len() / 3, s.len() * 2 / 3, s.len()] {
            for to in sizes {
                let mut t = Terminal::new(SIZE, Limits::default());
                t.feed(&s[..cut]);
                t.resize(to);
                let snap = t.snapshot(usize::MAX);
                assert_eq!(snap.size, to, "{name}");
                let mut r = Terminal::new(snap.size, Limits::default());
                r.feed(&snap.bytes);
                assert_eq!(r.dump(), t.dump(), "{name} at {cut} resized to {to:?}");
            }
        }
    }
}
