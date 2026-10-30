//! E2-04.5: the terminal emulator's input path (`ainkrad-term`), which takes whatever a child
//! process writes. Any bytes, any chunking, resizes in between: no panic, no hang, and a snapshot
//! taken at the end rebuilds the same screens and scrollback text.
#![no_main]
use ainkrad_term::{Limits, ScreenSink, Size, Terminal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first two bytes pick the size; 0xFF in the stream marks a chunk boundary, and a
    // boundary followed by two bytes `r c` with r < 8 also resizes (small sizes reach edge cases).
    let [rows, cols, rest @ ..] = data else { return };
    let limits = Limits { scrollback_lines: 64, scrollback_bytes: 4096, replay_bytes: 1024 };
    let mut t = Terminal::new(Size { rows: u16::from(rows % 40), cols: u16::from(cols % 120).max(2) }, limits);
    for chunk in rest.split(|&b| b == 0xff) {
        match chunk {
            [r, c, tail @ ..] if *r < 8 => {
                t.resize(Size { rows: u16::from(*r) * 5, cols: u16::from(*c % 120).max(2) });
                t.feed(tail);
            }
            _ => {
                t.feed(chunk);
            }
        }
    }
    let snap = t.snapshot(usize::MAX);
    // The rebuilt view keeps every line: rewrapped rows (below) may outnumber the original's.
    let unbounded = Limits { scrollback_lines: usize::MAX, scrollback_bytes: usize::MAX, ..limits };
    let mut again = Terminal::new(snap.size, unbounded);
    again.feed(&snap.bytes);
    assert_eq!(normal(&again.dump()), normal(&t.dump()));
});

/// A dump with the scrollback reduced to its plain text: rows kept from a wider screen wrap in
/// a narrower client (documented), so only the line breaks and repeated SGR may differ there.
/// Widths start at 2: a wide character cannot be shown at width 1 at all.
fn normal(dump: &str) -> (String, String, String) {
    let (head, rest) = dump.split_once("-- scrollback").expect("dump layout");
    let (lines, screen) = rest.split_once("-- screen").expect("dump layout");
    let mut text = String::new();
    for l in lines.lines().skip(1) {
        let mut rest = l;
        while let Some(i) = rest.find("\\e[") {
            text.push_str(&rest[..i]);
            rest = rest[i..].split_once('m').map_or("", |(_, r)| r);
        }
        text.push_str(rest);
    }
    (head.to_owned(), text, screen.to_owned())
}
