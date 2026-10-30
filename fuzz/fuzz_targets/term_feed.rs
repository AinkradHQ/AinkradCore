//! E2-04.5: the terminal emulator's input path (`ainkrad-term`), which takes whatever a child
//! process writes. Any bytes, any chunking, resizes in between: no panic, no hang, and a snapshot
//! taken at the end rebuilds the same screen.
#![no_main]
use ainkrad_term::{Limits, ScreenSink, Size, Terminal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first two bytes pick the size; 0xFF in the stream marks a chunk boundary, and a
    // boundary followed by two bytes `r c` with r < 8 also resizes (small sizes reach edge cases).
    let [rows, cols, rest @ ..] = data else { return };
    let limits = Limits { scrollback_lines: 64, scrollback_bytes: 4096, replay_bytes: 1024 };
    let mut t = Terminal::new(Size { rows: u16::from(rows % 40), cols: u16::from(cols % 120) }, limits);
    for chunk in rest.split(|&b| b == 0xff) {
        match chunk {
            [r, c, tail @ ..] if *r < 8 => {
                t.resize(Size { rows: u16::from(*r) * 5, cols: u16::from(*c % 120) });
                t.feed(tail);
            }
            _ => {
                t.feed(chunk);
            }
        }
    }
    let snap = t.snapshot(usize::MAX);
    let mut again = Terminal::new(snap.size, limits);
    again.feed(&snap.bytes);
    assert_eq!(again.dump(), t.dump());
});
