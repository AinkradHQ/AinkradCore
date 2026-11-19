//! `Terminal::tail`: the last visible rows as plain text, for a live preview.

use ainkrad_term::{Limits, ScreenSink, Size, Terminal};

fn term(bytes: &[u8]) -> Terminal {
    let mut t = Terminal::new(Size { rows: 6, cols: 20 }, Limits::default());
    t.feed(bytes);
    t
}

#[test]
fn the_last_non_empty_rows_come_back_as_plain_text() {
    let t = term(b"one\r\n\x1b[31mtwo\x1b[m  \r\nthree\r\n");
    assert_eq!(t.tail(2), ["two", "three"]);
    assert_eq!(t.tail(20), ["one", "two", "three"]);
    assert!(t.tail(0).is_empty());
}

#[test]
fn an_empty_screen_has_no_rows() {
    assert!(term(b"").tail(5).is_empty());
}
