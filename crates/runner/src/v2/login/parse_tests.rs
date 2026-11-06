//! KAN-441 L2 (L4, runner part): the parser on what a terminal does to text, and redaction.

use super::parse::{Screen, asks_for_code, find_token, find_url, redact};
use super::tests::{CODE, TOKEN, URL};

#[test]
fn redact_masks_the_secrets_and_the_key_shape() {
    let s = format!("bad {CODE} and {TOKEN}; sk-ant-api03-ABCdef_12 then {CODE}");
    let r = redact(&s, &[CODE]);
    assert_eq!(
        r,
        "bad [redacted] and [redacted]; [redacted] then [redacted]"
    );
    assert_eq!(redact("nothing here", &["", CODE]), "nothing here");
}

// ---- the parser --------------------------------------------------------------------------

fn lines(cols: usize, chunks: &[&[u8]]) -> Vec<String> {
    let mut s = Screen::new(cols);
    for c in chunks {
        s.feed(c);
    }
    s.flush();
    s.done().to_vec()
}

#[test]
fn a_url_wrapped_by_the_terminal_is_joined() {
    let text = format!("Visit this URL: {URL}{URL}");
    let mut out = String::new();
    for c in text.as_bytes().chunks(40) {
        out.push_str(std::str::from_utf8(c).unwrap());
        out.push_str("\r\n");
    }
    out.push_str("Paste code here > ");
    let l = lines(40, &[out.as_bytes()]);
    assert_eq!(find_url(&l).unwrap(), format!("{URL}{URL}"));
    // The next line, with spaces in it, is its own.
    assert!(l.iter().any(|l| l.starts_with("Paste")));
}

#[test]
fn ansi_codes_cr_and_reads_cut_anywhere() {
    let raw =
        format!("\x1b[?25l\x1b]0;title\x07\x1b[38;5;12m{URL}\x1b[0m\r\n\x1b(B\r\x1b[Kdone\r\n");
    let whole = lines(500, &[raw.as_bytes()]);
    assert_eq!(whole[0], URL);
    let bytes: Vec<&[u8]> = raw.as_bytes().chunks(1).collect();
    assert_eq!(lines(500, &bytes), whole);
    // A lone CR sends the cursor home: the redraw wins.
    assert_eq!(lines(500, &[b"old text\rnew\r\n"]), ["new"]);
}

#[test]
fn the_token_is_found_across_lines_and_reads_and_short_ones_are_not() {
    let (a, b) = TOKEN.split_at(25);
    let l = lines(500, &[a.as_bytes(), b"", b.as_bytes(), b"\r\n"]);
    assert_eq!(find_token(&l).unwrap().as_str(), TOKEN);
    let wrapped = lines(26, &[format!("{a}\r\n{b}\r\n").as_bytes()]);
    assert_eq!(find_token(&wrapped).unwrap().as_str(), TOKEN);
    assert!(find_token(&lines(500, &[b"sk-ant-oat01-short\r\n"])).is_none());
    assert!(
        find_token(&lines(
            500,
            &[b"sk-ant-api03-0123456789012345678901234567890\r\n"]
        ))
        .is_none()
    );
}

#[test]
fn prompts_are_told_from_the_url_line() {
    let l = vec![format!("{URL}&code=true")];
    assert!(!asks_for_code(&l, ""));
    for p in [
        "Paste code here if prompted > ",
        "Enter the code:",
        "Paste the code",
    ] {
        assert!(asks_for_code(&l, p), "{p}");
    }
    assert!(!asks_for_code(&l, "Waiting..."));
}

#[test]
fn a_screen_wipes_what_it_held() {
    let mut s = Screen::new(500);
    s.feed(format!("{TOKEN}\r\npartial").as_bytes());
    assert!(find_token(s.done()).is_some());
    s.wipe();
    assert!(s.done().is_empty() && s.tail().is_empty());
}
