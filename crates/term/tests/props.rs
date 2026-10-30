//! Property tests: any stream, any chunking, any snapshot point.

use ainkrad_term::{Attach, Limits, ScreenSink, Size, Terminal};
use proptest::prelude::*;

/// Terminal-ish tokens: text (incl. wide and combining), controls, and the sequences full-screen
/// apps use. Raw random bytes are covered by the fuzz target; these reach deep states.
fn token() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        4 => "[a-z0-9 ]{1,12}".prop_map(String::into_bytes),
        1 => prop::sample::select(vec!["漢", "字", "e\u{301}", "😀", "ｱ"]).prop_map(|s| s.as_bytes().to_vec()),
        2 => prop::sample::select(vec!["\r\n", "\n", "\r", "\t", "\x08", "\x07"]).prop_map(|s| s.as_bytes().to_vec()),
        1 => (1u16..30, 1u16..90).prop_map(|(r, c)| format!("\x1b[{r};{c}H").into_bytes()),
        1 => prop::sample::select(vec![
            "\x1b[K", "\x1b[1K", "\x1b[2K", "\x1b[J", "\x1b[1J", "\x1b[2J", "\x1b[3@", "\x1b[2P",
            "\x1b[2L", "\x1b[M", "\x1b[2S", "\x1b[T", "\x1bM", "\x1b[5X", "\x1b[3A", "\x1b[2B",
            "\x1b[4C", "\x1b[D", "\x1b[1;31m", "\x1b[0m", "\x1b[7m", "\x1b[38;5;200m",
            "\x1b[48;2;1;2;3m", "\x1b[?25l", "\x1b[?25h", "\x1b[?1h", "\x1b[?2004h", "\x1b[?1000h",
            "\x1b[?1006h", "\x1b=", "\x1b>",
        ]).prop_map(|s| s.as_bytes().to_vec()),
        1 => prop::sample::select(vec!["\x1b[?1049h", "\x1b[?1049l", "\x1b[?47h", "\x1b[?47l", "\x1b7", "\x1b8"])
            .prop_map(|s| s.as_bytes().to_vec()),
    ]
}

fn stream() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(token(), 0..120).prop_map(|t| t.concat())
}

fn size() -> impl Strategy<Value = Size> {
    (1u16..30, 1u16..90).prop_map(|(rows, cols)| Size { rows, cols })
}

fn fed(size: Size, limits: Limits, bytes: &[u8], cuts: &[usize]) -> Terminal {
    let mut t = Terminal::new(size, limits);
    let mut at = 0;
    for &c in cuts {
        let c = c % (bytes.len() + 1);
        if c > at {
            t.feed(&bytes[at..c]);
            at = c;
        }
    }
    t.feed(&bytes[at..]);
    t
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Chunking never changes the result.
    #[test]
    fn chunking_is_invisible(size in size(), s in stream(), mut cuts in prop::collection::vec(any::<usize>(), 0..20)) {
        cuts.sort_unstable();
        let one = fed(size, Limits::default(), &s, &[]);
        let many = fed(size, Limits::default(), &s, &cuts);
        prop_assert_eq!(one.dump(), many.dump());
        prop_assert_eq!(one.head(), s.len() as u64);
    }

    /// The reattach invariant: emu(A ++ B) == emu(snapshot(A) ++ tail-after-snapshot ++ B).
    #[test]
    fn snapshot_then_continue_equals_original(size in size(), s in stream(), cut in any::<usize>(), b in stream()) {
        let cut = cut % (s.len() + 1);
        let mut t = fed(size, Limits::default(), &s[..cut], &[]);
        let snap = t.snapshot(usize::MAX);
        // The documented gap: a blank pending-wrap cell is rebuilt through the DECSC slot.
        let trick: &[u8] = b"\x1b7\x08\x1b[X\x1b8";
        prop_assume!(!snap.bytes.windows(trick.len()).any(|w| w == trick));
        let mut client = Terminal::new(snap.size, Limits::default());
        client.feed(&snap.bytes);
        let Ok(Attach::Replay { bytes, .. }) = t.attach(Some(snap.seq), 0) else {
            return Err(TestCaseError::fail("a snapshot's seq must be replayable"));
        };
        client.feed(&bytes);
        for part in [&s[cut..], &b[..]] {
            t.feed(part);
            client.feed(part);
        }
        prop_assert_eq!(client.dump(), t.dump(), "A {:?} rest {:?} B {:?}", String::from_utf8_lossy(&s[..cut]), String::from_utf8_lossy(&s[cut..]), String::from_utf8_lossy(&b));
    }

    /// Scrollback and the replay window stay within their limits; truncation is explicit.
    #[test]
    fn limits_hold(size in size(), s in stream(), lines in 0usize..50, bytes in 0usize..4000, replay in 1usize..500) {
        let limits = Limits { scrollback_lines: lines, scrollback_bytes: bytes, replay_bytes: replay };
        let t = fed(size, limits, &s, &[]);
        let all = t.scrollback(0..u64::MAX);
        prop_assert!(all.lines.len() <= lines);
        prop_assert!(all.lines.iter().map(String::len).sum::<usize>() <= bytes);
        prop_assert_eq!(all.first, all.held.start);
        prop_assert_eq!(all.held.end - all.held.start, all.lines.len() as u64);
        let w = t.replay_window();
        prop_assert!(w.end - w.start <= replay as u64);
        prop_assert_eq!(w.end, s.len() as u64);
    }

    /// Any resume point: inside the window → exactly the missing bytes; older → a snapshot.
    #[test]
    fn attach_serves_exact_bytes_or_a_snapshot(s in stream(), resume in any::<u64>(), replay in 1usize..300) {
        let limits = Limits { replay_bytes: replay, ..Limits::default() };
        let t = fed(Size { rows: 5, cols: 20 }, limits, &s, &[]);
        let head = s.len() as u64;
        let resume = resume % (head + 2);
        match t.attach(Some(resume), 10) {
            Err(e) => prop_assert!(resume > head && e.head == head),
            Ok(Attach::Replay { from, bytes }) => {
                prop_assert_eq!(from, resume);
                prop_assert_eq!(&bytes[..], &s[resume as usize..]);
            }
            Ok(Attach::Snapshot(snap)) => {
                prop_assert!(resume < t.replay_window().start);
                prop_assert!(snap.seq <= head);
            }
        }
    }

    /// Resizing (also to absurd sizes) keeps the snapshot faithful.
    #[test]
    fn resize_keeps_snapshots_faithful(s in stream(), sizes in prop::collection::vec((0u16..2000, 2u16..2000), 1..4), b in stream()) {
        let mut t = fed(Size { rows: 10, cols: 40 }, Limits::default(), &s, &[]);
        for (rows, cols) in sizes {
            t.resize(Size { rows, cols });
            t.feed(&b);
        }
        let snap = t.snapshot(usize::MAX);
        let mut client = Terminal::new(snap.size, Limits::default());
        client.feed(&snap.bytes);
        // Scrollback rows from a wider screen wrap in the narrower client: same text, other breaks.
        let split = |d: String| {
            let (head, rest) = d.split_once("-- scrollback").unwrap();
            let (lines, screen) = rest.split_once("-- screen").unwrap();
            // Plain text: each wrapped piece repeats its SGR, so drop every `\e[...m`.
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
        };
        prop_assert_eq!(split(client.dump()), split(t.dump()), "snapshot {:?}", String::from_utf8_lossy(&snap.bytes));
    }
}
