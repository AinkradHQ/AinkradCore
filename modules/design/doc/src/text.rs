//! Text offsets (V2-04). The engine, Skia paragraph and `NSTextInputClient` all count UTF-16 code units; yrs here
//! counts bytes (`OffsetKind::Bytes`, the default). A `splice` op carries UTF-16 offsets and is turned into bytes
//! against the text it was checked on.

/// The byte offset of UTF-16 offset `u` in `s`, or `None` past the end or inside a character (a surrogate pair).
pub fn byte_of_utf16(s: &str, u: usize) -> Option<usize> {
    let mut n = 0;
    for (b, c) in s.char_indices() {
        if n == u {
            return Some(b);
        }
        n += c.len_utf16();
        if n > u {
            return None;
        }
    }
    (n == u).then_some(s.len())
}

/// `cur` with UTF-16 range `at..at+del` replaced by `ins`: (byte start, byte end, the result).
pub(crate) fn spliced(cur: &str, at: u32, del: u32, ins: &str) -> Option<(usize, usize, String)> {
    let a = byte_of_utf16(cur, at as usize)?;
    let b = byte_of_utf16(cur, at.checked_add(del)? as usize)?;
    Some((a, b, [&cur[..a], ins, &cur[b..]].concat()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, Live, Op};
    use design_model::NodeType;
    use serde_json::Map as JMap;

    const PAGE: &str = "n_aaaaaaaaaaaa";
    const T: &str = "n_tttttttttttt";

    fn live(text: &str) -> Live {
        let mut l = Live::new();
        let add = |id: &str, ty, parent: Option<&str>, text: Option<&str>| Op::Add {
            id: id.into(),
            ty,
            parent: parent.map(Into::into),
            order: "a".into(),
            name: String::new(),
            props: JMap::new(),
            text: text.map(Into::into),
        };
        l.apply_ops(&[
            add(PAGE, NodeType::Page, None, None),
            add(T, NodeType::Text, Some(PAGE), Some(text)),
        ])
        .unwrap();
        l
    }

    fn splice(at: u32, del: u32, text: &str) -> Op {
        Op::Splice {
            id: T.into(),
            at,
            del,
            text: text.into(),
        }
    }

    fn text(l: &Live) -> String {
        l.read().nodes[T].text.clone().unwrap()
    }

    #[test]
    fn utf16_offsets_map_to_bytes_and_never_split_a_character() {
        let s = "a日😀b";
        assert_eq!(byte_of_utf16(s, 0), Some(0));
        assert_eq!(byte_of_utf16(s, 1), Some(1));
        assert_eq!(byte_of_utf16(s, 2), Some(4), "after 日 (3 bytes, 1 unit)");
        assert_eq!(byte_of_utf16(s, 3), None, "inside the surrogate pair");
        assert_eq!(byte_of_utf16(s, 4), Some(8));
        assert_eq!(byte_of_utf16(s, 5), Some(9));
        assert_eq!(byte_of_utf16(s, 6), None, "past the end");
        assert_eq!(byte_of_utf16("", 0), Some(0));
    }

    #[test]
    fn splices_edit_cjk_emoji_and_rtl_text_and_sync_to_a_peer() {
        let mut a = live("hello");
        let mut b = Live::new();
        b.apply_remote(&a.outbox(true)).unwrap();
        // 👩‍💻 is U+1F469 U+200D U+1F4BB: 2 + 1 + 2 UTF-16 units
        for op in [
            splice(5, 0, " 日本語"),
            splice(0, 0, "👩‍💻 "),
            splice(6, 0, "مرحبا "),
            splice(0, 6, ""),
            splice(0, 0, "😀"),
        ] {
            let mut m = a.read();
            a.apply_typing(&mut m, &[op], false).unwrap();
        }
        assert_eq!(text(&a), "😀مرحبا hello 日本語");
        b.apply_remote(&a.outbox(true)).unwrap();
        assert_eq!(b.read(), a.read());
        assert_eq!(a.shadow_misses() + b.shadow_misses(), 0);
        let mut m = a.read();
        assert!(
            matches!(
                a.apply_typing(&mut m, &[splice(1, 0, "x")], false),
                Err(Error::Refused(_))
            ),
            "inside 😀"
        );
        let mut m = a.read();
        assert!(
            matches!(
                a.apply_typing(&mut m, &[splice(0, 0, "\u{202E}")], false),
                Err(Error::Refused(_))
            ),
            "bidi override characters are refused"
        );
        let mut m = a.read();
        assert!(matches!(
            a.apply_typing(&mut m, &[splice(0, 999, "")], false),
            Err(Error::Refused(_))
        ));
    }

    #[test]
    fn two_people_typing_in_one_label_keep_both() {
        let mut a = live("ab");
        let mut b = Live::new();
        b.apply_remote(&a.outbox(true)).unwrap();
        let mut m = a.read();
        a.apply_typing(&mut m, &[splice(1, 0, "X")], false).unwrap();
        let mut m = b.read();
        b.apply_typing(&mut m, &[splice(2, 0, "Y")], false).unwrap();
        let (ua, ub) = (a.outbox(true), b.outbox(true));
        a.apply_remote(&ub).unwrap();
        b.apply_remote(&ua).unwrap();
        assert_eq!(text(&a), "aXbY");
        assert_eq!(text(&b), "aXbY");
    }

    #[test]
    fn a_typed_run_is_one_undo_step_and_other_edits_are_their_own() {
        let mut l = live("");
        for (i, c) in "word".chars().enumerate() {
            let mut m = l.read();
            l.apply_typing(&mut m, &[splice(i as u32, 0, &c.to_string())], i > 0)
                .unwrap();
        }
        let set = Op::Set {
            id: T.into(),
            key: "w".into(),
            value: serde_json::json!(40),
        };
        l.apply_ops(std::slice::from_ref(&set)).unwrap();
        let mut m = l.read();
        l.apply_typing(&mut m, &[splice(4, 0, "s")], false).unwrap();
        assert!(l.undo());
        assert_eq!(text(&l), "word", "the new run");
        assert!(l.undo());
        assert!(!l.read().nodes[T].props.contains_key("w"), "the set");
        assert!(l.undo());
        assert_eq!(text(&l), "", "the whole word at once");
    }
}
