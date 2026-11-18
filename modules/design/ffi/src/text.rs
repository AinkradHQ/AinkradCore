//! Text editing state (V2-04), pure: one editing session on one text node, the caret/selection math and IME
//! composition. Offsets are UTF-16 code units, as `NSTextInputClient` and Skia paragraph count them; every offset
//! from the App is clamped to the text and snapped to a grapheme boundary here, so an edit never splits a character,
//! a surrogate pair or an emoji sequence.
//!
//! Marked text (an IME composition) is local: it is drawn in place but never written to the document; only the
//! committed string goes in, as one `splice` op. Ranges the App sees are in the composed text (the base text with
//! the marked text in place), as Cocoa's text system reports them.

use unicode_segmentation::UnicodeSegmentation;

pub(crate) fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Grapheme boundaries of `s` in UTF-16 (0 and the length included).
fn bounds(s: &str) -> Vec<usize> {
    let mut v = vec![0];
    let mut n = 0;
    for g in s.graphemes(true) {
        n += len16(g);
        v.push(n);
    }
    v
}

/// The boundary at or before `u` (clamped to the text).
pub(crate) fn snap(s: &str, u: usize) -> usize {
    let b = bounds(s);
    b[b.partition_point(|x| *x <= u) - 1]
}

/// The boundary at or after `u` (clamped to the text).
fn snap_up(s: &str, u: usize) -> usize {
    let b = bounds(s);
    b.get(b.partition_point(|x| *x < u))
        .copied()
        .unwrap_or(*b.last().unwrap_or(&0))
}

pub(crate) fn next(s: &str, u: usize) -> usize {
    snap_up(s, u + 1)
}

pub(crate) fn prev(s: &str, u: usize) -> usize {
    snap(s, u.saturating_sub(1))
}

/// Words (runs holding a letter or digit) as UTF-16 ranges.
fn words(s: &str) -> Vec<(usize, usize)> {
    let mut v = vec![];
    let mut n = 0;
    for w in s.split_word_bounds() {
        let l = len16(w);
        if w.chars().any(char::is_alphanumeric) {
            v.push((n, n + l));
        }
        n += l;
    }
    v
}

/// ⌥→: the end of the word the caret is in or the next one.
fn word_right(s: &str, u: usize) -> usize {
    words(s)
        .into_iter()
        .find(|w| w.1 > u)
        .map_or(len16(s), |w| w.1)
}

/// ⌥←: the start of the word the caret is in or the one before.
fn word_left(s: &str, u: usize) -> usize {
    words(s)
        .into_iter()
        .rev()
        .find(|w| w.0 < u)
        .map_or(0, |w| w.0)
}

/// `s` with UTF-16 range `a..b` (boundaries) replaced by `ins`.
fn splice(s: &str, a: usize, b: usize, ins: &str) -> String {
    let at = |u| design_doc::byte_of_utf16(s, u).unwrap_or(s.len());
    [&s[..at(a)], ins, &s[at(b)..]].concat()
}

/// Map offset `o` of `old` into `new` (an edit by someone else, or an undo): the common prefix and suffix stay put,
/// an offset inside the changed part goes to its end.
/// ponytail: a prefix/suffix diff, ambiguous only when the change sits in a repeated run; yrs sticky indices if needed
fn rebase_offset(old: &[u16], new: &[u16], o: usize) -> usize {
    let p = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let room = old.len().min(new.len()) - p;
    let sfx = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(room)
        .take_while(|(a, b)| a == b)
        .count();
    if o <= p {
        o
    } else if o >= old.len() - sfx {
        o + new.len() - old.len()
    } else {
        new.len() - sfx
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Marked {
    /// where in the base text it sits, and how many base units it hides (the selection it replaces)
    pub at: usize,
    pub replaced: usize,
    pub text: String,
    /// the IME's selection inside `text`
    pub sel: (usize, usize),
}

/// What a typing batch is, for undo grouping: a run of one kind is one undo step.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    Insert,
    Delete,
}

/// One splice to write: base range `at..at+del` -> `text`, then the caret at `caret`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Edit {
    pub at: usize,
    pub del: usize,
    pub text: String,
    pub caret: usize,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Session {
    pub id: String,
    /// the node's text as last read or written
    pub base: String,
    /// base offsets (when nothing is marked)
    pub anchor: usize,
    pub focus: usize,
    pub marked: Option<Marked>,
    /// the kind of the last committed batch, while the caret has not moved since
    pub last: Option<Kind>,
    /// a pointer drag is selecting
    pub selecting: bool,
    /// ↑/↓ keep the column they started from
    pub goal_x: Option<f32>,
}

impl Session {
    pub fn new(id: String, base: String, caret: usize) -> Session {
        let c = snap(&base, caret);
        Session {
            id,
            base,
            anchor: c,
            focus: c,
            marked: None,
            last: None,
            selecting: false,
            goal_x: None,
        }
    }

    pub fn composed(&self) -> String {
        match &self.marked {
            Some(m) => splice(&self.base, m.at, m.at + m.replaced, &m.text),
            None => self.base.clone(),
        }
    }

    /// The selection in the composed text, ordered.
    pub fn sel(&self) -> (usize, usize) {
        match &self.marked {
            Some(m) => (m.at + m.sel.0, m.at + m.sel.1),
            None => (self.anchor.min(self.focus), self.anchor.max(self.focus)),
        }
    }

    /// The marked range in the composed text.
    pub fn marked_range(&self) -> Option<(usize, usize)> {
        self.marked.as_ref().map(|m| (m.at, m.at + len16(&m.text)))
    }

    /// A base range from the App (`None` = the selection), clamped and widened to grapheme boundaries.
    fn range(&self, r: Option<(usize, usize)>) -> (usize, usize) {
        match r {
            Some((a, b)) => {
                let b = snap_up(&self.base, b.max(a));
                (snap(&self.base, a), b)
            }
            None => self.sel(),
        }
    }

    /// `insertText`: replaces the marked text if there is any, else `rep` or the selection.
    pub fn insert(&mut self, text: &str, rep: Option<(usize, usize)>) -> Option<Edit> {
        let (at, del) = match self.marked.take() {
            Some(m) => (m.at, m.replaced),
            None => {
                let (a, b) = self.range(rep);
                (a, b - a)
            }
        };
        if text.is_empty() && del == 0 {
            self.move_to(at, false);
            return None;
        }
        Some(Edit {
            at,
            del,
            text: text.to_string(),
            caret: at + len16(text),
            kind: if text.is_empty() {
                Kind::Delete
            } else {
                Kind::Insert
            },
        })
    }

    /// `setMarkedText`: `sel` is inside `text`, `rep` a base range (used only when nothing is marked yet). An empty
    /// `text` ends the composition; whatever it replaced is deleted (Cocoa removed it when the composition began).
    pub fn set_marked(
        &mut self,
        text: &str,
        sel: (usize, usize),
        rep: Option<(usize, usize)>,
    ) -> Option<Edit> {
        let (at, replaced) = match &self.marked {
            Some(m) => (m.at, m.replaced),
            None => {
                let (a, b) = self.range(rep);
                (a, b - a)
            }
        };
        self.last = None;
        if text.is_empty() {
            self.marked = None;
            self.move_to(at, false);
            return (replaced > 0).then(|| Edit {
                at,
                del: replaced,
                text: String::new(),
                caret: at,
                kind: Kind::Delete,
            });
        }
        let s0 = snap(text, sel.0);
        let s1 = snap(text, sel.1.max(sel.0)).max(s0);
        self.marked = Some(Marked {
            at,
            replaced,
            text: text.to_string(),
            sel: (s0, s1),
        });
        self.anchor = at;
        self.focus = at;
        None
    }

    /// `unmarkText`: the composition goes in as typed.
    pub fn unmark(&mut self) -> Option<Edit> {
        let m = self.marked.as_ref()?;
        let t = m.text.clone();
        self.insert(&t, None)
    }

    /// After `e` was written: the new base text and caret.
    pub fn applied(&mut self, e: &Edit) {
        self.base = splice(&self.base, e.at, e.at + e.del, &e.text);
        self.marked = None;
        self.anchor = e.caret;
        self.focus = e.caret;
        self.last = Some(e.kind);
        self.goal_x = None;
    }

    pub fn move_to(&mut self, u: usize, extend: bool) {
        let u = snap(&self.base, u);
        self.focus = u;
        if !extend {
            self.anchor = u;
        }
        self.last = None;
        self.goal_x = None;
    }

    /// ←/→ (`word` = ⌥): a selection collapses to its side first, as on the Mac.
    pub fn step(&mut self, right: bool, word: bool, extend: bool) {
        let (a, b) = self.sel();
        if !extend && a != b && !word {
            self.move_to(if right { b } else { a }, false);
            return;
        }
        let s = &self.base;
        let to = match (right, word) {
            (true, false) => next(s, self.focus),
            (false, false) => prev(s, self.focus),
            (true, true) => word_right(s, self.focus),
            (false, true) => word_left(s, self.focus),
        };
        self.move_to(to, extend);
    }

    /// ⌫ / ⌦ (`word` = ⌥): the selection, else one grapheme or word.
    pub fn delete(&mut self, forward: bool, word: bool) -> Option<Edit> {
        let (a, b) = self.sel();
        let s = &self.base;
        let (a, b) = match (a != b, forward, word) {
            (true, ..) => (a, b),
            (false, true, false) => (a, next(s, a)),
            (false, false, false) => (prev(s, a), a),
            (false, true, true) => (a, word_right(s, a)),
            (false, false, true) => (word_left(s, a), a),
        };
        (a < b).then(|| Edit {
            at: a,
            del: b - a,
            text: String::new(),
            caret: a,
            kind: Kind::Delete,
        })
    }

    pub fn select_all(&mut self) {
        self.anchor = 0;
        self.focus = len16(&self.base);
        self.last = None;
    }

    /// The node's text changed under the session (someone else, an undo): keep the caret on the same characters.
    pub fn rebase(&mut self, new: &str) {
        if new == self.base {
            return;
        }
        let (o, n): (Vec<u16>, Vec<u16>) = (
            self.base.encode_utf16().collect(),
            new.encode_utf16().collect(),
        );
        let map = |u: usize| snap(new, rebase_offset(&o, &n, u));
        self.anchor = map(self.anchor);
        self.focus = map(self.focus);
        if let Some(m) = &mut self.marked {
            let end = map(m.at + m.replaced);
            m.at = map(m.at);
            m.replaced = end.saturating_sub(m.at);
        }
        self.base = new.to_string();
        self.last = None;
        self.goal_x = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(base: &str, caret: usize) -> Session {
        Session::new("n_tttttttttttt".into(), base.into(), caret)
    }

    fn commit(s: &mut Session, e: Option<Edit>) {
        let e = e.expect("an edit");
        s.applied(&e);
    }

    #[test]
    fn carets_step_over_whole_graphemes() {
        // e + combining acute, a flag (two regional indicators), a ZWJ family, CJK
        let t = "e\u{301}🇯🇵👨‍👩‍👧日";
        assert_eq!(bounds(t), vec![0, 2, 6, 14, 15]);
        assert_eq!(next(t, 0), 2);
        assert_eq!(next(t, 2), 6);
        assert_eq!(next(t, 6), 14);
        assert_eq!(prev(t, 14), 6);
        assert_eq!(prev(t, 0), 0);
        assert_eq!(next(t, 15), 15);
        assert_eq!(snap(t, 9), 6, "inside the family snaps back");
        assert_eq!(snap(t, 99), 15, "clamped");
        assert_eq!(snap_up(t, 9), 14);
    }

    #[test]
    fn words_selection_and_collapse() {
        let mut x = s("hello, big world", 0);
        x.step(true, true, false);
        assert_eq!(x.sel(), (5, 5), "end of hello");
        x.step(true, true, true);
        assert_eq!(x.sel(), (5, 10), "extends over , big");
        x.step(false, false, false);
        assert_eq!(x.sel(), (5, 5), "← collapses to the left side");
        x.step(false, true, false);
        assert_eq!(x.sel(), (0, 0));
        x.select_all();
        assert_eq!(x.sel(), (0, 16));
    }

    #[test]
    fn typing_and_deleting_rtl_text() {
        let mut x = s("", 0);
        for c in ["س", "ل", "ا", "م"] {
            let e = x.insert(c, None);
            commit(&mut x, e);
        }
        assert_eq!(x.base, "سلام");
        assert_eq!(
            x.sel(),
            (4, 4),
            "logical order: the caret follows the last letter"
        );
        let e = x.delete(false, false);
        commit(&mut x, e);
        assert_eq!(x.base, "سلا");
        assert_eq!(x.last, Some(Kind::Delete));
        let e = x.delete(false, true);
        commit(&mut x, e);
        assert_eq!(x.base, "");
        assert_eq!(x.delete(false, false), None, "nothing to delete");
    }

    #[test]
    fn deleting_an_emoji_removes_the_whole_sequence() {
        let mut x = s("a👩‍💻b", 6);
        let e = x.delete(false, false);
        assert_eq!(e.as_ref().map(|e| (e.at, e.del)), Some((1, 5)));
        commit(&mut x, e);
        assert_eq!(x.base, "ab");
        // a replacement range from the App that cuts into a grapheme is widened to it
        let mut x = s("a👩‍💻b", 0);
        let e = x.insert("X", Some((2, 3)));
        assert_eq!(e.as_ref().map(|e| (e.at, e.del)), Some((1, 5)));
    }

    #[test]
    fn a_cjk_composition_is_local_until_committed() {
        // Japanese: type "nihon", the IME shows にほん, converts to 日本, the user confirms
        let mut x = s("A", 1);
        assert_eq!(x.set_marked("に", (1, 1), None), None);
        assert_eq!(x.set_marked("にほん", (3, 3), None), None);
        assert_eq!(x.composed(), "Aにほん");
        assert_eq!(x.base, "A", "nothing written yet");
        assert_eq!(x.marked_range(), Some((1, 4)));
        assert_eq!(x.sel(), (4, 4));
        // conversion: the IME selects the whole clause
        x.set_marked("日本", (0, 2), None);
        assert_eq!(x.sel(), (1, 3));
        let e = x.insert("日本", None).unwrap();
        assert_eq!((e.at, e.del, e.text.as_str(), e.caret), (1, 0, "日本", 3));
        commit(&mut x, Some(e));
        assert_eq!(x.base, "A日本");
        assert_eq!(x.marked_range(), None);
        assert_eq!(x.sel(), (3, 3));
    }

    #[test]
    fn a_composition_replaces_the_selection_and_can_be_cancelled_or_unmarked() {
        let mut x = s("hello world", 0);
        x.anchor = 6;
        x.focus = 11;
        x.set_marked("ㅎ", (1, 1), None);
        assert_eq!(x.composed(), "hello ㅎ");
        x.set_marked("한", (1, 1), None);
        let e = x.unmark();
        commit(&mut x, e);
        assert_eq!(x.base, "hello 한");
        // cancelled (Escape in the IME): the selection it replaced is gone, as in Cocoa
        let mut x = s("abc", 0);
        x.anchor = 0;
        x.focus = 2;
        x.set_marked("x", (1, 1), None);
        let e = x.set_marked("", (0, 0), None);
        assert_eq!(e.as_ref().map(|e| (e.at, e.del)), Some((0, 2)));
        // emoji picker / dictation: a plain insert of a long string with a replacement range
        let mut x = s("say ", 4);
        let e = x.insert("hello 😀", Some((4, 4)));
        commit(&mut x, e);
        assert_eq!(x.base, "say hello 😀");
        assert_eq!(x.sel(), (12, 12));
        // a marked selection past its text is clamped
        x.set_marked("ab", (9, 99), None);
        assert_eq!(x.marked.as_ref().unwrap().sel, (2, 2));
    }

    #[test]
    fn the_caret_follows_its_characters_when_the_text_changes_underneath() {
        let mut x = s("hello world", 6);
        x.rebase(">> hello world");
        assert_eq!(x.sel(), (9, 9), "an insert before the caret");
        x.rebase(">> hello world!");
        assert_eq!(x.sel(), (9, 9), "an insert after it");
        x.rebase("hello");
        assert_eq!(
            x.sel(),
            (5, 5),
            "its characters went: the end of the change"
        );
        let mut x = s("ab😀", 2);
        x.set_marked("x", (1, 1), None);
        x.rebase("Zab😀");
        assert_eq!(x.marked.as_ref().map(|m| m.at), Some(3));
        assert_eq!(x.composed(), "Zabx😀");
    }
}
