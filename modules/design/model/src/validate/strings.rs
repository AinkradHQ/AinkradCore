//! Name and text charsets.

use super::R;
use crate::limits::*;

/// Unicode format characters (category Cf): invisible, and they reorder or hide text (bidi overrides, zero-width
/// spaces, BOM, tag characters). Also the line/paragraph separators, which are not control characters in Rust.
pub fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x8E2 | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
        | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD
        | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

// HTML export (V6-03) must escape names and text: they are validated as printable, not as markup-safe.
/// A node name: 0..=100 characters, no control or format characters.
pub fn name_str(s: &str) -> R {
    if s.chars().count() > MAX_NAME_CHARS || s.chars().any(|c| c.is_control() || is_format_char(c))
    {
        return Err("name: 0..=100 printable characters".into());
    }
    Ok(())
}

pub fn text_str(s: &str) -> R {
    if s.chars().count() > MAX_TEXT_CHARS {
        return Err("text too long".into());
    }
    // ZWJ and ZWNJ are allowed: emoji sequences and several scripts need them.
    if s.chars().any(|c| {
        (c.is_control() && c != '\n' && c != '\t')
            || (is_format_char(c) && c != '\u{200C}' && c != '\u{200D}')
    }) {
        return Err("control and invisible formatting characters are not allowed".into());
    }
    Ok(())
}
