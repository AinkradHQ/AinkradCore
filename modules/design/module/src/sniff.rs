//! File type by magic bytes (T8 allow-list). The client's own content type is never consulted.

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Class {
    Image,
    Svg,
    Pdf,
    Font,
    Zip,
}

/// The type of `b` by its magic bytes, the allow-list of T8; `None` is refused.
pub(crate) fn sniff(b: &[u8]) -> Option<(&'static str, Class)> {
    let t = |p: &[u8]| b.starts_with(p);
    Some(if t(b"\x89PNG\r\n\x1a\n") {
        ("image/png", Class::Image)
    } else if t(b"\xff\xd8\xff") {
        ("image/jpeg", Class::Image)
    } else if t(b"GIF87a") || t(b"GIF89a") {
        ("image/gif", Class::Image)
    } else if b.len() > 12 && t(b"RIFF") && &b[8..12] == b"WEBP" {
        ("image/webp", Class::Image)
    } else if t(b"%PDF-") {
        ("application/pdf", Class::Pdf)
    } else if t(b"\x00\x01\x00\x00") || t(b"true") {
        ("font/ttf", Class::Font)
    } else if t(b"OTTO") {
        ("font/otf", Class::Font)
    } else if t(b"wOF2") {
        ("font/woff2", Class::Font)
    } else if t(b"PK\x03\x04") {
        ("application/zip", Class::Zip)
    } else if b.iter().take(4096).position(|c| *c == b'<').is_some()
        && String::from_utf8_lossy(&b[..b.len().min(4096)]).contains("<svg")
    {
        ("image/svg+xml", Class::Svg)
    } else {
        return None;
    })
}

/// The kinds a person may give a class; the first is the default.
pub(crate) fn kinds(c: Class) -> &'static [&'static str] {
    match c {
        Class::Image | Class::Svg => &["image", "icon", "logo"],
        Class::Pdf => &["pdf"],
        Class::Font => &["font"],
        Class::Zip => &["icon_composer"],
    }
}
