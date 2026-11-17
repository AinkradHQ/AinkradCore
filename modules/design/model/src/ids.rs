//! Id, hash, token-name and fractional-index grammars. Every function is total on any `&str`.

use crate::limits::MAX_ORDER_LEN;

/// `n_` + 12 base32 (a-z, 2-7), client-made.
pub fn is_node_id(s: &str) -> bool {
    s.len() == 14
        && s.strip_prefix("n_").is_some_and(|r| {
            r.bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        })
}

/// `dd_` + 1..=40 of `[a-z0-9]`.
pub fn is_doc_id(s: &str) -> bool {
    s.strip_prefix("dd_").is_some_and(|r| {
        (1..=40).contains(&r.len())
            && r.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// Lowercase hex sha256: the content address of a library asset (image or font file).
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `radius.control`, `color-accent`: lowercase segments joined by `.` or `-`, 1..=64 bytes.
pub fn is_token_name(s: &str) -> bool {
    let ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && ok(b[b.len() - 1])
        && b.iter().all(|&c| ok(c) || c == b'.' || c == b'-')
        && !s.contains("..")
        && !s.contains("--")
        && !s.contains(".-")
        && !s.contains("-.")
}

/// `<doc>/<node>`: a component reference.
pub fn parse_component_ref(s: &str) -> Option<(&str, &str)> {
    let (d, n) = s.split_once('/')?;
    (is_doc_id(d) && is_node_id(n)).then_some((d, n))
}

/// A fractional index: lowercase base-36 digits, 1..=32 long, never ending in `0` (so a midpoint always exists).
pub fn is_order(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ORDER_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        && !s.ends_with('0')
}

fn digit(b: u8) -> u32 {
    if b.is_ascii_digit() {
        u32::from(b - b'0')
    } else {
        u32::from(b - b'a') + 10
    }
}

fn ch(d: u32) -> char {
    char::from_digit(d, 36).unwrap_or('0')
}

/// A valid order strictly between `lo` and `hi` (`None` = open end). Both must be valid orders with `lo < hi`;
/// otherwise `None`. Also `None` when the result would exceed `MAX_ORDER_LEN` (caller rebalances siblings).
pub fn between(lo: Option<&str>, hi: Option<&str>) -> Option<String> {
    let lo_s = lo.unwrap_or("");
    if (lo.is_some() && !is_order(lo_s)) || hi.is_some_and(|h| !is_order(h)) {
        return None;
    }
    if let Some(h) = hi
        && lo_s >= h
    {
        return None;
    }
    let (a, b) = (lo_s.as_bytes(), hi.map(str::as_bytes));
    let mut out = String::new();
    let mut i = 0;
    // `hi_open`: the prefix built so far is already below `hi`, so the upper digit bound is 36.
    let mut hi_open = b.is_none();
    loop {
        if out.len() >= MAX_ORDER_LEN {
            return None;
        }
        let da = a.get(i).map_or(0, |&c| digit(c));
        let db = if hi_open {
            36
        } else {
            b.and_then(|b| b.get(i)).map_or(36, |&c| digit(c))
        };
        if db - da >= 2 {
            out.push(ch((da + db) / 2));
            return Some(out);
        }
        // Adjacent digits: keep `da`, and the upper bound opens up (we are now below `hi`) when da < db.
        out.push(ch(da));
        if da < db {
            hi_open = true;
        }
        i += 1;
    }
}

/// `n` evenly spaced valid orders in increasing order (fixed-width base 36, gaps of at least 4), for renumbering a
/// sibling list after `between` ran out of room. `None` above `MAX_NODES` siblings.
pub fn rebalance(n: usize) -> Option<Vec<String>> {
    if n > crate::limits::MAX_NODES {
        return None;
    }
    let slots = (n as u64 + 1) * 4;
    let (mut width, mut cap) = (1u32, 36u64);
    while cap < slots {
        width += 1;
        cap *= 36;
    }
    let step = cap / (n as u64 + 1);
    Some(
        (1..=n as u64)
            .map(|i| {
                let mut v = i * step;
                if v.is_multiple_of(36) {
                    v += 1; // never end in 0; the gap is at least 4, so the order stays below the next
                }
                let mut digits = vec![0u32; width as usize];
                for d in digits.iter_mut().rev() {
                    *d = (v % 36) as u32;
                    v /= 36;
                }
                digits.into_iter().map(ch).collect()
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammars() {
        assert!(is_node_id("n_abcdefg23456"));
        assert!(!is_node_id("n_abcdefg23458"));
        assert!(!is_node_id("n_ABCDEFG23456"));
        assert!(is_doc_id("dd_abc123"));
        assert!(!is_doc_id("dd_"));
        assert!(is_token_name("radius.control") && is_token_name("color-accent.day"));
        assert!(
            !is_token_name("Radius")
                && !is_token_name("a..b")
                && !is_token_name("a.")
                && !is_token_name("")
        );
        assert!(parse_component_ref("dd_x1/n_abcdefg23456").is_some());
        assert!(parse_component_ref("dd_x1/n_abc").is_none());
    }

    #[test]
    fn between_basics() {
        let m = between(None, None).unwrap();
        assert!(is_order(&m));
        let a = between(Some(&m), None).unwrap();
        assert!(a > m && is_order(&a));
        let c = between(Some(&m), Some(&a)).unwrap();
        assert!(m < c && c < a && is_order(&c));
        assert_eq!(between(Some("b"), Some("a")), None);
        assert_eq!(between(Some("a"), Some("a")), None);
        assert!(
            between(Some("a"), Some("a1")).is_some_and(|x| x.as_str() > "a" && x.as_str() < "a1")
        );
    }
}
