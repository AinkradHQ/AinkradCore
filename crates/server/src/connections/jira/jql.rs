//! The JQL pieces of a search: the scan that makes a caller's fragment safe to wrap, the ordering
//! terms rebuilt from names, the quoted project list.

use serde_json::{Map, Value};

pub(super) fn field_name_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Why a JQL fragment is refused, if it is: the fragment is wrapped in parentheses and ANDed with
/// the project constraint, which only holds if it is ONE balanced expression with no ORDER BY of
/// its own. Quotes and their backslash escapes are honoured; characters Jira may read as quotes
/// or parentheses but this scan does not are refused outright.
pub(super) fn scan_jql(s: &str) -> Result<(), String> {
    const ODD: [char; 11] = [
        '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}', '\u{201C}', '\u{201D}', '\u{201E}',
        '\u{201F}', '`', '\u{FF08}', '\u{FF09}',
    ];
    let bad = |why: &str| Err(format!("the JQL {why}"));
    if s.len() > 4000
        || s.chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return bad("is too long or has control characters");
    }
    if s.chars().any(|c| ODD.contains(&c)) {
        return bad("has a quote or bracket this adapter cannot read safely");
    }
    let (mut quote, mut esc, mut depth) = (None::<char>, false, 0i32);
    let mut outside = String::new();
    for ch in s.chars() {
        match quote {
            Some(q) => {
                if esc {
                    esc = false;
                } else if ch == '\\' {
                    esc = true;
                } else if ch == q {
                    quote = None;
                    outside.push(' ');
                }
            }
            None => match ch {
                '"' | '\'' => {
                    quote = Some(ch);
                    outside.push(' ');
                }
                '(' => {
                    depth += 1;
                    outside.push(' ');
                }
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        return bad("closes a parenthesis it never opened");
                    }
                    outside.push(' ');
                }
                c => outside.push(c),
            },
        }
    }
    if quote.is_some() || depth != 0 {
        return bad("has an unclosed quote or parenthesis");
    }
    let words: Vec<String> = outside
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    if words.windows(2).any(|w| w[0] == "order" && w[1] == "by") {
        return bad("has an ORDER BY: pass order_by instead");
    }
    Ok(())
}

/// `field` or `field asc|desc` terms, rebuilt.
pub(super) fn order_by(m: &Map<String, Value>) -> Result<Vec<String>, String> {
    let Some(v) = m.get("order_by").filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let list = v.as_array().filter(|a| a.len() <= 5);
    list.ok_or("order_by is a list of at most 5 terms like \"created desc\"")?
        .iter()
        .map(|t| {
            let t = t.as_str().unwrap_or("");
            let mut p = t.split_whitespace();
            let (f, d, extra) = (p.next().unwrap_or(""), p.next(), p.next());
            let f_ok = f.starts_with(|c: char| c.is_ascii_alphabetic())
                && field_name_ok(f)
                && !f.contains('-');
            let dir = match d.map(str::to_ascii_lowercase).as_deref() {
                None => "",
                Some("asc") => " ASC",
                Some("desc") => " DESC",
                Some(_) => return Err("an order_by direction is asc or desc".to_owned()),
            };
            (f_ok && extra.is_none())
                .then(|| format!("{f}{dir}"))
                .ok_or_else(|| "an order_by term is a field name and asc or desc".to_owned())
        })
        .collect()
}

pub(super) fn quote_all(keys: &[String]) -> String {
    keys.iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(", ")
}
