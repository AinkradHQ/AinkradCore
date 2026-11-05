//! The text check of a provider's base URL (KAN-429, tightened by KAN-435 G7, design §5.4).
//!
//! **This is a convenience, not the boundary.** It turns the obvious mistakes into a message at
//! the time a definition is written. A name that passes it can still resolve to a private address
//! (`127.0.0.1.nip.io`, a private zone, a rebinding host): the gateway resolves the host itself and
//! checks every answer at dial time (§4.4, threats T1/T2), and that check is what keeps an upstream
//! off internal addresses.

/// Name suffixes that are local, private or wildcard-DNS by convention.
const SUFFIXES: [&str; 10] = [
    ".internal",
    ".local",
    ".localhost",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
    ".nip.io",
    ".sslip.io",
    ".localtest.me",
];

/// A label that spells a number: all digits (decimal or octal), or `0x` and hex digits. Real names
/// do not have one, and `2130706433`, `017700000001` and `0x7f000001` are 127.0.0.1.
fn numeric(label: &str) -> bool {
    label.bytes().all(|b| b.is_ascii_digit())
        || label
            .strip_prefix("0x")
            .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Why `url` is not an acceptable base URL, if it is not.
pub fn url_problem(url: &str) -> Option<&'static str> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Some("a base URL is https://");
    };
    if url.len() > 200 || !url.is_ascii() || url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Some("a base URL is at most 200 printable ASCII characters");
    }
    if rest.contains(['@', '?', '#', '\\']) {
        return Some("a base URL has no credentials, query or fragment");
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if path.split('/').any(|s| s == ".." || s == ".") {
        return Some("a base URL path has no dot segments");
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|p| p != "443") {
        return Some("a base URL uses port 443");
    }
    if host.ends_with('.') {
        return Some("a base URL's host has no trailing dot");
    }
    let labels: Vec<&str> = host.split('.').collect();
    let dns = labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // The last label of an IP literal is a number; no real top-level domain is.
        && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit());
    if !dns || host == "localhost" || SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return Some(
            "a base URL's host is a public DNS name (no IP literal, localhost, or local or \
             private-zone suffix such as .local, .internal, .lan, .nip.io)",
        );
    }
    if labels.iter().any(|l| numeric(l)) {
        return Some("a base URL's host has no label that is a number (0x7f000001, 2130706433)");
    }
    // ponytail: every punycode label is refused, not only those that decode to a built-in host
    // (a decoder would be the only reason to carry one); lift it with the decoder if a provider needs it.
    if labels.iter().any(|l| l.starts_with("xn--")) {
        return Some("a base URL's host is ASCII: a punycode (xn--) label is refused");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::url_problem;

    #[test]
    fn the_built_in_hosts_and_an_ordinary_router_pass() {
        for url in [
            "https://api.anthropic.com",
            "https://api.openai.com/v1",
            "https://generativelanguage.googleapis.com",
            "https://openrouter.ai/api/v1",
            "https://router.example.com:443/api/v1",
            "https://api2.v1.example.com",
        ] {
            assert_eq!(url_problem(url), None, "{url}");
        }
    }

    #[test]
    fn a_host_that_hides_an_address_or_a_private_zone_is_refused() {
        for url in [
            "https://0x7f000001.example.com",
            "https://2130706433.example.com",
            "https://017700000001.example.com",
            "https://router.0x7f.example.com",
            "https://127.0.0.1.nip.io",
            "https://a.b.sslip.io",
            "https://foo.internal",
            "https://foo.internal.",
            "https://router.example.com.",
            "https://x.local",
            "https://x.localhost",
            "https://printer.home.arpa",
            "https://nas.lan",
            "https://x.corp",
            "https://x.intranet",
            "https://x.localtest.me",
            "https://xn--pnthropic-n4a.com",
            "https://api.xn--80ak6aa92e.com",
            "https://localhost",
            "https://192.0.2.7",
        ] {
            assert!(url_problem(url).is_some(), "{url}");
        }
        // A label that only starts like a number is a name.
        assert_eq!(url_problem("https://0xg.example.com"), None);
        assert_eq!(url_problem("https://a1.example.com"), None);
    }
}
