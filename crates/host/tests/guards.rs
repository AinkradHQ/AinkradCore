//! Source-level guards for the properties that must never regress.
use std::path::Path;

fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let name = p
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((name, std::fs::read_to_string(&p).unwrap()));
            }
        }
    }
    out
}

/// `src` with comments blanked (and, unless `keep_strings`, string and char literals too), byte for
/// byte the same length, newlines kept. So an offset found in the blanked text is valid in `src`.
fn blank(src: &str, keep_strings: bool) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    let wipe = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            let end = src[i..].find('\n').map_or(b.len(), |e| i + e);
            wipe(&mut out, i, end);
            i = end;
        } else if b[i..].starts_with(b"/*") {
            let end = src[i..].find("*/").map_or(b.len(), |e| i + e + 2);
            wipe(&mut out, i, end);
            i = end;
        } else if b[i] == b'"' || (b[i] == b'r' && matches!(b.get(i + 1), Some(b'"' | b'#'))) {
            // A plain or raw string: find its end.
            let hashes = b[i..].iter().skip(1).take_while(|c| **c == b'#').count();
            let raw = b[i] == b'r';
            let open = i + if raw { 1 + hashes } else { 0 };
            if b.get(open) != Some(&b'"') {
                i += 1;
                continue;
            }
            let mut j = open + 1;
            while j < b.len() {
                if !raw && b[j] == b'\\' {
                    j += 2;
                } else if b[j] == b'"'
                    && (!raw || b[j + 1..].iter().take_while(|c| **c == b'#').count() >= hashes)
                {
                    j += 1 + if raw { hashes } else { 0 };
                    break;
                } else {
                    j += 1;
                }
            }
            let j = j.min(b.len());
            if !keep_strings {
                wipe(&mut out, i, j);
            }
            i = j;
        } else if b[i] == b'\''
            && (b.get(i + 2) == Some(&b'\'')
                || (b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'')))
        {
            // A char literal (`'x'`, `'\n'`), not a lifetime.
            let end = if b[i + 1] == b'\\' { i + 4 } else { i + 3 };
            if !keep_strings {
                wipe(&mut out, i, end);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Production code only: comments blanked, and nothing from the first real `#[cfg(test)]` on. The
/// marker is looked for with strings and comments blanked, so one inside either cuts nothing.
fn production(src: &str) -> String {
    let bare = blank(src, false);
    let at = ["#[cfg(test)]", "#[cfg(all(test"]
        .iter()
        .filter_map(|m| bare.find(m))
        .min()
        .unwrap_or(src.len());
    blank(src, true)[..at].to_owned()
}

#[test]
fn production_cuts_at_the_real_test_module_only() {
    // A marker inside a string or a comment is not the cut.
    let src = "fn a() { let m = \"#[cfg(test)]\"; } // #[cfg(test)]\n/* #[cfg(test)] */ fn b() { unsafe { } }\n#[cfg(test)]\nmod tests { unsafe { } }\n";
    let p = production(src);
    assert!(p.contains("fn b()") && p.contains("unsafe"), "{p}");
    assert!(!p.contains("mod tests"), "{p}");
    assert!(!p.contains("// #[cfg"), "comments are blanked");
    // The strings stay in the production text (other guards look for them).
    assert!(production("const X: &str = \"/usr/bin/systemctl\";").contains("/usr/bin/systemctl"));
    // Raw strings, escapes and lifetimes do not derail it.
    let tricky = "fn f<'a>(x: &'a str) { let _ = r#\"a \"#[cfg(test)]\" b\"#; let _ = '\"'; let _ = \"q\\\"#[cfg(test)]\"; unsafe { } }\n#[cfg(test)]\nmod t {}\n";
    let p = production(tricky);
    assert!(p.contains("unsafe") && !p.contains("mod t"), "{p}");
    assert_eq!(blank(tricky, false).len(), tricky.len());
}

#[test]
fn only_exec_rs_starts_processes_and_only_two_programs() {
    for (name, src) in sources() {
        let n = production(&src).matches("Command::new").count();
        assert_eq!(n, usize::from(name == "exec.rs"), "{name}");
    }
    let exec = production(
        &sources()
            .into_iter()
            .find(|(n, _)| n == "exec.rs")
            .unwrap()
            .1,
    );
    assert!(exec.contains("\"/usr/bin/systemctl\"") && exec.contains("\"/usr/bin/journalctl\""));
    assert!(exec.contains(".env_clear()") && exec.contains(".stdin(Stdio::null())"));
    assert!(!exec.contains("\"sh\"") && !exec.contains("/bin/sh") && !exec.contains("/usr/local"));
    let real = ainkrad_host::Real;
    for prog in [
        "/bin/sh",
        "/usr/local/bin/ainkrad-runner",
        "systemctl",
        "/usr/bin/id",
    ] {
        let e = ainkrad_host::Exec::run(&real, prog, &[], 10).err().unwrap();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{prog}");
    }
}

#[test]
fn no_unsafe_no_network_no_async_and_small_files() {
    let banned_words = [
        "tokio",
        "TcpListener",
        "TcpStream",
        "UdpSocket",
        "UnixListener",
        "std::net",
        "reqwest",
        "sqlx",
        "from_raw_fd",
        "\"sh\"",
        "arg(\"-c\")",
    ];
    for (name, src) in sources() {
        // A `tests.rs` is a test-only module: prove it is declared under `#[cfg(test)]` in its
        // parent (so it can never ship), instead of exempting it by file name.
        if name.ends_with("tests.rs") {
            let parent = name.trim_end_matches("/tests.rs").to_owned() + ".rs";
            let decl = sources().into_iter().find(|(n, _)| *n == parent).unwrap().1;
            assert!(
                blank(&decl, false).contains("#[cfg(test)]\nmod tests;"),
                "{name} is not cfg(test) in {parent}"
            );
        } else {
            let code = production(&src);
            for banned in banned_words {
                assert!(!code.contains(banned), "{name}: {banned}");
            }
            assert_eq!(
                unsafe_words(&code.replace("\"unsafe\"", "")),
                0,
                "{name} has an unsafe"
            );
        }
        assert!(
            src.lines().count() < 500,
            "{name} is {} lines",
            src.lines().count()
        );
    }
    let cargo =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let cargo: String = cargo
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "tokio",
        "sqlx",
        "reqwest",
        "hyper",
        "axum",
        "ainkrad-core-server",
    ] {
        assert!(!cargo.contains(banned), "{banned}");
    }
    assert!(
        lints_inherit_workspace(&cargo),
        "[lints] workspace = true (unsafe_code = forbid)"
    );
    let root =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"))
            .unwrap();
    assert!(table_has(
        &root,
        "[workspace.lints.rust]",
        "unsafe_code = \"forbid\""
    ));
}

#[test]
fn the_only_unsafe_is_the_sys_peer_wrapper() {
    let sys =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../sys/src/lib.rs"))
            .unwrap();
    assert!(sys.contains("\"peer_uid\""), "listed in INVENTORY");
    assert!(sys.contains("pub fn peer_uid("));
}

/// Whether the `[lints]` table says `workspace = true` (a comment or another table does not count).
fn table_has(toml: &str, table: &str, line: &str) -> bool {
    let mut inside = false;
    for l in toml.lines().map(str::trim) {
        if l.starts_with('[') {
            inside = l == table;
        } else if inside && l == line {
            return true;
        }
    }
    false
}

fn lints_inherit_workspace(cargo: &str) -> bool {
    table_has(cargo, "[lints]", "workspace = true")
}

/// How many times `unsafe` appears as a word: a block, an fn, an impl, with or without a space.
fn unsafe_words(code: &str) -> usize {
    let id = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices("unsafe")
        .filter(|(i, _)| {
            !code[..*i].chars().next_back().is_some_and(id)
                && !code[i + 6..].chars().next().is_some_and(id)
        })
        .count()
}

/// The detectors above must really fail on the things they guard against.
#[test]
fn the_guards_detect_what_they_guard() {
    assert!(lints_inherit_workspace(
        "[package]\nname = \"x\"\n\n[lints]\nworkspace = true\n"
    ));
    for bad in [
        "[package]\nname = \"x\"\n",
        "[lints]\n",
        "[package]\n# workspace = true\n",
        "[dependencies]\nworkspace = true\n",
        "[lints]\n# workspace = true\n",
        "[lints.rust]\nworkspace = true\n",
    ] {
        assert!(!lints_inherit_workspace(bad), "{bad}");
    }
    for bad in [
        "unsafe { x() }",
        "unsafe{ x() }",
        "unsafe fn f() {}",
        "unsafe impl Send for X {}",
        "unsafe\n{ x() }",
        "let a = (unsafe { 1 });",
    ] {
        assert_eq!(unsafe_words(bad), 1, "{bad}");
    }
    for fine in [
        "unsafe_code",
        "no_unsafe_here",
        "fn unsafely() {}",
        "safe { }",
    ] {
        assert_eq!(unsafe_words(fine), 0, "{fine}");
    }
}
