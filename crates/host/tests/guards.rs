//! Source-level guards for the properties that must never regress.
use std::path::Path;

fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                out.push((name, std::fs::read_to_string(&p).unwrap()));
            }
        }
    }
    out
}

/// Production code only: no comments, nothing below `#[cfg(test)]`.
fn production(src: &str) -> String {
    let at = src
        .find("#[cfg(test)]")
        .into_iter()
        .chain(src.find("#[cfg(all(test"))
        .min();
    let body = &src[..at.unwrap_or(src.len())];
    let code: Vec<&str> = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    code.join("\n")
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
        // Test files (`tests.rs`) name the banned words on purpose.
        if name != "tests.rs" {
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
