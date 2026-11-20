//! Tiers 0 and 1 of the heavy-job decision (spec §5.2): the interactive refusal list and the rules
//! table. Pure: an argv in, a [`Verdict`] out. Project rules (`.ainkrad/jobs.toml [[rule]]`) are
//! consulted before the built-in table.

use serde::Deserialize;

/// What a matched rule says to do with the command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Row {
    /// Heavy commands go to a runner; a light one stays on the Core.
    pub heavy: bool,
    /// Toolchains the runner must have (`rust`, `node`, `go`, `python`, `xcode`, `java`).
    pub need: Vec<String>,
    /// Run first on the runner when the lockfile changed (`npm ci`).
    pub prepare: Option<Vec<String>>,
    /// Paths (relative to `cwd`) that come back after the job. Empty means "whatever changed".
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Tier 0: run it where the user is. The reason is shown to the shim.
    Interactive(&'static str),
    /// A rule decided.
    Rule(Row, Source),
    /// No rule matches: ask history, then Decisions.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Project,
    Builtin,
}

/// The program's name, without its directory.
fn program(argv: &[String]) -> &str {
    argv.first()
        .map_or("", |p| p.rsplit('/').next().unwrap_or(p))
}

/// The arguments that are not flags, with `cargo +toolchain` selectors dropped.
fn words(argv: &[String]) -> Vec<&str> {
    argv.iter()
        .skip(1)
        .map(String::as_str)
        .filter(|a| !a.starts_with('-') && !a.starts_with('+'))
        .collect()
}

fn has(argv: &[String], flag: &str) -> bool {
    argv.iter().skip(1).any(|a| a == flag)
}

/// Tier 0: a terminal user is waiting on this command, so it runs where they are.
pub fn interactive(argv: &[String], tty: bool) -> Option<&'static str> {
    if !tty {
        return None;
    }
    let (prog, w) = (program(argv), words(argv));
    let sub = w.first().copied().unwrap_or("");
    let hit = match prog {
        "cargo" => sub == "run" || sub == "r",
        "go" => sub == "run",
        "npm" | "pnpm" | "yarn" | "bun" => {
            sub == "start"
                || sub == "dev"
                || (sub == "run" && matches!(w.get(1), Some(&"dev" | &"start")))
        }
        "vite" => true,
        "next" => sub == "dev",
        "python" | "python3" => argv.len() == 1,
        "swift" => sub == "repl" || argv.len() == 1,
        _ => false,
    };
    (hit || has(argv, "-i") || has(argv, "--watch")).then_some("interactive")
}

/// A package manager installing: always light, always on the Core.
fn install(argv: &[String]) -> bool {
    let (prog, w) = (program(argv), words(argv));
    let sub = w.first().copied().unwrap_or("");
    match prog {
        "npm" | "pnpm" => matches!(sub, "install" | "i" | "ci" | "add" | "remove" | "uninstall"),
        "yarn" => w.is_empty() || matches!(sub, "install" | "add" | "remove"),
        "bun" => matches!(sub, "install" | "i" | "add" | "remove"),
        "cargo" => matches!(
            sub,
            "fetch" | "add" | "install" | "update" | "remove" | "generate-lockfile"
        ),
        "go" => matches!(sub, "get" | "mod"),
        "pip" | "pip3" | "uv" => matches!(sub, "install" | "add"),
        _ => false,
    }
}

fn heavy(need: &[&str], prepare: Option<&[&str]>, outputs: &[&str]) -> Row {
    Row {
        heavy: true,
        need: need.iter().map(|s| (*s).to_owned()).collect(),
        prepare: prepare.map(|p| p.iter().map(|s| (*s).to_owned()).collect()),
        outputs: outputs.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// A `package.json` script name that builds or tests (`build`, `test`, `build:prod`, `test:unit`).
fn script_is_heavy(name: &str) -> bool {
    let base = name.split(':').next().unwrap_or(name);
    matches!(base, "build" | "test")
}

/// Tier 1, built-in table (spec §5.2). `None` means no row.
pub fn builtin(argv: &[String]) -> Option<Row> {
    if install(argv) {
        return Some(Row::default());
    }
    let (prog, w) = (program(argv), words(argv));
    let sub = w.first().copied().unwrap_or("");
    match prog {
        "cargo"
            if matches!(
                sub,
                "build" | "b" | "test" | "t" | "check" | "c" | "clippy" | "bench" | "doc"
            ) =>
        {
            Some(heavy(&["rust"], None, &["target"]))
        }
        "go" if matches!(sub, "build" | "test") => Some(heavy(&["go"], None, &[])),
        "npm" | "pnpm" | "yarn" | "bun" => {
            let run = matches!(sub, "run" | "run-script");
            // `yarn build` and `pnpm build` are shorthand for `run build`; `npm build` is not.
            let script = if run {
                w.get(1).copied()
            } else {
                matches!(prog, "yarn" | "pnpm").then_some(sub)
            };
            let ok = matches!(sub, "test" | "t") || script.is_some_and(script_is_heavy);
            let prepare: &[&str] = match prog {
                "pnpm" => &["pnpm", "install", "--frozen-lockfile"],
                "yarn" => &["yarn", "install", "--frozen-lockfile"],
                "bun" => &["bun", "install", "--frozen-lockfile"],
                _ => &["npm", "ci"],
            };
            ok.then(|| heavy(&["node"], Some(prepare), &["dist", "build", ".next"]))
        }
        "make" => w.is_empty().then(|| heavy(&[], None, &[])),
        "xcodebuild" => {
            let probe = ["-version", "-list", "-showsdks", "-help", "-usage"];
            (!probe.iter().any(|p| has(argv, p))).then(|| heavy(&["xcode"], None, &["build"]))
        }
        "swift" if matches!(sub, "build" | "test") => Some(heavy(&["swift"], None, &[".build"])),
        "gradle" | "gradlew" => {
            let probe = ["--version", "-v", "--help", "-h"];
            (!probe.iter().any(|p| has(argv, p))).then(|| heavy(&["java"], None, &["build"]))
        }
        "pytest" => Some(heavy(&["python"], None, &[])),
        "tsc" => {
            (has(argv, "-b") || has(argv, "--build")).then(|| heavy(&["node"], None, &["dist"]))
        }
        _ => None,
    }
}

/// A project rule from `.ainkrad/jobs.toml`:
///
/// ```toml
/// [[rule]]
/// match = "make ci"          # leading words of the command; `*` matches any one word
/// heavy = true               # false keeps it on the Core
/// need = ["rust"]
/// prepare = ["npm", "ci"]
/// outputs = ["dist"]
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProjectRule {
    #[serde(rename = "match")]
    pub pattern: String,
    #[serde(default = "yes")]
    pub heavy: bool,
    #[serde(default)]
    pub need: Vec<String>,
    #[serde(default)]
    pub prepare: Option<Vec<String>>,
    #[serde(default)]
    pub outputs: Vec<String>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, Default)]
struct JobsFile {
    #[serde(default)]
    rule: Vec<ProjectRule>,
}

/// The `[[rule]]` tables of a `jobs.toml`; other tables (`[sync]`) are ignored. A file that does
/// not parse gives no rules, so a typo costs the override, never the job.
pub fn parse_project(toml_text: &str) -> Vec<ProjectRule> {
    toml::from_str::<JobsFile>(toml_text)
        .map(|f| f.rule)
        .unwrap_or_default()
}

impl ProjectRule {
    fn matches(&self, argv: &[String]) -> bool {
        let want: Vec<&str> = self.pattern.split_whitespace().collect();
        let mut have =
            std::iter::once(program(argv)).chain(argv.iter().skip(1).map(String::as_str));
        !want.is_empty()
            && want
                .iter()
                .all(|w| have.next().is_some_and(|h| *w == "*" || w == &h))
    }
}

/// Tiers 0 and 1 for one command. `rules` are the project's, first match wins.
pub fn decide(argv: &[String], tty: bool, rules: &[ProjectRule]) -> Verdict {
    if let Some(why) = interactive(argv, tty) {
        return Verdict::Interactive(why);
    }
    if let Some(r) = rules.iter().find(|r| r.matches(argv)) {
        let row = Row {
            heavy: r.heavy,
            need: r.need.clone(),
            prepare: r.prepare.clone(),
            outputs: r.outputs.clone(),
        };
        return Verdict::Rule(row, Source::Project);
    }
    builtin(argv).map_or(Verdict::Unknown, |r| Verdict::Rule(r, Source::Builtin))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn is_heavy(s: &str) -> Option<bool> {
        match decide(&a(s), false, &[]) {
            Verdict::Rule(r, _) => Some(r.heavy),
            _ => None,
        }
    }

    #[test]
    fn the_table_sends_builds_and_tests_away() {
        for c in [
            "cargo build --release",
            "cargo +nightly test",
            "cargo clippy",
            "go test ./...",
            "npm run build",
            "pnpm test",
            "yarn build",
            "make",
            "make -j8",
            "xcodebuild -scheme A",
            "swift build",
            "./gradlew assemble",
            "pytest -q",
            "tsc -b",
            "/usr/bin/cargo check",
        ] {
            assert_eq!(is_heavy(c), Some(true), "{c}");
        }
    }

    #[test]
    fn installs_and_probes_stay_light() {
        for c in [
            "npm ci",
            "npm install",
            "pnpm add x",
            "yarn",
            "cargo fetch",
            "cargo install ripgrep",
            "xcodebuild -version",
            "gradle --version",
        ] {
            assert_eq!(is_heavy(c), Some(false), "{c}");
        }
    }

    #[test]
    fn what_the_table_does_not_know_is_unknown() {
        for c in [
            "make test",
            "go vet",
            "cargo fmt",
            "npm run lint",
            "ls",
            "tsc",
        ] {
            assert_eq!(is_heavy(c), None, "{c}");
        }
    }

    #[test]
    fn a_terminal_user_waiting_runs_locally() {
        for c in [
            "cargo run",
            "go run .",
            "npm start",
            "npm run dev",
            "vite",
            "next dev",
            "python",
            "swift repl",
            "cargo test --watch",
            "python -i x.py",
        ] {
            assert!(
                matches!(decide(&a(c), true, &[]), Verdict::Interactive(_)),
                "{c}"
            );
            assert!(
                !matches!(decide(&a(c), false, &[]), Verdict::Interactive(_)),
                "no tty: {c}"
            );
        }
        assert!(!matches!(
            decide(&a("cargo build"), true, &[]),
            Verdict::Interactive(_)
        ));
        assert!(!matches!(
            decide(&a("python x.py"), true, &[]),
            Verdict::Interactive(_)
        ));
    }

    #[test]
    fn project_rules_come_first_and_ignore_other_tables() {
        let rules = parse_project(
            "[sync]\ninclude = [\"x\"]\n[[rule]]\nmatch = \"cargo test\"\nheavy = false\n[[rule]]\nmatch = \"make *\"\nneed = [\"go\"]\noutputs = [\"out\"]\n",
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(
            decide(&a("cargo test"), false, &rules),
            Verdict::Rule(Row::default(), Source::Project)
        );
        let Verdict::Rule(r, Source::Project) = decide(&a("make ci"), false, &rules) else {
            panic!()
        };
        assert!(r.heavy && r.need == ["go"] && r.outputs == ["out"]);
        // `make *` needs a word; bare make falls through to the table.
        assert!(matches!(
            decide(&a("make"), false, &rules),
            Verdict::Rule(_, Source::Builtin)
        ));
        assert!(parse_project("[[rule]\nbroken").is_empty());
    }
}
