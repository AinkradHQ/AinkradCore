//! Harness versions (E3.6): which versions of each harness a runner may drive, and the
//! `--version` probe a runner runs at start. Upstream CLIs update often, so the policy is
//! "the latest works": a version at or above the adapter's `min_version` (the oldest its
//! protocol handling is verified against) runs, unless it is on the harness's `known_bad`
//! list or above the admin's cap. A version newer than every tested one is
//! `untested_newer`: it runs, with a note, unless `harness.allow_untested_newer` is 0. The
//! adapters ignore event types and fields they do not know, so a newer CLI's additions do not
//! fail a run; a protocol break surfaces as a `protocol` failure (`classify`).

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::{agy, claude, codex, opencode};

/// One harness's version policy.
#[derive(Debug, Clone, Copy)]
pub struct Compat {
    pub harness: &'static str,
    /// The oldest version the adapter's protocol handling is verified against.
    pub min_version: &'static str,
    /// The versions the adapter was recorded against; the newest is `tested_up_to`.
    pub tested: &'static [&'static str],
    /// Versions known to break the adapter's protocol handling: inclusive ranges, `(v, v)`
    /// for one version.
    pub known_bad: &'static [(&'static str, &'static str)],
}

impl Compat {
    /// The newest tested version.
    pub fn tested_up_to(&self) -> &'static str {
        let newest = self.tested.iter().max_by_key(|v| Version::parse(v));
        newest.copied().unwrap_or(self.min_version)
    }
}

/// Every harness's policy. A version that breaks an adapter goes into its `known_bad`; a
/// version the adapter is re-recorded against goes into `tested`.
pub const COMPAT: &[Compat] = &[
    Compat {
        harness: "claude",
        min_version: claude::VERSION,
        tested: &[claude::VERSION],
        known_bad: &[],
    },
    Compat {
        harness: "codex",
        min_version: codex::VERSION,
        tested: &[codex::VERSION],
        known_bad: &[],
    },
    Compat {
        harness: "opencode",
        min_version: opencode::VERSION,
        tested: &[opencode::VERSION],
        known_bad: &[],
    },
    Compat {
        // agy renamed its tools between 1.4.2 and 1.4.4: nothing older is driven.
        harness: "agy",
        min_version: agy::VERSION,
        tested: &[agy::VERSION],
        known_bad: &[],
    },
];

/// The policy of `harness`, when it is a known one.
pub fn compat(harness: &str) -> Option<&'static Compat> {
    COMPAT.iter().find(|c| c.harness == harness)
}

/// `major.minor.patch`, with an optional `-prerelease`; a `+build` is ignored. A prerelease
/// sorts before its release.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    core: [u64; 3],
    /// `false` for a prerelease, so it sorts first.
    release: bool,
    // ponytail: prerelease tags compare as text ("beta.10" < "beta.9"); per-identifier
    // semver ordering if a known-bad range ever has to split prereleases.
    pre: String,
}

impl Version {
    /// `1.2.3`, `v1.2.3`, `1.2.3-beta.1`, `1.2.3+abc`; a fourth number is ignored.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let s = s.split_once('+').map_or(s, |(v, _)| v);
        let (core, pre) = s.split_once('-').unwrap_or((s, ""));
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() < 3
            || !parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let n = |i: usize| parts[i].parse::<u64>().ok();
        Some(Self {
            core: [n(0)?, n(1)?, n(2)?],
            release: pre.is_empty(),
            pre: pre.to_owned(),
        })
    }

    /// A version setting's value (`Unit::Version`): `major·10¹² + minor·10⁶ + patch`; 0 is
    /// none.
    pub fn from_setting(value: i64) -> Option<Self> {
        let v = u64::try_from(value).ok().filter(|v| *v > 0)?;
        let m = 1_000_000;
        Some(Self {
            core: [v / (m * m), v / m % m, v % m],
            release: true,
            pre: String::new(),
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c] = self.core;
        write!(f, "{a}.{b}.{c}")?;
        if !self.release {
            write!(f, "-{}", self.pre)?;
        }
        Ok(())
    }
}

/// How a reported version stands against its harness's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// A tested version.
    Supported,
    /// Newer than the minimum, not tested, not known bad: driven, with a note.
    UntestedNewer,
    /// Older than the minimum: refused.
    TooOld,
    /// On the known-bad list: refused.
    KnownBad,
    /// Not installed: not offered, no health problem.
    Missing,
    /// `--version` could not be read: refused.
    Unreadable,
    /// No adapter for it: refused.
    UnknownHarness,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::UntestedNewer => "untested_newer",
            Self::TooOld => "too_old",
            Self::KnownBad => "known_bad",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::UnknownHarness => "unknown_harness",
        }
    }
}

/// The admin's tightening of the policy (settings `harness.allow_untested_newer`,
/// `harness.<name>.max_version`). The default allows untested newer versions, uncapped.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub refuse_untested_newer: bool,
    /// Harness → the newest version it may run at.
    pub max_version: BTreeMap<String, Version>,
}

/// The judgement of one harness's reported version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: Status,
    /// The newest tested version, for a known harness.
    pub tested_up_to: Option<&'static str>,
    /// Not driven: the runner is unhealthy for it, with `reason`.
    pub refused: bool,
    /// Why it is refused, or the note on an untested version.
    pub reason: Option<String>,
}

impl Verdict {
    /// Whether runs may be dispatched to it.
    pub fn offered(&self) -> bool {
        !self.refused && self.status != Status::Missing
    }
}

/// Judges `version` of `harness` (`None`: not installed) under `policy`.
pub fn check(harness: &str, version: Option<&str>, policy: &Policy) -> Verdict {
    match compat(harness) {
        Some(c) => c.check(version, policy),
        None => Verdict {
            status: Status::UnknownHarness,
            tested_up_to: None,
            refused: true,
            reason: Some(format!("{harness} is not a known harness")),
        },
    }
}

impl Compat {
    /// Judges `version` of this harness (`None`: not installed) under `policy`.
    pub fn check(&self, version: Option<&str>, policy: &Policy) -> Verdict {
        let (c, harness) = (self, self.harness);
        let verdict = |status, tested_up_to, refused, reason: Option<String>| Verdict {
            status,
            tested_up_to,
            refused,
            reason,
        };
        let up_to = Some(c.tested_up_to());
        let Some(raw) = version else {
            return verdict(Status::Missing, up_to, false, None);
        };
        let Some(v) = Version::parse(raw) else {
            let why = format!("{harness} version is unreadable: {raw}");
            return verdict(Status::Unreadable, up_to, true, Some(why));
        };
        let parse = |s: &str| Version::parse(s).expect("compat versions parse");
        if let Some((from, to)) = c
            .known_bad
            .iter()
            .find(|(from, to)| (parse(from)..=parse(to)).contains(&v))
        {
            let range = if from == to {
                (*from).to_owned()
            } else {
                format!("{from} to {to}")
            };
            let why =
                format!("{harness} {v} is known to break Citadel's adapter (known bad: {range})");
            return verdict(Status::KnownBad, up_to, true, Some(why));
        }
        let min = parse(c.min_version);
        if v < min {
            let why = format!("{harness} {v} is older than the oldest supported, {min}");
            return verdict(Status::TooOld, up_to, true, Some(why));
        }
        let status = if c.tested.iter().any(|t| parse(t) == v) {
            Status::Supported
        } else {
            Status::UntestedNewer
        };
        let tested = c.tested_up_to();
        if let Some(cap) = policy.max_version.get(harness).filter(|cap| v > **cap) {
            let why = format!("{harness} {v} is above harness.{harness}.max_version, {cap}");
            return verdict(status, up_to, true, Some(why));
        }
        match status {
            Status::UntestedNewer if policy.refuse_untested_newer => {
                let why = format!(
                    "{harness} {v} is untested (tested up to {tested}) and \
                 harness.allow_untested_newer is 0"
                );
                verdict(status, up_to, true, Some(why))
            }
            Status::UntestedNewer => {
                let note = format!("{harness}: untested version {v} (tested up to {tested})");
                verdict(status, up_to, false, Some(note))
            }
            _ => verdict(status, up_to, false, None),
        }
    }
}

/// The first version in `--version` output: `2.1.306 (Claude Code)`, `codex-cli 0.154.0`,
/// `v1.4.4`, `1.5.0-beta.2`.
pub fn parse_version(output: &str) -> Option<&str> {
    output
        .split_whitespace()
        .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .map(|word| word.trim_start_matches('v'))
        .find(|word| Version::parse(word).is_some())
}

/// Runs `program --version` with an empty environment but `PATH`, and `HOME` set to `home`
/// so nothing of the user's config is read. `None` when the program is not installed; else
/// its version, or `unknown (<why>)` when it cannot be read (which `mismatch` refuses).
pub async fn probe(program: &Path, home: &Path, timeout: Duration) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.arg("--version")
        .current_dir(home)
        .env_clear()
        .env("HOME", home)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    // The binary may be mid-write (ETXTBSY: another thread's fork still holds the write handle): retry that.
    let run = async {
        loop {
            match cmd.output().await {
                Err(e) if crate::exec::local::text_busy(&e) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                other => break other,
            }
        }
    };
    let output = match tokio::time::timeout(timeout, run).await {
        Err(_) => return Some(format!("unknown (no answer within {timeout:?})")),
        Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound => return None,
        Ok(Err(e)) => return Some(format!("unknown ({e})")),
        Ok(Ok(output)) => output,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    match parse_version(&stdout) {
        Some(version) if output.status.success() => Some(version.to_owned()),
        _ => {
            let mut said = stdout.trim().to_owned();
            said.truncate(said.floor_char_boundary(80));
            Some(format!("unknown ({}: {said:?})", output.status))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;

    #[test]
    fn reads_each_harness_version_line() {
        assert_eq!(parse_version("2.1.306 (Claude Code)\n"), Some("2.1.306"));
        assert_eq!(parse_version("codex-cli 0.154.0"), Some("0.154.0"));
        assert_eq!(parse_version("1.18.34"), Some("1.18.34"));
        assert_eq!(parse_version("agy v1.4.4"), Some("1.4.4"));
        assert_eq!(parse_version("version 1.4"), None);
        assert_eq!(parse_version("1..2"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn reads_version_variants() {
        assert_eq!(
            parse_version("2.2.0-beta.3 (Claude Code)"),
            Some("2.2.0-beta.3")
        );
        assert_eq!(parse_version("opencode (v1.19.0)"), Some("1.19.0"));
        assert_eq!(parse_version("codex-cli 0.155.0+abc"), Some("0.155.0+abc"));
        let v = |s| Version::parse(s).unwrap();
        assert!(v("2.2.0-beta.1") < v("2.2.0"));
        assert!(v("2.1.306") < v("2.2.0-beta.1"));
        assert!(v("0.154.0") < v("0.1000.0"));
        assert_eq!(v("v1.2.3+build"), v("1.2.3"));
        assert_eq!(v("1.2.3.4"), v("1.2.3"));
        assert_eq!(v("1.5.0-rc.1").to_string(), "1.5.0-rc.1");
        assert_eq!(Version::parse("1.2"), None);
        assert_eq!(Version::parse("1.x.3"), None);
        assert_eq!(Version::from_setting(2_000_003_000_010), Some(v("2.3.10")));
        assert_eq!(Version::from_setting(0), None);
    }

    #[test]
    fn judges_each_status() {
        let open = Policy::default();
        let tested = claude::VERSION;
        let ok = check("claude", Some(tested), &open);
        assert_eq!(
            (ok.status, ok.refused, ok.reason),
            (Status::Supported, false, None)
        );
        assert_eq!(ok.tested_up_to, Some(tested));

        let newer = check("claude", Some("99.0.0"), &open);
        assert_eq!(newer.status, Status::UntestedNewer);
        assert!(newer.offered());
        assert_eq!(
            newer.reason.unwrap(),
            format!("claude: untested version 99.0.0 (tested up to {tested})")
        );

        let old = check("codex", Some("0.1.0"), &open);
        assert_eq!(old.status, Status::TooOld);
        assert!(old.refused && !old.offered());
        assert_eq!(
            old.reason.unwrap(),
            format!(
                "codex 0.1.0 is older than the oldest supported, {}",
                codex::VERSION
            )
        );
        // A prerelease of the minimum is older than it.
        let pre = format!("{}-beta.1", agy::VERSION);
        assert_eq!(check("agy", Some(&pre), &open).status, Status::TooOld);

        let missing = check("opencode", None, &open);
        assert_eq!(missing.status, Status::Missing);
        assert!(!missing.refused && !missing.offered());

        let garbled = check("claude", Some("unknown (exit 1: \"hi\")"), &open);
        assert_eq!(garbled.status, Status::Unreadable);
        assert!(garbled.refused);

        let pi = check("pi", Some("1.0.0"), &open);
        assert_eq!(pi.status, Status::UnknownHarness);
        assert_eq!(pi.reason.unwrap(), "pi is not a known harness");
    }

    #[test]
    fn known_bad_versions_and_ranges_are_refused() {
        // The shipped lists are empty; the matching is checked on a list of its own.
        const BAD: Compat = Compat {
            harness: "claude",
            min_version: "1.0.0",
            tested: &["1.0.0"],
            known_bad: &[("1.2.0", "1.2.0"), ("1.4.0", "1.5.9")],
        };
        let open = Policy::default();
        let status = |v: &str| BAD.check(Some(v), &open).status;
        for bad in ["1.2.0", "1.4.0", "1.5.9", "1.5.0-rc.1"] {
            assert_eq!(status(bad), Status::KnownBad, "{bad}");
        }
        for good in ["1.2.1", "1.3.9", "1.6.0"] {
            assert_eq!(status(good), Status::UntestedNewer, "{good}");
        }
        let why = BAD.check(Some("1.4.2"), &open).reason.unwrap();
        assert_eq!(
            why,
            "claude 1.4.2 is known to break Citadel's adapter (known bad: 1.4.0 to 1.5.9)"
        );
        assert!(COMPAT.iter().all(|c| c.known_bad.is_empty()));
    }

    #[test]
    fn the_policy_tightens_untested_and_capped_versions() {
        let strict = Policy {
            refuse_untested_newer: true,
            ..Policy::default()
        };
        let newer = check("claude", Some("99.0.0"), &strict);
        assert_eq!(newer.status, Status::UntestedNewer);
        assert!(newer.refused);
        assert!(
            newer
                .reason
                .unwrap()
                .ends_with("harness.allow_untested_newer is 0")
        );
        assert!(!check("claude", Some(claude::VERSION), &strict).refused);

        let capped = Policy {
            max_version: [("codex".to_owned(), Version::parse("1.0.0").unwrap())].into(),
            ..Policy::default()
        };
        let over = check("codex", Some("1.0.1"), &capped);
        assert!(over.refused);
        assert_eq!(
            over.reason.unwrap(),
            "codex 1.0.1 is above harness.codex.max_version, 1.0.0"
        );
        assert!(!check("codex", Some("1.0.0"), &capped).refused);
        assert!(!check("claude", Some("99.0.0"), &capped).refused);
    }

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A binary written a moment ago can be busy (ETXTBSY) when another thread forks in that
    /// window; the probe retries, so a script written and probed at once always answers.
    #[tokio::test]
    async fn a_freshly_written_binary_is_probed_while_other_threads_fork() {
        let dir = std::env::temp_dir().join(format!("ainkrad-etxtbsy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let forkers: Vec<_> = (0..4)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = std::process::Command::new("/bin/true").status();
                    }
                })
            })
            .collect();
        for i in 0..300 {
            let bin = script(&dir, &format!("v{i}"), "echo 'codex-cli 0.154.0'");
            let got = probe(&bin, &dir, Duration::from_secs(10)).await;
            assert_eq!(got.as_deref(), Some("0.154.0"), "round {i}");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for f in forkers {
            f.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn probes_a_version_and_reports_what_it_cannot_read() {
        let dir = std::env::temp_dir().join(format!("citadel-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = Duration::from_secs(5);
        let ok = script(
            &dir,
            "ok",
            "echo \"$HOME\" > \"$HOME/home\"; echo 'codex-cli 0.154.0'",
        );
        assert_eq!(probe(&ok, &dir, t).await.as_deref(), Some("0.154.0"));
        let home = std::fs::read_to_string(dir.join("home")).unwrap();
        assert_eq!(
            home.trim(),
            dir.display().to_string(),
            "HOME is the given dir"
        );

        assert_eq!(probe(&dir.join("absent"), &dir, t).await, None);
        let garbled = probe(&script(&dir, "garbled", "echo hi"), &dir, t).await;
        assert!(garbled.unwrap().starts_with("unknown ("));
        let failing = script(&dir, "failing", "echo 1.2.3; exit 3");
        assert!(
            probe(&failing, &dir, t)
                .await
                .unwrap()
                .starts_with("unknown (")
        );
        let hung = script(&dir, "hung", "exec sleep 30");
        let short = Duration::from_millis(200);
        assert_eq!(
            probe(&hung, &dir, short).await.as_deref(),
            Some("unknown (no answer within 200ms)")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
