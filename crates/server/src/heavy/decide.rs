//! The heavy-job decision, first match wins (spec §5.2): the interactive refusal list, rules (the
//! project's, then the built-in table), history, and finally the Decisions service for a command
//! nothing else knows. Whatever fails or stays unsure runs locally.

use std::collections::BTreeMap;
use std::path::Path;

use ainkrad_core::ids::UserId;
use sqlx::SqlitePool;

use super::history::{self, Hist};
use super::rules::{self, ProjectRule, Row, Verdict};
use crate::decisions::{Consumer, Decide, DecideRequest, Fallback, Question, Scored};

/// Which tier made a command heavy (`core_hw_jobs.tier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Rule,
    History,
    Decision,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::History => "history",
            Self::Decision => "decision",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// A person is at a terminal with it: 409 `interactive` (the shim runs it).
    Interactive,
    /// Run it where it was typed. `report` asks the shim to time it, for history.
    Local { reason: &'static str, report: bool },
    Heavy { row: Row, tier: Tier },
}

/// What the decision reads.
pub struct Deps<'a> {
    pub pool: &'a SqlitePool,
    pub decide: &'a dyn Decide,
    pub user: UserId,
    /// `decisions.heavy_job.min_confidence`: how sure the model must be to send a job away.
    pub min_confidence: f32,
}

/// What the folder says about the command, for tier 3.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Facts {
    pub languages: Vec<&'static str>,
    pub lockfiles: Vec<&'static str>,
}

/// Languages and lockfiles by the files in `dir` (the command's folder).
pub fn facts_of(dir: &Path) -> Facts {
    let languages = [
        ("Cargo.toml", "rust"),
        ("package.json", "node"),
        ("go.mod", "go"),
        ("pyproject.toml", "python"),
        ("requirements.txt", "python"),
        ("Package.swift", "swift"),
        ("build.gradle", "java"),
        ("build.gradle.kts", "java"),
        ("pom.xml", "java"),
        ("Makefile", "make"),
    ];
    let locks = [
        "Cargo.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lockb",
        "go.sum",
        "poetry.lock",
        "uv.lock",
        "Package.resolved",
    ];
    let mut f = Facts::default();
    for (file, lang) in languages {
        if dir.join(file).is_file() && !f.languages.contains(&lang) {
            f.languages.push(lang);
        }
    }
    f.lockfiles = locks.into_iter().filter(|l| dir.join(l).is_file()).collect();
    f
}

const HEAVY_SAFE: &str = "heavy_safe";
const HEAVY_UNSAFE: &str = "heavy_unsafe";
const LIGHT: &str = "light";

/// No local rule for an unknown command: the service's equal scores stand, and nothing is heavy.
struct NoRule;

impl Fallback for NoRule {
    fn score(&self, _: &Question) -> Option<Vec<(String, f32)>> {
        None
    }
}

/// Heavy when the model puts `heavy_safe` on top with at least `min` of the score.
pub fn heavy_by_scores(s: &Scored, min: f32) -> bool {
    let top = s
        .scores
        .iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .filter(|(_, v)| *v >= min);
    matches!(top, Some((o, _)) if o == HEAVY_SAFE)
}

/// Tier 3: ask the Decisions service. Any failure is `false`.
async fn ask_model(d: &Deps<'_>, argv: &[String], facts: &Facts) -> bool {
    let text: String = argv.join(" ").chars().take(400).collect();
    let q = Question {
        key: "cmd".to_owned(),
        text,
        facts: BTreeMap::from([
            ("languages".to_owned(), facts.languages.join(",")),
            ("lockfiles".to_owned(), facts.lockfiles.join(",")),
        ]),
    };
    let req = DecideRequest {
        consumer: Consumer::HeavyJob,
        user: d.user,
        options: [HEAVY_SAFE, HEAVY_UNSAFE, LIGHT].map(str::to_owned).to_vec(),
        questions: vec![q],
        context: BTreeMap::new(),
    };
    match d.decide.decide(req, &NoRule).await {
        Ok(scored) => scored
            .first()
            .is_some_and(|s| heavy_by_scores(s, d.min_confidence)),
        Err(_) => false,
    }
}

/// The decision for `argv` run in `dir` (a project's folder) by a caller that has a `tty` or not.
/// `project` is absent for a command outside any project: nothing to sync, so it stays local.
pub async fn decide(
    d: &Deps<'_>,
    project: Option<i64>,
    argv: &[String],
    tty: bool,
    project_rules: &[ProjectRule],
    dir: &Path,
) -> Decision {
    match rules::decide(argv, tty, project_rules) {
        Verdict::Interactive(_) => return Decision::Interactive,
        Verdict::Rule(row, _) => {
            return if row.heavy {
                Decision::Heavy { row, tier: Tier::Rule }
            } else {
                Decision::Local { reason: "light", report: false }
            };
        }
        Verdict::Unknown => {}
    }
    let Some(project) = project else {
        return Decision::Local { reason: "no_project", report: false };
    };
    let heavy = |tier| Decision::Heavy {
        row: Row { heavy: true, ..Row::default() },
        tier,
    };
    match history::lookup(d.pool, project, &history::cmd_key(argv)).await {
        Ok(Hist::Heavy) => return heavy(Tier::History),
        Ok(Hist::Light) => return Decision::Local { reason: "history_light", report: true },
        Ok(Hist::Unknown) => {}
        // A database that will not answer is not a reason to hold the command.
        Err(_) => return Decision::Local { reason: "history_unavailable", report: false },
    }
    if ask_model(d, argv, &facts_of(dir)).await {
        heavy(Tier::Decision)
    } else {
        Decision::Local { reason: "unknown_command", report: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::{BoxFuture, FutureExt};

    use crate::decisions::{DecideError, Source};

    /// Scores `heavy_safe` at `heavy`, the rest equal.
    struct Fixed(f32);

    impl Decide for Fixed {
        fn decide<'a>(
            &'a self,
            req: DecideRequest,
            _: &'a dyn Fallback,
        ) -> BoxFuture<'a, Result<Vec<Scored>, DecideError>> {
            let h = self.0;
            async move {
                Ok(req
                    .questions
                    .iter()
                    .map(|q| Scored {
                        key: q.key.clone(),
                        scores: vec![
                            (HEAVY_SAFE.to_owned(), h),
                            (HEAVY_UNSAFE.to_owned(), (1.0 - h) / 2.0),
                            (LIGHT.to_owned(), (1.0 - h) / 2.0),
                        ],
                        source: Source::Cache,
                    })
                    .collect())
            }
            .boxed()
        }
    }

    fn scored(heavy: f32, light: f32) -> Scored {
        Scored {
            key: "cmd".into(),
            scores: vec![(HEAVY_SAFE.into(), heavy), (HEAVY_UNSAFE.into(), 0.0), (LIGHT.into(), light)],
            source: Source::Cache,
        }
    }

    #[test]
    fn only_a_confident_heavy_safe_sends_a_job_away() {
        assert!(heavy_by_scores(&scored(0.8, 0.1), 0.7));
        assert!(!heavy_by_scores(&scored(0.6, 0.1), 0.7), "not confident enough");
        assert!(!heavy_by_scores(&scored(0.4, 0.5), 0.3), "light is on top");
        let equal = Scored {
            key: "cmd".into(),
            scores: vec![(HEAVY_SAFE.into(), 0.33), (HEAVY_UNSAFE.into(), 0.33), (LIGHT.into(), 0.33)],
            source: Source::None,
        };
        assert!(!heavy_by_scores(&equal, 0.7));
    }

    #[tokio::test]
    async fn the_model_is_asked_only_after_tiers_zero_to_two() {
        let pool = SqlitePool::connect_lazy("sqlite::memory:").unwrap();
        let hot = Fixed(0.9);
        let dir = std::env::temp_dir();
        let argv = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let d = Deps { pool: &pool, decide: &hot, user: UserId(1), min_confidence: 0.7 };
        // Tier 0 and 1 never touch the database or the model.
        assert_eq!(decide(&d, Some(1), &argv("cargo run"), true, &[], &dir).await, Decision::Interactive);
        let Decision::Heavy { tier, row } = decide(&d, Some(1), &argv("cargo test"), false, &[], &dir).await else { panic!() };
        assert_eq!((tier, row.need), (Tier::Rule, vec!["rust".to_owned()]));
        assert_eq!(
            decide(&d, Some(1), &argv("npm ci"), false, &[], &dir).await,
            Decision::Local { reason: "light", report: false }
        );
        // No project: nothing to sync, so no model call either.
        assert_eq!(
            decide(&d, None, &argv("./weird"), false, &[], &dir).await,
            Decision::Local { reason: "no_project", report: false }
        );
        // A database that cannot be read holds nothing back.
        assert_eq!(
            decide(&d, Some(1), &argv("./weird"), false, &[], &dir).await,
            Decision::Local { reason: "history_unavailable", report: false }
        );
    }

    #[test]
    fn the_folder_tells_languages_and_lockfiles() {
        let dir = std::env::temp_dir().join(format!("ainkrad-heavy-facts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "").unwrap();
        std::fs::write(dir.join("Cargo.lock"), "").unwrap();
        std::fs::write(dir.join("package.json"), "").unwrap();
        let f = facts_of(&dir);
        assert_eq!(f.languages, ["rust", "node"]);
        assert_eq!(f.lockfiles, ["Cargo.lock"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
