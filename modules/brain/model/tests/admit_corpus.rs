//! B3-01: the admission corpus. Every body is made up. One row per line: the expected band, and the
//! reason code that must be among the reasons when one is named. The grounding source is the body itself
//! (prefixed `User:`) unless a row gives its own.

use brain_model::admit::{Admission, Band, Candidate, Cited, Reason, admit};
use std::time::Instant;

struct Case {
    kind: &'static str,
    body: &'static str,
    source: Option<&'static str>,
    user_turn: bool,
    durable: Option<bool>,
    confidence: Option<f32>,
    existing: &'static [&'static str],
    no_source: bool,
    want: Band,
    reason: Option<Reason>,
}

fn row(kind: &'static str, body: &'static str, want: Band) -> Case {
    Case {
        kind,
        body,
        source: None,
        user_turn: true,
        durable: None,
        confidence: None,
        existing: &[],
        no_source: false,
        want,
        reason: None,
    }
}

fn run(c: &Case) -> Admission {
    let text = c
        .source
        .map_or_else(|| format!("User: {}", c.body), str::to_owned);
    let cited = if c.no_source {
        vec![]
    } else {
        vec![Cited::new(&text, c.user_turn)]
    };
    let cand = Candidate {
        body: c.body,
        kind: c.kind,
        durable: c.durable,
        confidence: c.confidence,
    };
    admit(&cand, &cited, c.existing)
}

fn check(cases: &[Case]) {
    for c in cases {
        let a = run(c);
        assert_eq!(a.band, c.want, "{:?} -> {:?}", c.body, a);
        if let Some(r) = c.reason {
            assert!(
                a.reasons.contains(&r),
                "{:?} lacks {:?}: {:?}",
                c.body,
                r,
                a
            );
        }
        if a.band == Band::Reject
            && c.reason.is_some()
            && !a.reasons.contains(&Reason::LowSpecificity)
        {
            // A hard reject scores zero; a soft reject scores under the lo bar.
            assert!(a.score < brain_model::admit::Q_LO, "{:?}", a);
        }
    }
}

#[test]
fn good_facts_are_admitted() {
    let good = [
        row(
            "fact",
            "The brain module stores each room in its own SQLCipher file named canon.db.",
            Band::Admit,
        ),
        row(
            "rule",
            "Always run `make check-env` before pushing a branch.",
            Band::Admit,
        ),
        row(
            "preference",
            "Ahmed prefers rounded rectangles over circles in every Core UI surface.",
            Band::Admit,
        ),
        row(
            "decision",
            "We decided to keep the Rust Core on SQLite with no new process.",
            Band::Admit,
        ),
        row(
            "project-state",
            "The epic/brain branch is the base for every Brain v2 story PR.",
            Band::Admit,
        ),
        row(
            "fact",
            "The runner binds to 127.0.0.1 on port 8443 unless --public is passed.",
            Band::Admit,
        ),
        row(
            "fact",
            "يستخدم النظام قاعدة بيانات SQLite لكل غرفة",
            Band::Admit,
        ),
        row(
            "preference",
            "أحمد يفضل أن تكون الواجهات بزوايا مستديرة دائما",
            Band::Admit,
        ),
        row(
            "rule",
            "Never commit .env files or secrets to any repository.",
            Band::Admit,
        ),
        row(
            "fact",
            "Lore notes are stored as Markdown with a title line and tags.",
            Band::Admit,
        ),
        row(
            "decision",
            "Merges use merge commits, never squash and never rebase.",
            Band::Admit,
        ),
        row(
            "summary",
            "The Wave 3 stories B2-03, B4-01 and B7-01 touch the ai-ops allow-list.",
            Band::Admit,
        ),
        row(
            "task",
            "Add the daily cap check to `brain_distils` before the idle gate.",
            Band::Admit,
        ),
        Case {
            durable: Some(true),
            confidence: Some(0.9),
            ..row(
                "fact",
                "The e5 model runs inside the Core and never leaves the machine.",
                Band::Admit,
            )
        },
    ];
    check(&good);
}

#[test]
fn borderline_goes_to_the_judge() {
    let border = [
        // Grounded but says nothing specific.
        row(
            "fact",
            "The service handles requests quickly and reliably.",
            Band::Borderline,
        ),
        // Specific, but only half of it is in the cited text.
        Case {
            source: Some("the daemon uses locks and Postgres"),
            reason: Some(Reason::WeakGrounding),
            ..row(
                "fact",
                "The sync daemon uses Postgres advisory locks for leader election",
                Band::Borderline,
            )
        },
        // Specific and grounded, but the model says it is not durable.
        // (The source says only part of it: a fully grounded, specific line still scores above the bar.)
        Case {
            durable: Some(false),
            confidence: Some(0.8),
            source: Some("User: the e5 model runs inside the Core"),
            reason: Some(Reason::ModelNotDurable),
            ..row(
                "fact",
                "The e5 model runs inside the Core and never leaves the machine.",
                Band::Borderline,
            )
        },
        // Generic advice that happens to be grounded.
        Case {
            reason: Some(Reason::GenericAdvice),
            ..row(
                "rule",
                "Always write tests and follow best practices in Rust projects",
                Band::Borderline,
            )
        },
    ];
    check(&border);
}

#[test]
fn junk_is_rejected_with_its_reason() {
    let junk = [
        Case {
            reason: Some(Reason::TooShort),
            ..row("fact", "ok thanks", Band::Reject)
        },
        Case {
            reason: Some(Reason::TooShort),
            ..row("fact", "   ", Band::Reject)
        },
        Case {
            reason: Some(Reason::Greeting),
            ..row("fact", "Hi there, thanks a lot", Band::Reject)
        },
        Case {
            reason: Some(Reason::Greeting),
            ..row("task", "Fixed the build", Band::Reject)
        },
        Case {
            reason: Some(Reason::Greeting),
            ..row("fact", "مرحبا كيف حالك اليوم", Band::Reject)
        },
        Case {
            reason: Some(Reason::Greeting),
            ..row("fact", "شكرا جزيلا", Band::Reject)
        },
        Case {
            reason: Some(Reason::StackTrace),
            ..row(
                "fact",
                "thread 'main' panicked at src/lib.rs:10:5\nnote: run with RUST_BACKTRACE=1",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::StackTrace),
            ..row(
                "fact",
                "Traceback (most recent call last):\n  File \"app.py\", line 3, in <module>\nValueError: bad input",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::StackTrace),
            ..row(
                "fact",
                "TypeError: x is undefined\n    at run (/app/index.js:10:5)",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::LogLines),
            ..row(
                "fact",
                "2026-11-18T10:00:01Z INFO server started\n2026-11-18T10:00:02Z INFO listening on 8443",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::LogLines),
            ..row(
                "fact",
                "Compiling brain-model v0.8.11\nFinished dev profile in 3.2s",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::LogLines),
            ..row("fact", "[ERROR] failed to open config file", Band::Reject)
        },
        Case {
            reason: Some(Reason::TimestampOnly),
            ..row("fact", "2026-11-18 10:42:07", Band::Reject)
        },
        Case {
            reason: Some(Reason::TimestampOnly),
            ..row("fact", "2026-11-18T10:42:07Z", Band::Reject)
        },
        Case {
            reason: Some(Reason::PathOnly),
            ..row("fact", "Sources/Brain/Views/InboxView.swift", Band::Reject)
        },
        Case {
            reason: Some(Reason::PathOnly),
            ..row(
                "fact",
                "src/lib.rs src/main.rs crates/server/src/api.rs",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::OneOffStatus),
            ..row(
                "project-state",
                "I'm working on PR #482 right now",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::OneOffStatus),
            ..row(
                "project-state",
                "Today the build failed on CI",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::OneOffStatus),
            ..row("project-state", "أعمل الآن على الطلب #123", Band::Reject)
        },
        Case {
            existing: &["the runner binds to 127.0.0.1 on port 8443 unless --public is passed."],
            reason: Some(Reason::Duplicate),
            ..row(
                "fact",
                "The runner binds to 127.0.0.1 on port 8443 unless --public is passed.",
                Band::Reject,
            )
        },
        Case {
            no_source: true,
            reason: Some(Reason::NoSource),
            ..row(
                "fact",
                "The brain module stores each room in its own SQLCipher file.",
                Band::Reject,
            )
        },
        Case {
            reason: Some(Reason::TaskDone),
            ..row(
                "task",
                "Wire the daily cap check into distil, done and merged.",
                Band::Reject,
            )
        },
        Case {
            user_turn: false,
            reason: Some(Reason::NeedsUserTurn),
            ..row(
                "rule",
                "Always run `make check-env` before pushing a branch.",
                Band::Reject,
            )
        },
        Case {
            source: Some("completely unrelated text about cooking pasta for dinner"),
            reason: Some(Reason::Ungrounded),
            ..row(
                "fact",
                "The brain module stores each room in its own SQLCipher file named canon.db.",
                Band::Reject,
            )
        },
        // Soft reject: weakly grounded, no anchor, and the model says not durable.
        Case {
            source: Some("the service requests"),
            durable: Some(false),
            ..row(
                "fact",
                "The service handles requests quickly and reliably.",
                Band::Reject,
            )
        },
    ];
    check(&junk);
}

#[test]
fn too_long_is_not_atomic() {
    let long = "alpha beta gamma delta ".repeat(50);
    let cited = [Cited::new(&long, true)];
    let a = admit(
        &Candidate {
            body: &long,
            kind: "fact",
            durable: None,
            confidence: None,
        },
        &cited,
        &[],
    );
    assert_eq!(a.band, Band::Reject);
    assert!(a.reasons.contains(&Reason::TooLong));
}

#[test]
fn same_input_same_answer() {
    let c = row(
        "fact",
        "The runner binds to 127.0.0.1 on port 8443 unless --public is passed.",
        Band::Admit,
    );
    assert_eq!(run(&c), run(&c));
    assert!(run(&c).score > 0.0 && run(&c).score <= 1.0);
}

#[test]
fn a_thousand_candidates_are_fast() {
    let source =
        "User: the brain module stores rooms in SQLCipher files and the runner binds to a port "
            .repeat(200);
    let cited = [Cited::new(&source, true)];
    let t = Instant::now();
    for i in 0..1000 {
        let body = format!("The runner binds to port {i} and stores rooms in SQLCipher files.");
        let a = admit(
            &Candidate {
                body: &body,
                kind: "fact",
                durable: None,
                confidence: None,
            },
            &cited,
            &[],
        );
        assert_ne!(a.band, Band::Reject);
    }
    // Acceptance is < 50 ms in release; a debug build is allowed ten times that.
    let limit = if cfg!(debug_assertions) { 500 } else { 50 };
    assert!(t.elapsed().as_millis() < limit, "{:?}", t.elapsed());
}
