//! B3-01: the admission rules. `admit` scores one candidate fact and says admit, borderline or reject,
//! with reason codes. Pure and deterministic: no I/O, no model call, no clock. The model's own `durable`
//! and `confidence` are inputs here, not calls made here. The judge call for the borderline band is B3-03.
//!
//! Every `Q_*` constant is a quality-tuning value. It ships as a conservative placeholder (keep more,
//! reject only the clear junk) and only B1-04 may change it, against the eval on the real data copy.

use std::collections::HashSet;

/// Q: score below this is rejected.
pub const Q_LO: f32 = 0.40;
/// Q: score at or above this is admitted. Between `Q_LO` and `Q_HI` is borderline.
pub const Q_HI: f32 = 0.70;
/// Q: the share of the body's content words that must appear in the cited text, else rejected.
pub const Q_GROUND_FLOOR: f32 = 0.34;
/// Q: below this grounding share the body is flagged `weak_grounding` (a reason only).
pub const Q_GROUND_WEAK: f32 = 0.60;
/// Q: share of a rule's content words that must occur in ONE user turn of ONE cited source.
pub const Q_USER_GROUNDING: f32 = 0.70;
/// Q: shortest body, in characters and in words.
pub const Q_MIN_CHARS: usize = 12;
pub const Q_MIN_WORDS: usize = 3;
/// Q: longest body in characters; a longer one is not an atomic fact.
pub const Q_MAX_CHARS: usize = 800;
/// Q: component weights of the score (they sum to 1.0).
pub const Q_W_SHAPE: f32 = 0.15;
pub const Q_W_SPECIFIC: f32 = 0.35;
pub const Q_W_GROUNDING: f32 = 0.30;
pub const Q_W_MODEL: f32 = 0.20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    Admit,
    Borderline,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    TooShort,
    TooLong,
    StackTrace,
    LogLines,
    TimestampOnly,
    PathOnly,
    Greeting,
    OneOffStatus,
    Duplicate,
    NoSource,
    TaskDone,
    NeedsUserTurn,
    Ungrounded,
    GenericAdvice,
    ModelNotDurable,
    LowSpecificity,
    WeakGrounding,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::StackTrace => "stack_trace",
            Self::LogLines => "log_lines",
            Self::TimestampOnly => "timestamp_only",
            Self::PathOnly => "path_only",
            Self::Greeting => "greeting",
            Self::OneOffStatus => "one_off_status",
            Self::Duplicate => "duplicate",
            Self::NoSource => "no_source",
            Self::TaskDone => "task_done",
            Self::NeedsUserTurn => "needs_user_turn",
            Self::Ungrounded => "ungrounded",
            Self::GenericAdvice => "generic_advice",
            Self::ModelNotDurable => "model_not_durable",
            Self::LowSpecificity => "low_specificity",
            Self::WeakGrounding => "weak_grounding",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    pub body: &'a str,
    /// `decision|fact|preference|rule|project-state|task|summary`.
    pub kind: &'a str,
    /// The distil model's own verdict, when it gave one.
    pub durable: Option<bool>,
    /// The distil model's confidence, 0..1, when it gave one.
    pub confidence: Option<f32>,
}

/// A source the candidate cites. Build it once per source and reuse it for every candidate of a batch.
#[derive(Debug, Clone)]
pub struct Cited {
    stems: HashSet<String>,
    /// The cited text contains a `User:` turn (the proof a rule or preference needs).
    pub user_turn: bool,
}

impl Cited {
    pub fn new(text: &str, user_turn: bool) -> Self {
        Self {
            stems: tokens(text).iter().map(|t| stem(t)).collect(),
            user_turn,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Admission {
    /// 0..1. A hard reject scores 0.
    pub score: f32,
    pub band: Band,
    pub reasons: Vec<Reason>,
}

/// Lowercase, Arabic diacritics and tatweel removed, alef/yaa variants folded.
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(*c, '\u{064B}'..='\u{065F}' | '\u{0640}'))
        .map(|c| match c {
            'أ' | 'إ' | 'آ' => 'ا',
            'ى' => 'ي',
            c => c,
        })
        .flat_map(char::to_lowercase)
        .collect()
}

fn tokens(s: &str) -> Vec<String> {
    norm(s)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

// ponytail: a 6-char prefix is the stemmer (request/requests match); real stemming if B1 shows misses.
fn stem(t: &str) -> String {
    t.chars().take(6).collect()
}

const STOP: &[&str] = &[
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "has", "have",
    "had", "not", "but", "you", "your", "our", "their", "its", "into", "when", "then", "than",
    "also", "can", "will", "would", "should", "could", "about", "over", "after", "before", "each",
    "every", "any", "all", "في", "من", "على", "الى", "عن", "هذا", "هذه", "ذلك", "التي", "الذي",
    "كان", "مع", "هو", "هي", "ثم", "او",
];

/// More stop words for the user-turn check only (the corpus bands stay), folded as `norm` folds.
const STOP_USER: &[&str] = &[
    "just", "like", "make", "sure", "some", "more", "very", "much", "what", "which", "there",
    "here", "they", "them", "these", "those", "been", "being", "does", "did", "how", "who", "why",
    "where", "while", "because", "only", "out", "get", "got", "let", "please", "علي", "الي", "الذين",
    "كانت", "يكون", "انه", "بعد", "قبل", "عند", "حتي", "لكن", "بين", "كما", "ايضا", "هناك", "عليه",
];

/// Distinct content stems of `s`: words of 3+ characters, stop words (English, Arabic) dropped.
pub fn content_stems(s: &str) -> HashSet<String> {
    let stop = |t: &str| STOP.contains(&t) || STOP_USER.contains(&t);
    let keep = |t: &String| t.chars().count() >= 3 && !stop(t);
    tokens(s).into_iter().filter(keep).map(|t| stem(&t)).collect()
}

const GREET: &[&str] = &[
    "hi",
    "hello",
    "hey",
    "thanks",
    "thank",
    "ok",
    "okay",
    "great",
    "nice",
    "cool",
    "lol",
    "done",
    "fixed",
    "merged",
    "مرحبا",
    "اهلا",
    "شكرا",
    "تمام",
    "حسنا",
];

const NOW: &[&str] = &[
    "now",
    "today",
    "currently",
    "yesterday",
    "tonight",
    "اليوم",
    "الان",
    "حاليا",
    "دلوقتي",
];

/// A status line on its own is one-off.
const STATUS_ALONE: &[&str] = &[
    "build passed",
    "build failed",
    "build is green",
    "tests pass",
    "tests passed",
    "tests failed",
    "ci is green",
    "ci is red",
];

/// A status marker is one-off only next to a "now" word.
const STATUS_NOW: &[&str] = &["working on", "waiting for", "in progress"];

const GENERIC: &[&str] = &[
    "best practices",
    "clean code",
    "write tests",
    "be careful",
    "make sure",
    "double check",
    "good practice",
    "readable code",
    "follow the guidelines",
    "افضل الممارسات",
];

const CUES: &[&str] = &[
    "always",
    "never",
    "prefer",
    "prefers",
    "use",
    "uses",
    "must",
    "convention",
    "decided",
    "requires",
    "default",
    "owner",
    "يفضل",
    "دائما",
    "ابدا",
    "يستخدم",
    "قررنا",
    "يجب",
    "الافتراضي",
];

const DONE: &[&str] = &[
    "done",
    "completed",
    "fixed",
    "merged",
    "finished",
    "closed",
    "تم",
];

fn is_trace_line(t: &str) -> bool {
    let l = t.trim().to_lowercase();
    l.contains("traceback (most recent call last)")
        || l.contains("panicked at")
        || l.contains("stack backtrace")
        || l.contains("stack trace")
        || l.starts_with("exception in thread")
        || (l.starts_with("file \"") && l.contains(", line "))
        || (l.starts_with("at ") && l.contains(':') && l.contains('('))
}

fn digits(b: &[u8], n: usize) -> bool {
    b.len() >= n && b[..n].iter().all(u8::is_ascii_digit)
}

fn is_log_line(t: &str) -> bool {
    let t = t.trim();
    let b = t.as_bytes();
    let iso_date = digits(b, 4) && b.get(4) == Some(&b'-');
    let clock = digits(b, 2) && b.get(2) == Some(&b':');
    let bracket = t.starts_with("[INFO]")
        || t.starts_with("[WARN]")
        || t.starts_with("[ERROR]")
        || t.starts_with("[DEBUG]")
        || t.starts_with("[TRACE]");
    let level = ["INFO:", "WARN:", "ERROR:", "DEBUG:", "TRACE:"]
        .iter()
        .any(|p| t.starts_with(p));
    let tool = [
        "Compiling ",
        "Finished ",
        "npm ERR!",
        "error[",
        "BUILD ",
        "test result:",
    ]
    .iter()
    .any(|p| t.starts_with(p));
    iso_date || clock || bracket || level || tool
}

fn has_issue_ref(body: &str) -> bool {
    let b = body.as_bytes();
    b.windows(2).any(|w| w[0] == b'#' && w[1].is_ascii_digit())
}

fn is_path_like(w: &str) -> bool {
    w.contains('/') || w.contains('\\')
}

/// The first ephemeral shape found, if any.
fn ephemeral(body: &str) -> Option<Reason> {
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.iter().any(|l| is_trace_line(l)) {
        return Some(Reason::StackTrace);
    }
    let logs = lines.iter().filter(|l| is_log_line(l)).count();
    if logs > 0 && logs * 2 >= lines.len() {
        return Some(Reason::LogLines);
    }
    if body.chars().any(|c| c.is_ascii_digit())
        && body
            .chars()
            .all(|c| !c.is_alphabetic() || c == 'T' || c == 'Z')
    {
        return Some(Reason::TimestampOnly);
    }
    let words: Vec<&str> = body.split_whitespace().collect();
    if !words.is_empty()
        && (words.iter().all(|w| is_path_like(w))
            || (words.len() == 1
                && words[0].rsplit_once('.').is_some_and(|(_, e)| {
                    (1..=5).contains(&e.len()) && e.chars().all(|c| c.is_ascii_alphanumeric())
                })))
    {
        return Some(Reason::PathOnly);
    }
    let toks = tokens(body);
    if let Some(first) = toks.first() {
        let greeting = GREET.contains(&first.as_str())
            && (toks.len() <= 3
                || (toks.len() <= 5
                    && [
                        "hi",
                        "hello",
                        "hey",
                        "thanks",
                        "thank",
                        "مرحبا",
                        "اهلا",
                        "شكرا",
                    ]
                    .contains(&first.as_str())));
        if greeting {
            return Some(Reason::Greeting);
        }
    }
    let n = norm(body);
    let now = toks.iter().any(|t| NOW.contains(&t.as_str()));
    let marker = has_issue_ref(body) || STATUS_NOW.iter().any(|p| n.contains(p));
    if (now && marker) || STATUS_ALONE.iter().any(|p| n.contains(p)) {
        return Some(Reason::OneOffStatus);
    }
    None
}

/// Anchors of specificity: code-ish token, proper noun, number, durable cue.
fn anchors(body: &str) -> usize {
    let words: Vec<&str> = body.split_whitespace().collect();
    let code = words.iter().any(|w| {
        w.contains('`')
            || w.contains('/')
            || w.contains("::")
            || w.starts_with("--")
            || w.contains('_')
            || w.contains("()")
            || w.trim_end_matches(['.', ',', ';'])
                .rsplit_once('.')
                .is_some_and(|(a, e)| {
                    !a.is_empty()
                        && [
                            "rs", "swift", "ts", "toml", "json", "md", "sql", "sh", "db", "yml",
                        ]
                        .contains(&e)
                })
            || (w.chars().skip(1).any(|c| c.is_ascii_uppercase())
                && w.chars().next().is_some_and(|c| c.is_ascii_lowercase()))
    });
    let proper = words.iter().skip(1).any(|w| {
        let w = w.trim_matches(|c: char| !c.is_alphanumeric());
        w.len() >= 2 && w.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    });
    let number = words.iter().any(|w| w.chars().any(|c| c.is_ascii_digit()));
    let cue = tokens(body).iter().any(|t| CUES.contains(&t.as_str()));
    [code, proper, number, cue].iter().filter(|b| **b).count()
}

fn grounding(body: &str, cited: &[Cited]) -> f32 {
    let content: Vec<String> = tokens(body)
        .into_iter()
        .filter(|t| t.chars().count() >= 3 && !STOP.contains(&t.as_str()))
        .map(|t| stem(&t))
        .collect();
    if content.is_empty() {
        return 0.0;
    }
    let hit = content
        .iter()
        .filter(|s| cited.iter().any(|c| c.stems.contains(*s)))
        .count();
    hit as f32 / content.len() as f32
}

pub fn admit(c: &Candidate, cited: &[Cited], existing: &[&str]) -> Admission {
    let body = c.body.trim();
    let mut hard = Vec::new();
    let mut soft = Vec::new();

    let chars = body.chars().count();
    let words = body.split_whitespace().count();
    if chars < Q_MIN_CHARS || words < Q_MIN_WORDS {
        hard.push(Reason::TooShort);
    }
    if chars > Q_MAX_CHARS {
        hard.push(Reason::TooLong);
    }
    hard.extend(ephemeral(body));
    let nb = norm(body);
    if existing.iter().any(|e| norm(e.trim()) == nb) {
        hard.push(Reason::Duplicate);
    }
    if cited.is_empty() {
        hard.push(Reason::NoSource);
    }
    let kind = c.kind;
    if kind == "task" && tokens(body).iter().any(|t| DONE.contains(&t.as_str())) {
        hard.push(Reason::TaskDone);
    }
    if matches!(kind, "rule" | "preference") && !cited.iter().any(|s| s.user_turn) {
        hard.push(Reason::NeedsUserTurn);
    }
    let g = grounding(body, cited);
    if !cited.is_empty() && g < Q_GROUND_FLOOR {
        hard.push(Reason::Ungrounded);
    }
    if !hard.is_empty() {
        return Admission {
            score: 0.0,
            band: Band::Reject,
            reasons: hard,
        };
    }

    let mut shape: f32 = match words {
        5..=60 => 1.0,
        3..=4 | 61..=120 => 0.6,
        _ => 0.3,
    };
    if body.lines().filter(|l| !l.trim().is_empty()).count() > 1 {
        shape = (shape - 0.2).max(0.0);
    }
    let mut specific = (0.2 + 0.25 * anchors(body) as f32).min(1.0);
    if anchors(body) == 0 {
        soft.push(Reason::LowSpecificity);
    }
    if GENERIC.iter().any(|p| nb.contains(p)) {
        specific *= 0.4;
        soft.push(Reason::GenericAdvice);
    }
    if g < Q_GROUND_WEAK {
        soft.push(Reason::WeakGrounding);
    }
    let durable = match c.durable {
        Some(true) => 1.0,
        Some(false) => {
            soft.push(Reason::ModelNotDurable);
            0.0
        }
        None => 0.6,
    };
    let model = durable
        * c.confidence
            .filter(|x| x.is_finite())
            .map_or(1.0, |x| x.clamp(0.0, 1.0));

    let score = Q_W_SHAPE * shape + Q_W_SPECIFIC * specific + Q_W_GROUNDING * g + Q_W_MODEL * model;
    let band = if score >= Q_HI {
        Band::Admit
    } else if score >= Q_LO {
        Band::Borderline
    } else {
        Band::Reject
    };
    Admission {
        score,
        band,
        reasons: soft,
    }
}
