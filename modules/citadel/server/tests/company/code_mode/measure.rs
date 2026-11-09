//! The numbers of a plan build (`Usage`), their median over repeats and the report.

use serde_json::{Value, json};

use super::super::stage::Stage;

/// A model's latency per turn, for the modelled time: an assumption (the e2e run's OpenCode
/// free model took about 3.4 s per tool call).
pub const TURN_MS: f64 = 3000.0;

/// Bytes per token, for the estimate.
const BYTES_PER_TOKEN: usize = 4;

pub fn tokens(bytes: usize) -> usize {
    bytes.div_ceil(BYTES_PER_TOKEN)
}

/// What one planning session cost.
#[derive(Debug, Clone, Default)]
pub struct Usage {
    /// Model turns: each tool call, or each shell command.
    pub turns: usize,
    /// Operations the server audited for the run (`mcp.*`).
    pub ops: i64,
    /// The tool definitions the run was given (`tools/list`), in bytes.
    pub defs: usize,
    /// What the model wrote: tool arguments, or shell commands.
    pub wrote: usize,
    /// What came back into its context: tool results, or what the commands printed.
    pub read: usize,
    /// Per turn, what it wrote and read (for the billed estimate).
    pub per_turn: Vec<usize>,
    /// The run's wall time, ms.
    pub ms: f64,
}

impl Usage {
    /// The wall time with a model's latency per turn (`TURN_MS`), which the fake harness has
    /// none of: what a real agent would take, roughly.
    pub fn modeled_ms(&self) -> f64 {
        self.ms + self.turns as f64 * TURN_MS
    }

    pub fn context_tokens(&self) -> usize {
        tokens(self.defs + self.wrote + self.read)
    }

    /// Every turn re-sends the definitions and all of the conversation before it.
    pub fn billed_tokens(&self) -> usize {
        let mut sent = 0;
        let mut so_far = self.defs;
        for t in &self.per_turn {
            sent += so_far;
            so_far += t;
        }
        tokens(sent)
    }

    pub fn json(&self) -> Value {
        json!({"turns": self.turns, "ops": self.ops, "defs_tokens": tokens(self.defs),
               "wrote_tokens": tokens(self.wrote), "read_tokens": tokens(self.read),
               "context_tokens": self.context_tokens(), "billed_tokens": self.billed_tokens(),
               "ms": self.ms.round(), "modeled_ms": self.modeled_ms().round()})
    }
}

/// How many times each session runs (`CODE_MODE_REPEAT`, default 1: fast mode).
pub fn repeats() -> usize {
    std::env::var("CODE_MODE_REPEAT")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1)
        .max(1)
}

/// `f`'s usage over `repeats()` fresh stages, with the median wall time.
pub async fn median<F, Fut>(name: &str, f: F) -> Usage
where
    F: Fn(Stage) -> Fut,
    Fut: std::future::Future<Output = Usage>,
{
    let mut runs = vec![];
    for _ in 0..repeats() {
        runs.push(f(Stage::new(name).await).await);
    }
    runs.sort_by(|a, b| a.ms.total_cmp(&b.ms));
    runs.swap_remove(runs.len() / 2)
}

/// `part` as a share of `whole`, in percent, saved.
pub fn saved(whole: f64, part: f64) -> f64 {
    100.0 * (1.0 - part / whole)
}

/// Each role's `tools/list` bytes, every tool listed and scoped.
pub type RoleLists = Vec<(&'static str, usize, usize)>;

pub fn report(roles: &RoleLists, sessions: &[(&str, &Usage)]) -> Value {
    println!("tool definitions per role (tools/list), all tools -> role-scoped:");
    for (role, all, scoped) in roles {
        println!(
            "  {role:<5} {all:>6} -> {scoped:>6} bytes  ~{:>5} -> {:>5} tokens  ({:.0}% less)",
            tokens(*all),
            tokens(*scoped),
            saved(*all as f64, *scoped as f64)
        );
    }
    println!(
        "{:<10} {:>5} {:>4} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7} {:>8}",
        "session", "turns", "ops", "defs", "wrote", "read", "context", "billed", "ms", "model s"
    );
    for (name, u) in sessions {
        println!(
            "{name:<10} {:>5} {:>4} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7.0} {:>8.1}",
            u.turns,
            u.ops,
            tokens(u.defs),
            tokens(u.wrote),
            tokens(u.read),
            u.context_tokens(),
            u.billed_tokens(),
            u.ms,
            u.modeled_ms() / 1000.0
        );
    }
    let out = json!({
        "roles": roles.iter().map(|(r, all, scoped)| json!({"role": r, "all_bytes": all,
                "all_tokens": tokens(*all), "scoped_bytes": scoped,
                "scoped_tokens": tokens(*scoped)}))
            .collect::<Vec<_>>(),
        "sessions": sessions.iter().map(|(n, u)| json!({"session": n, "usage": u.json()}))
            .collect::<Vec<_>>(),
        "repeat": repeats(),
    });
    if let Ok(path) = std::env::var("CODE_MODE_OUT") {
        std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
    out
}
