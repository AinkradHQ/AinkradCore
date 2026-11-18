#![no_main]
//! Any text, any kind: `admit` never panics and always returns a score in 0..=1.

use brain_model::admit::{Candidate, Cited, admit};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (body, source) = s.split_once('\u{1}').unwrap_or((s, s));
    let kinds = ["fact", "rule", "preference", "task", "decision", "summary", "project-state"];
    let kind = kinds[data.len() % kinds.len()];
    let cited = [Cited::new(source, data.len() % 2 == 0)];
    let c = Candidate { body, kind, durable: Some(data.len() % 3 == 0), confidence: Some(f32::NAN) };
    let a = admit(&c, &cited, &[source]);
    assert!((0.0..=1.0).contains(&a.score));
});
