//! Bench (Y3-02): what recording adds to the terminal relay's hot path. `stream` calls
//! `OutputTap::output` once per output frame the runner sends a client; that call is the whole
//! cost (the offset arithmetic beside it is two integer ops). The story's bar is under 1 ms per
//! frame; this asserts it for the mean and the 99.9th percentile, with a writer that keeps up and
//! with one that has stalled (a full queue drops the chunk, it never blocks).
//!
//! Run: `cargo bench -p leyline-module --bench relay_tap`.

use std::time::{Duration, Instant};

use ainkrad_core_server::api::v1::OutputTap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use leyline_module::record::Tap;

const FRAMES: usize = 200_000;
const FRAME_BYTES: usize = 4096;
const BAR: Duration = Duration::from_millis(1);

fn measure(tap: &Tap, frame: &str) -> (Duration, Duration) {
    let mut times = Vec::with_capacity(FRAMES);
    let mut offset = 0u64;
    for _ in 0..FRAMES {
        let t = Instant::now();
        tap.output(offset, frame);
        times.push(t.elapsed());
        offset += FRAME_BYTES as u64;
    }
    times.sort_unstable();
    let mean = times.iter().sum::<Duration>() / FRAMES as u32;
    (mean, times[FRAMES * 999 / 1000])
}

fn main() {
    let frame = B64.encode(vec![b'x'; FRAME_BYTES]);

    let (tap, mut drain) = Tap::queue();
    let reader = std::thread::spawn(move || while drain.next_blocking().is_some() {});
    let (mean, p999) = measure(&tap, &frame);
    println!("writer keeping up: mean {mean:?}, p99.9 {p999:?} per {FRAME_BYTES}-byte frame");
    assert!(
        mean < BAR && p999 < BAR,
        "the tap is on the relay's hot path"
    );
    drop(tap);
    reader.join().unwrap();

    // Nobody reads: the queue fills and every later call is a refused `try_send`.
    let (tap, _stalled) = Tap::queue();
    let (mean, p999) = measure(&tap, &frame);
    println!("writer stalled:    mean {mean:?}, p99.9 {p999:?}");
    assert!(
        mean < BAR && p999 < BAR,
        "a stalled writer must not slow the relay"
    );
}
