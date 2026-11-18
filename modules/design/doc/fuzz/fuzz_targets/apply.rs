//! Remote updates (one, or 2-3 cut from the input) applied on top of a real document, each followed by a local edit,
//! then everything the App does with them: read (what the renderer gets), full diff, outbox, undo. On a 512 KB stack,
//! like the App's render thread. A crash, an abort (stack, memory) or a panic that escapes `design-doc` fails the run.
#![no_main]

const BASE: &[u8] = include_bytes!("../seeds/apply/base");

/// The App links design-ffi's allocator cap (any single Rust allocation over 256 MiB is refused), and yrs reserves
/// wire-sized collections with `try_reserve`, which then fails cleanly. Mirror it here so a hostile length is a decode
/// error, as in the App, not a 45 GB `malloc` that libFuzzer reports as out-of-memory.
struct Capped;
// SAFETY: forwards to the system allocator, only refusing (null) oversized requests, which `GlobalAlloc` allows.
unsafe impl std::alloc::GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        if l.size() > 256 << 20 {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.alloc(l) }
        }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        if n > 256 << 20 {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::System.realloc(p, l, n) }
        }
    }
}
#[global_allocator]
static ALLOC: Capped = Capped;

/// `[0xf0 | k, a, b, rest...]` -> `rest` cut into 2 (k even) or 3 (k odd) updates at fractions `a`, `b` of its
/// length; anything else is one update.
fn split(data: &[u8]) -> Vec<&[u8]> {
    match data {
        [k, a, b, rest @ ..] if *k >= 0xf0 => {
            let at = |f: u8| rest.len() * f as usize / 256;
            let (x, y) = (at(*a).min(at(*b)), at(*a).max(at(*b)));
            if k & 1 == 0 {
                vec![&rest[..x], &rest[x..]]
            } else {
                vec![&rest[..x], &rest[x..y], &rest[y..]]
            }
        }
        _ => vec![data],
    }
}

libfuzzer_sys::fuzz_target!(
    // libfuzzer-sys aborts on every panic, even one `design-doc` catches (yrs decoders panic on some bytes); a panic
    // that escapes still fails the run through `join().unwrap()`.
    init: std::panic::set_hook(Box::new(|_| {})),
    |data: &[u8]| {
        let data = data.to_vec();
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || {
                let mut l = design_doc::Live::new();
                l.apply_remote(BASE).unwrap();
                let op = br#"[{"op":"set","id":"n_bbbbbbbbbbbb","key":"w","value":10}]"#;
                let ops = design_doc::parse_ops(op).unwrap();
                // 2 or 3 updates in a row when the first byte is >= 0xf0 (duplicate clients across updates, pending
                // updates that a later one completes), with a local edit after each; otherwise one update (the seeds)
                for u in split(&data) {
                    let _ = l.apply_remote(u);
                    let _ = l.apply_ops(&ops);
                    let _ = l.read();
                }
                let _ = l.diff(&[]);
                let _ = l.outbox(true);
                l.undo();
                let _ = l.read();
            })
            .unwrap()
            .join()
            .unwrap();
    }
);
