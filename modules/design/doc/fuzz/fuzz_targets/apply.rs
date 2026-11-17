//! A remote update applied on top of a real document, then everything the App does with it: read (what the renderer
//! gets), full diff, outbox, a local edit and undo. On a 512 KB stack, like the App's render thread. A crash, an
//! abort (stack, memory) or a panic that escapes `design-doc` fails the run.
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
                let _ = l.apply_remote(&data);
                let _ = l.read();
                let _ = l.diff(&[]);
                let _ = l.outbox(true);
                let op = br#"[{"op":"set","id":"n_bbbbbbbbbbbb","key":"w","value":10}]"#;
                if let Ok(ops) = design_doc::parse_ops(op) {
                    let _ = l.apply_ops(&ops);
                    l.undo();
                }
                let _ = l.read();
            })
            .unwrap()
            .join()
            .unwrap();
    }
);
