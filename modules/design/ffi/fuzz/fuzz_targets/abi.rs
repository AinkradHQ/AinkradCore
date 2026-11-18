#![no_main]
#![allow(unsafe_code)]

#[path = "../abi_program.rs"]
mod program;

libfuzzer_sys::fuzz_target!(
    // libfuzzer-sys aborts on every panic, even one the engine catches (yrs decoders panic on some malformed bytes,
    // and `design-doc` turns that into DE_ERR_INVALID). A panic that reaches the program's checks (DE_ERR_PANIC, a bad
    // return code) still unwinds out of this closure, and libfuzzer-sys aborts on that.
    init: std::panic::set_hook(Box::new(|_| {})),
    |data: &[u8]| program::run(data)
);
