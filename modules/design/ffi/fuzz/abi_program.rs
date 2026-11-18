// The C ABI under random calls (V2-02 acceptance). Shared by the fuzz target (`fuzz_targets/abi.rs`) and the
// deterministic test (`tests/abi.rs`).
//
// Input bytes drive a program: each step picks a function, a handle (live, random, freed), pointers (NULL, a real
// buffer, a NULL with a length) and lengths, out-buffers of random capacity, and floats from raw bits (NaN, inf).
// Every return code must be a known one and every successful output must fit its buffer. Any crash, panic escaping
// the ABI or out-of-bounds write fails the run.

use design_ffi::ffi::*;

const IDS: [&str; 5] = [
    "n_aaaaaaaaaaaa",
    "n_bbbbbbbbbbbb",
    "n_cccccccccccc",
    "n_dddddddddddd",
    "n_eeeeeeeeeeee",
];

struct In<'a>(&'a [u8], usize);

impl In<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.0.get(self.1).copied().unwrap_or(0);
        self.1 += 1;
        b
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    fn u64(&mut self) -> u64 {
        (self.u32() as u64) << 32 | self.u32() as u64
    }
    fn f32(&mut self) -> f32 {
        match self.u8() % 4 {
            0 => f32::from_bits(self.u32()),
            1 => (self.u32() % 4000) as f32 - 1000.0,
            2 => (self.u8() % 8) as f32 * 0.25 + 0.25,
            _ => 1.0,
        }
    }
    fn done(&self) -> bool {
        self.1 >= self.0.len()
    }
}

fn edit_json(i: &mut In) -> String {
    let id = |i: &mut In| IDS[i.u8() as usize % IDS.len()];
    let n = (i.u8() % 4) as usize + 1;
    let ops: Vec<String> = (0..n)
        .map(|_| match i.u8() % 10 {
            0 => format!(r#"{{"op":"add","id":"{}","type":"page","parent":null,"order":"a"}}"#, IDS[0]),
            1 => format!(
                r#"{{"op":"add","id":"{}","type":"frame","parent":"{}","order":"a{}","props":{{"w":{},"h":200,"x":{}}}}}"#,
                id(i), IDS[0], i.u8() % 10, i.u8() as u32 + 10, i.u8()
            ),
            2 => format!(
                r#"{{"op":"add","id":"{}","type":"text","parent":"{}","order":"b","text":"hi {}"}}"#,
                id(i), id(i), i.u8()
            ),
            3 => format!(r#"{{"op":"set","id":"{}","key":"w","value":{}}}"#, id(i), i.u8()),
            4 => format!(r#"{{"op":"move","id":"{}","parent":"{}","order":"a{}"}}"#, id(i), id(i), i.u8() % 10),
            5 => format!(r#"{{"op":"delete","id":"{}"}}"#, id(i)),
            6 => format!(r#"{{"op":"name","id":"{}","name":"n{}"}}"#, id(i), i.u8()),
            7 => format!(r#"{{"op":"text","id":"{}","text":"t{}"}}"#, id(i), i.u8()),
            8 => format!(
                r#"{{"op":"splice","id":"{}","at":{},"del":{},"text":"日😀{}"}}"#,
                id(i), i.u8() % 8, i.u8() % 4, i.u8()
            ),
            _ => format!(r##"{{"op":"set","id":"{}","key":"fill","value":[{{"type":"solid","color":"#ff0000"}}]}}"##, id(i)),
        })
        .collect();
    format!("[{}]", ops.join(","))
}

const KNOWN: [i32; 14] = [
    0,
    1,
    DE_ERR_HANDLE,
    DE_ERR_ARG,
    DE_ERR_TOO_LARGE,
    DE_ERR_INVALID,
    DE_ERR_SMALL_BUFFER,
    DE_ERR_NO_SURFACE,
    DE_ERR_PANIC,
    DE_ERR_POISONED,
    DE_ERR_GPU,
    DE_ERR_RESET,
    DE_ERR_HALTED,
    -100,
];

fn check(rc: i32) {
    assert!(KNOWN.contains(&rc), "unknown return code {rc}");
    assert_ne!(rc, DE_ERR_PANIC, "a panic inside the engine");
}

/// Run one program.
pub fn run(data: &[u8]) {
    let mut i = In(data, 0);
    let doc = b"dd_fuzz";
    let mut live = [0u64; 2];
    for h in &mut live {
        // SAFETY: valid buffers.
        check(unsafe { de_engine_new(doc.as_ptr(), doc.len(), h) });
    }
    let mut freed = 0u64;
    let blob: Vec<u8> = data.iter().rev().copied().collect();
    let mut out = vec![0u8; 1 << 16];
    let mut out_len = 0usize;
    let mut steps = 0;
    while !i.done() && steps < 256 {
        steps += 1;
        let h = match i.u8() % 5 {
            0 | 1 => live[0],
            2 => live[1],
            3 => i.u64(),
            _ => freed,
        };
        // an input: (ptr, len), sometimes a NULL with a length, sometimes a template edit
        let json = edit_json(&mut i);
        let (ip, il): (*const u8, usize) = match i.u8() % 5 {
            0 => (std::ptr::null(), 0),
            1 => (std::ptr::null(), i.u32() as usize),
            2 => (blob.as_ptr(), i.u32() as usize % (blob.len() + 1)),
            3 => (json.as_ptr(), json.len()),
            _ => (blob.as_ptr(), blob.len()),
        };
        // an output: capacity and pointers
        let (op, cap, ol): (*mut u8, usize, *mut usize) = match i.u8() % 5 {
            0 => (std::ptr::null_mut(), 0, &mut out_len),
            1 => (
                out.as_mut_ptr(),
                i.u32() as usize % (out.len() + 1),
                &mut out_len,
            ),
            2 => (std::ptr::null_mut(), 64, &mut out_len),
            3 => (out.as_mut_ptr(), out.len(), std::ptr::null_mut()),
            _ => (out.as_mut_ptr(), out.len(), &mut out_len),
        };
        out_len = usize::MAX;
        let (x, y) = (i.f32(), i.f32());
        // SAFETY: every (ptr, len) above is NULL or inside a live buffer, which is the ABI's contract.
        let rc = unsafe {
            match i.u8() % 32 {
                0 => de_sync_apply(h, i.u8() as u32 % 3, ip, il),
                1 => de_sync_state_vector(h, op, cap, ol),
                2 => de_sync_diff(h, ip, il, op, cap, ol),
                3 => {
                    // relay: A's outbox into B, as the Core would
                    let rc = de_sync_outbox(live[0], out.as_mut_ptr(), out.len(), &mut out_len);
                    check(rc);
                    if rc == DE_OK {
                        check(de_sync_apply(live[1], DE_DOC, out.as_ptr(), out_len));
                    }
                    -100
                }
                4 => de_sync_outbox(h, op, cap, ol),
                5 => de_presence_set(h, ip, il),
                6 => de_presence_encode(h, op, cap, ol),
                7 => de_presence_apply(h, ip, il),
                8 => de_presence_peers(h, op, cap, ol),
                9..=11 => de_edit(h, ip, il),
                12 => de_undo(h),
                13 => de_redo(h),
                14 => de_resize(h, x, y, i.f32()),
                15 => de_set_theme(h, i.u32()),
                16 => de_set_page(h, i.u32() % 3),
                17 => de_pointer(h, i.u32() % 4, x, y, i.u32()),
                18 => de_scroll(h, x, y),
                19 => de_magnify(h, i.f32(), x, y),
                20 => de_key(h, i.u32() % 9, i.u32()),
                21 => de_selection(h, op, cap, ol),
                22 => {
                    let id = IDS[i.u8() as usize % IDS.len()];
                    match i.u8() % 2 {
                        0 => de_node(h, id.as_ptr(), id.len(), op, cap, ol),
                        _ => de_node(h, ip, il, op, cap, ol),
                    }
                }
                23 => de_missing_assets(h, op, cap, ol),
                24 => de_engine_free(if i.u8() % 8 == 0 { h } else { freed }),
                25 => de_attach_metal(h, std::ptr::null_mut(), std::ptr::null_mut()),
                26 => de_detach(h),
                27 => de_draw_metal(h, std::ptr::null_mut()),
                28 => match i.u8() % 10 {
                    0 => de_hit(h, x, y, op, cap, ol),
                    1 => de_needs_frame(h),
                    2 => de_fit(h),
                    3 => design_ffi::testing::draw_cpu(h, i.u8() as i32, i.u8() as i32),
                    4 => de_pointer(h, DE_POINTER_DOWN, x, y, i.u32() % 16),
                    // V2-03: drags (several moves in a row), cursor, camera settle
                    5 => {
                        let m = i.u32() % 16;
                        for _ in 0..(i.u8() % 6) {
                            check(de_pointer(h, DE_POINTER_MOVE, i.f32(), i.f32(), m));
                        }
                        de_pointer(h, DE_POINTER_UP, x, y, m)
                    }
                    6 => {
                        let c = de_cursor(h, x, y);
                        if c >= 0 {
                            assert!(c <= DE_CURSOR_RESIZE_NESW, "cursor {c}");
                            0
                        } else {
                            c
                        }
                    }
                    7 => de_gesture_end(h, i.u32() % 2),
                    8 => de_tick(h, i.f32()),
                    _ => de_fit_selection(h),
                },
                // V2-04: text editing, with real text (CJK, emoji, RTL, combining) or the raw input
                30 | 31 => {
                    const T: [&str; 6] = [
                        "日本",
                        "👩\u{200d}💻",
                        "مرحبا",
                        "a\n",
                        "e\u{301}",
                        "\u{202e}",
                    ];
                    let t = T[i.u8() as usize % T.len()];
                    let (tp, tl) = if i.u8() % 3 == 0 {
                        (ip, il)
                    } else {
                        (t.as_ptr(), t.len())
                    };
                    let r = |i: &mut In| match i.u8() % 4 {
                        0 => DE_TEXT_NO_RANGE,
                        1 => i.u32() as i32 as i64,
                        _ => (i.u8() % 12) as i64,
                    };
                    match i.u8() % 9 {
                        0 => de_text_begin(h, x, y),
                        1 => de_text_end(h),
                        2 => de_text_insert(h, tp, tl, r(&mut i), r(&mut i)),
                        3 => de_text_set_marked(
                            h,
                            tp,
                            tl,
                            r(&mut i),
                            r(&mut i),
                            r(&mut i),
                            r(&mut i),
                        ),
                        4 => de_text_unmark(h),
                        5 => de_text_command(h, i.u32() % 10, i.u32()),
                        6 => de_text_state(h, op, cap, ol),
                        7 => de_text_first_rect(h, r(&mut i), r(&mut i), op, cap, ol),
                        _ => {
                            let c = de_text_index_at(h, x, y);
                            if c >= 0 { 0 } else { c }
                        }
                    }
                }
                // V2-06: peers, own presence, follow
                29 => {
                    let m = format!(
                        r#"{{"peer":"person:d_{}","conn":{},"label":"p","cursor":[{},{}],"selection":["{}"],"view":[0,0,{},{}]}}"#,
                        i.u8(),
                        i.u8() % 4,
                        i.u8(),
                        i.u8(),
                        IDS[i.u8() as usize % IDS.len()],
                        i.u8(),
                        i.u8()
                    );
                    let (mp, ml) = if i.u8() % 2 == 0 {
                        (m.as_ptr(), m.len())
                    } else {
                        (ip, il)
                    };
                    let who = format!("person:d_{}", i.u8());
                    match i.u8() % 5 {
                        0 | 1 => de_presence_remote(h, mp, ml),
                        2 => de_presence_local(h, op, cap, ol),
                        3 => de_presence_list(h, op, cap, ol),
                        _ if i.u8() % 2 == 0 => de_follow(h, who.as_ptr(), who.len()),
                        _ => de_follow(h, ip, il),
                    }
                }
                _ => match i.u8() % 2 {
                    0 => de_font_add(h, std::ptr::null(), 0, ip, il),
                    _ => {
                        let k = "1".repeat(64);
                        de_asset_add(h, k.as_ptr(), k.len(), ip, il)
                    }
                },
            }
        };
        check(rc);
        if rc == DE_OK && !ol.is_null() && out_len != usize::MAX {
            assert!(out_len <= cap, "wrote {out_len} into a {cap}-byte buffer");
        }
        // a freed engine is replaced so the program keeps going
        for h in &mut live {
            let mut n = 0usize;
            // SAFETY: a size probe (NULL, 0) with a valid out_len.
            if unsafe { de_selection(*h, std::ptr::null_mut(), 0, &mut n) } == DE_ERR_HANDLE {
                freed = *h;
                // SAFETY: valid buffers.
                check(unsafe { de_engine_new(doc.as_ptr(), doc.len(), h) });
            }
        }
    }
    for h in live {
        check(de_engine_free(h));
    }
}
