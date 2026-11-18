//! Not part of the C ABI: hooks the fuzz target and tests use to reach the draw path, and the panic proof.

use crate::ffi::with;

/// Draw one small CPU frame (at most 256 x 256 px).
#[doc(hidden)]
pub fn draw_cpu(h: u64, w: i32, height: i32) -> i32 {
    with(h, |e| Ok(e.draw_cpu(w, height) as i32))
}

/// Seed an engine with a whole model document and its design system (benches and tests: a generated scene).
#[doc(hidden)]
pub fn import(h: u64, doc: &design_model::Doc, system: &design_model::Doc) -> i32 {
    with(h, |e| {
        e.import(doc, system);
        Ok(0)
    })
}

/// Draw one frame at the view size: on Metal when `metal` is true (the default device, offscreen, waiting for the
/// GPU), else CPU raster. Returns the frame time in µs, or an error code.
#[doc(hidden)]
pub fn frame_us(h: u64, metal: bool) -> i32 {
    with(h, |e| e.bench_frame(metal).ok_or(crate::ffi::DE_ERR_GPU))
}

/// Set the camera directly (benches: a known zoom and pan).
#[doc(hidden)]
pub fn set_camera(h: u64, zoom: f32, pan: (f32, f32)) -> i32 {
    with(h, |e| {
        e.camera.zoom = zoom;
        e.camera.pan = pan;
        Ok(0)
    })
}

/// The camera `(zoom, pan x, pan y)`.
#[doc(hidden)]
pub fn camera(h: u64) -> Option<(f32, f32, f32)> {
    let mut out = None;
    with(h, |e| {
        out = Some((e.camera.zoom, e.camera.pan.0, e.camera.pan.1));
        Ok(0)
    });
    out
}

/// One peer marker the overlay would draw: `(label, ai, cursor, selected rects)`.
pub type PeerMark = (String, bool, Option<(f32, f32)>, usize);

/// The peer markers the overlay would draw.
#[doc(hidden)]
pub fn peer_marks(h: u64) -> Vec<PeerMark> {
    let mut out = vec![];
    with(h, |e| {
        e.refresh();
        out = e
            .remote_marks()
            .into_iter()
            .map(|m| (m.label, m.ai, m.cursor, m.selected.len()))
            .collect();
        Ok(0)
    });
    out
}

/// World rect `[l, t, r, b]` of a node as drawn now (preview included).
#[doc(hidden)]
pub fn rect(h: u64, id: &str) -> Option<[f32; 4]> {
    let mut out = None;
    with(h, |e| {
        e.refresh();
        out = e.rect(id).map(|r| [r.left, r.top, r.right, r.bottom]);
        Ok(0)
    });
    out
}

#[cfg(test)]
mod tests {
    use crate::ffi::*;

    // yrs 0.28.1 itself is UB under Miri (stacked and tree borrows) when a doc creates its root types, so anything
    // that makes an engine cannot run there; the pointer checks below can.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_panic_is_caught_and_poisons_only_its_engine() {
        let (a, b) = (
            engine_new("dd_panic").unwrap(),
            engine_new("dd_panic").unwrap(),
        );
        assert_eq!(with(a, |_| panic!("boom")), DE_ERR_PANIC);
        assert_eq!(de_undo(a), DE_ERR_POISONED);
        assert_eq!(de_undo(b), 0);
        assert_eq!(guard(|| panic!("outside an engine")), DE_ERR_PANIC);
        assert_eq!(de_engine_free(a), DE_OK);
        assert_eq!(de_engine_free(b), DE_OK);
        assert_eq!(de_engine_free(b), DE_ERR_HANDLE);
    }

    #[test]
    #[allow(unsafe_code)]
    fn pointer_checks() {
        let buf = [1u8, 2, 3, 4];
        let null = std::ptr::null::<u8>();
        unsafe {
            assert_eq!(bytes(null, 0, 8), Ok(&[][..]));
            assert_eq!(bytes(null, 3, 8), Err(DE_ERR_ARG));
            assert_eq!(bytes(buf.as_ptr(), 4, 3), Err(DE_ERR_TOO_LARGE));
            assert_eq!(bytes(buf.as_ptr(), 4, 8), Ok(&buf[..]));
            assert_eq!(
                bytes(std::ptr::without_provenance(usize::MAX), 2, 8),
                Err(DE_ERR_ARG)
            );
            assert_eq!(text([0xffu8].as_ptr(), 1, 8), Err(DE_ERR_ARG));
            assert_eq!(text(b"dd_x".as_ptr(), 4, 8), Ok("dd_x"));
            let mut out = [0u8; 4];
            let mut n = 0usize;
            assert_eq!(
                put(b"abcdef", out.as_mut_ptr(), 4, &mut n),
                Err(DE_ERR_SMALL_BUFFER)
            );
            assert_eq!((n, out), (6, [0; 4]));
            assert_eq!(put(b"ab", std::ptr::null_mut(), 4, &mut n), Err(DE_ERR_ARG));
            assert_eq!(
                put(b"ab", out.as_mut_ptr(), 4, std::ptr::null_mut()),
                Err(DE_ERR_ARG)
            );
            let mut wide = [0usize; 2];
            let odd = (wide.as_mut_ptr() as *mut u8).add(1) as *mut usize;
            assert_eq!(put(b"ab", out.as_mut_ptr(), 4, odd), Err(DE_ERR_ARG));
            assert_eq!(put(b"ab", out.as_mut_ptr(), 4, &mut n), Ok(DE_OK));
            assert_eq!((n, &out[..2]), (2, &b"ab"[..]));
            assert_eq!(put(b"", std::ptr::null_mut(), 0, &mut n), Ok(DE_OK));
            assert_eq!(n, 0);
        }
        assert_eq!(de_undo(0), DE_ERR_HANDLE);
        assert_eq!(de_resize(u64::MAX, 1.0, 1.0, 1.0), DE_ERR_HANDLE);
        assert_eq!(guard(|| panic!("caught")), DE_ERR_PANIC);
        // the allocation cap: a hostile length fails a reservation instead of reaching the system
        assert!(Vec::<u8>::new().try_reserve(512 << 20).is_err());
    }
}
