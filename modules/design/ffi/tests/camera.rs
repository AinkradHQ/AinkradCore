//! `de_camera` and `de_fit_rect`: the formula the App draws overlays with.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use design_ffi::testing;
use serde_json::{Value, json};

const PAGE: &str = "n_pppppppppppp";
const A: &str = "n_aaaaaaaaaaaa";

fn engine() -> u64 {
    let mut h = 0u64;
    let id = b"dd_camera";
    let ops = json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a",
         "props": {"x": 300, "y": 120, "w": 200, "h": 100}},
    ])
    .to_string();
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut h), DE_OK);
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
    }
    assert_eq!(de_resize(h, 1000.0, 600.0, 2.0), DE_OK);
    h
}

fn camera(h: u64) -> (f32, f32, f32) {
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    assert_eq!(
        unsafe { de_camera(h, buf.as_mut_ptr(), buf.len(), &mut n) },
        DE_OK
    );
    let v: Value = serde_json::from_slice(&buf[..n]).unwrap();
    (
        v["zoom"].as_f64().unwrap() as f32,
        v["pan"][0].as_f64().unwrap() as f32,
        v["pan"][1].as_f64().unwrap() as f32,
    )
}

fn hit(h: u64, x: f32, y: f32) -> Value {
    let mut buf = vec![0u8; 4096];
    let mut n = 0usize;
    assert_eq!(
        unsafe { de_hit(h, x, y, buf.as_mut_ptr(), buf.len(), &mut n) },
        DE_OK
    );
    serde_json::from_slice(&buf[..n]).unwrap()
}

#[test]
fn the_formula_matches_what_hits_and_draws() {
    let h = engine();
    // a zoom about a point, then a scroll: nothing is left at identity
    assert_eq!(de_magnify(h, 1.7, 400.0, 250.0), DE_OK);
    assert_eq!(de_scroll(h, 33.0, -21.0), DE_OK);
    let (z, px, py) = camera(h);
    assert!(z != 1.0 && (px, py) != (0.0, 0.0));
    let to_view = |x: f32, y: f32| (x * z + px, y * z + py);
    // the frame's corners (just inside) hit it; just outside they do not
    let (l, t) = to_view(300.0, 120.0);
    let (r, b) = to_view(500.0, 220.0);
    assert_eq!(hit(h, l + 1.0, t + 1.0)["id"], A);
    assert_eq!(hit(h, r - 1.0, b - 1.0)["id"], A);
    assert_eq!(hit(h, l - 2.0, t - 2.0), Value::Null);
    assert_eq!(hit(h, r + 2.0, b + 2.0), Value::Null);
    // the renderer's rect agrees with the camera the formula reads
    let rr = testing::rect(h, A).unwrap();
    assert_eq!(rr, [300.0, 120.0, 500.0, 220.0]);
    let tc = testing::camera(h).unwrap();
    assert_eq!(tc, (z, px, py));
}

#[test]
fn fit_rect_centres_the_rect() {
    let h = engine();
    assert_eq!(de_scroll(h, 500.0, 500.0), DE_OK);
    assert_eq!(de_fit_rect(h, 100.0, 50.0, 400.0, 200.0, 1), DE_OK);
    let (z, px, py) = camera(h);
    // 5 % margins: 400 wide fills 90 % of 1000
    assert!((z - 2.25).abs() < 1e-4, "{z}");
    let (cx, cy) = ((100.0 + 200.0) * z + px, (50.0 + 100.0) * z + py);
    assert!(
        (cx - 500.0).abs() < 0.01 && (cy - 300.0).abs() < 0.01,
        "{cx} {cy}"
    );
    assert_eq!(de_fit_rect(h, 0.0, 0.0, 0.0, 10.0, 0), DE_ERR_ARG);
    assert_eq!(de_fit_rect(h, f32::NAN, 0.0, 10.0, 10.0, 0), DE_ERR_ARG);
}
