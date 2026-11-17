//! `png_diff <a.png> <b.png> [diff-out.png]` : per-pixel comparison (RGBA8888), prints
//! mean abs diff, share of pixels whose worst channel differs by > 8 / > 32 (of 255), and PSNR.
use skia_safe::{AlphaType, ColorType, Data, EncodedImageFormat, Image, ImageInfo};

fn load(p: &str) -> (Vec<u8>, i32, i32) {
    let img = Image::from_encoded(Data::new_copy(&std::fs::read(p).unwrap())).expect("decode");
    let (w, h) = (img.width(), img.height());
    let info = ImageInfo::new((w, h), ColorType::RGBA8888, AlphaType::Premul, None);
    let mut px = vec![0u8; (w * h * 4) as usize];
    assert!(img.read_pixels(&info, &mut px, (w * 4) as usize, (0, 0), skia_safe::image::CachingHint::Disallow));
    (px, w, h)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (pa, w, h) = load(&a[1]);
    let (pb, w2, h2) = load(&a[2]);
    assert_eq!((w, h), (w2, h2), "size mismatch");
    let n = (w * h) as usize;
    let (mut sum, mut sq, mut over8, mut over32) = (0u64, 0u64, 0usize, 0usize);
    let mut heat = vec![0u8; n * 4];
    for i in 0..n {
        let mut worst = 0i32;
        for c in 0..3 {
            let d = (pa[i * 4 + c] as i32 - pb[i * 4 + c] as i32).abs();
            sum += d as u64;
            sq += (d * d) as u64;
            worst = worst.max(d);
        }
        over8 += (worst > 8) as usize;
        over32 += (worst > 32) as usize;
        let v = (worst * 4).min(255) as u8;
        heat[i * 4..i * 4 + 4].copy_from_slice(&[v, 0, 0, 255]);
    }
    let mse = sq as f64 / (n * 3) as f64;
    let psnr = if mse == 0.0 { f64::INFINITY } else { 10.0 * (255.0f64 * 255.0 / mse).log10() };
    println!(
        "{}x{} mean_abs_diff={:.3} px>8={:.3}% px>32={:.3}% psnr={:.1}dB",
        w, h, sum as f64 / (n * 3) as f64, 100.0 * over8 as f64 / n as f64, 100.0 * over32 as f64 / n as f64, psnr
    );
    if a.len() > 3 {
        let info = ImageInfo::new((w, h), ColorType::RGBA8888, AlphaType::Premul, None);
        let img = skia_safe::images::raster_from_data(&info, Data::new_copy(&heat), (w * 4) as usize).unwrap();
        std::fs::write(&a[3], img.encode(None, EncodedImageFormat::PNG, 100).unwrap().as_bytes()).unwrap();
    }
}
