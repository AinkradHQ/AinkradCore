//! CPU raster of the spike scene: `cpu_render <font.ttf> <outdir> [bench]`.
//! Renders the three zoom cameras the Mac host snapshots (25%, 100%, 400%) at 2560x1600 px (1280x800 pt @2x).
use design_spike::Engine;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (font, out) = (&a[1], &a[2]);
    std::fs::create_dir_all(out).unwrap();
    let t = std::time::Instant::now();
    let mut e = Engine::new(font);
    let open_ms = t.elapsed().as_secs_f64() * 1e3;
    let (n, tx, g) = e.scene.counts();
    println!("scene nodes={n} text={tx} glass={g} open_ms={open_ms:.1} layout_ms={:.1}", e.scene.layout_ms);
    e.view = (1280.0, 800.0);
    e.scale = 2.0;
    // must match the host's snapshot cameras (Swift side: zoom + pan in points)
    let cams = [("fit", e.fit_zoom(), (20.0, 20.0)), ("z25", 0.25, (-300.0, -200.0)), ("z100", 1.0, (-1000.0, -1100.0)), ("z400", 4.0, (-4500.0, -4400.0)), ("z10", 0.10, (20.0, 20.0)), ("z800", 8.0, (-140.0, -220.0))];
    for (name, z, pan) in cams {
        e.set_camera(z, pan);
        let t = std::time::Instant::now();
        let mut s = e.render_cpu(2560, 1600);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        design_spike::save_png(&mut s, &format!("{out}/cpu-{name}.png"));
        println!("{name}: cpu raster {ms:.1} ms");
    }
}
